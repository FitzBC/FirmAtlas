"""Conservative relationships declared by complete commands embedded in ELF files."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Optional, Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry


NATIVE_RELATIONSHIP_SCHEMA_VERSION = (
    "firmatlas.mapping.native-relationship/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("native-embedded-command-relationship", "0.1.0")
_CONTENT_KINDS = frozenset({"file", "hardlink", "archive", "archive_member"})
_PROCESS_CONTROL = re.compile(
    r"^killall(?P<flags>(?:\s+-[A-Za-z0-9-]+)*)\s+"
    r"(?P<target>[A-Za-z0-9_.+-]+)$"
)
_CFM_POST = re.compile(
    r"^cfm\s+post\s+(?P<target>[A-Za-z0-9_.+-]+)\s+"
    r"(?P<topic>[^?\s,]+)\?op=(?P<operation>[^,\s]+)"
    r"(?:,(?P<arguments>.*))?$"
)
_FORMAT_SPECIFIER = re.compile(
    r"%(?!%)[-+0 #]*\d*(?:\.\d+)?[diuoxXfFeEgGaAcspn]"
)


class NativeRelationshipKind(str, Enum):
    IPC_COMMAND = "ipc_command"
    PROCESS_CONTROL = "process_control"


class NativeRelationshipBindingStatus(str, Enum):
    EMBEDDED_COMMAND = "embedded_command"
    EMBEDDED_COMMAND_TEMPLATE = "embedded_command_template"


@dataclass(frozen=True)
class NativeRelationshipPolicy:
    max_source_bytes: int = 64 * 1024 * 1024
    max_strings: int = 100_000
    max_relationships: int = 10_000
    min_string_length: int = 4

    def __post_init__(self) -> None:
        if min(
            self.max_source_bytes,
            self.max_strings,
            self.max_relationships,
            self.min_string_length,
        ) <= 0:
            raise ValueError("native relationship limits must be positive")


@dataclass(frozen=True)
class NativeRelationship:
    relationship_id: str
    kind: NativeRelationshipKind
    action: str
    target: str
    topic: Optional[str]
    operation: Optional[str]
    arguments: Tuple[str, ...]
    command: str
    binding_status: NativeRelationshipBindingStatus
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class NativeRelationshipResult:
    source_path: str
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    relationships: Tuple[NativeRelationship, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    open_obligation: str
    diagnostics: Tuple[str, ...] = ()
    schema_version: str = NATIVE_RELATIONSHIP_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "relationships": [
                {
                    **asdict(item),
                    "kind": item.kind.value,
                    "binding_status": item.binding_status.value,
                }
                for item in self.relationships
            ],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
        }


def _empty(
    source: SourceArtifactEntry,
    status: CoverageStatus,
    diagnostic: str,
    processed_bytes: int = 0,
) -> NativeRelationshipResult:
    return NativeRelationshipResult(
        source.canonical_path,
        status,
        processed_bytes,
        _PRODUCER,
        (),
        (),
        "embedded commands require a code callsite or runtime observation",
        (diagnostic,),
    )


def _printable_strings(content: bytes, minimum: int):
    start = 0
    while start < len(content):
        while start < len(content) and not 0x20 <= content[start] <= 0x7E:
            start += 1
        end = start
        while end < len(content) and 0x20 <= content[end] <= 0x7E:
            end += 1
        if end - start >= minimum:
            yield start, end, content[start:end].decode("ascii")
        start = end + 1


def _identity(source_path: str, kind: NativeRelationshipKind, command: str) -> str:
    raw = json.dumps(
        [source_path, kind.value, command], separators=(",", ":")
    ).encode()
    return "native-relationship:" + hashlib.sha256(raw).hexdigest()


def discover_native_relationships(
    source: SourceArtifactEntry,
    content: bytes,
    policy: NativeRelationshipPolicy = NativeRelationshipPolicy(),
) -> NativeRelationshipResult:
    """Recover complete embedded command relationships without claiming execution."""
    if source.kind not in _CONTENT_KINDS:
        return _empty(source, CoverageStatus.UNSUPPORTED, "unsupported_source_kind")
    if source.content_sha256 is None or len(content) != source.size \
            or hashlib.sha256(content).hexdigest() != source.content_sha256:
        return _empty(source, CoverageStatus.FAILED, "source_mismatch")
    if len(content) > policy.max_source_bytes:
        return _empty(source, CoverageStatus.SKIPPED_BY_POLICY, "source_budget_exceeded")
    if len(content) < 16 or content[:4] != b"\x7fELF":
        return _empty(source, CoverageStatus.UNSUPPORTED, "unsupported_binary_format")
    if content[4] not in {1, 2} or content[5] not in {1, 2}:
        return _empty(
            source, CoverageStatus.FAILED, "malformed_elf_identity", len(content)
        )

    relationships = []
    atoms = []
    seen = set()
    limited = False
    for string_index, (start, end, command) in enumerate(
        _printable_strings(content, policy.min_string_length)
    ):
        if string_index >= policy.max_strings:
            limited = True
            break
        process = _PROCESS_CONTROL.fullmatch(command)
        ipc = _CFM_POST.fullmatch(command)
        if process is not None:
            kind = NativeRelationshipKind.PROCESS_CONTROL
            action = "signal"
            target = process.group("target")
            topic = operation = None
            arguments = tuple(process.group("flags").split())
        elif ipc is not None:
            kind = NativeRelationshipKind.IPC_COMMAND
            action = "post"
            target = ipc.group("target")
            topic = ipc.group("topic")
            operation = ipc.group("operation")
            raw_arguments = ipc.group("arguments")
            arguments = tuple(raw_arguments.split(",")) if raw_arguments else ()
        else:
            continue
        identity = _identity(source.canonical_path, kind, command)
        if identity in seen:
            continue
        if len(relationships) >= policy.max_relationships:
            limited = True
            break
        seen.add(identity)
        atom = capture_evidence(
            source,
            content,
            SpanSelection(SpanKind.BINARY, start, end),
            EvidenceClaim(
                identity,
                "embeds_command_target",
                target,
                ObservationKind.DIRECT_STATIC,
                "declares_native_relationship",
                0.75,
            ),
            _PRODUCER,
        )
        atoms.append(atom)
        binding_status = (
            NativeRelationshipBindingStatus.EMBEDDED_COMMAND_TEMPLATE
            if _FORMAT_SPECIFIER.search(command)
            else NativeRelationshipBindingStatus.EMBEDDED_COMMAND
        )
        relationships.append(NativeRelationship(
            identity,
            kind,
            action,
            target,
            topic,
            operation,
            arguments,
            command,
            binding_status,
            (atom.evidence_id,),
        ))

    diagnostics = (
        ("native_relationship.budget_exhausted",) if limited else ()
    )
    return NativeRelationshipResult(
        source.canonical_path,
        CoverageStatus.PARTIAL if limited else CoverageStatus.COMPLETED,
        len(content),
        _PRODUCER,
        tuple(sorted(relationships, key=lambda item: (item.kind.value, item.command))),
        tuple(sorted(atoms, key=lambda item: item.evidence_id)),
        "embedded commands require a code callsite or runtime observation",
        diagnostics,
    )
