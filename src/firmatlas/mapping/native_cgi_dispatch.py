"""Evidence-backed ARM32 string-switch dispatch for proprietary CGI handlers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import struct
from typing import Tuple

from .domain import (
    AnalyzerIdentity,
    CoverageStatus,
    EvidenceAtom,
    ObservationKind,
    SpanKind,
)
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry
from .native_deep import (
    _ALLOC,
    _ARM_MACHINE,
    _EXEC,
    _arm_branch_target,
    _find_pic_base,
    _parse_elf,
    _read_route_literal,
    _word_at_address,
)
from .native_arm_xref import _function_start


ARM_CGI_DISPATCH_SCHEMA_VERSION = (
    "firmatlas.mapping.arm-cgi-string-dispatch/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("native-arm-cgi-string-dispatch", "0.1.0")
_CONTENT_KINDS = frozenset({"file", "hardlink", "archive", "archive_member"})


@dataclass(frozen=True)
class ArmCgiDispatchAnchor:
    target_ref: str
    interface_path: str

    @property
    def dispatch_token(self) -> str:
        marker = "/cgi-bin/"
        if marker in self.interface_path:
            return self.interface_path.split(marker, 1)[1].split("/", 1)[0]
        return self.interface_path.rstrip("/").rsplit("/", 1)[-1]

    def __post_init__(self) -> None:
        if (
            not self.target_ref.strip()
            or not self.interface_path.startswith("/")
            or not self.dispatch_token
        ):
            raise ValueError("CGI dispatch anchor requires target and absolute path")


@dataclass(frozen=True)
class ArmCgiDispatchProfile:
    name: str = "arm32-pic-cgi-string-switch/v1"
    min_dispatcher_entries: int = 2
    max_function_scan_bytes: int = 16 * 1024
    max_route_bytes: int = 256

    def __post_init__(self) -> None:
        if (
            not self.name.strip()
            or self.min_dispatcher_entries < 2
            or self.max_function_scan_bytes <= 0
            or self.max_route_bytes <= 0
        ):
            raise ValueError("invalid ARM CGI dispatch profile")


@dataclass(frozen=True)
class ArmCgiDispatchPolicy:
    max_source_bytes: int = 64 * 1024 * 1024
    max_anchors: int = 10_000
    max_bindings: int = 20_000

    def __post_init__(self) -> None:
        if min(self.max_source_bytes, self.max_anchors, self.max_bindings) <= 0:
            raise ValueError("ARM CGI dispatch budgets must be positive")


@dataclass(frozen=True)
class ArmCgiDispatchBinding:
    binding_id: str
    target_ref: str
    interface_path: str
    dispatch_token: str
    dispatcher_address: int
    dispatcher_entry_count: int
    comparison_address: int
    comparison_target_address: int
    handler_address: int
    handler_identity: str
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class ArmCgiDispatchResult:
    source_path: str
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    profile: str
    bindings: Tuple[ArmCgiDispatchBinding, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[str, ...] = ()
    schema_version: str = ARM_CGI_DISPATCH_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "bindings": [asdict(item) for item in self.bindings],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
        }


@dataclass(frozen=True)
class _Candidate:
    dispatch_token: str
    route_offset: int
    dispatcher_address: int
    pic_base_offset: int
    comparison_address: int
    comparison_offset: int
    comparison_target_address: int
    handler_address: int
    handler_call_offset: int


def _empty(
    source: SourceArtifactEntry,
    profile: ArmCgiDispatchProfile,
    status: CoverageStatus,
    diagnostic: str,
) -> ArmCgiDispatchResult:
    return ArmCgiDispatchResult(
        source.canonical_path, status, 0, _PRODUCER, profile.name, (), (),
        (diagnostic,),
    )


def _binding_id(source_path: str, anchor: ArmCgiDispatchAnchor, candidate: _Candidate) -> str:
    encoded = json.dumps(
        [
            source_path,
            anchor.target_ref,
            anchor.interface_path,
            candidate.dispatcher_address,
            candidate.comparison_address,
            candidate.handler_address,
        ],
        separators=(",", ":"),
    ).encode()
    return "native-cgi-dispatch:" + hashlib.sha256(encoded).hexdigest()


def _scan(elf, content: bytes, profile: ArmCgiDispatchProfile) -> Tuple[_Candidate, ...]:
    got = next((
        section for section in elf.sections
        if section.name == ".got"
        and section.section_type == 1
        and section.flags & _ALLOC
        and not section.flags & _EXEC
    ), None)
    if got is None:
        return ()
    executable = tuple(
        section for section in elf.sections
        if section.section_type == 1
        and section.flags & (_ALLOC | _EXEC) == (_ALLOC | _EXEC)
    )
    candidates = []
    for section in executable:
        for relative in range(0, section.size - 52 + 1, 4):
            offset = section.offset + relative
            words = struct.unpack_from(elf.endian_prefix + "13I", content, offset)
            if not (
                words[1] & 0xFFFFF000 == 0xE59F3000
                and words[2] == 0xE0843003
                and words[3] == 0xE1A01003
                and words[4] & 0xFFFFFF00 == 0xE3A02000
                and words[5] & 0xFF000000 == 0xEB000000
                and words[6] == 0xE1A03000
                and words[7] == 0xE3530000
                and words[8] & 0xFF000000 == 0x1A000000
                and words[12] & 0xFF000000 == 0xEB000000
            ):
                continue
            comparison_address = section.address + relative
            pic = _find_pic_base(
                elf, content, comparison_address, got.address,
                profile.max_function_scan_bytes,
            )
            function = _function_start(
                elf, content, comparison_address, profile.max_function_scan_bytes
            )
            if pic is None or function is None:
                continue
            literal_address = (
                comparison_address + 4 + 8 + (words[1] & 0xFFF)
            )
            route_delta = _word_at_address(elf, content, literal_address)
            if route_delta is None:
                continue
            route = _read_route_literal(
                elf, content, (got.address + route_delta) & 0xFFFFFFFF,
                profile.max_route_bytes,
            )
            if route is None or len(route[0].encode("utf-8")) != (words[4] & 0xFF):
                continue
            comparison_target = _arm_branch_target(
                comparison_address + 20, words[5]
            )
            handler_address = _arm_branch_target(
                comparison_address + 48, words[12]
            )
            if not all(any(
                section.flags & (_ALLOC | _EXEC) == (_ALLOC | _EXEC)
                and section.address <= address < section.address + section.size
                for section in executable
            ) for address in (comparison_target, handler_address)):
                continue
            branch_target = _arm_branch_target(
                comparison_address + 32, words[8]
            )
            if branch_target <= comparison_address + 48:
                continue
            candidates.append(_Candidate(
                route[0], route[1], function[0], pic[1], comparison_address,
                offset, comparison_target, handler_address,
                offset + 48,
            ))
    grouped = {}
    for item in candidates:
        grouped.setdefault(
            (item.dispatcher_address, item.comparison_target_address), []
        ).append(item)
    return tuple(
        item
        for item in candidates
        if len({
            entry.dispatch_token for entry in grouped[
                (item.dispatcher_address, item.comparison_target_address)
            ]
        }) >= profile.min_dispatcher_entries
    )


def discover_arm_cgi_string_dispatch(
    source: SourceArtifactEntry,
    content: bytes,
    anchors: Tuple[ArmCgiDispatchAnchor, ...],
    profile: ArmCgiDispatchProfile = ArmCgiDispatchProfile(),
    policy: ArmCgiDispatchPolicy = ArmCgiDispatchPolicy(),
) -> ArmCgiDispatchResult:
    """Bind exact CGI suffixes to direct ARM handler branches."""

    if len(content) > policy.max_source_bytes:
        return _empty(source, profile, CoverageStatus.SKIPPED_BY_POLICY,
                      "source_budget_exceeded")
    if len(anchors) > policy.max_anchors:
        return _empty(source, profile, CoverageStatus.SKIPPED_BY_POLICY,
                      "anchor_budget_exceeded")
    if source.kind not in _CONTENT_KINDS:
        return _empty(source, profile, CoverageStatus.FAILED,
                      "unsupported_source_kind")
    if (
        source.content_sha256 is None
        or len(content) != source.size
        or hashlib.sha256(content).hexdigest() != source.content_sha256
    ):
        return _empty(source, profile, CoverageStatus.FAILED, "source_mismatch")
    try:
        elf = _parse_elf(content)
        if elf.pointer_size != 4 or elf.machine != _ARM_MACHINE:
            return _empty(source, profile, CoverageStatus.UNSUPPORTED,
                          "unsupported_architecture")
        candidates = _scan(elf, content, profile)
    except TypeError:
        return _empty(source, profile, CoverageStatus.UNSUPPORTED,
                      "unsupported_binary_format")
    except (ValueError, struct.error) as exc:
        return _empty(source, profile, CoverageStatus.FAILED,
                      "malformed_elf:" + str(exc))

    by_token = {}
    for candidate in candidates:
        by_token.setdefault(candidate.dispatch_token, []).append(candidate)
    bindings = []
    atoms = []
    truncated = False
    for anchor in sorted(set(anchors), key=lambda item: (
        item.target_ref, item.interface_path,
    )):
        for candidate in by_token.get(anchor.dispatch_token, ()):
            if len(bindings) >= policy.max_bindings:
                truncated = True
                continue
            binding_id = _binding_id(source.canonical_path, anchor, candidate)
            handler_identity = "{}@0x{:08x}".format(
                source.canonical_path, candidate.handler_address
            )
            route_atom = capture_evidence(
                source, content,
                SpanSelection(
                    SpanKind.BINARY, candidate.route_offset,
                    candidate.route_offset + len(candidate.dispatch_token.encode()),
                ),
                EvidenceClaim(
                    binding_id, "matches_interface_suffix", anchor.interface_path,
                    ObservationKind.DETERMINISTIC_DERIVED,
                    "matches_interface_suffix", 1.0,
                ), _PRODUCER,
            )
            pic_atom = capture_evidence(
                source, content,
                SpanSelection(
                    SpanKind.BINARY, candidate.pic_base_offset,
                    candidate.pic_base_offset + 8,
                ),
                EvidenceClaim(
                    binding_id, "establishes_pic_base", ".got",
                    ObservationKind.DETERMINISTIC_DERIVED,
                    "establishes_pic_base", 1.0,
                ), _PRODUCER,
            )
            comparison_atom = capture_evidence(
                source, content,
                SpanSelection(
                    SpanKind.BINARY, candidate.comparison_offset,
                    candidate.comparison_offset + 36,
                ),
                EvidenceClaim(
                    binding_id, "dispatches_cgi_token", candidate.dispatch_token,
                    ObservationKind.DETERMINISTIC_DERIVED,
                    "dispatches_cgi_token", 1.0,
                ), _PRODUCER,
            )
            handler_atom = capture_evidence(
                source, content,
                SpanSelection(
                    SpanKind.BINARY, candidate.handler_call_offset,
                    candidate.handler_call_offset + 4,
                ),
                EvidenceClaim(
                    binding_id, "binds_handler", handler_identity,
                    ObservationKind.DETERMINISTIC_DERIVED,
                    "binds_handler", 1.0,
                ), _PRODUCER,
            )
            group_count = len({
                item.dispatch_token for item in candidates
                if item.dispatcher_address == candidate.dispatcher_address
                and item.comparison_target_address
                == candidate.comparison_target_address
            })
            bindings.append(ArmCgiDispatchBinding(
                binding_id, anchor.target_ref, anchor.interface_path,
                candidate.dispatch_token, candidate.dispatcher_address,
                group_count, candidate.comparison_address,
                candidate.comparison_target_address, candidate.handler_address,
                handler_identity, "elf.arm32-pic-cgi-string-switch/v1",
                (
                    route_atom.evidence_id, pic_atom.evidence_id,
                    comparison_atom.evidence_id, handler_atom.evidence_id,
                ),
            ))
            atoms.extend((route_atom, pic_atom, comparison_atom, handler_atom))
    diagnostics = (
        ("binding_budget_exceeded",) if truncated else ()
    )
    return ArmCgiDispatchResult(
        source.canonical_path,
        CoverageStatus.PARTIAL if truncated else CoverageStatus.COMPLETED,
        len(content), _PRODUCER, profile.name, tuple(bindings), tuple(atoms),
        diagnostics,
    )
