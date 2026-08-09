"""Conservative response-contract clues from firmware-bundled JSON fixtures."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any, Optional, Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry


RESPONSE_FIXTURE_SCHEMA_VERSION = "firmatlas.mapping.response-fixture/v1alpha1"
_PRODUCER = AnalyzerIdentity("response-fixture-producer", "0.1.0")


class ResponseFixtureBindingStatus(str, Enum):
    FIXTURE_DECLARED = "fixture_declared"


@dataclass(frozen=True)
class ResponseFixturePolicy:
    max_source_bytes: int = 2 * 1024 * 1024
    max_fields: int = 10_000

    def __post_init__(self) -> None:
        if self.max_source_bytes <= 0 or self.max_fields <= 0:
            raise ValueError("response fixture limits must be positive")


@dataclass(frozen=True)
class ResponseFixtureField:
    field_id: str
    name: str
    json_pointer: str
    value_kind: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class ResponseFixtureResult:
    source_path: str
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    endpoint_clue: Optional[str]
    binding_status: Optional[ResponseFixtureBindingStatus]
    fields: Tuple[ResponseFixtureField, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    open_obligation: str
    diagnostics: Tuple[str, ...] = ()
    schema_version: str = RESPONSE_FIXTURE_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "binding_status": self.binding_status.value if self.binding_status else None,
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
        }


def _identity(prefix: str, *values: str) -> str:
    raw = json.dumps(values, separators=(",", ":"), ensure_ascii=False).encode()
    return "{}:{}".format(prefix, hashlib.sha256(raw).hexdigest())


def _kind(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, list):
        return "array"
    return "object"


def _walk(value: Any, pointer: str = ""):
    if isinstance(value, dict):
        for name, child in value.items():
            escaped = name.replace("~", "~0").replace("/", "~1")
            child_pointer = "{}/{}".format(pointer, escaped)
            yield name, child_pointer, _kind(child)
            yield from _walk(child, child_pointer)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child, pointer + "/*")


def discover_response_fixture(
    source: SourceArtifactEntry,
    content: bytes,
    policy: ResponseFixturePolicy = ResponseFixturePolicy(),
) -> ResponseFixtureResult:
    """Publish response-shape clues without asserting a runtime route binding."""
    path = PurePosixPath(source.canonical_path)
    applicable = path.suffix.lower() == ".txt" and "goform" in path.parts
    if not applicable:
        return ResponseFixtureResult(
            source.canonical_path, CoverageStatus.NOT_APPLICABLE, 0, _PRODUCER,
            None, None, (), (),
            "response fixture does not prove runtime route registration",
        )
    if source.content_sha256 is None or len(content) != source.size \
            or hashlib.sha256(content).hexdigest() != source.content_sha256:
        raise ValueError("response fixture content does not match inventory")
    if len(content) > policy.max_source_bytes:
        return ResponseFixtureResult(
            source.canonical_path, CoverageStatus.SKIPPED_BY_POLICY, 0, _PRODUCER,
            None, None, (), (),
            "response fixture does not prove runtime route registration",
            ("response_fixture.byte_budget_exceeded",),
        )
    try:
        document = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return ResponseFixtureResult(
            source.canonical_path, CoverageStatus.FAILED, len(content), _PRODUCER,
            "goform/{}".format(path.stem), ResponseFixtureBindingStatus.FIXTURE_DECLARED,
            (), (), "response fixture does not prove runtime route registration",
            ("response_fixture.invalid_json",),
        )

    endpoint = "goform/{}".format(path.stem)
    endpoint_ref = _identity("response-fixture-endpoint", source.canonical_path, endpoint)
    atoms = []
    if content:
        endpoint_atom = capture_evidence(
            source, content, SpanSelection(SpanKind.TEXT_UTF8, 0, 1),
            EvidenceClaim(
                endpoint_ref, "suggests_response_contract_for", endpoint,
                ObservationKind.DETERMINISTIC_DERIVED,
                "observes_fixture_endpoint", 0.65,
            ), _PRODUCER,
        )
        atoms.append(endpoint_atom)

    field_occurrences = list(_walk(document))
    limited = len(field_occurrences) > policy.max_fields
    field_occurrences = field_occurrences[:policy.max_fields]
    cursors = {}
    fields = {}
    for name, pointer, value_kind in field_occurrences:
        encoded = json.dumps(name, ensure_ascii=False)[1:-1].encode("utf-8")
        pattern = re.compile(rb'"' + re.escape(encoded) + rb'"\s*:')
        cursor = cursors.get(name, 0)
        match = pattern.search(content, cursor)
        if match is None:
            continue
        name_start = match.start() + 1
        name_end = name_start + len(encoded)
        cursors[name] = match.end()
        field_id = _identity("response-fixture-field", endpoint_ref, pointer)
        atom = capture_evidence(
            source, content,
            SpanSelection(SpanKind.TEXT_UTF8, name_start, name_end),
            EvidenceClaim(
                field_id, "declares_response_field", name,
                ObservationKind.DIRECT_STATIC,
                "observes_response_field", 0.7,
            ), _PRODUCER,
        )
        atoms.append(atom)
        existing = fields.get(pointer)
        evidence_ids = (
            (atom.evidence_id,)
            if existing is None
            else tuple(dict.fromkeys((*existing.evidence_ids, atom.evidence_id)))
        )
        fields[pointer] = ResponseFixtureField(
            field_id, name, pointer, value_kind, evidence_ids
        )

    diagnostics = (
        ("response_fixture.field_budget_exceeded",) if limited else ()
    )
    return ResponseFixtureResult(
        source.canonical_path,
        CoverageStatus.PARTIAL if limited else CoverageStatus.COMPLETED,
        len(content), _PRODUCER, endpoint,
        ResponseFixtureBindingStatus.FIXTURE_DECLARED,
        tuple(sorted(fields.values(), key=lambda item: item.json_pointer)),
        tuple(sorted(atoms, key=lambda item: item.evidence_id)),
        "response fixture does not prove runtime route registration; locate a route binding or runtime observation",
        diagnostics,
    )
