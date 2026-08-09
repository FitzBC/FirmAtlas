"""Bounded cross-artifact clues for parameters observed in frontend requests."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .frontend import FrontendAssetGraphResult, FrontendParameterDirection
from .inventory import SourceArtifactEntry

PARAMETER_CLUE_SCHEMA_VERSION = "firmatlas.mapping.parameter-clue/v1alpha1"
_PRODUCER = AnalyzerIdentity("frontend-parameter-clue", "0.1.0")
_IDENTIFIER_BYTES = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")


class ParameterClueArtifactRole(str, Enum):
    CONFIGURATION = "configuration"
    SCRIPT = "script"
    NATIVE = "native"
    OTHER = "other"


@dataclass(frozen=True)
class ParameterClueArtifact:
    source: SourceArtifactEntry
    content: bytes
    role: ParameterClueArtifactRole

    def __post_init__(self) -> None:
        if self.source.kind not in {"file", "hardlink"}:
            raise ValueError("parameter clue artifacts must be regular content")


@dataclass(frozen=True)
class ParameterCluePolicy:
    max_artifacts: int = 10_000
    max_total_bytes: int = 256 * 1024 * 1024
    max_parameters: int = 10_000
    max_hits_per_parameter: int = 100

    def __post_init__(self) -> None:
        if min(self.max_artifacts, self.max_total_bytes, self.max_parameters, self.max_hits_per_parameter) <= 0:
            raise ValueError("parameter clue limits must be positive")


@dataclass(frozen=True)
class ParameterClueOccurrence:
    artifact_path: str
    artifact_role: ParameterClueArtifactRole
    start_byte: int
    end_byte: int
    evidence_id: str


@dataclass(frozen=True)
class FrontendParameterClueAssessment:
    parameter_id: str
    request_candidate_id: str
    parameter_name: str
    assessment_status: str
    frontend_evidence_ids: Tuple[str, ...]
    occurrences: Tuple[ParameterClueOccurrence, ...]


@dataclass(frozen=True)
class FrontendParameterClueIndex:
    coverage_status: CoverageStatus
    processed_artifact_count: int
    processed_bytes: int
    producer: AnalyzerIdentity
    assessments: Tuple[FrontendParameterClueAssessment, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[str, ...] = ()
    schema_version: str = PARAMETER_CLUE_SCHEMA_VERSION


def _exact_offsets(content: bytes, token: bytes):
    start = 0
    while True:
        offset = content.find(token, start)
        if offset < 0:
            return
        end = offset + len(token)
        if (offset == 0 or content[offset - 1] not in _IDENTIFIER_BYTES) and (
            end == len(content) or content[end] not in _IDENTIFIER_BYTES
        ):
            yield offset
        start = offset + 1


def trace_frontend_parameter_clues(
    frontend_graph: FrontendAssetGraphResult,
    artifacts: Tuple[ParameterClueArtifact, ...],
    policy: ParameterCluePolicy = ParameterCluePolicy(),
) -> FrontendParameterClueIndex:
    """Index exact same-firmware token occurrences without claiming value flow."""
    paths = tuple(item.source.canonical_path for item in artifacts)
    if len(paths) != len(set(paths)):
        raise ValueError("parameter clue artifacts require unique source paths")

    parameters, frontend_evidence = {}, {}
    for result in frontend_graph.results:
        frontend_evidence.update((atom.evidence_id, atom) for atom in result.evidence_atoms)
        for parameter in result.parameters:
            if parameter.direction is FrontendParameterDirection.REQUEST:
                parameters[parameter.parameter_id] = parameter
    ordered_parameters = tuple(sorted(parameters.values(), key=lambda item: item.parameter_id))
    diagnostics, limited = [], False
    if len(ordered_parameters) > policy.max_parameters:
        ordered_parameters = ordered_parameters[:policy.max_parameters]
        diagnostics.append("parameter_clue.parameter_budget_exhausted")
        limited = True

    accepted, processed_bytes = [], 0
    for artifact in sorted(artifacts, key=lambda item: item.source.canonical_path):
        if len(accepted) >= policy.max_artifacts:
            diagnostics.append("parameter_clue.artifact_budget_exhausted")
            limited = True
            break
        if processed_bytes + len(artifact.content) > policy.max_total_bytes:
            diagnostics.append("parameter_clue.byte_budget_exhausted")
            limited = True
            break
        accepted.append(artifact)
        processed_bytes += len(artifact.content)

    evidence, assessments = dict(frontend_evidence), []
    for parameter in ordered_parameters:
        occurrences, hit_limited = [], False
        token = parameter.name.encode("utf-8")
        for artifact in accepted:
            for offset in _exact_offsets(artifact.content, token):
                if len(occurrences) >= policy.max_hits_per_parameter:
                    hit_limited = limited = True
                    break
                atom = capture_evidence(
                    artifact.source, artifact.content,
                    SpanSelection(SpanKind.BINARY if artifact.role is ParameterClueArtifactRole.NATIVE else SpanKind.TEXT_UTF8, offset, offset + len(token)),
                    EvidenceClaim(parameter.parameter_id, "has_same_firmware_token_clue", parameter.name, ObservationKind.DIRECT_STATIC, "external_parameter_token", 0.55),
                    _PRODUCER,
                )
                evidence[atom.evidence_id] = atom
                occurrences.append(ParameterClueOccurrence(artifact.source.canonical_path, artifact.role, offset, offset + len(token), atom.evidence_id))
            if hit_limited:
                diagnostics.append("parameter_clue.hit_budget_exhausted")
                break
        status = "coverage_limited" if limited or hit_limited else "external_clue_observed" if occurrences else "no_external_clue"
        assessments.append(FrontendParameterClueAssessment(parameter.parameter_id, parameter.request_candidate_id, parameter.name, status, parameter.evidence_ids, tuple(occurrences)))

    return FrontendParameterClueIndex(
        CoverageStatus.PARTIAL if limited else CoverageStatus.COMPLETED,
        len(accepted), processed_bytes, _PRODUCER, tuple(assessments),
        tuple(sorted(evidence.values(), key=lambda item: item.evidence_id)),
        tuple(sorted(set(diagnostics))),
    )
