"""Deterministic candidate correlation across independent mapping producers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
from typing import Tuple

from .domain import CoverageStatus
from .frontend import FrontendEndpointShape, FrontendProducerResult
from .native import NativeHintKind, NativeProducerResult


CORRELATION_RESULT_SCHEMA_VERSION = "firmatlas.mapping.correlation-result/v1alpha1"
_RULE_VERSION = "frontend-native-exact/v1"


class CorrelationMatchBasis(str, Enum):
    EXACT_ENDPOINT = "exact_endpoint"
    EXACT_COMPONENT = "exact_component"


class CandidateAssociationStatus(str, Enum):
    CANDIDATE = "candidate"


@dataclass(frozen=True)
class CorrelationPolicy:
    max_associations: int = 50_000

    def __post_init__(self) -> None:
        if self.max_associations <= 0:
            raise ValueError("correlation association budget must be positive")


@dataclass(frozen=True)
class CandidateAssociation:
    association_id: str
    frontend_candidate_id: str
    native_hint_id: str
    native_source_path: str
    match_basis: CorrelationMatchBasis
    status: CandidateAssociationStatus
    evidence_ids: Tuple[str, ...]
    rule_version: str = _RULE_VERSION


@dataclass(frozen=True)
class CorrelationObligation:
    obligation_id: str
    target_ref: str
    target_kind: str
    required_capability: str
    reason: str
    candidate_analyzers: Tuple[str, ...]
    priority: int


@dataclass(frozen=True)
class UnmatchedFrontendCandidate:
    frontend_candidate_id: str
    endpoint: str
    reason: str


@dataclass(frozen=True)
class CorrelationDiagnostic:
    code: str
    message: str


@dataclass(frozen=True)
class FrontendNativeCorrelationResult:
    coverage_status: CoverageStatus
    associations: Tuple[CandidateAssociation, ...]
    obligations: Tuple[CorrelationObligation, ...]
    unmatched_frontend_candidates: Tuple[UnmatchedFrontendCandidate, ...]
    diagnostics: Tuple[CorrelationDiagnostic, ...] = ()
    rule_version: str = _RULE_VERSION
    schema_version: str = CORRELATION_RESULT_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "rule_version": self.rule_version,
            "coverage_status": self.coverage_status.value,
            "associations": [
                {
                    **asdict(item),
                    "match_basis": item.match_basis.value,
                    "status": item.status.value,
                }
                for item in self.associations
            ],
            "obligations": [asdict(item) for item in self.obligations],
            "unmatched_frontend_candidates": [
                asdict(item) for item in self.unmatched_frontend_candidates
            ],
            "diagnostics": [asdict(item) for item in self.diagnostics],
        }


def _stable_id(prefix: str, payload: dict) -> str:
    encoded = json.dumps(
        payload, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "{}:{}".format(prefix, hashlib.sha256(encoded).hexdigest())


def _endpoint_component(endpoint: str) -> str:
    path = endpoint.split("?", 1)[0].rstrip("/")
    return path.rsplit("/", 1)[-1]


def _obligations(association_id: str) -> tuple:
    values = []
    for priority, capability in ((90, "registers_route"), (80, "binds_handler")):
        values.append(
            CorrelationObligation(
                obligation_id=_stable_id(
                    "correlation-obligation",
                    {
                        "association_id": association_id,
                        "required_capability": capability,
                        "rule_version": _RULE_VERSION,
                    },
                ),
                target_ref=association_id,
                target_kind="candidate_association",
                required_capability=capability,
                reason=(
                    "exact string corroboration does not prove {}".format(capability)
                ),
                candidate_analyzers=("native-deep", "runtime"),
                priority=priority,
            )
        )
    return tuple(values)


def _unmatched_obligation(frontend_candidate_id: str) -> CorrelationObligation:
    capability = "registers_route"
    return CorrelationObligation(
        obligation_id=_stable_id(
            "correlation-obligation",
            {
                "frontend_candidate_id": frontend_candidate_id,
                "required_capability": capability,
                "rule_version": _RULE_VERSION,
            },
        ),
        target_ref=frontend_candidate_id,
        target_kind="frontend_candidate",
        required_capability=capability,
        reason="frontend request construction has no exact backend route hint",
        candidate_analyzers=("script-backend", "native-deep", "runtime"),
        priority=95,
    )


def correlate_frontend_native(
    frontend_results: Tuple[FrontendProducerResult, ...],
    native_results: Tuple[NativeProducerResult, ...],
    policy: CorrelationPolicy = CorrelationPolicy(),
) -> FrontendNativeCorrelationResult:
    """Correlate exact request strings while preserving candidate-only status."""

    if not frontend_results or not native_results:
        return FrontendNativeCorrelationResult(
            coverage_status=CoverageStatus.NOT_APPLICABLE,
            associations=(),
            obligations=(),
            unmatched_frontend_candidates=(),
            diagnostics=(
                CorrelationDiagnostic(
                    "missing_producer_inputs",
                    "frontend and native producer results are both required",
                ),
            ),
        )

    associations = []
    obligations = []
    unmatched = []
    budget_exceeded = False
    processed_frontend_ids = set()
    association_ids = set()
    frontend_candidates = sorted(
        (candidate for result in frontend_results for candidate in result.candidates),
        key=lambda candidate: candidate.candidate_id,
    )
    native_hints = sorted(
        (
            (result.source_path, hint)
            for result in native_results
            for hint in result.hints
        ),
        key=lambda item: (item[0], item[1].hint_id),
    )
    for candidate in frontend_candidates:
        if candidate.candidate_id in processed_frontend_ids:
            continue
        processed_frontend_ids.add(candidate.candidate_id)
        component = _endpoint_component(candidate.endpoint)
        candidate_matches = []
        found_match = False
        for native_source_path, hint in native_hints:
            if (
                hint.kind is NativeHintKind.ENDPOINT_LITERAL
                and candidate.endpoint_shape is FrontendEndpointShape.EXACT_LITERAL
                and hint.value == candidate.endpoint
            ):
                basis = CorrelationMatchBasis.EXACT_ENDPOINT
            elif hint.kind is NativeHintKind.ROUTE_TOKEN and (
                hint.value == component
            ):
                basis = CorrelationMatchBasis.EXACT_COMPONENT
            else:
                continue
            found_match = True
            association_id = _stable_id(
                "frontend-native-association",
                {
                    "frontend_candidate_id": candidate.candidate_id,
                    "native_hint_id": hint.hint_id,
                    "rule_version": _RULE_VERSION,
                },
            )
            if association_id in association_ids:
                continue
            if (
                len(associations) + len(candidate_matches)
                >= policy.max_associations
            ):
                budget_exceeded = True
                continue
            association = CandidateAssociation(
                association_id=association_id,
                frontend_candidate_id=candidate.candidate_id,
                native_hint_id=hint.hint_id,
                native_source_path=native_source_path,
                match_basis=basis,
                status=CandidateAssociationStatus.CANDIDATE,
                evidence_ids=tuple(
                    dict.fromkeys((*candidate.evidence_ids, *hint.evidence_ids))
                ),
            )
            candidate_matches.append(association)
            association_ids.add(association_id)
            obligations.extend(_obligations(association_id))
        if found_match:
            associations.extend(candidate_matches)
        else:
            unmatched.append(
                UnmatchedFrontendCandidate(
                    frontend_candidate_id=candidate.candidate_id,
                    endpoint=candidate.endpoint,
                    reason="no_case_sensitive_exact_native_hint",
                )
            )
            obligations.append(_unmatched_obligation(candidate.candidate_id))
    incomplete = any(
        result.coverage_status is not CoverageStatus.COMPLETED
        for result in (*frontend_results, *native_results)
    )
    diagnostics = []
    if budget_exceeded:
        diagnostics.append(
            CorrelationDiagnostic(
                "association_budget_exceeded",
                "association budget truncated frontend/native correlation",
            )
        )
    if incomplete:
        diagnostics.append(
            CorrelationDiagnostic(
                "upstream_coverage_incomplete",
                "candidate correlation used one or more incomplete producer results",
            )
        )
    return FrontendNativeCorrelationResult(
        coverage_status=(
            CoverageStatus.PARTIAL
            if diagnostics
            else CoverageStatus.COMPLETED
        ),
        associations=tuple(associations),
        obligations=tuple(obligations),
        unmatched_frontend_candidates=tuple(unmatched),
        diagnostics=tuple(diagnostics),
    )
