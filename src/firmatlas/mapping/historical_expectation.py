"""Compare historical vulnerability claims with an evidence-backed catalog."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from typing import Dict, Tuple

from .discovery_catalog import DiscoveryCandidateKind, DiscoveryCatalog
from .domain import CoverageStatus


HISTORICAL_EXPECTATION_DIFF_SCHEMA_VERSION = (
    "firmatlas.mapping.historical-expectation-diff/v1alpha1"
)
HISTORICAL_EXPECTATIONS_SCHEMA_VERSION = (
    "firmatlas.mapping.historical-expectations/v1alpha1"
)


class HistoricalApplicability(str, Enum):
    EXACT_ARTIFACT = "exact_artifact"
    PRODUCT_FAMILY = "product_family"
    UNKNOWN = "unknown"
    OUT_OF_SCOPE = "out_of_scope"


class HistoricalMatchStatus(str, Enum):
    OBSERVED = "observed"
    PARTIAL = "partial"
    MISSING = "missing"
    NOT_ASSESSABLE = "not_assessable"


class HistoricalGapReason(str, Enum):
    NONE = "none"
    PARAMETER_NOT_OBSERVED = "parameter_not_observed"
    METHOD_NOT_OBSERVED = "method_not_observed"
    DISPATCHER_BINDING_WITHOUT_INTERFACE = "dispatcher_binding_without_interface"
    INTERFACE_NOT_OBSERVED = "interface_not_observed"
    ARTIFACT_SCOPE_UNKNOWN = "artifact_scope_unknown"
    ARTIFACT_OUT_OF_SCOPE = "artifact_out_of_scope"
    COVERAGE_INCOMPLETE = "coverage_incomplete"


@dataclass(frozen=True)
class HistoricalInterfaceExpectation:
    vulnerability_identifier: str
    interface_value: str
    parameters: Tuple[str, ...]
    source_ref: str
    applicability: HistoricalApplicability
    method: str = ""
    handler_value: str = ""
    claimed_versions: Tuple[str, ...] = ()
    applicability_basis: str = ""

    def __post_init__(self) -> None:
        if not self.vulnerability_identifier.strip():
            raise ValueError("historical expectation requires vulnerability_identifier")
        if not self.interface_value.strip():
            raise ValueError("historical expectation requires interface_value")
        if not self.source_ref.strip():
            raise ValueError("historical expectation requires source_ref")
        if len(self.parameters) != len(set(self.parameters)):
            raise ValueError("duplicate historical expectation parameter")
        if len(self.claimed_versions) != len(set(self.claimed_versions)):
            raise ValueError("duplicate historical claimed version")

    @classmethod
    def from_dict(cls, value: dict) -> "HistoricalInterfaceExpectation":
        return cls(
            vulnerability_identifier=str(value["vulnerability_identifier"]),
            interface_value=str(value["interface_value"]),
            parameters=tuple(str(item) for item in value.get("parameters", ())),
            source_ref=str(value["source_ref"]),
            applicability=HistoricalApplicability(value["applicability"]),
            method=str(value.get("method") or "").upper(),
            handler_value=str(value.get("handler_value") or ""),
            claimed_versions=tuple(
                str(item) for item in value.get("claimed_versions", ())
            ),
            applicability_basis=str(value.get("applicability_basis") or ""),
        )

    def to_dict(self) -> dict:
        return {
            "expectation_id": self.expectation_id,
            "vulnerability_identifier": self.vulnerability_identifier,
            "interface_value": self.interface_value,
            "method": self.method or None,
            "handler_value": self.handler_value or None,
            "parameters": list(self.parameters),
            "source_ref": self.source_ref,
            "applicability": self.applicability.value,
            "claimed_versions": list(self.claimed_versions),
            "applicability_basis": self.applicability_basis,
        }

    @property
    def expectation_id(self) -> str:
        payload = json.dumps(
            (
                self.vulnerability_identifier,
                self.interface_value,
                self.method,
                self.handler_value,
                self.parameters,
                self.source_ref,
                self.applicability.value,
                self.claimed_versions,
                self.applicability_basis,
            ),
            separators=(",", ":"),
        ).encode()
        return "historical-expectation:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class HistoricalExpectationMatch:
    expectation_id: str
    vulnerability_identifier: str
    interface_value: str
    method: str
    handler_value: str
    expected_parameters: Tuple[str, ...]
    source_ref: str
    applicability: HistoricalApplicability
    claimed_versions: Tuple[str, ...]
    applicability_basis: str
    status: HistoricalMatchStatus
    gap_reason: HistoricalGapReason
    candidate_ids: Tuple[str, ...]
    catalog_evidence_ids: Tuple[str, ...]
    observed_methods: Tuple[str, ...]
    observed_parameters: Tuple[str, ...]
    missing_parameters: Tuple[str, ...]


@dataclass(frozen=True)
class HistoricalExpectationDiff:
    catalog_id: str
    catalog_coverage_status: CoverageStatus
    inventory_coverage_status: CoverageStatus
    entries: Tuple[HistoricalExpectationMatch, ...]
    summary: Dict[str, int]
    schema_version: str = HISTORICAL_EXPECTATION_DIFF_SCHEMA_VERSION

    @property
    def report_id(self) -> str:
        payload = json.dumps(
            {
                "schema_version": self.schema_version,
                "catalog_id": self.catalog_id,
                "catalog_coverage_status": self.catalog_coverage_status.value,
                "inventory_coverage_status": self.inventory_coverage_status.value,
                "entries": self._entry_documents(),
                "summary": self.summary,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return "historical-expectation-diff:" + hashlib.sha256(payload).hexdigest()

    def _entry_documents(self) -> list:
        return [
            {
                "expectation_id": item.expectation_id,
                "vulnerability_identifier": item.vulnerability_identifier,
                "interface_value": item.interface_value,
                "method": item.method or None,
                "handler_value": item.handler_value or None,
                "expected_parameters": list(item.expected_parameters),
                "source_ref": item.source_ref,
                "applicability": item.applicability.value,
                "claimed_versions": list(item.claimed_versions),
                "applicability_basis": item.applicability_basis,
                "status": item.status.value,
                "gap_reason": item.gap_reason.value,
                "candidate_ids": list(item.candidate_ids),
                "catalog_evidence_ids": list(item.catalog_evidence_ids),
                "observed_methods": list(item.observed_methods),
                "observed_parameters": list(item.observed_parameters),
                "missing_parameters": list(item.missing_parameters),
            }
            for item in self.entries
        ]

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "report_id": self.report_id,
            "catalog_id": self.catalog_id,
            "catalog_coverage_status": self.catalog_coverage_status.value,
            "inventory_coverage_status": self.inventory_coverage_status.value,
            "summary": dict(sorted(self.summary.items())),
            "entries": self._entry_documents(),
        }


def _interface_identity(value: str) -> str:
    return value.strip().lstrip("/")


def load_historical_expectations(document: dict) -> Tuple[HistoricalInterfaceExpectation, ...]:
    if document.get("schema_version") != HISTORICAL_EXPECTATIONS_SCHEMA_VERSION:
        raise ValueError("unsupported historical expectations schema_version")
    values = tuple(
        HistoricalInterfaceExpectation.from_dict(item)
        for item in document.get("expectations", ())
    )
    if not values:
        raise ValueError("historical expectations document must not be empty")
    if len({item.expectation_id for item in values}) != len(values):
        raise ValueError("duplicate historical expectation")
    return values


def compare_historical_expectations(
    catalog: DiscoveryCatalog,
    expectations: Tuple[HistoricalInterfaceExpectation, ...],
) -> HistoricalExpectationDiff:
    """Compare explicit historical claims without promoting them to firmware facts."""

    entries = []
    for expectation in sorted(expectations, key=lambda item: item.expectation_id):
        identity = _interface_identity(expectation.interface_value)
        candidates = tuple(
            candidate for candidate in catalog.candidates
            if candidate.candidate_kind == DiscoveryCandidateKind.REQUEST_INTERFACE
            and _interface_identity(candidate.canonical_identity) == identity
        )
        route_token = identity.rsplit("/", 1)[-1]
        native_candidates = tuple(
            candidate for candidate in catalog.candidates
            if candidate.candidate_kind in (
                DiscoveryCandidateKind.NATIVE_ROUTE_BINDING,
                DiscoveryCandidateKind.NATIVE_HINT,
            )
            and _interface_identity(candidate.canonical_identity) in {
                route_token, expectation.handler_value
            }
        )
        referenced_candidates = candidates if candidates else native_candidates
        candidate_ids = tuple(
            sorted(item.candidate_id for item in referenced_candidates)
        )
        parameters = tuple(
            parameter for parameter in catalog.parameters
            if parameter.owner_ref in set(candidate_ids)
        )
        observed_names = tuple(sorted({item.name for item in parameters}))
        observed_methods = tuple(sorted({
            dict(item.attributes).get("method", "").upper()
            for item in candidates
            if dict(item.attributes).get("method", "").strip()
        }))
        missing_names = tuple(
            name for name in expectation.parameters if name not in observed_names
        )
        evidence_ids = tuple(sorted({
            evidence_id
            for item in referenced_candidates for evidence_id in item.evidence_ids
        } | {
            evidence_id
            for item in parameters for evidence_id in item.evidence_ids
        }))
        status = (
            HistoricalMatchStatus.OBSERVED
            if (
                candidates
                and not missing_names
                and (not expectation.method or expectation.method in observed_methods)
            )
            else HistoricalMatchStatus.PARTIAL
            if candidates
            else HistoricalMatchStatus.NOT_ASSESSABLE
            if (
                expectation.applicability != HistoricalApplicability.EXACT_ARTIFACT
                or catalog.coverage_status != CoverageStatus.COMPLETED
                or catalog.source_inventory_coverage_status != CoverageStatus.COMPLETED
            )
            else HistoricalMatchStatus.MISSING
        )
        gap_reason = (
            HistoricalGapReason.NONE
            if status == HistoricalMatchStatus.OBSERVED
            else HistoricalGapReason.PARAMETER_NOT_OBSERVED
            if candidates and missing_names
            else HistoricalGapReason.METHOD_NOT_OBSERVED
            if candidates
            else HistoricalGapReason.ARTIFACT_OUT_OF_SCOPE
            if expectation.applicability == HistoricalApplicability.OUT_OF_SCOPE
            else HistoricalGapReason.ARTIFACT_SCOPE_UNKNOWN
            if expectation.applicability != HistoricalApplicability.EXACT_ARTIFACT
            else HistoricalGapReason.COVERAGE_INCOMPLETE
            if (
                catalog.coverage_status != CoverageStatus.COMPLETED
                or catalog.source_inventory_coverage_status != CoverageStatus.COMPLETED
            )
            else HistoricalGapReason.DISPATCHER_BINDING_WITHOUT_INTERFACE
            if native_candidates
            else HistoricalGapReason.INTERFACE_NOT_OBSERVED
        )
        entries.append(HistoricalExpectationMatch(
            expectation_id=expectation.expectation_id,
            vulnerability_identifier=expectation.vulnerability_identifier,
            interface_value=expectation.interface_value,
            method=expectation.method,
            handler_value=expectation.handler_value,
            expected_parameters=expectation.parameters,
            source_ref=expectation.source_ref,
            applicability=expectation.applicability,
            claimed_versions=expectation.claimed_versions,
            applicability_basis=expectation.applicability_basis,
            status=status,
            gap_reason=gap_reason,
            candidate_ids=candidate_ids,
            catalog_evidence_ids=evidence_ids,
            observed_methods=observed_methods,
            observed_parameters=observed_names,
            missing_parameters=missing_names,
        ))
    summary: Dict[str, int] = {}
    for entry in entries:
        summary[entry.status.value] = summary.get(entry.status.value, 0) + 1
    return HistoricalExpectationDiff(
        catalog.catalog_id,
        catalog.coverage_status,
        catalog.source_inventory_coverage_status,
        tuple(entries),
        summary,
    )
