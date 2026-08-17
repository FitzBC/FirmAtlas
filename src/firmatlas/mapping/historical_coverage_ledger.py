"""Project the complete historical denominator into an auditable coverage ledger.

The ledger is a contextual read model.  It joins structured expectations with
the unresolved work queue, but never promotes historical text or catalog clues
into firmware graph facts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
from typing import Dict, Tuple

from .historical_coverage_queue import (
    HistoricalCoverageQueue,
    HistoricalEvidenceState,
)
from .historical_expectation import HistoricalMatchStatus
from .historical_graph_overlay import HistoricalGraphOverlay


HISTORICAL_COVERAGE_LEDGER_SCHEMA_VERSION = (
    "firmatlas.mapping.historical-coverage-ledger/v1alpha1"
)
HISTORICAL_COVERAGE_LEDGER_CLAIM_BOUNDARY = (
    "Historical coverage states describe evidence availability and structural "
    "observation only; they do not assert vulnerability presence, reachability, "
    "or exploitability."
)


class HistoricalCoverageLedgerStatus(str, Enum):
    OBSERVED = "observed"
    PARTIAL = "partial"
    NOT_FOUND = "not_found"
    NOT_ASSESSABLE = "not_assessable"


@dataclass(frozen=True)
class HistoricalCoverageLedgerEntry:
    vulnerability_identifier: str
    audit_category: str
    status: HistoricalCoverageLedgerStatus
    reason_codes: Tuple[str, ...]
    reason_explanations: Tuple[str, ...]
    action: str
    evidence_state: str
    applicabilities: Tuple[str, ...]
    claimed_versions: Tuple[str, ...]
    applicability_bases: Tuple[str, ...]
    interface_values: Tuple[str, ...]
    methods: Tuple[str, ...]
    handler_values: Tuple[str, ...]
    expected_parameters: Tuple[str, ...]
    observed_parameters: Tuple[str, ...]
    missing_parameters: Tuple[str, ...]
    configuration_keys: Tuple[str, ...]
    source_refs: Tuple[str, ...]
    catalog_candidate_ids: Tuple[str, ...]
    catalog_evidence_ids: Tuple[str, ...]
    graph_node_ids: Tuple[str, ...]
    graph_edge_ids: Tuple[str, ...]

    def to_dict(self) -> dict:
        value = asdict(self)
        value["status"] = self.status.value
        for key, item in tuple(value.items()):
            if isinstance(item, tuple):
                value[key] = list(item)
        return value

    @classmethod
    def from_dict(cls, value: dict) -> "HistoricalCoverageLedgerEntry":
        tuple_fields = {
            "reason_codes", "reason_explanations", "applicabilities",
            "claimed_versions", "applicability_bases", "interface_values",
            "methods", "handler_values", "expected_parameters",
            "observed_parameters", "missing_parameters", "configuration_keys",
            "source_refs", "catalog_candidate_ids", "catalog_evidence_ids",
            "graph_node_ids", "graph_edge_ids",
        }
        return cls(**{
            **{
                key: tuple(value.get(key, ()))
                for key in tuple_fields
            },
            "vulnerability_identifier": str(value["vulnerability_identifier"]),
            "audit_category": str(value["audit_category"]),
            "status": HistoricalCoverageLedgerStatus(value["status"]),
            "action": str(value.get("action") or ""),
            "evidence_state": str(value.get("evidence_state") or ""),
        })


@dataclass(frozen=True)
class HistoricalCoverageLedger:
    graph_id: str
    catalog_id: str
    overlay_id: str
    queue_id: str
    audit_id: str
    total_vulnerability_count: int
    entries: Tuple[HistoricalCoverageLedgerEntry, ...]
    summary: Dict[str, Dict[str, int]]
    claim_boundary: str = HISTORICAL_COVERAGE_LEDGER_CLAIM_BOUNDARY
    schema_version: str = HISTORICAL_COVERAGE_LEDGER_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != HISTORICAL_COVERAGE_LEDGER_SCHEMA_VERSION:
            raise ValueError("unsupported historical coverage ledger schema_version")
        if self.claim_boundary != HISTORICAL_COVERAGE_LEDGER_CLAIM_BOUNDARY:
            raise ValueError("historical coverage ledger claim boundary cannot change")
        if len(self.entries) != self.total_vulnerability_count:
            raise ValueError("historical coverage ledger does not cover denominator")
        identifiers = [item.vulnerability_identifier for item in self.entries]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("duplicate vulnerability in historical coverage ledger")
        expected = {"status": {}, "audit_category": {}, "evidence_state": {}}
        for entry in self.entries:
            _increment(expected["status"], entry.status.value)
            _increment(expected["audit_category"], entry.audit_category)
            _increment(expected["evidence_state"], entry.evidence_state or "structured")
        if self.summary != expected:
            raise ValueError("historical coverage ledger summary does not match entries")

    @property
    def ledger_id(self) -> str:
        encoded = json.dumps(
            self.to_dict(include_id=False), separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        return "historical-coverage-ledger:" + hashlib.sha256(encoded).hexdigest()

    def to_dict(self, *, include_id: bool = True) -> dict:
        value = {
            "schema_version": self.schema_version,
            "graph_id": self.graph_id,
            "catalog_id": self.catalog_id,
            "overlay_id": self.overlay_id,
            "queue_id": self.queue_id,
            "audit_id": self.audit_id,
            "total_vulnerability_count": self.total_vulnerability_count,
            "claim_boundary": self.claim_boundary,
            "summary": {
                key: dict(sorted(counts.items()))
                for key, counts in sorted(self.summary.items())
            },
            "entries": [item.to_dict() for item in self.entries],
        }
        if include_id:
            value["ledger_id"] = self.ledger_id
        return value

    @classmethod
    def from_dict(cls, value: dict) -> "HistoricalCoverageLedger":
        ledger = cls(
            graph_id=str(value["graph_id"]),
            catalog_id=str(value["catalog_id"]),
            overlay_id=str(value["overlay_id"]),
            queue_id=str(value["queue_id"]),
            audit_id=str(value["audit_id"]),
            total_vulnerability_count=int(value["total_vulnerability_count"]),
            entries=tuple(
                HistoricalCoverageLedgerEntry.from_dict(item)
                for item in value["entries"]
            ),
            summary={
                str(key): {str(name): int(count) for name, count in counts.items()}
                for key, counts in value["summary"].items()
            },
            claim_boundary=str(value["claim_boundary"]),
            schema_version=str(value["schema_version"]),
        )
        if value.get("ledger_id") not in (None, ledger.ledger_id):
            raise ValueError("historical coverage ledger identity does not match content")
        return ledger


def _increment(counts: Dict[str, int], value: str) -> None:
    counts[value] = counts.get(value, 0) + 1


def _unique(values) -> Tuple[str, ...]:
    return tuple(sorted({item for item in values if item}))


def _overlay_status(entries) -> HistoricalCoverageLedgerStatus:
    states = {item.status for item in entries}
    if states == {HistoricalMatchStatus.OBSERVED}:
        return HistoricalCoverageLedgerStatus.OBSERVED
    if states == {HistoricalMatchStatus.NOT_ASSESSABLE}:
        return HistoricalCoverageLedgerStatus.NOT_ASSESSABLE
    if states == {HistoricalMatchStatus.MISSING}:
        return HistoricalCoverageLedgerStatus.NOT_FOUND
    return HistoricalCoverageLedgerStatus.PARTIAL


def _queue_status(evidence_state: HistoricalEvidenceState) -> HistoricalCoverageLedgerStatus:
    if evidence_state in {
        HistoricalEvidenceState.SOURCE_VERIFIED,
        HistoricalEvidenceState.SOURCE_PARTIAL,
        HistoricalEvidenceState.CATALOG_CLUE_ONLY,
    }:
        return HistoricalCoverageLedgerStatus.PARTIAL
    return HistoricalCoverageLedgerStatus.NOT_ASSESSABLE


def build_historical_coverage_ledger(
    overlay: HistoricalGraphOverlay,
    queue: HistoricalCoverageQueue,
) -> HistoricalCoverageLedger:
    """Join one immutable overlay and its complementary queue by CVE identity."""

    audit = overlay.vulnerability_audit
    if audit is None:
        raise ValueError("historical coverage ledger requires vulnerability audit")
    if queue.audit_id != audit.audit_id:
        raise ValueError("historical coverage ledger inputs must reference same audit")
    if queue.catalog_id != overlay.catalog_id:
        raise ValueError("historical coverage ledger inputs must reference same catalog")

    grouped = {}
    for item in overlay.entries:
        grouped.setdefault(item.vulnerability_identifier, []).append(item)
    queue_ids = {item.vulnerability_identifier for item in queue.entries}
    if set(grouped) & queue_ids:
        raise ValueError("historical overlay and queue must be complementary")

    entries = []
    for identifier, matches in grouped.items():
        entries.append(HistoricalCoverageLedgerEntry(
            vulnerability_identifier=identifier,
            audit_category="compared_interface",
            status=_overlay_status(matches),
            reason_codes=_unique(item.gap_reason.value for item in matches),
            reason_explanations=_unique(item.gap_explanation for item in matches),
            action="none",
            evidence_state="structured",
            applicabilities=_unique(item.applicability.value for item in matches),
            claimed_versions=_unique(
                value for item in matches for value in item.claimed_versions
            ),
            applicability_bases=_unique(item.applicability_basis for item in matches),
            interface_values=_unique(item.interface_value for item in matches),
            methods=_unique(item.method for item in matches),
            handler_values=_unique(item.handler_value for item in matches),
            expected_parameters=_unique(
                value for item in matches for value in item.expected_parameters
            ),
            observed_parameters=_unique(
                value for item in matches for value in item.observed_parameters
            ),
            missing_parameters=_unique(
                value for item in matches for value in item.missing_parameters
            ),
            configuration_keys=(),
            source_refs=_unique(item.source_ref for item in matches),
            catalog_candidate_ids=_unique(
                value for item in matches for value in item.catalog_candidate_ids
            ),
            catalog_evidence_ids=_unique(
                value for item in matches for value in item.catalog_evidence_ids
            ),
            graph_node_ids=_unique(
                value for item in matches for value in item.graph_node_ids
            ),
            graph_edge_ids=_unique(
                value for item in matches for value in item.graph_edge_ids
            ),
        ))

    for item in queue.entries:
        entries.append(HistoricalCoverageLedgerEntry(
            vulnerability_identifier=item.vulnerability_identifier,
            audit_category=item.audit_category,
            status=_queue_status(item.evidence_state),
            reason_codes=item.reason_codes,
            reason_explanations=(),
            action=item.action.value,
            evidence_state=item.evidence_state.value,
            applicabilities=(),
            claimed_versions=(),
            applicability_bases=(),
            interface_values=item.source_verified_interfaces,
            methods=(),
            handler_values=item.handler_names,
            expected_parameters=item.source_verified_parameters,
            observed_parameters=item.observed_parameters,
            missing_parameters=item.missing_compound_parameters,
            configuration_keys=item.configuration_keys,
            source_refs=item.source_refs,
            catalog_candidate_ids=item.catalog_candidate_ids,
            catalog_evidence_ids=(),
            graph_node_ids=(),
            graph_edge_ids=(),
        ))

    ordered = tuple(sorted(entries, key=lambda item: item.vulnerability_identifier))
    summary = {"status": {}, "audit_category": {}, "evidence_state": {}}
    for item in ordered:
        _increment(summary["status"], item.status.value)
        _increment(summary["audit_category"], item.audit_category)
        _increment(summary["evidence_state"], item.evidence_state or "structured")
    return HistoricalCoverageLedger(
        graph_id=overlay.graph_id,
        catalog_id=overlay.catalog_id,
        overlay_id=overlay.overlay_id,
        queue_id=queue.queue_id,
        audit_id=audit.audit_id,
        total_vulnerability_count=audit.total_vulnerability_count,
        entries=ordered,
        summary=summary,
    )
