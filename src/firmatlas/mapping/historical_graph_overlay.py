"""Project historical vulnerability comparisons onto a communication graph.

The overlay is a read model. Historical claims remain contextual input and can
never create or change firmware graph nodes, edges, or observation statuses.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Dict, Optional, Tuple

from .communication_graph import (
    CommunicationArchitectureGraph,
    CommunicationGraphEdgeKind,
    CommunicationGraphNodeKind,
)
from .historical_expectation import (
    HistoricalApplicability,
    HistoricalExpectationDiff,
    HistoricalGapReason,
    HistoricalMatchStatus,
    HistoricalRouteBindingReport,
    HistoricalRouteBindingStatus,
    HistoricalVulnerabilityAudit,
)


HISTORICAL_GRAPH_OVERLAY_SCHEMA_VERSION = (
    "firmatlas.mapping.historical-graph-overlay/v1alpha1"
)
HISTORICAL_GRAPH_OVERLAY_CLAIM_BOUNDARY = (
    "Historical vulnerability claims are contextual expectations only; "
    "graph links visualize exact catalog references and do not assert "
    "vulnerability presence or firmware-version applicability."
)


_GAP_EXPLANATIONS = {
    HistoricalGapReason.NONE: (
        "The expected interface, method, and parameters were observed in the "
        "evidence-backed catalog."
    ),
    HistoricalGapReason.PARAMETER_NOT_OBSERVED: (
        "The interface was observed, but one or more expected parameters were "
        "not observed in the analyzed evidence."
    ),
    HistoricalGapReason.METHOD_NOT_OBSERVED: (
        "The interface was observed, but the expected transport method was not "
        "observed in the analyzed evidence."
    ),
    HistoricalGapReason.DISPATCHER_BINDING_WITHOUT_INTERFACE: (
        "A native dispatcher clue was observed, but no matching request "
        "interface was recovered."
    ),
    HistoricalGapReason.INTERFACE_NOT_OBSERVED: (
        "The expected interface was not observed despite complete catalog and "
        "source-inventory coverage for this artifact."
    ),
    HistoricalGapReason.ARTIFACT_SCOPE_UNKNOWN: (
        "The historical claim cannot be assessed because its applicability to "
        "this exact firmware artifact is unknown."
    ),
    HistoricalGapReason.ARTIFACT_OUT_OF_SCOPE: (
        "The historical claim targets a different firmware artifact or version "
        "lineage; structural overlap is shown separately when present."
    ),
    HistoricalGapReason.COVERAGE_INCOMPLETE: (
        "The expected interface was not observed, but incomplete analysis or "
        "inventory coverage prevents a missing conclusion."
    ),
}


@dataclass(frozen=True)
class HistoricalGraphOverlayAudit:
    audit_id: str
    total_vulnerability_count: int
    category_counts: Dict[str, int]
    exact_artifact_expectation_count: int
    exact_artifact_observed_count: int


@dataclass(frozen=True)
class HistoricalGraphOverlayEntry:
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
    gap_explanation: str
    observed_methods: Tuple[str, ...]
    observed_parameters: Tuple[str, ...]
    missing_parameters: Tuple[str, ...]
    catalog_candidate_ids: Tuple[str, ...]
    catalog_evidence_ids: Tuple[str, ...]
    route_binding_status: Optional[HistoricalRouteBindingStatus]
    observed_handlers: Tuple[str, ...]
    graph_node_ids: Tuple[str, ...]
    graph_edge_ids: Tuple[str, ...]
    graph_link_bases: Tuple[str, ...]
    unmapped_catalog_reference_ids: Tuple[str, ...]
    unmapped_catalog_evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class HistoricalGraphOverlay:
    graph_id: str
    catalog_id: str
    expectation_diff_id: str
    route_binding_report_id: str
    claim_boundary: str
    entries: Tuple[HistoricalGraphOverlayEntry, ...]
    summary: Dict[str, Dict[str, int]]
    diagnostics: Tuple[str, ...]
    vulnerability_audit: Optional[HistoricalGraphOverlayAudit] = None
    schema_version: str = HISTORICAL_GRAPH_OVERLAY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != HISTORICAL_GRAPH_OVERLAY_SCHEMA_VERSION:
            raise ValueError("unsupported historical graph overlay schema_version")
        if not self.graph_id.startswith("communication-graph:"):
            raise ValueError("historical overlay requires communication graph identity")
        if not self.catalog_id.startswith("discovery-catalog:"):
            raise ValueError("historical overlay requires discovery catalog identity")
        if not self.expectation_diff_id.startswith(
            "historical-expectation-diff:"
        ):
            raise ValueError("historical overlay requires expectation diff identity")
        if self.claim_boundary != HISTORICAL_GRAPH_OVERLAY_CLAIM_BOUNDARY:
            raise ValueError("historical overlay claim boundary cannot be changed")
        if (
            self.route_binding_report_id
            and not self.route_binding_report_id.startswith(
                "historical-route-binding:"
            )
        ):
            raise ValueError(
                "historical overlay requires route-binding report identity"
            )
        expectation_ids = [item.expectation_id for item in self.entries]
        if len(expectation_ids) != len(set(expectation_ids)):
            raise ValueError("duplicate historical overlay expectation identity")
        for entry in self.entries:
            if len(entry.graph_node_ids) != len(set(entry.graph_node_ids)):
                raise ValueError("duplicate historical overlay graph node reference")
            if len(entry.graph_edge_ids) != len(set(entry.graph_edge_ids)):
                raise ValueError("duplicate historical overlay graph edge reference")
            if entry.gap_explanation != _GAP_EXPLANATIONS[entry.gap_reason]:
                raise ValueError(
                    "historical overlay gap explanation must match reason"
                )
        expected_summary: Dict[str, Dict[str, int]] = {
            "status": {},
            "applicability": {},
            "gap_reason": {},
            "route_binding_status": {},
        }
        for entry in self.entries:
            _increment(expected_summary["status"], entry.status.value)
            _increment(
                expected_summary["applicability"], entry.applicability.value
            )
            _increment(expected_summary["gap_reason"], entry.gap_reason.value)
            if entry.route_binding_status:
                _increment(
                    expected_summary["route_binding_status"],
                    entry.route_binding_status.value,
                )
        if self.summary != expected_summary:
            raise ValueError("historical overlay summary does not match entries")

    @property
    def overlay_id(self) -> str:
        document = self.to_dict(include_id=False)
        encoded = json.dumps(
            document, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        return "historical-graph-overlay:" + hashlib.sha256(encoded).hexdigest()

    def to_dict(self, *, include_id: bool = True) -> dict:
        document = {
            "schema_version": self.schema_version,
            "graph_id": self.graph_id,
            "catalog_id": self.catalog_id,
            "expectation_diff_id": self.expectation_diff_id,
            "route_binding_report_id": self.route_binding_report_id or None,
            "claim_boundary": self.claim_boundary,
            "summary": {
                key: dict(sorted(value.items()))
                for key, value in sorted(self.summary.items())
            },
            "entries": [
                {
                    **asdict(item),
                    "applicability": item.applicability.value,
                    "status": item.status.value,
                    "gap_reason": item.gap_reason.value,
                    "route_binding_status": (
                        item.route_binding_status.value
                        if item.route_binding_status else None
                    ),
                    "expected_parameters": list(item.expected_parameters),
                    "claimed_versions": list(item.claimed_versions),
                    "observed_methods": list(item.observed_methods),
                    "observed_parameters": list(item.observed_parameters),
                    "missing_parameters": list(item.missing_parameters),
                    "catalog_candidate_ids": list(item.catalog_candidate_ids),
                    "catalog_evidence_ids": list(item.catalog_evidence_ids),
                    "observed_handlers": list(item.observed_handlers),
                    "graph_node_ids": list(item.graph_node_ids),
                    "graph_edge_ids": list(item.graph_edge_ids),
                    "graph_link_bases": list(item.graph_link_bases),
                    "unmapped_catalog_reference_ids": list(
                        item.unmapped_catalog_reference_ids
                    ),
                    "unmapped_catalog_evidence_ids": list(
                        item.unmapped_catalog_evidence_ids
                    ),
                }
                for item in self.entries
            ],
            "diagnostics": list(self.diagnostics),
            "vulnerability_audit": (
                {
                    **asdict(self.vulnerability_audit),
                    "category_counts": dict(sorted(
                        self.vulnerability_audit.category_counts.items()
                    )),
                }
                if self.vulnerability_audit else None
            ),
        }
        if include_id:
            document["overlay_id"] = self.overlay_id
        return document

    @classmethod
    def from_dict(cls, value: dict) -> "HistoricalGraphOverlay":
        try:
            audit_value = value.get("vulnerability_audit")
            overlay = cls(
                graph_id=str(value["graph_id"]),
                catalog_id=str(value["catalog_id"]),
                expectation_diff_id=str(value["expectation_diff_id"]),
                route_binding_report_id=str(
                    value.get("route_binding_report_id") or ""
                ),
                claim_boundary=str(value["claim_boundary"]),
                entries=tuple(
                    HistoricalGraphOverlayEntry(
                        expectation_id=str(item["expectation_id"]),
                        vulnerability_identifier=str(
                            item["vulnerability_identifier"]
                        ),
                        interface_value=str(item["interface_value"]),
                        method=str(item.get("method") or ""),
                        handler_value=str(item.get("handler_value") or ""),
                        expected_parameters=tuple(
                            item.get("expected_parameters", ())
                        ),
                        source_ref=str(item["source_ref"]),
                        applicability=HistoricalApplicability(
                            item["applicability"]
                        ),
                        claimed_versions=tuple(item.get("claimed_versions", ())),
                        applicability_basis=str(
                            item.get("applicability_basis") or ""
                        ),
                        status=HistoricalMatchStatus(item["status"]),
                        gap_reason=HistoricalGapReason(item["gap_reason"]),
                        gap_explanation=str(item["gap_explanation"]),
                        observed_methods=tuple(item.get("observed_methods", ())),
                        observed_parameters=tuple(
                            item.get("observed_parameters", ())
                        ),
                        missing_parameters=tuple(
                            item.get("missing_parameters", ())
                        ),
                        catalog_candidate_ids=tuple(
                            item.get("catalog_candidate_ids", ())
                        ),
                        catalog_evidence_ids=tuple(
                            item.get("catalog_evidence_ids", ())
                        ),
                        route_binding_status=(
                            HistoricalRouteBindingStatus(
                                item["route_binding_status"]
                            )
                            if item.get("route_binding_status") else None
                        ),
                        observed_handlers=tuple(
                            item.get("observed_handlers", ())
                        ),
                        graph_node_ids=tuple(item.get("graph_node_ids", ())),
                        graph_edge_ids=tuple(item.get("graph_edge_ids", ())),
                        graph_link_bases=tuple(
                            item.get("graph_link_bases", ())
                        ),
                        unmapped_catalog_reference_ids=tuple(
                            item.get("unmapped_catalog_reference_ids", ())
                        ),
                        unmapped_catalog_evidence_ids=tuple(
                            item.get("unmapped_catalog_evidence_ids", ())
                        ),
                    )
                    for item in value["entries"]
                ),
                summary={
                    str(key): {
                        str(name): int(count)
                        for name, count in counts.items()
                    }
                    for key, counts in value["summary"].items()
                },
                diagnostics=tuple(value.get("diagnostics", ())),
                vulnerability_audit=(
                    HistoricalGraphOverlayAudit(
                        audit_id=str(audit_value["audit_id"]),
                        total_vulnerability_count=int(
                            audit_value["total_vulnerability_count"]
                        ),
                        category_counts={
                            str(key): int(count)
                            for key, count in audit_value[
                                "category_counts"
                            ].items()
                        },
                        exact_artifact_expectation_count=int(
                            audit_value["exact_artifact_expectation_count"]
                        ),
                        exact_artifact_observed_count=int(
                            audit_value["exact_artifact_observed_count"]
                        ),
                    ) if audit_value else None
                ),
                schema_version=str(value["schema_version"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, ValueError):
                raise
            raise ValueError("invalid historical graph overlay document") from exc
        supplied_id = value.get("overlay_id")
        if supplied_id is not None and supplied_id != overlay.overlay_id:
            raise ValueError("historical graph overlay identity does not match content")
        return overlay


def _increment(summary: Dict[str, int], value: str) -> None:
    summary[value] = summary.get(value, 0) + 1


def project_historical_graph_overlay(
    graph: CommunicationArchitectureGraph,
    diff: HistoricalExpectationDiff,
    route_binding_report: Optional[HistoricalRouteBindingReport] = None,
    vulnerability_audit: Optional[HistoricalVulnerabilityAudit] = None,
) -> HistoricalGraphOverlay:
    """Link an expectation diff to exact graph references without promotion."""

    if graph.source_catalog_id != diff.catalog_id:
        raise ValueError("historical overlay inputs must reference the same catalog")
    if (
        route_binding_report is not None
        and route_binding_report.catalog_id != diff.catalog_id
    ):
        raise ValueError("historical overlay inputs must reference the same catalog")
    if (
        vulnerability_audit is not None
        and vulnerability_audit.expectation_diff_id != diff.report_id
    ):
        raise ValueError(
            "historical vulnerability audit must reference the expectation diff"
        )

    nodes = {item.node_id: item for item in graph.nodes}
    route_entries = {
        item.expectation_id: item
        for item in route_binding_report.entries
    } if route_binding_report else {}
    if len(route_entries) != len(
        route_binding_report.entries if route_binding_report else ()
    ):
        raise ValueError("duplicate route-binding expectation identity")

    status_summary: Dict[str, int] = {}
    applicability_summary: Dict[str, int] = {}
    gap_summary: Dict[str, int] = {}
    route_summary: Dict[str, int] = {}
    diagnostics = []
    entries = []
    for match in diff.entries:
        route = route_entries.get(match.expectation_id)
        reference_ids = set(match.candidate_ids)
        if route:
            reference_ids.update(route.route_binding_ids)
            reference_ids.update(route.native_clue_ids)
        graph_node_ids = reference_ids & nodes.keys()
        link_bases = set()
        if set(match.candidate_ids) & graph_node_ids:
            link_bases.add("catalog_candidate_id")
        if route and set(route.route_binding_ids) & graph_node_ids:
            link_bases.add("route_binding_id")
        if route and set(route.native_clue_ids) & graph_node_ids:
            link_bases.add("native_clue_id")

        parameter_names = set(match.expected_parameters) | set(
            match.observed_parameters
        )
        for edge in graph.edges:
            target = nodes[edge.target_ref]
            if (
                edge.edge_kind is CommunicationGraphEdgeKind.ACCEPTS_PARAMETER
                and edge.source_ref in set(match.candidate_ids)
                and target.node_kind is CommunicationGraphNodeKind.PARAMETER
                and target.label in parameter_names
            ):
                graph_node_ids.add(edge.target_ref)
                link_bases.add("parameter_owner_edge")

        # Add exact handler targets reachable from a selected route binding.
        for edge in graph.edges:
            if (
                edge.edge_kind is CommunicationGraphEdgeKind.BINDS_HANDLER
                and edge.source_ref in graph_node_ids
            ):
                graph_node_ids.add(edge.target_ref)
                link_bases.add("route_handler_edge")

        graph_edge_ids = tuple(sorted(
            edge.edge_id for edge in graph.edges
            if edge.source_ref in graph_node_ids
            and edge.target_ref in graph_node_ids
            and edge.edge_kind is not CommunicationGraphEdgeKind.DECLARED_IN_ARTIFACT
        ))
        mapped_evidence = {
            evidence_id
            for node_id in graph_node_ids
            for evidence_id in nodes[node_id].evidence_ids
        }
        mapped_evidence.update(
            evidence_id
            for edge in graph.edges
            if edge.edge_id in set(graph_edge_ids)
            for evidence_id in edge.evidence_ids
        )
        unmapped_refs = tuple(sorted(reference_ids - graph_node_ids))
        unmapped_evidence = tuple(sorted(
            set(match.catalog_evidence_ids) - mapped_evidence
        ))
        if unmapped_refs:
            diagnostics.append(
                f"{match.expectation_id}: catalog references absent from graph: "
                + ", ".join(unmapped_refs)
            )
        if unmapped_evidence:
            diagnostics.append(
                f"{match.expectation_id}: catalog evidence absent from linked "
                "graph elements: " + ", ".join(unmapped_evidence)
            )

        _increment(status_summary, match.status.value)
        _increment(applicability_summary, match.applicability.value)
        _increment(gap_summary, match.gap_reason.value)
        if route:
            _increment(route_summary, route.status.value)
        entries.append(HistoricalGraphOverlayEntry(
            expectation_id=match.expectation_id,
            vulnerability_identifier=match.vulnerability_identifier,
            interface_value=match.interface_value,
            method=match.method,
            handler_value=match.handler_value,
            expected_parameters=match.expected_parameters,
            source_ref=match.source_ref,
            applicability=match.applicability,
            claimed_versions=match.claimed_versions,
            applicability_basis=match.applicability_basis,
            status=match.status,
            gap_reason=match.gap_reason,
            gap_explanation=_GAP_EXPLANATIONS[match.gap_reason],
            observed_methods=match.observed_methods,
            observed_parameters=match.observed_parameters,
            missing_parameters=match.missing_parameters,
            catalog_candidate_ids=match.candidate_ids,
            catalog_evidence_ids=match.catalog_evidence_ids,
            route_binding_status=route.status if route else None,
            observed_handlers=route.observed_handlers if route else (),
            graph_node_ids=tuple(sorted(graph_node_ids)),
            graph_edge_ids=graph_edge_ids,
            graph_link_bases=tuple(sorted(link_bases)),
            unmapped_catalog_reference_ids=unmapped_refs,
            unmapped_catalog_evidence_ids=unmapped_evidence,
        ))

    audit = HistoricalGraphOverlayAudit(
        audit_id=vulnerability_audit.audit_id,
        total_vulnerability_count=vulnerability_audit.total_vulnerability_count,
        category_counts=vulnerability_audit.category_counts,
        exact_artifact_expectation_count=(
            vulnerability_audit.exact_artifact_expectation_count
        ),
        exact_artifact_observed_count=(
            vulnerability_audit.exact_artifact_observed_count
        ),
    ) if vulnerability_audit else None
    return HistoricalGraphOverlay(
        graph_id=graph.graph_id,
        catalog_id=diff.catalog_id,
        expectation_diff_id=diff.report_id,
        route_binding_report_id=(
            route_binding_report.report_id if route_binding_report else ""
        ),
        claim_boundary=HISTORICAL_GRAPH_OVERLAY_CLAIM_BOUNDARY,
        entries=tuple(entries),
        summary={
            "status": status_summary,
            "applicability": applicability_summary,
            "gap_reason": gap_summary,
            "route_binding_status": route_summary,
        },
        diagnostics=tuple(diagnostics),
        vulnerability_audit=audit,
    )
