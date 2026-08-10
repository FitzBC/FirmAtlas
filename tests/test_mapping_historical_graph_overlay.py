from dataclasses import replace
import unittest

from firmatlas.mapping.communication_graph import (
    CommunicationGraphEdgeKind,
    project_communication_architecture_graph,
)
from firmatlas.mapping.discovery_catalog import (
    DiscoveryCandidate,
    DiscoveryCandidateKind,
    DiscoveryCatalog,
    DiscoveryClaimStatus,
    DiscoveryParameter,
)
from firmatlas.mapping.domain import CoverageStatus
from firmatlas.mapping.historical_expectation import (
    HistoricalApplicability,
    HistoricalInterfaceExpectation,
    HistoricalMatchStatus,
    HistoricalRouteBindingStatus,
    compare_historical_expectations,
    compare_historical_route_bindings,
)
from firmatlas.mapping.historical_graph_overlay import (
    HISTORICAL_GRAPH_OVERLAY_CLAIM_BOUNDARY,
    HistoricalGraphOverlay,
    project_historical_graph_overlay,
)


def _catalog() -> DiscoveryCatalog:
    request = DiscoveryCandidate(
        candidate_id="candidate:set-iptv",
        candidate_kind=DiscoveryCandidateKind.REQUEST_INTERFACE,
        canonical_identity="goform/SetIPTVCfg",
        claim_status=DiscoveryClaimStatus.SUPPORTED,
        source_path="webroot_ro/js/iptv.js",
        source_construct="page_model_set_url",
        evidence_ids=(),
        attributes=(("method", "POST"),),
    )
    route = DiscoveryCandidate(
        candidate_id="native-route:set-iptv",
        candidate_kind=DiscoveryCandidateKind.NATIVE_ROUTE_BINDING,
        canonical_identity="SetIPTVCfg",
        claim_status=DiscoveryClaimStatus.SUPPORTED,
        source_path="bin/httpd",
        source_construct="arm_pic_callsite",
        evidence_ids=(),
        attributes=(("handler_symbol", "formSetIptv"),),
    )
    handler = DiscoveryCandidate(
        candidate_id="native-handler:set-iptv",
        candidate_kind=DiscoveryCandidateKind.NATIVE_HANDLER,
        canonical_identity="formSetIptv",
        claim_status=DiscoveryClaimStatus.SUPPORTED,
        source_path="bin/httpd",
        source_construct="arm_function",
        evidence_ids=(),
    )
    parameter = DiscoveryParameter(
        parameter_id="parameter:list",
        owner_ref=request.candidate_id,
        name="list",
        namespace="form",
        literal_value=None,
        selector_values=(),
        is_operation_selector=False,
        source_construct="page_model_submit",
        evidence_ids=(),
    )
    return DiscoveryCatalog(
        catalog_id="discovery-catalog:" + "1" * 64,
        firmware_artifact_sha256="2" * 64,
        source_inventory_sha256="3" * 64,
        coverage_status=CoverageStatus.COMPLETED,
        source_inventory_coverage_status=CoverageStatus.COMPLETED,
        candidates=(request, route, handler),
        parameters=(parameter,),
        evidence_atoms=(),
        coverage=(),
    )


def _expectation(
    *,
    applicability: HistoricalApplicability = HistoricalApplicability.OUT_OF_SCOPE,
) -> HistoricalInterfaceExpectation:
    return HistoricalInterfaceExpectation(
        vulnerability_identifier="CVE-2025-5836",
        interface_value="/goform/SetIPTVCfg",
        method="POST",
        handler_value="formSetIptv",
        parameters=("list",),
        source_ref="historical-semantic-analysis:CVE-2025-5836",
        applicability=applicability,
        claimed_versions=("V15.03.06.42_multi",),
        applicability_basis="Different AC9 firmware lineage.",
    )


class HistoricalGraphOverlayContractTests(unittest.TestCase):
    def test_projection_links_only_exact_catalog_graph_references(self) -> None:
        catalog = _catalog()
        graph = project_communication_architecture_graph(catalog)
        expectation = _expectation()
        diff = compare_historical_expectations(catalog, (expectation,))
        routes = compare_historical_route_bindings(catalog, (expectation,))

        overlay = project_historical_graph_overlay(graph, diff, routes)

        self.assertEqual(graph.graph_id, overlay.graph_id)
        self.assertEqual(diff.report_id, overlay.expectation_diff_id)
        self.assertEqual(
            HISTORICAL_GRAPH_OVERLAY_CLAIM_BOUNDARY,
            overlay.claim_boundary,
        )
        entry = overlay.entries[0]
        self.assertEqual(HistoricalMatchStatus.OBSERVED, entry.status)
        self.assertEqual(HistoricalApplicability.OUT_OF_SCOPE, entry.applicability)
        self.assertEqual(
            HistoricalRouteBindingStatus.VERIFIED_EXPECTED_HANDLER,
            entry.route_binding_status,
        )
        self.assertEqual(
            {
                "candidate:set-iptv",
                "native-route:set-iptv",
                "parameter:list",
            },
            set(entry.graph_node_ids),
        )
        linked_edges = {
            item.edge_id: item for item in graph.edges
            if item.edge_id in entry.graph_edge_ids
        }
        self.assertIn(
            CommunicationGraphEdgeKind.ACCEPTS_PARAMETER,
            {item.edge_kind for item in linked_edges.values()},
        )
        self.assertEqual(
            ("catalog_candidate_id", "parameter_owner_edge", "route_binding_id"),
            entry.graph_link_bases,
        )
        self.assertEqual({"observed": 1}, overlay.summary["status"])
        self.assertEqual({"out_of_scope": 1}, overlay.summary["applicability"])
        self.assertEqual(overlay.overlay_id, project_historical_graph_overlay(
            graph, diff, routes
        ).overlay_id)

    def test_missing_expectation_remains_unlinked_and_explains_gap(self) -> None:
        catalog = _catalog()
        graph = project_communication_architecture_graph(catalog)
        expectation = replace(
            _expectation(applicability=HistoricalApplicability.EXACT_ARTIFACT),
            vulnerability_identifier="CVE-missing",
            interface_value="/goform/DefinitelyMissing",
            handler_value="",
            parameters=("secret",),
        )
        diff = compare_historical_expectations(catalog, (expectation,))

        overlay = project_historical_graph_overlay(graph, diff)

        entry = overlay.entries[0]
        self.assertEqual(HistoricalMatchStatus.MISSING, entry.status)
        self.assertEqual("interface_not_observed", entry.gap_reason.value)
        self.assertEqual((), entry.graph_node_ids)
        self.assertEqual((), entry.graph_edge_ids)
        self.assertIn("not observed", entry.gap_explanation.lower())

    def test_projection_rejects_cross_catalog_reports_without_mutation(self) -> None:
        catalog = _catalog()
        graph = project_communication_architecture_graph(catalog)
        diff = compare_historical_expectations(catalog, (_expectation(),))
        original_graph = graph.to_dict()
        original_diff = diff.to_dict()

        with self.assertRaisesRegex(ValueError, "same catalog"):
            project_historical_graph_overlay(
                graph,
                replace(diff, catalog_id="discovery-catalog:" + "9" * 64),
            )

        self.assertEqual(original_graph, graph.to_dict())
        self.assertEqual(original_diff, diff.to_dict())

    def test_document_round_trip_rejects_boundary_or_summary_tampering(self) -> None:
        catalog = _catalog()
        overlay = project_historical_graph_overlay(
            project_communication_architecture_graph(catalog),
            compare_historical_expectations(catalog, (_expectation(),)),
        )
        document = overlay.to_dict()

        self.assertEqual(
            overlay.overlay_id,
            HistoricalGraphOverlay.from_dict(document).overlay_id,
        )
        with self.assertRaisesRegex(ValueError, "claim boundary"):
            HistoricalGraphOverlay.from_dict({
                **document, "claim_boundary": "historical claims are facts",
            })
        with self.assertRaisesRegex(ValueError, "summary"):
            HistoricalGraphOverlay.from_dict({
                **document,
                "summary": {**document["summary"], "status": {"observed": 9}},
            })


if __name__ == "__main__":
    unittest.main()
