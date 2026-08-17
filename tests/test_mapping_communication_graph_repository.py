import io
import json
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from firmatlas.mapping import (
    CommunicationGraphQuery,
    CommunicationGraphEdgeKind,
    CoverageStatus,
    CommunicationGraphConflictError,
    DiscoveryCatalogRepository,
    HistoricalApplicability,
    HistoricalCoverageLedgerQuery,
    HistoricalGraphOverlayQuery,
    HistoricalInterfaceExpectation,
    HistoricalMatchStatus,
    compare_historical_expectations,
    compare_historical_route_bindings,
    project_historical_graph_overlay,
    project_communication_architecture_graph,
)
from tests.test_mapping_historical_coverage_ledger import _ledger_fixture
from tests.test_mapping_catalog_repository import _catalog
from firmatlas.cli import main as firmatlas_main
from firmatlas.mapping.repository import _reachable_graph_neighbors


class CommunicationGraphRepositoryContractTests(unittest.TestCase):
    def test_call_edges_expand_forward_without_merging_other_callers(self):
        edges = (
            SimpleNamespace(
                edge_kind=CommunicationGraphEdgeKind.CALLS,
                source_ref="caller:a", target_ref="callee:shared",
            ),
            SimpleNamespace(
                edge_kind=CommunicationGraphEdgeKind.CALLS,
                source_ref="caller:b", target_ref="callee:shared",
            ),
            SimpleNamespace(
                edge_kind=CommunicationGraphEdgeKind.BINDS_HANDLER,
                source_ref="dispatch:a", target_ref="caller:a",
            ),
        )

        self.assertEqual(
            {"callee:shared", "dispatch:a"},
            _reachable_graph_neighbors({"caller:a"}, edges),
        )
        self.assertEqual(
            set(),
            _reachable_graph_neighbors({"callee:shared"}, edges),
        )

    def setUp(self):
        self.repository = DiscoveryCatalogRepository(":memory:")
        self.catalog = _catalog()
        self.graph = project_communication_architecture_graph(self.catalog)

    def tearDown(self):
        self.repository.close()

    def _historical_overlay(self):
        expectation = HistoricalInterfaceExpectation(
            vulnerability_identifier="CVE-2025-22946",
            interface_value="/goform/SetOnlineDevName",
            method="POST",
            parameters=("mac", "devName"),
            source_ref="historical-semantic-analysis:CVE-2025-22946",
            applicability=HistoricalApplicability.EXACT_ARTIFACT,
            claimed_versions=("V15.03.2.21",),
            applicability_basis="Exact vendor artifact hash.",
        )
        diff = compare_historical_expectations(self.catalog, (expectation,))
        routes = compare_historical_route_bindings(
            self.catalog, (expectation,)
        )
        return project_historical_graph_overlay(self.graph, diff, routes)

    def test_publish_requires_source_catalog_and_is_immutable_and_idempotent(self):
        with self.assertRaisesRegex(ValueError, "source catalog"):
            self.repository.publish_communication_graph(self.graph)

        self.repository.publish(self.catalog)
        first = self.repository.publish_communication_graph(self.graph)
        second = self.repository.publish_communication_graph(self.graph)

        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(self.graph.graph_id, first["graph_id"])
        listing = self.repository.list_communication_graphs()
        self.assertEqual(1, listing["total"])
        self.assertEqual(self.graph.graph_id, listing["items"][0]["graph_id"])
        conflicting = replace(
            self.graph, diagnostics=("content changed",)
        )
        with self.assertRaises(CommunicationGraphConflictError):
            self.repository.publish_communication_graph(conflicting)

    def test_historical_overlay_requires_graph_and_queries_two_dimensions(self):
        overlay = self._historical_overlay()
        with self.assertRaisesRegex(ValueError, "graph is not published"):
            self.repository.publish_historical_graph_overlay(overlay)

        self.repository.publish(self.catalog)
        self.repository.publish_communication_graph(self.graph)
        first = self.repository.publish_historical_graph_overlay(overlay)
        second = self.repository.publish_historical_graph_overlay(overlay)
        result = self.repository.query_historical_graph_overlay(
            self.graph.graph_id,
            HistoricalGraphOverlayQuery(
                statuses=(HistoricalMatchStatus.OBSERVED.value,),
                applicabilities=(HistoricalApplicability.EXACT_ARTIFACT.value,),
            ),
        )

        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(overlay.overlay_id, result["overlay"]["overlay_id"])
        self.assertEqual(1, result["total_entry_count"])
        self.assertEqual(1, result["selected_entry_count"])
        self.assertEqual(
            {"observed": 1}, result["facets"]["status"]
        )
        self.assertEqual(
            "exact_artifact", result["entries"][0]["applicability"]
        )
        self.assertTrue(result["entries"][0]["graph_node_ids"])

        empty = self.repository.query_historical_graph_overlay(
            self.graph.graph_id,
            HistoricalGraphOverlayQuery(statuses=("missing",)),
        )
        self.assertEqual(0, empty["selected_entry_count"])

    def test_historical_overlay_rejects_unknown_graph_references(self):
        overlay = self._historical_overlay()
        self.repository.publish(self.catalog)
        self.repository.publish_communication_graph(self.graph)
        bad_entry = replace(
            overlay.entries[0],
            graph_node_ids=("candidate:not-in-graph",),
        )

        with self.assertRaisesRegex(ValueError, "unknown graph node"):
            self.repository.publish_historical_graph_overlay(replace(
                overlay, entries=(bad_entry,)
            ))

    def test_historical_coverage_ledger_persists_complete_denominator_and_queries_reason(self):
        catalog, graph, overlay, queue = _ledger_fixture()
        from firmatlas.mapping import build_historical_coverage_ledger
        ledger = build_historical_coverage_ledger(overlay, queue)

        with self.assertRaisesRegex(ValueError, "graph is not published"):
            self.repository.publish_historical_coverage_ledger(ledger)
        self.repository.publish(catalog)
        self.repository.publish_communication_graph(graph)
        self.repository.publish_historical_graph_overlay(overlay)
        first = self.repository.publish_historical_coverage_ledger(ledger)
        second = self.repository.publish_historical_coverage_ledger(ledger)
        result = self.repository.query_historical_coverage_ledger(
            graph.graph_id,
            HistoricalCoverageLedgerQuery(
                text="security.ddos.map",
                statuses=("partial",),
                audit_categories=("parameter_only",),
            ),
        )

        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(3, result["total_entry_count"])
        self.assertEqual(1, result["selected_entry_count"])
        self.assertEqual("CVE-parameter", result["entries"][0][
            "vulnerability_identifier"
        ])
        self.assertEqual(
            {"not_assessable": 1, "observed": 1, "partial": 1},
            result["facets"]["status"],
        )
        bad_catalog_entry = replace(
            overlay.entries[0],
            catalog_candidate_ids=("candidate:not-in-catalog",),
        )
        with self.assertRaisesRegex(ValueError, "unknown catalog candidate"):
            self.repository.publish_historical_graph_overlay(replace(
                overlay, entries=(bad_catalog_entry,)
            ))

    def test_publish_rejects_graph_evidence_absent_from_source_catalog(self):
        self.repository.publish(self.catalog)
        bad_node = replace(
            self.graph.nodes[0], evidence_ids=("evidence:missing",)
        )
        bad_graph = replace(
            self.graph, nodes=(bad_node, *self.graph.nodes[1:])
        )

        with self.assertRaisesRegex(ValueError, "unknown catalog evidence"):
            self.repository.publish_communication_graph(bad_graph)
        wrong_coverage = replace(
            self.graph,
            source_catalog_coverage_status=CoverageStatus.PARTIAL,
        )
        with self.assertRaisesRegex(ValueError, "coverage does not match"):
            self.repository.publish_communication_graph(wrong_coverage)

    def test_query_returns_graph_structure_and_resolved_evidence_atoms(self):
        self.repository.publish(self.catalog)
        self.repository.publish_communication_graph(self.graph)

        result = self.repository.query_communication_graph(
            self.graph.graph_id, CommunicationGraphQuery()
        )
        repeated = self.repository.query_communication_graph(
            self.graph.graph_id, CommunicationGraphQuery()
        )

        self.assertEqual(
            "firmatlas.mapping.communication-graph-query-result/v1alpha1",
            result["schema_version"],
        )
        self.assertTrue(result["query_id"].startswith(
            "communication-graph-query:"
        ))
        self.assertEqual(result["query_id"], repeated["query_id"])
        self.assertEqual(self.graph.graph_id, result["graph"]["graph_id"])
        self.assertEqual(len(self.graph.nodes), result["total_node_count"])
        self.assertEqual(len(self.graph.edges), result["total_edge_count"])
        self.assertEqual(
            {item.evidence_id for item in self.catalog.evidence_atoms},
            {item["evidence_id"] for item in result["evidence_atoms"]},
        )
        node_ids = {item["node_id"] for item in result["nodes"]}
        self.assertTrue(all(
            item["source_ref"] in node_ids and item["target_ref"] in node_ids
            for item in result["edges"]
        ))

    def test_query_focuses_exact_interface_through_parameter_view_preset(self):
        self.repository.publish(self.catalog)
        self.repository.publish_communication_graph(self.graph)

        result = self.repository.query_communication_graph(
            self.graph.graph_id,
            CommunicationGraphQuery(
                preset_id="parameter_state",
                focus_canonical_identities=(
                    "/goform/SetOnlineDevName",
                ),
                max_hops=1,
            ),
        )

        self.assertEqual("completed", result["query_status"])
        self.assertEqual(
            {"interface", "parameter"},
            {item["node_kind"] for item in result["nodes"]},
        )
        self.assertEqual(
            {"mac", "devName"},
            {
                item["label"] for item in result["nodes"]
                if item["node_kind"] == "parameter"
            },
        )
        self.assertEqual(
            {"accepts_parameter"},
            {item["edge_kind"] for item in result["edges"]},
        )
        self.assertEqual(1, result["facets"]["node_kinds"]["interface"])
        self.assertEqual(2, result["facets"]["node_kinds"]["parameter"])

    def test_query_filters_text_and_evidence_without_inventing_neighbors(self):
        self.repository.publish(self.catalog)
        self.repository.publish_communication_graph(self.graph)
        request = next(
            item for item in self.graph.nodes
            if item.node_kind.value == "interface"
        )

        by_text = self.repository.query_communication_graph(
            self.graph.graph_id,
            CommunicationGraphQuery(
                text="online dev", node_kinds=("interface",)
            ),
        )
        by_evidence = self.repository.query_communication_graph(
            self.graph.graph_id,
            CommunicationGraphQuery(
                evidence_id=request.evidence_ids[0],
                node_kinds=("interface",),
            ),
        )

        self.assertEqual(
            ["/goform/SetOnlineDevName"],
            [item["label"] for item in by_text["nodes"]],
        )
        self.assertEqual(
            [request.node_id],
            [item["node_id"] for item in by_evidence["nodes"]],
        )
        self.assertEqual([], by_text["edges"])
        self.assertEqual([], by_evidence["edges"])

    def test_query_reports_missing_focus_and_budget_without_dangling_edges(self):
        self.repository.publish(self.catalog)
        self.repository.publish_communication_graph(self.graph)

        missing = self.repository.query_communication_graph(
            self.graph.graph_id,
            CommunicationGraphQuery(
                focus_canonical_identities=("/missing",)
            ),
        )
        bounded = self.repository.query_communication_graph(
            self.graph.graph_id,
            CommunicationGraphQuery(max_nodes=2, max_edges=1),
        )

        self.assertEqual("partial", missing["query_status"])
        self.assertEqual([], missing["nodes"])
        self.assertIn("focus_identity_not_found", missing["diagnostics"][0])
        self.assertEqual("partial", bounded["query_status"])
        self.assertEqual(2, bounded["selected_node_count"])
        self.assertLessEqual(bounded["selected_edge_count"], 1)
        node_ids = {item["node_id"] for item in bounded["nodes"]}
        self.assertTrue(all(
            edge["source_ref"] in node_ids and edge["target_ref"] in node_ids
            for edge in bounded["edges"]
        ))

        with self.assertRaisesRegex(ValueError, "unknown preset"):
            self.repository.query_communication_graph(
                self.graph.graph_id,
                CommunicationGraphQuery(preset_id="missing"),
            )

    def test_cli_publishes_analysis_graph_and_queries_parameter_view(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "mapping.db"
            run_document = root / "analysis-run.json"
            graph_document = root / "graph.json"
            run_document.write_text(
                json.dumps({"catalog": self.catalog.to_dict()}),
                encoding="utf-8",
            )
            graph_document.write_text(
                json.dumps(self.graph.to_dict()), encoding="utf-8"
            )
            published = io.StringIO()
            queried = io.StringIO()
            with redirect_stdout(published):
                publish_code = firmatlas_main((
                    "mapping", "publish-graph", "--database", str(database),
                    "--catalog-document", str(run_document),
                    str(graph_document),
                ))
            with redirect_stdout(queried):
                query_code = firmatlas_main((
                    "mapping", "query-graph", "--database", str(database),
                    self.graph.graph_id,
                    "--preset", "parameter_state",
                    "--focus-identity", "/goform/SetOnlineDevName",
                    "--max-hops", "1",
                ))

        self.assertEqual(0, publish_code)
        self.assertEqual(0, query_code)
        self.assertTrue(json.loads(published.getvalue())["graph"]["created"])
        result = json.loads(queried.getvalue())
        self.assertEqual("completed", result["query_status"])
        self.assertEqual(
            {"interface", "parameter"},
            {item["node_kind"] for item in result["nodes"]},
        )

    def test_cli_publishes_and_queries_historical_overlay(self):
        overlay = self._historical_overlay()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "mapping.db"
            run_document = root / "analysis-run.json"
            graph_document = root / "graph.json"
            overlay_document = root / "overlay.json"
            run_document.write_text(
                json.dumps({"catalog": self.catalog.to_dict()}),
                encoding="utf-8",
            )
            graph_document.write_text(
                json.dumps(self.graph.to_dict()), encoding="utf-8"
            )
            overlay_document.write_text(
                json.dumps(overlay.to_dict()), encoding="utf-8"
            )
            with redirect_stdout(io.StringIO()):
                firmatlas_main((
                    "mapping", "publish-graph", "--database", str(database),
                    "--catalog-document", str(run_document),
                    str(graph_document),
                ))
                publish_code = firmatlas_main((
                    "mapping", "publish-history-overlay",
                    "--database", str(database), str(overlay_document),
                ))
            queried = io.StringIO()
            with redirect_stdout(queried):
                query_code = firmatlas_main((
                    "mapping", "query-history-overlay",
                    "--database", str(database), self.graph.graph_id,
                    "--status", "observed",
                    "--applicability", "exact_artifact",
                ))

        self.assertEqual(0, publish_code)
        self.assertEqual(0, query_code)
        result = json.loads(queried.getvalue())
        self.assertEqual(1, result["selected_entry_count"])
        self.assertEqual(overlay.overlay_id, result["overlay"]["overlay_id"])

    def test_cli_publishes_and_queries_complete_historical_ledger(self):
        catalog, graph, overlay, queue = _ledger_fixture()
        from firmatlas.mapping import build_historical_coverage_ledger
        ledger = build_historical_coverage_ledger(overlay, queue)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "mapping.db"
            run_document = root / "analysis-run.json"
            graph_document = root / "graph.json"
            overlay_document = root / "overlay.json"
            ledger_document = root / "ledger.json"
            run_document.write_text(
                json.dumps({"catalog": catalog.to_dict()}), encoding="utf-8"
            )
            graph_document.write_text(json.dumps(graph.to_dict()), encoding="utf-8")
            overlay_document.write_text(json.dumps(overlay.to_dict()), encoding="utf-8")
            ledger_document.write_text(json.dumps(ledger.to_dict()), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                firmatlas_main((
                    "mapping", "publish-graph", "--database", str(database),
                    "--catalog-document", str(run_document), str(graph_document),
                ))
                firmatlas_main((
                    "mapping", "publish-history-overlay", "--database", str(database),
                    str(overlay_document),
                ))
                publish_code = firmatlas_main((
                    "mapping", "publish-history-ledger", "--database", str(database),
                    str(ledger_document),
                ))
            queried = io.StringIO()
            with redirect_stdout(queried):
                query_code = firmatlas_main((
                    "mapping", "query-history-ledger", "--database", str(database),
                    graph.graph_id, "--query", "security.ddos.map",
                    "--status", "partial", "--audit-category", "parameter_only",
                ))

        self.assertEqual(0, publish_code)
        self.assertEqual(0, query_code)
        result = json.loads(queried.getvalue())
        self.assertEqual(3, result["total_entry_count"])
        self.assertEqual(1, result["selected_entry_count"])
        self.assertEqual("CVE-parameter", result["entries"][0][
            "vulnerability_identifier"
        ])

    def test_persisted_graph_is_queryable_after_repository_reopen(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "mapping.db"
            first = DiscoveryCatalogRepository(str(database))
            try:
                first.publish(self.catalog)
                first.publish_communication_graph(self.graph)
            finally:
                first.close()
            second = DiscoveryCatalogRepository(str(database))
            try:
                result = second.query_communication_graph(
                    self.graph.graph_id,
                    CommunicationGraphQuery(
                        focus_canonical_identities=(
                            "/goform/SetOnlineDevName",
                        ),
                        max_hops=1,
                    ),
                )
            finally:
                second.close()

        self.assertIsNotNone(result)
        self.assertEqual(self.graph.graph_id, result["graph"]["graph_id"])
        self.assertGreater(result["selected_edge_count"], 0)


if __name__ == "__main__":
    unittest.main()
