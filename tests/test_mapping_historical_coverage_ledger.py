import unittest

from firmatlas.mapping import (
    HistoricalApplicability,
    HistoricalInterfaceExpectation,
    HistoricalSemanticClue,
    HistoricalVulnerabilityRecord,
    build_historical_coverage_ledger,
    build_historical_coverage_queue,
    build_historical_vulnerability_audit,
    compare_historical_expectations,
    project_communication_architecture_graph,
    project_historical_graph_overlay,
)
from tests.test_mapping_historical_graph_overlay import _catalog


def _ledger_fixture():
    catalog = _catalog()
    graph = project_communication_architecture_graph(catalog)
    expectation = HistoricalInterfaceExpectation(
        vulnerability_identifier="CVE-observed",
        interface_value="/goform/SetIPTVCfg",
        method="POST",
        handler_value="formSetIptv",
        parameters=("list",),
        source_ref="primary:observed",
        applicability=HistoricalApplicability.EXACT_ARTIFACT,
        claimed_versions=("15.03.05.19",),
        applicability_basis="The source names the selected artifact.",
    )
    diff = compare_historical_expectations(catalog, (expectation,))
    records = (
        HistoricalVulnerabilityRecord("CVE-observed", True, 1, 1),
        HistoricalVulnerabilityRecord("CVE-parameter", True, 0, 1),
        HistoricalVulnerabilityRecord("CVE-unknown", False, 0, 0),
    )
    audit = build_historical_vulnerability_audit(diff, records)
    overlay = project_historical_graph_overlay(graph, diff, vulnerability_audit=audit)
    queue = build_historical_coverage_queue(
        audit,
        (HistoricalSemanticClue(
            "CVE-parameter",
            "A configuration key is consumed by a native handler.",
            parameters=("security.ddos.map",),
            handler_names=("formGetDdosDefenceList",),
            source_refs=("primary:parameter",),
            parameter_classifications=(("security.ddos.map", "configuration_key"),),
        ),),
        catalog,
    )
    return catalog, graph, overlay, queue


class HistoricalCoverageLedgerContractTests(unittest.TestCase):
    def test_projects_every_vulnerability_once_without_inventing_graph_facts(self):
        catalog, graph, overlay, queue = _ledger_fixture()

        ledger = build_historical_coverage_ledger(overlay, queue)

        self.assertEqual(graph.graph_id, ledger.graph_id)
        self.assertEqual(catalog.catalog_id, ledger.catalog_id)
        self.assertEqual(3, ledger.total_vulnerability_count)
        self.assertEqual(
            {"not_assessable": 1, "observed": 1, "partial": 1},
            ledger.summary["status"],
        )
        entries = {
            item.vulnerability_identifier: item for item in ledger.entries
        }
        observed = entries["CVE-observed"]
        self.assertEqual("observed", observed.status.value)
        self.assertEqual(("/goform/SetIPTVCfg",), observed.interface_values)
        self.assertTrue(observed.graph_node_ids)
        self.assertEqual(("primary:observed",), observed.source_refs)

        partial = entries["CVE-parameter"]
        self.assertEqual("partial", partial.status.value)
        self.assertEqual((), partial.interface_values)
        self.assertEqual((), partial.graph_node_ids)
        self.assertIn(
            "configuration_key_misclassified_as_request_parameter",
            partial.reason_codes,
        )
        self.assertEqual(("security.ddos.map",), partial.configuration_keys)

        unknown = entries["CVE-unknown"]
        self.assertEqual("not_assessable", unknown.status.value)
        self.assertEqual(("semantic_analysis_missing",), unknown.reason_codes)

    def test_identity_is_deterministic_and_rejects_cross_run_inputs(self):
        _, _, overlay, queue = _ledger_fixture()

        first = build_historical_coverage_ledger(overlay, queue)
        second = build_historical_coverage_ledger(overlay, queue)

        self.assertEqual(first.ledger_id, second.ledger_id)
        self.assertEqual(first.to_dict(), second.to_dict())
        with self.assertRaisesRegex(ValueError, "same audit"):
            build_historical_coverage_ledger(
                overlay,
                type(queue)(
                    audit_id="historical-vulnerability-audit:" + "9" * 64,
                    catalog_id=queue.catalog_id,
                    entries=queue.entries,
                    summary=queue.summary,
                ),
            )


if __name__ == "__main__":
    unittest.main()
