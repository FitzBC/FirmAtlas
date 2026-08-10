import hashlib
import json
from pathlib import Path
import unittest


REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-19-vendor-tenda-ac9-http-console-graph.json"
)


class CommunicationGraphHttpConsoleReportTests(unittest.TestCase):
    def test_real_ac9_report_preserves_http_graph_and_evidence_contract(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))

        self.assertEqual(
            "firmatlas.mapping.vendor-tenda-ac9-r2-19/"
            "http-console-graph-v1alpha1",
            report["schema_version"],
        )
        self.assertEqual(5_674, report["analysis"]["node_count"])
        self.assertEqual(7_212, report["analysis"]["edge_count"])
        self.assertEqual(
            [
                "/goform/refreshDLNA",
                "goform/GetDlnaCfg",
                "goform/SetDlnaCfg",
                "goform/expandDlnaFile?",
            ],
            report["http_acceptance"]["dlna_interface_index"]["labels"],
        )
        focused = report["http_acceptance"]["focused_interface_structure"]
        self.assertEqual("completed", focused["query_status"])
        self.assertEqual(23, focused["node_count"])
        self.assertEqual(22, focused["edge_count"])
        self.assertEqual(4, focused["open_obligation_count"])
        self.assertEqual(
            ["serializes_parameter"],
            [item["capability"] for item in focused["dlnaEn_evidence"]],
        )

    def test_console_contract_is_bound_to_the_checked_in_sources(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        console = report["console_acceptance"]

        self.assertTrue(console["production_document_served"])
        self.assertIn("evidence_atom_drilldown", console["interaction_contract"])
        self.assertIn(
            "responsive_three-pane_layout", console["interaction_contract"]
        )
        for source, expected_sha256 in console["source_sha256"].items():
            actual = hashlib.sha256(Path(source).read_bytes()).hexdigest()
            self.assertEqual(expected_sha256, actual, source)


if __name__ == "__main__":
    unittest.main()
