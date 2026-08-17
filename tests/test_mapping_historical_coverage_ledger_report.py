import hashlib
import json
from pathlib import Path
import unittest


REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-29-vendor-tenda-ac9-historical-coverage-ledger.json"
)


class HistoricalCoverageLedgerReportTests(unittest.TestCase):
    def test_real_ac9_report_covers_and_explains_all_71_records(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        ledger = report["coverage_ledger"]

        self.assertEqual(71, ledger["total_vulnerability_count"])
        self.assertEqual(
            {"not_assessable": 60, "observed": 9, "partial": 2},
            ledger["status_summary"],
        )
        self.assertEqual(14, ledger["structured_expectation_count"])
        self.assertEqual(57, ledger["open_queue_count"])
        self.assertEqual(3, ledger["exact_artifact_expectation_count"])
        self.assertEqual(3, ledger["exact_artifact_observed_count"])
        observed = ledger["selected_cases"]["CVE-2021-42659"]
        self.assertEqual("observed", observed["status"])
        self.assertEqual(["/goform/SetVirtualServerCfg"], observed["interface_values"])
        parameter = ledger["selected_cases"]["CVE-2026-2191"]
        self.assertEqual("partial", parameter["status"])
        self.assertEqual(["security.ddos.map"], parameter["configuration_keys"])
        self.assertEqual([], parameter["interface_values"])
        self.assertEqual([], parameter["graph_node_ids"])

    def test_report_binds_http_and_console_acceptance_to_sources(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        self.assertEqual(71, report["http_acceptance"]["all_entry_count"])
        self.assertEqual(1, report["http_acceptance"]["parameter_gap_query_count"])
        self.assertTrue(report["http_acceptance"]["publication"]["created"])
        self.assertFalse(report["http_acceptance"]["repeated_publication"]["created"])
        for source, digest in report["console_acceptance"]["source_sha256"].items():
            self.assertEqual(digest, hashlib.sha256(Path(source).read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
