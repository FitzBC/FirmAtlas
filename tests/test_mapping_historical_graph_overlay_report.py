import hashlib
import json
from pathlib import Path
import unittest


REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-20-vendor-tenda-ac9-historical-graph-overlay.json"
)


class HistoricalGraphOverlayReportTests(unittest.TestCase):
    def test_real_ac9_report_keeps_observation_and_scope_separate(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))

        self.assertEqual(
            "firmatlas.mapping.vendor-tenda-ac9-r2-20/"
            "historical-graph-overlay-v1alpha1",
            report["schema_version"],
        )
        comparison = report["historical_comparison"]
        self.assertEqual(13, comparison["expectation_count"])
        self.assertEqual(
            {"not_assessable": 5, "observed": 8},
            comparison["status_summary"],
        )
        self.assertEqual(
            {"exact_artifact": 2, "out_of_scope": 11},
            comparison["applicability_summary"],
        )
        audit = comparison["vulnerability_denominator"]
        self.assertEqual(71, audit["total_vulnerability_count"])
        self.assertEqual(2, audit["exact_artifact_expectation_count"])
        self.assertEqual(2, audit["exact_artifact_observed_count"])
        cross_version = comparison["selected_cases"]["CVE-2025-5836"]
        self.assertEqual("observed", cross_version["status"])
        self.assertEqual("out_of_scope", cross_version["applicability"])
        self.assertIn("list", cross_version["observed_parameters"])
        self.assertTrue(cross_version["graph_node_ids"])
        missing = comparison["selected_cases"]["CVE-2026-6015"]
        self.assertEqual("not_assessable", missing["status"])
        self.assertEqual("artifact_out_of_scope", missing["gap_reason"])
        self.assertEqual(["PPPOEPassword"], missing["missing_parameters"])

    def test_http_and_console_acceptance_are_bound_to_checked_in_sources(self):
        report = json.loads(REPORT.read_text(encoding="utf-8"))
        acceptance = report["http_acceptance"]

        self.assertEqual(13, acceptance["all_entry_count"])
        self.assertEqual(2, acceptance["exact_artifact_observed_count"])
        self.assertEqual(11, acceptance["cross_version_count"])
        self.assertEqual(5, acceptance["not_assessable_count"])
        self.assertTrue(acceptance["publication"]["created"])
        self.assertFalse(acceptance["repeated_publication"]["created"])
        self.assertEqual([], report["diagnostics"])
        console = report["console_acceptance"]
        self.assertTrue(console["production_document_served"])
        self.assertIn(
            "historical_status_and_applicability_are_separate",
            console["interaction_contract"],
        )
        for source, expected_sha256 in console["source_sha256"].items():
            self.assertEqual(
                expected_sha256,
                hashlib.sha256(Path(source).read_bytes()).hexdigest(),
                source,
            )


if __name__ == "__main__":
    unittest.main()
