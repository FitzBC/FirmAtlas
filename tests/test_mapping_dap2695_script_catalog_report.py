import json
from pathlib import Path
import unittest

from scripts.build_dap2695_script_catalog_report import (
    ARTIFACT,
    DAP2695_ROOT,
    build,
)


class Dap2695ScriptCatalogReportTests(unittest.TestCase):
    REPORT = Path(
        "docs/firmware-mapping/samples/"
        "r2-35-dlink-dap2695-script-catalog.json"
    )

    def test_checked_in_report_replays_independent_script_holdout(self):
        if not DAP2695_ROOT.is_dir() or not ARTIFACT.is_file():
            self.skipTest("retained DAP-2695 holdout is unavailable")

        report, run, graph = build()

        self.assertEqual(
            report,
            json.loads(self.REPORT.read_text(encoding="utf-8")),
        )
        projection = report["script_backend_projection"]
        self.assertEqual(485, projection["source_count"])
        self.assertEqual("completed", projection["scoped_catalog_coverage_status"])
        self.assertGreater(projection["candidate_count"], 3000)
        self.assertGreater(projection["evidence_count"], 3000)
        self.assertIn("reads_parameter", projection["capabilities"])
        self.assertIn("writes_configuration", projection["capabilities"])
        self.assertEqual("partial", report["analysis_run"]["coverage_status"])
        self.assertEqual(run.catalog.catalog_id, report["analysis_run"]["catalog_id"])
        self.assertEqual(graph.graph_id, report["graph"]["graph_id"])


if __name__ == "__main__":
    unittest.main()
