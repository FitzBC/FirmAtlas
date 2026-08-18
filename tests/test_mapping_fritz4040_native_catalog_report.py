import json
from pathlib import Path
import unittest

from scripts.build_fritz4040_native_catalog_report import (
    ARTIFACT,
    FRITZ4040_ROOT,
    MISSING_FROM_FRONTEND_DRIVEN,
    build,
)


class Fritz4040NativeCatalogReportTests(unittest.TestCase):
    REPORT = Path(
        "docs/firmware-mapping/samples/"
        "r2-34-openwrt-fritz4040-native-catalog.json"
    )

    def test_checked_in_report_replays_independent_native_holdout(self):
        if not FRITZ4040_ROOT.is_dir() or not ARTIFACT.is_file():
            self.skipTest("retained FRITZ!Box 4040 holdout is unavailable")

        report, run, graph = build()

        self.assertEqual(
            report,
            json.loads(self.REPORT.read_text(encoding="utf-8")),
        )
        direct = report["direct_native_projection"]
        self.assertEqual(24, direct["operation_count"])
        self.assertEqual(24, direct["binding_count"])
        self.assertEqual(24, direct["handler_count"])
        self.assertEqual(24, direct["binds_handler_edge_count"])
        self.assertEqual("completed", direct["scoped_catalog_coverage_status"])
        self.assertEqual(
            sorted(MISSING_FROM_FRONTEND_DRIVEN),
            report["regression_delta"]["previously_missing_now_present"],
        )
        self.assertEqual(run.catalog.catalog_id, report["analysis_run"]["catalog_id"])
        self.assertEqual(graph.graph_id, report["graph"]["graph_id"])


if __name__ == "__main__":
    unittest.main()
