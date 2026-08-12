import json
from pathlib import Path
import unittest


REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-24-vendor-tenda-ac9-configuration-blob-flow.json"
)


class ConfigurationBlobFlowReportTests(unittest.TestCase):
    def test_documented_report_is_deterministic(self):
        from scripts.build_vendor_tenda_ac9_configuration_blob_flow_report import (
            ROOT, build,
        )

        if not ROOT.is_dir():
            self.skipTest("local vendor Tenda AC9 rootfs is unavailable")
        self.assertEqual(json.loads(REPORT.read_text()), build())


if __name__ == "__main__":
    unittest.main()
