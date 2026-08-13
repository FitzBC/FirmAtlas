import json
from pathlib import Path
import unittest


REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-25-vendor-tenda-ac9-configuration-text-import.json"
)


class ConfigurationTextImportReportTests(unittest.TestCase):
    def test_documented_report_is_deterministic(self):
        from scripts.build_vendor_tenda_ac9_configuration_text_import_report import (
            ROOT, build,
        )

        if not ROOT.is_dir():
            self.skipTest("local vendor Tenda AC9 rootfs is unavailable")
        self.assertEqual(json.loads(REPORT.read_text()), build())


if __name__ == "__main__":
    unittest.main()
