import json
from pathlib import Path
import unittest


REPORT = (
    Path(__file__).resolve().parents[1]
    / "docs/firmware-mapping/samples/r2-27-vendor-tenda-ac9-configuration-url-ipc.json"
)


class ConfigurationUrlIpcReportTests(unittest.TestCase):
    def test_checked_in_report_matches_independent_cold_start(self):
        if not REPORT.is_file():
            self.skipTest("R2-27 report has not been generated")
        from scripts.build_vendor_tenda_ac9_configuration_url_ipc_report import build

        self.assertEqual(
            json.loads(REPORT.read_text(encoding="utf-8")),
            build(),
        )


if __name__ == "__main__":
    unittest.main()
