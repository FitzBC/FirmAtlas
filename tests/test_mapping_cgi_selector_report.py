import json
from pathlib import Path
import unittest


REPORT = (
    Path(__file__).resolve().parents[1]
    / "docs/firmware-mapping/samples/r2-28-vendor-tenda-ac9-cgi-selector.json"
)


class CgiSelectorReportTests(unittest.TestCase):
    def test_checked_in_report_matches_independent_cold_start(self):
        if not REPORT.is_file():
            self.skipTest("R2-28 report has not been generated")
        from scripts.build_vendor_tenda_ac9_cgi_selector_report import build

        self.assertEqual(json.loads(REPORT.read_text(encoding="utf-8")), build())


if __name__ == "__main__":
    unittest.main()
