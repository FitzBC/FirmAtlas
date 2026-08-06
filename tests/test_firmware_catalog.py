import unittest

from firmatlas.firmware_catalog import (
    FIRMEMUHUB_DEVICES_URL,
    IOTVULBENCH_DETAIL_URL,
    IOTVULBENCH_LIST_URL,
    collect_public_catalog,
    parse_firmemuhub_devices,
)
from firmatlas.intelligence.repository import IntelligenceRepository


DEVICES = """
| Benchmark ID | Vendor | Model | Firmware Version |
| [BM-2024-00001](./Benchmark/BM-2024-00001) | TP-Link | TL-WR940N | wr940nv4.bin |
| [BM-2024-00012](./Benchmark/BM-2024-00012) | Tenda | AC9 | tenda ac9.zip |
"""

VULNERABILITIES = """
## TP Link
- CVE-2017-13772
## Tenda
- CVE-2018-16334
"""

DETAILS = {
    "CVE-2017-13772": "environments:\n- name: BM-2024-00001\n",
    "CVE-2018-16334": "environments:\n- name: BM-2024-00012\n",
}


class FirmwareCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = IntelligenceRepository(":memory:")

    def tearDown(self) -> None:
        self.repository.close()

    def loader(self, url: str) -> str:
        if url == FIRMEMUHUB_DEVICES_URL:
            return DEVICES
        if url == IOTVULBENCH_LIST_URL:
            return VULNERABILITIES
        for identifier, detail in DETAILS.items():
            if url == IOTVULBENCH_DETAIL_URL.format(identifier=identifier):
                return detail
        raise OSError(url)

    def test_parses_metadata_without_downloading_firmware(self) -> None:
        items = parse_firmemuhub_devices(DEVICES)

        self.assertEqual(2, len(items))
        self.assertEqual("firmemuhub:BM-2024-00001", items[0]["candidate_id"])
        self.assertTrue(items[0]["download_url"].endswith("wr940nv4.bin"))
        self.assertIn("tenda%20ac9.zip", items[1]["download_url"])
        self.assertEqual("listed", items[0]["url_status"])

    def test_catalog_supports_sample_and_vulnerability_bidirectional_queries(self) -> None:
        sources, candidates, leads, failures = collect_public_catalog(self.loader)
        self.repository.upsert_firmware_sources(sources)
        self.repository.upsert_firmware_candidates(candidates)
        self.repository.upsert_firmware_vulnerability_leads(leads)

        page = self.repository.list_firmware_candidates(query="CVE-2017-13772")
        detail = self.repository.get_firmware_candidate("firmemuhub:BM-2024-00001")
        reverse = self.repository.firmware_candidates_for_vulnerability(
            "CVE-2018-16334"
        )
        overview = self.repository.firmware_catalog_overview()

        self.assertEqual([], failures)
        self.assertEqual(1, page["total"])
        self.assertEqual("TL-WR940N", page["items"][0]["model"])
        self.assertEqual("CVE-2017-13772", detail["vulnerabilities"][0]["vulnerability_identifier"])
        self.assertEqual("AC9", reverse["items"][0]["model"])
        self.assertEqual(2, overview["counts"]["candidate_count"])
        self.assertEqual(2, overview["counts"]["linked_candidate_count"])
        self.assertGreaterEqual(overview["counts"]["source_count"], 10)


if __name__ == "__main__":
    unittest.main()
