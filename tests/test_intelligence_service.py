import unittest

from firmatlas.intelligence.repository import IntelligenceRepository
from firmatlas.intelligence.sample_data import demo_records
from firmatlas.intelligence.service import IntelligenceService


class FakeNvd:
    def __init__(self) -> None:
        self.ranges = []

    def fetch_modified(self, start, end):
        self.ranges.append((start, end))
        return iter(demo_records()[:2])


class FakeCisa:
    def fetch_all(self):
        return iter(demo_records()[2:4])


class IntelligenceServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = IntelligenceRepository(":memory:")
        self.nvd = FakeNvd()
        self.service = IntelligenceService(
            self.repository, nvd=self.nvd, cisa=FakeCisa()
        )

    def tearDown(self) -> None:
        self.repository.close()

    def test_sync_records_run_cursor_and_firmware_results(self) -> None:
        result = self.service.sync(("nvd", "cisa-kev"), days=3)

        self.assertEqual("succeeded", result["status"])
        self.assertEqual(4, result["fetched_count"])
        self.assertEqual(4, self.repository.list()["total"])
        self.assertIsNotNone(self.repository.get_cursor("nvd"))
        self.assertIsNotNone(self.repository.get_cursor("cisa-kev"))

    def test_rejects_unknown_source_without_stuck_lock(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported"):
            self.service.sync(("unknown",))

        result = self.service.sync(("nvd",))
        self.assertEqual("succeeded", result["status"])


if __name__ == "__main__":
    unittest.main()
