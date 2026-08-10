import hashlib
import json
from pathlib import Path
import unittest


SAMPLES = Path("docs/firmware-mapping/samples")


class HistoricalCoverageQueueReportTests(unittest.TestCase):
    def test_ac9_r2_21_replay_closes_one_parameter_only_gap(self):
        replay_path = SAMPLES / "r2-21-vendor-tenda-ac9-historical-replay.json"
        queue_path = SAMPLES / "r2-21-vendor-tenda-ac9-historical-coverage-queue.json"
        replay = json.loads(replay_path.read_text(encoding="utf-8"))
        queue = json.loads(queue_path.read_text(encoding="utf-8"))

        by_cve = {
            item["vulnerability_identifier"]: item for item in replay["entries"]
        }
        virtual_server = by_cve["CVE-2021-42659"]
        self.assertEqual("observed", virtual_server["status"])
        self.assertEqual("exact_artifact", virtual_server["applicability"])
        self.assertEqual("POST", virtual_server["method"])
        self.assertEqual(["list"], virtual_server["observed_parameters"])
        self.assertEqual([], virtual_server["missing_parameters"])

        queue_by_cve = {
            item["vulnerability_identifier"]: item for item in queue["entries"]
        }
        self.assertNotIn("CVE-2021-42659", queue_by_cve)
        self.assertEqual(57, queue["summary"]["open"])
        self.assertEqual(2, queue["summary"]["repair_parameter_extraction"])
        self.assertEqual(
            "configuration_key",
            next(
                clue["parameter_classifications"][0]["role"]
                for clue in json.loads((SAMPLES / (
                    "r2-21-vendor-tenda-ac9-historical-semantic-clues.json"
                )).read_text(encoding="utf-8"))["clues"]
                if clue["vulnerability_identifier"] == "CVE-2026-2191"
            ),
        )
        self.assertEqual(
            "historical-coverage-queue:2b84180a4aaccf9b19d3efca5cf7e5e0c2f67336c84843b00a219782adeb778e",
            queue["queue_id"],
        )
        self.assertEqual(
            "f284fd35d355afd1d2e229b7e34460d338e58ec7e2a81ac5987433846922d5f5",
            hashlib.sha256(queue_path.read_bytes()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
