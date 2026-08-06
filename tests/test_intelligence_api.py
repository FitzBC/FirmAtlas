import json
from pathlib import Path
import tempfile
import threading
import unittest
from dataclasses import replace
from urllib.request import Request, urlopen

from firmatlas.intelligence.api import create_handler
from firmatlas.intelligence.relevance import FirmwareRelevanceClassifier
from firmatlas.intelligence.repository import IntelligenceRepository
from firmatlas.intelligence.sample_data import demo_records
from firmatlas.intelligence.service import IntelligenceService
from http.server import ThreadingHTTPServer


class IntelligenceApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = IntelligenceRepository(":memory:")
        classifier = FirmwareRelevanceClassifier()
        policy = self.repository.get_policy()
        for record in demo_records()[:2]:
            self.repository.upsert(record, classifier.classify(record, policy))
        service = IntelligenceService(self.repository)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(service))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.repository.close()

    def get(self, path):
        with urlopen(
            "http://127.0.0.1:{}{}".format(self.server.server_port, path), timeout=2
        ) as response:
            return response.status, json.loads(response.read())["data"]

    def put(self, path, payload):
        request = Request(
            "http://127.0.0.1:{}{}".format(self.server.server_port, path),
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="PUT",
        )
        with urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read())["data"]

    def post(self, path, payload):
        request = Request(
            "http://127.0.0.1:{}{}".format(self.server.server_port, path),
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read())["data"]

    def test_overview_and_filtered_feed(self) -> None:
        status, overview = self.get("/api/intelligence/overview")
        feed_status, feed = self.get(
            "/api/intelligence/vulnerabilities?q=Hikvision&relevance=firmware"
        )
        vendor_status, vendor_feed = self.get(
            "/api/intelligence/vulnerabilities?vendor=Hikvision&relevance=firmware"
        )

        self.assertEqual(200, status)
        self.assertEqual(2, overview["counts"]["relevant"])
        self.assertEqual(200, feed_status)
        self.assertEqual(1, feed["total"])
        self.assertEqual(200, vendor_status)
        self.assertEqual(1, vendor_feed["total"])
        self.assertEqual("Hikvision", vendor_feed["items"][0]["vendor"])

    def test_updates_relevance_policy_through_api(self) -> None:
        status, result = self.put(
            "/api/intelligence/settings", {"vendor_keywords": ["Acme"]}
        )

        self.assertEqual(200, status)
        self.assertEqual(["Acme"], result["policy"]["vendor_keywords"])
        self.assertEqual(2, result["reclassified_count"])

    def test_semantic_analysis_and_masked_model_settings(self) -> None:
        settings_status, settings = self.get("/api/intelligence/semantic/settings")
        update_status, updated = self.put(
            "/api/intelligence/semantic/settings",
            {"base_url": "http://127.0.0.1:48760/v1", "api_key": "secret"},
        )
        analyze_status, analysis = self.post(
            "/api/intelligence/vulnerabilities/CVE-2026-29417/semantic-analysis",
            {},
        )
        cached_status, cached = self.get(
            "/api/intelligence/vulnerabilities/CVE-2026-29417/semantic-analysis"
        )

        self.assertEqual(200, settings_status)
        self.assertEqual("http://127.0.0.1:48760/v1", settings["base_url"])
        self.assertEqual(200, update_status)
        self.assertTrue(updated["has_api_key"])
        self.assertNotIn("api_key", updated)
        self.assertEqual(200, analyze_status)
        self.assertFalse(analysis["cached"])
        self.assertEqual(200, cached_status)
        self.assertEqual("CVE-2026-29417", cached["vulnerability_identifier"])

    def test_server_pagination_and_semantic_explorer_routes(self) -> None:
        base = demo_records()[0]
        semantic_fixture = replace(
            base, identifier="CVE-2025-9001", source_identifier="CVE-2025-9001",
            summary="The HTTP endpoint /goform/apply accepts the argument cmd.",
        )
        classifier = FirmwareRelevanceClassifier()
        self.repository.upsert(
            semantic_fixture,
            classifier.classify(semantic_fixture, self.repository.get_policy()),
        )
        self.post(
            "/api/intelligence/vulnerabilities/CVE-2025-9001/semantic-analysis", {}
        )

        feed_status, feed = self.get(
            "/api/intelligence/vulnerabilities?relevance=firmware&page=2&page_size=1"
        )
        explore_status, explore = self.get(
            "/api/intelligence/semantic/explore?kind=interface&page=1&page_size=10"
        )
        categories_status, categories = self.get(
            "/api/intelligence/semantic/categories"
        )
        recommend_status, recommendation = self.get(
            "/api/intelligence/semantic/interface-recommendation?value=%2Fgoform%2Fsave"
        )

        self.assertEqual(200, feed_status)
        self.assertEqual(2, feed["page"])
        self.assertEqual(1, len(feed["items"]))
        self.assertEqual(200, explore_status)
        self.assertGreaterEqual(explore["total"], 1)
        self.assertEqual(200, categories_status)
        self.assertGreaterEqual(categories["total"], 1)
        self.assertEqual(200, recommend_status)
        self.assertEqual(
            "goform_lower_registry",
            recommendation["selection"]["architecture"]["key"],
        )
        self.assertEqual(["/goform/apply"], [item["value"] for item in recommendation["items"]])

    def test_can_serve_built_console_and_spa_routes(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "index.html").write_text(
                "<!doctype html><title>FirmAtlas</title>", encoding="utf-8"
            )
            service = IntelligenceService(self.repository)
            self.server = ThreadingHTTPServer(
                ("127.0.0.1", 0), create_handler(service, static_dir=directory)
            )
            self.thread = threading.Thread(
                target=self.server.serve_forever, daemon=True
            )
            self.thread.start()

            with urlopen(
                "http://127.0.0.1:{}/semantic/interfaces".format(
                    self.server.server_port
                ),
                timeout=2,
            ) as response:
                body = response.read().decode("utf-8")

            self.assertEqual(200, response.status)
            self.assertIn("<title>FirmAtlas</title>", body)


if __name__ == "__main__":
    unittest.main()
