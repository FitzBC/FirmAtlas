import json
import hashlib
import copy
from pathlib import Path
import tempfile
import threading
import unittest
from dataclasses import replace
from urllib.request import Request, urlopen
from urllib.parse import urlencode

from firmatlas.intelligence.api import create_handler
from firmatlas.intelligence.relevance import FirmwareRelevanceClassifier
from firmatlas.intelligence.repository import IntelligenceRepository
from firmatlas.intelligence.sample_data import demo_records
from firmatlas.intelligence.service import IntelligenceService
from http.server import ThreadingHTTPServer
from firmatlas.mapping import (
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    discover_frontend_requests,
)
from firmatlas.mapping.repository import DiscoveryCatalogRepository
from tests.test_mapping_hidden_interface import _catalog as _hidden_catalog


class IntelligenceApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = IntelligenceRepository(":memory:")
        classifier = FirmwareRelevanceClassifier()
        policy = self.repository.get_policy()
        for record in demo_records()[:2]:
            self.repository.upsert(record, classifier.classify(record, policy))
        service = IntelligenceService(self.repository)
        self.mapping_repository = DiscoveryCatalogRepository(":memory:")
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            create_handler(service, mapping_repository=self.mapping_repository),
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.mapping_repository.close()
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

    def test_mapping_catalog_routes_expose_search_and_evidence_detail(self) -> None:
        content = b'''var submitStr = "mac=" + mac + "&devName=" + name;
        $.post("/goform/SetOnlineDevName", submitStr, callback);'''
        source = SourceArtifactEntry(
            canonical_path="webroot/js/online.js", original_path="webroot/js/online.js",
            kind="file", size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )
        frontend = discover_frontend_requests(source, content)
        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64, "2" * 64,
            (DiscoveryProducerBatch.frontend((frontend,), "webroot/**/*.js"),),
        ))
        self.mapping_repository.publish(catalog)

        list_status, catalogs = self.get("/api/mappings/catalogs")
        search_status, candidates = self.get(
            "/api/mappings/catalogs/{}/candidates?q=online%20dev&kind=request_interface".format(
                catalog.catalog_id
            )
        )
        candidate_id = candidates["items"][0]["candidate_id"]
        detail_status, detail = self.get(
            "/api/mappings/catalogs/{}/candidates/{}".format(
                catalog.catalog_id, candidate_id
            )
        )

        self.assertEqual(200, list_status)
        self.assertEqual(1, catalogs["total"])
        self.assertEqual(200, search_status)
        self.assertEqual("/goform/SetOnlineDevName", candidates["items"][0]["canonical_identity"])
        self.assertEqual(200, detail_status)
        self.assertEqual({"mac", "devName"}, {x["name"] for x in detail["parameters"]})

    def test_mapping_hidden_interface_route_exposes_cross_firmware_projection(self) -> None:
        self.mapping_repository.publish(_hidden_catalog())

        status, result = self.get(
            "/api/mappings/potential-hidden-interfaces?q=hidden%20operation"
        )

        self.assertEqual(200, status)
        self.assertEqual(1, result["total"])
        self.assertEqual("hiddenOperation", result["items"][0]["operation_token"])

    def test_mapping_snapshot_comparison_route(self) -> None:
        base = _hidden_catalog().to_dict()
        target = copy.deepcopy(base)
        target["catalog_id"] = "discovery-catalog:" + "7" * 64
        target["firmware_artifact_sha256"] = "7" * 64
        target["candidates"] = [
            item for item in target["candidates"]
            if item["candidate_kind"] != "set_difference_attribution"
        ]
        self.mapping_repository.publish_dict(base)
        self.mapping_repository.publish_dict(target)

        status, result = self.get(
            "/api/mappings/compare?" + urlencode({
                "base": base["catalog_id"], "target": target["catalog_id"],
            })
        )

        self.assertEqual(200, status)
        self.assertEqual(1, result["summary"]["resolved_hidden_interface_count"])
        self.assertFalse(result["same_firmware_family_verified"])

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

    def test_firmware_catalog_routes_support_bidirectional_lookup(self) -> None:
        self.repository.upsert_firmware_sources(({
            "source_id": "fixture", "name": "Fixture source",
            "source_type": "benchmark", "base_url": "https://example.test",
            "vendor": None, "trust_level": "high", "access_notes": "",
            "evidence_url": "https://example.test/evidence",
        },))
        self.repository.upsert_firmware_candidates(({
            "candidate_id": "fixture:BM-1", "source_id": "fixture",
            "external_id": "BM-1", "vendor": "Hikvision", "product": "DS-2CD",
            "model": "DS-2CD", "firmware_version": "V1", "filename": "firmware.bin",
            "download_url": "https://example.test/firmware.bin",
            "source_page_url": "https://example.test/BM-1",
            "evidence_url": "https://example.test/evidence", "url_status": "listed",
            "download_kind": "direct", "notes": "",
        },))
        self.repository.upsert_firmware_vulnerability_leads(({
            "candidate_id": "fixture:BM-1",
            "vulnerability_identifier": "CVE-2026-29417",
            "relationship": "verified_benchmark_environment", "confidence": "high",
            "evidence_url": "https://example.test/detail", "notes": "",
            "association_origin": "derived", "match_method": "exact_version",
            "match_score": 98, "candidate_version": "V1",
            "affected_constraint": "V1",
            "matched_criteria": "cpe:2.3:o:hikvision:ds-2cd_firmware:v1:*:*:*:*:*:*:*",
        },))

        overview_status, overview = self.get("/api/firmware/overview")
        page_status, page = self.get("/api/firmware/candidates?q=CVE-2026-29417")
        detail_status, detail = self.get("/api/firmware/candidates/fixture%3ABM-1")
        reverse_status, reverse = self.get(
            "/api/firmware/vulnerabilities/CVE-2026-29417/samples"
        )
        version_status, version_page = self.get(
            "/api/firmware/candidates?match=version"
        )

        self.assertEqual(200, overview_status)
        self.assertEqual(1, overview["counts"]["candidate_count"])
        self.assertEqual(200, page_status)
        self.assertEqual(1, page["total"])
        self.assertEqual(200, detail_status)
        self.assertEqual("firmware.bin", detail["filename"])
        self.assertEqual(200, reverse_status)
        self.assertEqual("fixture:BM-1", reverse["items"][0]["candidate_id"])
        self.assertEqual("exact_version", reverse["items"][0]["match_method"])
        self.assertEqual(200, version_status)
        self.assertEqual(1, version_page["total"])
        self.assertEqual(1, overview["counts"]["exact_version_link_count"])


if __name__ == "__main__":
    unittest.main()
