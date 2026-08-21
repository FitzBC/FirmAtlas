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
    CorpusEvidenceTier,
    CorpusReportInput,
    CorpusSampleInput,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    discover_frontend_requests,
    HistoricalApplicability,
    HistoricalInterfaceExpectation,
    compare_historical_expectations,
    compare_historical_route_bindings,
    project_historical_graph_overlay,
    project_communication_architecture_graph,
    FirmwareMappingJobSnapshot,
    FirmwareMappingJobStatus,
    MappingReasoningProposal,
    MappingReasoningRun,
    MappingReasoningRunStatus,
    build_corpus_report,
)
from firmatlas.mapping.repository import DiscoveryCatalogRepository
from tests.test_mapping_hidden_interface import _catalog as _hidden_catalog
from tests.test_mapping_historical_coverage_ledger import _ledger_fixture
from firmatlas.mapping import build_historical_coverage_ledger


class FakeMappingJobService:
    max_upload_bytes = 64 * 1024 * 1024

    def __init__(self):
        self.submitted = []
        self.snapshot = FirmwareMappingJobSnapshot(
            job_id="firmware-mapping-job:" + "a" * 64,
            original_filename="ac9.trx",
            firmware_artifact_sha256="b" * 64,
            artifact_size=12,
            runner_id="test-runner/v1",
            status=FirmwareMappingJobStatus.QUEUED,
            submitted_at="2026-08-18T00:00:00+00:00",
        )

    def submit(self, stream, filename, content_length, release_context=None):
        self.submitted.append((
            stream.read(content_length), filename, content_length, release_context,
        ))
        return self.snapshot

    def get(self, job_id):
        return self.snapshot if job_id == self.snapshot.job_id else None

    def list(self, limit=20):
        return (self.snapshot,)


class FakeMappingReasoningService:
    adapter_id = "minimax-reasoner:test"

    def __init__(self):
        self.submitted = []
        self.run = MappingReasoningRun(
            run_id="mapping-reasoning-run:" + "c" * 64,
            catalog_id="discovery-catalog:" + "d" * 64,
            firmware_artifact_sha256="e" * 64,
            adapter_id=self.adapter_id,
            status=MappingReasoningRunStatus.COMPLETED,
            submitted_at="2026-08-18T00:00:00+00:00",
            finished_at="2026-08-18T00:00:02+00:00",
            proposals=(MappingReasoningProposal(
                proposal_id="mapping-reasoning-proposal:" + "f" * 64,
                kind="analysis_step",
                target_ref="candidate:ac9",
                summary="Trace registrar call sites.",
                rationale="A route owner remains unresolved.",
                cited_evidence_ids=("evidence:ac9",),
                required_corroboration="deterministic call-site evidence",
                confidence=0.8,
            ),),
        )

    def submit(self, catalog_id):
        self.submitted.append(catalog_id)
        return self.run

    def latest(self, catalog_id):
        return self.run if catalog_id == self.run.catalog_id else None


class IntelligenceApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = IntelligenceRepository(":memory:")
        classifier = FirmwareRelevanceClassifier()
        policy = self.repository.get_policy()
        for record in demo_records()[:2]:
            self.repository.upsert(record, classifier.classify(record, policy))
        service = IntelligenceService(self.repository)
        self.mapping_repository = DiscoveryCatalogRepository(":memory:")
        self.mapping_jobs = FakeMappingJobService()
        self.mapping_reasoning = FakeMappingReasoningService()
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            create_handler(
                service,
                mapping_repository=self.mapping_repository,
                mapping_job_service=self.mapping_jobs,
                mapping_reasoning_service=self.mapping_reasoning,
            ),
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

    def post_artifact(self, path, payload, filename, identity=None):
        identity = identity or {}
        request = Request(
            "http://127.0.0.1:{}{}".format(self.server.server_port, path),
            data=payload,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Firmware-Filename": filename,
                **identity,
            },
            method="POST",
        )
        with urlopen(request, timeout=2) as response:
            return response.status, json.loads(response.read())["data"]

    def test_mapping_job_routes_accept_artifact_and_expose_lifecycle(self) -> None:
        status, submitted = self.post_artifact(
            "/api/mappings/jobs", b"AC9 firmware", "ac9.trx", {
                "X-Firmware-Vendor": "Tenda",
                "X-Firmware-Product": "AC9",
                "X-Device-Model": "AC9",
                "X-Firmware-Version": "V15.03.05.19(6318)",
            },
        )
        detail_status, detail = self.get(
            "/api/mappings/jobs/{}".format(submitted["job_id"])
        )
        list_status, listing = self.get("/api/mappings/jobs")

        self.assertEqual(202, status)
        self.assertEqual("queued", submitted["status"])
        self.assertEqual(
            ("Tenda", "AC9", "AC9", "V15.03.05.19(6318)"),
            tuple(getattr(self.mapping_jobs.submitted[0][3], field) for field in (
                "vendor", "product", "device_model", "firmware_version",
            )),
        )
        self.assertEqual(200, detail_status)
        self.assertEqual(submitted["job_id"], detail["job_id"])
        self.assertEqual(200, list_status)
        self.assertTrue(listing["enabled"])
        self.assertEqual([submitted["job_id"]], [item["job_id"] for item in listing["items"]])

    def test_mapping_reasoning_routes_expose_capability_and_proposal_run(self) -> None:
        catalog_id = self.mapping_reasoning.run.catalog_id

        submitted_status, submitted = self.post(
            "/api/mappings/catalogs/{}/reasoning".format(catalog_id), {}
        )
        observed_status, observed = self.get(
            "/api/mappings/catalogs/{}/reasoning".format(catalog_id)
        )

        self.assertEqual(202, submitted_status)
        self.assertEqual([catalog_id], self.mapping_reasoning.submitted)
        self.assertEqual("model_suggested", submitted["proposals"][0]["status"])
        self.assertEqual(200, observed_status)
        self.assertTrue(observed["enabled"])
        self.assertEqual("minimax-reasoner:test", observed["adapter_id"])
        self.assertEqual(submitted["run_id"], observed["latest"]["run_id"])

    def test_mapping_corpus_route_returns_latest_published_gate(self) -> None:
        catalog = _hidden_catalog()
        report = build_corpus_report(CorpusReportInput(
            corpus_version="firmatlas.mapping.corpus/test",
            required_categories=("native_only",),
            samples=(CorpusSampleInput(
                "native", "native_only", "native_registry", "test",
                CorpusEvidenceTier.REAL_FIRMWARE,
                required_capabilities=("binds_handler",),
                expected_firmware_sha256=catalog.firmware_artifact_sha256,
                catalog=catalog,
            ),),
        ))
        self.mapping_repository.publish_corpus_report(report)

        status, observed = self.get("/api/mappings/corpus-report")

        self.assertEqual(200, status)
        self.assertEqual(report.report_id, observed["report_id"])
        self.assertEqual("passed", observed["gate_status"])

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

    def test_mapping_catalog_force_graph_route_excludes_frontend_static_resources(self) -> None:
        content = b'''var body = "timezone=" + zone;
        $.post("/goform/SetTimeCfg", body, callback);'''
        source = SourceArtifactEntry(
            canonical_path="webroot/js/system.js", original_path="webroot/js/system.js",
            kind="file", size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )
        frontend = discover_frontend_requests(source, content)
        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64, "2" * 64,
            (DiscoveryProducerBatch.frontend((frontend,), "webroot/**/*.js"),),
        ))
        self.mapping_repository.publish(catalog)

        status, result = self.get(
            "/api/mappings/catalogs/{}/interface-force-graph".format(catalog.catalog_id)
        )

        self.assertEqual(200, status)
        self.assertEqual(catalog.catalog_id, result["catalog_id"])
        self.assertEqual({"firmware"}, {item["node_kind"] for item in result["nodes"]})
        self.assertEqual(0, result["summary"]["interface_count"])
        self.assertEqual(1, result["summary"]["excluded_static_resource_interface_count"])
        self.assertIn("不自动证明完整 URL", result["claim_boundary"])

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

    def test_mapping_graph_routes_reuse_persisted_query_semantics(self) -> None:
        catalog = _hidden_catalog()
        graph = project_communication_architecture_graph(catalog)
        self.mapping_repository.publish(catalog)
        self.mapping_repository.publish_communication_graph(graph)

        list_status, listing = self.get("/api/mappings/graphs")
        query_status, result = self.get(
            "/api/mappings/graphs/{}?{}".format(
                graph.graph_id,
                urlencode({
                    "preset": "interface_structure",
                    "focus_identity": "/cgi-bin/cstecgi.cgi",
                    "max_hops": 1,
                    "max_nodes": 50,
                    "max_edges": 100,
                }),
            )
        )

        self.assertEqual(200, list_status)
        self.assertEqual(1, listing["total"])
        self.assertEqual(graph.graph_id, listing["items"][0]["graph_id"])
        self.assertEqual(200, query_status)
        self.assertEqual(graph.graph_id, result["graph"]["graph_id"])
        self.assertEqual("completed", result["query_status"])
        self.assertIn(
            "interface", {item["node_kind"] for item in result["nodes"]}
        )
        self.assertTrue(result["evidence_atoms"])

    def test_mapping_graph_historical_overlay_route_keeps_scope_separate(self) -> None:
        catalog = _hidden_catalog()
        graph = project_communication_architecture_graph(catalog)
        expectation = HistoricalInterfaceExpectation(
            vulnerability_identifier="CVE-context",
            interface_value="/cgi-bin/cstecgi.cgi",
            parameters=(),
            source_ref="historical-semantic-analysis:CVE-context",
            applicability=HistoricalApplicability.OUT_OF_SCOPE,
            claimed_versions=("other-version",),
            applicability_basis="Cross-version structural comparison.",
        )
        diff = compare_historical_expectations(catalog, (expectation,))
        overlay = project_historical_graph_overlay(
            graph,
            diff,
            compare_historical_route_bindings(catalog, (expectation,)),
        )
        self.mapping_repository.publish(catalog)
        self.mapping_repository.publish_communication_graph(graph)
        self.mapping_repository.publish_historical_graph_overlay(overlay)

        status, result = self.get(
            "/api/mappings/graphs/{}/historical-overlay?{}".format(
                graph.graph_id,
                urlencode({
                    "status": "observed",
                    "applicability": "out_of_scope",
                }),
            )
        )

        self.assertEqual(200, status)
        self.assertEqual(1, result["selected_entry_count"])
        self.assertEqual("observed", result["entries"][0]["status"])
        self.assertEqual(
            "out_of_scope", result["entries"][0]["applicability"]
        )
        self.assertIn("contextual expectations", result["overlay"][
            "claim_boundary"
        ])

    def test_mapping_graph_historical_coverage_route_explains_full_denominator(self) -> None:
        catalog, graph, overlay, queue = _ledger_fixture()
        ledger = build_historical_coverage_ledger(overlay, queue)
        self.mapping_repository.publish(catalog)
        self.mapping_repository.publish_communication_graph(graph)
        self.mapping_repository.publish_historical_graph_overlay(overlay)
        self.mapping_repository.publish_historical_coverage_ledger(ledger)

        status, result = self.get(
            "/api/mappings/graphs/{}/historical-coverage?{}".format(
                graph.graph_id,
                urlencode({
                    "q": "security.ddos.map",
                    "status": "partial",
                    "audit_category": "parameter_only",
                }),
            )
        )

        self.assertEqual(200, status)
        self.assertEqual(3, result["total_entry_count"])
        self.assertEqual(1, result["selected_entry_count"])
        self.assertEqual("CVE-parameter", result["entries"][0][
            "vulnerability_identifier"
        ])
        self.assertIn("do not assert vulnerability presence", result["ledger"][
            "claim_boundary"
        ])

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
