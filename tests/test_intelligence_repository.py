import unittest
from dataclasses import replace

from firmatlas.intelligence.models import RelevancePolicy
from firmatlas.intelligence.relevance import FirmwareRelevanceClassifier
from firmatlas.intelligence.repository import IntelligenceRepository
from firmatlas.intelligence.sample_data import demo_records
from firmatlas.intelligence.semantic_service import SemanticAnalysisService


class IntelligenceRepositoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = IntelligenceRepository(":memory:")
        self.classifier = FirmwareRelevanceClassifier()
        self.policy = RelevancePolicy()

    def tearDown(self) -> None:
        self.repository.close()

    def test_upsert_search_and_overview(self) -> None:
        for item in demo_records()[:2]:
            self.repository.upsert(item, self.classifier.classify(item, self.policy))

        result = self.repository.list(query="Hikvision")
        overview = self.repository.overview()

        self.assertEqual(1, result["total"])
        self.assertEqual("CVE-2026-29417", result["items"][0]["identifier"])
        self.assertEqual(2, overview["counts"]["relevant"])
        self.assertEqual(1, overview["counts"]["kev"])

    def test_policy_update_reclassifies_existing_records(self) -> None:
        item = demo_records()[0]
        self.repository.upsert(item, self.classifier.classify(item, self.policy))
        policy = RelevancePolicy(
            firmware_keywords=(), device_keywords=(), firmware_only_vendors=()
        )
        self.repository.save_policy(policy)

        count = self.repository.reclassify(self.classifier, policy)

        self.assertEqual(1, count)
        self.assertEqual(
            "unrelated", self.repository.get(item.identifier)["relevance_level"]
        )

    def test_bulk_fts_exploit_cwe_and_statistics(self) -> None:
        items = []
        for record in demo_records()[:2]:
            items.append((record, self.classifier.classify(record, self.policy)))
        self.repository.upsert_many(items)

        self.assertEqual(1, self.repository.list(query="Hikvision")["total"])
        self.assertEqual(1, self.repository.list(cwe="CWE-78")["total"])
        statistics = self.repository.statistics()
        self.assertEqual(2, statistics["counts"]["total"])
        self.assertTrue(statistics["severity"])

    def test_vendor_filter_is_exact_and_composes_with_other_filters(self) -> None:
        items = [
            (record, self.classifier.classify(record, self.policy))
            for record in demo_records()[:4]
        ]
        self.repository.upsert_many(items)

        result = self.repository.list(vendor="QNAP", severity="HIGH")

        self.assertEqual(1, result["total"])
        self.assertEqual("QNAP", result["items"][0]["vendor"])
        self.assertEqual("HIGH", result["items"][0]["severity"])

    def test_feed_pages_are_newest_first_and_include_semantic_badges(self) -> None:
        base = demo_records()[0]
        older = replace(
            base, identifier="CVE-2024-0001", source_identifier="CVE-2024-0001",
            published_at="2024-01-01T00:00:00Z", modified_at="2024-01-02T00:00:00Z",
            summary="The HTTP endpoint /goform/apply accepts the argument cmd.",
        )
        newer = replace(
            base, identifier="CVE-2025-0001", source_identifier="CVE-2025-0001",
            published_at="2025-03-01T00:00:00Z", modified_at="2025-03-02T00:00:00Z",
        )
        for item in (older, newer):
            self.repository.upsert(item, self.classifier.classify(item, self.policy))
        SemanticAnalysisService(self.repository).analyze_identifier(older.identifier)

        first = self.repository.list(limit=1, offset=0)
        second = self.repository.list(limit=1, offset=1)

        self.assertEqual("CVE-2025-0001", first["items"][0]["identifier"])
        self.assertEqual(1, first["page"])
        self.assertEqual(2, first["pages"])
        self.assertTrue(first["has_next"])
        self.assertEqual("CVE-2024-0001", second["items"][0]["identifier"])
        self.assertEqual(1, second["items"][0]["semantic_interface_count"])
        self.assertEqual(1, second["items"][0]["semantic_parameter_count"])

    def test_semantic_explorer_lists_observations_and_associated_firmware(self) -> None:
        base = demo_records()[0]
        fixtures = (
            replace(
                base, identifier="CVE-2024-1001", source_identifier="CVE-2024-1001",
                vendor="D-Link", product="Router firmware",
                summary="The HTTP endpoint /goform/apply accepts the argument cmd.",
            ),
            replace(
                base, identifier="CVE-2024-1002", source_identifier="CVE-2024-1002",
                vendor="Tenda", product="AC firmware",
                summary="The CGI endpoint /cgi-bin/apply.cgi accepts the parameter page.",
            ),
        )
        semantic = SemanticAnalysisService(self.repository)
        for item in fixtures:
            self.repository.upsert(item, self.classifier.classify(item, self.policy))
            semantic.analyze_identifier(item.identifier)

        catalog = self.repository.semantic_explore("interface", limit=10)
        detail = self.repository.semantic_explore(
            "interface", value="/goform/apply", limit=10
        )
        categories = self.repository.semantic_categories()

        self.assertEqual(2, catalog["total"])
        self.assertEqual("/cgi-bin/apply.cgi", catalog["items"][0]["value"])
        self.assertEqual("form_handler", detail["selection"]["category"])
        self.assertEqual("D-Link", detail["items"][0]["vendor"])
        self.assertEqual("Router firmware", detail["items"][0]["product"])
        self.assertEqual(
            {"cgi_gateway", "form_handler"},
            {item["key"] for item in categories["items"]},
        )

    def test_category_drilldown_distinguishes_actions_and_normalizes_models(self) -> None:
        base = demo_records()[0]
        fixtures = (
            replace(
                base, identifier="CVE-2025-2101", source_identifier="CVE-2025-2101",
                vendor="D-Link", product="DIR-816 A2 firmware",
                summary="The HTTP endpoint /importexport.php accepts the parameter file.",
                cpes=("cpe:2.3:o:dlink:dir-816_a2_firmware:1.10CNB04:*:*:*:*:*:*:*",),
            ),
            replace(
                base, identifier="CVE-2025-2102", source_identifier="CVE-2025-2102",
                vendor="Tenda", product="AC18 firmware",
                summary="The HTTP endpoint /upgrade_filter.asp accepts the parameter image.",
                cpes=("cpe:2.3:o:tenda:ac18_firmware:15.03.05.19:*:*:*:*:*:*:*",),
            ),
            replace(
                base, identifier="CVE-2025-2103", source_identifier="CVE-2025-2103",
                vendor="D-Link", product="DIR-878 firmware",
                summary="The HTTP endpoint /dbsrv.asp accepts the parameter query.",
            ),
        )
        semantic = SemanticAnalysisService(self.repository)
        for item in fixtures:
            self.repository.upsert(item, self.classifier.classify(item, self.policy))
            semantic.analyze_identifier(item.identifier)

        result = self.repository.semantic_explore(
            "category", value="web_action", query="", limit=10
        )

        self.assertEqual(3, result["total"])
        self.assertEqual(
            {
                "import_export_action",
                "firmware_upgrade_action",
                "data_service_action",
            },
            {item["subtype"] for item in result["items"]},
        )
        profile = result["selection"]
        self.assertEqual("动态页面动作", profile["label"])
        self.assertEqual("D-Link", profile["top_vendors"][0]["vendor"])
        self.assertIn("D-Link DIR-816 A2 固件", {
            item["label"] for item in profile["top_models"]
        })
        model = next(
            item for item in profile["top_models"]
            if item["label"] == "D-Link DIR-816 A2 固件"
        )
        self.assertEqual("1.10CNB04", model["version_summary"])
        self.assertEqual("description", model["source"])
        self.assertNotIn("cpe:", str(profile).lower())

        filtered = self.repository.semantic_explore(
            "category", value="web_action", query="upgrade", limit=10
        )
        self.assertEqual(["/upgrade_filter.asp"], [item["value"] for item in filtered["items"]])


if __name__ == "__main__":
    unittest.main()
