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

    def test_placeholder_identity_never_overwrites_known_vendor_and_product(self) -> None:
        base = demo_records()[0]
        known = replace(
            base, identifier="CVE-2025-2401", source_identifier="CVE-2025-2401",
            vendor="TP-Link", product="TL-WR1043ND firmware", source="nvd",
        )
        placeholder = replace(
            known, source="cisa-kev", vendor="n/a", product="unknown",
        )

        self.repository.upsert(known, self.classifier.classify(known, self.policy))
        self.repository.upsert(
            placeholder, self.classifier.classify(placeholder, self.policy)
        )

        stored = self.repository.get(known.identifier)
        self.assertEqual("TP-Link", stored["vendor"])
        self.assertEqual("TL-WR1043ND firmware", stored["product"])

    def test_identity_repair_restores_cpe_vendor_for_downstream_statistics(self) -> None:
        base = demo_records()[0]
        item = replace(
            base, identifier="CVE-2018-16119", source_identifier="CVE-2018-16119",
            vendor="TP-Link", product="tl-wr1043nd firmware",
            title="TP-Link TL-WR1043ND buffer overflow",
            summary=(
                "TP-Link WR1043nd firmware exposes the HTTP endpoint "
                "/userRpm/MediaServerFoldersCfgRpm.htm."
            ),
            cpes=(
                "cpe:2.3:o:tp-link:tl-wr1043nd_firmware:3.00:*:*:*:*:*:*:*",
            ),
        )
        self.repository.upsert(item, self.classifier.classify(item, self.policy))
        SemanticAnalysisService(self.repository).analyze_identifier(item.identifier)
        with self.repository.transaction() as connection:
            connection.execute(
                "UPDATE vulnerabilities SET vendor='n/a',product='n/a',title=? "
                "WHERE identifier=?",
                ("CVE-2018-16119 · n/a n/a", item.identifier),
            )

        repaired = self.repository.repair_vulnerability_identities(force=True)

        stored = self.repository.get(item.identifier)
        self.assertEqual(1, repaired)
        self.assertEqual("TP-Link", stored["vendor"])
        self.assertEqual("tl-wr1043nd firmware", stored["product"])
        self.assertEqual(
            "CVE-2018-16119 · TP-Link tl-wr1043nd firmware", stored["title"]
        )
        categories = self.repository.semantic_categories()["items"]
        management = next(row for row in categories if row["key"] == "management_route")
        self.assertEqual(1, management["vendor_count"])
        self.assertEqual(["TP-Link"], management["vendors"])

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

    def test_category_drilldown_groups_architecture_and_normalizes_models(self) -> None:
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
            {"flat_page_controller"},
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

    def test_architecture_filter_profiles_only_matching_firmware_families(self) -> None:
        base = demo_records()[0]
        fixtures = (
            replace(
                base, identifier="CVE-2025-2201", source_identifier="CVE-2025-2201",
                vendor="Tenda", product="AC10 firmware",
                summary="The HTTP endpoint /goform/SetOnlineDevName accepts the parameter name.",
            ),
            replace(
                base, identifier="CVE-2025-2202", source_identifier="CVE-2025-2202",
                vendor="Tenda", product="AC18 firmware",
                summary="The HTTP endpoint /goform/SetStaticRouteCfg accepts the parameter route.",
            ),
            replace(
                base, identifier="CVE-2025-2203", source_identifier="CVE-2025-2203",
                vendor="D-Link", product="DIR-825 firmware",
                summary="The HTTP endpoint /goform/goform_set_cmd_process accepts the parameter cmd.",
            ),
        )
        semantic = SemanticAnalysisService(self.repository)
        for item in fixtures:
            self.repository.upsert(item, self.classifier.classify(item, self.policy))
            semantic.analyze_identifier(item.identifier)

        result = self.repository.semantic_explore(
            "category", value="form_handler", subtype="goform_camel_registry", limit=10
        )
        profile = result["selection"]

        self.assertEqual(2, result["total"])
        self.assertEqual("goform_camel_registry", profile["active_subtype"]["key"])
        self.assertEqual(2, profile["scope_interface_count"])
        self.assertEqual(1, profile["scope_vendor_count"])
        self.assertEqual(["Tenda"], [item["vendor"] for item in profile["top_vendors"]])
        self.assertEqual(
            {"Tenda AC10 固件", "Tenda AC18 固件"},
            {item["label"] for item in profile["top_models"]},
        )
        camel = next(item for item in profile["subtypes"] if item["key"] == "goform_camel_registry")
        self.assertEqual(1, camel["vendor_count"])
        self.assertEqual(2, camel["model_count"])
        self.assertEqual(
            {"/goform/SetOnlineDevName", "/goform/SetStaticRouteCfg"},
            {item["value"] for item in camel["examples"]},
        )

    def test_interface_structure_recommendation_accepts_an_unseen_route(self) -> None:
        base = demo_records()[0]
        fixtures = (
            replace(
                base, identifier="CVE-2025-2301", source_identifier="CVE-2025-2301",
                vendor="Tenda", product="AC10 firmware",
                summary="The HTTP endpoint /goform/SetOnlineDevName accepts the parameter name.",
            ),
            replace(
                base, identifier="CVE-2025-2302", source_identifier="CVE-2025-2302",
                vendor="Tenda", product="AC18 firmware",
                summary="The HTTP endpoint /goform/SetStaticRouteCfg accepts the parameter route.",
            ),
            replace(
                base, identifier="CVE-2025-2303", source_identifier="CVE-2025-2303",
                vendor="D-Link", product="DIR-825 firmware",
                summary="The HTTP endpoint /goform/goform_set_cmd_process accepts the parameter cmd.",
            ),
        )
        semantic = SemanticAnalysisService(self.repository)
        for item in fixtures:
            self.repository.upsert(item, self.classifier.classify(item, self.policy))
            semantic.analyze_identifier(item.identifier)

        result = self.repository.recommend_interface_structure(
            "/goform/SetGuestWifiCfg", limit=10
        )

        self.assertEqual("form_handler", result["selection"]["category"]["key"])
        self.assertEqual(
            "goform_camel_registry", result["selection"]["architecture"]["key"]
        )
        self.assertFalse(result["selection"]["observed"])
        self.assertEqual(
            {"/goform/SetOnlineDevName", "/goform/SetStaticRouteCfg"},
            {item["value"] for item in result["items"]},
        )
        self.assertTrue(all(item["similarity_score"] >= 80 for item in result["items"]))
        self.assertEqual(["Tenda"], [item["vendor"] for item in result["related_vendors"]])
        self.assertEqual(
            {"Tenda AC10 固件", "Tenda AC18 固件"},
            {item["label"] for item in result["related_firmware"]},
        )
        self.assertEqual(
            {"CVE-2025-2301", "CVE-2025-2302"},
            {item["identifier"] for item in result["related_vulnerabilities"]},
        )

        full_url = self.repository.recommend_interface_structure(
            "http://router.local/goform/SetGuestWifiCfg?token=secret", limit=10
        )
        self.assertEqual(
            "/goform/SetGuestWifiCfg", full_url["selection"]["normalized_value"]
        )
        self.assertEqual(
            {item["value"] for item in result["items"]},
            {item["value"] for item in full_url["items"]},
        )

    def test_form_handler_subtypes_describe_backend_registration_architecture(self) -> None:
        base = demo_records()[0]
        expected = {
            "/goform/SetOnlineDevName": "goform_camel_registry",
            "/goform/SetStaticRouteCfg": "goform_camel_registry",
            "/goform/goform_set_cmd_process": "goform_snake_registry",
            "/goform/ate": "goform_lower_registry",
            "/goform/*": "goform_wildcard_dispatcher",
        }
        semantic = SemanticAnalysisService(self.repository)
        for index, route in enumerate(expected, start=1):
            item = replace(
                base,
                identifier="CVE-2025-31{:02d}".format(index),
                source_identifier="CVE-2025-31{:02d}".format(index),
                summary="The HTTP endpoint {} accepts the parameter value.".format(route),
            )
            self.repository.upsert(item, self.classifier.classify(item, self.policy))
            semantic.analyze_identifier(item.identifier)
        duplicate = replace(
            base,
            identifier="CVE-2025-3199",
            source_identifier="CVE-2025-3199",
            summary="The HTTP endpoint /goform/SetOnlineDevName accepts the parameter name.",
        )
        self.repository.upsert(
            duplicate, self.classifier.classify(duplicate, self.policy)
        )
        semantic.analyze_identifier(duplicate.identifier)

        result = self.repository.semantic_explore(
            "category", value="form_handler", limit=20
        )

        self.assertEqual(
            expected,
            {item["value"]: item["subtype"] for item in result["items"]},
        )
        self.assertEqual(5, result["selection"]["interface_count"])

    def test_all_style_subtypes_describe_backend_routing_architecture(self) -> None:
        base = demo_records()[0]
        expected = {
            "cgi_gateway": {
                "/cgi-bin/cstecgi.cgi": "shared_cgi_dispatcher",
                "/cgi-bin/admin/setparam.cgi": "nested_cgi_module",
                "/cgi-bin/account_mgr.cgi": "cgi_executable_registry",
                "/authentication.cgi": "external_cgi_handler",
            },
            "hnap_soap": {
                "/HNAP1": "hnap_envelope_dispatcher",
                "/HNAP1/SetClientInfo": "hnap_uri_method",
                "/control/WANIPConnection": "upnp_service_control",
                "/web/cgi-bin/hnap/hnap_service": "soap_service_endpoint",
            },
            "resource_api": {
                "/api/v1/devices/register": "versioned_resource_router",
                "/api/CONFIG/restore": "namespaced_api_router",
                "/api/login": "flat_api_registry",
            },
            "web_action": {
                "/importexport.php": "flat_page_controller",
                "/sysmanage/updateos.php": "namespaced_page_controller",
                "/home.jsp": "servlet_page_controller",
                "/download.do": "framework_action_dispatcher",
            },
            "management_route": {
                "/boafrm/formFilter": "boafrm_handler_registry",
                "/RPC2": "flat_named_management_handler",
                "/admin/sign/DeviceSynch": "namespaced_management_router",
                "/config.xml": "structured_data_endpoint",
                "/images/captcha.jpeg": "media_endpoint",
                "/opaque/path": "unresolved_management_route",
            },
        }
        semantic = SemanticAnalysisService(self.repository)
        index = 0
        for routes in expected.values():
            for route in routes:
                index += 1
                item = replace(
                    base,
                    identifier="CVE-2025-32{:02d}".format(index),
                    source_identifier="CVE-2025-32{:02d}".format(index),
                    summary="The HTTP endpoint {} accepts the parameter value.".format(route),
                )
                self.repository.upsert(
                    item, self.classifier.classify(item, self.policy)
                )
                semantic.analyze_identifier(item.identifier)

        for category, routes in expected.items():
            result = self.repository.semantic_explore(
                "category", value=category, limit=50
            )
            actual = {item["value"]: item["subtype"] for item in result["items"]}
            self.assertEqual(routes, actual)


if __name__ == "__main__":
    unittest.main()
