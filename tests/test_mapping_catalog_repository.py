import hashlib
import io
import json
import copy
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest

from firmatlas.mapping import (
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    MappingReleaseContext,
    SourceArtifactEntry,
    UbusArtifactInput,
    assemble_discovery_catalog,
    discover_frontend_requests,
    discover_ubus_backend_graph,
    ubus_operation_references_from_frontend,
)
from tests.test_mapping_hidden_interface import _catalog as _hidden_catalog
from firmatlas.mapping.repository import (
    CatalogConflictError,
    DiscoveryCatalogRepository,
)
from firmatlas.cli import main


def _catalog():
    content = b'''function changeDevName(macAddress, newName) {
      var submitStr = "mac=" + macAddress + "&devName=" + encodeURIComponent(newName);
      $.post("/goform/SetOnlineDevName", submitStr, callback);
    }'''
    source = SourceArtifactEntry(
        canonical_path="webroot/js/device.js",
        original_path="webroot/js/device.js",
        kind="file",
        size=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
    )
    frontend = discover_frontend_requests(source, content)
    return assemble_discovery_catalog(DiscoveryCatalogInput(
        firmware_artifact_sha256="1" * 64,
        source_inventory_sha256="2" * 64,
        batches=(DiscoveryProducerBatch.frontend((frontend,), "webroot/**/*.js"),),
    ))


class DiscoveryCatalogRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.repository = DiscoveryCatalogRepository(":memory:")
        self.catalog = _catalog()

    def tearDown(self):
        self.repository.close()

    def test_publish_is_idempotent_and_lists_catalog_summary(self):
        first = self.repository.publish(self.catalog)
        second = self.repository.publish(self.catalog)

        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        result = self.repository.list_catalogs()
        self.assertEqual(1, result["total"])
        self.assertEqual(self.catalog.catalog_id, result["items"][0]["catalog_id"])
        self.assertEqual(len(self.catalog.candidates), result["items"][0]["candidate_count"])
        self.assertEqual(len(self.catalog.parameters), result["items"][0]["parameter_count"])
        self.assertEqual(
            "completed",
            result["items"][0]["source_inventory_coverage_status"],
        )

    def test_same_catalog_id_with_different_payload_is_rejected(self):
        self.repository.publish(self.catalog)
        payload = self.catalog.to_dict()
        payload["coverage_status"] = "failed"
        with self.assertRaises(CatalogConflictError):
            self.repository.publish_dict(payload)

    def test_candidate_query_filters_text_and_kind_and_reports_counts(self):
        self.repository.publish(self.catalog)
        result = self.repository.query_candidates(
            self.catalog.catalog_id,
            query="online dev",
            candidate_kind="request_interface",
            limit=10,
            offset=0,
        )
        self.assertEqual(1, result["total"])
        item = result["items"][0]
        self.assertEqual("/goform/SetOnlineDevName", item["canonical_identity"])
        self.assertEqual(2, item["parameter_count"])
        self.assertEqual(0, item["association_count"])
        self.assertEqual(0, item["open_obligation_count"])

    def test_candidate_detail_aggregates_parameters_evidence_and_catalog_coverage(self):
        self.repository.publish(self.catalog)
        candidate = self.catalog.candidates[0]
        detail = self.repository.get_candidate(self.catalog.catalog_id, candidate.candidate_id)

        self.assertEqual(candidate.candidate_id, detail["candidate"]["candidate_id"])
        self.assertEqual({"mac", "devName"}, {x["name"] for x in detail["parameters"]})
        self.assertGreaterEqual(len(detail["evidence_atoms"]), 1)
        self.assertEqual(1, len(detail["coverage"]))
        self.assertEqual(
            "completed", detail["catalog"]["source_inventory_coverage_status"]
        )
        self.assertEqual([], detail["associations"])
        self.assertEqual([], detail["open_obligations"])

    def test_candidate_detail_follows_ubus_binding_to_runtime_principal(self):
        frontend_content = b"rpc.declare({object:'luci',method:'getFeatures'});"
        frontend_source = SourceArtifactEntry(
            "www/system.js", "www/system.js", "file", len(frontend_content),
            hashlib.sha256(frontend_content).hexdigest(),
        )
        frontend = discover_frontend_requests(frontend_source, frontend_content)
        plugin_content = b'''#!/usr/bin/env lua
local methods = { getFeatures = { args = {}, call = function() end } }
if arg[1] == "list" then elseif arg[1] == "call" then end
'''
        plugin_source = SourceArtifactEntry(
            "usr/libexec/rpcd/luci", "usr/libexec/rpcd/luci", "file",
            len(plugin_content), hashlib.sha256(plugin_content).hexdigest(),
        )
        backend = discover_ubus_backend_graph(
            ubus_operation_references_from_frontend((frontend,)),
            (UbusArtifactInput(plugin_source, plugin_content),),
        )
        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            firmware_artifact_sha256="3" * 64,
            source_inventory_sha256="4" * 64,
            batches=(
                DiscoveryProducerBatch.frontend((frontend,), "www/**/*.js"),
                DiscoveryProducerBatch.ubus_backend((backend,), "usr/libexec/rpcd/*"),
            ),
        ))
        repository = DiscoveryCatalogRepository(":memory:")
        try:
            repository.publish(catalog)
            operation = next(
                item for item in catalog.candidates
                if item.candidate_kind.value == "request_interface"
            )
            detail = repository.get_candidate(catalog.catalog_id, operation.candidate_id)
        finally:
            repository.close()

        self.assertEqual(
            {"ubus_backend_binding", "runtime_principal"},
            {item["candidate_kind"] for item in detail["related_candidates"]},
        )

    def test_unknown_catalog_and_candidate_return_none(self):
        self.assertIsNone(self.repository.get_catalog("missing"))
        self.repository.publish(self.catalog)
        self.assertIsNone(self.repository.get_candidate(self.catalog.catalog_id, "missing"))

    def test_compare_catalogs_uses_published_documents(self):
        self.repository.publish(self.catalog)
        target = copy.deepcopy(self.catalog.to_dict())
        target["catalog_id"] = "discovery-catalog:" + "9" * 64
        target["firmware_artifact_sha256"] = "9" * 64
        request = next(
            item for item in target["candidates"]
            if item["candidate_kind"] == "request_interface"
        )
        request["attributes"] = [
            [key, "PUT" if key == "method" else value]
            for key, value in request["attributes"]
        ]
        self.repository.publish_dict(target)

        result = self.repository.compare_catalogs(
            self.catalog.catalog_id, target["catalog_id"]
        )

        self.assertEqual("coverage_equivalent", result["comparison_status"])
        self.assertEqual(1, result["summary"]["changed_candidate_count"])
        self.assertIsNone(self.repository.compare_catalogs("missing", target["catalog_id"]))

    def test_release_context_makes_version_family_explicit_and_immutable(self):
        self.repository.publish(self.catalog)
        target = copy.deepcopy(self.catalog.to_dict())
        target["catalog_id"] = "discovery-catalog:" + "8" * 64
        target["firmware_artifact_sha256"] = "8" * 64
        self.repository.publish_dict(target)
        base_context = MappingReleaseContext(
            "OpenWrt", "OpenWrt", "Tenda AC9", "18.06.7", "source:18", "official filename"
        )
        target_context = MappingReleaseContext(
            "OpenWrt", "OpenWrt", "Tenda AC9", "19.07.8", "source:19", "official filename"
        )
        self.repository.register_release_context(self.catalog.catalog_id, base_context)
        self.repository.register_release_context(target["catalog_id"], target_context)

        result = self.repository.compare_catalogs(
            self.catalog.catalog_id, target["catalog_id"]
        )

        self.assertTrue(result["same_firmware_family_verified"])
        summaries = self.repository.list_catalogs()["items"]
        self.assertEqual(
            {"18.06.7", "19.07.8"},
            {item["release_context"]["firmware_version"] for item in summaries},
        )
        with self.assertRaises(CatalogConflictError):
            self.repository.register_release_context(
                self.catalog.catalog_id,
                MappingReleaseContext(
                    "OpenWrt", "OpenWrt", "Other", "18.06.7",
                    "source:other", "conflicting model",
                ),
            )

    def test_cli_publishes_document_and_lists_same_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "mapping.db"
            document = root / "catalog.json"
            document.write_text(json.dumps(self.catalog.to_dict()), encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, main([
                    "mapping", "publish-catalog", "--database", str(database),
                    str(document),
                ]))
                self.assertEqual(0, main([
                    "mapping", "list-catalogs", "--database", str(database),
                ]))
            rendered = output.getvalue()
            self.assertIn(self.catalog.catalog_id, rendered)
            self.assertIn('"created": true', rendered)

    def test_potential_hidden_interfaces_are_projected_and_queryable(self):
        catalog = _hidden_catalog()
        self.repository.publish(catalog)

        result = self.repository.query_potential_hidden_interfaces(
            query="hidden operation"
        )

        self.assertEqual(1, result["total"])
        self.assertEqual(1, result["summary"]["firmware_count"])
        self.assertEqual(
            "hiddenOperation", result["items"][0]["operation_token"]
        )
        self.assertFalse(result["items"][0]["runtime_reachability_verified"])
        self.assertEqual(1, result["distributions"]["firmware"][0]["count"])

    def test_latest_incomplete_catalog_suppresses_stale_hidden_candidates(self):
        self.repository.publish(_hidden_catalog())
        self.repository.publish(_hidden_catalog(frontend_partial=True))

        result = self.repository.query_potential_hidden_interfaces()

        self.assertEqual(0, result["total"])
        self.assertEqual(0, result["summary"]["eligible_firmware_count"])
        self.assertEqual(1, result["summary"]["coverage_gap_firmware_count"])


if __name__ == "__main__":
    unittest.main()
