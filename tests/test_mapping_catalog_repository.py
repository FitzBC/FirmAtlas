import hashlib
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest

from firmatlas.mapping import (
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    discover_frontend_requests,
)
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

    def test_unknown_catalog_and_candidate_return_none(self):
        self.assertIsNone(self.repository.get_catalog("missing"))
        self.repository.publish(self.catalog)
        self.assertIsNone(self.repository.get_candidate(self.catalog.catalog_id, "missing"))

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


if __name__ == "__main__":
    unittest.main()
