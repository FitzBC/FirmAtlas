import copy
import unittest

from firmatlas.mapping import MappingReleaseContext, compare_mapping_catalog_documents
from tests.test_mapping_catalog_repository import _catalog
from tests.test_mapping_hidden_interface import _catalog as _hidden_catalog


def _versioned_document(firmware: str, *, method: str = "POST") -> dict:
    document = copy.deepcopy(_catalog().to_dict())
    document["catalog_id"] = "discovery-catalog:" + firmware[0] * 64
    document["firmware_artifact_sha256"] = firmware
    candidate = next(
        item for item in document["candidates"]
        if item["candidate_kind"] == "request_interface"
    )
    candidate["attributes"] = [
        [key, method if key == "method" else value]
        for key, value in candidate["attributes"]
    ]
    return document


class MappingSnapshotDiffTests(unittest.TestCase):
    def test_aligns_same_operation_and_reports_semantic_change(self):
        base = _versioned_document("1" * 64, method="POST")
        target = _versioned_document("2" * 64, method="PUT")

        result = compare_mapping_catalog_documents(base, target).to_dict()

        self.assertEqual("coverage_equivalent", result["comparison_status"])
        self.assertFalse(result["same_firmware_family_verified"])
        change = next(
            item for item in result["changes"]
            if item["category"] == "candidate"
        )
        self.assertEqual("changed", change["change_kind"])
        self.assertEqual(
            "request_interface|/goform/SetOnlineDevName",
            change["stable_identity"],
        )
        self.assertIn("attributes", change["changed_fields"])
        self.assertEqual("firmware_change_supported", change["confidence"])

    def test_reports_add_remove_without_treating_evidence_ids_as_change(self):
        base = _versioned_document("1" * 64)
        target = _versioned_document("2" * 64)
        target["candidates"] = []
        target["parameters"] = []

        result = compare_mapping_catalog_documents(base, target).to_dict()

        self.assertEqual(1, result["summary"]["removed_candidate_count"])
        self.assertEqual(0, result["summary"]["changed_candidate_count"])
        self.assertEqual(2, result["summary"]["removed_parameter_count"])

    def test_marks_different_producer_coverage_as_confounded(self):
        base = _versioned_document("1" * 64)
        target = _versioned_document("2" * 64, method="PUT")
        target["coverage"][0]["producer_version"] = "99.0.0"
        target["coverage"][0]["status"] = "partial"

        result = compare_mapping_catalog_documents(base, target).to_dict()

        self.assertEqual("coverage_confounded", result["comparison_status"])
        candidate = next(
            item for item in result["changes"]
            if item["category"] == "candidate"
        )
        self.assertEqual("coverage_confounded", candidate["confidence"])
        coverage = next(
            item for item in result["changes"]
            if item["category"] == "coverage"
        )
        self.assertEqual("changed", coverage["change_kind"])
        self.assertIn("producer_version", coverage["changed_fields"])
        self.assertIn("status", coverage["changed_fields"])

    def test_equal_but_incomplete_coverage_limits_claim_to_observed_scope(self):
        base = _versioned_document("1" * 64, method="POST")
        target = _versioned_document("2" * 64, method="PUT")
        base["source_inventory_coverage_status"] = "partial"
        target["source_inventory_coverage_status"] = "partial"

        result = compare_mapping_catalog_documents(base, target).to_dict()

        self.assertEqual("coverage_equivalent_partial", result["comparison_status"])
        candidate = next(
            item for item in result["changes"]
            if item["category"] == "candidate"
        )
        self.assertEqual("observed_scope_only", candidate["confidence"])

    def test_compares_potential_hidden_status_only_with_complete_gates(self):
        base = _hidden_catalog().to_dict()
        target = copy.deepcopy(base)
        target["catalog_id"] = "discovery-catalog:" + "9" * 64
        target["firmware_artifact_sha256"] = "9" * 64
        target["candidates"] = [
            item for item in target["candidates"]
            if item["candidate_kind"] != "set_difference_attribution"
        ]

        result = compare_mapping_catalog_documents(base, target).to_dict()

        hidden = next(
            item for item in result["changes"]
            if item["category"] == "potential_hidden_interface"
        )
        self.assertEqual("removed", hidden["change_kind"])
        self.assertEqual("hiddenOperation", hidden["display_identity"])
        self.assertEqual(1, result["summary"]["resolved_hidden_interface_count"])

    def test_incomplete_hidden_gate_is_unavailable_not_resolved(self):
        base = _hidden_catalog().to_dict()
        target = copy.deepcopy(base)
        target["catalog_id"] = "discovery-catalog:" + "8" * 64
        target["firmware_artifact_sha256"] = "8" * 64
        target["coverage"][-1]["status"] = "partial"

        result = compare_mapping_catalog_documents(base, target).to_dict()

        self.assertEqual("coverage_confounded", result["comparison_status"])
        self.assertEqual(0, result["summary"]["resolved_hidden_interface_count"])
        self.assertFalse(any(
            item["category"] == "potential_hidden_interface"
            for item in result["changes"]
        ))
        self.assertTrue(any(
            item["code"] == "hidden_interface_comparison_unavailable"
            for item in result["diagnostics"]
        ))

    def test_verifies_same_release_family_only_from_two_evidence_contexts(self):
        base = _versioned_document("1" * 64)
        target = _versioned_document("2" * 64)
        base_context = MappingReleaseContext(
            vendor="OpenWrt", product="OpenWrt", device_model="Tenda AC9",
            firmware_version="18.06.7", source_ref="openwrt-downloads-18.06.7",
            evidence="official target filename contains tenda-ac9",
        )
        target_context = MappingReleaseContext(
            vendor="openwrt", product="OpenWrt", device_model="tenda ac9",
            firmware_version="19.07.8", source_ref="openwrt-downloads-19.07.8",
            evidence="official target filename contains tenda-ac9",
        )

        result = compare_mapping_catalog_documents(
            base, target, base_context, target_context
        ).to_dict()

        self.assertTrue(result["same_firmware_family_verified"])
        self.assertEqual("18.06.7", result["base"]["release_context"]["firmware_version"])
        self.assertEqual("19.07.8", result["target"]["release_context"]["firmware_version"])
        self.assertFalse(any(
            item["code"] == "firmware_family_unverified"
            for item in result["diagnostics"]
        ))


if __name__ == "__main__":
    unittest.main()
