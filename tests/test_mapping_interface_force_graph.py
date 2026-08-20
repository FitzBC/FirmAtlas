import unittest

from firmatlas.mapping.interface_force_graph import project_interface_force_graph


class InterfaceForceGraphProjectionTests(unittest.TestCase):
    def test_projects_binary_interface_parameters_and_evidence_honestly(self):
        request_id = "frontend-request:set-time"
        association_id = "frontend-native-association:set-time"
        parameter_id = "frontend-parameter:timezone"
        document = {
            "catalog_id": "discovery-catalog:test",
            "firmware_artifact_sha256": "1" * 64,
            "coverage_status": "partial",
            "source_inventory_coverage_status": "completed",
            "candidates": [
                {
                    "candidate_id": request_id,
                    "candidate_kind": "request_interface",
                    "canonical_identity": "goform/SetTimeCfg",
                    "claim_status": "candidate",
                    "source_path": "webroot_ro/js/system.js",
                    "source_construct": "R.pageModel.setUrl",
                    "evidence_ids": ["evidence:request"],
                    "attributes": [["method", "POST"], ["endpoint_shape", "exact_literal"]],
                },
                {
                    "candidate_id": "native-route-binding:set-time",
                    "candidate_kind": "native_route_binding",
                    "canonical_identity": "SetTimeCfg",
                    "claim_status": "supported",
                    "source_path": "bin/httpd",
                    "source_construct": "elf.named-route-handler-pairs/v1",
                    "evidence_ids": ["evidence:binding"],
                    "attributes": [
                        ["target_ref", association_id],
                        ["handler_symbol", "formSetTimeCfg"],
                        ["handler_identity", "bin/httpd@0x00071234"],
                    ],
                },
                {
                    "candidate_id": "parameter-clue:timezone",
                    "candidate_kind": "parameter_clue_assessment",
                    "canonical_identity": "goform/SetTimeCfg|timezone",
                    "claim_status": "candidate",
                    "source_path": "bin/httpd",
                    "source_construct": "bounded-string-xref/v1",
                    "evidence_ids": ["evidence:clue"],
                    "attributes": [
                        ["target_ref", parameter_id],
                        ["assessment_status", "external_clue_observed"],
                        ["occurrence_count", "1"],
                        ["artifact_paths", '["bin/httpd"]'],
                    ],
                },
            ],
            "parameters": [{
                "parameter_id": parameter_id,
                "owner_ref": request_id,
                "name": "timezone",
                "namespace": "form",
                "literal_value": None,
                "selector_values": ["0", "8"],
                "is_operation_selector": True,
                "source_construct": "form_urlencoded",
                "evidence_ids": ["evidence:parameter"],
            }],
            "associations": [{
                "association_id": association_id,
                "frontend_candidate_id": request_id,
                "native_hint_id": "native-hint:set-time",
                "match_basis": "exact_component",
                "evidence_ids": ["evidence:association"],
            }],
            "open_obligations": [],
            "evidence_atoms": [
                {
                    "evidence_id": "evidence:parameter",
                    "predicate": "reads_parameter",
                    "object_value": "timezone",
                    "capability": "reads_parameter",
                    "source_span": {
                        "artifact_path": "webroot_ro/js/system.js",
                        "locator": "bytes:120-128",
                    },
                },
                {
                    "evidence_id": "evidence:clue",
                    "predicate": "mentions_parameter",
                    "object_value": "timezone",
                    "capability": "mentions_parameter",
                    "source_span": {
                        "artifact_path": "bin/httpd",
                        "locator": "virtual:0x712f0",
                    },
                },
            ],
        }

        result = project_interface_force_graph(document, release_context={
            "vendor": "Tenda", "product": "AC9", "device_model": "AC9",
            "firmware_version": "V15.03.05.19(6318)",
        })

        by_id = {item["node_id"]: item for item in result["nodes"]}
        component = next(item for item in result["nodes"] if item["node_kind"] == "component")
        interface = next(item for item in result["nodes"] if item["node_kind"] == "interface")
        parameter = next(item for item in result["nodes"] if item["node_kind"] == "parameter")
        self.assertEqual("bin/httpd", component["label"])
        self.assertEqual("/goform/SetTimeCfg", interface["label"])
        self.assertEqual(component["node_id"], interface["parent_id"])
        self.assertEqual(interface["node_id"], parameter["parent_id"])
        self.assertEqual("integer", parameter["details"]["data_type"])
        self.assertEqual("selector_domain", parameter["details"]["data_type_basis"])
        self.assertEqual(["0", "8"], parameter["details"]["allowed_values"])
        self.assertEqual("bin/httpd@0x00071234", interface["details"]["handler_identity"])
        self.assertEqual("virtual:0x712f0", parameter["details"]["evidence_locations"][1]["locator"])
        self.assertEqual(1, result["summary"]["binary_component_count"])
        self.assertEqual(1, result["summary"]["parameter_count"])
        self.assertIn(result["root_node_id"], by_id)

    def test_keeps_native_only_registration_and_unknown_parameter_type_explicit(self):
        document = {
            "catalog_id": "discovery-catalog:test",
            "firmware_artifact_sha256": "2" * 64,
            "coverage_status": "completed",
            "source_inventory_coverage_status": "completed",
            "candidates": [{
                "candidate_id": "native-route-binding:hidden",
                "candidate_kind": "native_route_binding",
                "canonical_identity": "HiddenCfg",
                "claim_status": "supported",
                "source_path": "bin/httpd",
                "source_construct": "elf.named-route-handler-pairs/v1",
                "evidence_ids": ["evidence:hidden"],
                "attributes": [["target_ref", "native-registrar:hidden"]],
            }],
            "parameters": [], "associations": [], "open_obligations": [],
            "evidence_atoms": [],
        }

        result = project_interface_force_graph(document)

        interface = next(item for item in result["nodes"] if item["node_kind"] == "interface")
        self.assertEqual("HiddenCfg", interface["label"])
        self.assertEqual("native_registration_only", interface["details"]["exposure_status"])
        self.assertEqual("unresolved", interface["details"]["path_status"])
        self.assertFalse(interface["details"]["frontend_reference_observed"])
        self.assertEqual(1, result["summary"]["native_only_interface_count"])


if __name__ == "__main__":
    unittest.main()
