import hashlib
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    DiscoveryCandidateKind,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    SourceArtifactEntry,
    UbusAccessMode,
    UbusArtifactInput,
    UbusBackendBindingStatus,
    UbusOperationReference,
    assemble_discovery_catalog,
    discover_frontend_requests,
    discover_ubus_backend_graph,
    ubus_operation_references_from_frontend,
)


def artifact(path: str, content: bytes) -> UbusArtifactInput:
    return UbusArtifactInput(
        SourceArtifactEntry(
            path, path, "file", len(content), hashlib.sha256(content).hexdigest()
        ),
        content,
    )


class UbusBackendProducerContractTests(unittest.TestCase):
    def test_frontend_results_are_adapted_to_exact_and_dynamic_ubus_operations(self):
        source = artifact(
            "www/luci-static/resources/network.js",
            b"rpc.declare({object:'hostapd.%s'.format(ifname),method:'del_client'});"
            b"rpc.declare({object:'luci',method:'getFeatures'});",
        )
        frontend = discover_frontend_requests(source.source, source.content)

        operations = ubus_operation_references_from_frontend((frontend,))

        self.assertEqual(
            {
                "ubus://hostapd.{dynamic}/del_client",
                "ubus://luci/getFeatures",
            },
            {item.logical_operation for item in operations},
        )
        self.assertTrue(all(item.evidence_ids for item in operations))

    def test_rpcd_lua_exec_plugin_binds_declared_method_to_artifact(self):
        script = b'''#!/usr/bin/env lua
local methods = {
  getFeatures = {
    args = { detail = false },
    call = function(args) return { result = true } end
  }
}
if arg[1] == "list" then
  for _, method in pairs(methods) do end
elseif arg[1] == "call" then
  local method = methods[arg[2]]
end
'''
        operation = UbusOperationReference(
            "frontend:features", "luci", "getFeatures", ("frontend:evidence",)
        )

        result = discover_ubus_backend_graph(
            (operation,),
            (artifact("usr/libexec/rpcd/luci", script),),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.principals))
        self.assertEqual("usr/libexec/rpcd/luci", result.principals[0].artifact_path)
        self.assertEqual(1, len(result.bindings))
        binding = result.bindings[0]
        self.assertEqual("ubus://luci/getFeatures", binding.logical_operation)
        self.assertEqual(
            UbusBackendBindingStatus.STATIC_PLUGIN_DISPATCH,
            binding.status,
        )
        self.assertEqual(("detail",), binding.parameter_names)
        self.assertEqual((), result.open_obligations)

    def test_native_rpcd_plugin_is_candidate_until_registration_table_is_resolved(self):
        binary = b"\x7fELF\x00rpc_plugin\x00luci-rpc\x00getBoardJSON\x00"
        operation = UbusOperationReference(
            "frontend:board", "luci-rpc", "getBoardJSON", ()
        )

        result = discover_ubus_backend_graph(
            (operation,),
            (artifact("usr/lib/rpcd/luci.so", binary),),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual(1, len(result.bindings))
        self.assertEqual(
            UbusBackendBindingStatus.NATIVE_PLUGIN_CANDIDATE,
            result.bindings[0].status,
        )
        self.assertEqual(1, len(result.open_obligations))
        self.assertEqual(
            "resolve_ubus_registration_table",
            result.open_obligations[0].required_capability,
        )

    def test_native_plugin_does_not_claim_unrelated_object_string(self):
        binary = b"\x7fELF\x00rpc_plugin\x00luci-rpc\x00file\x00read\x00"
        operation = UbusOperationReference("frontend:file", "file", "read", ())

        result = discover_ubus_backend_graph(
            (operation,), (artifact("usr/lib/rpcd/luci.so", binary),),
        )

        self.assertEqual((), result.bindings)
        self.assertEqual(
            "resolve_ubus_runtime_owner",
            result.open_obligations[0].required_capability,
        )

    def test_acl_wildcard_matches_dynamic_operation_template_without_claiming_owner(self):
        acl = b'''{
  "luci-access": {
    "write": { "ubus": { "hostapd.*": [ "del_client" ] } }
  }
}'''
        operation = UbusOperationReference(
            "frontend:disconnect",
            "hostapd.{dynamic}",
            "del_client",
            (),
        )

        result = discover_ubus_backend_graph(
            (operation,),
            (artifact("usr/share/rpcd/acl.d/luci-base.json", acl),),
        )

        self.assertEqual(1, len(result.access_grants))
        grant = result.access_grants[0]
        self.assertEqual("ubus://hostapd.{dynamic}/del_client", grant.logical_operation)
        self.assertEqual("luci-access", grant.policy_group)
        self.assertEqual(UbusAccessMode.WRITE, grant.access_mode)
        self.assertEqual((), result.bindings)
        self.assertEqual("resolve_ubus_runtime_owner", result.open_obligations[0].required_capability)

    def test_catalog_preserves_principal_binding_policy_and_owner_obligation(self):
        frontend_source = artifact(
            "www/luci-static/resources/system.js",
            b"rpc.declare({object:'luci-rpc',method:'getBoardJSON'});",
        )
        frontend = discover_frontend_requests(
            frontend_source.source, frontend_source.content
        )
        operation = UbusOperationReference(
            frontend.candidates[0].candidate_id,
            "luci-rpc",
            "getBoardJSON",
            frontend.candidates[0].evidence_ids,
        )
        backend = discover_ubus_backend_graph(
            (operation,),
            (
                artifact(
                    "usr/lib/rpcd/luci.so",
                    b"\x7fELF\x00rpc_plugin\x00luci-rpc\x00getBoardJSON\x00",
                ),
                artifact(
                    "usr/share/rpcd/acl.d/luci-base.json",
                    b'{"luci-access":{"read":{"ubus":{"luci-rpc":["getBoardJSON"]}}}}',
                ),
            ),
        )

        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            firmware_artifact_sha256="a" * 64,
            source_inventory_sha256="b" * 64,
            batches=(
                DiscoveryProducerBatch.frontend((frontend,), "www/**/*.js"),
                DiscoveryProducerBatch.ubus_backend((backend,), "usr/{lib,share}/rpcd/**"),
            ),
        ))

        kinds = {item.candidate_kind for item in catalog.candidates}
        self.assertIn(DiscoveryCandidateKind.RUNTIME_PRINCIPAL, kinds)
        self.assertIn(DiscoveryCandidateKind.UBUS_BACKEND_BINDING, kinds)
        self.assertIn(DiscoveryCandidateKind.UBUS_ACCESS_GRANT, kinds)
        self.assertEqual(1, len(catalog.open_obligations))
        self.assertEqual(
            frontend.candidates[0].candidate_id,
            catalog.open_obligations[0].target_ref,
        )


if __name__ == "__main__":
    unittest.main()
