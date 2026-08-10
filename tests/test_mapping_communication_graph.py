import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace

from firmatlas.mapping import (
    CoverageStatus,
    DiscoveryCandidate,
    DiscoveryCandidateKind,
    DiscoveryCatalog,
    DiscoveryCatalogInput,
    DiscoveryClaimStatus,
    DiscoveryCoverage,
    DiscoveryAssociation,
    DiscoveryParameter,
    DiscoveryProducerKind,
    DiscoveryProducerBatch,
    CommunicationGraphPolicy,
    CommunicationGraphNodeKind,
    CommunicationGraphEdgeKind,
    EvidenceAtom,
    EvidenceSpan,
    FrontendAssetInput,
    ObservationKind,
    ObligationStatus,
    SchedulerObligation,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    discover_frontend_asset_graph,
    discover_frontend_invocation_reachability,
    discover_native_relationships,
    project_communication_architecture_graph,
)
from firmatlas.mapping.__main__ import main as mapping_main


class CommunicationArchitectureGraphContractTests(unittest.TestCase):
    def test_projects_request_parameter_and_invocation_with_evidence(self):
        content = b'''function submitConfig() {
  $.post("/goform/SetCfg", "deviceName=router", callback);
}
submitConfig();'''
        source = self.source("webroot_ro/js/config.js", content)
        frontend_graph = discover_frontend_asset_graph((
            FrontendAssetInput(source, content),
        ))
        frontend = frontend_graph.results[0]
        reachability = discover_frontend_invocation_reachability(
            source, content, frontend
        )
        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            firmware_artifact_sha256="1" * 64,
            source_inventory_sha256="2" * 64,
            batches=(
                DiscoveryProducerBatch.frontend((frontend,), "frontend"),
                DiscoveryProducerBatch.frontend_reachability(
                    (reachability,), "frontend-reachability"
                ),
            ),
        ))

        first = project_communication_architecture_graph(catalog)
        second = project_communication_architecture_graph(catalog)

        self.assertEqual(first.graph_id, second.graph_id)
        self.assertEqual(
            {
                "artifact", "interface", "parameter", "invocation",
            },
            {item.node_kind.value for item in first.nodes},
        )
        request = next(
            item for item in first.nodes if item.node_kind.value == "interface"
        )
        parameter = next(
            item for item in first.nodes if item.node_kind.value == "parameter"
        )
        invocation = next(
            item for item in first.nodes if item.node_kind.value == "invocation"
        )
        self.assertEqual("/goform/SetCfg", request.label)
        self.assertEqual("deviceName", parameter.label)
        self.assertEqual(
            "active_call_path", dict(invocation.attributes)["status"]
        )
        semantic_edges = {
            (item.edge_kind.value, item.source_ref, item.target_ref): item
            for item in first.edges
            if item.edge_kind.value != "declared_in_artifact"
        }
        self.assertIn(
            ("accepts_parameter", request.node_id, parameter.node_id),
            semantic_edges,
        )
        self.assertIn(
            ("has_invocation_state", request.node_id, invocation.node_id),
            semantic_edges,
        )
        catalog_evidence = {
            item.evidence_id for item in catalog.evidence_atoms
        }
        for edge in semantic_edges.values():
            self.assertTrue(edge.evidence_ids)
            self.assertLessEqual(set(edge.evidence_ids), catalog_evidence)

    def test_projects_feature_gate_route_binding_and_exact_handler(self):
        request = DiscoveryCandidate(
            "request:set", DiscoveryCandidateKind.REQUEST_INTERFACE,
            "goform/SetCfg", DiscoveryClaimStatus.CANDIDATE,
            "webroot_ro/js/config.js", "jquery.post", ("evidence:1",),
        )
        gate = DiscoveryCandidate(
            "gate:cfg", DiscoveryCandidateKind.FRONTEND_FEATURE_GATE,
            "CONFIG_CFG", DiscoveryClaimStatus.SUPPORTED,
            "webroot_ro/js/macro.js", "feature-gate", ("evidence:1",),
            (("request_candidate_refs", '["request:set"]'),),
        )
        binding = DiscoveryCandidate(
            "binding:set", DiscoveryCandidateKind.NATIVE_ROUTE_BINDING,
            "SetCfg", DiscoveryClaimStatus.SUPPORTED,
            "bin/httpd", "arm-pic", ("evidence:1",),
            (
                ("target_ref", "request:set"),
                ("registration_address", "0x1000"),
                ("handler_identity", "formSetCfg@0x2000"),
            ),
        )
        handler = DiscoveryCandidate(
            "handler:set", DiscoveryCandidateKind.NATIVE_HANDLER,
            "formSetCfg@0x2000", DiscoveryClaimStatus.SUPPORTED,
            "bin/httpd", "arm-pic", ("evidence:1",),
            (
                ("target_ref", "request:set"),
                ("registration_address", "0x1000"),
                ("route_token", "SetCfg"),
            ),
        )
        catalog = self.catalog((request, gate, binding, handler))

        graph = project_communication_architecture_graph(catalog)

        nodes = {item.node_id: item for item in graph.nodes}
        self.assertEqual("feature_gate", nodes[gate.candidate_id].node_kind.value)
        self.assertEqual("route_binding", nodes[binding.candidate_id].node_kind.value)
        self.assertEqual("handler", nodes[handler.candidate_id].node_kind.value)
        edges = {
            (item.edge_kind.value, item.source_ref, item.target_ref)
            for item in graph.edges
        }
        self.assertIn(("gates", gate.candidate_id, request.candidate_id), edges)
        self.assertIn(
            ("has_route_binding", request.candidate_id, binding.candidate_id),
            edges,
        )
        self.assertIn(
            ("binds_handler", binding.candidate_id, handler.candidate_id),
            edges,
        )

    def test_route_binding_links_request_without_replacing_registrar_ref(self):
        request = DiscoveryCandidate(
            "request:get-dlna", DiscoveryCandidateKind.REQUEST_INTERFACE,
            "goform/GetDlnaCfg", DiscoveryClaimStatus.CANDIDATE,
            "www/js/dlna.js", "jquery.getJSON", ("evidence:1",),
        )
        registrar = DiscoveryCandidate(
            "native-registrar:dlna", DiscoveryCandidateKind.NATIVE_REGISTRAR,
            "registrar@0x171ec", DiscoveryClaimStatus.SUPPORTED,
            "bin/httpd", "route-table", ("evidence:1",),
        )
        binding = DiscoveryCandidate(
            "binding:get-dlna", DiscoveryCandidateKind.NATIVE_ROUTE_BINDING,
            "GetDlnaCfg", DiscoveryClaimStatus.SUPPORTED,
            "bin/httpd", "route-table", ("evidence:1",),
            (
                ("target_ref", registrar.candidate_id),
                ("registration_address", "0x171ec"),
                ("handler_identity", "getDLNAserverCfg"),
            ),
        )

        obligation = SchedulerObligation(
            "obligation:get-dlna", request.candidate_id, "registers_route",
            "route owner not yet proven", 95, ("native-deep",),
            ObligationStatus.OPEN,
        )
        graph = project_communication_architecture_graph(self.catalog(
            (request, registrar, binding), obligations=(obligation,)
        ))

        edges = {
            (item.edge_kind.value, item.source_ref, item.target_ref)
            for item in graph.edges
        }
        self.assertIn(
            ("has_route_binding", request.candidate_id, binding.candidate_id),
            edges,
        )
        self.assertIn(
            ("has_route_binding", registrar.candidate_id, binding.candidate_id),
            edges,
        )
        self.assertIn(
            (
                "satisfies_obligation", binding.candidate_id,
                obligation.obligation_id,
            ),
            edges,
        )
        self.assertNotIn(
            (
                "requires_evidence", request.candidate_id,
                obligation.obligation_id,
            ),
            edges,
        )
        obligation_node = next(
            item for item in graph.nodes
            if item.node_id == obligation.obligation_id
        )
        self.assertEqual("satisfied_in_projection", obligation_node.status)
        self.assertEqual(
            "open", dict(obligation_node.attributes)["catalog_status"]
        )

        candidate_graph = project_communication_architecture_graph(self.catalog(
            (
                request, registrar,
                replace(binding, claim_status=DiscoveryClaimStatus.CANDIDATE),
            ),
            obligations=(obligation,),
        ))
        candidate_edges = {
            (item.edge_kind.value, item.source_ref, item.target_ref)
            for item in candidate_graph.edges
        }
        self.assertIn(
            (
                "requires_evidence", request.candidate_id,
                obligation.obligation_id,
            ),
            candidate_edges,
        )
        self.assertNotIn(
            (
                "satisfies_obligation", binding.candidate_id,
                obligation.obligation_id,
            ),
            candidate_edges,
        )

    def test_projects_resolved_cross_process_communication_relation(self):
        source_content = (
            b"\x7fELF\x01\x01" + b"\x00" * 58
            + b"cfm post netctrl 51?op=6\x00"
        )
        target_content = b"\x7fELF\x01\x01" + b"\x00" * 58
        source_result = discover_native_relationships(
            self.source("bin/time_check", source_content), source_content
        )
        target_result = discover_native_relationships(
            self.source("bin/netctrl", target_content), target_content
        )
        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            firmware_artifact_sha256="1" * 64,
            source_inventory_sha256="2" * 64,
            batches=(DiscoveryProducerBatch.native_relationship(
                (source_result, target_result), "native-relationships"
            ),),
        ))

        graph = project_communication_architecture_graph(catalog)

        relation = next(
            item for item in graph.nodes
            if item.node_kind.value == "communication_relation"
        )
        artifacts = {
            item.source_path: item for item in graph.nodes
            if item.node_kind.value == "artifact"
        }
        edges = {
            (item.edge_kind.value, item.source_ref, item.target_ref)
            for item in graph.edges
        }
        self.assertIn(
            (
                "initiates_relationship",
                artifacts["bin/time_check"].node_id,
                relation.node_id,
            ),
            edges,
        )
        self.assertIn(
            (
                "targets_component",
                relation.node_id,
                artifacts["bin/netctrl"].node_id,
            ),
            edges,
        )
        self.assertEqual(
            "resolved_same_firmware",
            dict(relation.attributes)["target_resolution_status"],
        )

    def test_merges_one_unresolved_component_referenced_by_multiple_relations(self):
        relationships = tuple(
            DiscoveryCandidate(
                "relation:{}".format(index),
                DiscoveryCandidateKind.NATIVE_RELATIONSHIP,
                "bin/source{}|signal|minidlna".format(index),
                DiscoveryClaimStatus.CANDIDATE,
                "bin/source{}".format(index), "native-relationship",
                ("evidence:1",),
                (
                    ("target_artifact_paths", "[]"),
                    ("target_component", "minidlna"),
                    (
                        "target_resolution_status",
                        "unresolved_in_analyzed_sources",
                    ),
                ),
            )
            for index in range(2)
        )

        graph = project_communication_architecture_graph(
            self.catalog(relationships)
        )

        components = [
            item for item in graph.nodes if item.node_kind.value == "component"
        ]
        self.assertEqual(1, len(components))
        self.assertEqual("minidlna", components[0].label)
        self.assertEqual(
            2,
            sum(
                item.edge_kind.value == "targets_component"
                and item.target_ref == components[0].node_id
                for item in graph.edges
            ),
        )

    def test_focuses_semantic_subgraph_without_artifact_fanout(self):
        request = DiscoveryCandidate(
            "request:set", DiscoveryCandidateKind.REQUEST_INTERFACE,
            "goform/SetCfg", DiscoveryClaimStatus.CANDIDATE,
            "webroot_ro/js/config.js", "jquery.post", ("evidence:1",),
        )
        unrelated = DiscoveryCandidate(
            "request:other", DiscoveryCandidateKind.REQUEST_INTERFACE,
            "goform/Unrelated", DiscoveryClaimStatus.CANDIDATE,
            "webroot_ro/js/config.js", "jquery.post", ("evidence:1",),
        )
        gate = DiscoveryCandidate(
            "gate:cfg", DiscoveryCandidateKind.FRONTEND_FEATURE_GATE,
            "CONFIG_CFG", DiscoveryClaimStatus.SUPPORTED,
            "webroot_ro/js/macro.js", "feature-gate", ("evidence:1",),
            (("request_candidate_refs", '["request:set"]'),),
        )
        binding = DiscoveryCandidate(
            "binding:set", DiscoveryCandidateKind.NATIVE_ROUTE_BINDING,
            "SetCfg", DiscoveryClaimStatus.SUPPORTED,
            "bin/httpd", "arm-pic", ("evidence:1",),
            (
                ("target_ref", "request:set"),
                ("registration_address", "0x1000"),
                ("handler_identity", "formSetCfg@0x2000"),
            ),
        )
        handler = DiscoveryCandidate(
            "handler:set", DiscoveryCandidateKind.NATIVE_HANDLER,
            "formSetCfg@0x2000", DiscoveryClaimStatus.SUPPORTED,
            "bin/httpd", "arm-pic", ("evidence:1",),
            (
                ("target_ref", "request:set"),
                ("registration_address", "0x1000"),
                ("route_token", "SetCfg"),
            ),
        )
        catalog = self.catalog((request, unrelated, gate, binding, handler))

        graph = project_communication_architecture_graph(
            catalog,
            CommunicationGraphPolicy(
                focus_canonical_identities=("goform/SetCfg",),
                max_hops=2,
            ),
        )

        node_ids = {item.node_id for item in graph.nodes}
        self.assertIn(request.candidate_id, node_ids)
        self.assertIn(gate.candidate_id, node_ids)
        self.assertIn(binding.candidate_id, node_ids)
        self.assertIn(handler.candidate_id, node_ids)
        self.assertNotIn(unrelated.candidate_id, node_ids)
        self.assertEqual(CoverageStatus.COMPLETED, graph.projection_status)

    def test_reports_missing_focus_identity_without_inventing_nodes(self):
        catalog = self.catalog(())

        graph = project_communication_architecture_graph(
            catalog,
            CommunicationGraphPolicy(
                focus_canonical_identities=("goform/Missing",),
            ),
        )

        self.assertEqual(CoverageStatus.PARTIAL, graph.projection_status)
        self.assertEqual((), graph.nodes)
        self.assertIn(
            "communication_graph.focus_identity_not_found:goform/Missing",
            graph.diagnostics,
        )

    def test_preserves_coverage_and_open_obligations_for_completeness_view(self):
        request = DiscoveryCandidate(
            "request:set", DiscoveryCandidateKind.REQUEST_INTERFACE,
            "goform/SetCfg", DiscoveryClaimStatus.CANDIDATE,
            "webroot_ro/js/config.js", "jquery.post", ("evidence:1",),
        )
        obligation = SchedulerObligation(
            "obligation:set-owner", request.candidate_id, "binds_handler",
            "frontend request has no verified handler", 90,
            ("native-deep",), ObligationStatus.OPEN,
        )
        coverage = DiscoveryCoverage(
            "auto:frontend", DiscoveryProducerKind.FRONTEND,
            "frontend-request-producer", "0.4.0",
            CoverageStatus.COMPLETED, True, 1,
        )
        catalog = self.catalog(
            (request,), obligations=(obligation,), coverage=(coverage,)
        )

        graph = project_communication_architecture_graph(catalog)

        obligation_node = next(
            item for item in graph.nodes
            if item.node_kind.value == "obligation"
        )
        self.assertEqual("open", obligation_node.status)
        self.assertEqual("binds_handler", obligation_node.label)
        self.assertIn(
            (
                "requires_evidence",
                request.candidate_id,
                obligation.obligation_id,
            ),
            {
                (item.edge_kind.value, item.source_ref, item.target_ref)
                for item in graph.edges
            },
        )
        self.assertEqual(1, len(graph.coverage))
        self.assertEqual("frontend", graph.coverage[0].producer_kind)
        self.assertEqual("completed", graph.coverage[0].status.value)
        self.assertEqual(
            {
                "interface_structure", "communication_components",
                "parameter_state", "completeness",
            },
            {item.preset_id for item in graph.view_presets},
        )

    def test_projects_logical_rpc_backend_principal_access_and_response_contract(self):
        request = DiscoveryCandidate(
            "request:rpc", DiscoveryCandidateKind.REQUEST_INTERFACE,
            "ubus://system/info", DiscoveryClaimStatus.CANDIDATE,
            "www/system.js", "luci.rpc.declare", ("evidence:1",),
        )
        principal = DiscoveryCandidate(
            "principal:rpcd", DiscoveryCandidateKind.RUNTIME_PRINCIPAL,
            "usr/sbin/rpcd", DiscoveryClaimStatus.SUPPORTED,
            "usr/sbin/rpcd", "native_executable", ("evidence:1",),
        )
        binding = DiscoveryCandidate(
            "binding:rpc", DiscoveryCandidateKind.UBUS_BACKEND_BINDING,
            "ubus://system/info", DiscoveryClaimStatus.SUPPORTED,
            "usr/libexec/rpcd/system", "static_plugin_dispatch",
            ("evidence:1",),
            (
                ("target_ref", request.candidate_id),
                ("principal_id", principal.candidate_id),
            ),
        )
        grant = DiscoveryCandidate(
            "grant:rpc", DiscoveryCandidateKind.UBUS_ACCESS_GRANT,
            "ubus://system/info", DiscoveryClaimStatus.SUPPORTED,
            "usr/share/rpcd/acl.d/system.json", "rpcd_acl",
            ("evidence:1",),
            (("target_ref", request.candidate_id),),
        )
        response = DiscoveryCandidate(
            "response:rpc", DiscoveryCandidateKind.RESPONSE_FIXTURE_CONTRACT,
            "ubus://system/info", DiscoveryClaimStatus.CANDIDATE,
            "www/system-info.json", "fixture", ("evidence:1",),
            (("frontend_request_refs", '["request:rpc"]'),),
        )
        catalog = self.catalog((request, principal, binding, grant, response))

        graph = project_communication_architecture_graph(catalog)

        kinds = {item.node_id: item.node_kind.value for item in graph.nodes}
        self.assertEqual("runtime_principal", kinds[principal.candidate_id])
        self.assertEqual("backend_binding", kinds[binding.candidate_id])
        self.assertEqual("access_grant", kinds[grant.candidate_id])
        self.assertEqual("response_contract", kinds[response.candidate_id])
        edges = {
            (item.edge_kind.value, item.source_ref, item.target_ref)
            for item in graph.edges
        }
        self.assertIn(
            ("has_backend_binding", request.candidate_id, binding.candidate_id),
            edges,
        )
        self.assertIn(
            ("executed_by", binding.candidate_id, principal.candidate_id),
            edges,
        )
        self.assertIn(
            ("has_access_grant", request.candidate_id, grant.candidate_id),
            edges,
        )
        self.assertIn(
            ("has_response_contract", request.candidate_id, response.candidate_id),
            edges,
        )

    def test_projects_dispatch_protection_assembly_and_feature_pivot_refs(self):
        request = DiscoveryCandidate(
            "request:upload", DiscoveryCandidateKind.REQUEST_INTERFACE,
            "setting/setUploadSetting", DiscoveryClaimStatus.CANDIDATE,
            "www/advance/config.html", "multipart", ("evidence:1",),
        )
        gate = DiscoveryCandidate(
            "gate:upload", DiscoveryCandidateKind.FRONTEND_FEATURE_GATE,
            "CONFIG_UPLOAD", DiscoveryClaimStatus.SUPPORTED,
            "www/config.js", "feature-gate", ("evidence:1",),
            (("request_candidate_refs", '["request:upload"]'),),
        )
        binding = DiscoveryCandidate(
            "binding:upload", DiscoveryCandidateKind.NATIVE_ROUTE_BINDING,
            "setUploadSetting", DiscoveryClaimStatus.SUPPORTED,
            "www/cgi-bin/cstecgi.cgi", "mips-inline", ("evidence:1",),
            (
                ("target_ref", request.candidate_id),
                ("registration_address", "0x3000"),
                ("handler_identity", "uploadHandler@0x4000"),
            ),
        )
        candidates = [request, gate, binding]
        for candidate_id, kind in (
            ("dispatch:upload", DiscoveryCandidateKind.NATIVE_NESTED_DISPATCH),
            ("protection:upload", DiscoveryCandidateKind.NATIVE_REQUEST_PROTECTION),
            ("assembly:upload", DiscoveryCandidateKind.NATIVE_SERVICE_ASSEMBLY),
        ):
            candidates.append(DiscoveryCandidate(
                candidate_id, kind, candidate_id,
                DiscoveryClaimStatus.SUPPORTED, "www/cgi-bin/cstecgi.cgi",
                "verified-native", ("evidence:1",),
                (("target_ref", request.candidate_id),),
            ))
        xref = DiscoveryCandidate(
            "xref:upload", DiscoveryCandidateKind.ARM_LITERAL_XREF,
            "upload literal", DiscoveryClaimStatus.CANDIDATE,
            "bin/httpd", "arm-xref", ("evidence:1",),
            (("target_ref", binding.candidate_id),),
        )
        pivot = DiscoveryCandidate(
            "pivot:upload", DiscoveryCandidateKind.ARM_FEATURE_PIVOT,
            "upload feature pivot", DiscoveryClaimStatus.CANDIDATE,
            "bin/httpd", "arm-pivot", ("evidence:1",),
            (
                ("target_ref", gate.candidate_id),
                ("route_binding_ref", binding.candidate_id),
            ),
        )
        candidates.extend((xref, pivot))
        graph = project_communication_architecture_graph(
            self.catalog(tuple(candidates))
        )

        edges = {
            (item.edge_kind.value, item.source_ref, item.target_ref)
            for item in graph.edges
        }
        self.assertIn(
            ("dispatched_by", request.candidate_id, "dispatch:upload"), edges
        )
        self.assertIn(
            ("protected_by", request.candidate_id, "protection:upload"), edges
        )
        self.assertIn(
            ("assembled_by", request.candidate_id, "assembly:upload"), edges
        )
        self.assertIn(
            ("has_literal_xref", binding.candidate_id, xref.candidate_id), edges
        )
        self.assertIn(
            ("has_feature_pivot", gate.candidate_id, pivot.candidate_id), edges
        )
        self.assertIn(
            ("pivots_to_route_binding", pivot.candidate_id, binding.candidate_id),
            edges,
        )

    def test_projects_parameter_clue_and_frontend_native_association(self):
        request = DiscoveryCandidate(
            "request:set", DiscoveryCandidateKind.REQUEST_INTERFACE,
            "goform/SetCfg", DiscoveryClaimStatus.CANDIDATE,
            "www/config.js", "jquery.post", ("evidence:1",),
        )
        parameter = DiscoveryParameter(
            "parameter:name", request.candidate_id, "deviceName", "form",
            "router", ("router",), False, "form-encoded", ("evidence:1",),
        )
        clue = DiscoveryCandidate(
            "clue:name", DiscoveryCandidateKind.PARAMETER_CLUE_ASSESSMENT,
            "goform/SetCfg|deviceName", DiscoveryClaimStatus.CANDIDATE,
            "bin/httpd", "parameter-clue", ("evidence:1",),
            (("target_ref", parameter.parameter_id),),
        )
        native_hint = DiscoveryCandidate(
            "hint:set", DiscoveryCandidateKind.NATIVE_HINT,
            "SetCfg", DiscoveryClaimStatus.CANDIDATE,
            "bin/httpd", "native-string", ("evidence:1",),
        )
        association_node = DiscoveryCandidate(
            "association:set", DiscoveryCandidateKind.CANDIDATE_ASSOCIATION,
            "request:set|hint:set", DiscoveryClaimStatus.CANDIDATE,
            "bin/httpd", "frontend-native-exact/v1", ("evidence:1",),
        )
        association = DiscoveryAssociation(
            association_node.candidate_id, request.candidate_id,
            native_hint.candidate_id, "exact_action", ("evidence:1",),
        )
        catalog = self.catalog(
            (request, clue, native_hint, association_node),
            parameters=(parameter,),
            associations=(association,),
        )

        graph = project_communication_architecture_graph(catalog)

        self.assertEqual(
            "parameter_clue",
            next(
                item for item in graph.nodes if item.node_id == clue.candidate_id
            ).node_kind.value,
        )
        edges = {
            (item.edge_kind.value, item.source_ref, item.target_ref)
            for item in graph.edges
        }
        self.assertIn(
            ("has_parameter_clue", parameter.parameter_id, clue.candidate_id),
            edges,
        )
        self.assertIn(
            (
                "has_native_association", request.candidate_id,
                association_node.candidate_id,
            ),
            edges,
        )
        self.assertIn(
            (
                "associated_with", association_node.candidate_id,
                native_hint.candidate_id,
            ),
            edges,
        )

    def test_budget_truncation_is_partial_and_never_leaves_dangling_edges(self):
        requests = tuple(
            DiscoveryCandidate(
                "request:{}".format(index),
                DiscoveryCandidateKind.REQUEST_INTERFACE,
                "goform/Route{}".format(index),
                DiscoveryClaimStatus.CANDIDATE,
                "www/routes.js", "jquery.post", ("evidence:1",),
            )
            for index in range(3)
        )

        graph = project_communication_architecture_graph(
            self.catalog(requests),
            CommunicationGraphPolicy(max_nodes=2, max_edges=1),
        )

        self.assertEqual(CoverageStatus.PARTIAL, graph.projection_status)
        self.assertIn(
            "communication_graph.projection_budget_exceeded",
            graph.diagnostics,
        )
        node_ids = {item.node_id for item in graph.nodes}
        self.assertTrue(all(
            item.source_ref in node_ids and item.target_ref in node_ids
            for item in graph.edges
        ))

    def test_unresolved_legacy_target_ref_is_partial_without_dangling_edge(self):
        xref = DiscoveryCandidate(
            "xref:legacy", DiscoveryCandidateKind.ARM_LITERAL_XREF,
            "legacy literal", DiscoveryClaimStatus.CANDIDATE,
            "bin/httpd", "arm-xref", ("evidence:1",),
            (("target_ref", "legacy-anchor:not-a-catalog-node"),),
        )

        graph = project_communication_architecture_graph(self.catalog((xref,)))

        self.assertEqual(CoverageStatus.PARTIAL, graph.projection_status)
        self.assertIn(
            "communication_graph.unresolved_reference:"
            "xref:legacy:legacy-anchor:not-a-catalog-node",
            graph.diagnostics,
        )
        self.assertIn(xref.candidate_id, {item.node_id for item in graph.nodes})
        node_ids = {item.node_id for item in graph.nodes}
        self.assertTrue(all(
            item.source_ref in node_ids and item.target_ref in node_ids
            for item in graph.edges
        ))

    def test_view_presets_cover_every_semantic_node_and_edge_kind(self):
        graph = project_communication_architecture_graph(self.catalog(()))

        preset_node_kinds = {
            kind for preset in graph.view_presets for kind in preset.node_kinds
        }
        preset_edge_kinds = {
            kind for preset in graph.view_presets for kind in preset.edge_kinds
        }
        self.assertLessEqual(
            {item.value for item in CommunicationGraphNodeKind},
            preset_node_kinds,
        )
        self.assertLessEqual(
            {
                item.value for item in CommunicationGraphEdgeKind
                if item is not CommunicationGraphEdgeKind.DECLARED_IN_ARTIFACT
            },
            preset_edge_kinds,
        )

    def test_analyze_root_cli_writes_focus_graph_for_uploaded_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rootfs"
            root.mkdir()
            (root / "index.html").write_text(
                '<form action="/apply"><input name="token"></form>',
                encoding="utf-8",
            )
            run_output = Path(directory) / "run.json"
            graph_output = Path(directory) / "graph.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = mapping_main((
                    "analyze-root", str(root),
                    "--artifact-sha256", "c" * 64,
                    "--output", str(run_output),
                    "--profile", "base",
                    "--graph-output", str(graph_output),
                    "--graph-focus", "/apply",
                    "--graph-max-hops", "1",
                ))
            summary = json.loads(stdout.getvalue())
            run_document = json.loads(run_output.read_text(encoding="utf-8"))
            graph_document = json.loads(
                graph_output.read_text(encoding="utf-8")
            )

        self.assertEqual(0, exit_code)
        self.assertEqual(
            "firmatlas.mapping.communication-architecture-graph/v1alpha1",
            graph_document["schema_version"],
        )
        self.assertEqual(
            run_document["catalog"]["catalog_id"],
            graph_document["source_catalog_id"],
        )
        self.assertEqual(graph_document["graph_id"], summary["graph_id"])
        self.assertEqual(str(graph_output), summary["graph_output"])
        self.assertEqual(
            ["/apply"],
            [
                item["label"] for item in graph_document["nodes"]
                if item["node_kind"] == "interface"
            ],
        )

    def test_cli_rejects_graph_options_without_leaving_partial_run_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rootfs"
            root.mkdir()
            (root / "index.html").write_text(
                '<form action="/apply"></form>', encoding="utf-8"
            )
            run_output = Path(directory) / "run.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = mapping_main((
                    "analyze-root", str(root),
                    "--artifact-sha256", "c" * 64,
                    "--output", str(run_output),
                    "--profile", "base",
                    "--graph-focus", "/apply",
                ))
            run_exists = run_output.exists()

        self.assertEqual(1, exit_code)
        self.assertFalse(run_exists)

    @staticmethod
    def catalog(
        candidates: tuple,
        obligations: tuple = (),
        coverage: tuple = (),
        parameters: tuple = (),
        associations: tuple = (),
    ) -> DiscoveryCatalog:
        evidence = EvidenceAtom(
            "evidence:1", "subject:1", "observes", "value",
            EvidenceSpan("fixture.bin", "a" * 64, "binary:0-1"),
            "fixture", "1.0.0", ObservationKind.DIRECT_STATIC,
            "observes_fixture", 1.0,
        )
        return DiscoveryCatalog(
            catalog_id="discovery-catalog:test",
            firmware_artifact_sha256="1" * 64,
            source_inventory_sha256="2" * 64,
            coverage_status=CoverageStatus.COMPLETED,
            source_inventory_coverage_status=CoverageStatus.COMPLETED,
            candidates=candidates,
            parameters=parameters,
            evidence_atoms=(evidence,),
            coverage=coverage,
            associations=associations,
            open_obligations=obligations,
        )

    @staticmethod
    def source(path: str, content: bytes) -> SourceArtifactEntry:
        return SourceArtifactEntry(
            canonical_path=path,
            original_path=path,
            kind="file",
            size=len(content),
            content_sha256=hashlib.sha256(content).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
