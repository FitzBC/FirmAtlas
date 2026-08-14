import hashlib
from pathlib import Path
import unittest

from firmatlas.mapping import (
    ArmConfigurationUrlDocumentArtifact,
    CommunicationGraphEdgeKind,
    CommunicationGraphNodeKind,
    CoverageStatus,
    DiscoveryCandidateKind,
    DiscoveryClaimStatus,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    analyze_extracted_root,
    discover_arm_configuration_url_document_flows,
    project_communication_architecture_graph,
    replay_evidence,
)


ROOT = (
    Path(__file__).resolve().parents[2]
    / "iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root"
)


def _artifact(path: str) -> ArmConfigurationUrlDocumentArtifact:
    content = ROOT.joinpath(*path.split("/")).read_bytes()
    source = SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )
    return ArmConfigurationUrlDocumentArtifact(source, content)


class ArmConfigurationUrlDocumentFlowContractTests(unittest.TestCase):
    def test_actual_ac9_recovers_distinct_url_document_consumer_without_inventing_activation(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")
        artifacts = (_artifact("lib/libtpi.so"), _artifact("lib/libCfm.so"))

        result = discover_arm_configuration_url_document_flows(artifacts)

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual(1, len(result.flows))
        flow = result.flows[0]
        self.assertEqual("lib/libtpi.so@0x00009c5c", flow.writer_identity)
        self.assertEqual("/webroot/default_url.cfg", flow.runtime_path)
        self.assertEqual("lib/libCfm.so@0x00008d0c", flow.loader_identity)
        self.assertEqual("lib/libCfm.so@0x0000766c", flow.parser_identity)
        self.assertEqual("lib/libCfm.so@0x00008e08", flow.reload_identity)
        self.assertEqual("cfm/url_mib/*", flow.state_scope)
        self.assertEqual("key_value_document", flow.write_granularity)
        self.assertEqual("unresolved", flow.activation_status)
        self.assertEqual(1, len(result.open_obligations))
        self.assertIn("url_document_content_missing", result.diagnostics)
        obligation = result.open_obligations[0]
        self.assertEqual(flow.flow_id, obligation.target_ref)
        self.assertEqual(
            "binds_configuration_url_loader_activation",
            obligation.required_capability,
        )
        for atom in result.evidence_atoms:
            artifact = next(
                item for item in artifacts
                if item.source.canonical_path == atom.source_span.artifact_path
            )
            self.assertTrue(replay_evidence(atom, artifact.source, artifact.content))

    def test_catalog_and_graph_keep_url_state_scope_candidate_and_obligation_visible(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")
        result = discover_arm_configuration_url_document_flows((
            _artifact("lib/libtpi.so"), _artifact("lib/libCfm.so"),
        ))
        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "a" * 64,
            "b" * 64,
            (DiscoveryProducerBatch.native_configuration_url_document_flow(
                (result,), "test:configuration-url-document"
            ),),
        ))

        candidate = next(
            item for item in catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.NATIVE_CONFIGURATION_URL_DOCUMENT_FLOW
        )
        self.assertEqual(DiscoveryClaimStatus.CANDIDATE, candidate.claim_status)
        self.assertEqual(
            "/webroot/default_url.cfg->cfm/url_mib/*",
            candidate.canonical_identity,
        )
        self.assertEqual(candidate.candidate_id, catalog.open_obligations[0].target_ref)
        graph = project_communication_architecture_graph(catalog)
        state = next(
            node for node in graph.nodes
            if node.node_kind is CommunicationGraphNodeKind.STATE
            and node.label == "cfm/url_mib/*"
        )
        self.assertTrue(any(
            edge.edge_kind is CommunicationGraphEdgeKind.IMPORTS_STATE
            and edge.source_ref == candidate.candidate_id
            and edge.target_ref == state.node_id
            and edge.status == "candidate"
            for edge in graph.edges
        ))
        self.assertTrue(any(
            node.node_kind is CommunicationGraphNodeKind.OBLIGATION
            and dict(node.attributes)["target_ref"] == candidate.candidate_id
            for node in graph.nodes
        ))

    def test_auto_v18_adds_url_document_flow_and_v17_stays_frozen(self):
        self.assertEqual(
            "firmatlas.mapping.profile/auto-v20", MappingAnalysisProfile.auto().profile_id
        )
        self.assertIn(
            "native_configuration_url_document_flow",
            MappingAnalysisProfile.auto().enabled_analyzers,
        )
        self.assertNotIn(
            "native_configuration_url_document_flow",
            MappingAnalysisProfile.auto_v17().enabled_analyzers,
        )

    def test_actual_ac9_analysis_run_publishes_url_scope_and_activation_obligation(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")

        run = analyze_extracted_root(MappingAnalysisRequest(ROOT, "a" * 64))

        self.assertEqual("firmatlas.mapping.profile/auto-v20", run.profile_id)
        candidate = next(
            item for item in run.catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.NATIVE_CONFIGURATION_URL_DOCUMENT_FLOW
        )
        self.assertTrue(any(
            item.target_ref == candidate.candidate_id
            and item.required_capability
            == "binds_configuration_url_loader_activation"
            for item in run.catalog.open_obligations
        ))
        graph = project_communication_architecture_graph(run.catalog)
        self.assertIn("cfm/url_mib/*", {item.label for item in graph.nodes})


if __name__ == "__main__":
    unittest.main()
