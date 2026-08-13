import hashlib
import json
from pathlib import Path
import unittest

from firmatlas.mapping import (
    ArmConfigurationTextImportArtifact,
    CoverageStatus,
    CommunicationGraphEdgeKind,
    CommunicationGraphNodeKind,
    DiscoveryCandidateKind,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    SourceArtifactEntry,
    analyze_extracted_root,
    assemble_discovery_catalog,
    discover_arm_configuration_text_import_flows,
    project_communication_architecture_graph,
    replay_evidence,
)


ROOT = (
    Path(__file__).resolve().parents[2]
    / "iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root"
)


def _artifact(path: str) -> ArmConfigurationTextImportArtifact:
    content = ROOT.joinpath(*path.split("/")).read_bytes()
    source = SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )
    return ArmConfigurationTextImportArtifact(source, content)


class ArmConfigurationTextImportFlowContractTests(unittest.TestCase):
    def test_actual_ac9_recovers_uploaded_document_parser_and_exact_state_keys(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")
        artifacts = (
            _artifact("lib/libtpi.so"),
            _artifact("lib/libCfm.so"),
            _artifact("bin/cfmd"),
            _artifact("webroot_ro/default.cfg"),
            _artifact("etc_ro/init.d/rcS"),
        )

        result = discover_arm_configuration_text_import_flows(artifacts)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.flows))
        flow = result.flows[0]
        self.assertEqual("lib/libtpi.so@0x00009c5c", flow.upload_identity)
        self.assertEqual("lib/libCfm.so@0x0000588c", flow.restore_identity)
        self.assertEqual("lib/libCfm.so@0x0000429c", flow.ipc_client_identity)
        self.assertEqual("bin/cfmd@0x0000a504", flow.ipc_dispatcher_identity)
        self.assertEqual(14, flow.request_opcode)
        self.assertEqual("0", flow.payload_literal)
        self.assertEqual("lib/libCfm.so@0x00007314", flow.parser_identity)
        self.assertEqual("/webroot/default.cfg", flow.primary_runtime_path)
        self.assertEqual("/webroot/default_url.cfg", flow.secondary_runtime_path)
        self.assertEqual("##the public configure end##", flow.section_delimiter)
        self.assertEqual("cfm Upload", flow.import_command)
        self.assertEqual("cfm/default_mib/*", flow.state_scope)
        self.assertEqual("key_value_document", flow.write_granularity)
        self.assertEqual(1015, len(flow.declared_keys))
        self.assertEqual(1013, len(set(flow.declared_keys)))
        self.assertIn("security.ddos.map", flow.declared_keys)
        self.assertIn("sys.schedulereboot.enable", flow.declared_keys)
        self.assertNotIn("configuration_partition[0]", result.to_dict().__repr__())

        by_path = {item.source.canonical_path: item for item in artifacts}
        for atom in result.evidence_atoms:
            artifact = by_path[atom.source_span.artifact_path]
            self.assertTrue(replay_evidence(atom, artifact.source, artifact.content))

    def test_source_mismatch_fails_closed(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")
        good = _artifact("webroot_ro/default.cfg")
        bad = ArmConfigurationTextImportArtifact(good.source, good.content + b"x")

        result = discover_arm_configuration_text_import_flows((bad,))

        self.assertEqual(CoverageStatus.FAILED, result.coverage_status)
        self.assertEqual((), result.flows)
        self.assertIn("source_mismatch", result.diagnostics)

    def test_catalog_and_graph_publish_configuration_states_not_http_parameters(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")
        result = discover_arm_configuration_text_import_flows((
            _artifact("lib/libtpi.so"),
            _artifact("lib/libCfm.so"),
            _artifact("bin/cfmd"),
            _artifact("webroot_ro/default.cfg"),
            _artifact("etc_ro/init.d/rcS"),
        ))
        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "a" * 64,
            "b" * 64,
            (DiscoveryProducerBatch.native_configuration_text_import_flow(
                (result,), "test:configuration-text-import"
            ),),
        ))

        candidate = next(
            item for item in catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.NATIVE_CONFIGURATION_TEXT_IMPORT_FLOW
        )
        self.assertEqual("cfm Upload->cfm/default_mib/*", candidate.canonical_identity)
        self.assertEqual((), catalog.parameters)
        graph = project_communication_architecture_graph(catalog)
        states = {
            node.label: node for node in graph.nodes
            if node.node_kind is CommunicationGraphNodeKind.STATE
        }
        self.assertIn("security.ddos.map", states)
        self.assertIn("sys.schedulereboot.enable", states)
        self.assertNotIn("configuration_partition[0]", states)
        self.assertTrue(any(
            edge.edge_kind is CommunicationGraphEdgeKind.IMPORTS_STATE
            and edge.source_ref == candidate.candidate_id
            and next(
                node for node in graph.nodes if node.node_id == edge.target_ref
            ).label == "security.ddos.map"
            for edge in graph.edges
        ))
        parameter_state = next(
            item for item in graph.view_presets
            if item.preset_id == "parameter_state"
        )
        self.assertIn("imports_state", parameter_state.edge_kinds)

    def test_auto_v17_replaces_blob_interpretation_and_v16_stays_frozen(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")

        self.assertEqual(
            "firmatlas.mapping.profile/auto-v17", MappingAnalysisProfile.auto().profile_id
        )
        self.assertIn(
            "native_configuration_blob_flow",
            MappingAnalysisProfile.auto_v16().enabled_analyzers,
        )
        self.assertNotIn(
            "native_configuration_blob_flow",
            MappingAnalysisProfile.auto().enabled_analyzers,
        )
        run = analyze_extracted_root(MappingAnalysisRequest(ROOT, "a" * 64))
        kinds = {item.candidate_kind for item in run.catalog.candidates}
        self.assertIn(DiscoveryCandidateKind.NATIVE_CONFIGURATION_TEXT_IMPORT_FLOW, kinds)
        self.assertNotIn(DiscoveryCandidateKind.NATIVE_CONFIGURATION_BLOB_FLOW, kinds)
        graph = project_communication_architecture_graph(run.catalog)
        labels = {node.label for node in graph.nodes}
        self.assertIn("security.ddos.map", labels)
        self.assertNotIn("configuration_partition[0]", labels)


if __name__ == "__main__":
    unittest.main()
