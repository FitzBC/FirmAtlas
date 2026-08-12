import hashlib
from pathlib import Path
import unittest

from firmatlas.mapping import (
    ArmConfigurationBlobArtifact,
    CoverageStatus,
    CommunicationGraphEdgeKind,
    DiscoveryCandidateKind,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    discover_arm_configuration_blob_flows,
    project_communication_architecture_graph,
    replay_evidence,
)


ROOT = (
    Path(__file__).resolve().parents[2]
    / "iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root"
)


def _artifact(path: str) -> ArmConfigurationBlobArtifact:
    content = ROOT.joinpath(*path.split("/")).read_bytes()
    source = SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )
    return ArmConfigurationBlobArtifact(source, content)


class ArmConfigurationBlobFlowContractTests(unittest.TestCase):
    def test_actual_ac9_recovers_upload_ipc_restore_mtd_state_flow(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")
        artifacts = (
            _artifact("lib/libCfm.so"),
            _artifact("bin/cfmd"),
        )

        result = discover_arm_configuration_blob_flows(artifacts)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.flows))
        flow = result.flows[0]
        self.assertEqual("lib/libCfm.so@0x0000429c", flow.client_identity)
        self.assertEqual("bin/cfmd@0x0000a504", flow.dispatcher_identity)
        self.assertEqual(14, flow.request_opcode)
        self.assertEqual(15, flow.response_opcode)
        self.assertEqual(2016, flow.message_size)
        self.assertEqual(516, flow.payload_offset)
        self.assertEqual("0", flow.payload_literal)
        self.assertEqual("atoi", flow.decoder_symbol)
        self.assertEqual("RestoreMTD", flow.state_writer_symbol)
        self.assertEqual("configuration_partition[0]", flow.state_scope)
        self.assertEqual("whole_configuration_image", flow.write_granularity)
        self.assertEqual(7, len(flow.evidence_ids))

        by_path = {item.source.canonical_path: item for item in artifacts}
        atoms = {atom.evidence_id: atom for atom in result.evidence_atoms}
        self.assertEqual(set(flow.evidence_ids), set(atoms))
        for evidence_id in flow.evidence_ids:
            atom = atoms[evidence_id]
            artifact = by_path[atom.source_span.artifact_path]
            self.assertTrue(replay_evidence(
                atom, artifact.source, artifact.content
            ))

    def test_source_mismatch_fails_closed_without_a_state_claim(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")
        good = _artifact("lib/libCfm.so")
        bad = ArmConfigurationBlobArtifact(good.source, good.content + b"x")

        result = discover_arm_configuration_blob_flows((bad,))

        self.assertEqual(CoverageStatus.FAILED, result.coverage_status)
        self.assertEqual((), result.flows)
        self.assertIn("source_mismatch", result.diagnostics)

    def test_catalog_and_graph_keep_blob_state_distinct_from_http_parameter(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")
        result = discover_arm_configuration_blob_flows((
            _artifact("lib/libCfm.so"), _artifact("bin/cfmd")
        ))

        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "a" * 64,
            "b" * 64,
            (DiscoveryProducerBatch.native_configuration_blob_flow(
                (result,), "test:configuration-blob"
            ),),
        ))

        candidate = next(
            item for item in catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.NATIVE_CONFIGURATION_BLOB_FLOW
        )
        self.assertEqual(
            "UploadValue:opcode=14->configuration_partition[0]",
            candidate.canonical_identity,
        )
        self.assertEqual((), catalog.parameters)
        graph = project_communication_architecture_graph(catalog)
        self.assertTrue(any(
            edge.edge_kind is CommunicationGraphEdgeKind.WRITES_STATE
            and edge.source_ref == candidate.candidate_id
            for edge in graph.edges
        ))


if __name__ == "__main__":
    unittest.main()
