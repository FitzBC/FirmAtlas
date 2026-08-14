import hashlib
from pathlib import Path
import unittest

from firmatlas.mapping import (
    ArmCgiSelectorArtifact,
    ArmConfigurationUrlIpcArtifact,
    CommunicationGraphEdgeKind,
    CoverageStatus,
    DiscoveryCandidateKind,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    SourceArtifactEntry,
    MappingAnalysisRequest,
    MappingAnalysisProfile,
    analyze_extracted_root,
    assemble_discovery_catalog,
    discover_arm_cgi_selector_dispatches,
    discover_arm_configuration_url_ipc_flows,
    project_communication_architecture_graph,
    replay_evidence,
)


ROOT = (
    Path(__file__).resolve().parents[2]
    / "iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root"
)


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )


def _selector_artifact(path: str) -> ArmCgiSelectorArtifact:
    content = ROOT.joinpath(*path.split("/")).read_bytes()
    return ArmCgiSelectorArtifact(_source(path, content), content)


def _url_artifact(path: str) -> ArmConfigurationUrlIpcArtifact:
    content = ROOT.joinpath(*path.split("/")).read_bytes()
    return ArmConfigurationUrlIpcArtifact(_source(path, content), content)


class ArmCgiSelectorDispatchContractTests(unittest.TestCase):
    def test_actual_ac9_recovers_unanchored_cgi_bin_selector_inventory(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")

        result = discover_arm_cgi_selector_dispatches((
            _selector_artifact("bin/httpd"),
        ))

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(
            {
                "upgrade": 0x3B4A8,
                "UploadCfg": 0x3B850,
                "DownloadCfg": 0x3C0AC,
                "DownloadLog": 0x3CE4C,
                "DownloadFlash": 0x3D4C0,
                "DownloadWebsite": 0x3D6C0,
                "UploadWebsite": 0x3E564,
            },
            {item.selector: item.handler_address for item in result.selectors},
        )
        for item in result.selectors:
            self.assertEqual("cgi-bin", item.transport_namespace)
            self.assertEqual(0x2EB64, item.namespace_registration_address)
            self.assertEqual(0x178F0, item.namespace_registrar_address)
            self.assertEqual("bin/httpd@0x0003a678", item.owner_identity)
            self.assertEqual("bin/httpd@0x0003a9a0", item.dispatcher_identity)
            self.assertEqual(
                "/cgi-bin/{}".format(item.selector), item.interface_path
            )
            self.assertEqual("deterministic_derived", item.interface_path_status)
            self.assertEqual("unresolved", item.method_status)
            self.assertEqual("no_direct_handler_call", item.loader_activation_status)
        flash = next(item for item in result.selectors if item.selector == "DownloadFlash")
        self.assertEqual(11, flash.comparison_width)
        self.assertEqual(8, len(result.open_obligations))
        self.assertEqual(
            {
                "binds_cgi_selector_http_method",
                "binds_configuration_url_loader_activation",
            },
            {item.required_capability for item in result.open_obligations},
        )
        self.assertTrue({
            "registers_cgi_transport_namespace",
            "resolves_cgi_namespace_owner_symbol",
            "parses_cgi_path_segment",
            "derives_cgi_interface_path",
        }.issubset({item.capability for item in result.evidence_atoms}))
        artifact = _selector_artifact("bin/httpd")
        self.assertFalse(any(
            item.interface_path.startswith("/goform/")
            or item.method == "POST"
            for item in result.selectors
        ))
        for atom in result.evidence_atoms:
            self.assertTrue(replay_evidence(atom, artifact.source, artifact.content))

    def test_catalog_and_graph_link_uploadwebsite_to_url_consumer_without_endpoint(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")
        selectors = discover_arm_cgi_selector_dispatches((
            _selector_artifact("bin/httpd"),
        ))
        url = discover_arm_configuration_url_ipc_flows((
            _url_artifact("lib/libCfm.so"),
            _url_artifact("bin/cfmd"),
            _url_artifact("bin/httpd"),
            _url_artifact("bin/cfm"),
        ))
        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "a" * 64,
            "b" * 64,
            (
                DiscoveryProducerBatch.native_cgi_selector_dispatch(
                    (selectors,), "test:cgi-selector"
                ),
                DiscoveryProducerBatch.native_configuration_url_ipc_flow(
                    (url,), "test:url-ipc"
                ),
            ),
        ))

        selector = next(
            item for item in catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.NATIVE_CGI_SELECTOR
            and item.canonical_identity == "/cgi-bin/UploadWebsite"
        )
        self.assertEqual(
            "/cgi-bin/UploadWebsite", dict(selector.attributes)["interface_path"]
        )
        self.assertEqual((), catalog.parameters)
        self.assertTrue(any(
            item.target_ref == selector.candidate_id
            and item.required_capability == "binds_cgi_selector_http_method"
            for item in catalog.open_obligations
        ))
        consumer = next(
            item for item in catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.NATIVE_CONFIGURATION_URL_CONSUMER
            and dict(item.attributes)["function_identity"]
            == "bin/httpd@0x0003e564"
        )
        graph = project_communication_architecture_graph(catalog)
        self.assertTrue(any(
            edge.edge_kind is CommunicationGraphEdgeKind.CALLS
            and edge.source_ref == selector.candidate_id
            and edge.target_ref == consumer.candidate_id
            for edge in graph.edges
        ))
        self.assertFalse(any(
            node.node_kind.value == "interface"
            for node in graph.nodes
        ))

    def test_source_mismatch_fails_closed(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")
        good = _selector_artifact("bin/httpd")
        bad = ArmCgiSelectorArtifact(good.source, good.content + b"x")

        result = discover_arm_cgi_selector_dispatches((bad,))

        self.assertEqual(CoverageStatus.FAILED, result.coverage_status)
        self.assertEqual((), result.selectors)
        self.assertIn("source_mismatch", result.diagnostics)

    def test_auto_v20_runs_selector_inventory_from_the_uploaded_root(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")

        result = analyze_extracted_root(MappingAnalysisRequest(
            ROOT, "c" * 64, profile=MappingAnalysisProfile.auto_v20()
        ))

        self.assertTrue(any(
            item.candidate_kind is DiscoveryCandidateKind.NATIVE_CGI_SELECTOR
            and item.canonical_identity == "/cgi-bin/UploadWebsite"
            for item in result.catalog.candidates
        ))
        stage = next(
            item for item in result.stages
            if item.stage_name == "native_cgi_selector_dispatch"
        )
        self.assertEqual(CoverageStatus.COMPLETED, stage.coverage_status)
        self.assertEqual(7, stage.output_count)


if __name__ == "__main__":
    unittest.main()
