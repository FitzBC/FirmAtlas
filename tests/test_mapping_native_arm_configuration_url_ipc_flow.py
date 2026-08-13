import hashlib
import json
from pathlib import Path
import unittest

from firmatlas.mapping import (
    ArmConfigurationUrlIpcArtifact,
    CoverageStatus,
    CommunicationGraphEdgeKind,
    DiscoveryCandidateKind,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    discover_arm_configuration_url_ipc_flows,
    project_communication_architecture_graph,
    replay_evidence,
)


ROOT = (
    Path(__file__).resolve().parents[2]
    / "iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root"
)


def _artifact(path: str) -> ArmConfigurationUrlIpcArtifact:
    content = ROOT.joinpath(*path.split("/")).read_bytes()
    source = SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )
    return ArmConfigurationUrlIpcArtifact(source, content)


class ArmConfigurationUrlIpcFlowContractTests(unittest.TestCase):
    def test_actual_ac9_recovers_five_url_store_operations_and_http_consumers(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")

        result = discover_arm_configuration_url_ipc_flows((
            _artifact("lib/libCfm.so"),
            _artifact("bin/cfmd"),
            _artifact("bin/httpd"),
            _artifact("bin/cfm"),
        ))

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(5, len(result.operations))
        self.assertEqual(5, len(result.consumers))
        expected = {
            "get": ("GetUrlValue", 32, (33,), "GetCfmUrlValue", "url_mib_get_value"),
            "set": ("SetUrlValue", 30, (31,), "SetCfmUrlValue", "url_mib_set_value"),
            "unset": ("UnSetUrlValue", 36, (37,), "UnSetCfmUrlValue", "url_mib_unset_value"),
            "commit": ("CommitUrlCfm", 34, (16, 35), "SaveCfmUrl2Flash", "save_url_mib"),
            "show": ("ShowUrlValue", 38, (39,), "ShowCfmUrlValue", "url_mib_list"),
        }
        self.assertEqual(expected, {
            item.operation: (
                item.client_symbol,
                item.request_opcode,
                item.response_opcodes,
                item.server_wrapper_symbol,
                item.store_primitive_symbol,
            )
            for item in result.operations
        })
        for item in result.operations:
            self.assertEqual(2016, item.message_size)
            self.assertEqual("/var/cfm_socket", item.channel_path)
            self.assertEqual(4 if item.operation != "commit" else None,
                             item.key_offset)
            self.assertEqual(516 if item.operation in {"get", "set"} else None,
                             item.value_offset)
            self.assertEqual("cfm/url_mib/*", item.state_scope)

        self.assertEqual(
            {
                "urlgroup.class%d.list%d",
                "urlgroup.class%d.listnum",
                "urlgroup.class%d.sysnum",
                "urlgroup.list%d",
                "urlgroup.listnum",
                "urlgroup.sysnum",
            },
            {key for item in result.consumers for key in item.state_key_templates},
        )
        self.assertEqual(
            {"GetUrlValue": 1, "SetUrlValue": 1,
             "UnSetUrlValue": 1, "CommitUrlCfm": 1,
             "ShowUrlValue": 1},
            {
                symbol: count for path, symbol, count in result.client_call_counts
                if path == "bin/cfm"
            },
        )
        for consumer in result.consumers:
            self.assertEqual(
                set(consumer.access_modes),
                {mode for _, mode in consumer.state_accesses},
            )
        self.assertTrue({
            "urlgroup.rule.list%d", "urlgroup.rule.listnum",
            "urlgroup.flag", "urlgroup.name",
        }.isdisjoint(
            {key for item in result.consumers for key in item.state_key_templates}
        ))
        self.assertEqual(
            {"GetUrlValue": 16, "SetUrlValue": 6,
             "UnSetUrlValue": 2, "CommitUrlCfm": 1},
            {
                symbol: count for path, symbol, count in result.client_call_counts
                if path == "bin/httpd"
            },
        )

        by_path = {item.source.canonical_path: item for item in (
            _artifact("lib/libCfm.so"), _artifact("bin/cfmd"), _artifact("bin/httpd")
        )}
        for atom in result.evidence_atoms:
            artifact = by_path[atom.source_span.artifact_path]
            self.assertTrue(replay_evidence(atom, artifact.source, artifact.content))

    def test_catalog_and_graph_keep_url_keys_as_state_templates_not_http_parameters(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")
        result = discover_arm_configuration_url_ipc_flows((
            _artifact("lib/libCfm.so"), _artifact("bin/cfmd"), _artifact("bin/httpd")
        ))

        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "a" * 64,
            "b" * 64,
            (DiscoveryProducerBatch.native_configuration_url_ipc_flow(
                (result,), "test:url-ipc"
            ),),
        ))

        operations = tuple(
            item for item in catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.NATIVE_CONFIGURATION_URL_IPC_FLOW
        )
        consumers = tuple(
            item for item in catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.NATIVE_CONFIGURATION_URL_CONSUMER
        )
        self.assertEqual(5, len(operations))
        self.assertEqual(5, len(consumers))
        self.assertEqual((), catalog.parameters)
        get_attributes = dict(next(
            item for item in operations
            if dict(item.attributes)["operation"] == "get"
        ).attributes)
        self.assertIn(["bin/httpd", 16], json.loads(
            get_attributes["client_call_counts"]
        ))
        graph = project_communication_architecture_graph(catalog)
        self.assertTrue(any(
            edge.edge_kind is CommunicationGraphEdgeKind.READS_STATE
            for edge in graph.edges
        ))
        self.assertTrue(any(
            edge.edge_kind is CommunicationGraphEdgeKind.WRITES_STATE
            for edge in graph.edges
        ))
        parameter_state = next(
            item for item in graph.view_presets if item.preset_id == "parameter_state"
        )
        self.assertTrue({
            "reads_state", "writes_state", "deletes_state", "persists_state",
        }.issubset(set(parameter_state.edge_kinds)))
        self.assertIn("component", parameter_state.node_kinds)
        labels = {item.label for item in graph.nodes}
        self.assertIn("urlgroup.class%d.list%d", labels)
        self.assertNotIn("urlgroup.rule.list%d", labels)
        self.assertNotIn("urlgroup.flag", labels)
        self.assertNotIn("urlgroup.name", labels)
        for candidate in consumers:
            attributes = dict(candidate.attributes)
            accesses = {
                tuple(item) for item in json.loads(attributes["state_accesses"])
            }
            self.assertTrue(accesses)

    def test_source_mismatch_fails_closed(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")
        good = _artifact("lib/libCfm.so")
        bad = ArmConfigurationUrlIpcArtifact(good.source, good.content + b"x")

        result = discover_arm_configuration_url_ipc_flows((bad,))

        self.assertEqual(CoverageStatus.FAILED, result.coverage_status)
        self.assertEqual((), result.operations)
        self.assertEqual((), result.consumers)
        self.assertIn("source_mismatch", result.diagnostics)


if __name__ == "__main__":
    unittest.main()
