import hashlib
from pathlib import Path
import unittest

from firmatlas.mapping import (
    ArmCrossElfArtifact,
    ArmCrossElfCallAnchor,
    CoverageStatus,
    CommunicationGraphEdgeKind,
    DiscoveryCandidateKind,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    SourceArtifactEntry,
    discover_arm_cross_elf_calls,
    discover_native_pointer_command_table_bindings,
    assemble_discovery_catalog,
    project_communication_architecture_graph,
)


ROOT = (
    Path(__file__).resolve().parents[2]
    / "iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root"
)


def _artifact(path: str) -> ArmCrossElfArtifact:
    content = ROOT.joinpath(*path.split("/")).read_bytes()
    source = SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )
    return ArmCrossElfArtifact(source, content)


class ArmCrossElfCallContractTests(unittest.TestCase):
    def test_actual_ac9_recovers_cfm_pointer_command_table(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")
        artifact = _artifact("bin/cfm")

        result = discover_native_pointer_command_table_bindings(
            artifact.source, artifact.content
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        upload = next(item for item in result.bindings if item.command == "Upload")
        self.assertEqual("gCtlCmdArr", upload.table_symbol)
        self.assertEqual(0x13A6C, upload.registration_address)
        self.assertEqual(0x9E20, upload.handler_address)
        self.assertEqual("bin/cfm@0x00009e20", upload.handler_identity)
        self.assertEqual(4, len(upload.evidence_ids))

    def test_actual_ac9_follows_imports_from_cgi_handler_across_elf_exports(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")

        result = discover_arm_cross_elf_calls(
            (
                _artifact("bin/httpd"),
                _artifact("lib/libtpi.so"),
                _artifact("bin/cfm"),
                _artifact("lib/libCfm.so"),
            ),
            (
                ArmCrossElfCallAnchor(
                    "native-cgi-dispatch:upload",
                    "bin/httpd",
                    0x3B850,
                ),
                ArmCrossElfCallAnchor(
                    "native-command-binding:cfm-upload",
                    "bin/cfm",
                    0x9E20,
                ),
            ),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertFalse(any(
            item.source_path == "lib/libc.so.0"
            or item.source_path == "lib/libpthread.so.0"
            for item in result.hops
        ))
        observed = {
            (
                hop.source_function_identity,
                hop.callsite_address,
                hop.imported_symbol,
                hop.target_function_identity,
            )
            for hop in result.hops
        }
        self.assertIn(
            ("bin/httpd@0x0003b850", 0x3BA38, "tpi_upfile_handle",
             "lib/libtpi.so@0x00009e80"),
            observed,
        )
        command = next(
            item for item in result.hops
            if item.callsite_address == 0x9D68
            and item.imported_symbol == "doSystemCmd"
        )
        self.assertEqual(("cfm Upload",), command.argument_literals)
        self.assertEqual("unresolved_import_owner", command.target_resolution_status)
        self.assertEqual("", command.target_path)
        self.assertIn(
            ("lib/libtpi.so@0x00009e80", 0x9EF4, "tpi_sys_cfg_upload",
             "lib/libtpi.so@0x00009c5c"),
            observed,
        )
        self.assertIn(
            ("bin/cfm@0x00009e20", 0x9E64, "UploadValue",
             "lib/libCfm.so@0x0000429c"),
            observed,
        )
        self.assertIn(
            ("lib/libCfm.so@0x0000429c", 0x4334, "SendMsg",
             "lib/libCfm.so@0x00003578"),
            observed,
        )
        self.assertIn(
            ("lib/libCfm.so@0x0000429c", 0x4374, "RecvMsg",
             "lib/libCfm.so@0x000035ac"),
            observed,
        )
        send = next(item for item in result.hops if item.callsite_address == 0x4334)
        self.assertEqual(2, len(send.evidence_ids))

    def test_unknown_anchor_artifact_fails_closed(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")
        result = discover_arm_cross_elf_calls(
            (_artifact("bin/httpd"),),
            (ArmCrossElfCallAnchor("route:x", "bin/missing", 0x1000),),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual((), result.hops)
        self.assertIn("anchor_artifact_missing", result.diagnostics)

    def test_catalog_projects_cross_elf_hops_with_exact_origin_and_target(self):
        if not ROOT.is_dir():
            self.skipTest("external Tenda AC9 corpus is not available")
        artifact = _artifact("bin/httpd")
        result = discover_arm_cross_elf_calls(
            (artifact, _artifact("lib/libtpi.so")),
            (ArmCrossElfCallAnchor(
                "native-cgi-dispatch:upload", "bin/httpd", 0x3B850
            ),),
        )

        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            firmware_artifact_sha256="a" * 64,
            source_inventory_sha256="b" * 64,
            batches=(DiscoveryProducerBatch.native_cross_elf_call(
                (result,), "test:cross-elf"
            ),),
        ))

        call = next(
            item for item in catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.NATIVE_CROSS_ELF_CALL
            and dict(item.attributes)["imported_symbol"] == "tpi_upfile_handle"
        )
        self.assertEqual(
            '["native-cgi-dispatch:upload"]',
            dict(call.attributes)["origin_refs"],
        )
        graph = project_communication_architecture_graph(catalog)
        first = next(
            item for item in catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.NATIVE_CROSS_ELF_CALL
            and dict(item.attributes)["imported_symbol"] == "tpi_upfile_handle"
        )
        second = next(
            item for item in catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.NATIVE_CROSS_ELF_CALL
            and dict(item.attributes)["imported_symbol"] == "tpi_sys_cfg_upload"
        )
        self.assertTrue(any(
            edge.edge_kind is CommunicationGraphEdgeKind.CALLS
            and edge.source_ref == first.candidate_id
            and edge.target_ref == second.candidate_id
            for edge in graph.edges
        ))
        self.assertEqual(
            "lib/libtpi.so@0x00009e80",
            dict(call.attributes)["target_function_identity"],
        )


if __name__ == "__main__":
    unittest.main()
