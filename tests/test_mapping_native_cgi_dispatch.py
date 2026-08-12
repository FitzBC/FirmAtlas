import hashlib
from pathlib import Path
import struct
import unittest

from firmatlas.mapping import (
    ArmCgiDispatchAnchor,
    CommunicationGraphEdgeKind,
    CommunicationGraphNodeKind,
    CoverageStatus,
    DiscoveryCandidateKind,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    discover_arm_cgi_string_dispatch,
    discover_frontend_requests,
    project_communication_architecture_graph,
)
from tests.test_mapping_native_callsite import _arm32_pic_fixture, _arm_bl


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )


def _cgi_dispatch_fixture() -> bytes:
    payload = bytearray(_arm32_pic_fixture())
    section_table_offset = struct.unpack_from("<I", payload, 32)[0]
    text_offset = struct.unpack_from(
        "<I", payload, section_table_offset + 2 * 40 + 16
    )[0]

    def put(address: int, value: int) -> None:
        struct.pack_into(
            "<I", payload, text_offset + address - 0x1000, value & 0xFFFFFFFF
        )

    # Reuse the two exact .rodata strings from the shared ELF fixture.  The
    # dispatcher compares each token, checks the zero result, then directly
    # branches to a different executable handler.
    route_one = "SetOnlineDevName"
    route_two = "GetDeviceDetail"
    put(0x1100, 0xE92D4810)  # push {r4, r11, lr}
    put(0x1104, 0xE59F4074)  # PIC delta at 0x1180
    put(0x1108, 0xE08F4004)  # r4 = GOT

    def dispatch_block(
        address: int, literal_address: int, token: str, handler: int,
    ) -> None:
        put(address + 0x00, 0xE51B0018)  # load request token
        displacement = literal_address - (address + 0x04 + 8)
        put(address + 0x04, 0xE59F3000 | displacement)
        put(address + 0x08, 0xE0843003)  # token = GOT + literal delta
        put(address + 0x0C, 0xE1A01003)  # r1 = token
        put(address + 0x10, 0xE3A02000 | len(token))
        put(address + 0x14, _arm_bl(address + 0x14, 0x1200))
        put(address + 0x18, 0xE1A03000)
        put(address + 0x1C, 0xE3530000)  # compare result with zero
        put(address + 0x20, 0x1A000005)  # non-match skips handler arm
        put(address + 0x24, 0xE51B0010)
        put(address + 0x28, 0xE51B1018)
        put(address + 0x2C, 0xE51B2014)
        put(address + 0x30, _arm_bl(address + 0x30, handler))

    dispatch_block(0x110C, 0x1184, route_one, 0x11C0)
    dispatch_block(0x1144, 0x1188, route_two, 0x11E0)
    put(0x1180, 0x3000 - 0x1110)
    put(0x1184, 0x2000 - 0x3000)
    put(0x1188, 0x2000 + len(route_one) + 1 - 0x3000)
    put(0x11C0, 0xE12FFF1E)
    put(0x11E0, 0xE12FFF1E)
    return bytes(payload)


def _replace_text_word(content: bytes, address: int, value: int) -> bytes:
    payload = bytearray(content)
    section_table_offset = struct.unpack_from("<I", payload, 32)[0]
    text_offset = struct.unpack_from(
        "<I", payload, section_table_offset + 2 * 40 + 16
    )[0]
    struct.pack_into(
        "<I", payload, text_offset + address - 0x1000, value & 0xFFFFFFFF
    )
    return bytes(payload)


class ArmCgiStringDispatchContractTests(unittest.TestCase):
    def test_download_subpath_uses_the_first_cgi_dispatch_segment(self):
        anchor = ArmCgiDispatchAnchor(
            "frontend-request:download",
            "/cgi-bin/DownloadCfg/RouterCfm.cfg",
        )

        self.assertEqual("DownloadCfg", anchor.dispatch_token)

    def test_exact_token_comparison_binds_frontend_cgi_path_to_handler(self):
        content = _cgi_dispatch_fixture()

        result = discover_arm_cgi_string_dispatch(
            _source("bin/httpd", content),
            content,
            (ArmCgiDispatchAnchor(
                "frontend-request:upload",
                "/cgi-bin/SetOnlineDevName",
            ),),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.bindings))
        binding = result.bindings[0]
        self.assertEqual("SetOnlineDevName", binding.dispatch_token)
        self.assertEqual(0x1100, binding.dispatcher_address)
        self.assertEqual(0x11C0, binding.handler_address)
        self.assertEqual("bin/httpd@0x000011c0", binding.handler_identity)
        self.assertEqual(2, binding.dispatcher_entry_count)
        self.assertEqual(4, len(binding.evidence_ids))

    def test_one_similar_entry_is_not_enough_to_claim_a_dispatcher_family(self):
        content = _replace_text_word(
            _cgi_dispatch_fixture(),
            0x1144 + 0x14,
            _arm_bl(0x1144 + 0x14, 0x11E0),
        )

        result = discover_arm_cgi_string_dispatch(
            _source("bin/httpd", content),
            content,
            (ArmCgiDispatchAnchor(
                "frontend-request:upload",
                "/cgi-bin/SetOnlineDevName",
            ),),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual((), result.bindings)

    def test_token_length_mismatch_does_not_bind_a_frontend_path(self):
        content = _replace_text_word(
            _cgi_dispatch_fixture(), 0x110C + 0x10, 0xE3A02001
        )

        result = discover_arm_cgi_string_dispatch(
            _source("bin/httpd", content),
            content,
            (ArmCgiDispatchAnchor(
                "frontend-request:upload",
                "/cgi-bin/SetOnlineDevName",
            ),),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual((), result.bindings)

    def test_actual_ac9_upload_and_download_bind_to_cgi_handlers(self):
        path = (
            Path(__file__).resolve().parents[2]
            / "iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/"
              "squashfs-root/bin/httpd"
        )
        if not path.exists():
            self.skipTest("local AC9 representative sample is unavailable")
        content = path.read_bytes()

        result = discover_arm_cgi_string_dispatch(
            _source("bin/httpd", content),
            content,
            (
                ArmCgiDispatchAnchor(
                    "frontend-request:upload", "/cgi-bin/UploadCfg"
                ),
                ArmCgiDispatchAnchor(
                    "frontend-request:download", "/cgi-bin/DownloadCfg"
                ),
            ),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        bindings = {item.dispatch_token: item for item in result.bindings}
        self.assertEqual({"UploadCfg", "DownloadCfg"}, set(bindings))
        self.assertEqual(0x3A9A0, bindings["UploadCfg"].dispatcher_address)
        self.assertEqual(0x3B850, bindings["UploadCfg"].handler_address)
        self.assertEqual(0x3C0AC, bindings["DownloadCfg"].handler_address)
        self.assertEqual(6, bindings["UploadCfg"].dispatcher_entry_count)
        self.assertTrue(all(
            atom.source_span.artifact_path == "bin/httpd"
            for atom in result.evidence_atoms
        ))

    def test_catalog_and_graph_preserve_request_dispatch_and_handler_chain(self):
        frontend_content = (
            b'<form method="post" action="/cgi-bin/SetOnlineDevName">'
            b'<input name="filename" type="file"></form>'
        )
        frontend = discover_frontend_requests(
            _source("webroot_ro/system_backup.html", frontend_content),
            frontend_content,
        )
        request = frontend.candidates[0]
        native_content = _cgi_dispatch_fixture()
        native = discover_arm_cgi_string_dispatch(
            _source("bin/httpd", native_content), native_content,
            (ArmCgiDispatchAnchor(request.candidate_id, request.endpoint),),
        )

        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            firmware_artifact_sha256="1" * 64,
            source_inventory_sha256="2" * 64,
            batches=(
                DiscoveryProducerBatch.frontend((frontend,), "frontend"),
                DiscoveryProducerBatch.native_cgi_dispatch(
                    (native,), "native:cgi-dispatch"
                ),
            ),
        ))

        dispatch = next(
            item for item in catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.NATIVE_CGI_DISPATCH
        )
        handler = next(
            item for item in catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.NATIVE_HANDLER
        )
        self.assertEqual(request.candidate_id, dict(dispatch.attributes)["target_ref"])
        self.assertEqual(handler.candidate_id, dict(dispatch.attributes)["handler_ref"])
        graph = project_communication_architecture_graph(catalog)
        self.assertEqual(
            CommunicationGraphNodeKind.DISPATCH,
            next(item for item in graph.nodes if item.node_id == dispatch.candidate_id).node_kind,
        )
        self.assertIn(
            (
                CommunicationGraphEdgeKind.DISPATCHED_BY,
                request.candidate_id,
                dispatch.candidate_id,
            ),
            {(item.edge_kind, item.source_ref, item.target_ref) for item in graph.edges},
        )
        self.assertIn(
            (
                CommunicationGraphEdgeKind.BINDS_HANDLER,
                dispatch.candidate_id,
                handler.candidate_id,
            ),
            {(item.edge_kind, item.source_ref, item.target_ref) for item in graph.edges},
        )


if __name__ == "__main__":
    unittest.main()
