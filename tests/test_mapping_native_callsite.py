import hashlib
from dataclasses import replace
from pathlib import Path
import struct
import unittest

from firmatlas.mapping import (
    ArmPicCallsiteProfile,
    CoverageStatus,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    NativeRouteAnchor,
    ObligationStatus,
    SchedulerObligation,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    correlate_frontend_native,
    discover_arm_pic_callsite_bindings,
    discover_frontend_requests,
    discover_native_hints,
    native_deep_scheduler_analyzer,
    replay_evidence,
    run_obligation_scheduler,
)


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        canonical_path=path,
        original_path=path,
        kind="file",
        size=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
    )


def _arm_bl(instruction_address: int, target_address: int) -> int:
    delta = target_address - (instruction_address + 8)
    if delta % 4:
        raise ValueError("ARM BL target must be word aligned")
    return 0xEB000000 | ((delta // 4) & 0x00FFFFFF)


def _arm32_pic_fixture() -> bytes:
    route_one = b"SetOnlineDevName\x00"
    route_two = b"GetDeviceDetail\x00"
    rodata = route_one + route_two
    text = bytearray(b"\x00" * 0x300)

    def put(address: int, value: int) -> None:
        struct.pack_into("<I", text, address - 0x1000, value & 0xFFFFFFFF)

    put(0x1000, 0xE92D4010)  # push {r4, lr}
    put(0x1004, 0xE59F4074)  # ldr r4, [pc, #0x74] -> 0x1080
    put(0x1008, 0xE08F4004)  # add r4, pc, r4 -> .got

    put(0x100C, 0xE59F3070)  # route delta literal -> 0x1084
    put(0x1010, 0xE0843003)  # add r3, r4, r3
    put(0x1014, 0xE1A00003)  # mov r0, r3
    put(0x1018, 0xE59F3068)  # handler GOT offset -> 0x1088
    put(0x101C, 0xE7943003)  # ldr r3, [r4, r3]
    put(0x1020, 0xE1A01003)  # mov r1, r3
    put(0x1024, _arm_bl(0x1024, 0x1200))

    put(0x1028, 0xE59F305C)  # second independent route/handler pair
    put(0x102C, 0xE0843003)
    put(0x1030, 0xE1A00003)
    put(0x1034, 0xE59F3054)
    put(0x1038, 0xE7943003)
    put(0x103C, 0xE1A01003)
    put(0x1040, _arm_bl(0x1040, 0x1200))

    put(0x1080, 0x3000 - 0x1010)  # PIC base literal
    put(0x1084, 0x2000 - 0x3000)  # route one relative to GOT
    put(0x1088, 0x00000000)       # handler one GOT slot offset
    put(0x108C, 0x2000 + len(route_one) - 0x3000)
    put(0x1090, 0x00000004)
    put(0x1100, 0xE12FFF1E)       # handler one
    put(0x1120, 0xE12FFF1E)       # handler two
    put(0x1200, 0xE12FFF1E)       # registrar

    dynstr = b"\x00formSetDeviceName\x00formGetDeviceDetail\x00"
    first_name = 1
    second_name = first_name + len(b"formSetDeviceName\x00")
    dynsym = b"\x00" * 16 + struct.pack(
        "<IIIBBH", first_name, 0x1100, 4, 0x12, 0, 2
    ) + struct.pack(
        "<IIIBBH", second_name, 0x1120, 4, 0x12, 0, 2
    )
    relocations = struct.pack("<II", 0x3000, (1 << 8) | 21) + struct.pack(
        "<II", 0x3004, (2 << 8) | 21
    )
    got = b"\x00" * 8

    names = ["", ".shstrtab", ".text", ".rodata", ".dynstr", ".dynsym", ".rel.dyn", ".got"]
    shstrtab = b"\x00"
    name_offsets = {"": 0}
    for name in names[1:]:
        name_offsets[name] = len(shstrtab)
        shstrtab += name.encode() + b"\x00"
    definitions = [
        (".shstrtab", 3, 0, 0, shstrtab, 0, 0, 1),
        (".text", 1, 0x6, 0x1000, bytes(text), 0, 0, 4),
        (".rodata", 1, 0x2, 0x2000, rodata, 0, 0, 1),
        (".dynstr", 3, 0x2, 0x2400, dynstr, 0, 0, 1),
        (".dynsym", 11, 0x2, 0x2500, dynsym, 4, 16, 4),
        (".rel.dyn", 9, 0x2, 0x2600, relocations, 5, 8, 4),
        (".got", 1, 0x3, 0x3000, got, 0, 4, 4),
    ]

    header_size = 52
    payload = bytearray(b"\x00" * header_size)
    section_rows = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for name, section_type, flags, address, data, link, entry_size, alignment in definitions:
        while len(payload) % max(1, alignment):
            payload.append(0)
        offset = len(payload)
        payload.extend(data)
        section_rows.append((
            name_offsets[name], section_type, flags, address, offset, len(data),
            link, 0, alignment, entry_size,
        ))
    while len(payload) % 4:
        payload.append(0)
    section_offset = len(payload)
    for row in section_rows:
        payload.extend(struct.pack("<IIIIIIIIII", *row))
    ident = b"\x7fELF" + bytes((1, 1, 1, 0)) + b"\x00" * 8
    payload[:header_size] = ident + struct.pack(
        "<HHIIIIIHHHHHH", 2, 40, 1, 0x1000, 0, section_offset, 0,
        header_size, 0, 0, 40, len(section_rows), 1,
    )
    return bytes(payload)


def _arm32_negative_literal_pic_fixture() -> bytes:
    payload = bytearray(_arm32_pic_fixture())
    section_table_offset = struct.unpack_from("<I", payload, 32)[0]
    text_offset = struct.unpack_from("<I", payload, section_table_offset + 2 * 40 + 16)[0]

    def put(address: int, value: int) -> None:
        struct.pack_into("<I", payload, text_offset + address - 0x1000, value & 0xFFFFFFFF)

    for address in range(0x100C, 0x1044, 4):
        put(address, 0)
    put(0x1280, 0xE51F3204)  # ldr r3, [pc, #-0x204] -> 0x1084
    put(0x1284, 0xE0843003)
    put(0x1288, 0xE1A00003)
    put(0x128C, 0xE51F320C)  # ldr r3, [pc, #-0x20c] -> 0x1088
    put(0x1290, 0xE7943003)
    put(0x1294, 0xE1A01003)
    put(0x1298, _arm_bl(0x1298, 0x1200))
    put(0x129C, 0xE51F3218)  # second independent pair
    put(0x12A0, 0xE0843003)
    put(0x12A4, 0xE1A00003)
    put(0x12A8, 0xE51F3220)
    put(0x12AC, 0xE7943003)
    put(0x12B0, 0xE1A01003)
    put(0x12B4, _arm_bl(0x12B4, 0x1200))
    return bytes(payload)


class ArmPicCallsiteContractTests(unittest.TestCase):
    def test_negative_pc_relative_literal_pool_proves_binding(self):
        content = _arm32_negative_literal_pic_fixture()
        source = _source("bin/httpd", content)

        result = discover_arm_pic_callsite_bindings(
            source, content,
            (NativeRouteAnchor("association:set-online-name", "SetOnlineDevName"),),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.bindings))
        self.assertEqual(0x1298, result.bindings[0].registration_address)
        self.assertEqual("formSetDeviceName", result.bindings[0].handler_symbol)

    def test_same_callsite_proves_route_and_handler_binding(self):
        content = _arm32_pic_fixture()
        source = _source("bin/httpd", content)
        anchor = NativeRouteAnchor("association:set-online-name", "SetOnlineDevName")

        result = discover_arm_pic_callsite_bindings(
            source, content, (anchor,), ArmPicCallsiteProfile(min_registrar_pairs=2)
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.bindings))
        binding = result.bindings[0]
        self.assertEqual(0x1024, binding.registration_address)
        self.assertEqual(0x1100, binding.handler_address)
        self.assertEqual("bin/httpd@0x00001100", binding.handler_identity)
        self.assertEqual("formSetDeviceName", binding.handler_symbol)
        self.assertEqual(0x1200, binding.registrar_address)
        self.assertEqual(2, binding.registrar_pair_count)
        self.assertEqual(
            {
                "mentions_endpoint", "establishes_pic_base",
                "resolves_handler_symbol", "registers_route", "binds_handler",
            },
            {atom.capability for atom in result.evidence_atoms},
        )
        self.assertTrue(all(replay_evidence(atom, source, content) for atom in result.evidence_atoms))

    def test_tampered_handler_relocation_proof_is_rejected(self):
        content = _arm32_pic_fixture()
        source = _source("bin/httpd", content)
        result = discover_arm_pic_callsite_bindings(
            source, content,
            (NativeRouteAnchor("association:set-online-name", "SetOnlineDevName"),),
        )
        with self.assertRaisesRegex(ValueError, "handler symbol proof is invalid"):
            replace(
                result,
                evidence_atoms=tuple(
                    replace(atom, object_value="bin/httpd@0x00001120")
                    if atom.capability == "resolves_handler_symbol" else atom
                    for atom in result.evidence_atoms
                ),
            )

    def test_tampered_handler_symbol_metadata_is_rejected(self):
        content = _arm32_pic_fixture()
        source = _source("bin/httpd", content)
        result = discover_arm_pic_callsite_bindings(
            source, content,
            (NativeRouteAnchor("association:set-online-name", "SetOnlineDevName"),),
        )
        with self.assertRaisesRegex(ValueError, "handler symbol proof is invalid"):
            replace(
                result,
                bindings=(replace(
                    result.bindings[0], handler_symbol="formUnexpectedHandler"
                ),),
            )

    def test_single_pair_does_not_infer_a_registrar(self):
        content = _arm32_pic_fixture().replace(
            struct.pack("<I", 0xE59F305C), b"\x00\x00\x00\x00", 1
        )
        result = discover_arm_pic_callsite_bindings(
            _source("bin/httpd", content), content,
            (NativeRouteAnchor("association:set-online-name", "SetOnlineDevName"),),
        )
        self.assertEqual((), result.bindings)
        self.assertEqual((), result.evidence_atoms)

    def test_duplicate_anchor_is_idempotent(self):
        content = _arm32_pic_fixture()
        anchor = NativeRouteAnchor("association:set-online-name", "SetOnlineDevName")
        result = discover_arm_pic_callsite_bindings(
            _source("bin/httpd", content), content, (anchor, anchor)
        )
        self.assertEqual(1, len(result.bindings))
        self.assertEqual(5, len(result.evidence_atoms))

    def test_wrong_relocation_or_argument_register_cannot_bind_handler(self):
        base = _arm32_pic_fixture()
        wrong_relocation = base.replace(
            struct.pack("<II", 0x3000, (1 << 8) | 21),
            struct.pack("<II", 0x3000, (1 << 8) | 22),
            1,
        )
        wrong_register = base.replace(
            struct.pack("<I", 0xE1A01003), struct.pack("<I", 0xE1A02003), 1
        )
        anchor = NativeRouteAnchor("association:set-online-name", "SetOnlineDevName")
        for content in (wrong_relocation, wrong_register):
            with self.subTest(content_sha256=hashlib.sha256(content).hexdigest()):
                result = discover_arm_pic_callsite_bindings(
                    _source("bin/httpd", content), content, (anchor,)
                )
                self.assertEqual((), result.bindings)

    def test_handler_symbol_must_belong_to_an_executable_section(self):
        content = _arm32_pic_fixture().replace(
            struct.pack("<IIIBBH", 1, 0x1100, 4, 0x12, 0, 2),
            struct.pack("<IIIBBH", 1, 0x1100, 4, 0x12, 0, 0),
            1,
        )
        result = discover_arm_pic_callsite_bindings(
            _source("bin/httpd", content), content,
            (NativeRouteAnchor("association:set-online-name", "SetOnlineDevName"),),
        )
        self.assertEqual((), result.bindings)

    def test_unresolved_pic_base_cannot_bind_route(self):
        content = _arm32_pic_fixture().replace(
            struct.pack("<I", 0x3000 - 0x1010),
            struct.pack("<I", 0x3004 - 0x1010),
            1,
        )
        result = discover_arm_pic_callsite_bindings(
            _source("bin/httpd", content), content,
            (NativeRouteAnchor("association:set-online-name", "SetOnlineDevName"),),
        )
        self.assertEqual((), result.bindings)

    def test_actual_ac9_callsite_closes_exact_route_and_handler_obligations(self):
        path = (
            Path(__file__).resolve().parents[2]
            / "iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root/bin/httpd"
        )
        if not path.exists():
            self.skipTest("local AC9 representative sample is unavailable")
        content = path.read_bytes()
        source = _source("bin/httpd", content)
        target_ref = "association:ac9-set-online-name"
        result = discover_arm_pic_callsite_bindings(
            source, content,
            (NativeRouteAnchor(target_ref, "SetOnlineDevName"),),
        )

        self.assertEqual(1, len(result.bindings))
        binding = result.bindings[0]
        self.assertEqual(0x42AEC, binding.registration_address)
        self.assertEqual(0x60EE8, binding.handler_address)
        self.assertIn("registrar@0x00017134", binding.source_construct)
        self.assertEqual(
            {
                "binary:bytes=874584-874600",
                "binary:bytes=237920-237928",
                "binary:bytes=25140-25148",
                "binary:bytes=240340-240368",
            },
            {atom.source_span.locator for atom in result.evidence_atoms},
        )
        obligations = tuple(
            SchedulerObligation(
                obligation_id="obligation:" + capability,
                target_ref=target_ref,
                required_capability=capability,
                reason="candidate evidence is insufficient",
                priority=90,
                candidate_analyzers=("native-deep",),
                status=ObligationStatus.OPEN,
            )
            for capability in ("registers_route", "binds_handler")
        )
        scheduled = run_obligation_scheduler(
            obligations, (native_deep_scheduler_analyzer(result),)
        )
        self.assertEqual(2, len(scheduled.resolved_obligations))
        self.assertEqual(0, len(scheduled.open_obligations))

    def test_catalog_handler_preserves_callsite_and_relocation_evidence(self):
        frontend_content = b'''var pageModel = R.pageModel({
          setUrl: "/goform/SetOnlineDevName"
        });'''
        frontend = discover_frontend_requests(
            _source("webroot/js/online.js", frontend_content), frontend_content
        )
        native_content = _arm32_pic_fixture()
        native_source = _source("bin/httpd", native_content)
        shallow = discover_native_hints(native_source, native_content)
        correlation = correlate_frontend_native((frontend,), (shallow,))
        self.assertEqual(1, len(correlation.associations))
        deep = discover_arm_pic_callsite_bindings(
            native_source, native_content,
            (NativeRouteAnchor(
                correlation.associations[0].association_id, "SetOnlineDevName"
            ),),
        )
        scheduler = run_obligation_scheduler(
            correlation.obligations, (native_deep_scheduler_analyzer(deep),)
        )
        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64, "2" * 64,
            (
                DiscoveryProducerBatch.frontend((frontend,), "webroot/**/*.js"),
                DiscoveryProducerBatch.native((shallow,), "bin/httpd"),
                DiscoveryProducerBatch.native_deep((deep,), "bin/httpd:callsite"),
            ), correlation, scheduler,
        ))

        handler = next(
            item for item in catalog.candidates
            if item.candidate_kind.value == "native_handler"
        )
        evidence = {atom.evidence_id: atom for atom in catalog.evidence_atoms}
        self.assertEqual(
            {"resolves_handler_symbol", "binds_handler"},
            {evidence[evidence_id].capability for evidence_id in handler.evidence_ids},
        )
        self.assertEqual(0, len(catalog.open_obligations))

    def test_catalog_preserves_two_routes_bound_to_the_same_handler(self):
        frontend_content = b'''$.post("/goform/SetOnlineDevName", {});
        $.post("/goform/GetDeviceDetail", {});'''
        frontend = discover_frontend_requests(
            _source("webroot/js/routes.js", frontend_content), frontend_content
        )
        second_route_delta = 0x2000 + len(b"SetOnlineDevName\x00") - 0x3000
        native_content = _arm32_pic_fixture().replace(
            struct.pack("<II", second_route_delta & 0xFFFFFFFF, 4),
            struct.pack("<II", second_route_delta & 0xFFFFFFFF, 0),
            1,
        )
        native_source = _source("bin/httpd", native_content)
        shallow = discover_native_hints(native_source, native_content)
        correlation = correlate_frontend_native((frontend,), (shallow,))
        native_by_id = {item.hint_id: item for item in shallow.hints}
        deep = discover_arm_pic_callsite_bindings(
            native_source, native_content,
            tuple(
                NativeRouteAnchor(
                    association.association_id,
                    native_by_id[association.native_hint_id].value,
                )
                for association in correlation.associations
            ),
        )
        scheduler = run_obligation_scheduler(
            correlation.obligations, (native_deep_scheduler_analyzer(deep),)
        )
        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64, "2" * 64,
            (
                DiscoveryProducerBatch.frontend((frontend,), "webroot/js/routes.js"),
                DiscoveryProducerBatch.native((shallow,), "bin/httpd"),
                DiscoveryProducerBatch.native_deep((deep,), "bin/httpd:callsite"),
            ), correlation, scheduler,
        ))
        handlers = [
            item for item in catalog.candidates
            if item.candidate_kind.value == "native_handler"
        ]
        self.assertEqual(2, len(handlers))
        self.assertEqual(2, len({item.candidate_id for item in handlers}))
        self.assertEqual(
            {"bin/httpd@0x00001100"},
            {item.canonical_identity for item in handlers},
        )

    def test_actual_ac9_online_list_closes_all_five_association_obligations(self):
        root = (
            Path(__file__).resolve().parents[2]
            / "iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root"
        )
        frontend_path = root / "webroot_ro/js/online_list.js"
        native_path = root / "bin/httpd"
        if not frontend_path.exists() or not native_path.exists():
            self.skipTest("local AC9 representative sample is unavailable")
        frontend_content = frontend_path.read_bytes()
        native_content = native_path.read_bytes()
        frontend = discover_frontend_requests(
            _source("webroot_ro/js/online_list.js", frontend_content), frontend_content
        )
        native_source = _source("bin/httpd", native_content)
        shallow = discover_native_hints(native_source, native_content)
        correlation = correlate_frontend_native((frontend,), (shallow,))
        native_by_id = {item.hint_id: item for item in shallow.hints}
        anchors = tuple(
            NativeRouteAnchor(
                association.association_id,
                native_by_id[association.native_hint_id].value,
            )
            for association in correlation.associations
        )

        deep = discover_arm_pic_callsite_bindings(
            native_source, native_content, anchors
        )
        scheduler = run_obligation_scheduler(
            correlation.obligations, (native_deep_scheduler_analyzer(deep),)
        )

        self.assertEqual(5, len(correlation.associations))
        self.assertEqual(5, len(deep.bindings))
        self.assertEqual(10, len(scheduler.resolved_obligations))
        self.assertEqual(0, len(scheduler.open_obligations))
        self.assertEqual(
            {
                "getOnlineList": ("formGetOnlineList", 0x5ECF4, 0x42788),
                "SetOnlineDevName": ("formSetDeviceName", 0x60EE8, 0x42AEC),
                "setBlackRule": ("formAddMacfilterRule", 0xC1BD8, 0x42B78),
                "delBlackRule": ("formDelMacfilterRule", 0xC3278, 0x42B94),
                "getBlackRuleList": ("formGetMacfilterRuleList", 0xC483C, 0x42BB0),
            },
            {
                item.route_token: (
                    item.handler_symbol, item.handler_address,
                    item.registration_address,
                )
                for item in deep.bindings
            },
        )
        self.assertEqual({164}, {item.registrar_pair_count for item in deep.bindings})


if __name__ == "__main__":
    unittest.main()
