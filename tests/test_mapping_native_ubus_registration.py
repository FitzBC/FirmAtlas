import hashlib
from pathlib import Path
import struct
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    SourceArtifactEntry,
    UbusArtifactInput,
    UbusBackendBindingStatus,
    UbusOperationReference,
    discover_native_ubus_registrations,
    discover_ubus_backend_graph,
    replay_evidence,
)


AC9_RPCD_ROOT = Path(
    "var/mapping-work/ac9-version-diff/extractions/openwrt-19.07.8/"
    "extractions/firmware.bin.extracted/0/partition_1.bin.extracted/0/"
    "squashfs-root/usr/lib/rpcd"
)


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        canonical_path=path,
        original_path=path,
        kind="file",
        size=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
    )


def _arm_branch(address: int, target: int) -> bytes:
    displacement = (target - address - 8) // 4
    return struct.pack("<I", 0xEA000000 | (displacement & 0x00FFFFFF))


def _sectionless_rpcd_elf(
    *, handler: int = 0x1200, registrar_symbol: str = "ubus_add_object"
) -> bytes:
    """Small sectionless ARM ELF modeling the OpenWrt rpcd plugin ABI."""

    content = bytearray(0x1400)
    text_offset, text_address = 0x100, 0x1000
    data_offset, data_address = 0x1000, 0x2000
    init_address, plt_address = 0x1100, 0x1080
    object_address, type_address = 0x2000, 0x2040
    methods_address, plugin_address = 0x2080, 0x20c0
    hash_address, dynsym_address = 0x1300, 0x1320
    dynstr_address, rel_address = 0x1380, 0x13c0
    dynamic_address, got_address = 0x2200, 0x20f0
    strings = {"file": 0x1240, "luci-rpc-file": 0x1248, "read": 0x1258}

    def put(address: int, value: bytes) -> None:
        if text_address <= address < text_address + 0x400:
            offset = text_offset + address - text_address
        else:
            offset = data_offset + address - data_address
        content[offset : offset + len(value)] = value

    # Standard ARM PLT entry, then plugin init loads &obj into r1 and tail-calls it.
    put(plt_address, struct.pack("<III", 0xE28FC600, 0xE28CCA12, 0xE5BCF000))
    literal_address = init_address + 12
    put(init_address, struct.pack("<II", 0xE59F1004, 0xE08F1001))
    put(init_address + 8, _arm_branch(init_address + 8, plt_address))
    put(literal_address, struct.pack("<I", object_address - (init_address + 12)))
    put(handler, struct.pack("<I", 0xE12FFF1E))
    for value, address in strings.items():
        put(address, value.encode() + b"\x00")

    # libubus 32-bit object/type/method layouts used by OpenWrt 19.07.
    put(object_address + 28, struct.pack("<I", strings["file"]))
    put(object_address + 40, struct.pack("<I", type_address))
    put(object_address + 52, struct.pack("<II", methods_address, 1))
    put(type_address, struct.pack("<IIII", strings["luci-rpc-file"], 0, methods_address, 1))
    put(methods_address, struct.pack("<IIIIII", strings["read"], handler, 0, 0, 0, 0))
    put(plugin_address, struct.pack("<III", 0, 0, init_address))

    dynstr = b"\x00" + registrar_symbol.encode() + b"\x00rpc_plugin\x00"
    registrar_name = 1
    plugin_name = 2 + len(registrar_symbol)
    put(dynstr_address, dynstr)
    put(dynsym_address, b"\x00" * 16)
    put(dynsym_address + 16, struct.pack("<IIIBBH", registrar_name, 0, 0, 0x12, 0, 0))
    put(dynsym_address + 32, struct.pack(
        "<IIIBBH", plugin_name, plugin_address, 12, 0x11, 0, 1
    ))
    put(hash_address, struct.pack("<IIIII", 1, 3, 1, 0, 0))
    put(rel_address, struct.pack("<II", got_address, (1 << 8) | 22))
    dynamic = (
        (4, hash_address), (5, dynstr_address), (6, dynsym_address),
        (10, len(dynstr)), (11, 16), (23, rel_address),
        (2, 8), (20, 17), (0, 0),
    )
    put(dynamic_address, b"".join(struct.pack("<II", *item) for item in dynamic))

    ident = b"\x7fELF" + bytes((1, 1, 1, 0)) + b"\x00" * 8
    header = ident + struct.pack(
        "<HHIIIIIHHHHHH", 3, 40, 1, init_address, 52, 0, 0,
        52, 32, 3, 0, 0, 0,
    )
    content[:52] = header
    content[52:84] = struct.pack(
        "<IIIIIIII", 1, text_offset, text_address, text_address, 0x400, 0x400, 5, 0x1000
    )
    content[84:116] = struct.pack(
        "<IIIIIIII", 1, data_offset, data_address, data_address, 0x400, 0x400, 6, 0x1000
    )
    content[116:148] = struct.pack(
        "<IIIIIIII", 2, data_offset + dynamic_address - data_address,
        dynamic_address, dynamic_address, len(dynamic) * 8, len(dynamic) * 8, 6, 4
    )
    return bytes(content)


class NativeUbusRegistrationContractTests(unittest.TestCase):
    def test_sectionless_rpcd_table_proves_object_method_and_handler(self):
        content = _sectionless_rpcd_elf()
        source = _source("usr/lib/rpcd/file.so", content)

        result = discover_native_ubus_registrations(source, content)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertTrue(result.registration_coverage_complete)
        self.assertEqual(1, len(result.objects))
        obj = result.objects[0]
        self.assertEqual("file", obj.object_name)
        self.assertEqual("luci-rpc-file", obj.type_name)
        self.assertEqual(1, len(obj.methods))
        self.assertEqual("read", obj.methods[0].method_name)
        self.assertEqual("usr/lib/rpcd/file.so@0x00001200", obj.methods[0].handler_identity)
        self.assertEqual(
            {
                "identifies_rpcd_plugin_init", "calls_ubus_add_object",
                "registers_ubus_object", "registers_ubus_method", "binds_ubus_handler",
            },
            {atom.capability for atom in result.evidence_atoms},
        )
        self.assertTrue(all(replay_evidence(atom, source, content) for atom in result.evidence_atoms))

    def test_method_string_without_ubus_registrar_call_is_not_registration(self):
        content = _sectionless_rpcd_elf(registrar_symbol="not_ubus_add_object")
        result = discover_native_ubus_registrations(
            _source("usr/lib/rpcd/file.so", content), content
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertFalse(result.registration_coverage_complete)
        self.assertEqual((), result.objects)
        self.assertEqual("ubus_registrar_not_verified", result.diagnostics[0].code)

    def test_non_executable_handler_fails_closed(self):
        content = _sectionless_rpcd_elf(handler=0x2080)
        result = discover_native_ubus_registrations(
            _source("usr/lib/rpcd/file.so", content), content
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual((), result.objects)
        self.assertEqual("ubus_method_handler_not_executable", result.diagnostics[0].code)

    def test_actual_ac9_file_plugin_recovers_all_seven_methods(self):
        path = AC9_RPCD_ROOT / "file.so"
        if not path.exists():
            self.skipTest("local AC9 OpenWrt sample is unavailable")
        content = path.read_bytes()

        result = discover_native_ubus_registrations(
            _source("usr/lib/rpcd/file.so", content), content
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual("file", result.objects[0].object_name)
        self.assertEqual(
            {"read", "write", "list", "stat", "md5", "remove", "exec"},
            {item.method_name for item in result.objects[0].methods},
        )

    def test_verified_registration_closes_backend_owner_obligation(self):
        content = _sectionless_rpcd_elf()
        source = _source("usr/lib/rpcd/file.so", content)
        registration = discover_native_ubus_registrations(source, content)
        operation = UbusOperationReference("frontend:file-read", "file", "read", ())

        graph = discover_ubus_backend_graph(
            (operation,),
            (UbusArtifactInput(source, content),),
            native_registrations=(registration,),
        )

        self.assertEqual(CoverageStatus.COMPLETED, graph.coverage_status)
        self.assertEqual((), graph.open_obligations)
        self.assertEqual(1, len(graph.bindings))
        self.assertEqual(
            UbusBackendBindingStatus.VERIFIED_NATIVE_REGISTRATION,
            graph.bindings[0].status,
        )
        self.assertEqual(
            "usr/lib/rpcd/file.so@0x00001200",
            graph.bindings[0].handler_identity,
        )
        self.assertIn(
            "usr/lib/rpcd/file.so@0x00001200",
            {atom.object_value for atom in graph.evidence_atoms},
        )

    def test_registration_from_different_bytes_cannot_enter_backend_scope(self):
        content = _sectionless_rpcd_elf()
        source = _source("usr/lib/rpcd/file.so", content)
        registration = discover_native_ubus_registrations(source, content)
        changed = content[:-1] + bytes((content[-1] ^ 1,))
        changed_source = _source(source.canonical_path, changed)

        with self.assertRaisesRegex(ValueError, "does not match backend artifact"):
            discover_ubus_backend_graph(
                (UbusOperationReference("frontend:file-read", "file", "read", ()),),
                (UbusArtifactInput(changed_source, changed),),
                native_registrations=(registration,),
            )


if __name__ == "__main__":
    unittest.main()
