import hashlib
import struct
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    DiscoveryCatalogInput,
    DiscoveryCandidateKind,
    DiscoveryProducerBatch,
    NativeCommandBindingStatus,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    discover_native_command_table_bindings,
)


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )


def _command_table_elf(handler_address: int = 0x1100) -> bytes:
    text = bytearray(b"\x00" * 0x200)
    struct.pack_into("<I", text, 0x100, 0xE12FFF1E)
    entry = bytearray(b"\x00" * 372)
    entry[:len(b"minidlna")] = b"minidlna"
    struct.pack_into("<III", entry, 100, 3, 10, 0)
    command = b"cfm post netctrl 51?op=6"
    entry[112:112 + len(command)] = command
    struct.pack_into("<I", entry, 368, handler_address)
    dynstr = b"\x00daemon_exe_info\x00"
    dynsym = b"\x00" * 16 + struct.pack(
        "<IIIBBH", 1, 0x3000, len(entry), 0x11, 0, 3
    )
    names = ("", ".shstrtab", ".text", ".data", ".dynstr", ".dynsym")
    shstrtab = b"\x00"
    name_offsets = {"": 0}
    for name in names[1:]:
        name_offsets[name] = len(shstrtab)
        shstrtab += name.encode("ascii") + b"\x00"
    definitions = (
        (".shstrtab", 3, 0, 0, shstrtab, 0, 0, 1),
        (".text", 1, 0x6, 0x1000, bytes(text), 0, 0, 4),
        (".data", 1, 0x3, 0x3000, bytes(entry), 0, 0, 4),
        (".dynstr", 3, 0x2, 0x4000, dynstr, 0, 0, 1),
        (".dynsym", 11, 0x2, 0x4100, dynsym, 4, 16, 4),
    )
    header_size = 52
    payload = bytearray(b"\x00" * header_size)
    rows = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    for name, kind, flags, address, value, link, entry_size, alignment in definitions:
        while len(payload) % alignment:
            payload.append(0)
        offset = len(payload)
        payload.extend(value)
        rows.append((
            name_offsets[name], kind, flags, address, offset, len(value),
            link, 0, alignment, entry_size,
        ))
    while len(payload) % 4:
        payload.append(0)
    section_offset = len(payload)
    for row in rows:
        payload.extend(struct.pack("<IIIIIIIIII", *row))
    ident = b"\x7fELF" + bytes((1, 1, 1, 0)) + b"\x00" * 8
    payload[:header_size] = ident + struct.pack(
        "<HHIIIIIHHHHHH", 2, 40, 1, 0x1000, 0, section_offset, 0,
        header_size, 0, 0, 40, len(rows), 1,
    )
    return bytes(payload)


class NativeCommandTableBindingContractTests(unittest.TestCase):
    def test_command_binding_is_queryable_as_catalog_candidate(self):
        content = _command_table_elf()
        result = discover_native_command_table_bindings(
            _source("bin/time_check", content), content
        )

        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            firmware_artifact_sha256="1" * 64,
            source_inventory_sha256="2" * 64,
            batches=(DiscoveryProducerBatch.native_command_binding(
                (result,), "native:command-table"
            ),),
        ))

        candidate = catalog.candidates[0]
        self.assertEqual(
            DiscoveryCandidateKind.NATIVE_COMMAND_BINDING,
            candidate.candidate_kind,
        )
        self.assertEqual(
            "bin/time_check|minidlna|handler=0x00001100",
            candidate.canonical_identity,
        )
        self.assertEqual(
            "cfm post netctrl 51?op=6",
            dict(candidate.attributes)["command"],
        )

    def test_symbol_profile_binds_process_command_and_executable_handler(self):
        content = _command_table_elf()

        result = discover_native_command_table_bindings(
            _source("bin/time_check", content), content
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.bindings))
        binding = result.bindings[0]
        self.assertEqual("minidlna", binding.process_name)
        self.assertEqual("cfm post netctrl 51?op=6", binding.command)
        self.assertEqual(0x1100, binding.handler_address)
        self.assertEqual("bin/time_check@0x00001100", binding.handler_identity)
        self.assertEqual(
            NativeCommandBindingStatus.TABLE_BOUND,
            binding.binding_status,
        )
        self.assertEqual(
            {
                "resolves_command_table_symbol",
                "names_managed_process",
                "declares_bound_command",
                "binds_command_handler",
            },
            {atom.capability for atom in result.evidence_atoms},
        )

    def test_nonexecutable_handler_pointer_is_rejected(self):
        content = _command_table_elf(handler_address=0x3000)

        result = discover_native_command_table_bindings(
            _source("bin/time_check", content), content
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual((), result.bindings)
        self.assertIn("handler_not_executable", result.diagnostics)


if __name__ == "__main__":
    unittest.main()
