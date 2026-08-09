import hashlib
import json
from pathlib import Path
import struct
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    NativeHintKind,
    NativePolicy,
    SourceArtifactEntry,
    discover_native_hints,
    replay_evidence,
)


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        canonical_path=path,
        original_path=path,
        kind="file",
        size=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
    )


def _elf32_fixture() -> bytes:
    shstrtab = b"\x00.shstrtab\x00.dynstr\x00.dynsym\x00.rodata\x00"
    dynstr = b"\x00formSetDeviceName\x00websFormHandler\x00getpid\x00"
    dynsym = b"\x00" * 16
    dynsym += struct.pack("<IIIBBH", 1, 0x1000, 8, 0x12, 0, 4)
    dynsym += struct.pack("<IIIBBH", 19, 0x2000, 8, 0x12, 0, 4)
    rodata = (
        b"GetStaticRouteCfg\x00SetStaticRouteCfg\x00"
        b"SetOnlineDevName\x00/webroot\x00httpd listen ip = %s port = %d\x00"
    )

    header_size = 52
    cursor = header_size
    offsets = []
    payload = bytearray(b"\x00" * header_size)
    for value in (shstrtab, dynstr, dynsym, rodata):
        while len(payload) % 4:
            payload.append(0)
        offsets.append(len(payload))
        payload.extend(value)
    while len(payload) % 4:
        payload.append(0)
    section_offset = len(payload)
    sections = [struct.pack("<IIIIIIIIII", *([0] * 10))]
    sections.append(
        struct.pack("<IIIIIIIIII", 1, 3, 0, 0, offsets[0], len(shstrtab), 0, 0, 1, 0)
    )
    sections.append(
        struct.pack("<IIIIIIIIII", 11, 3, 0, 0, offsets[1], len(dynstr), 0, 0, 1, 0)
    )
    sections.append(
        struct.pack("<IIIIIIIIII", 19, 11, 0, 0, offsets[2], len(dynsym), 2, 1, 4, 16)
    )
    sections.append(
        struct.pack("<IIIIIIIIII", 27, 1, 2, 0, offsets[3], len(rodata), 0, 0, 1, 0)
    )
    for section in sections:
        payload.extend(section)

    ident = b"\x7fELF" + bytes((1, 1, 1, 0)) + b"\x00" * 8
    header = ident + struct.pack(
        "<HHIIIIIHHHHHH",
        2,
        40,
        1,
        0,
        0,
        section_offset,
        0,
        header_size,
        0,
        0,
        40,
        len(sections),
        1,
    )
    payload[:header_size] = header
    return bytes(payload)


def _elf64_big_endian_fixture() -> bytes:
    shstrtab = b"\x00.shstrtab\x00.dynstr\x00.dynsym\x00.rodata\x00"
    dynstr = b"\x00formApplyConfig\x00"
    dynsym = b"\x00" * 24
    dynsym += struct.pack(">IBBHQQ", 1, 0x12, 0, 4, 0x1000, 8)
    rodata = b"SetApplyConfig\x00"
    header_size = 64
    payload = bytearray(b"\x00" * header_size)
    offsets = []
    for value in (shstrtab, dynstr, dynsym, rodata):
        while len(payload) % 8:
            payload.append(0)
        offsets.append(len(payload))
        payload.extend(value)
    while len(payload) % 8:
        payload.append(0)
    section_offset = len(payload)
    sections = [struct.pack(">IIQQQQIIQQ", *([0] * 10))]
    sections.append(
        struct.pack(">IIQQQQIIQQ", 1, 3, 0, 0, offsets[0], len(shstrtab), 0, 0, 1, 0)
    )
    sections.append(
        struct.pack(">IIQQQQIIQQ", 11, 3, 0, 0, offsets[1], len(dynstr), 0, 0, 1, 0)
    )
    sections.append(
        struct.pack(">IIQQQQIIQQ", 19, 11, 0, 0, offsets[2], len(dynsym), 2, 1, 8, 24)
    )
    sections.append(
        struct.pack(">IIQQQQIIQQ", 27, 1, 2, 0, offsets[3], len(rodata), 0, 0, 1, 0)
    )
    for section in sections:
        payload.extend(section)
    ident = b"\x7fELF" + bytes((2, 2, 1, 0)) + b"\x00" * 8
    header = ident + struct.pack(
        ">HHIQQQIHHHHHH",
        2,
        183,
        1,
        0,
        0,
        section_offset,
        0,
        header_size,
        0,
        0,
        64,
        len(sections),
        1,
    )
    payload[:header_size] = header
    return bytes(payload)


class NativeShallowProducerContractTests(unittest.TestCase):
    def test_sectionless_elf_keeps_metadata_and_printable_hint_coverage(self):
        ident = b"\x7fELF" + bytes((1, 1, 1, 0)) + b"\x00" * 8
        header = ident + struct.pack(
            "<HHIIIIIHHHHHH",
            2, 40, 1, 0, 0, 0, 0, 52, 0, 0, 0, 0, 0,
        )
        content = header + b"\x00SetOnlineDevName\x00"

        result = discover_native_hints(_source("usr/sbin/uhttpd", content), content)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual("elf", result.detected_format)
        self.assertEqual("ARM", result.machine)
        self.assertEqual(
            {"SetOnlineDevName"}, {item.value for item in result.hints}
        )

    def test_elf_strings_and_dynamic_symbols_are_separate_hint_kinds(self):
        content = _elf32_fixture()
        source = _source("bin/httpd", content)

        result = discover_native_hints(source, content)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual("elf", result.detected_format)
        self.assertEqual(32, result.bitness)
        self.assertEqual("little", result.endianness)
        self.assertEqual("ARM", result.machine)
        self.assertEqual(
            {
                (NativeHintKind.ROUTE_TOKEN, "GetStaticRouteCfg"),
                (NativeHintKind.ROUTE_TOKEN, "SetStaticRouteCfg"),
                (NativeHintKind.ROUTE_TOKEN, "SetOnlineDevName"),
                (NativeHintKind.SERVER_HINT, "/webroot"),
                (NativeHintKind.SERVER_HINT, "httpd listen ip = %s port = %d"),
                (NativeHintKind.SYMBOL, "formSetDeviceName"),
                (NativeHintKind.SYMBOL, "websFormHandler"),
            },
            {(item.kind, item.value) for item in result.hints},
        )
        self.assertNotIn("getpid", {item.value for item in result.hints})
        self.assertEqual(
            {"mentions_endpoint", "server_hint", "declares_symbol"},
            {item.capability for item in result.evidence_atoms},
        )
        self.assertEqual(
            {item.evidence_id for item in result.evidence_atoms},
            {
                evidence_id
                for hint in result.hints
                for evidence_id in hint.evidence_ids
            },
        )
        for atom in result.evidence_atoms:
            self.assertTrue(replay_evidence(atom, source, content))
        self.assertEqual(
            "firmatlas.mapping.native-result/v1alpha1",
            result.to_dict()["schema_version"],
        )
        self.assertIsInstance(json.dumps(result.to_dict()), str)

    def test_elf64_big_endian_metadata_and_symbols_are_supported(self):
        content = _elf64_big_endian_fixture()

        result = discover_native_hints(_source("bin/service", content), content)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(64, result.bitness)
        self.assertEqual("big", result.endianness)
        self.assertEqual("AArch64", result.machine)
        self.assertEqual(
            {
                (NativeHintKind.ROUTE_TOKEN, "SetApplyConfig"),
                (NativeHintKind.SYMBOL, "formApplyConfig"),
            },
            {(item.kind, item.value) for item in result.hints},
        )

    def test_duplicate_string_occurrences_merge_hint_but_keep_evidence(self):
        content = _elf32_fixture() + b"SetOnlineDevName\x00"
        source = _source("bin/httpd", content)

        result = discover_native_hints(source, content)

        hint = next(item for item in result.hints if item.value == "SetOnlineDevName")
        self.assertEqual(2, len(hint.evidence_ids))

    def test_unrelated_printable_strings_are_not_promoted_to_route_hints(self):
        content = _elf32_fixture().replace(
            b"GetStaticRouteCfg\x00", b"ordinary_message!\x00"
        )

        result = discover_native_hints(_source("bin/httpd", content), content)

        self.assertNotIn(
            "ordinary_message!", {item.value for item in result.hints}
        )

    def test_non_elf_binary_is_explicitly_unsupported(self):
        content = b"SetOnlineDevName\x00formSetDeviceName\x00"

        result = discover_native_hints(_source("bin/blob", content), content)

        self.assertEqual(CoverageStatus.UNSUPPORTED, result.coverage_status)
        self.assertIsNone(result.detected_format)
        self.assertEqual((), result.hints)
        self.assertEqual("unsupported_binary_format", result.diagnostics[0].code)

    def test_malformed_elf_is_failed_not_an_empty_success(self):
        content = b"\x7fELF\x01\x01" + b"\x00" * 20

        result = discover_native_hints(_source("bin/httpd", content), content)

        self.assertEqual(CoverageStatus.FAILED, result.coverage_status)
        self.assertEqual("elf", result.detected_format)
        self.assertEqual("malformed_elf", result.diagnostics[0].code)

    def test_source_and_hint_budgets_are_explicit(self):
        content = _elf32_fixture()
        source = _source("bin/httpd", content)

        skipped = discover_native_hints(
            source, content, NativePolicy(max_source_bytes=16)
        )
        partial = discover_native_hints(
            source, content, NativePolicy(max_hints=2)
        )

        self.assertEqual(CoverageStatus.SKIPPED_BY_POLICY, skipped.coverage_status)
        self.assertEqual(CoverageStatus.PARTIAL, partial.coverage_status)
        self.assertEqual(2, len(partial.hints))
        self.assertEqual("hint_budget_exceeded", partial.diagnostics[0].code)

    def test_actual_ac9_httpd_contains_frontend_correlatable_hints(self):
        repository = Path(__file__).resolve().parents[1]
        path = (
            repository.parent
            / "iot_seedintelligentanalysis"
            / "_tenda_ac9.zip.extracted"
            / "squashfs-root/bin/httpd"
        )
        if not path.exists():
            self.skipTest("local AC9 representative sample is unavailable")
        content = path.read_bytes()
        source = _source("bin/httpd", content)

        result = discover_native_hints(source, content)

        values = {item.value for item in result.hints}
        self.assertLessEqual(
            {
                "GetStaticRouteCfg",
                "SetStaticRouteCfg",
                "SetOnlineDevName",
                "getOnlineList",
                "setBlackRule",
                "delBlackRule",
                "formGetRouteStatic",
                "fromSetRouteStatic",
                "formSetDeviceName",
                "/webroot",
            },
            values,
        )
        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        for atom in result.evidence_atoms:
            self.assertTrue(replay_evidence(atom, source, content))


if __name__ == "__main__":
    unittest.main()
