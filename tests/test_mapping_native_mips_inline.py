import hashlib
import json
from dataclasses import replace
from pathlib import Path
import struct
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    FrontendAssetInput,
    MipsInlineRouteTableProfile,
    NativeRouteAnchor,
    ObligationStatus,
    SchedulerObligation,
    SourceArtifactEntry,
    discover_mips_inline_route_bindings,
    discover_frontend_asset_graph,
    native_deep_scheduler_analyzer,
    replay_evidence,
    run_obligation_scheduler,
)


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )


def _mips_inline_table_fixture(entries=None) -> bytes:
    text = b"\x00" * 0x200

    def entry(route: str, handler: int) -> bytes:
        encoded = route.encode("ascii")
        return encoded + b"\x00" * (64 - len(encoded)) + struct.pack("<I", handler)

    entries = entries or (("getInitCfg", 0x1100), ("setLanCfg", 0x1120))
    data = b"".join(entry(route, handler) for route, handler in entries)
    dynstr = b"\x00get_handle_t\x00"
    dynsym = b"\x00" * 16 + struct.pack(
        "<IIIBBH", 1, 0x3000, len(data), 0x11, 0, 3
    )
    names = ("", ".shstrtab", ".text", ".data", ".dynstr", ".dynsym")
    shstrtab = b"\x00"
    name_offsets = {"": 0}
    for name in names[1:]:
        name_offsets[name] = len(shstrtab)
        shstrtab += name.encode("ascii") + b"\x00"
    definitions = (
        (".shstrtab", 3, 0, 0, shstrtab, 0, 0, 1),
        (".text", 1, 0x6, 0x1000, text, 0, 0, 4),
        (".data", 1, 0x3, 0x3000, data, 0, 0, 4),
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
        "<HHIIIIIHHHHHH", 2, 8, 1, 0x1000, 0, section_offset, 0,
        header_size, 0, 0, 40, len(rows), 1,
    )
    return bytes(payload)


class MipsInlineRouteTableContractTests(unittest.TestCase):
    def test_documented_x5000r_dispatch_report_is_exactly_replayable(self):
        from scripts.build_x5000r_mips_dispatch_report import (
            X5000R_ROOT,
            build_summary,
        )

        if not X5000R_ROOT.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        documented = json.loads(Path(
            "docs/firmware-mapping/samples/m1-16-x5000r-mips-dispatch.json"
        ).read_text())

        replayed = build_summary(X5000R_ROOT)

        self.assertEqual(documented, replayed)
        self.assertEqual({
            "frontend_selector": 199,
            "native_registration": 138,
            "native_unique_route": 137,
            "bound_frontend_selector": 123,
            "binding_proof": 124,
            "frontend_only": 76,
            "native_only": 14,
        }, replayed["counts"])

    def test_exported_inline_table_proves_selector_handler_binding(self):
        content = _mips_inline_table_fixture()
        source = _source("www/cgi-bin/cstecgi.cgi", content)

        result = discover_mips_inline_route_bindings(
            source,
            content,
            (NativeRouteAnchor("operation:set-lan", "setLanCfg"),),
            MipsInlineRouteTableProfile(min_valid_entries=2),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.bindings))
        binding = result.bindings[0]
        self.assertEqual(0x3044, binding.registration_address)
        self.assertEqual(0x1120, binding.handler_address)
        self.assertEqual(
            "www/cgi-bin/cstecgi.cgi@0x00001120", binding.handler_identity
        )
        self.assertEqual(
            {
                "mentions_endpoint", "resolves_table_symbol",
                "registers_route", "binds_handler",
            },
            {atom.capability for atom in result.evidence_atoms},
        )
        self.assertTrue(all(
            replay_evidence(atom, source, content) for atom in result.evidence_atoms
        ))

    def test_invalid_entry_makes_coverage_partial_without_hiding_valid_binding(self):
        content = _mips_inline_table_fixture((
            ("getInitCfg", 0x1100),
            ("brokenCfg", 0x9000),
            ("setLanCfg", 0x1120),
        ))
        source = _source("www/cgi-bin/cstecgi.cgi", content)

        result = discover_mips_inline_route_bindings(
            source, content,
            (NativeRouteAnchor("operation:set-lan", "setLanCfg"),),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual(1, len(result.bindings))
        self.assertEqual(
            ["inline_table_entry_invalid"],
            [item.code for item in result.diagnostics],
        )

    def test_tampered_table_symbol_proof_is_rejected(self):
        content = _mips_inline_table_fixture()
        source = _source("www/cgi-bin/cstecgi.cgi", content)
        result = discover_mips_inline_route_bindings(
            source, content,
            (NativeRouteAnchor("operation:set-lan", "setLanCfg"),),
        )

        with self.assertRaisesRegex(ValueError, "table symbol proof is invalid"):
            replace(
                result,
                evidence_atoms=tuple(
                    replace(atom, object_value="other_handle_t@0x00003000:size=0x88")
                    if atom.capability == "resolves_table_symbol" else atom
                    for atom in result.evidence_atoms
                ),
            )

    def test_verified_inline_binding_closes_exact_scheduler_obligations(self):
        content = _mips_inline_table_fixture()
        source = _source("www/cgi-bin/cstecgi.cgi", content)
        target_ref = "operation:set-lan"
        result = discover_mips_inline_route_bindings(
            source, content,
            (NativeRouteAnchor(target_ref, "setLanCfg"),),
        )
        obligations = tuple(
            SchedulerObligation(
                "obligation:" + capability,
                target_ref,
                capability,
                "candidate evidence is insufficient",
                90,
                ("native-deep",),
                ObligationStatus.OPEN,
            )
            for capability in ("registers_route", "binds_handler")
        )

        scheduled = run_obligation_scheduler(
            obligations, (native_deep_scheduler_analyzer(result),)
        )

        self.assertEqual(2, len(scheduled.resolved_obligations))
        self.assertEqual(0, len(scheduled.open_obligations))

    def test_actual_x5000r_binds_static_frontend_selector_subset(self):
        from scripts.build_x5000r_frontend_asset_graph import PATHS, X5000R_ROOT

        binary_path = X5000R_ROOT / "www/cgi-bin/cstecgi.cgi"
        if not binary_path.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        assets = []
        for path in PATHS:
            content = (X5000R_ROOT / path).read_bytes()
            assets.append(FrontendAssetInput(_source(path, content), content))
        frontend = discover_frontend_asset_graph(tuple(assets))
        anchors = tuple(
            NativeRouteAnchor(parameter.request_candidate_id, parameter.literal_value)
            for result in frontend.results
            for parameter in result.parameters
            if parameter.is_operation_selector
            and parameter.source_construct == "shared-cgi.topicurl"
        )
        content = binary_path.read_bytes()
        source = _source("www/cgi-bin/cstecgi.cgi", content)

        result = discover_mips_inline_route_bindings(source, content, anchors)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(124, len(result.bindings))
        self.assertEqual(123, len({item.route_token for item in result.bindings}))
        self.assertEqual(496, len(result.evidence_atoms))
        self.assertEqual((), result.diagnostics)
        selected = {
            item.route_token: (item.registration_address, item.handler_address)
            for item in result.bindings
            if item.route_token in {
                "getInitCfg", "getSysStatusCfg", "getWanCfg",
                "setWanCfg", "setLanCfg",
            }
        }
        self.assertEqual({
            "getInitCfg": (0x4490A0, 0x415454),
            "getSysStatusCfg": (0x44916C, 0x4166E8),
            "getWanCfg": (0x449854, 0x40D080),
            "setWanCfg": (0x44A9A4, 0x4212CC),
            "setLanCfg": (0x44AA2C, 0x4209B8),
        }, selected)
        self.assertTrue(all(
            replay_evidence(atom, source, content) for atom in result.evidence_atoms
        ))


if __name__ == "__main__":
    unittest.main()
