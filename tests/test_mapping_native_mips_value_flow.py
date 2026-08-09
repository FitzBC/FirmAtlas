import hashlib
import json
from pathlib import Path
import struct
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    MipsHandlerValueFlowPolicy,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    discover_mips_handler_value_flows,
    replay_evidence,
)


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )


def _i(op: int, rs: int, rt: int, immediate: int) -> int:
    return (op << 26) | (rs << 21) | (rt << 16) | (immediate & 0xFFFF)


def _r(rs: int, rt: int, rd: int, function: int) -> int:
    return (rs << 21) | (rt << 16) | (rd << 11) | function


def _mips_value_flow_fixture() -> bytes:
    zero, v0, a0, a1, a2, s0, s1, t9, gp, ra = 0, 2, 4, 5, 6, 16, 17, 25, 28, 31
    gp_value = 0xAFF0
    getter_slot = 0x300C
    setter_slot = 0x3010
    words = (
        _i(0x0F, zero, gp, 1),
        _i(0x09, gp, gp, -0x5010),
        _r(a0, zero, s0, 0x21),
        _r(s0, zero, a0, 0x21),
        _i(0x0F, zero, a1, 0),
        _i(0x09, a1, a1, 0x2000),
        _i(0x0F, zero, a2, 0),
        _i(0x09, a2, a2, 0x2012),
        _i(0x23, gp, t9, getter_slot - gp_value),
        _r(t9, zero, ra, 0x09),
        0,
        _r(v0, zero, s1, 0x21),
        _i(0x0F, zero, a0, 0),
        _i(0x09, a0, a0, 0x2006),
        _r(s1, zero, a1, 0x21),
        _i(0x23, gp, t9, setter_slot - gp_value),
        _r(t9, zero, ra, 0x09),
        0,
        _r(ra, zero, zero, 0x08),
        0,
    )
    text = b"".join(struct.pack("<I", word) for word in words) + b"\x00" * 0x100
    rodata = b"lanIp\x00lan_ipaddr\x00\x00"
    got = struct.pack("<IIIII", 0, 0, 0, 0x1100, 0x1200)
    dynamic = b"".join(struct.pack("<II", tag, value) for tag, value in (
        (3, 0x3000),
        (0x7000000A, 4),
        (0x70000011, 3),
        (0x70000013, 2),
        (0, 0),
    ))
    dynstr = b"\x00websGetVar\x00nvram_set\x00"
    dynsym = b"\x00" * 16
    dynsym += struct.pack("<IIIBBH", 1, 0x1100, 4, 0x12, 0, 2)
    dynsym += struct.pack("<IIIBBH", 12, 0x1200, 0, 0x12, 0, 0)

    names = ("", ".shstrtab", ".text", ".rodata", ".got", ".dynamic", ".dynstr", ".dynsym")
    shstrtab = b"\x00"
    name_offsets = {"": 0}
    for name in names[1:]:
        name_offsets[name] = len(shstrtab)
        shstrtab += name.encode("ascii") + b"\x00"
    definitions = (
        (".shstrtab", 3, 0, 0, shstrtab, 0, 0, 1),
        (".text", 1, 0x6, 0x1000, text, 0, 0, 4),
        (".rodata", 1, 0x2, 0x2000, rodata, 0, 0, 1),
        (".got", 1, 0x3, 0x3000, got, 0, 4, 4),
        (".dynamic", 6, 0x3, 0x4000, dynamic, 0, 8, 4),
        (".dynstr", 3, 0x2, 0x5000, dynstr, 0, 0, 1),
        (".dynsym", 11, 0x2, 0x5100, dynsym, 6, 16, 4),
    )
    header_size = 52
    payload = bytearray(b"\x00" * header_size)
    rows = [(0,) * 10]
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


class MipsHandlerValueFlowContractTests(unittest.TestCase):
    def test_straight_line_getter_to_state_setter_is_replayable(self):
        content = _mips_value_flow_fixture()
        source = _source("www/cgi-bin/cstecgi.cgi", content)

        result = discover_mips_handler_value_flows(source, content, 0x1000)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual("jr_ra", result.boundary_reason)
        self.assertEqual(1, len(result.flows))
        flow = result.flows[0]
        self.assertEqual("lanIp", flow.parameter_name)
        self.assertEqual("lan_ipaddr", flow.state_key)
        self.assertEqual(0x1024, flow.getter_callsite)
        self.assertEqual(0x1040, flow.setter_callsite)
        self.assertEqual(5, len(flow.evidence_ids))
        atoms = {atom.evidence_id: atom for atom in result.evidence_atoms}
        self.assertEqual(set(flow.evidence_ids), set(atoms))
        for evidence_id in flow.evidence_ids:
            self.assertTrue(replay_evidence(atoms[evidence_id], source, content))

    def test_source_mismatch_fails_closed(self):
        content = _mips_value_flow_fixture()
        source = _source("www/cgi-bin/cstecgi.cgi", content)

        result = discover_mips_handler_value_flows(source, content + b"x", 0x1000)

        self.assertEqual(CoverageStatus.FAILED, result.coverage_status)
        self.assertEqual("source_mismatch", result.diagnostics[0].code)
        self.assertEqual((), result.flows)

    def test_validated_flow_is_published_as_supported_catalog_candidate(self):
        content = _mips_value_flow_fixture()
        source = _source("www/cgi-bin/cstecgi.cgi", content)
        value_flow = discover_mips_handler_value_flows(source, content, 0x1000)

        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64,
            "2" * 64,
            (DiscoveryProducerBatch.native_value_flow(
                (value_flow,), "www/cgi-bin/cstecgi.cgi:setLanCfg"
            ),),
        ))

        self.assertEqual(1, len(catalog.candidates))
        candidate = catalog.candidates[0]
        self.assertEqual("native_parameter_state_flow", candidate.candidate_kind.value)
        self.assertEqual("supported", candidate.claim_status.value)
        self.assertEqual("lanIp->lan_ipaddr", candidate.canonical_identity)
        self.assertEqual({
            "handler_identity": "www/cgi-bin/cstecgi.cgi@0x00001000",
            "parameter_name": "lanIp",
            "state_key": "lan_ipaddr",
            "getter_symbol": "websGetVar",
            "setter_symbol": "nvram_set",
            "getter_callsite": "0x1024",
            "setter_callsite": "0x1040",
        }, dict(candidate.attributes))
        self.assertEqual(5, len(catalog.evidence_atoms))

    def test_instruction_budget_is_partial_and_publishes_no_incomplete_flow(self):
        content = _mips_value_flow_fixture()
        source = _source("www/cgi-bin/cstecgi.cgi", content)

        result = discover_mips_handler_value_flows(
            source, content, 0x1000,
            policy=MipsHandlerValueFlowPolicy(max_instructions=10),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual("instruction_budget", result.boundary_reason)
        self.assertEqual((), result.flows)

    def test_unsupported_register_transform_stops_before_false_flow(self):
        content = bytearray(_mips_value_flow_fixture())
        text_offset = content.find(struct.pack("<I", _i(0x0F, 0, 28, 1)))
        self.assertGreaterEqual(text_offset, 0)
        # Replace the state-key LUI with xor s1,s1,s1. The narrow Profile must
        # not guess how an unsupported transform changes provenance.
        content[text_offset + 12 * 4:text_offset + 13 * 4] = struct.pack(
            "<I", _r(17, 17, 17, 0x26)
        )
        content = bytes(content)
        source = _source("www/cgi-bin/cstecgi.cgi", content)

        result = discover_mips_handler_value_flows(source, content, 0x1000)

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual("unsupported_instruction", result.boundary_reason)
        self.assertEqual(0x1030, result.boundary_address)
        self.assertEqual((), result.flows)

    def test_documented_x5000r_value_flow_report_is_exactly_replayable(self):
        from scripts.build_x5000r_mips_value_flow_report import X5000R_ROOT, build_summary

        if not X5000R_ROOT.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        documented = json.loads(Path(
            "docs/firmware-mapping/samples/m1-17-x5000r-mips-value-flow.json"
        ).read_text())

        replayed = build_summary(X5000R_ROOT)

        self.assertEqual(documented, replayed)
        self.assertEqual(2, replayed["counts"]["validated_parameter_state_flows"])
        self.assertEqual([
            ["lanIp", "lan_ipaddr"],
            ["lanNetmask", "lan_netmask"],
        ], replayed["validated_pairs"])


if __name__ == "__main__":
    unittest.main()
