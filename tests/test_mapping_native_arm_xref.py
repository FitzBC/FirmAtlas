import hashlib
import struct
import unittest

from firmatlas.mapping import (
    ArmLiteralAnchor,
    ArmFunctionTarget,
    CoverageStatus,
    DiscoveryCatalogInput,
    DiscoveryCandidateKind,
    DiscoveryProducerBatch,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    discover_arm_literal_xrefs,
    discover_arm_function_literal_xrefs,
)


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )


def _arm_pic_literal_elf() -> bytes:
    shstrtab = b"\x00.shstrtab\x00.text\x00.rodata\x00.got\x00"
    text = struct.pack(
        "<10I",
        0xE92D4010,  # push {r4, lr}
        0xE59F4014,  # ldr r4, [pc, #20] -> PIC delta
        0xE08F4004,  # add r4, pc, r4 -> GOT
        0xE59F0010,  # ldr r0, [pc, #16] -> literal delta
        0xE0840000,  # add r0, r4, r0 -> anchor
        0xE8BD8010,  # pop {r4, pc}
        0xE1A00000,
        0xE1A00000,
        0x00001FF0,  # 0x1010 + 0x1ff0 = GOT 0x3000
        0xFFFFF000,  # GOT 0x3000 - 0x1000 = rodata 0x2000
    )
    rodata = b"/var/etc/upan\x00unreferenced\x00"
    got = b"\x00" * 16
    header_size = 52
    payload = bytearray(b"\x00" * header_size)
    offsets = []
    for value in (shstrtab, text, rodata, got):
        while len(payload) % 4:
            payload.append(0)
        offsets.append(len(payload))
        payload.extend(value)
    while len(payload) % 4:
        payload.append(0)
    section_offset = len(payload)
    sections = [struct.pack("<IIIIIIIIII", *([0] * 10))]
    sections.append(struct.pack(
        "<IIIIIIIIII", 1, 3, 0, 0, offsets[0], len(shstrtab), 0, 0, 1, 0,
    ))
    sections.append(struct.pack(
        "<IIIIIIIIII", 11, 1, 0x6, 0x1000, offsets[1], len(text), 0, 0, 4, 0,
    ))
    sections.append(struct.pack(
        "<IIIIIIIIII", 17, 1, 0x2, 0x2000, offsets[2], len(rodata), 0, 0, 1, 0,
    ))
    sections.append(struct.pack(
        "<IIIIIIIIII", 25, 1, 0x3, 0x3000, offsets[3], len(got), 0, 0, 4, 0,
    ))
    for section in sections:
        payload.extend(section)
    ident = b"\x7fELF" + bytes((1, 1, 1, 0)) + b"\x00" * 8
    payload[:header_size] = ident + struct.pack(
        "<HHIIIIIHHHHHH", 2, 40, 1, 0x1000, 0, section_offset, 0,
        header_size, 0, 0, 40, len(sections), 1,
    )
    return bytes(payload)


class NativeArmLiteralXrefContractTests(unittest.TestCase):
    def test_bound_function_discovers_only_literals_it_references(self):
        content = _arm_pic_literal_elf()

        result = discover_arm_function_literal_xrefs(
            _source("bin/time_check", content),
            content,
            (ArmFunctionTarget("binding:daemon", 0x1000),),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(["/var/etc/upan"], [item.literal_value for item in result.xrefs])
        self.assertEqual("binding:daemon", result.xrefs[0].target_ref)

    def test_function_discovery_preserves_source_mismatch_failure(self):
        content = _arm_pic_literal_elf()
        source = SourceArtifactEntry(
            "bin/time_check", "bin/time_check", "file", len(content), "0" * 64
        )

        result = discover_arm_function_literal_xrefs(
            source, content, (ArmFunctionTarget("binding:daemon", 0x1000),)
        )

        self.assertEqual(CoverageStatus.FAILED, result.coverage_status)
        self.assertIn("source_mismatch", result.diagnostics)

    def test_literal_xref_is_queryable_as_catalog_candidate(self):
        content = _arm_pic_literal_elf()
        result = discover_arm_literal_xrefs(
            _source("bin/time_check", content), content,
            (ArmLiteralAnchor("clue:media-mount", "/var/etc/upan"),),
        )

        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            firmware_artifact_sha256="1" * 64,
            source_inventory_sha256="2" * 64,
            batches=(DiscoveryProducerBatch.arm_literal_xref(
                (result,), "native:literal-xref"
            ),),
        ))

        candidate = catalog.candidates[0]
        self.assertEqual(
            DiscoveryCandidateKind.ARM_LITERAL_XREF,
            candidate.candidate_kind,
        )
        self.assertEqual(
            "bin/time_check@0x00001000|/var/etc/upan",
            candidate.canonical_identity,
        )
        self.assertEqual(
            "0x0000100c", dict(candidate.attributes)["instruction_address"]
        )

    def test_pic_got_literal_xref_publishes_code_and_function_evidence(self):
        content = _arm_pic_literal_elf()
        source = _source("bin/time_check", content)

        result = discover_arm_literal_xrefs(
            source,
            content,
            (ArmLiteralAnchor("clue:media-mount", "/var/etc/upan"),),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.xrefs))
        xref = result.xrefs[0]
        self.assertEqual(0x1000, xref.function_start_address)
        self.assertEqual(0x100C, xref.instruction_address)
        self.assertEqual(0x2000, xref.literal_address)
        self.assertEqual("arm32.pic-got-literal", xref.source_construct)
        self.assertEqual(
            {
                "mentions_literal",
                "establishes_pic_base",
                "references_literal",
                "bounds_candidate_function",
            },
            {atom.capability for atom in result.evidence_atoms},
        )

    def test_unreferenced_literal_does_not_create_an_xref(self):
        content = _arm_pic_literal_elf()

        result = discover_arm_literal_xrefs(
            _source("bin/time_check", content),
            content,
            (ArmLiteralAnchor("clue:unused", "unreferenced"),),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual((), result.xrefs)


if __name__ == "__main__":
    unittest.main()
