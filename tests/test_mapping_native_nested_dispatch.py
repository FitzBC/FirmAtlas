import hashlib
from dataclasses import replace
import json
from pathlib import Path
import struct
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    MipsNestedDispatchAnchor,
    MipsNestedDispatchPolicy,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    discover_mips_cgi_nested_dispatch,
    replay_evidence,
)


X5000R_ROOT = Path(
    "var/mapping-work/x5000r-v9.1.0u.6118/extractions/"
    "firmware.bin.extracted/1004C/C8343R-6118.bin.extracted/184C70/"
    "squashfs-root"
)


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )


class MipsNestedDispatchContractTests(unittest.TestCase):
    def test_documented_x5000r_nested_dispatch_is_exactly_replayable(self):
        from scripts.build_x5000r_nested_dispatch_report import build_summary

        if not X5000R_ROOT.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        documented = json.loads(Path(
            "docs/firmware-mapping/samples/"
            "m1-20-x5000r-nested-dispatch.json"
        ).read_text(encoding="utf-8"))

        self.assertEqual(documented, build_summary(X5000R_ROOT))

    def test_actual_x5000r_proves_upload_mode_to_set_handler_path(self):
        binary_path = X5000R_ROOT / "www/cgi-bin/cstecgi.cgi"
        if not binary_path.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        content = binary_path.read_bytes()
        source = _source("www/cgi-bin/cstecgi.cgi", content)

        result = discover_mips_cgi_nested_dispatch(
            source,
            content,
            (MipsNestedDispatchAnchor(
                "frontend-request:set-upload-setting",
                "action",
                "upload",
                "setting",
                "setUploadSetting",
            ),),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.paths))
        path = result.paths[0]
        self.assertEqual("action=upload", path.transport_selector)
        self.assertEqual("setting/setUploadSetting", path.nested_selector)
        self.assertEqual("setUploadSetting", path.normalized_operation)
        self.assertEqual("set_handle_t", path.dispatch_table_symbol)
        self.assertEqual(0x0042E390, path.dispatcher_address)
        self.assertEqual(0x0042E5A8, path.transport_match_callsite)
        self.assertEqual(0x0042E648, path.selector_extract_callsite)
        self.assertEqual(0x0042E660, path.upload_parse_callsite)
        self.assertEqual(0x0042E7D0, path.suffix_normalization_address)
        self.assertEqual(0x0044A124, path.registration_address)
        self.assertEqual(0x0042BF14, path.handler_address)
        self.assertEqual(6, len(path.evidence_ids))
        self.assertEqual({
            "selects_transport_mode",
            "parses_upload_body",
            "constructs_dispatch_payload",
            "normalizes_operation_suffix",
            "selects_dispatch_table",
            "binds_handler",
        }, {atom.capability for atom in result.evidence_atoms})
        self.assertTrue(all(
            replay_evidence(atom, source, content)
            for atom in result.evidence_atoms
        ))

    def test_validated_path_is_published_as_supported_catalog_candidate(self):
        from scripts.build_x5000r_expanded_frontend_report import build_analysis

        binary_path = X5000R_ROOT / "www/cgi-bin/cstecgi.cgi"
        if not binary_path.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        content = binary_path.read_bytes()
        source = _source("www/cgi-bin/cstecgi.cgi", content)
        _, frontend, _, _, _, _ = build_analysis(X5000R_ROOT)
        target_ref = next(
            parameter.request_candidate_id
            for frontend_result in frontend.results
            for parameter in frontend_result.parameters
            if parameter.literal_value == "setUploadSetting"
        )
        result = discover_mips_cgi_nested_dispatch(
            source,
            content,
            (MipsNestedDispatchAnchor(
                target_ref, "action", "upload", "setting", "setUploadSetting"
            ),),
        )

        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64,
            "2" * 64,
            (
                DiscoveryProducerBatch.frontend(
                    frontend.results, "X5000R:expanded-frontend-scope/v1"
                ),
                DiscoveryProducerBatch.native_nested_dispatch(
                    (result,), "www/cgi-bin/cstecgi.cgi:main"
                ),
            ),
        ))

        candidate = next(
            item for item in catalog.candidates
            if item.candidate_kind.value == "native_nested_dispatch"
        )
        self.assertEqual("native_nested_dispatch", candidate.candidate_kind.value)
        self.assertEqual("supported", candidate.claim_status.value)
        self.assertEqual(
            "action=upload -> setting/setUploadSetting -> set_handle_t",
            candidate.canonical_identity,
        )
        self.assertEqual({
            "target_ref": target_ref,
            "normalized_operation": "setUploadSetting",
            "dispatcher_identity": "www/cgi-bin/cstecgi.cgi@0x0042e390",
            "handler_identity": "www/cgi-bin/cstecgi.cgi@0x0042bf14",
            "registration_address": "0x44a124",
            "transport_match_callsite": "0x42e5a8",
            "selector_extract_callsite": "0x42e648",
            "upload_parse_callsite": "0x42e660",
            "suffix_normalization_address": "0x42e7d0",
        }, dict(candidate.attributes))
        self.assertEqual(6, len(candidate.evidence_ids))

    def test_second_query_segment_must_be_the_selector_source(self):
        binary_path = X5000R_ROOT / "www/cgi-bin/cstecgi.cgi"
        if not binary_path.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        content = bytearray(binary_path.read_bytes())
        selector_index_instruction_offset = 0x2E630
        self.assertEqual(
            struct.pack("<I", 0x24040001),
            content[
                selector_index_instruction_offset:
                selector_index_instruction_offset + 4
            ],
        )
        content[
            selector_index_instruction_offset:selector_index_instruction_offset + 4
        ] = struct.pack("<I", 0x24040002)
        content = bytes(content)
        source = _source("www/cgi-bin/cstecgi.cgi", content)

        result = discover_mips_cgi_nested_dispatch(
            source,
            content,
            (MipsNestedDispatchAnchor(
                "frontend-request:set-upload-setting",
                "action", "upload", "setting", "setUploadSetting",
            ),),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual((), result.paths)
        self.assertEqual(
            "selector_extraction_not_proven", result.diagnostics[0].code
        )

    def test_table_literal_without_indirect_handler_call_does_not_bind(self):
        binary_path = X5000R_ROOT / "www/cgi-bin/cstecgi.cgi"
        if not binary_path.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        content = bytearray(binary_path.read_bytes())
        indirect_call_offset = 0x2E904
        self.assertEqual(
            struct.pack("<I", 0x0320F809),
            content[indirect_call_offset:indirect_call_offset + 4],
        )
        content[indirect_call_offset:indirect_call_offset + 4] = b"\x00" * 4
        content = bytes(content)
        source = _source("www/cgi-bin/cstecgi.cgi", content)

        result = discover_mips_cgi_nested_dispatch(
            source,
            content,
            (MipsNestedDispatchAnchor(
                "frontend-request:set-upload-setting",
                "action", "upload", "setting", "setUploadSetting",
            ),),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual((), result.paths)
        self.assertEqual("table_dispatch_not_proven", result.diagnostics[0].code)

    def test_upload_literal_without_a_guarded_branch_does_not_select_mode(self):
        binary_path = X5000R_ROOT / "www/cgi-bin/cstecgi.cgi"
        if not binary_path.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        content = bytearray(binary_path.read_bytes())
        branch_offset = 0x2E5B0
        self.assertEqual(
            struct.pack("<I", 0x10400072),
            content[branch_offset:branch_offset + 4],
        )
        content[branch_offset:branch_offset + 4] = b"\x00" * 4
        content = bytes(content)
        source = _source("www/cgi-bin/cstecgi.cgi", content)

        result = discover_mips_cgi_nested_dispatch(
            source,
            content,
            (MipsNestedDispatchAnchor(
                "frontend-request:set-upload-setting",
                "action", "upload", "setting", "setUploadSetting",
            ),),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual((), result.paths)
        self.assertEqual("transport_branch_not_proven", result.diagnostics[0].code)

    def test_tampered_dispatch_table_claim_is_rejected(self):
        binary_path = X5000R_ROOT / "www/cgi-bin/cstecgi.cgi"
        if not binary_path.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        content = binary_path.read_bytes()
        source = _source("www/cgi-bin/cstecgi.cgi", content)
        result = discover_mips_cgi_nested_dispatch(
            source,
            content,
            (MipsNestedDispatchAnchor(
                "frontend-request:set-upload-setting",
                "action", "upload", "setting", "setUploadSetting",
            ),),
        )

        with self.assertRaisesRegex(ValueError, "dispatch table proof is inconsistent"):
            replace(
                result,
                evidence_atoms=tuple(
                    replace(atom, object_value="other_handle_t")
                    if atom.capability == "selects_dispatch_table" else atom
                    for atom in result.evidence_atoms
                ),
            )

    def test_source_mismatch_fails_closed(self):
        binary_path = X5000R_ROOT / "www/cgi-bin/cstecgi.cgi"
        if not binary_path.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        content = binary_path.read_bytes()
        source = _source("www/cgi-bin/cstecgi.cgi", content)

        result = discover_mips_cgi_nested_dispatch(
            source,
            content + b"x",
            (MipsNestedDispatchAnchor(
                "frontend-request:set-upload-setting",
                "action", "upload", "setting", "setUploadSetting",
            ),),
        )

        self.assertEqual(CoverageStatus.FAILED, result.coverage_status)
        self.assertEqual("source_mismatch", result.diagnostics[0].code)
        self.assertEqual((), result.paths)

    def test_dispatcher_instruction_budget_is_partial(self):
        binary_path = X5000R_ROOT / "www/cgi-bin/cstecgi.cgi"
        if not binary_path.exists():
            self.skipTest("local X5000R representative sample is unavailable")
        content = binary_path.read_bytes()
        source = _source("www/cgi-bin/cstecgi.cgi", content)

        result = discover_mips_cgi_nested_dispatch(
            source,
            content,
            (MipsNestedDispatchAnchor(
                "frontend-request:set-upload-setting",
                "action", "upload", "setting", "setUploadSetting",
            ),),
            policy=MipsNestedDispatchPolicy(max_dispatcher_instructions=128),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual("instruction_budget", result.diagnostics[0].code)
        self.assertEqual((), result.paths)


if __name__ == "__main__":
    unittest.main()
