import hashlib
from dataclasses import replace
import json
from pathlib import Path
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    DiscoveryCatalogInput,
    DiscoveryCandidateKind,
    DiscoveryProducerBatch,
    MipsRequestProtectionAnchor,
    MipsRequestProtectionPolicy,
    RequestProtectionStatus,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    discover_frontend_requests,
    discover_mips_request_protection,
    replay_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
X5000R_ROOT = ROOT / (
    "var/mapping-work/x5000r-v9.1.0u.6118/extractions/firmware.bin.extracted/"
    "1004C/C8343R-6118.bin.extracted/184C70/squashfs-root"
)
LIGHTTPD = X5000R_ROOT / "usr/sbin/lighttpd"


def _source(content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        canonical_path="usr/sbin/lighttpd",
        original_path="usr/sbin/lighttpd",
        kind="file",
        size=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
    )


class MipsRequestProtectionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.content = LIGHTTPD.read_bytes()
        cls.source = _source(cls.content)

    def test_documented_x5000r_protection_scope_is_exactly_replayable(self) -> None:
        from scripts.build_x5000r_request_protection_report import build_summary

        documented = json.loads((
            ROOT / "docs/firmware-mapping/samples/"
            "m1-21-x5000r-request-protection.json"
        ).read_text(encoding="utf-8"))

        self.assertEqual(documented, build_summary(X5000R_ROOT))

    def test_actual_x5000r_distinguishes_protected_page_from_cgi_path(self) -> None:
        result = discover_mips_request_protection(
            self.source,
            self.content,
            (
                MipsRequestProtectionAnchor("page:config", "/advance/config.html"),
                MipsRequestProtectionAnchor(
                    "nested:setUploadSetting", "/cgi-bin/cstecgi.cgi"
                ),
            ),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(
            {
                "/advance/config.html": RequestProtectionStatus.GUARDED_BY_PATH_GATE,
                "/cgi-bin/cstecgi.cgi": (
                    RequestProtectionStatus.EXCLUDED_FROM_PATH_GATE
                ),
            },
            {item.request_path: item.protection_status for item in result.assessments},
        )
        upload = next(
            item for item in result.assessments
            if item.request_path == "/cgi-bin/cstecgi.cgi"
        )
        self.assertEqual(
            (".asp", ".html", ".htm", "config.dat", "/login/login.cgi"),
            upload.guard_patterns,
        )
        self.assertEqual(0x00407B2C, upload.auth_callsite)
        self.assertEqual(0x00409300, upload.auth_hook_address)
        self.assertEqual(0x00407B40, upload.enforcement_address)
        self.assertEqual(302, upload.denial_status)
        self.assertEqual(0x00408978, upload.authenticator_address)
        self.assertEqual(0x004093E8, upload.authenticator_callsite)
        self.assertEqual("SESSION_ID", upload.cookie_name)
        self.assertEqual(0x00408A9C, upload.cookie_callsite)
        self.assertEqual(0x00408AB4, upload.session_lookup_callsite)
        self.assertEqual(
            {
                "selects_protection_scope",
                "invokes_authenticator",
                "validates_session_cookie",
                "enforces_auth_redirect",
                "classifies_request_scope",
            },
            {
                atom.capability for atom in result.evidence_atoms
                if atom.subject_ref == upload.assessment_id
            },
        )
        self.assertTrue(all(
            replay_evidence(atom, self.source, self.content)
            for atom in result.evidence_atoms
        ))

    def test_missing_auth_hook_does_not_publish_a_scope_assessment(self) -> None:
        mutated = bytearray(self.content)
        mutated[0x7B2C:0x7B30] = b"\x00\x00\x00\x00"
        result = discover_mips_request_protection(
            _source(bytes(mutated)), bytes(mutated),
            (MipsRequestProtectionAnchor("target", "/cgi-bin/cstecgi.cgi"),),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual((), result.assessments)
        self.assertEqual("auth_hook_not_proven", result.diagnostics[0].code)

    def test_missing_302_enforcement_does_not_claim_a_guard(self) -> None:
        mutated = bytearray(self.content)
        mutated[0x7B40:0x7B44] = b"\xc8\x00\x02\x24"  # addiu v0, zero, 200
        result = discover_mips_request_protection(
            _source(bytes(mutated)), bytes(mutated),
            (MipsRequestProtectionAnchor("target", "/advance/config.html"),),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual("auth_enforcement_not_proven", result.diagnostics[0].code)

    def test_missing_session_cookie_key_does_not_claim_authentication(self) -> None:
        mutated = self.content.replace(b"SESSION_ID\x00", b"SESSXON_ID\x00", 1)
        result = discover_mips_request_protection(
            _source(mutated), mutated,
            (MipsRequestProtectionAnchor("target", "/advance/config.html"),),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual("session_validation_not_proven", result.diagnostics[0].code)

    def test_tampered_scope_classification_is_rejected(self) -> None:
        result = discover_mips_request_protection(
            self.source, self.content,
            (MipsRequestProtectionAnchor("target", "/cgi-bin/cstecgi.cgi"),),
        )
        assessment = result.assessments[0]

        with self.assertRaisesRegex(ValueError, "protection status"):
            replace(
                result,
                assessments=(replace(
                    assessment,
                    protection_status=RequestProtectionStatus.GUARDED_BY_PATH_GATE,
                ),),
            )

    def test_source_mismatch_and_instruction_budget_fail_closed(self) -> None:
        mismatch = discover_mips_request_protection(
            self.source, self.content + b"x",
            (MipsRequestProtectionAnchor("target", "/cgi-bin/cstecgi.cgi"),),
        )
        budget = discover_mips_request_protection(
            self.source, self.content,
            (MipsRequestProtectionAnchor("target", "/cgi-bin/cstecgi.cgi"),),
            policy=MipsRequestProtectionPolicy(max_instructions=10),
        )

        self.assertEqual(CoverageStatus.FAILED, mismatch.coverage_status)
        self.assertEqual("source_mismatch", mismatch.diagnostics[0].code)
        self.assertEqual(CoverageStatus.PARTIAL, budget.coverage_status)
        self.assertEqual("instruction_budget", budget.diagnostics[0].code)

    def test_validated_assessment_is_queryable_as_catalog_candidate(self) -> None:
        frontend_content = b'''$.post("/cgi-bin/cstecgi.cgi", {topicurl: "x"});'''
        frontend_source = SourceArtifactEntry(
            canonical_path="www/request.js", original_path="www/request.js",
            kind="file", size=len(frontend_content),
            content_sha256=hashlib.sha256(frontend_content).hexdigest(),
        )
        frontend = discover_frontend_requests(frontend_source, frontend_content)
        target = frontend.candidates[0].candidate_id
        result = discover_mips_request_protection(
            self.source, self.content,
            (MipsRequestProtectionAnchor(target, "/cgi-bin/cstecgi.cgi"),),
        )
        # Catalog referential integrity is exercised with a minimal supported target.
        catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
            "1" * 64,
            "2" * 64,
            (
                DiscoveryProducerBatch.frontend((frontend,), "www/request.js"),
                DiscoveryProducerBatch.native_request_protection(
                    (result,), "usr/sbin/lighttpd:custom-auth"
                ),
            ),
        ))

        candidates = [
            item for item in catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.NATIVE_REQUEST_PROTECTION
        ]
        self.assertEqual(1, len(candidates))
        self.assertEqual(
            "/cgi-bin/cstecgi.cgi -> excluded_from_path_gate",
            candidates[0].canonical_identity,
        )
        self.assertEqual(
            target, dict(candidates[0].attributes)["target_ref"]
        )


if __name__ == "__main__":
    unittest.main()
