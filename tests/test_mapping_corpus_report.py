import hashlib
import unittest
from pathlib import Path
from dataclasses import replace

from firmatlas.mapping import (
    CoverageStatus,
    CorpusEvidenceTier,
    CorpusGateStatus,
    CorpusReportInput,
    CorpusSampleInput,
    CorpusSampleStatus,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    SchedulerObligation,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    build_corpus_report,
    discover_frontend_requests,
)


def _frontend_catalog(content: bytes, firmware_sha256: str = "1" * 64):
    source = SourceArtifactEntry(
        canonical_path="www/app.js",
        original_path="www/app.js",
        kind="file",
        size=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
    )
    frontend = discover_frontend_requests(source, content)
    return assemble_discovery_catalog(DiscoveryCatalogInput(
        firmware_artifact_sha256=firmware_sha256,
        source_inventory_sha256="2" * 64,
        batches=(DiscoveryProducerBatch.frontend((frontend,), "www/**/*.js"),),
    ))


class CorpusReportContractTests(unittest.TestCase):
    def test_real_firmware_evidence_verifies_one_required_architecture(self):
        catalog = _frontend_catalog(
            b'$.post("/goform/SetOnlineDevName", {mac: value});'
        )
        report = build_corpus_report(CorpusReportInput(
            corpus_version="firmatlas.mapping.corpus/m1.1",
            required_categories=("form_handler",),
            samples=(CorpusSampleInput(
                sample_id="tenda-ac9-goform-dev",
                architecture_category="form_handler",
                architecture_subtype="goform_camel_registry",
                role="development",
                evidence_tier=CorpusEvidenceTier.REAL_FIRMWARE,
                required_capabilities=("constructs_request",),
                expected_firmware_sha256="1" * 64,
                catalog=catalog,
            ),),
        ))

        self.assertEqual(CorpusGateStatus.PASSED, report.gate_status)
        self.assertEqual(CorpusSampleStatus.VERIFIED, report.samples[0].status)
        self.assertEqual(("constructs_request",), report.samples[0].observed_capabilities)
        self.assertEqual(1, report.categories[0].real_firmware_verified_count)
        self.assertEqual(0, report.categories[0].open_obligation_count)
        self.assertTrue(report.report_id.startswith("corpus-report:"))
        self.assertEqual(report.to_dict(), build_corpus_report(CorpusReportInput(
            corpus_version="firmatlas.mapping.corpus/m1.1",
            required_categories=("form_handler",),
            samples=(CorpusSampleInput(
                sample_id="tenda-ac9-goform-dev",
                architecture_category="form_handler",
                architecture_subtype="goform_camel_registry",
                role="development",
                evidence_tier=CorpusEvidenceTier.REAL_FIRMWARE,
                required_capabilities=("constructs_request",),
                expected_firmware_sha256="1" * 64,
                catalog=catalog,
            ),),
        )).to_dict())

    def test_contract_fixture_and_external_lead_cannot_satisfy_real_firmware_gate(self):
        hnap = _frontend_catalog(
            b'$.ajax({url:"/HNAP1", method:"POST", '
            b'headers:{"SOAPAction":"GetDeviceSettings"}});',
            firmware_sha256="3" * 64,
        )
        report = build_corpus_report(CorpusReportInput(
            corpus_version="firmatlas.mapping.corpus/m1.1",
            required_categories=("hnap_soap", "cgi_gateway"),
            samples=(
                CorpusSampleInput(
                    "fixture-hnap", "hnap_soap", "hnap_envelope_dispatcher",
                    "contract", CorpusEvidenceTier.CONTRACT_FIXTURE,
                    ("constructs_request", "selects_operation"), catalog=hnap,
                ),
                CorpusSampleInput(
                    "totolink-x5000r", "cgi_gateway", "shared_cgi_dispatcher",
                    "acquisition-gap", CorpusEvidenceTier.EXTERNAL_LEAD,
                    ("constructs_request", "selects_operation"),
                ),
            ),
        ))

        self.assertEqual(CorpusGateStatus.PARTIAL, report.gate_status)
        self.assertEqual(
            {
                "fixture-hnap": CorpusSampleStatus.CONTRACT_ONLY,
                "totolink-x5000r": CorpusSampleStatus.ACQUISITION_GAP,
            },
            {item.sample_id: item.status for item in report.samples},
        )
        self.assertEqual(
            {
                "hnap_soap": CorpusSampleStatus.CONTRACT_ONLY,
                "cgi_gateway": CorpusSampleStatus.ACQUISITION_GAP,
            },
            {item.architecture_category: item.status for item in report.categories},
        )

    def test_contract_fixture_cannot_mask_a_real_firmware_coverage_gap(self):
        contract = _frontend_catalog(
            b'$.ajax({url:"/HNAP1", headers:{"SOAPAction":"GetInfo"}});',
            firmware_sha256="3" * 64,
        )
        partial_real = replace(
            _frontend_catalog(b'fetch("/HNAP1");'),
            coverage_status=CoverageStatus.PARTIAL,
            source_inventory_coverage_status=CoverageStatus.PARTIAL,
        )
        report = build_corpus_report(CorpusReportInput(
            corpus_version="firmatlas.mapping.corpus/m1.2",
            required_categories=("hnap_soap",),
            samples=(
                CorpusSampleInput(
                    "hnap-contract", "hnap_soap", "hnap_envelope", "contract",
                    CorpusEvidenceTier.CONTRACT_FIXTURE,
                    ("constructs_request", "selects_operation"), catalog=contract,
                ),
                CorpusSampleInput(
                    "hnap-real-partial", "hnap_soap", "hnap_xgi", "validation",
                    CorpusEvidenceTier.REAL_FIRMWARE,
                    ("constructs_request",), expected_firmware_sha256="1" * 64,
                    catalog=partial_real,
                ),
            ),
        ))

        self.assertEqual(CorpusSampleStatus.COVERAGE_GAP, report.categories[0].status)

    def test_preexisting_extraction_is_reported_as_derived_not_real_firmware(self):
        catalog = _frontend_catalog(b'$.post("/cgi-bin/admin.asp", {});')
        report = build_corpus_report(CorpusReportInput(
            corpus_version="firmatlas.mapping.corpus/m1.1",
            required_categories=("script_backend",),
            samples=(CorpusSampleInput(
                "dsl2877-derived", "script_backend", "vendor_asp_controller",
                "cross-architecture", CorpusEvidenceTier.DERIVED_FIRMWARE,
                required_capabilities=("constructs_request",), catalog=catalog,
            ),),
        ))

        self.assertEqual(CorpusGateStatus.PARTIAL, report.gate_status)
        self.assertEqual(CorpusSampleStatus.DERIVED_ONLY, report.samples[0].status)
        self.assertEqual(1, report.categories[0].derived_firmware_verified_count)
        self.assertEqual(0, report.categories[0].real_firmware_verified_count)

    def test_missing_or_forbidden_evidence_is_an_explicit_coverage_gap(self):
        catalog = _frontend_catalog(b'$.post("/HNAP1", {});')
        report = build_corpus_report(CorpusReportInput(
            corpus_version="firmatlas.mapping.corpus/m1.1",
            required_categories=("hnap_soap",),
            samples=(CorpusSampleInput(
                "negative-hnap", "hnap_soap", "empty_hnap_placeholder",
                "negative-control", CorpusEvidenceTier.REAL_FIRMWARE,
                required_capabilities=("selects_operation",),
                forbidden_capabilities=("constructs_request",),
                expected_firmware_sha256="1" * 64,
                catalog=catalog,
            ),),
        ))

        sample = report.samples[0]
        self.assertEqual(CorpusGateStatus.FAILED, report.gate_status)
        self.assertEqual(CorpusSampleStatus.COVERAGE_GAP, sample.status)
        self.assertEqual(("selects_operation",), sample.missing_capabilities)
        self.assertEqual(("constructs_request",), sample.unexpected_capabilities)

    def test_catalog_firmware_identity_mismatch_is_rejected(self):
        catalog = _frontend_catalog(b'fetch("/api/status");')
        with self.assertRaisesRegex(ValueError, "firmware identity"):
            build_corpus_report(CorpusReportInput(
                corpus_version="firmatlas.mapping.corpus/m1.1",
                required_categories=("resource_api",),
                samples=(CorpusSampleInput(
                    "wrong-artifact", "resource_api", "namespaced_api_router",
                    "holdout", CorpusEvidenceTier.REAL_FIRMWARE,
                    required_capabilities=("constructs_request",),
                    expected_firmware_sha256="9" * 64, catalog=catalog,
                ),),
            ))

    def test_real_firmware_tier_requires_an_expected_artifact_identity(self):
        catalog = _frontend_catalog(b'$.post("/goform/SetX", {});')
        with self.assertRaisesRegex(ValueError, "real firmware.*identity"):
            build_corpus_report(CorpusReportInput(
                corpus_version="firmatlas.mapping.corpus/m1.1",
                required_categories=("form_handler",),
                samples=(CorpusSampleInput(
                    "unattested-real", "form_handler", "goform_registry",
                    "development", CorpusEvidenceTier.REAL_FIRMWARE,
                    required_capabilities=("constructs_request",),
                    catalog=catalog,
                ),),
            ))

    def test_actual_m1_corpus_reports_real_fixture_and_missing_tiers_separately(self):
        root = Path(
            "../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root"
        )
        if not (root / "bin/httpd").exists():
            self.skipTest("local AC9 representative sample is unavailable")
        from scripts.build_mapping_corpus_report import build_m1_report

        report = build_m1_report(root)
        categories = {
            item.architecture_category: item.status for item in report.categories
        }
        self.assertEqual(CorpusGateStatus.PARTIAL, report.gate_status)
        self.assertEqual(CorpusSampleStatus.VERIFIED, categories["form_handler"])
        self.assertEqual(CorpusSampleStatus.COVERAGE_GAP, categories["hnap_soap"])
        self.assertEqual(CorpusSampleStatus.CONTRACT_ONLY, categories["cgi_gateway"])
        self.assertEqual(CorpusSampleStatus.COVERAGE_GAP, categories["script_backend"])
        self.assertEqual(CorpusSampleStatus.ACQUISITION_GAP, categories["native_only"])
        ac9 = next(item for item in report.samples if item.sample_id.startswith("tenda-ac9"))
        self.assertEqual(0, ac9.open_obligation_count)
        self.assertIn("binds_handler", ac9.observed_capabilities)
        dap3520 = next(
            item for item in report.samples if item.sample_id.startswith("dlink-dap3520")
        )
        self.assertEqual(CorpusSampleStatus.COVERAGE_GAP, dap3520.status)
        dap3520_root = Path(
            "../iot_seedintelligentanalysis/binwalk_result/类型6/BM-2024-00027/"
            "_DAP-3520_REVA_FIRMWARE_PATCH_1.17.RC047.ZIP.extracted/"
            "_DAP-3520_FW_v117-rc047.bin.extracted/squashfs-root"
        )
        if dap3520_root.exists():
            self.assertEqual(273, dap3520.candidate_count)
            self.assertEqual(288, dap3520.evidence_count)
            self.assertEqual((), dap3520.missing_capabilities)

    def test_open_obligation_prevents_verified_status(self):
        catalog = _frontend_catalog(b'$.post("/goform/SetX", {});')
        catalog = replace(catalog, open_obligations=(SchedulerObligation(
            "obligation:handler", "candidate:set-x", "binds_handler",
            "handler binding remains unknown", 80, ("native-deep",),
        ),))
        report = build_corpus_report(CorpusReportInput(
            corpus_version="firmatlas.mapping.corpus/m1.1",
            required_categories=("form_handler",),
            samples=(CorpusSampleInput(
                "open-handler", "form_handler", "goform_registry",
                "development", CorpusEvidenceTier.REAL_FIRMWARE,
                ("constructs_request",), expected_firmware_sha256="1" * 64,
                catalog=catalog,
            ),),
        ))

        self.assertEqual(CorpusSampleStatus.COVERAGE_GAP, report.samples[0].status)
        self.assertEqual(1, report.categories[0].open_obligation_count)

    def test_required_category_without_any_sample_remains_visible(self):
        catalog = _frontend_catalog(b'$.post("/goform/SetX", {});')
        report = build_corpus_report(CorpusReportInput(
            corpus_version="firmatlas.mapping.corpus/m1.1",
            required_categories=("form_handler", "native_only"),
            samples=(CorpusSampleInput(
                "one-form", "form_handler", "goform_registry",
                "development", CorpusEvidenceTier.REAL_FIRMWARE,
                ("constructs_request",), expected_firmware_sha256="1" * 64,
                catalog=catalog,
            ),),
        ))

        self.assertEqual(CorpusGateStatus.PARTIAL, report.gate_status)
        self.assertEqual(
            CorpusSampleStatus.ACQUISITION_GAP,
            next(
                item.status for item in report.categories
                if item.architecture_category == "native_only"
            ),
        )

    def test_gate_requires_nonempty_categories_and_capability_expectations(self):
        with self.assertRaisesRegex(ValueError, "required architecture category"):
            CorpusReportInput(
                corpus_version="firmatlas.mapping.corpus/m1.1",
                required_categories=(),
                samples=(CorpusSampleInput(
                    "lead", "native_only", "native_registry", "gap",
                    CorpusEvidenceTier.EXTERNAL_LEAD, ("binds_handler",),
                ),),
            )
        with self.assertRaisesRegex(ValueError, "capability expectation"):
            CorpusSampleInput(
                "empty", "native_only", "native_registry", "gap",
                CorpusEvidenceTier.EXTERNAL_LEAD,
            )

    def test_report_identity_binds_satisfied_capability_policy(self):
        catalog = _frontend_catalog(
            b'$.ajax({url:"/HNAP1", headers:{"SOAPAction":"GetInfo"}});'
        )

        def report_requiring(capability):
            return build_corpus_report(CorpusReportInput(
                corpus_version="firmatlas.mapping.corpus/m1.1",
                required_categories=("hnap_soap",),
                samples=(CorpusSampleInput(
                    "hnap", "hnap_soap", "hnap_envelope", "contract",
                    CorpusEvidenceTier.CONTRACT_FIXTURE,
                    required_capabilities=(capability,), catalog=catalog,
                ),),
            ))

        request_report = report_requiring("constructs_request")
        selector_report = report_requiring("selects_operation")
        self.assertNotEqual(request_report.report_id, selector_report.report_id)
        self.assertEqual(
            ("constructs_request",),
            request_report.samples[0].required_capabilities,
        )


if __name__ == "__main__":
    unittest.main()
