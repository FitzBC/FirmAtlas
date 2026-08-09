from dataclasses import replace
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from firmatlas.mapping.discovery_catalog import (
    DiscoveryCandidate,
    DiscoveryCandidateKind,
    DiscoveryCatalog,
    DiscoveryClaimStatus,
    DiscoveryParameter,
)
from firmatlas.mapping.domain import CoverageStatus
from firmatlas.mapping.historical_expectation import (
    HistoricalGapReason,
    HistoricalApplicability,
    HistoricalInterfaceExpectation,
    HistoricalMatchStatus,
    HistoricalVulnerabilityRecord,
    build_historical_vulnerability_audit,
    HistoricalRouteBindingStatus,
    compare_historical_route_bindings,
    compare_historical_expectations,
)
from firmatlas.mapping.__main__ import main as mapping_main
from firmatlas.mapping.analysis_run import (
    BUILTIN_ANALYZER_REGISTRY_V1,
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    analyze_extracted_root,
)


def catalog_with_interface_and_parameter() -> DiscoveryCatalog:
    candidate = DiscoveryCandidate(
        candidate_id="candidate:set-iptv",
        candidate_kind=DiscoveryCandidateKind.REQUEST_INTERFACE,
        canonical_identity="goform/SetIPTVCfg",
        claim_status=DiscoveryClaimStatus.SUPPORTED,
        source_path="webroot_ro/js/iptv.js",
        source_construct="page_model_set_url",
        evidence_ids=("evidence:interface",),
    )
    parameter = DiscoveryParameter(
        parameter_id="parameter:list",
        owner_ref=candidate.candidate_id,
        name="list",
        namespace="form",
        literal_value=None,
        selector_values=(),
        is_operation_selector=False,
        source_construct="page_model_submit",
        evidence_ids=("evidence:parameter",),
    )
    return DiscoveryCatalog(
        catalog_id="discovery-catalog:" + "1" * 64,
        firmware_artifact_sha256="2" * 64,
        source_inventory_sha256="3" * 64,
        coverage_status=CoverageStatus.COMPLETED,
        source_inventory_coverage_status=CoverageStatus.COMPLETED,
        candidates=(candidate,),
        parameters=(parameter,),
        evidence_atoms=(),
        coverage=(),
    )


def catalog_with_native_route_only() -> DiscoveryCatalog:
    return DiscoveryCatalog(
        catalog_id="discovery-catalog:" + "4" * 64,
        firmware_artifact_sha256="2" * 64,
        source_inventory_sha256="3" * 64,
        coverage_status=CoverageStatus.COMPLETED,
        source_inventory_coverage_status=CoverageStatus.COMPLETED,
        candidates=(DiscoveryCandidate(
            candidate_id="native-route:quick-index",
            candidate_kind=DiscoveryCandidateKind.NATIVE_ROUTE_BINDING,
            canonical_identity="QuickIndex",
            claim_status=DiscoveryClaimStatus.SUPPORTED,
            source_path="bin/httpd",
            source_construct="arm_pic_callsite",
            evidence_ids=("evidence:native-route",),
        ),),
        parameters=(),
        evidence_atoms=(),
        coverage=(),
    )


class HistoricalExpectationDiffContractTests(unittest.TestCase):
    def test_historical_route_binding_requires_the_expected_handler(self):
        catalog = replace(
            catalog_with_native_route_only(),
            candidates=(replace(
                catalog_with_native_route_only().candidates[0],
                attributes=(("handler_symbol", "formQuickIndex"),),
            ),),
        )
        expectation = HistoricalInterfaceExpectation(
            vulnerability_identifier="CVE-2026-6015",
            interface_value="/goform/QuickIndex",
            handler_value="formQuickIndex",
            parameters=("PPPOEPassword",),
            source_ref="semantic-analysis:CVE-2026-6015",
            applicability=HistoricalApplicability.OUT_OF_SCOPE,
        )

        result = compare_historical_route_bindings(catalog, (expectation,))

        entry = result.entries[0]
        self.assertEqual(
            HistoricalRouteBindingStatus.VERIFIED_EXPECTED_HANDLER,
            entry.status,
        )
        self.assertEqual(("formQuickIndex",), entry.observed_handlers)
        self.assertEqual(("native-route:quick-index",), entry.route_binding_ids)
        self.assertEqual({"verified_expected_handler": 1}, result.summary)

    def test_vulnerability_audit_keeps_uncomparable_records_in_denominator(self):
        expectation = HistoricalInterfaceExpectation(
            vulnerability_identifier="CVE-1",
            interface_value="/goform/SetIPTVCfg",
            parameters=("list",),
            source_ref="semantic-analysis:CVE-1",
            applicability=HistoricalApplicability.EXACT_ARTIFACT,
        )
        diff = compare_historical_expectations(
            catalog_with_interface_and_parameter(), (expectation,)
        )
        audit = build_historical_vulnerability_audit(diff, (
            HistoricalVulnerabilityRecord("CVE-1", True, 1, 1),
            HistoricalVulnerabilityRecord("CVE-2", True, 0, 1),
            HistoricalVulnerabilityRecord("CVE-3", True, 0, 0),
            HistoricalVulnerabilityRecord("CVE-4", False, 0, 0),
        ))

        self.assertEqual(4, audit.total_vulnerability_count)
        self.assertEqual({
            "compared_interface": 1,
            "parameter_only": 1,
            "no_structured_communication": 1,
            "not_analyzed": 1,
        }, audit.category_counts)
        self.assertEqual(("CVE-4",), audit.not_analyzed_identifiers)
        self.assertEqual(1, audit.exact_artifact_observed_count)

    AC9_ROOT = Path(
        "../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root"
    )

    def test_primary_ac9_history_replay_separates_exact_and_cross_version_claims(self):
        if not self.AC9_ROOT.is_dir():
            self.skipTest("local vendor Tenda AC9 rootfs is unavailable")
        manifest = json.loads(Path(
            "docs/firmware-mapping/samples/"
            "r2-03-vendor-tenda-ac9-historical-expectations.json"
        ).read_text(encoding="utf-8"))
        expectations = tuple(
            HistoricalInterfaceExpectation.from_dict(item)
            for item in manifest["expectations"]
        )
        run = analyze_extracted_root(MappingAnalysisRequest(
            root=self.AC9_ROOT,
            firmware_artifact_sha256=(
                "981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296"
            ),
            profile=MappingAnalysisProfile.auto_v1(),
        ), registry=BUILTIN_ANALYZER_REGISTRY_V1)
        result = compare_historical_expectations(run.catalog, expectations)
        by_cve = {item.vulnerability_identifier: item for item in result.entries}

        exact = [
            item for item in result.entries
            if item.applicability == HistoricalApplicability.EXACT_ARTIFACT
        ]
        self.assertEqual(2, len(exact))
        self.assertEqual(
            {HistoricalMatchStatus.OBSERVED}, {item.status for item in exact}
        )
        self.assertIn("list", by_cve["CVE-2025-5836"].observed_parameters)
        self.assertEqual(
            HistoricalGapReason.METHOD_NOT_OBSERVED,
            by_cve["CVE-2025-5847"].gap_reason,
        )
        self.assertTrue(by_cve["CVE-2026-6015"].candidate_ids)
        documented = json.loads(Path(
            "docs/firmware-mapping/samples/"
            "r2-03-vendor-tenda-ac9-historical-diff.json"
        ).read_text(encoding="utf-8"))
        self.assertEqual(result.report_id, documented["report_id"])
        self.assertEqual(run.catalog.catalog_id, documented["catalog_id"])
        self.assertEqual(result.summary, documented["summary"])

    def test_auto_v2_closes_ac9_method_gap_with_framework_evidence(self):
        if not self.AC9_ROOT.is_dir():
            self.skipTest("local vendor Tenda AC9 rootfs is unavailable")
        manifest = json.loads(Path(
            "docs/firmware-mapping/samples/"
            "r2-03-vendor-tenda-ac9-historical-expectations.json"
        ).read_text(encoding="utf-8"))
        expectations = tuple(
            HistoricalInterfaceExpectation.from_dict(item)
            for item in manifest["expectations"]
        )
        run = analyze_extracted_root(MappingAnalysisRequest(
            root=self.AC9_ROOT,
            firmware_artifact_sha256=(
                "981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296"
            ),
            profile=MappingAnalysisProfile.auto(),
        ))
        result = compare_historical_expectations(run.catalog, expectations)
        remote = next(
            item for item in result.entries
            if item.vulnerability_identifier == "CVE-2025-5847"
        )

        self.assertEqual(HistoricalMatchStatus.OBSERVED, remote.status)
        self.assertEqual(("POST",), remote.observed_methods)
        graph_stage = next(
            item for item in run.stages
            if item.stage_name == "frontend_asset_graph"
        )
        self.assertEqual(CoverageStatus.COMPLETED, graph_stage.coverage_status)
        self.assertGreater(graph_stage.output_count, 0)
        scope = json.loads(Path(
            "docs/firmware-mapping/samples/"
            "r2-04-vendor-tenda-ac9-vulnerability-scope.json"
        ).read_text(encoding="utf-8"))
        audit = build_historical_vulnerability_audit(result, tuple(
            HistoricalVulnerabilityRecord(**item) for item in scope["records"]
        ))
        self.assertEqual(71, audit.total_vulnerability_count)
        self.assertEqual({
            "compared_interface": 13,
            "parameter_only": 3,
            "no_structured_communication": 9,
            "not_analyzed": 46,
        }, audit.category_counts)
        documented = json.loads(Path(
            "docs/firmware-mapping/samples/"
            "r2-04-vendor-tenda-ac9-framework-history.json"
        ).read_text(encoding="utf-8"))
        self.assertEqual(run.analysis_run_id, documented["analysis_run_id"])
        self.assertEqual(result.report_id, documented[
            "historical_expectation_diff"
        ]["report_id"])
        self.assertEqual(audit.audit_id, documented[
            "vulnerability_scope_audit"
        ]["audit_id"])

    def test_cli_analyzes_root_and_writes_historical_diff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rootfs"
            root.mkdir()
            (root / "index.html").write_text(
                '<form action="/goform/SetSambaCfg" method="POST">'
                '<input name="password"></form>',
                encoding="utf-8",
            )
            expectations = Path(directory) / "expectations.json"
            expectations.write_text(json.dumps({
                "schema_version": "firmatlas.mapping.historical-expectations/v1alpha1",
                "expectations": [{
                    "vulnerability_identifier": "CVE-2025-22949",
                    "interface_value": "/goform/SetSambaCfg",
                    "method": "POST",
                    "parameters": ["password"],
                    "source_ref": "semantic-analysis:CVE-2025-22949",
                    "applicability": "exact_artifact",
                    "claimed_versions": ["15.03.05.19"],
                    "applicability_basis": "fixture represents the claimed artifact",
                }],
            }), encoding="utf-8")
            output = Path(directory) / "historical-diff.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = mapping_main((
                    "compare-history", str(root),
                    "--artifact-sha256", "a" * 64,
                    "--expectations", str(expectations),
                    "--output", str(output),
                    "--profile", "base",
                ))
            summary = json.loads(stdout.getvalue())
            document = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(0, exit_code)
        self.assertEqual({"observed": 1}, document["summary"])
        self.assertEqual(document["report_id"], summary["report_id"])
        self.assertEqual("discovery-catalog", document["catalog_id"].split(":")[0])

    def test_expectation_json_preserves_version_scope_basis(self) -> None:
        expectation = HistoricalInterfaceExpectation.from_dict({
            "vulnerability_identifier": "CVE-2025-22949",
            "interface_value": "/goform/SetSambaCfg",
            "method": "POST",
            "handler_value": "formSetSambaCfg",
            "parameters": ["password"],
            "source_ref": "semantic-analysis:CVE-2025-22949",
            "applicability": "exact_artifact",
            "claimed_versions": ["15.03.05.19"],
            "applicability_basis": "artifact release is V15.03.05.19",
        })

        self.assertEqual("POST", expectation.method)
        self.assertEqual("formSetSambaCfg", expectation.handler_value)
        self.assertEqual(("15.03.05.19",), expectation.claimed_versions)
        self.assertEqual(
            "artifact release is V15.03.05.19", expectation.applicability_basis
        )
        self.assertEqual(
            "exact_artifact", expectation.to_dict()["applicability"]
        )
        self.assertEqual(
            "formSetSambaCfg", expectation.to_dict()["handler_value"]
        )

    def test_report_is_content_addressed_and_json_serializable(self) -> None:
        expectation = HistoricalInterfaceExpectation(
            vulnerability_identifier="CVE-2025-5836",
            interface_value="/goform/SetIPTVCfg",
            parameters=("list",),
            source_ref="semantic-analysis:CVE-2025-5836",
            applicability=HistoricalApplicability.EXACT_ARTIFACT,
        )
        first = compare_historical_expectations(
            catalog_with_interface_and_parameter(), (expectation,)
        )
        second = compare_historical_expectations(
            catalog_with_interface_and_parameter(), (expectation,)
        )

        self.assertEqual(first.report_id, second.report_id)
        document = first.to_dict()
        self.assertEqual(first.report_id, document["report_id"])
        self.assertEqual("completed", document["catalog_coverage_status"])
        self.assertEqual("completed", document["inventory_coverage_status"])
        self.assertEqual("observed", document["entries"][0]["status"])
        self.assertEqual("none", document["entries"][0]["gap_reason"])

    def test_observed_historical_interface_preserves_catalog_evidence(self) -> None:
        result = compare_historical_expectations(
            catalog_with_interface_and_parameter(),
            (HistoricalInterfaceExpectation(
                vulnerability_identifier="CVE-2025-5836",
                interface_value="/goform/SetIPTVCfg",
                parameters=("list",),
                source_ref="semantic-analysis:CVE-2025-5836",
                applicability=HistoricalApplicability.EXACT_ARTIFACT,
            ),),
        )

        self.assertEqual(HistoricalMatchStatus.OBSERVED, result.entries[0].status)
        self.assertEqual(("candidate:set-iptv",), result.entries[0].candidate_ids)
        self.assertEqual(
            ("evidence:interface", "evidence:parameter"),
            result.entries[0].catalog_evidence_ids,
        )
        self.assertEqual(
            HistoricalApplicability.EXACT_ARTIFACT,
            result.entries[0].applicability,
        )
        self.assertEqual(
            "semantic-analysis:CVE-2025-5836", result.entries[0].source_ref
        )
        self.assertEqual(("list",), result.entries[0].expected_parameters)
        self.assertEqual({"observed": 1}, result.summary)

    def test_observed_interface_with_missing_parameter_is_a_parameter_gap(self) -> None:
        result = compare_historical_expectations(
            catalog_with_interface_and_parameter(),
            (HistoricalInterfaceExpectation(
                vulnerability_identifier="CVE-2025-5836",
                interface_value="/goform/SetIPTVCfg",
                parameters=("list", "vlanId"),
                source_ref="semantic-analysis:CVE-2025-5836",
                applicability=HistoricalApplicability.EXACT_ARTIFACT,
            ),),
        )

        entry = result.entries[0]
        self.assertEqual(HistoricalMatchStatus.PARTIAL, entry.status)
        self.assertEqual(HistoricalGapReason.PARAMETER_NOT_OBSERVED, entry.gap_reason)
        self.assertEqual(("vlanId",), entry.missing_parameters)

    def test_missing_declared_method_is_a_transport_shape_gap(self) -> None:
        result = compare_historical_expectations(
            catalog_with_interface_and_parameter(),
            (HistoricalInterfaceExpectation(
                vulnerability_identifier="CVE-2025-5847",
                interface_value="/goform/SetIPTVCfg",
                method="POST",
                parameters=("list",),
                source_ref="semantic-analysis:CVE-2025-5847",
                applicability=HistoricalApplicability.EXACT_ARTIFACT,
            ),),
        )

        entry = result.entries[0]
        self.assertEqual(HistoricalMatchStatus.PARTIAL, entry.status)
        self.assertEqual(HistoricalGapReason.METHOD_NOT_OBSERVED, entry.gap_reason)
        self.assertEqual((), entry.observed_methods)

    def test_native_route_without_request_is_a_dispatcher_gap(self) -> None:
        result = compare_historical_expectations(
            catalog_with_native_route_only(),
            (HistoricalInterfaceExpectation(
                vulnerability_identifier="CVE-2026-6015",
                interface_value="/goform/QuickIndex",
                parameters=("PPPOEPassword",),
                source_ref="semantic-analysis:CVE-2026-6015",
                applicability=HistoricalApplicability.EXACT_ARTIFACT,
            ),),
        )

        entry = result.entries[0]
        self.assertEqual(HistoricalMatchStatus.MISSING, entry.status)
        self.assertEqual(
            HistoricalGapReason.DISPATCHER_BINDING_WITHOUT_INTERFACE,
            entry.gap_reason,
        )
        self.assertEqual(("native-route:quick-index",), entry.candidate_ids)
        self.assertEqual(("evidence:native-route",), entry.catalog_evidence_ids)

    def test_product_family_claim_is_not_called_a_miss_for_this_artifact(self) -> None:
        result = compare_historical_expectations(
            catalog_with_interface_and_parameter(),
            (HistoricalInterfaceExpectation(
                vulnerability_identifier="CVE-2025-10442",
                interface_value="/goform/exeCommand",
                parameters=("cmdinput",),
                source_ref="semantic-analysis:CVE-2025-10442",
                applicability=HistoricalApplicability.PRODUCT_FAMILY,
            ),),
        )

        entry = result.entries[0]
        self.assertEqual(HistoricalMatchStatus.NOT_ASSESSABLE, entry.status)
        self.assertEqual(HistoricalGapReason.ARTIFACT_SCOPE_UNKNOWN, entry.gap_reason)

    def test_incomplete_catalog_cannot_prove_an_interface_gap(self) -> None:
        catalog = replace(
            catalog_with_interface_and_parameter(),
            coverage_status=CoverageStatus.PARTIAL,
        )
        result = compare_historical_expectations(
            catalog,
            (HistoricalInterfaceExpectation(
                vulnerability_identifier="CVE-2025-10442",
                interface_value="/goform/exeCommand",
                parameters=("cmdinput",),
                source_ref="semantic-analysis:CVE-2025-10442",
                applicability=HistoricalApplicability.EXACT_ARTIFACT,
            ),),
        )

        entry = result.entries[0]
        self.assertEqual(HistoricalMatchStatus.NOT_ASSESSABLE, entry.status)
        self.assertEqual(HistoricalGapReason.COVERAGE_INCOMPLETE, entry.gap_reason)

    def test_explicit_out_of_scope_takes_precedence_over_incomplete_coverage(self):
        catalog = replace(
            catalog_with_interface_and_parameter(),
            coverage_status=CoverageStatus.PARTIAL,
        )
        result = compare_historical_expectations(
            catalog,
            (HistoricalInterfaceExpectation(
                vulnerability_identifier="CVE-2025-10442",
                interface_value="/goform/exeCommand",
                parameters=("cmdinput",),
                source_ref="semantic-analysis:CVE-2025-10442",
                applicability=HistoricalApplicability.OUT_OF_SCOPE,
            ),),
        )

        self.assertEqual(
            HistoricalGapReason.ARTIFACT_OUT_OF_SCOPE,
            result.entries[0].gap_reason,
        )


if __name__ == "__main__":
    unittest.main()
