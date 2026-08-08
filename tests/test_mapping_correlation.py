from firmatlas.mapping import (
    AnalyzerIdentity,
    CorrelationPolicy,
    CoverageStatus,
    FrontendEndpointShape,
    FrontendProducerResult,
    FrontendRequestCandidate,
    FrontendRequestRole,
    NativeHint,
    NativeHintKind,
    NativeProducerResult,
    SourceArtifactEntry,
    correlate_frontend_native,
    discover_frontend_requests,
    discover_native_hints,
)
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import unittest


def _frontend(
    endpoint: str,
    candidate_id: str = "frontend:1",
    endpoint_shape: FrontendEndpointShape = FrontendEndpointShape.EXACT_LITERAL,
) -> FrontendProducerResult:
    return FrontendProducerResult(
        source_path="webroot/js/page.js",
        coverage_status=CoverageStatus.COMPLETED,
        processed_bytes=100,
        producer=AnalyzerIdentity("frontend-request-producer", "0.1.0"),
        candidates=(
            FrontendRequestCandidate(
                candidate_id=candidate_id,
                endpoint=endpoint,
                endpoint_shape=endpoint_shape,
                request_role=FrontendRequestRole.WRITE,
                method="POST",
                representation="form_urlencoded",
                source_construct="fixture",
                evidence_ids=("frontend-evidence",),
            ),
        ),
        parameters=(),
        evidence_atoms=(),
    )


def _native(
    value: str,
    kind: NativeHintKind = NativeHintKind.ROUTE_TOKEN,
    hint_id: str = "native:1",
    source_path: str = "bin/httpd",
) -> NativeProducerResult:
    return NativeProducerResult(
        source_path=source_path,
        coverage_status=CoverageStatus.COMPLETED,
        processed_bytes=1000,
        producer=AnalyzerIdentity("native-shallow-producer", "0.1.0"),
        detected_format="elf",
        bitness=32,
        endianness="little",
        machine="ARM",
        hints=(
            NativeHint(
                hint_id=hint_id,
                kind=kind,
                value=value,
                source_construct="fixture",
                evidence_ids=("native-evidence",),
            ),
        ),
        evidence_atoms=(),
    )


class FrontendNativeCorrelationContractTests(unittest.TestCase):
    def test_documented_ac9_summary_preserves_candidate_only_status(self):
        repository = Path(__file__).resolve().parents[1]
        payload = json.loads(
            (
                repository
                / "docs/firmware-mapping/samples/m1-06c-frontend-native-correlation-summary.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(7, payload["result"]["association_count"])
        self.assertEqual(14, payload["result"]["obligation_count"])
        self.assertEqual(
            {"candidate"},
            {item["status"] for item in payload["result"]["associations"]},
        )
        self.assertEqual(0, payload["negative_controls"][1]["binding_count"])

    def test_missing_producer_inputs_are_not_an_empty_success(self):
        result = correlate_frontend_native((), ())

        self.assertEqual(CoverageStatus.NOT_APPLICABLE, result.coverage_status)
        self.assertEqual("missing_producer_inputs", result.diagnostics[0].code)

    def test_exact_action_component_creates_candidate_and_two_obligations(self):
        result = correlate_frontend_native(
            (_frontend("goform/SetOnlineDevName"),),
            (_native("SetOnlineDevName"),),
        )

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(1, len(result.associations))
        association = result.associations[0]
        self.assertEqual("exact_component", association.match_basis.value)
        self.assertEqual("candidate", association.status.value)
        self.assertEqual("frontend:1", association.frontend_candidate_id)
        self.assertEqual("native:1", association.native_hint_id)
        self.assertEqual(
            ("frontend-evidence", "native-evidence"), association.evidence_ids
        )
        self.assertEqual(
            {"registers_route", "binds_handler"},
            {item.required_capability for item in result.obligations},
        )
        self.assertEqual((), result.unmatched_frontend_candidates)
        self.assertEqual(
            "firmatlas.mapping.correlation-result/v1alpha1",
            result.to_dict()["schema_version"],
        )
        self.assertIsInstance(json.dumps(result.to_dict()), str)

    def test_symbol_name_similarity_never_becomes_a_handler_binding(self):
        result = correlate_frontend_native(
            (_frontend("goform/SetOnlineDevName"),),
            (_native("formSetDeviceName", NativeHintKind.SYMBOL),),
        )

        self.assertEqual((), result.associations)
        self.assertEqual(1, len(result.obligations))
        obligation = result.obligations[0]
        self.assertEqual("registers_route", obligation.required_capability)
        self.assertEqual("frontend:1", obligation.target_ref)
        self.assertEqual("frontend_candidate", obligation.target_kind)
        self.assertEqual(
            "no_case_sensitive_exact_native_hint",
            result.unmatched_frontend_candidates[0].reason,
        )

    def test_incomplete_upstream_coverage_cannot_be_reported_as_complete(self):
        partial_native = replace(
            _native("SetOnlineDevName"), coverage_status=CoverageStatus.PARTIAL
        )

        result = correlate_frontend_native(
            (_frontend("goform/SetOnlineDevName"),), (partial_native,)
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual(1, len(result.associations))
        self.assertEqual("upstream_coverage_incomplete", result.diagnostics[0].code)

    def test_association_budget_returns_an_exact_partial_prefix(self):
        native_results = (
            _native("SetOnlineDevName", hint_id="native:1", source_path="bin/httpd"),
            _native("SetOnlineDevName", hint_id="native:2", source_path="bin/httpd2"),
        )

        result = correlate_frontend_native(
            (_frontend("goform/SetOnlineDevName"),),
            native_results,
            CorrelationPolicy(max_associations=1),
        )

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual(1, len(result.associations))
        self.assertEqual(2, len(result.obligations))
        self.assertEqual("association_budget_exceeded", result.diagnostics[0].code)

    def test_shared_endpoint_operations_keep_distinct_frontend_identity(self):
        frontend_results = (
            _frontend("/HNAP1", candidate_id="frontend:GetDeviceSettings"),
            _frontend("/HNAP1", candidate_id="frontend:SetDeviceSettings"),
        )

        result = correlate_frontend_native(
            frontend_results,
            (
                _native(
                    "/HNAP1",
                    NativeHintKind.ENDPOINT_LITERAL,
                    hint_id="native:hnap",
                ),
            ),
        )

        self.assertEqual(2, len(result.associations))
        self.assertEqual(
            {"frontend:GetDeviceSettings", "frontend:SetDeviceSettings"},
            {item.frontend_candidate_id for item in result.associations},
        )
        self.assertEqual(
            {"exact_endpoint"},
            {item.match_basis.value for item in result.associations},
        )
        self.assertEqual(4, len(result.obligations))

    def test_repeated_upstream_results_do_not_duplicate_association_identity(self):
        frontend = _frontend("goform/SetOnlineDevName")
        native = _native("SetOnlineDevName")

        result = correlate_frontend_native(
            (frontend, frontend), (native, native)
        )
        bounded = correlate_frontend_native(
            (frontend, frontend),
            (native, native),
            CorrelationPolicy(max_associations=1),
        )

        self.assertEqual(1, len(result.associations))
        self.assertEqual(2, len(result.obligations))
        self.assertEqual(CoverageStatus.COMPLETED, bounded.coverage_status)

    def test_literal_prefix_cannot_claim_an_exact_endpoint_match(self):
        frontend = _frontend(
            "/cgi-bin/status?",
            endpoint_shape=FrontendEndpointShape.LITERAL_PREFIX,
        )

        result = correlate_frontend_native(
            (frontend,),
            (
                _native(
                    "/cgi-bin/status?",
                    NativeHintKind.ENDPOINT_LITERAL,
                ),
            ),
        )

        self.assertEqual((), result.associations)
        self.assertEqual(1, len(result.unmatched_frontend_candidates))

    def test_result_order_is_stable_across_upstream_input_order(self):
        frontend_results = (
            _frontend("goform/GetStatus", candidate_id="frontend:get"),
            _frontend("goform/SetStatus", candidate_id="frontend:set"),
        )
        native_results = (
            _native("GetStatus", hint_id="native:get"),
            _native("SetStatus", hint_id="native:set"),
        )

        forward = correlate_frontend_native(frontend_results, native_results)
        reverse = correlate_frontend_native(
            tuple(reversed(frontend_results)), tuple(reversed(native_results))
        )

        self.assertEqual(forward.to_dict(), reverse.to_dict())

    def test_actual_ac9_correlates_all_frontend_candidates_to_httpd_only(self):
        repository = Path(__file__).resolve().parents[1]
        root = (
            repository.parent
            / "iot_seedintelligentanalysis"
            / "_tenda_ac9.zip.extracted"
            / "squashfs-root"
        )
        required = (
            "webroot_ro/js/static_route.js",
            "webroot_ro/js/online_list.js",
            "bin/httpd",
            "bin/dhttpd",
        )
        if not all((root / relative).exists() for relative in required):
            self.skipTest("local AC9 representative sample is unavailable")

        def analyze(relative: str, producer):
            content = (root / relative).read_bytes()
            source = SourceArtifactEntry(
                canonical_path=relative,
                original_path=relative,
                kind="file",
                size=len(content),
                content_sha256=hashlib.sha256(content).hexdigest(),
            )
            return producer(source, content)

        frontend_results = (
            analyze(required[0], discover_frontend_requests),
            analyze(required[1], discover_frontend_requests),
        )
        native_results = (
            analyze(required[2], discover_native_hints),
            analyze(required[3], discover_native_hints),
        )

        result = correlate_frontend_native(frontend_results, native_results)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(7, len(result.associations))
        self.assertEqual(14, len(result.obligations))
        self.assertEqual((), result.unmatched_frontend_candidates)
        self.assertEqual(
            {"bin/httpd"},
            {item.native_source_path for item in result.associations},
        )
        self.assertEqual(
            {"candidate"}, {item.status.value for item in result.associations}
        )


if __name__ == "__main__":
    unittest.main()
