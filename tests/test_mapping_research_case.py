import unittest
import hashlib
from pathlib import Path
from dataclasses import replace

from scripts.build_mapping_research_cases import build_research_case_corpus

from firmatlas.mapping import (
    CaseClaim,
    CaseClaimStatus,
    CaseEvidenceKind,
    CaseEvidenceReference,
    CaseObligation,
    CaseObligationStatus,
    CaseStage,
    FrontendAssetInput,
    ResearchCaseInput,
    NativeRouteAnchor,
    SourceArtifactEntry,
    build_research_case,
    discover_arm_pic_callsite_bindings,
    discover_frontend_requests,
    discover_frontend_asset_graph,
    discover_mips_inline_route_bindings,
    discover_mips_handler_value_flows,
    discover_native_hints,
    discover_web_configuration,
    validate_research_case_corpus,
)


FIRMWARE_SHA = "9" * 64


def _ac9_case_input() -> ResearchCaseInput:
    evidence = (
        CaseEvidenceReference(
            "frontend:goform", CaseEvidenceKind.FRONTEND_REQUEST,
            "webroot_ro/js/online_list.js", "d" * 64,
            "text:bytes=100-128", "constructs_request",
            "frontend-request-producer@0.1.0",
        ),
        CaseEvidenceReference(
            "config:fastcgi", CaseEvidenceKind.WEB_CONFIGURATION,
            "etc_ro/nginx/conf/nginx.conf", "6" * 64,
            "text:bytes=800-840", "maps_namespace",
            "web-configuration-producer@0.1.0",
        ),
        CaseEvidenceReference(
            "native:httpd", CaseEvidenceKind.NATIVE_BINDING,
            "bin/httpd", "2" * 64,
            "binary:bytes=240340-240368", "binds_handler",
            "native-deep-producer@0.2.0",
        ),
    )
    return ResearchCaseInput(
        case_key="tenda-ac9-split-web-stack",
        title="Tenda AC9 split nginx/FastCGI and goform backend",
        firmware_artifact_sha256=FIRMWARE_SHA,
        architecture_tags=("split_web_stack", "goform_registry", "fastcgi_sidecar"),
        research_question=(
            "Which process owns /goform when the observed nginx namespace only exposes LuCI?"
        ),
        evidence=evidence,
        claims=(
            CaseClaim(
                "claim:namespace-divergence",
                "The nginx/FastCGI branch does not cover the observed /goform namespace.",
                ("frontend:goform", "config:fastcgi"),
            ),
            CaseClaim(
                "claim:httpd-binding",
                "The selected /goform route is registered by bin/httpd.",
                ("frontend:goform", "native:httpd"),
            ),
        ),
        stages=(
            CaseStage(
                "stage:config-gap", 1,
                "Preserve backend ownership as unresolved after namespace comparison.",
                ("claim:namespace-divergence",),
                creates_obligations=("obligation:goform-owner",),
            ),
            CaseStage(
                "stage:native-proof", 2,
                "Resolve ownership only after native call-site validation.",
                ("claim:httpd-binding",),
                resolves_obligations=("obligation:goform-owner",),
            ),
        ),
        obligations=(
            CaseObligation(
                "obligation:goform-owner",
                "Identify the binary that registers the /goform route.",
                "binds_handler",
                CaseObligationStatus.RESOLVED,
                ("native:httpd",),
            ),
        ),
        counterfactuals=(
            "Assigning /goform to nginx because it is in the same firmware "
            "would select the wrong namespace branch.",
            "Selecting dhttpd by filename alone would choose a binary with "
            "no matching action-component evidence.",
        ),
        paper_uses=(
            "Motivating example for evidence-backed backend ownership recovery.",
        ),
        limitations=(
            "This case proves selected registrations, not every runtime-reachable route.",
        ),
    )


class ResearchCaseTests(unittest.TestCase):
    def test_builds_content_addressed_case_with_temporal_obligation_resolution(self) -> None:
        case = build_research_case(_ac9_case_input())

        self.assertTrue(case.case_id.startswith("research-case:"))
        self.assertEqual("resolved", case.obligations[0].status.value)
        self.assertEqual(CaseClaimStatus.SUPPORTED, case.claims[0].status)
        self.assertEqual(
            ("stage:config-gap", "stage:native-proof"),
            tuple(stage.stage_id for stage in case.stages),
        )
        self.assertEqual(case.case_id, build_research_case(_ac9_case_input()).case_id)
        self.assertEqual("supported", case.to_dict()["claims"][0]["status"])

    def test_rejects_claim_with_unknown_evidence(self) -> None:
        value = _ac9_case_input()
        broken = ResearchCaseInput(
            **{
                **value.__dict__,
                "claims": (CaseClaim("claim:bad", "Unsupported", ("missing",)),),
            }
        )

        with self.assertRaisesRegex(ValueError, "unknown evidence"):
            build_research_case(broken)

    def test_rejects_obligation_resolved_before_a_stage_resolves_it(self) -> None:
        value = _ac9_case_input()
        broken = ResearchCaseInput(
            **{**value.__dict__, "stages": value.stages[:1]}
        )

        with self.assertRaisesRegex(ValueError, "resolved obligation"):
            build_research_case(broken)

    def test_rejected_obligation_requires_an_explicit_rejection_stage(self) -> None:
        value = _ac9_case_input()
        rejected = CaseObligation(
            "obligation:goform-owner",
            "Test and reject a proposed owner.",
            "binds_handler",
            CaseObligationStatus.REJECTED,
            ("native:httpd",),
        )
        stages = (
            value.stages[0],
            CaseStage(
                "stage:reject", 2, "Reject the candidate.",
                ("claim:httpd-binding",),
                rejects_obligations=("obligation:goform-owner",),
            ),
        )

        case = build_research_case(ResearchCaseInput(
            **{**value.__dict__, "stages": stages, "obligations": (rejected,)}
        ))

        self.assertEqual(CaseObligationStatus.REJECTED, case.obligations[0].status)

    def test_corpus_gate_requires_cross_line_evidence_and_paper_context(self) -> None:
        case = build_research_case(_ac9_case_input())

        validation = validate_research_case_corpus((case,))

        self.assertTrue(validation.paper_ready)
        self.assertEqual(1, validation.case_count)
        self.assertEqual(3, validation.evidence_line_count)
        self.assertEqual((), validation.issues)

    def test_corpus_gate_does_not_promote_single_line_case(self) -> None:
        value = _ac9_case_input()
        single = ResearchCaseInput(
            **{
                **value.__dict__,
                "case_key": "single-line",
                "evidence": value.evidence[:1],
                "claims": (
                    CaseClaim("claim:single", "Only frontend evidence.", ("frontend:goform",)),
                ),
                "stages": (
                    CaseStage("stage:single", 1, "Observe request.", ("claim:single",)),
                ),
                "obligations": (),
            }
        )

        validation = validate_research_case_corpus((build_research_case(single),))

        self.assertFalse(validation.paper_ready)
        self.assertIn("single-line: fewer than two independent evidence lines", validation.issues)

    def test_rejects_noncanonical_evidence_source_path(self) -> None:
        with self.assertRaisesRegex(ValueError, "canonical evidence-relative"):
            CaseEvidenceReference(
                "evidence:path", CaseEvidenceKind.FRONTEND_REQUEST,
                "www/../www/app.js", "1" * 64, "text:bytes=1-2",
                "constructs_request", "producer@1",
            )

    def test_corpus_gate_rejects_tampered_case_identity_and_empty_corpus(self) -> None:
        case = build_research_case(_ac9_case_input())

        tampered = validate_research_case_corpus((replace(
            case, case_id="research-case:" + "0" * 64
        ),))
        empty = validate_research_case_corpus(())

        self.assertFalse(tampered.paper_ready)
        self.assertIn(
            "tenda-ac9-split-web-stack: case identity does not replay",
            tampered.issues,
        )
        self.assertFalse(empty.paper_ready)
        self.assertEqual(("case corpus is empty",), empty.issues)

    def test_corpus_gate_reports_invalid_case_contract_without_crashing(self) -> None:
        case = replace(build_research_case(_ac9_case_input()), title="")

        validation = validate_research_case_corpus((case,))

        self.assertFalse(validation.paper_ready)
        self.assertIn(
            "tenda-ac9-split-web-stack: invalid case contract",
            validation.issues[0],
        )

    def test_stage_rejects_duplicate_references(self) -> None:
        with self.assertRaisesRegex(ValueError, "stage claim_ids must be unique"):
            CaseStage("stage:bad", 1, "Duplicate.", ("claim:a", "claim:a"))

    def test_real_ac9_case_preserves_gap_and_later_native_resolution(self) -> None:
        corpus = build_research_case_corpus()
        case = corpus["cases"][0]

        self.assertTrue(corpus["validation"]["paper_ready"])
        self.assertEqual(14, corpus["validation"]["evidence_line_count"])
        self.assertEqual(
            ["unresolved", "unresolved", "supported"],
            [case["claims"][index]["status"] for index in (2, 3, 4)],
        )
        self.assertEqual(
            ["obligation:goform-owner"],
            list(case["stages"][1]["creates_obligations"]),
        )
        self.assertEqual(
            ["obligation:goform-owner"],
            list(case["stages"][3]["resolves_obligations"]),
        )
        self.assertIn("formSetDeviceName", case["claims"][4]["statement"])

    def test_ac9_dlna_case_preserves_fixture_daemon_split_as_open(self) -> None:
        corpus = build_research_case_corpus()
        case = corpus["cases"][2]

        self.assertEqual("tenda-ac9-dlna-fixture-daemon-split", case["case_key"])
        self.assertEqual(3, corpus["validation"]["case_count"])
        self.assertEqual(
            [
                "supported", "supported", "supported", "supported",
                "supported", "supported", "supported", "supported",
                "supported", "supported", "supported", "unresolved",
            ],
            [claim["status"] for claim in case["claims"]],
        )
        obligations = {
            item["obligation_id"]: item for item in case["obligations"]
        }
        self.assertEqual("open", obligations["obligation:dlna-handler-owner"]["status"])
        self.assertEqual(
            "resolved",
            obligations["obligation:dlna-supervisor-ipc-binding"]["status"],
        )
        frontend = [
            item for item in case["evidence"]
            if item["kind"] == "frontend_request"
        ]
        self.assertEqual(5, len(frontend))
        self.assertEqual(
            {"constructs_request"},
            {item["capability"] for item in frontend},
        )
        relationships = [
            item for item in case["evidence"]
            if item["kind"] == "native_relationship"
        ]
        self.assertEqual(2, len(relationships))
        self.assertEqual(
            4,
            sum(
                item["kind"] == "native_command_binding"
                for item in case["evidence"]
            ),
        )
        self.assertEqual(
            6,
            sum(
                item["kind"] == "native_binding"
                for item in case["evidence"]
            ),
        )
        self.assertEqual(
            24,
            sum(
                item["kind"] == "native_literal_xref"
                for item in case["evidence"]
            ),
        )
        self.assertEqual(
            "stage:dlna-persisted-graph-query",
            case["stages"][-1]["stage_id"],
        )
        family_evidence = {
            item["evidence_ref"]: item
            for item in case["evidence"]
            if item["evidence_ref"].startswith("coverage:ac9-ac18-")
            or item["evidence_ref"].startswith("coverage:ac18-dlna-")
            or item["evidence_ref"].startswith("coverage:ac9-dlna-")
        }
        self.assertEqual(
            {
                "coverage:ac9-dlna-feature-pivots",
                "coverage:ac18-dlna-route-positive-control",
                "coverage:ac9-ac18-dlna-family-equivalence",
                "coverage:ac9-dlna-frontend-reachability",
                "coverage:ac18-dlna-frontend-reachability-control",
                "coverage:ac9-dlna-communication-graph",
                "coverage:ac18-dlna-communication-graph-control",
                "coverage:ac9-dlna-persisted-graph-query",
            },
            set(family_evidence),
        )
        self.assertEqual(
            {"coverage_ledger"},
            {item["kind"] for item in family_evidence.values()},
        )
        feature_gate = [
            item for item in case["evidence"]
            if item["kind"] == "frontend_feature_gate"
        ]
        self.assertEqual(5, len(feature_gate))
        self.assertEqual(
            {
                "declares_feature_value",
                "maps_feature_to_ui_target",
                "reveals_feature_target",
                "routes_feature_target_to_page",
                "loads_feature_script",
            },
            {item["capability"] for item in feature_gate},
        )
        resolution = next(
            item for item in case["evidence"]
            if item["evidence_ref"]
            == "coverage:ac9-native-relationship-target-resolution"
        )
        self.assertEqual("coverage_ledger", resolution["kind"])
        report_path = Path(resolution["source_path"])
        self.assertEqual(
            hashlib.sha256(report_path.read_bytes()).hexdigest(),
            resolution["source_artifact_sha256"],
        )

    def test_real_ac9_case_evidence_replays_from_current_producers(self) -> None:
        root = Path(
            "../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root"
        )
        if not root.exists():
            self.skipTest("local AC9 representative sample is unavailable")

        def analyze(relative_path, producer):
            content = (root / relative_path).read_bytes()
            source = SourceArtifactEntry(
                relative_path, relative_path, "file", len(content),
                hashlib.sha256(content).hexdigest(),
            )
            return source, content, producer(source, content)

        _, _, frontend = analyze(
            "webroot_ro/js/online_list.js", discover_frontend_requests
        )
        _, _, nginx = analyze(
            "etc_ro/nginx/conf/nginx.conf", discover_web_configuration
        )
        _, _, startup = analyze(
            "etc_ro/nginx/conf/nginx_init.sh", discover_web_configuration
        )
        httpd_source, httpd_content, shallow = analyze(
            "bin/httpd", discover_native_hints
        )
        _, _, dhttpd = analyze("bin/dhttpd", discover_native_hints)
        deep = discover_arm_pic_callsite_bindings(
            httpd_source,
            httpd_content,
            (NativeRouteAnchor("anchor:set-online", "SetOnlineDevName"),),
        )
        replayed = {
            atom.evidence_id: atom
            for result in (frontend, nginx, startup, shallow, deep)
            for atom in result.evidence_atoms
        }
        case = build_research_case_corpus()["cases"][0]
        atom_refs = [
            item for item in case["evidence"]
            if item["evidence_ref"].startswith("evidence:")
        ]

        self.assertLessEqual(
            {item["evidence_ref"] for item in atom_refs}, set(replayed)
        )
        for reference in atom_refs:
            atom = replayed[reference["evidence_ref"]]
            self.assertEqual(
                reference["source_artifact_sha256"],
                atom.source_span.artifact_sha256,
            )
            self.assertEqual(reference["locator"], atom.source_span.locator)
            self.assertEqual(reference["capability"], atom.capability)
            self.assertEqual(
                reference["producer"],
                "{}@{}".format(atom.producer, atom.producer_version),
            )
        selected = {
            "GetStaticRouteCfg", "SetStaticRouteCfg", "SetOnlineDevName",
            "getOnlineList", "setBlackRule", "delBlackRule",
        }
        self.assertTrue(selected <= {item.value for item in shallow.hints})
        self.assertFalse(selected & {item.value for item in dhttpd.hints})

    def test_real_x5000r_case_evidence_replays_from_current_producers(self) -> None:
        from scripts.build_mapping_corpus_report import X5000R_ROOT
        from scripts.build_x5000r_set_difference_report import build_analysis
        from scripts.build_x5000r_expanded_frontend_report import (
            build_analysis as build_expanded_analysis,
        )
        from scripts.build_x5000r_nested_dispatch_report import (
            build_analysis as build_nested_analysis,
        )
        from scripts.build_x5000r_request_protection_report import (
            build_analysis as build_protection_analysis,
        )
        from scripts.build_x5000r_service_assembly_report import (
            build_analysis as build_service_assembly_analysis,
        )

        if not X5000R_ROOT.exists():
            self.skipTest("local X5000R representative sample is unavailable")

        def analyze(relative_path, producer):
            content = (X5000R_ROOT / relative_path).read_bytes()
            source = SourceArtifactEntry(
                relative_path, relative_path, "file", len(content),
                hashlib.sha256(content).hexdigest(),
            )
            return producer(source, content)

        frontend_assets = []
        for relative_path in (
            "www/static/js/config.js",
            "www/static/js/config_ie.js",
            "www/static/js/topicurl.js",
        ):
            content = (X5000R_ROOT / relative_path).read_bytes()
            frontend_assets.append(FrontendAssetInput(
                SourceArtifactEntry(
                    relative_path, relative_path, "file", len(content),
                    hashlib.sha256(content).hexdigest(),
                ),
                content,
            ))
        frontend_graph = discover_frontend_asset_graph(tuple(frontend_assets))
        selector_anchors = tuple(
            NativeRouteAnchor(
                parameter.request_candidate_id, parameter.literal_value
            )
            for result in frontend_graph.results
            for parameter in result.parameters
            if parameter.is_operation_selector
            and parameter.source_construct == "shared-cgi.topicurl"
        )
        binary_content = (X5000R_ROOT / "www/cgi-bin/cstecgi.cgi").read_bytes()
        binary_source = SourceArtifactEntry(
            "www/cgi-bin/cstecgi.cgi", "www/cgi-bin/cstecgi.cgi", "file",
            len(binary_content), hashlib.sha256(binary_content).hexdigest(),
        )
        deep = discover_mips_inline_route_bindings(
            binary_source, binary_content, selector_anchors
        )
        value_flow = discover_mips_handler_value_flows(
            binary_source, binary_content, 0x004209B8
        )
        _, _, set_difference = build_analysis(X5000R_ROOT)
        (
            _, expanded_frontend, _, _, _, expanded_difference
        ) = build_expanded_analysis(X5000R_ROOT)
        *_, nested_dispatch = build_nested_analysis(X5000R_ROOT)
        _, _, protection = build_protection_analysis(X5000R_ROOT)
        _, _, service_assembly = build_service_assembly_analysis(X5000R_ROOT)
        results = (
            *frontend_graph.results,
            analyze("lighttp/lighttpd.conf", discover_web_configuration),
            analyze("www/cgi-bin/cstecgi.cgi", discover_native_hints),
            deep,
            value_flow,
            set_difference,
            *expanded_frontend.results,
            expanded_difference,
            nested_dispatch,
            protection,
            service_assembly,
        )
        replayed = {
            atom.evidence_id: atom
            for result in results
            for atom in result.evidence_atoms
        }
        case = build_research_case_corpus()["cases"][1]
        references = [
            item for item in case["evidence"]
            if item["evidence_ref"].startswith("evidence:")
        ]

        self.assertLessEqual(
            {item["evidence_ref"] for item in references}, set(replayed)
        )
        for reference in references:
            atom = replayed[reference["evidence_ref"]]
            self.assertEqual(reference["locator"], atom.source_span.locator)
            self.assertEqual(reference["capability"], atom.capability)
            self.assertEqual(
                reference["producer"],
                "{}@{}".format(atom.producer, atom.producer_version),
            )
        self.assertEqual(1, len(frontend_graph.bindings))
        self.assertEqual(
            199,
            sum(
                parameter.is_operation_selector
                for result in frontend_graph.results
                for parameter in result.parameters
                if parameter.source_construct == "shared-cgi.topicurl"
            ),
        )
        obligations = {
            item["obligation_id"]: item for item in case["obligations"]
        }
        self.assertEqual(
            "resolved",
            obligations["obligation:x5000r-cross-resource-endpoint"]["status"],
        )
        self.assertEqual(
            "open", obligations["obligation:x5000r-selector-handler"]["status"]
        )
        self.assertEqual(
            "resolved",
            obligations["obligation:x5000r-setlancfg-prefix-value-flow"]["status"],
        )
        self.assertEqual(
            "open", obligations["obligation:x5000r-branched-value-flow"]["status"]
        )
        self.assertEqual(
            "resolved",
            obligations["obligation:x5000r-set-difference-shape"]["status"],
        )
        self.assertEqual(
            "resolved",
            obligations["obligation:x5000r-frontend-scope-expansion"]["status"],
        )
        self.assertEqual(
            "resolved", obligations["obligation:x5000r-upload-mode-owner"]["status"]
        )
        self.assertEqual(
            "open",
            obligations["obligation:x5000r-upload-runtime-reachability"]["status"],
        )
        self.assertEqual(
            "rejected", obligations["obligation:x5000r-upload-auth-guard"]["status"]
        )
        self.assertEqual(
            "resolved",
            obligations["obligation:x5000r-static-service-assembly"]["status"],
        )
        self.assertEqual(124, len(deep.bindings))
        self.assertEqual(123, len({item.route_token for item in deep.bindings}))
        coverage = next(
            item for item in case["evidence"]
            if item["evidence_ref"]
            == "coverage:x5000r-mips-dispatch-set-difference"
        )
        report_path = Path(coverage["source_path"])
        self.assertTrue(report_path.is_file())
        self.assertEqual(
            coverage["source_artifact_sha256"],
            hashlib.sha256(report_path.read_bytes()).hexdigest(),
        )
        hidden_coverage = next(
            item for item in case["evidence"]
            if item["evidence_ref"]
            == "coverage:x5000r-potential-hidden-interfaces"
        )
        hidden_report_path = Path(hidden_coverage["source_path"])
        self.assertTrue(hidden_report_path.is_file())
        self.assertEqual(
            hidden_coverage["source_artifact_sha256"],
            hashlib.sha256(hidden_report_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(12, case["stages"][-1]["order"])
        expanded_coverage = next(
            item for item in case["evidence"]
            if item["evidence_ref"]
            == "coverage:x5000r-expanded-frontend-scope"
        )
        expanded_report_path = Path(expanded_coverage["source_path"])
        self.assertTrue(expanded_report_path.is_file())
        self.assertEqual(
            expanded_coverage["source_artifact_sha256"],
            hashlib.sha256(expanded_report_path.read_bytes()).hexdigest(),
        )
        nested_coverage = next(
            item for item in case["evidence"]
            if item["evidence_ref"] == "coverage:x5000r-nested-upload-dispatch"
        )
        nested_report_path = Path(nested_coverage["source_path"])
        self.assertTrue(nested_report_path.is_file())
        self.assertEqual(
            nested_coverage["source_artifact_sha256"],
            hashlib.sha256(nested_report_path.read_bytes()).hexdigest(),
        )
        protection_coverage = next(
            item for item in case["evidence"]
            if item["evidence_ref"] == "coverage:x5000r-request-protection"
        )
        protection_report_path = Path(protection_coverage["source_path"])
        self.assertTrue(protection_report_path.is_file())
        self.assertEqual(
            protection_coverage["source_artifact_sha256"],
            hashlib.sha256(protection_report_path.read_bytes()).hexdigest(),
        )
        assembly_coverage = next(
            item for item in case["evidence"]
            if item["evidence_ref"] == "coverage:x5000r-service-assembly"
        )
        assembly_report_path = Path(assembly_coverage["source_path"])
        self.assertTrue(assembly_report_path.is_file())
        self.assertEqual(
            assembly_coverage["source_artifact_sha256"],
            hashlib.sha256(assembly_report_path.read_bytes()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
