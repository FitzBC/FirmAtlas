import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout

from firmatlas.mapping import (
    BUILTIN_ANALYZER_REGISTRY,
    BUILTIN_ANALYZER_REGISTRY_V19,
    BUILTIN_ANALYZER_REGISTRY_V18,
    BUILTIN_ANALYZER_REGISTRY_V17,
    BUILTIN_ANALYZER_REGISTRY_V16,
    BUILTIN_ANALYZER_REGISTRY_V15,
    BUILTIN_ANALYZER_REGISTRY_V14,
    BUILTIN_ANALYZER_REGISTRY_V13,
    CoverageStatus,
    CommunicationGraphEdgeKind,
    DiscoveryCandidateKind,
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    MappingAnalyzerRegistry,
    SchedulerTermination,
    analyze_extracted_root,
    build_potential_hidden_interface_index,
    project_communication_architecture_graph,
)
from firmatlas.mapping.__main__ import main as mapping_main


class MappingAnalysisRunContractTests(unittest.TestCase):
    def test_current_default_profile_and_registry_have_frozen_v19_aliases(self):
        self.assertEqual(
            MappingAnalysisProfile.auto(), MappingAnalysisProfile.auto_v19()
        )
        self.assertEqual(
            BUILTIN_ANALYZER_REGISTRY, BUILTIN_ANALYZER_REGISTRY_V19
        )
        self.assertNotEqual(
            MappingAnalysisProfile.auto_v19(), MappingAnalysisProfile.auto_v18()
        )
        self.assertNotEqual(
            BUILTIN_ANALYZER_REGISTRY_V19, BUILTIN_ANALYZER_REGISTRY_V18
        )

    AC9_ROOT = Path(
        "var/mapping-work/ac9-version-diff/extractions/openwrt-19.07.8/"
        "extractions/firmware.bin.extracted/0/partition_1.bin.extracted/0/squashfs-root"
    )
    TENDA_AC9_ROOT = (
        Path(__file__).resolve().parents[2]
        / "iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root"
    )
    def test_extracted_root_runs_selected_producers_and_publishes_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "www").mkdir()
            (root / "www/index.html").write_text(
                '<form action="/admin/apply" method="post">'
                '<input name="hostname"></form>',
                encoding="utf-8",
            )
            (root / "www/status.php").write_text(
                '<?php $mode = $_POST["mode"]; ?>', encoding="utf-8"
            )
            (root / "www/goform").mkdir()
            (root / "www/goform/GetStatus.txt").write_text(
                '{"status":"ready"}', encoding="utf-8"
            )
            (root / "etc/nginx").mkdir(parents=True)
            (root / "etc/nginx/nginx.conf").write_text(
                'server { listen 80; root /www; }', encoding="utf-8"
            )
            (root / "bin").mkdir()
            (root / "bin/time_check").write_bytes(
                b"\x7fELF\x01\x01" + b"\x00" * 58
                + b"cfm post netctrl 51?op=6\x00"
            )
            artifact_sha256 = hashlib.sha256(b"uploaded-firmware").hexdigest()

            first = analyze_extracted_root(MappingAnalysisRequest(
                root=root, firmware_artifact_sha256=artifact_sha256
            ))
            second = analyze_extracted_root(MappingAnalysisRequest(
                root=root, firmware_artifact_sha256=artifact_sha256
            ))

        self.assertEqual(first.analysis_run_id, second.analysis_run_id)
        self.assertEqual(first.catalog.catalog_id, second.catalog.catalog_id)
        self.assertEqual(CoverageStatus.COMPLETED, first.inventory_coverage_status)
        self.assertEqual(
            {
                "inventory", "source_plan", "frontend", "frontend_asset_graph",
                "frontend_feature_gate",
                "frontend_reachability",
                "web_configuration",
                "script_backend", "native", "native_ubus_registration",
                "arm_pic_callsite", "arm_pic_registrar", "set_difference",
                "parameter_clue", "response_fixture", "ubus_backend",
                "native_relationship",
                "native_command_binding",
                "native_cgi_dispatch",
                "native_pointer_command_binding",
                "native_cross_elf_call",
                "native_configuration_text_import_flow",
                "native_configuration_url_document_flow",
                "native_configuration_url_ipc_flow",
                "arm_literal_xref",
                "arm_feature_pivot",
                "scheduler", "catalog",
            },
            {stage.stage_name for stage in first.stages},
        )
        stage_names = tuple(stage.stage_name for stage in first.stages)
        self.assertLess(
            stage_names.index("frontend_asset_graph"),
            stage_names.index("frontend_feature_gate"),
        )
        self.assertLess(
            stage_names.index("frontend_feature_gate"),
            stage_names.index("frontend_reachability"),
        )
        self.assertLess(
            stage_names.index("frontend_reachability"),
            stage_names.index("parameter_clue"),
        )
        self.assertEqual(
            SchedulerTermination.FIXED_POINT,
            first.catalog.scheduler_termination,
        )
        self.assertIn(
            "goform/GetStatus",
            {
                item.canonical_identity
                for item in first.catalog.candidates
                if item.candidate_kind
                is DiscoveryCandidateKind.RESPONSE_FIXTURE_CONTRACT
            },
        )
        self.assertIn(
            "bin/time_check|post|netctrl|topic=51|op=6",
            {
                item.canonical_identity
                for item in first.catalog.candidates
                if item.candidate_kind is DiscoveryCandidateKind.NATIVE_RELATIONSHIP
            },
        )
        self.assertIn(
            "/admin/apply",
            {
                item.canonical_identity
                for item in first.catalog.candidates
                if item.candidate_kind is DiscoveryCandidateKind.REQUEST_INTERFACE
            },
        )
        self.assertIn("hostname", {item.name for item in first.catalog.parameters})
        self.assertIn("mode", {item.name for item in first.catalog.parameters})
        self.assertEqual(
            {"/admin/apply|hostname"},
            {
                item.canonical_identity
                for item in first.catalog.candidates
                if item.candidate_kind
                is DiscoveryCandidateKind.PARAMETER_CLUE_ASSESSMENT
            },
        )
        self.assertTrue(first.source_plan)

    def test_producer_failure_is_preserved_in_a_partial_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "www").mkdir()
            (root / "www/broken.js").write_bytes(b"\xff\xfe")

            result = analyze_extracted_root(MappingAnalysisRequest(
                root=root, firmware_artifact_sha256="b" * 64
            ))

        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        frontend = next(
            stage for stage in result.stages if stage.stage_name == "frontend"
        )
        self.assertEqual(CoverageStatus.PARTIAL, frontend.coverage_status)
        self.assertIn("frontend.invalid_utf8", frontend.diagnostics)
        self.assertEqual(0, len(result.catalog.candidates))

    def test_auto_profile_attributes_requests_to_a_disabled_frontend_feature(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "webroot_ro/js").mkdir(parents=True)
            (root / "webroot_ro/js/macro_config.js").write_text(
                'var CONFIG_DLNA_SERVER="n";', encoding="utf-8"
            )
            (root / "webroot_ro/js/main.js").write_text(
                '''var modulesObj={"usb_dlna":CONFIG_DLNA_SERVER},prop;
if(modulesObj[prop]=="y"){$("#"+prop).removeClass("none");}
case "usb_dlna":showIframe("DLNA","dlna.html",620,450);''',
                encoding="utf-8",
            )
            (root / "webroot_ro/dlna.html").write_text(
                '<script src="js/dlna.js"></script>', encoding="utf-8"
            )
            (root / "webroot_ro/js/dlna.js").write_text(
                '$.getJSON("goform/GetDlnaCfg", cb);', encoding="utf-8"
            )

            result = analyze_extracted_root(MappingAnalysisRequest(
                root=root,
                firmware_artifact_sha256=hashlib.sha256(
                    b"feature-gated-firmware"
                ).hexdigest(),
            ))

        stage = next(
            item for item in result.stages
            if item.stage_name == "frontend_feature_gate"
        )
        self.assertEqual(CoverageStatus.COMPLETED, stage.coverage_status)
        self.assertEqual(1, stage.output_count)
        candidate = next(
            item for item in result.catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.FRONTEND_FEATURE_GATE
        )
        self.assertEqual("CONFIG_DLNA_SERVER", candidate.canonical_identity)
        self.assertEqual("disabled", dict(candidate.attributes)["gate_status"])

    def test_auto_profile_publishes_frontend_invocation_reachability(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "www/js").mkdir(parents=True)
            (root / "www/js/page.js").write_text(
                '''function refreshDLNA() {
  $.post("/goform/refreshDLNA", "action=1", callback);
}
// $("#refresh").on("click", refreshDLNA);''',
                encoding="utf-8",
            )

            result = analyze_extracted_root(MappingAnalysisRequest(
                root=root,
                firmware_artifact_sha256="a" * 64,
            ))

        stage = next(
            item for item in result.stages
            if item.stage_name == "frontend_reachability"
        )
        self.assertEqual(CoverageStatus.COMPLETED, stage.coverage_status)
        self.assertEqual(1, stage.output_count)
        candidate = next(
            item for item in result.catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.FRONTEND_INVOCATION
        )
        attributes = dict(candidate.attributes)
        self.assertEqual("declared_but_unreached", attributes["status"])
        self.assertEqual("refreshDLNA", attributes["function_name"])
        self.assertEqual("1", attributes["commented_reference_count"])

    def test_reachability_profile_does_not_require_asset_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "page.js").write_text(
                '$.post("/goform/Direct", "value=1", callback);',
                encoding="utf-8",
            )
            profile = MappingAnalysisProfile(
                "firmatlas.mapping.profile/test-reachability-v1",
                ("frontend", "frontend_reachability"),
            )

            result = analyze_extracted_root(MappingAnalysisRequest(
                root=root,
                firmware_artifact_sha256="f" * 64,
                profile=profile,
            ))

        self.assertNotIn(
            "frontend_asset_graph",
            {item.stage_name for item in result.stages},
        )
        stage = next(
            item for item in result.stages
            if item.stage_name == "frontend_reachability"
        )
        self.assertEqual(CoverageStatus.COMPLETED, stage.coverage_status)
        self.assertEqual(1, stage.output_count)

    def test_cli_writes_full_run_and_prints_a_bounded_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rootfs"
            root.mkdir()
            (root / "index.html").write_text(
                '<form action="/apply"><input name="token"></form>',
                encoding="utf-8",
            )
            output = Path(directory) / "run.json"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = mapping_main((
                    "analyze-root", str(root), "--artifact-sha256", "c" * 64,
                    "--output", str(output), "--profile", "base",
                ))

            summary = json.loads(stdout.getvalue())
            document = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(0, exit_code)
        self.assertEqual(document["analysis_run_id"], summary["analysis_run_id"])
        self.assertEqual(1, summary["candidate_count"])
        self.assertEqual(1, summary["parameter_count"])
        self.assertEqual(str(output), summary["output"])
        self.assertEqual("firmatlas.mapping.profile/base-v1", summary["profile_id"])

    def test_elf_paths_are_not_misrouted_to_text_producers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "usr/sbin").mkdir(parents=True)
            (root / "www/cgi-bin").mkdir(parents=True)
            elf = b"\x7fELF\x01\x01\x01" + b"\x00" * 80
            (root / "usr/sbin/uhttpd").write_bytes(elf)
            (root / "www/cgi-bin/tool.cgi").write_bytes(elf)

            result = analyze_extracted_root(MappingAnalysisRequest(
                root=root, firmware_artifact_sha256="d" * 64
            ))

        kinds = {item.source_path: item.analyzer_kinds for item in result.source_plan}
        self.assertEqual(
            ("native", "native_relationship"), kinds["usr/sbin/uhttpd"]
        )
        self.assertEqual(
            ("native", "native_relationship"), kinds["www/cgi-bin/tool.cgi"]
        )

    def test_auto_profile_closes_real_ac9_native_ubus_registration_work(self):
        if not self.AC9_ROOT.is_dir():
            self.skipTest("local OpenWrt AC9 rootfs is unavailable")

        result = analyze_extracted_root(MappingAnalysisRequest(
            root=self.AC9_ROOT,
            firmware_artifact_sha256=(
                "d40b191c95c5b6e43358785d6c6e9d7915296e9a954d27fbc1936bdf48568ec9"
            ),
            profile=MappingAnalysisProfile.auto(),
        ))

        bindings = [
            item for item in result.catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.UBUS_BACKEND_BINDING
            and dict(item.attributes).get("binding_status")
            == "verified_native_registration"
        ]
        self.assertEqual(31, len(bindings))
        self.assertNotIn(
            "resolve_ubus_registration_table",
            {item.required_capability for item in result.catalog.open_obligations},
        )
        stage = next(
            item for item in result.stages
            if item.stage_name == "native_ubus_registration"
        )
        self.assertEqual(CoverageStatus.COMPLETED, stage.coverage_status)
        self.assertEqual(4, stage.output_count)
        self.assertEqual("firmatlas.mapping.profile/auto-v19", result.profile_id)
        self.assertEqual(
            "firmatlas.mapping.analyzer-registry/builtin-v19",
            result.analyzer_registry_id,
        )

    def test_profile_cannot_request_an_analyzer_missing_from_registry(self):
        registry = MappingAnalyzerRegistry(
            "firmatlas.mapping.analyzer-registry/test-v1", ("frontend",)
        )
        with self.assertRaisesRegex(ValueError, "unavailable analyzers"):
            analyze_extracted_root(
                MappingAnalysisRequest(
                    root=Path("does-not-need-to-exist"),
                    firmware_artifact_sha256="e" * 64,
                    profile=MappingAnalysisProfile.auto(),
                ),
                registry=registry,
            )

    def test_auto_profile_deepens_primary_vendor_tenda_ac9_arm_routes(self):
        if not self.TENDA_AC9_ROOT.is_dir():
            self.skipTest("local vendor Tenda AC9 rootfs is unavailable")

        result = analyze_extracted_root(MappingAnalysisRequest(
            root=self.TENDA_AC9_ROOT,
            firmware_artifact_sha256="981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296",
            profile=MappingAnalysisProfile.auto(),
        ))

        routes = {
            item.canonical_identity
            for item in result.catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.NATIVE_ROUTE_BINDING
        }
        self.assertTrue({
            "SetOnlineDevName", "setBlackRule", "delBlackRule",
            "getOnlineList", "getBlackRuleList", "SetSambaCfg",
            "GetUSBStatus",
        } <= routes)
        samba_handler = next(
            item for item in result.catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.NATIVE_HANDLER
            and item.canonical_identity == "bin/httpd@0x000a5258"
        )
        self.assertEqual(
            "formSetSambaConf", dict(samba_handler.attributes)["handler_symbol"]
        )
        usb_status_handler = next(
            item for item in result.catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.NATIVE_HANDLER
            and item.canonical_identity == "bin/httpd@0x000a62d0"
        )
        self.assertEqual(
            "formGetUSBStatus",
            dict(usb_status_handler.attributes)["handler_symbol"],
        )
        upload_dispatch = next(
            item for item in result.catalog.candidates
            if (
                item.candidate_kind
                is DiscoveryCandidateKind.NATIVE_CGI_DISPATCH
                and item.canonical_identity == "UploadCfg"
            )
        )
        self.assertEqual(
            "/cgi-bin/UploadCfg",
            dict(upload_dispatch.attributes)["interface_path"],
        )
        self.assertEqual(
            "bin/httpd@0x0003b850",
            dict(upload_dispatch.attributes)["handler_identity"],
        )
        self.assertEqual(
            "6", dict(upload_dispatch.attributes)["dispatcher_entry_count"]
        )
        cgi_stage = next(
            item for item in result.stages
            if item.stage_name == "native_cgi_dispatch"
        )
        self.assertEqual(CoverageStatus.COMPLETED, cgi_stage.coverage_status)
        self.assertGreaterEqual(cgi_stage.output_count, 1)
        expected_callsite = {
            "tpi_upfile_handle": "0x0003ba38",
            "tpi_sys_cfg_upload": "0x00009ef4",
            "doSystemCmd": "0x00009d68",
            "UploadValue": "0x00009e64",
            "SendMsg": "0x00004334",
            "RecvMsg": "0x00004374",
        }
        cross_calls = {
            attributes["imported_symbol"]: item
            for item in result.catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.NATIVE_CROSS_ELF_CALL
            if (attributes := dict(item.attributes)).get("imported_symbol")
            in expected_callsite
            and attributes.get("callsite_address")
            == expected_callsite[attributes["imported_symbol"]]
        }
        self.assertEqual(
            {
                "tpi_upfile_handle", "tpi_sys_cfg_upload", "doSystemCmd",
                "UploadValue", "SendMsg", "RecvMsg",
            },
            set(cross_calls),
        )
        self.assertEqual(
            '["cfm Upload"]',
            dict(cross_calls["doSystemCmd"].attributes)["argument_literals"],
        )
        upload_command = next(
            item for item in result.catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.NATIVE_COMMAND_BINDING
            and dict(item.attributes).get("command") == "Upload"
        )
        graph = project_communication_architecture_graph(result.catalog)
        call_edges = {
            (edge.source_ref, edge.target_ref)
            for edge in graph.edges
            if edge.edge_kind is CommunicationGraphEdgeKind.CALLS
        }
        self.assertIn(
            (cross_calls["tpi_upfile_handle"].candidate_id,
             cross_calls["tpi_sys_cfg_upload"].candidate_id),
            call_edges,
        )
        self.assertIn(
            (cross_calls["doSystemCmd"].candidate_id,
             upload_command.candidate_id),
            call_edges,
        )
        self.assertIn(
            (upload_command.candidate_id,
             cross_calls["UploadValue"].candidate_id),
            call_edges,
        )
        text_flow = next(
            item for item in result.catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.NATIVE_CONFIGURATION_TEXT_IMPORT_FLOW
        )
        text_attributes = dict(text_flow.attributes)
        self.assertEqual("cfm Upload", text_attributes["import_command"])
        self.assertEqual(
            "lib/libCfm.so@0x0000588c", text_attributes["restore_identity"]
        )
        self.assertEqual(
            "cfm/default_mib/*", text_attributes["state_scope"]
        )
        text_stage = next(
            item for item in result.stages
            if item.stage_name == "native_configuration_text_import_flow"
        )
        self.assertEqual(CoverageStatus.COMPLETED, text_stage.coverage_status)
        self.assertEqual(1, text_stage.output_count)
        feature_gate_stage = next(
            item for item in result.stages
            if item.stage_name == "frontend_feature_gate"
        )
        self.assertEqual(
            CoverageStatus.COMPLETED, feature_gate_stage.coverage_status
        )
        self.assertEqual(3, feature_gate_stage.output_count)
        dlna_gate = next(
            item for item in result.catalog.candidates
            if (
                item.candidate_kind
                is DiscoveryCandidateKind.FRONTEND_FEATURE_GATE
                and item.canonical_identity == "CONFIG_DLNA_SERVER"
            )
        )
        dlna_gate_attributes = dict(dlna_gate.attributes)
        self.assertEqual("disabled", dlna_gate_attributes["gate_status"])
        self.assertEqual("n", dlna_gate_attributes["configured_value"])
        self.assertEqual("y", dlna_gate_attributes["enabled_value"])
        self.assertEqual("usb_dlna", dlna_gate_attributes["ui_target_id"])
        self.assertEqual(
            [
                "/goform/refreshDLNA",
                "goform/GetDlnaCfg",
                "goform/SetDlnaCfg",
                "goform/expandDlnaFile?",
            ],
            json.loads(dlna_gate_attributes["request_endpoints"]),
        )
        feature_disabled = {
            item.canonical_identity
            for item in result.catalog.candidates
            if (
                item.candidate_kind
                is DiscoveryCandidateKind.SET_DIFFERENCE_ATTRIBUTION
                and dict(item.attributes)["attribution_kind"]
                == "frontend_feature_disabled"
            )
        }
        self.assertEqual(
            {
                "GetDlnaCfg",
                "SetDlnaCfg",
                "expandDlnaFile",
                "refreshDLNA",
            },
            feature_disabled,
        )
        usb_status_binding = next(
            item for item in result.catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.NATIVE_ROUTE_BINDING
            and item.canonical_identity == "GetUSBStatus"
        )
        usb_status_literals = {
            dict(item.attributes)["literal_value"]
            for item in result.catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.ARM_LITERAL_XREF
            and dict(item.attributes)["target_ref"]
            == usb_status_binding.candidate_id
        }
        self.assertTrue(
            {"dlna.en", "/var/etc/upan", "dlna"} <= usb_status_literals
        )
        stage = next(
            item for item in result.stages if item.stage_name == "arm_pic_callsite"
        )
        self.assertEqual(CoverageStatus.COMPLETED, stage.coverage_status)
        self.assertGreaterEqual(stage.output_count, 5)
        registrar_stage = next(
            item for item in result.stages
            if item.stage_name == "arm_pic_registrar"
        )
        self.assertEqual(CoverageStatus.COMPLETED, registrar_stage.coverage_status)
        self.assertEqual(188, registrar_stage.output_count)
        hidden = build_potential_hidden_interface_index(result.catalog)
        self.assertEqual(CoverageStatus.COMPLETED, hidden.coverage_status)
        self.assertEqual(84, len(hidden.items))
        self.assertNotIn(
            "GetUSBStatus",
            {item.operation_token for item in hidden.items},
        )
        hidden_tokens = {item.operation_token for item in hidden.items}
        self.assertIn("GetDeviceDetail", hidden_tokens)
        self.assertNotIn("SetSambaCfg", hidden_tokens)
        self.assertFalse({
            "setUsbUnload", "setNotUpgrade", "setPptpUserList",
        } & hidden_tokens)
        recovered = {
            item.canonical_identity: dict(item.attributes).get("handler_symbol")
            for item in result.catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.NATIVE_ROUTE_BINDING
            and item.canonical_identity in {"GetUpnpCfg", "GetSySLogCfg"}
        }
        self.assertEqual({
            "GetUpnpCfg": "formGetUpnpLists",
            "GetSySLogCfg": "formGetSysLog",
        }, recovered)
        command_binding = next(
            item for item in result.catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.NATIVE_COMMAND_BINDING
        )
        self.assertEqual(
            "bin/time_check|minidlna|handler=0x00015868",
            command_binding.canonical_identity,
        )
        self.assertEqual(
            "cfm post netctrl 51?op=6",
            dict(command_binding.attributes)["command"],
        )
        command_stage = next(
            item for item in result.stages
            if item.stage_name == "native_command_binding"
        )
        self.assertEqual(CoverageStatus.COMPLETED, command_stage.coverage_status)
        self.assertEqual(1, command_stage.output_count)
        xref_stage = next(
            item for item in result.stages
            if item.stage_name == "arm_literal_xref"
        )
        self.assertEqual(CoverageStatus.COMPLETED, xref_stage.coverage_status)
        self.assertEqual(14, xref_stage.output_count)
        self.assertEqual(
            {"/var/etc/upan", "time_check_daemon_minidlna"},
            {
                dict(item.attributes)["literal_value"]
                for item in result.catalog.candidates
                if item.candidate_kind is DiscoveryCandidateKind.ARM_LITERAL_XREF
                and dict(item.attributes)["function_identity"]
                == "bin/time_check@0x00015868"
            },
        )
        feature_pivot_stage = next(
            item for item in result.stages
            if item.stage_name == "arm_feature_pivot"
        )
        self.assertEqual(
            CoverageStatus.COMPLETED, feature_pivot_stage.coverage_status
        )
        self.assertEqual(21, feature_pivot_stage.output_count)
        feature_pivots = [
            item for item in result.catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.ARM_FEATURE_PIVOT
        ]
        dlna_pivots = [
            item for item in feature_pivots
            if dict(item.attributes)["feature_token"] == "dlna"
        ]
        self.assertEqual(3, len(dlna_pivots))
        self.assertEqual(
            {"dlna", "dlna.en"},
            {dict(item.attributes)["literal_value"] for item in dlna_pivots},
        )
        self.assertEqual(
            {"GetUSBStatus"},
            {dict(item.attributes)["route_token"] for item in dlna_pivots},
        )
        self.assertEqual(
            {"formGetUSBStatus"},
            {dict(item.attributes)["handler_symbol"] for item in dlna_pivots},
        )
        self.assertTrue(all(
            item.claim_status.value == "candidate" for item in dlna_pivots
        ))
        reachability_stage = next(
            item for item in result.stages
            if item.stage_name == "frontend_reachability"
        )
        self.assertEqual(
            CoverageStatus.COMPLETED, reachability_stage.coverage_status
        )
        self.assertEqual(134, reachability_stage.output_count)
        dlna_invocations = {
            item.canonical_identity: dict(item.attributes)
            for item in result.catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.FRONTEND_INVOCATION
            and item.canonical_identity in {
                "/goform/refreshDLNA",
                "goform/GetDlnaCfg",
                "goform/SetDlnaCfg",
                "goform/expandDlnaFile?",
            }
        }
        self.assertEqual(
            "declared_but_unreached",
            dlna_invocations["/goform/refreshDLNA"]["status"],
        )
        self.assertEqual(
            "1",
            dlna_invocations["/goform/refreshDLNA"][
                "commented_reference_count"
            ],
        )
        self.assertEqual(
            "active_call_path",
            dlna_invocations["goform/expandDlnaFile?"]["status"],
        )
        self.assertEqual(
            '["initEvent","getMoreFolder"]',
            dlna_invocations["goform/expandDlnaFile?"]["call_path"],
        )


if __name__ == "__main__":
    unittest.main()
