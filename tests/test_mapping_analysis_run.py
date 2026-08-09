import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout

from firmatlas.mapping import (
    CoverageStatus,
    DiscoveryCandidateKind,
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    MappingAnalyzerRegistry,
    SchedulerTermination,
    analyze_extracted_root,
)
from firmatlas.mapping.__main__ import main as mapping_main


class MappingAnalysisRunContractTests(unittest.TestCase):
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
            (root / "etc/nginx").mkdir(parents=True)
            (root / "etc/nginx/nginx.conf").write_text(
                'server { listen 80; root /www; }', encoding="utf-8"
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
                "web_configuration",
                "script_backend", "native", "native_ubus_registration",
                "arm_pic_callsite", "ubus_backend", "scheduler", "catalog",
            },
            {stage.stage_name for stage in first.stages},
        )
        self.assertEqual(
            SchedulerTermination.FIXED_POINT,
            first.catalog.scheduler_termination,
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
        self.assertEqual(("native",), kinds["usr/sbin/uhttpd"])
        self.assertEqual(("native",), kinds["www/cgi-bin/tool.cgi"])

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
        self.assertEqual("firmatlas.mapping.profile/auto-v3", result.profile_id)
        self.assertEqual(
            "firmatlas.mapping.analyzer-registry/builtin-v3",
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
        } <= routes)
        samba_handler = next(
            item for item in result.catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.NATIVE_HANDLER
            and item.canonical_identity == "bin/httpd@0x000a5258"
        )
        self.assertEqual(
            "formSetSambaConf", dict(samba_handler.attributes)["handler_symbol"]
        )
        stage = next(
            item for item in result.stages if item.stage_name == "arm_pic_callsite"
        )
        self.assertEqual(CoverageStatus.COMPLETED, stage.coverage_status)
        self.assertGreaterEqual(stage.output_count, 5)


if __name__ == "__main__":
    unittest.main()
