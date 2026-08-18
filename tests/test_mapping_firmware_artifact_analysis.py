import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from firmatlas.mapping import (
    BinwalkExtractor,
    ExtractionPolicy,
    FirmwareArtifactAnalysisRequest,
    FirmwareArtifactAnalysisStatus,
    ToolIdentity,
    WorkerExecution,
    analyze_firmware_artifact,
)
from firmatlas.mapping.__main__ import main as mapping_main
from firmatlas.cli import main as firmatlas_main


class SuccessfulRootfsWorker:
    def probe(self):
        return ToolIdentity(name="binwalk", version="3.1.0")

    def extract(self, request):
        root = request.destination / "0" / "firmware.bin.extracted" / "squashfs-root"
        (root / "www").mkdir(parents=True)
        (root / "www" / "index.html").write_text(
            '<form action="/goform/Apply" method="post"><input name="mode"></form>',
            encoding="utf-8",
        )
        (root / "bin").mkdir()
        (root / "bin" / "httpd").write_bytes(b"\x7fELF\x01\x01" + b"\x00" * 58)
        return WorkerExecution(
            exit_code=0,
            timed_out=False,
            argv=("binwalk", "-Me", "/input/firmware.bin"),
            stdout="",
            stderr="",
            enforced_limits=("no_network", "output_bytes", "output_files", "wall_time"),
        )


class EmptyRootfsWorker:
    def probe(self):
        return ToolIdentity(name="binwalk", version="3.1.0")

    def extract(self, request):
        (request.destination / "payload.txt").write_text("not a rootfs", encoding="utf-8")
        return WorkerExecution(
            exit_code=0,
            timed_out=False,
            argv=("binwalk", "-Me", "/input/firmware.bin"),
            stdout="",
            stderr="",
            enforced_limits=("no_network", "output_bytes", "output_files", "wall_time"),
        )


class AmbiguousRootfsWorker:
    def probe(self):
        return ToolIdentity(name="binwalk", version="3.1.0")

    def extract(self, request):
        for name in ("first", "second"):
            root = request.destination / name / "squashfs-root"
            (root / "www").mkdir(parents=True)
            (root / "www" / "index.html").write_text("ok", encoding="utf-8")
        return WorkerExecution(
            exit_code=0,
            timed_out=False,
            argv=("binwalk", "-Me", "/input/firmware.bin"),
            stdout="",
            stderr="",
            enforced_limits=("no_network", "output_bytes", "output_files", "wall_time"),
        )


class FirmwareArtifactAnalysisContractTests(unittest.TestCase):
    def test_raw_artifact_runs_extraction_selects_root_and_publishes_mapping_run(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            artifact = workspace / "firmware.bin"
            artifact.write_bytes(b"uploaded firmware")
            result = analyze_firmware_artifact(
                FirmwareArtifactAnalysisRequest(
                    artifact_path=artifact,
                    extraction_destination=workspace / "derived",
                    extraction_policy=ExtractionPolicy(max_seconds=30),
                ),
                BinwalkExtractor(SuccessfulRootfsWorker()),
            )

        self.assertEqual(FirmwareArtifactAnalysisStatus.COMPLETED, result.status)
        self.assertEqual(
            hashlib.sha256(b"uploaded firmware").hexdigest(),
            result.firmware_artifact_sha256,
        )
        self.assertEqual(
            "0/firmware.bin.extracted/squashfs-root", result.selected_root_path,
        )
        self.assertIsNotNone(result.mapping_run)
        self.assertIn(
            "/goform/Apply",
            {item.canonical_identity for item in result.mapping_run.catalog.candidates},
        )
        payload = result.to_dict()
        self.assertEqual("completed", payload["status"])
        self.assertEqual(result.mapping_run.analysis_run_id, payload["analysis_run_id"])
        self.assertNotIn("artifact_path", payload)

    def test_successful_extraction_without_a_rootfs_is_explicit_not_analyzed(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            artifact = workspace / "firmware.bin"
            artifact.write_bytes(b"not a recognized root")
            result = analyze_firmware_artifact(
                FirmwareArtifactAnalysisRequest(
                    artifact_path=artifact,
                    extraction_destination=workspace / "derived",
                ),
                BinwalkExtractor(EmptyRootfsWorker()),
            )

        self.assertEqual(FirmwareArtifactAnalysisStatus.NO_ROOTFS, result.status)
        self.assertIsNone(result.mapping_run)
        self.assertEqual(("analysis.rootfs_not_found",), result.diagnostic_codes)

    def test_equally_plausible_roots_remain_explicitly_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            artifact = workspace / "firmware.bin"
            artifact.write_bytes(b"ambiguous root")
            result = analyze_firmware_artifact(
                FirmwareArtifactAnalysisRequest(
                    artifact_path=artifact,
                    extraction_destination=workspace / "derived",
                ),
                BinwalkExtractor(AmbiguousRootfsWorker()),
            )

        self.assertEqual(FirmwareArtifactAnalysisStatus.AMBIGUOUS_ROOTFS, result.status)
        self.assertIsNone(result.selected_root_path)
        self.assertIsNone(result.mapping_run)
        self.assertEqual(("analysis.rootfs_ambiguous",), result.diagnostic_codes)

    def test_cli_analyze_artifact_writes_replayable_run_and_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            artifact = workspace / "firmware.bin"
            artifact.write_bytes(b"cli uploaded firmware")
            output = workspace / "raw-analysis.json"
            graph_output = workspace / "communication-graph.json"
            stream = io.StringIO()
            with patch(
                "firmatlas.mapping.__main__.ContainerBinwalkWorker",
                side_effect=lambda _config: SuccessfulRootfsWorker(),
            ), redirect_stdout(stream):
                exit_code = mapping_main((
                    "analyze-artifact", str(artifact),
                    "--destination", str(workspace / "derived"),
                    "--runtime", "/usr/local/bin/docker",
                    "--image-ref", "example.invalid/binwalk@sha256:" + "a" * 64,
                    "--output", str(output),
                    "--graph-output", str(graph_output),
                ))

            payload = json.loads(output.read_text(encoding="utf-8"))
            summary = json.loads(stream.getvalue())
            graph = json.loads(graph_output.read_text(encoding="utf-8"))

        self.assertEqual(0, exit_code)
        self.assertEqual("completed", payload["status"])
        self.assertEqual(payload["analysis_run_id"], summary["analysis_run_id"])
        self.assertEqual(summary["graph_id"], graph["graph_id"])
        self.assertEqual("0/firmware.bin.extracted/squashfs-root", payload["selected_root_path"])

    def test_publishing_a_raw_artifact_result_uses_its_nested_mapping_run(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            artifact = workspace / "firmware.bin"
            artifact.write_bytes(b"publish artifact result")
            result = analyze_firmware_artifact(
                FirmwareArtifactAnalysisRequest(
                    artifact_path=artifact,
                    extraction_destination=workspace / "derived",
                ),
                BinwalkExtractor(SuccessfulRootfsWorker()),
            )
            result_path = workspace / "raw-analysis.json"
            result_path.write_text(
                json.dumps(result.to_dict()), encoding="utf-8",
            )
            from firmatlas.mapping import project_communication_architecture_graph
            graph = project_communication_architecture_graph(result.mapping_run.catalog)
            graph_path = workspace / "graph.json"
            graph_path.write_text(json.dumps(graph.to_dict()), encoding="utf-8")
            stream = io.StringIO()
            with redirect_stdout(stream):
                exit_code = firmatlas_main((
                    "mapping", "publish-graph", "--database", str(workspace / "firmatlas.db"),
                    "--catalog-document", str(result_path), str(graph_path),
                ))
            payload = json.loads(stream.getvalue())

        self.assertEqual(0, exit_code)
        self.assertEqual(result.mapping_run.catalog.catalog_id, payload["catalog"]["catalog_id"])
        self.assertEqual(graph.graph_id, payload["graph"]["graph_id"])


if __name__ == "__main__":
    unittest.main()
