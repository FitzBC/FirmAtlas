import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from firmatlas.mapping import (
    BinwalkExtractor,
    ExtractionPolicy,
    ExtractionRequest,
    ExtractionStatus,
    InventoryPolicy,
    ToolIdentity,
    WorkerExecution,
)


class SuccessfulFakeBinwalkWorker:
    def __init__(self):
        self.requests = []

    def probe(self):
        return ToolIdentity(name="binwalk", version="3.1.0")

    def extract(self, request):
        self.requests.append(request)
        output = request.destination / "extractions" / "squashfs-root" / "www"
        output.mkdir(parents=True)
        (output / "index.js").write_text("fetch('/HNAP1')\n", encoding="utf-8")
        return WorkerExecution(
            exit_code=0,
            timed_out=False,
            argv=("binwalk", "-Me", "/input/firmware.bin"),
            stdout="extracted squashfs",
            stderr="",
            enforced_limits=("no_network", "output_bytes", "output_files", "wall_time"),
        )


class TimedOutFakeBinwalkWorker:
    def probe(self):
        return ToolIdentity(name="binwalk", version="3.1.0")

    def extract(self, request):
        request.destination.mkdir(parents=True, exist_ok=True)
        (request.destination / "partial.txt").write_text("partial", encoding="utf-8")
        return WorkerExecution(
            exit_code=-9,
            timed_out=True,
            argv=("binwalk", "-Me", "/input/firmware.bin"),
            stdout="partial extraction",
            stderr="worker timeout",
            enforced_limits=("no_network", "output_bytes", "output_files", "wall_time"),
        )


class MissingBinwalkWorker:
    def __init__(self):
        self.extract_called = False

    def probe(self):
        raise FileNotFoundError("binwalk")

    def extract(self, request):
        self.extract_called = True
        raise AssertionError("extract must not run after a failed probe")


class UnexpectedCommandWorker(SuccessfulFakeBinwalkWorker):
    def extract(self, request):
        execution = super().extract(request)
        return WorkerExecution(
            exit_code=execution.exit_code,
            timed_out=execution.timed_out,
            argv=("sh", "-c", "binwalk -Me /input/firmware.bin"),
            stdout=execution.stdout,
            stderr=execution.stderr,
            enforced_limits=execution.enforced_limits,
        )


class UnverifiedLimitsWorker(SuccessfulFakeBinwalkWorker):
    def extract(self, request):
        execution = super().extract(request)
        return WorkerExecution(
            exit_code=execution.exit_code,
            timed_out=execution.timed_out,
            argv=execution.argv,
            stdout=execution.stdout,
            stderr=execution.stderr,
            enforced_limits=("wall_time",),
        )


class CrashedBinwalkWorker(SuccessfulFakeBinwalkWorker):
    def extract(self, request):
        raise RuntimeError("container runtime stopped")


class EscapingSymlinkWorker(SuccessfulFakeBinwalkWorker):
    def extract(self, request):
        execution = super().extract(request)
        (request.destination / "escape").symlink_to("../../outside")
        return execution


class BinwalkExtractorContractTests(unittest.TestCase):
    def test_successful_extraction_links_worker_evidence_to_a_source_inventory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = root / "firmware.bin"
            artifact.write_bytes(b"firmware-image")
            artifact_sha256 = hashlib.sha256(b"firmware-image").hexdigest()
            worker = SuccessfulFakeBinwalkWorker()
            destination = root / "derived"
            extractor = BinwalkExtractor(worker)

            result = extractor.extract(
                ExtractionRequest(
                    artifact_path=artifact,
                    artifact_sha256=artifact_sha256,
                    destination=destination,
                    policy=ExtractionPolicy(
                        max_seconds=120,
                        inventory_policy=InventoryPolicy(max_files=100),
                    ),
                )
            )

            self.assertEqual(ExtractionStatus.SUCCESS, result.status)
            self.assertEqual(artifact_sha256, result.parent_artifact_sha256)
            self.assertEqual(ToolIdentity("binwalk", "3.1.0"), result.tool)
            self.assertEqual(
                ["extractions/squashfs-root/www/index.js"],
                [entry.canonical_path for entry in result.inventory.entries],
            )
            self.assertEqual("completed", result.inventory.coverage_status.value)
            self.assertRegex(result.execution_fingerprint, r"^[0-9a-f]{64}$")
            self.assertEqual(1, len(worker.requests))
            self.assertEqual(artifact.resolve(), worker.requests[0].artifact_path)
            self.assertEqual(destination.resolve(), worker.requests[0].destination)
            self.assertEqual(120, worker.requests[0].max_seconds)

            payload = result.to_dict()
            self.assertEqual(
                "firmatlas.mapping.extraction/v1alpha1", payload["schema_version"]
            )
            self.assertEqual("success", payload["status"])
            self.assertEqual("3.1.0", payload["tool"]["version"])
            self.assertEqual(
                result.inventory.inventory_sha256,
                payload["inventory"]["inventory_sha256"],
            )
            self.assertNotIn("stdout", payload["execution"])
            self.assertNotIn("stderr", payload["execution"])
            self.assertRegex(payload["execution"]["stdout_sha256"], r"^[0-9a-f]{64}$")
            self.assertIsInstance(json.dumps(payload), str)

    def test_timeout_preserves_partial_derived_artifacts_and_diagnostic(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = root / "firmware.bin"
            artifact.write_bytes(b"firmware-image")
            artifact_sha256 = hashlib.sha256(b"firmware-image").hexdigest()

            result = BinwalkExtractor(TimedOutFakeBinwalkWorker()).extract(
                ExtractionRequest(
                    artifact_path=artifact,
                    artifact_sha256=artifact_sha256,
                    destination=root / "derived",
                )
            )

            self.assertEqual(ExtractionStatus.PARTIAL_SUCCESS, result.status)
            self.assertEqual(
                ["partial.txt"],
                [entry.canonical_path for entry in result.inventory.entries],
            )
            self.assertEqual(
                ["extraction.worker_timeout"],
                [diagnostic.code for diagnostic in result.diagnostics],
            )

    def test_missing_binwalk_is_a_structured_failed_result(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = root / "firmware.bin"
            artifact.write_bytes(b"firmware-image")
            artifact_sha256 = hashlib.sha256(b"firmware-image").hexdigest()
            worker = MissingBinwalkWorker()

            result = BinwalkExtractor(worker).extract(
                ExtractionRequest(
                    artifact_path=artifact,
                    artifact_sha256=artifact_sha256,
                    destination=root / "derived",
                )
            )

            self.assertEqual(ExtractionStatus.FAILED, result.status)
            self.assertEqual(ToolIdentity("binwalk", "unavailable"), result.tool)
            self.assertIsNone(result.inventory)
            self.assertFalse(worker.extract_called)
            self.assertEqual(
                ["extraction.tool_unavailable"],
                [diagnostic.code for diagnostic in result.diagnostics],
            )

    def test_worker_execution_must_attest_the_expected_binwalk_command(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = root / "firmware.bin"
            artifact.write_bytes(b"firmware-image")
            artifact_sha256 = hashlib.sha256(b"firmware-image").hexdigest()

            result = BinwalkExtractor(UnexpectedCommandWorker()).extract(
                ExtractionRequest(
                    artifact_path=artifact,
                    artifact_sha256=artifact_sha256,
                    destination=root / "derived",
                )
            )

            self.assertEqual(ExtractionStatus.FAILED, result.status)
            self.assertIsNone(result.inventory)
            self.assertEqual(
                ["extraction.unexpected_command"],
                [diagnostic.code for diagnostic in result.diagnostics],
            )

    def test_worker_must_attest_isolation_and_resource_limits(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = root / "firmware.bin"
            artifact.write_bytes(b"firmware-image")

            result = BinwalkExtractor(UnverifiedLimitsWorker()).extract(
                ExtractionRequest(
                    artifact_path=artifact,
                    artifact_sha256=hashlib.sha256(b"firmware-image").hexdigest(),
                    destination=root / "derived",
                )
            )

            self.assertEqual(ExtractionStatus.FAILED, result.status)
            self.assertIsNone(result.inventory)
            self.assertEqual(
                ["extraction.worker_limits_unverified"],
                [diagnostic.code for diagnostic in result.diagnostics],
            )

    def test_worker_crash_is_contained_as_a_structured_failure(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = root / "firmware.bin"
            artifact.write_bytes(b"firmware-image")

            result = BinwalkExtractor(CrashedBinwalkWorker()).extract(
                ExtractionRequest(
                    artifact_path=artifact,
                    artifact_sha256=hashlib.sha256(b"firmware-image").hexdigest(),
                    destination=root / "derived",
                )
            )

            self.assertEqual(ExtractionStatus.FAILED, result.status)
            self.assertIsNone(result.inventory)
            self.assertEqual(
                ["extraction.worker_crashed"],
                [diagnostic.code for diagnostic in result.diagnostics],
            )

    def test_digest_mismatch_stops_before_worker_or_destination_mutation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = root / "firmware.bin"
            artifact.write_bytes(b"firmware-image")
            worker = SuccessfulFakeBinwalkWorker()
            destination = root / "derived"

            with self.assertRaisesRegex(ValueError, "digest does not match"):
                BinwalkExtractor(worker).extract(
                    ExtractionRequest(
                        artifact_path=artifact,
                        artifact_sha256="0" * 64,
                        destination=destination,
                    )
                )

            self.assertFalse(destination.exists())
            self.assertEqual([], worker.requests)

    def test_unsafe_derived_output_downgrades_success_to_partial(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = root / "firmware.bin"
            artifact.write_bytes(b"firmware-image")

            result = BinwalkExtractor(EscapingSymlinkWorker()).extract(
                ExtractionRequest(
                    artifact_path=artifact,
                    artifact_sha256=hashlib.sha256(b"firmware-image").hexdigest(),
                    destination=root / "derived",
                )
            )

            self.assertEqual(ExtractionStatus.PARTIAL_SUCCESS, result.status)
            self.assertEqual("partial", result.inventory.coverage_status.value)
            self.assertIn(
                "inventory.symlink_escape",
                [diagnostic.code for diagnostic in result.inventory.diagnostics],
            )


if __name__ == "__main__":
    unittest.main()
