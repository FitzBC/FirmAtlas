import hashlib
import io
from pathlib import Path
import tempfile
import unittest

from firmatlas.mapping import (
    BinwalkExtractor,
    DiscoveryCatalogRepository,
    ExtractionPolicy,
    FirmwareArtifactAnalysisRequest,
    FirmwareMappingJobService,
    FirmwareMappingJobPolicy,
    FirmwareMappingJobSnapshot,
    FirmwareMappingJobStatus,
    FirmwareMappingJobStore,
    MappingReleaseContext,
    ToolIdentity,
    WorkerExecution,
    analyze_firmware_artifact,
)


class InlineExecutor:
    def submit(self, function, *args):
        function(*args)


class RootfsWorker:
    def probe(self):
        return ToolIdentity(name="binwalk", version="3.1.0")

    def extract(self, request):
        root = request.destination / "firmware.bin.extracted" / "squashfs-root"
        (root / "www").mkdir(parents=True)
        (root / "www" / "index.html").write_text(
            '<form action="/goform/Apply" method="post">'
            '<input name="mode"></form>',
            encoding="utf-8",
        )
        return WorkerExecution(
            exit_code=0,
            timed_out=False,
            argv=("binwalk", "-Me", "/input/firmware.bin"),
            stdout="",
            stderr="",
            enforced_limits=("no_network", "output_bytes", "output_files", "wall_time"),
        )


class FakeRunner:
    runner_id = "test-runner/v1"

    def __init__(self):
        self.artifacts = []

    def run(self, artifact_path: Path, extraction_destination: Path):
        self.artifacts.append(artifact_path.read_bytes())
        return analyze_firmware_artifact(
            FirmwareArtifactAnalysisRequest(
                artifact_path=artifact_path,
                extraction_destination=extraction_destination,
                extraction_policy=ExtractionPolicy(max_seconds=30),
            ),
            BinwalkExtractor(RootfsWorker()),
        )


class FirmwareMappingJobServiceContractTests(unittest.TestCase):
    def test_upload_budget_and_content_length_are_enforced_before_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FirmwareMappingJobStore(":memory:")
            mappings = DiscoveryCatalogRepository(":memory:")
            runner = FakeRunner()
            service = FirmwareMappingJobService(
                Path(directory), store, mappings, runner,
                policy=FirmwareMappingJobPolicy(
                    max_upload_bytes=8, upload_chunk_bytes=4,
                ),
                executor=InlineExecutor(),
            )

            with self.assertRaisesRegex(ValueError, "exceeds size budget"):
                service.submit(io.BytesIO(b"123456789"), "ac9.trx", 9)
            with self.assertRaisesRegex(ValueError, "ended early"):
                service.submit(io.BytesIO(b"123"), "ac9.trx", 4)

            self.assertEqual([], runner.artifacts)
            self.assertEqual((), service.list())
            service.close()
            mappings.close()

    def test_same_artifact_and_runner_reuses_one_job_and_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            store = FirmwareMappingJobStore(":memory:")
            mappings = DiscoveryCatalogRepository(":memory:")
            runner = FakeRunner()
            service = FirmwareMappingJobService(
                Path(directory), store, mappings, runner, executor=InlineExecutor(),
            )

            first = service.submit(io.BytesIO(b"same AC9"), "ac9-a.trx", 8)
            second = service.submit(io.BytesIO(b"same AC9"), "ac9-b.trx", 8)

            self.assertEqual(first.job_id, second.job_id)
            self.assertEqual([b"same AC9"], runner.artifacts)
            self.assertEqual(1, len(service.list()))
            service.close()
            mappings.close()

    def test_reopening_store_marks_interrupted_active_job_as_failed(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "firmatlas.db")
            store = FirmwareMappingJobStore(database)
            snapshot = FirmwareMappingJobSnapshot(
                job_id="firmware-mapping-job:" + "c" * 64,
                original_filename="ac9.trx",
                firmware_artifact_sha256="d" * 64,
                artifact_size=1024,
                runner_id="test-runner/v1",
                status=FirmwareMappingJobStatus.RUNNING,
                submitted_at="2026-08-18T00:00:00+00:00",
                started_at="2026-08-18T00:00:01+00:00",
            )
            store.create(snapshot)
            store.close()

            recovered_store = FirmwareMappingJobStore(database)
            recovered = recovered_store.get(snapshot.job_id)

            self.assertEqual(FirmwareMappingJobStatus.FAILED, recovered.status)
            self.assertEqual("job.interrupted", recovered.error_code)
            self.assertIsNotNone(recovered.finished_at)
            recovered_store.close()

    def test_submitted_artifact_runs_in_background_and_publishes_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            store = FirmwareMappingJobStore(":memory:")
            mappings = DiscoveryCatalogRepository(":memory:")
            runner = FakeRunner()
            service = FirmwareMappingJobService(
                workspace, store, mappings, runner, executor=InlineExecutor(),
            )

            release = MappingReleaseContext(
                vendor="Tenda", product="AC9", device_model="AC9",
                firmware_version="V15.03.05.19(6318)",
                source_ref="user-upload:ac9.trx",
                evidence="User supplied firmware identity at upload time.",
            )
            submitted = service.submit(
                io.BytesIO(b"uploaded AC9 firmware"), "../../ac9.trx", 21,
                release_context=release,
            )
            observed = service.get(submitted.job_id)

            self.assertEqual(FirmwareMappingJobStatus.COMPLETED, observed.status)
            self.assertEqual("ac9.trx", observed.original_filename)
            self.assertEqual(
                hashlib.sha256(b"uploaded AC9 firmware").hexdigest(),
                observed.firmware_artifact_sha256,
            )
            self.assertEqual([b"uploaded AC9 firmware"], runner.artifacts)
            self.assertIsNotNone(observed.artifact_analysis_id)
            self.assertIsNotNone(observed.catalog_id)
            self.assertIsNotNone(observed.graph_id)
            self.assertEqual(release, observed.release_context)
            self.assertEqual(1, mappings.list_catalogs()["total"])
            self.assertEqual(
                "Tenda",
                mappings.list_catalogs()["items"][0]["release_context"]["vendor"],
            )
            self.assertEqual(1, mappings.list_communication_graphs()["total"])
            self.assertTrue((workspace / "runs" / observed.job_id.split(":", 1)[1]
                             / "analysis.json").is_file())

            service.close()
            mappings.close()


if __name__ == "__main__":
    unittest.main()
