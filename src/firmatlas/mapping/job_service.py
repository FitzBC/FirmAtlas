"""Persistent asynchronous orchestration for user-supplied firmware artifacts."""

from __future__ import annotations

from concurrent.futures import Executor, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from pathlib import Path
import sqlite3
import threading
from typing import BinaryIO, Optional, Protocol, Tuple
import uuid

from .analysis_run import MappingAnalysisProfile
from .communication_graph import (
    CommunicationGraphPolicy,
    project_communication_architecture_graph,
)
from .container_worker import ContainerBinwalkConfig, ContainerBinwalkWorker
from .extraction import BinwalkExtractor, ExtractionPolicy, FirmwareExtractor
from .firmware_artifact_analysis import (
    FirmwareArtifactAnalysisRequest,
    FirmwareArtifactAnalysisRun,
    FirmwareArtifactAnalysisStatus,
    analyze_firmware_artifact,
)
from .repository import DiscoveryCatalogRepository
from .snapshot_diff import MappingReleaseContext


FIRMWARE_MAPPING_JOB_SCHEMA_VERSION = "firmatlas.mapping.job/v1alpha1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class FirmwareMappingJobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class FirmwareMappingJobPolicy:
    max_upload_bytes: int = 64 * 1024 * 1024
    upload_chunk_bytes: int = 1024 * 1024

    def __post_init__(self) -> None:
        if self.max_upload_bytes <= 0 or self.upload_chunk_bytes <= 0:
            raise ValueError("firmware mapping job upload budgets must be positive")
        if self.upload_chunk_bytes > self.max_upload_bytes:
            raise ValueError("upload chunk budget cannot exceed upload size budget")


@dataclass(frozen=True)
class FirmwareMappingJobSnapshot:
    job_id: str
    original_filename: str
    firmware_artifact_sha256: str
    artifact_size: int
    runner_id: str
    status: FirmwareMappingJobStatus
    submitted_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    artifact_analysis_id: Optional[str] = None
    catalog_id: Optional[str] = None
    graph_id: Optional[str] = None
    error_code: Optional[str] = None
    release_context: Optional[MappingReleaseContext] = None
    schema_version: str = FIRMWARE_MAPPING_JOB_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "job_id": self.job_id,
            "original_filename": self.original_filename,
            "firmware_artifact_sha256": self.firmware_artifact_sha256,
            "artifact_size": self.artifact_size,
            "runner_id": self.runner_id,
            "status": self.status.value,
            "submitted_at": self.submitted_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "artifact_analysis_id": self.artifact_analysis_id,
            "catalog_id": self.catalog_id,
            "graph_id": self.graph_id,
            "error_code": self.error_code,
            "release_context": (
                self.release_context.to_dict()
                if self.release_context is not None else None
            ),
        }


class FirmwareMappingJobRunner(Protocol):
    runner_id: str

    def run(
        self, artifact_path: Path, extraction_destination: Path,
    ) -> FirmwareArtifactAnalysisRun:
        ...


@dataclass(frozen=True)
class FirmwareMappingRuntimeConfig:
    workspace: Path
    runtime_path: Path
    image_ref: str
    expected_version: str = "3.1.0"
    max_upload_bytes: int = 64 * 1024 * 1024
    max_analysis_seconds: int = 900

    def __post_init__(self) -> None:
        object.__setattr__(self, "workspace", Path(self.workspace))
        object.__setattr__(self, "runtime_path", Path(self.runtime_path))
        if not self.image_ref.strip() or not self.expected_version.strip():
            raise ValueError("firmware mapping runtime requires image and version")
        if self.max_upload_bytes <= 0 or self.max_analysis_seconds <= 0:
            raise ValueError("firmware mapping runtime budgets must be positive")


class FirmwareArtifactJobRunner:
    """Adapter from one stored artifact to the raw-artifact analysis module."""

    def __init__(
        self,
        runner_id: str,
        extractor: FirmwareExtractor,
        extraction_policy: ExtractionPolicy = ExtractionPolicy(),
        mapping_profile: MappingAnalysisProfile = MappingAnalysisProfile.auto(),
    ) -> None:
        if not runner_id.strip():
            raise ValueError("firmware mapping runner requires identity")
        self.runner_id = runner_id
        self._extractor = extractor
        self._extraction_policy = extraction_policy
        self._mapping_profile = mapping_profile

    def run(
        self, artifact_path: Path, extraction_destination: Path,
    ) -> FirmwareArtifactAnalysisRun:
        return analyze_firmware_artifact(
            FirmwareArtifactAnalysisRequest(
                artifact_path=artifact_path,
                extraction_destination=extraction_destination,
                extraction_policy=self._extraction_policy,
                mapping_profile=self._mapping_profile,
            ),
            self._extractor,
        )


class FirmwareMappingJobStore:
    """SQLite Adapter for mutable orchestration state, separate from Analysis Run facts."""

    def __init__(self, database: str = "var/firmatlas.db") -> None:
        if database != ":memory:":
            Path(database).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(
            database, check_same_thread=False, timeout=10,
        )
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS firmware_mapping_jobs (
                    job_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    firmware_artifact_sha256 TEXT NOT NULL,
                    artifact_size INTEGER NOT NULL,
                    runner_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    submitted_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    artifact_analysis_id TEXT,
                    catalog_id TEXT,
                    graph_id TEXT,
                    error_code TEXT,
                    release_context_json TEXT
                )
                """
            )
            columns = {
                row[1] for row in self._connection.execute(
                    "PRAGMA table_info(firmware_mapping_jobs)"
                ).fetchall()
            }
            if "release_context_json" not in columns:
                self._connection.execute(
                    "ALTER TABLE firmware_mapping_jobs ADD COLUMN release_context_json TEXT"
                )
            self._connection.execute(
                """
                UPDATE firmware_mapping_jobs
                SET status = ?, finished_at = ?, error_code = ?
                WHERE status IN (?, ?)
                """,
                (
                    FirmwareMappingJobStatus.FAILED.value,
                    _utc_now(),
                    "job.interrupted",
                    FirmwareMappingJobStatus.QUEUED.value,
                    FirmwareMappingJobStatus.RUNNING.value,
                ),
            )
            self._connection.commit()

    def create(
        self, snapshot: FirmwareMappingJobSnapshot,
    ) -> Tuple[FirmwareMappingJobSnapshot, bool]:
        with self._lock:
            cursor = self._connection.execute(
                """
                INSERT OR IGNORE INTO firmware_mapping_jobs (
                    job_id, schema_version, original_filename,
                    firmware_artifact_sha256, artifact_size, runner_id, status,
                    submitted_at, started_at, finished_at, artifact_analysis_id,
                    catalog_id, graph_id, error_code, release_context_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                self._values(snapshot),
            )
            self._connection.commit()
            observed = self.get(snapshot.job_id)
            assert observed is not None
            return observed, cursor.rowcount == 1

    def update(self, snapshot: FirmwareMappingJobSnapshot) -> None:
        with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE firmware_mapping_jobs SET
                    schema_version = ?, original_filename = ?,
                    firmware_artifact_sha256 = ?, artifact_size = ?,
                    runner_id = ?, status = ?, submitted_at = ?, started_at = ?,
                    finished_at = ?, artifact_analysis_id = ?, catalog_id = ?,
                    graph_id = ?, error_code = ?, release_context_json = ?
                WHERE job_id = ?
                """,
                self._values(snapshot)[1:] + (snapshot.job_id,),
            )
            if cursor.rowcount != 1:
                self._connection.rollback()
                raise KeyError(snapshot.job_id)
            self._connection.commit()

    def get(self, job_id: str) -> Optional[FirmwareMappingJobSnapshot]:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM firmware_mapping_jobs WHERE job_id = ?", (job_id,),
            ).fetchone()
        return self._snapshot(row) if row is not None else None

    def list(self, limit: int = 20) -> Tuple[FirmwareMappingJobSnapshot, ...]:
        if limit <= 0:
            raise ValueError("firmware mapping job list limit must be positive")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM firmware_mapping_jobs
                ORDER BY submitted_at DESC, job_id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return tuple(self._snapshot(row) for row in rows)

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    @staticmethod
    def _values(snapshot: FirmwareMappingJobSnapshot) -> tuple:
        return (
            snapshot.job_id,
            snapshot.schema_version,
            snapshot.original_filename,
            snapshot.firmware_artifact_sha256,
            snapshot.artifact_size,
            snapshot.runner_id,
            snapshot.status.value,
            snapshot.submitted_at,
            snapshot.started_at,
            snapshot.finished_at,
            snapshot.artifact_analysis_id,
            snapshot.catalog_id,
            snapshot.graph_id,
            snapshot.error_code,
            json.dumps(snapshot.release_context.to_dict(), ensure_ascii=False)
            if snapshot.release_context is not None else None,
        )

    @staticmethod
    def _snapshot(row: sqlite3.Row) -> FirmwareMappingJobSnapshot:
        return FirmwareMappingJobSnapshot(
            job_id=row["job_id"],
            schema_version=row["schema_version"],
            original_filename=row["original_filename"],
            firmware_artifact_sha256=row["firmware_artifact_sha256"],
            artifact_size=row["artifact_size"],
            runner_id=row["runner_id"],
            status=FirmwareMappingJobStatus(row["status"]),
            submitted_at=row["submitted_at"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            artifact_analysis_id=row["artifact_analysis_id"],
            catalog_id=row["catalog_id"],
            graph_id=row["graph_id"],
            error_code=row["error_code"],
            release_context=(
                MappingReleaseContext(**json.loads(row["release_context_json"]))
                if row["release_context_json"] else None
            ),
        )


class FirmwareMappingJobService:
    """Deep module from a bounded upload stream to published mapping read models."""

    def __init__(
        self,
        workspace: Path,
        store: FirmwareMappingJobStore,
        mappings: DiscoveryCatalogRepository,
        runner: FirmwareMappingJobRunner,
        policy: FirmwareMappingJobPolicy = FirmwareMappingJobPolicy(),
        executor: Optional[Executor] = None,
        graph_policy: CommunicationGraphPolicy = CommunicationGraphPolicy(),
    ) -> None:
        self._workspace = Path(workspace)
        self._workspace.mkdir(parents=True, exist_ok=True)
        if self._workspace.is_symlink():
            raise ValueError("firmware mapping workspace cannot be a symbolic link")
        self._workspace = self._workspace.resolve()
        self._artifacts = self._workspace / "artifacts"
        self._uploads = self._workspace / "uploads"
        self._runs = self._workspace / "runs"
        for directory in (self._artifacts, self._uploads, self._runs):
            directory.mkdir(parents=True, exist_ok=True)
        self._store = store
        self._mappings = mappings
        self._runner = runner
        self._policy = policy
        self._graph_policy = graph_policy
        self._submit_lock = threading.Lock()
        self._owns_executor = executor is None
        self._executor = executor or ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="firmware-mapping",
        )

    @property
    def max_upload_bytes(self) -> int:
        return self._policy.max_upload_bytes

    def submit(
        self, stream: BinaryIO, original_filename: str, content_length: int,
        release_context: Optional[MappingReleaseContext] = None,
    ) -> FirmwareMappingJobSnapshot:
        filename = self._safe_filename(original_filename)
        if content_length <= 0:
            raise ValueError("firmware artifact upload must not be empty")
        if content_length > self._policy.max_upload_bytes:
            raise ValueError("firmware artifact upload exceeds size budget")
        with self._submit_lock:
            temporary = self._uploads / ("." + uuid.uuid4().hex + ".part")
            digest = hashlib.sha256()
            remaining = content_length
            try:
                with temporary.open("xb") as destination:
                    while remaining:
                        chunk = stream.read(min(remaining, self._policy.upload_chunk_bytes))
                        if not chunk:
                            raise ValueError("firmware artifact upload ended early")
                        if len(chunk) > remaining:
                            raise ValueError("firmware artifact upload exceeded Content-Length")
                        destination.write(chunk)
                        digest.update(chunk)
                        remaining -= len(chunk)
                artifact_sha256 = digest.hexdigest()
                artifact_path = self._artifacts / (artifact_sha256 + ".bin")
                if artifact_path.exists() and self._sha256(artifact_path) == artifact_sha256:
                    temporary.unlink()
                else:
                    temporary.replace(artifact_path)
            finally:
                if temporary.exists():
                    temporary.unlink()

            job_digest = hashlib.sha256(json.dumps(
                {
                    "firmware_artifact_sha256": artifact_sha256,
                    "runner_id": self._runner.runner_id,
                    "release_context": (
                        release_context.to_dict() if release_context else None
                    ),
                },
                separators=(",", ":"), sort_keys=True,
            ).encode("utf-8")).hexdigest()
            snapshot, created = self._store.create(FirmwareMappingJobSnapshot(
                job_id="firmware-mapping-job:" + job_digest,
                original_filename=filename,
                firmware_artifact_sha256=artifact_sha256,
                artifact_size=content_length,
                runner_id=self._runner.runner_id,
                status=FirmwareMappingJobStatus.QUEUED,
                submitted_at=_utc_now(),
                release_context=release_context,
            ))
            if created:
                self._executor.submit(self._execute, snapshot.job_id, artifact_path)
            return self.get(snapshot.job_id) or snapshot

    def get(self, job_id: str) -> Optional[FirmwareMappingJobSnapshot]:
        return self._store.get(job_id)

    def list(self, limit: int = 20) -> Tuple[FirmwareMappingJobSnapshot, ...]:
        return self._store.list(limit)

    def close(self) -> None:
        if self._owns_executor:
            self._executor.shutdown(wait=True, cancel_futures=False)
        self._store.close()

    def _execute(self, job_id: str, artifact_path: Path) -> None:
        current = self._store.get(job_id)
        if current is None:
            return
        running = FirmwareMappingJobSnapshot(
            **{
                **current.__dict__,
                "status": FirmwareMappingJobStatus.RUNNING,
                "started_at": _utc_now(),
            }
        )
        self._store.update(running)
        run_directory = self._runs / job_id.split(":", 1)[1]
        run_directory.mkdir(parents=True, exist_ok=True)
        try:
            analysis = self._runner.run(
                artifact_path, run_directory / "extraction",
            )
            self._write_json_atomic(
                run_directory / "analysis.json", analysis.to_dict(),
            )
            if analysis.mapping_run is None:
                self._store.update(FirmwareMappingJobSnapshot(
                    **{
                        **running.__dict__,
                        "status": FirmwareMappingJobStatus.FAILED,
                        "finished_at": _utc_now(),
                        "artifact_analysis_id": analysis.artifact_analysis_id,
                        "error_code": "analysis." + analysis.status.value,
                    }
                ))
                return
            graph = project_communication_architecture_graph(
                analysis.mapping_run.catalog, self._graph_policy,
            )
            self._write_json_atomic(run_directory / "graph.json", graph.to_dict())
            self._mappings.publish(analysis.mapping_run.catalog)
            self._mappings.publish_communication_graph(graph)
            if running.release_context is not None:
                self._mappings.register_release_context(
                    analysis.mapping_run.catalog.catalog_id,
                    running.release_context,
                )
            status = (
                FirmwareMappingJobStatus.COMPLETED
                if analysis.status is FirmwareArtifactAnalysisStatus.COMPLETED
                else FirmwareMappingJobStatus.PARTIAL
            )
            self._store.update(FirmwareMappingJobSnapshot(
                **{
                    **running.__dict__,
                    "status": status,
                    "finished_at": _utc_now(),
                    "artifact_analysis_id": analysis.artifact_analysis_id,
                    "catalog_id": analysis.mapping_run.catalog.catalog_id,
                    "graph_id": graph.graph_id,
                }
            ))
        except Exception:
            self._store.update(FirmwareMappingJobSnapshot(
                **{
                    **running.__dict__,
                    "status": FirmwareMappingJobStatus.FAILED,
                    "finished_at": _utc_now(),
                    "error_code": "job.runner_failed",
                }
            ))

    @staticmethod
    def _safe_filename(value: str) -> str:
        filename = value.replace("\\", "/").rsplit("/", 1)[-1].strip()
        if (
            not filename or len(filename) > 255
            or any(ord(character) < 32 for character in filename)
        ):
            raise ValueError("firmware artifact filename is invalid")
        return filename

    @staticmethod
    def _write_json_atomic(path: Path, document: dict) -> None:
        temporary = path.with_name("." + path.name + ".tmp")
        temporary.write_text(
            json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


def create_container_firmware_mapping_job_service(
    database: str,
    mappings: DiscoveryCatalogRepository,
    config: FirmwareMappingRuntimeConfig,
) -> FirmwareMappingJobService:
    """Compose the production container, runner, store, and job module once."""

    container = ContainerBinwalkConfig(
        runtime_path=config.runtime_path,
        image_ref=config.image_ref,
        expected_version=config.expected_version,
    )
    profile = MappingAnalysisProfile.auto()
    runner = FirmwareArtifactJobRunner(
        runner_id="container-binwalk:{}:{}:{}".format(
            container.image_digest, config.expected_version, profile.profile_id,
        ),
        extractor=BinwalkExtractor(ContainerBinwalkWorker(container)),
        extraction_policy=ExtractionPolicy(max_seconds=config.max_analysis_seconds),
        mapping_profile=profile,
    )
    return FirmwareMappingJobService(
        workspace=config.workspace,
        store=FirmwareMappingJobStore(database),
        mappings=mappings,
        runner=runner,
        policy=FirmwareMappingJobPolicy(
            max_upload_bytes=config.max_upload_bytes,
        ),
    )
