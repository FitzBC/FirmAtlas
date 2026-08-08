"""Isolated firmware extraction orchestration and Binwalk adapter contract."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import json
from pathlib import Path
import re
from typing import Optional, Protocol, Tuple

from .domain import CoverageStatus
from .inventory import InventoryPolicy, SourceInventory, build_inventory


EXTRACTION_SCHEMA_VERSION = "firmatlas.mapping.extraction/v1alpha1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_LIMITS = frozenset(
    {"wall_time", "output_files", "output_bytes", "no_network"}
)


class ExtractionStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"


@dataclass(frozen=True)
class ToolIdentity:
    name: str
    version: str


@dataclass(frozen=True)
class ExtractionPolicy:
    max_seconds: int = 900
    inventory_policy: InventoryPolicy = field(default_factory=InventoryPolicy)

    def __post_init__(self) -> None:
        if self.max_seconds <= 0:
            raise ValueError("max_seconds must be positive")


@dataclass(frozen=True)
class ExtractionRequest:
    artifact_path: Path
    artifact_sha256: str
    destination: Path
    policy: ExtractionPolicy = field(default_factory=ExtractionPolicy)


@dataclass(frozen=True)
class WorkerExtractionRequest:
    artifact_path: Path
    destination: Path
    max_seconds: int
    max_output_files: int
    max_output_bytes: int
    no_network: bool = True
    recursive: bool = True


@dataclass(frozen=True)
class WorkerExecution:
    exit_code: int
    timed_out: bool
    argv: Tuple[str, ...]
    stdout: str
    stderr: str
    enforced_limits: Tuple[str, ...]


class ExtractionWorker(Protocol):
    def probe(self) -> ToolIdentity:
        ...

    def extract(self, request: WorkerExtractionRequest) -> WorkerExecution:
        ...


@dataclass(frozen=True)
class ExtractionDiagnostic:
    code: str
    message: str


@dataclass(frozen=True)
class ExtractionResult:
    parent_artifact_sha256: str
    status: ExtractionStatus
    tool: ToolIdentity
    execution_fingerprint: str
    execution: WorkerExecution
    policy: ExtractionPolicy
    inventory: Optional[SourceInventory]
    diagnostics: Tuple[ExtractionDiagnostic, ...] = ()
    schema_version: str = EXTRACTION_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "parent_artifact_sha256": self.parent_artifact_sha256,
            "status": self.status.value,
            "tool": asdict(self.tool),
            "policy": asdict(self.policy),
            "execution_fingerprint": self.execution_fingerprint,
            "execution": {
                "exit_code": self.execution.exit_code,
                "timed_out": self.execution.timed_out,
                "argv": list(self.execution.argv),
                "enforced_limits": list(self.execution.enforced_limits),
                "stdout_sha256": hashlib.sha256(
                    self.execution.stdout.encode("utf-8")
                ).hexdigest(),
                "stderr_sha256": hashlib.sha256(
                    self.execution.stderr.encode("utf-8")
                ).hexdigest(),
            },
            "inventory": self.inventory.to_dict() if self.inventory else None,
            "diagnostics": [asdict(item) for item in self.diagnostics],
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _execution_fingerprint(
    artifact_sha256: str,
    tool: ToolIdentity,
    execution: WorkerExecution,
) -> str:
    payload = {
        "artifact_sha256": artifact_sha256,
        "argv": list(execution.argv),
        "enforced_limits": sorted(execution.enforced_limits),
        "exit_code": execution.exit_code,
        "stderr_sha256": hashlib.sha256(execution.stderr.encode("utf-8")).hexdigest(),
        "stdout_sha256": hashlib.sha256(execution.stdout.encode("utf-8")).hexdigest(),
        "timed_out": execution.timed_out,
        "tool": {"name": tool.name, "version": tool.version},
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


class BinwalkExtractor:
    """Orchestrate a Binwalk worker without executing tools in the caller process."""

    def __init__(self, worker: ExtractionWorker):
        self._worker = worker

    def extract(self, request: ExtractionRequest) -> ExtractionResult:
        artifact_path = Path(request.artifact_path)
        if not artifact_path.is_file():
            raise ValueError("firmware artifact must be an existing regular file")
        if not _SHA256.fullmatch(request.artifact_sha256):
            raise ValueError("artifact_sha256 must be a lowercase SHA-256")
        if _sha256_file(artifact_path) != request.artifact_sha256:
            raise ValueError("firmware artifact digest does not match artifact_sha256")

        destination = Path(request.destination)
        if destination.exists() and any(destination.iterdir()):
            raise ValueError("extraction destination must be absent or empty")
        destination.mkdir(parents=True, exist_ok=True)

        try:
            tool = self._worker.probe()
        except (OSError, RuntimeError) as exc:
            tool = ToolIdentity(name="binwalk", version="unavailable")
            execution = WorkerExecution(
                exit_code=127,
                timed_out=False,
                argv=("binwalk", "--version"),
                stdout="",
                stderr=type(exc).__name__,
                enforced_limits=(),
            )
            return ExtractionResult(
                parent_artifact_sha256=request.artifact_sha256,
                status=ExtractionStatus.FAILED,
                tool=tool,
                execution_fingerprint=_execution_fingerprint(
                    request.artifact_sha256, tool, execution
                ),
                execution=execution,
                policy=request.policy,
                inventory=None,
                diagnostics=(
                    ExtractionDiagnostic(
                        code="extraction.tool_unavailable",
                        message="Binwalk worker probe failed: {}".format(
                            type(exc).__name__
                        ),
                    ),
                ),
            )
        if tool.name.lower() != "binwalk" or not tool.version.strip():
            raise ValueError("extraction worker did not report a valid Binwalk identity")
        worker_request = WorkerExtractionRequest(
            artifact_path=artifact_path.resolve(),
            destination=destination.resolve(),
            max_seconds=request.policy.max_seconds,
            max_output_files=request.policy.inventory_policy.max_files,
            max_output_bytes=request.policy.inventory_policy.max_expanded_bytes,
        )
        try:
            execution = self._worker.extract(worker_request)
        except (OSError, RuntimeError) as exc:
            execution = WorkerExecution(
                exit_code=125,
                timed_out=False,
                argv=("binwalk", "-Me", "/input/firmware.bin"),
                stdout="",
                stderr=type(exc).__name__,
                enforced_limits=(),
            )
            return ExtractionResult(
                parent_artifact_sha256=request.artifact_sha256,
                status=ExtractionStatus.FAILED,
                tool=tool,
                execution_fingerprint=_execution_fingerprint(
                    request.artifact_sha256, tool, execution
                ),
                execution=execution,
                policy=request.policy,
                inventory=None,
                diagnostics=(
                    ExtractionDiagnostic(
                        code="extraction.worker_crashed",
                        message="Binwalk worker execution failed: {}".format(
                            type(exc).__name__
                        ),
                    ),
                ),
            )
        fingerprint = _execution_fingerprint(
            request.artifact_sha256, tool, execution
        )
        expected_command = (
            bool(execution.argv)
            and Path(execution.argv[0]).name == "binwalk"
            and "-Me" in execution.argv[1:]
        )
        if not expected_command:
            return ExtractionResult(
                parent_artifact_sha256=request.artifact_sha256,
                status=ExtractionStatus.FAILED,
                tool=tool,
                execution_fingerprint=fingerprint,
                execution=execution,
                policy=request.policy,
                inventory=None,
                diagnostics=(
                    ExtractionDiagnostic(
                        code="extraction.unexpected_command",
                        message="worker did not attest the canonical Binwalk -Me command",
                    ),
                ),
            )
        missing_limits = _REQUIRED_LIMITS.difference(execution.enforced_limits)
        if missing_limits:
            return ExtractionResult(
                parent_artifact_sha256=request.artifact_sha256,
                status=ExtractionStatus.FAILED,
                tool=tool,
                execution_fingerprint=fingerprint,
                execution=execution,
                policy=request.policy,
                inventory=None,
                diagnostics=(
                    ExtractionDiagnostic(
                        code="extraction.worker_limits_unverified",
                        message="worker did not attest required limits: {}".format(
                            ", ".join(sorted(missing_limits))
                        ),
                    ),
                ),
            )
        if execution.timed_out or execution.exit_code != 0:
            code = (
                "extraction.worker_timeout"
                if execution.timed_out
                else "extraction.worker_failed"
            )
            partial_inventory = build_inventory(
                destination, request.policy.inventory_policy
            )
            has_partial_output = partial_inventory.observed_count > 0
            return ExtractionResult(
                parent_artifact_sha256=request.artifact_sha256,
                status=(
                    ExtractionStatus.PARTIAL_SUCCESS
                    if has_partial_output
                    else ExtractionStatus.FAILED
                ),
                tool=tool,
                execution_fingerprint=fingerprint,
                execution=execution,
                policy=request.policy,
                inventory=partial_inventory,
                diagnostics=(
                    ExtractionDiagnostic(
                        code=code,
                        message="Binwalk worker did not complete successfully",
                    ),
                ),
            )

        inventory = build_inventory(destination, request.policy.inventory_policy)
        status = (
            ExtractionStatus.SUCCESS
            if inventory.coverage_status is CoverageStatus.COMPLETED
            else ExtractionStatus.PARTIAL_SUCCESS
        )
        return ExtractionResult(
            parent_artifact_sha256=request.artifact_sha256,
            status=status,
            tool=tool,
            execution_fingerprint=fingerprint,
            execution=execution,
            policy=request.policy,
            inventory=inventory,
        )
