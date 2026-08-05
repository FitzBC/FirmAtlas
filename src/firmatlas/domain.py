"""Stable, dependency-free domain types shared by analysis adapters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, Tuple


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AnalysisStatus(str, Enum):
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class ArtifactRef:
    sha256: str
    size: int
    media_type: str = "application/octet-stream"

    def __post_init__(self) -> None:
        if not _SHA256.fullmatch(self.sha256):
            raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
        if self.size < 0:
            raise ValueError("artifact size cannot be negative")


@dataclass(frozen=True)
class AnalyzerIdentity:
    name: str
    version: str
    rules_version: str

    def __post_init__(self) -> None:
        if not all((self.name, self.version, self.rules_version)):
            raise ValueError("analyzer name and versions are required")


@dataclass(frozen=True)
class EvidenceRef:
    artifact_sha256: str
    locator: str
    description: str = ""

    def __post_init__(self) -> None:
        if not _SHA256.fullmatch(self.artifact_sha256):
            raise ValueError("evidence artifact sha256 is invalid")
        if not self.locator:
            raise ValueError("evidence locator is required")


@dataclass(frozen=True)
class Observation:
    kind: str
    subject: str
    attributes: Dict[str, Any]
    confidence: Confidence
    evidence: Tuple[EvidenceRef, ...]

    def __post_init__(self) -> None:
        if not self.kind or not self.subject:
            raise ValueError("observation kind and subject are required")
        if not self.evidence:
            raise ValueError("an observation must cite at least one evidence item")


@dataclass(frozen=True)
class AnalysisReport:
    run_id: str
    artifact: ArtifactRef
    analyzer: AnalyzerIdentity
    status: AnalysisStatus
    started_at: datetime
    finished_at: datetime
    observations: Tuple[Observation, ...] = field(default_factory=tuple)
    diagnostics: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.run_id:
            raise ValueError("run_id is required")
        if self.started_at.tzinfo is None or self.finished_at.tzinfo is None:
            raise ValueError("analysis timestamps must be timezone-aware")
        if self.finished_at < self.started_at:
            raise ValueError("analysis cannot finish before it starts")
        if self.status in (AnalysisStatus.FAILED, AnalysisStatus.UNSUPPORTED):
            if not self.diagnostics:
                raise ValueError("failed or unsupported analysis requires diagnostics")

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-compatible result envelope for the control-plane seam."""

        result = asdict(self)
        result["status"] = self.status.value
        result["started_at"] = self.started_at.isoformat()
        result["finished_at"] = self.finished_at.isoformat()
        for observation in result["observations"]:
            observation["confidence"] = observation["confidence"].value
        return result


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
