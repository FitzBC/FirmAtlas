"""One deterministic entry point from a raw firmware artifact to a mapping run."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Optional, Tuple

from .analysis_run import (
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    MappingAnalysisRun,
    MappingAnalyzerRegistry,
    BUILTIN_ANALYZER_REGISTRY,
    analyze_extracted_root,
)
from .domain import CoverageStatus
from .extraction import (
    ExtractionPolicy,
    ExtractionRequest,
    ExtractionResult,
    ExtractionStatus,
    FirmwareExtractor,
)


FIRMWARE_ARTIFACT_ANALYSIS_SCHEMA_VERSION = (
    "firmatlas.mapping.firmware-artifact-analysis/v1alpha1"
)


class FirmwareArtifactAnalysisStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    EXTRACTION_FAILED = "extraction_failed"
    NO_ROOTFS = "no_rootfs"
    AMBIGUOUS_ROOTFS = "ambiguous_rootfs"


@dataclass(frozen=True)
class RootfsSelectionPolicy:
    """Conservatively identify a rootfs emitted by a recursive extractor."""

    accepted_directory_names: Tuple[str, ...] = (
        "squashfs-root", "rootfs", "filesystem-root", "fs-root",
    )
    marker_names: Tuple[str, ...] = (
        "bin", "sbin", "etc", "usr", "lib", "www", "webroot",
    )

    def __post_init__(self) -> None:
        if not self.accepted_directory_names or not self.marker_names:
            raise ValueError("rootfs selection policy requires names and markers")
        if any(not item.strip() or "/" in item for item in self.accepted_directory_names):
            raise ValueError("rootfs directory names must be simple names")
        if any(not item.strip() or "/" in item for item in self.marker_names):
            raise ValueError("rootfs marker names must be simple names")
        if len(self.accepted_directory_names) != len(set(self.accepted_directory_names)):
            raise ValueError("rootfs directory names must be unique")
        if len(self.marker_names) != len(set(self.marker_names)):
            raise ValueError("rootfs marker names must be unique")


@dataclass(frozen=True)
class FirmwareArtifactAnalysisRequest:
    """Caller-facing request for the raw-artifact analysis seam."""

    artifact_path: Path
    extraction_destination: Path
    extraction_policy: ExtractionPolicy = field(default_factory=ExtractionPolicy)
    mapping_profile: MappingAnalysisProfile = field(
        default_factory=MappingAnalysisProfile.auto
    )
    rootfs_selection_policy: RootfsSelectionPolicy = field(
        default_factory=RootfsSelectionPolicy
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_path", Path(self.artifact_path))
        object.__setattr__(
            self, "extraction_destination", Path(self.extraction_destination)
        )


@dataclass(frozen=True)
class FirmwareArtifactAnalysisRun:
    """Immutable result of extraction, root selection, and mapping orchestration."""

    artifact_analysis_id: str
    firmware_artifact_sha256: str
    status: FirmwareArtifactAnalysisStatus
    extraction: ExtractionResult
    selected_root_path: Optional[str]
    mapping_run: Optional[MappingAnalysisRun]
    diagnostic_codes: Tuple[str, ...] = ()
    schema_version: str = FIRMWARE_ARTIFACT_ANALYSIS_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "artifact_analysis_id": self.artifact_analysis_id,
            "firmware_artifact_sha256": self.firmware_artifact_sha256,
            "status": self.status.value,
            "extraction": self.extraction.to_dict(),
            "selected_root_path": self.selected_root_path,
            "analysis_run_id": (
                self.mapping_run.analysis_run_id if self.mapping_run else None
            ),
            "catalog_id": (
                self.mapping_run.catalog.catalog_id if self.mapping_run else None
            ),
            "mapping_run": self.mapping_run.to_dict() if self.mapping_run else None,
            "diagnostic_codes": list(self.diagnostic_codes),
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _root_candidates(
    destination: Path, policy: RootfsSelectionPolicy,
) -> Tuple[Path, ...]:
    """Return only equally best, non-symlink rootfs candidates."""

    resolved_destination = destination.resolve()
    priorities = {
        name: len(policy.accepted_directory_names) - index
        for index, name in enumerate(policy.accepted_directory_names)
    }
    candidates = []
    for candidate in sorted(resolved_destination.rglob("*")):
        if candidate.name not in priorities or candidate.is_symlink() or not candidate.is_dir():
            continue
        try:
            candidate.relative_to(resolved_destination)
        except ValueError:
            continue
        marker_count = sum(
            (candidate / marker).is_dir() or (candidate / marker).is_file()
            for marker in policy.marker_names
        )
        if marker_count == 0:
            continue
        relative = candidate.relative_to(resolved_destination).as_posix()
        candidates.append(((marker_count, priorities[candidate.name]), relative, candidate))
    if not candidates:
        return ()
    best_score = max(item[0] for item in candidates)
    return tuple(item[2] for item in candidates if item[0] == best_score)


def _identity(
    firmware_artifact_sha256: str,
    extraction: ExtractionResult,
    selected_root_path: Optional[str],
    mapping_run: Optional[MappingAnalysisRun],
    status: FirmwareArtifactAnalysisStatus,
    diagnostic_codes: Tuple[str, ...],
) -> str:
    payload = {
        "firmware_artifact_sha256": firmware_artifact_sha256,
        "extraction_execution_fingerprint": extraction.execution_fingerprint,
        "selected_root_path": selected_root_path,
        "analysis_run_id": mapping_run.analysis_run_id if mapping_run else None,
        "status": status.value,
        "diagnostic_codes": list(diagnostic_codes),
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return "firmware-artifact-analysis:" + hashlib.sha256(encoded).hexdigest()


def _result(
    firmware_artifact_sha256: str,
    status: FirmwareArtifactAnalysisStatus,
    extraction: ExtractionResult,
    destination: Path,
    selected_root: Optional[Path] = None,
    mapping_run: Optional[MappingAnalysisRun] = None,
    diagnostic_codes: Tuple[str, ...] = (),
) -> FirmwareArtifactAnalysisRun:
    selected_root_path = (
        selected_root.resolve().relative_to(destination.resolve()).as_posix()
        if selected_root is not None else None
    )
    codes = tuple(sorted(set(diagnostic_codes)))
    return FirmwareArtifactAnalysisRun(
        artifact_analysis_id=_identity(
            firmware_artifact_sha256, extraction, selected_root_path,
            mapping_run, status, codes,
        ),
        firmware_artifact_sha256=firmware_artifact_sha256,
        status=status,
        extraction=extraction,
        selected_root_path=selected_root_path,
        mapping_run=mapping_run,
        diagnostic_codes=codes,
    )


def analyze_firmware_artifact(
    request: FirmwareArtifactAnalysisRequest,
    extractor: FirmwareExtractor,
    registry: MappingAnalyzerRegistry = BUILTIN_ANALYZER_REGISTRY,
) -> FirmwareArtifactAnalysisRun:
    """Analyze a raw artifact without exposing extraction or rootfs plumbing to callers."""

    artifact = request.artifact_path
    if not artifact.is_file():
        raise ValueError("firmware artifact must be an existing regular file")
    artifact_sha256 = _sha256_file(artifact)
    extraction = extractor.extract(ExtractionRequest(
        artifact_path=artifact,
        artifact_sha256=artifact_sha256,
        destination=request.extraction_destination,
        policy=request.extraction_policy,
    ))
    extraction_codes = tuple(item.code for item in extraction.diagnostics)
    if extraction.status is ExtractionStatus.FAILED:
        return _result(
            artifact_sha256, FirmwareArtifactAnalysisStatus.EXTRACTION_FAILED,
            extraction, request.extraction_destination, diagnostic_codes=extraction_codes,
        )

    roots = _root_candidates(
        request.extraction_destination, request.rootfs_selection_policy,
    )
    if not roots:
        return _result(
            artifact_sha256, FirmwareArtifactAnalysisStatus.NO_ROOTFS, extraction,
            request.extraction_destination,
            diagnostic_codes=extraction_codes + ("analysis.rootfs_not_found",),
        )
    if len(roots) > 1:
        return _result(
            artifact_sha256, FirmwareArtifactAnalysisStatus.AMBIGUOUS_ROOTFS, extraction,
            request.extraction_destination,
            diagnostic_codes=extraction_codes + ("analysis.rootfs_ambiguous",),
        )
    root = roots[0]
    mapping_run = analyze_extracted_root(MappingAnalysisRequest(
        root=root,
        firmware_artifact_sha256=artifact_sha256,
        profile=request.mapping_profile,
        inventory_policy=request.extraction_policy.inventory_policy,
    ), registry)
    status = (
        FirmwareArtifactAnalysisStatus.COMPLETED
        if (
            extraction.status is ExtractionStatus.SUCCESS
            and mapping_run.coverage_status is CoverageStatus.COMPLETED
        )
        else FirmwareArtifactAnalysisStatus.PARTIAL
    )
    return _result(
        artifact_sha256, status, extraction, request.extraction_destination,
        selected_root=root, mapping_run=mapping_run,
        diagnostic_codes=extraction_codes,
    )
