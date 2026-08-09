"""Deterministic, non-executing source inventory for a firmware root."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat
from tempfile import TemporaryFile
from typing import List, Optional, Tuple
import zipfile

from .domain import CoverageStatus


INVENTORY_SCHEMA_VERSION = "firmatlas.mapping.inventory/v1alpha2"


@dataclass(frozen=True)
class InventoryPolicy:
    max_files: int = 100_000
    max_total_bytes: int = 4 * 1024 * 1024 * 1024
    max_file_bytes: int = 512 * 1024 * 1024
    max_expanded_bytes: int = 8 * 1024 * 1024 * 1024
    max_archive_depth: int = 3
    max_symlink_depth: int = 40

    def __post_init__(self) -> None:
        for field_name in (
            "max_files",
            "max_total_bytes",
            "max_file_bytes",
            "max_expanded_bytes",
        ):
            if getattr(self, field_name) <= 0:
                raise ValueError("{} must be positive".format(field_name))
        if self.max_archive_depth < 0:
            raise ValueError("max_archive_depth must be nonnegative")
        if self.max_symlink_depth <= 0:
            raise ValueError("max_symlink_depth must be positive")


@dataclass(frozen=True)
class SourceArtifactEntry:
    canonical_path: str
    original_path: str
    kind: str
    size: int
    content_sha256: Optional[str]
    link_target: Optional[str] = None
    expansion_status: str = "not_applicable"
    parent_path: Optional[str] = None
    resolved_path: Optional[str] = None


@dataclass(frozen=True)
class InventoryDiagnostic:
    code: str
    path: str
    message: str


@dataclass(frozen=True)
class SourceInventory:
    inventory_sha256: str
    entries: Tuple[SourceArtifactEntry, ...]
    policy: InventoryPolicy
    diagnostics: Tuple[InventoryDiagnostic, ...] = ()
    coverage_status: CoverageStatus = CoverageStatus.COMPLETED
    observed_count: int = 0
    processed_count: int = 0
    processed_bytes: int = 0
    expanded_bytes: int = 0
    schema_version: str = INVENTORY_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "inventory_sha256": self.inventory_sha256,
            "policy": asdict(self.policy),
            "coverage_status": self.coverage_status.value,
            "observed_count": self.observed_count,
            "processed_count": self.processed_count,
            "processed_bytes": self.processed_bytes,
            "expanded_bytes": self.expanded_bytes,
            "entries": [asdict(item) for item in self.entries],
            "diagnostics": [asdict(item) for item in self.diagnostics],
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_archive_member(raw_name: str) -> Optional[str]:
    portable = raw_name.replace("\\", "/")
    if (
        not portable
        or "\x00" in portable
        or portable.startswith("/")
        or re.match(r"^[A-Za-z]:", portable)
    ):
        return None
    parts = PurePosixPath(portable).parts
    if ".." in parts:
        return None
    normalized = "/".join(part for part in parts if part not in {"", "."})
    return normalized or None


def _firmware_link_components(raw_target: str) -> Optional[Tuple[str, ...]]:
    """Split a link target while preserving parent traversal order."""

    if not raw_target or "\x00" in raw_target:
        return None
    return tuple(part for part in raw_target.split("/") if part not in {"", "."})


def _resolve_firmware_symlink(
    root: Path,
    source_relative: str,
    raw_target: str,
    max_depth: int,
) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
    """Resolve a link as the firmware kernel would, without opening its target."""

    source_parts = tuple(PurePosixPath(source_relative).parts)
    pending_parts = _firmware_link_components(raw_target)
    if pending_parts is None:
        return (
            "rejected_escape",
            None,
            "inventory.symlink_escape",
            "symlink target escapes the firmware root",
        )
    pending = list(pending_parts)
    resolved: List[str] = (
        [] if raw_target.startswith("/") else list(source_parts[:-1])
    )
    seen_links = {source_relative}
    followed_links = 1
    while pending:
        part = pending.pop(0)
        if part == "..":
            if not resolved:
                return (
                    "rejected_escape",
                    None,
                    "inventory.symlink_escape",
                    "symlink chain escapes the firmware root",
                )
            resolved.pop()
            continue
        candidate_parts = tuple(resolved + [part])
        candidate = root.joinpath(*candidate_parts)
        try:
            candidate_mode = candidate.lstat().st_mode
        except (FileNotFoundError, NotADirectoryError):
            missing_path = "/".join(candidate_parts + tuple(pending))
            runtime_root = candidate_parts[0] if candidate_parts else None
            runtime_root_path = root / runtime_root if runtime_root else None
            declared_empty_runtime_tree = False
            if runtime_root in {"tmp", "var"} and runtime_root_path is not None:
                try:
                    declared_empty_runtime_tree = (
                        runtime_root_path.is_dir()
                        and next(runtime_root_path.iterdir(), None) is None
                    )
                except OSError:
                    declared_empty_runtime_tree = False
            if (
                candidate_parts
                and (
                    candidate_parts[0] == "dev"
                    or declared_empty_runtime_tree
                )
                and ".." not in pending
            ):
                return (
                    "recorded_runtime_target_not_materialized",
                    missing_path,
                    None,
                    None,
                )
            return (
                "missing_target",
                missing_path,
                "inventory.symlink_target_missing",
                "symlink target is missing from the firmware root",
            )
        except OSError as exc:
            return (
                "target_inspection_failed",
                "/".join(candidate_parts + tuple(pending)),
                "inventory.symlink_target_inspection_failed",
                "symlink target metadata could not be inspected: {}".format(
                    type(exc).__name__
                ),
            )
        if not stat.S_ISLNK(candidate_mode):
            resolved.append(part)
            continue

        candidate_relative = "/".join(candidate_parts)
        if candidate_relative in seen_links:
            return (
                "rejected_cycle",
                candidate_relative,
                "inventory.symlink_cycle",
                "symlink chain contains a cycle",
            )
        if followed_links >= max_depth:
            return (
                "depth_limited",
                candidate_relative,
                "inventory.symlink_depth_exceeded",
                "symlink chain exceeds max_symlink_depth",
            )
        seen_links.add(candidate_relative)
        followed_links += 1
        try:
            nested_target = str(candidate.readlink())
        except OSError as exc:
            return (
                "target_inspection_failed",
                candidate_relative,
                "inventory.symlink_target_inspection_failed",
                "symlink target could not be read: {}".format(type(exc).__name__),
            )
        nested_parts = _firmware_link_components(nested_target)
        if nested_parts is None:
            return (
                "rejected_escape",
                None,
                "inventory.symlink_escape",
                "symlink chain escapes the firmware root",
            )
        pending = list(nested_parts) + pending
        if nested_target.startswith("/"):
            resolved = []

    resolved_path = "/".join(resolved) or "."
    return (
        (
            "recorded_chroot_absolute_not_followed"
            if raw_target.startswith("/")
            else "recorded_not_followed"
        ),
        resolved_path,
        None,
        None,
    )


def _inspect_zip(
    source: object,
    canonical_path: str,
    policy: InventoryPolicy,
    remaining_files: int,
    expanded_bytes_before: int,
    archive_depth: int,
) -> Tuple[
    List[SourceArtifactEntry],
    List[InventoryDiagnostic],
    int,
    int,
    int,
    bool,
]:
    entries: List[SourceArtifactEntry] = []
    diagnostics: List[InventoryDiagnostic] = []
    observed_count = 0
    processed_count = 0
    expanded_bytes = 0
    coverage_incomplete = False
    seen_member_paths = set()
    with zipfile.ZipFile(source) as archive:
        for member in sorted(archive.infolist(), key=lambda item: item.filename):
            if member.is_dir():
                continue
            observed_count += 1
            member_display = "{}!{}".format(canonical_path, member.filename)
            if processed_count >= remaining_files:
                coverage_incomplete = True
                diagnostics.append(
                    InventoryDiagnostic(
                        code="inventory.file_count_budget_exceeded",
                        path=member_display,
                        message="archive member was not processed because max_files was reached",
                    )
                )
                continue
            member_path = _canonical_archive_member(member.filename)
            if member_path is None:
                coverage_incomplete = True
                diagnostics.append(
                    InventoryDiagnostic(
                        code="inventory.archive_path_traversal",
                        path="{}!{}".format(canonical_path, member.filename),
                        message="archive member path is absolute or escapes its parent",
                    )
                )
                continue
            if member_path in seen_member_paths:
                coverage_incomplete = True
                diagnostics.append(
                    InventoryDiagnostic(
                        code="inventory.archive_member_collision",
                        path="{}!{}".format(canonical_path, member.filename),
                        message="multiple archive members normalize to the same canonical path",
                    )
                )
                continue
            seen_member_paths.add(member_path)
            if member.file_size > policy.max_file_bytes:
                coverage_incomplete = True
                diagnostics.append(
                    InventoryDiagnostic(
                        code="inventory.file_budget_exceeded",
                        path="{}!{}".format(canonical_path, member_path),
                        message="archive member exceeds max_file_bytes",
                    )
                )
                continue
            if (
                expanded_bytes_before + expanded_bytes + member.file_size
                > policy.max_expanded_bytes
            ):
                coverage_incomplete = True
                diagnostics.append(
                    InventoryDiagnostic(
                        code="inventory.archive_expansion_budget_exceeded",
                        path="{}!{}".format(canonical_path, member_path),
                        message=(
                            "archive member was not decompressed because "
                            "max_expanded_bytes was reached"
                        ),
                    )
                )
                continue
            try:
                member_digest = hashlib.sha256()
                with archive.open(member) as member_stream, TemporaryFile(
                    mode="w+b"
                ) as nested_source:
                    for chunk in iter(lambda: member_stream.read(1024 * 1024), b""):
                        member_digest.update(chunk)
                        nested_source.write(chunk)
                    nested_source.seek(0)
                    is_nested_archive = zipfile.is_zipfile(nested_source)
                    nested_source.seek(0)
                    nested_depth_limited = (
                        is_nested_archive
                        and archive_depth + 1 > policy.max_archive_depth
                    )
                    member_canonical_path = "{}!{}".format(
                        canonical_path, member_path
                    )
                    entries.append(
                        SourceArtifactEntry(
                            canonical_path=member_canonical_path,
                            original_path="{}!{}".format(
                                canonical_path, member.filename
                            ),
                            kind=(
                                "archive" if is_nested_archive else "archive_member"
                            ),
                            size=member.file_size,
                            content_sha256=member_digest.hexdigest(),
                            parent_path=canonical_path,
                            expansion_status=(
                                "depth_limited"
                                if nested_depth_limited
                                else "inspected"
                                if is_nested_archive
                                else "not_applicable"
                            ),
                        )
                    )
                    processed_count += 1
                    expanded_bytes += member.file_size
                    if nested_depth_limited:
                        coverage_incomplete = True
                        diagnostics.append(
                            InventoryDiagnostic(
                                code="inventory.archive_depth_exceeded",
                                path=member_canonical_path,
                                message=(
                                    "nested archive was not inspected because "
                                    "max_archive_depth was reached"
                                ),
                            )
                        )
                    elif is_nested_archive:
                        (
                            nested_entries,
                            nested_diagnostics,
                            nested_observed,
                            nested_processed,
                            nested_expanded,
                            nested_coverage_incomplete,
                        ) = _inspect_zip(
                            nested_source,
                            member_canonical_path,
                            policy,
                            remaining_files - processed_count,
                            expanded_bytes_before + expanded_bytes,
                            archive_depth + 1,
                        )
                        entries.extend(nested_entries)
                        diagnostics.extend(nested_diagnostics)
                        observed_count += nested_observed
                        processed_count += nested_processed
                        expanded_bytes += nested_expanded
                        coverage_incomplete = (
                            coverage_incomplete or nested_coverage_incomplete
                        )
            except (OSError, RuntimeError, zipfile.BadZipFile, NotImplementedError) as exc:
                coverage_incomplete = True
                diagnostics.append(
                    InventoryDiagnostic(
                        code="inventory.archive_member_read_failed",
                        path="{}!{}".format(canonical_path, member_path),
                        message="archive member could not be read: {}".format(
                            type(exc).__name__
                        ),
                    )
                )
                continue
    return (
        entries,
        diagnostics,
        observed_count,
        processed_count,
        expanded_bytes,
        coverage_incomplete,
    )


def build_inventory(root: Path, policy: InventoryPolicy) -> SourceInventory:
    """Return a stable inventory of regular files below an extracted root."""

    root = Path(root)
    if not root.is_dir():
        raise ValueError("inventory root must be an existing directory")
    entries_list: List[SourceArtifactEntry] = []
    diagnostics: List[InventoryDiagnostic] = []
    candidates = tuple(
        path
        for path in sorted(
            root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()
        )
        if path.is_symlink() or not path.is_dir()
    )
    processed_count = 0
    processed_bytes = 0
    expanded_bytes = 0
    archive_observed_count = 0
    inode_cache = {}
    coverage_incomplete = False
    for path in candidates:
        relative = path.relative_to(root).as_posix()
        if processed_count >= policy.max_files:
            coverage_incomplete = True
            diagnostics.append(
                InventoryDiagnostic(
                    code="inventory.file_count_budget_exceeded",
                    path=relative,
                    message="source artifact was not processed because max_files was reached",
                )
            )
            continue
        if path.is_symlink():
            link_target = path.readlink()
            status, resolved_path, diagnostic_code, diagnostic_message = (
                _resolve_firmware_symlink(
                    root,
                    relative,
                    str(link_target),
                    policy.max_symlink_depth,
                )
            )
            entries_list.append(
                SourceArtifactEntry(
                    canonical_path=relative,
                    original_path=relative,
                    kind="symlink",
                    size=path.lstat().st_size,
                    content_sha256=None,
                    link_target=str(link_target),
                    expansion_status=status,
                    resolved_path=resolved_path,
                )
            )
            if diagnostic_code is not None:
                coverage_incomplete = True
                diagnostics.append(
                    InventoryDiagnostic(
                        code=diagnostic_code,
                        path=relative,
                        message=diagnostic_message or "symlink resolution failed",
                    )
                )
            processed_count += 1
            continue
        if path.is_file():
            stat_result = path.stat()
            file_size = stat_result.st_size
            inode_key = (stat_result.st_dev, stat_result.st_ino)
            cached_inode = inode_cache.get(inode_key) if stat_result.st_nlink > 1 else None
            if cached_inode is not None:
                first_path, content_sha256 = cached_inode
                entries_list.append(
                    SourceArtifactEntry(
                        canonical_path=relative,
                        original_path=relative,
                        kind="hardlink",
                        size=file_size,
                        content_sha256=content_sha256,
                        expansion_status="recorded_not_reopened",
                        parent_path=first_path,
                    )
                )
                processed_count += 1
                continue
            if file_size > policy.max_file_bytes:
                coverage_incomplete = True
                diagnostics.append(
                    InventoryDiagnostic(
                        code="inventory.file_size_budget_exceeded",
                        path=relative,
                        message="source artifact was not read because it exceeds max_file_bytes",
                    )
                )
                continue
            if processed_bytes + file_size > policy.max_total_bytes:
                coverage_incomplete = True
                diagnostics.append(
                    InventoryDiagnostic(
                        code="inventory.total_byte_budget_exceeded",
                        path=relative,
                        message="source artifact was not read because max_total_bytes was reached",
                    )
                )
                continue
            is_zip = zipfile.is_zipfile(path)
            depth_limited = is_zip and policy.max_archive_depth == 0
            content_sha256 = _sha256_file(path)
            entries_list.append(
                SourceArtifactEntry(
                    canonical_path=relative,
                    original_path=relative,
                    kind="archive" if is_zip else "file",
                    size=file_size,
                    content_sha256=content_sha256,
                    expansion_status=(
                        "depth_limited"
                        if depth_limited
                        else "inspected" if is_zip else "not_applicable"
                    ),
                )
            )
            processed_count += 1
            processed_bytes += file_size
            if stat_result.st_nlink > 1:
                inode_cache[inode_key] = (relative, content_sha256)
            if depth_limited:
                coverage_incomplete = True
                diagnostics.append(
                    InventoryDiagnostic(
                        code="inventory.archive_depth_exceeded",
                        path=relative,
                        message="archive was not inspected because max_archive_depth is zero",
                    )
                )
            elif is_zip:
                (
                    archive_entries,
                    archive_diagnostics,
                    archive_observed,
                    archive_processed,
                    archive_expanded,
                    archive_coverage_incomplete,
                ) = _inspect_zip(
                    path,
                    relative,
                    policy,
                    policy.max_files - processed_count,
                    expanded_bytes,
                    1,
                )
                entries_list.extend(archive_entries)
                diagnostics.extend(archive_diagnostics)
                archive_observed_count += archive_observed
                processed_count += archive_processed
                expanded_bytes += archive_expanded
                coverage_incomplete = coverage_incomplete or archive_coverage_incomplete
            continue
        node_mode = path.lstat().st_mode
        if stat.S_ISFIFO(node_mode):
            node_kind = "fifo"
        elif stat.S_ISSOCK(node_mode):
            node_kind = "socket"
        elif stat.S_ISCHR(node_mode):
            node_kind = "character_device"
        elif stat.S_ISBLK(node_mode):
            node_kind = "block_device"
        else:
            node_kind = "filesystem_node"
        entries_list.append(
            SourceArtifactEntry(
                canonical_path=relative,
                original_path=relative,
                kind=node_kind,
                size=path.lstat().st_size,
                content_sha256=None,
                expansion_status="unsupported",
            )
        )
        diagnostics.append(
            InventoryDiagnostic(
                code="inventory.unsupported_filesystem_node",
                path=relative,
                message="filesystem node was recorded but never opened",
            )
        )
        processed_count += 1
        coverage_incomplete = True
    entries = tuple(sorted(entries_list, key=lambda entry: entry.canonical_path))
    manifest = [
        {
            "canonical_path": entry.canonical_path,
            "content_sha256": entry.content_sha256,
            "kind": entry.kind,
            "link_target": entry.link_target,
            "parent_path": entry.parent_path,
            "resolved_path": entry.resolved_path,
            "size": entry.size,
            "expansion_status": entry.expansion_status,
        }
        for entry in entries
    ]
    diagnostic_manifest = [
        {"code": item.code, "message": item.message, "path": item.path}
        for item in diagnostics
    ]
    coverage_status = (
        CoverageStatus.PARTIAL if coverage_incomplete else CoverageStatus.COMPLETED
    )
    encoded = json.dumps(
        {
            "coverage_status": coverage_status.value,
            "diagnostics": diagnostic_manifest,
            "entries": manifest,
            "observed_count": len(candidates) + archive_observed_count,
            "expanded_bytes": expanded_bytes,
            "processed_bytes": processed_bytes,
            "processed_count": processed_count,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return SourceInventory(
        inventory_sha256=hashlib.sha256(encoded).hexdigest(),
        entries=entries,
        policy=policy,
        diagnostics=tuple(diagnostics),
        coverage_status=coverage_status,
        observed_count=len(candidates) + archive_observed_count,
        processed_count=processed_count,
        processed_bytes=processed_bytes,
        expanded_bytes=expanded_bytes,
    )
