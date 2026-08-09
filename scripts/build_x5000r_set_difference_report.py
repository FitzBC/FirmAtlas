#!/usr/bin/env python3
"""Build the replayable X5000R frontend/native set-difference attribution."""

from __future__ import annotations

from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
import re

from firmatlas.mapping import (
    AttributionArtifact,
    AttributionArtifactRole,
    FrontendAssetInput,
    NativeRouteAnchor,
    SourceArtifactEntry,
    attribute_frontend_native_set_difference,
    discover_frontend_asset_graph,
    discover_mips_inline_route_bindings,
)


X5000R_ROOT = Path(
    "var/mapping-work/x5000r-v9.1.0u.6118/extractions/firmware.bin.extracted/"
    "1004C/C8343R-6118.bin.extracted/184C70/squashfs-root"
)
FRONTEND_PATHS = (
    "www/static/js/config.js",
    "www/static/js/config_ie.js",
    "www/static/js/topicurl.js",
)
BINARY_PATH = "www/cgi-bin/cstecgi.cgi"
WEB_SUFFIXES = frozenset({".asp", ".htm", ".html", ".js"})


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )


def _frontend_asset(root: Path, path: str) -> FrontendAssetInput:
    content = (root / path).read_bytes()
    return FrontendAssetInput(_source(path, content), content)


def _probe_anchors(content: bytes) -> tuple:
    values = {
        match.group(1).decode("ascii")
        for match in re.finditer(rb"([\x21-\x7e]{4,63})\x00", content)
    }
    return tuple(
        NativeRouteAnchor(
            "native-table-probe:" + hashlib.sha256(value.encode()).hexdigest(),
            value,
        )
        for value in sorted(values)
    )


def _auxiliary_artifacts(root: Path) -> tuple:
    artifacts = []
    excluded = set(FRONTEND_PATHS) | {BINARY_PATH}
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            continue
        content = path.read_bytes()
        if relative.startswith("www/") and path.suffix.lower() in WEB_SUFFIXES:
            try:
                content.decode("utf-8")
            except UnicodeDecodeError:
                continue
            role = AttributionArtifactRole.WEB_AUXILIARY
        elif content.startswith(b"\x7fELF"):
            role = AttributionArtifactRole.NATIVE_AUXILIARY
        else:
            continue
        artifacts.append(AttributionArtifact(_source(relative, content), content, role))
    return tuple(artifacts)


def build_analysis(root: Path = X5000R_ROOT):
    frontend_assets = tuple(_frontend_asset(root, path) for path in FRONTEND_PATHS)
    frontend = discover_frontend_asset_graph(frontend_assets)
    binary = (root / BINARY_PATH).read_bytes()
    native_source = _source(BINARY_PATH, binary)
    native = discover_mips_inline_route_bindings(
        native_source, binary, _probe_anchors(binary)
    )
    artifacts = _auxiliary_artifacts(root)
    result = attribute_frontend_native_set_difference(
        frontend, native, artifacts
    )
    return native_source, artifacts, result


def build_summary(root: Path = X5000R_ROOT) -> dict:
    native_source, artifacts, result = build_analysis(root)
    counts = Counter(item.kind.value for item in result.attributions)
    sides = Counter(item.side.value for item in result.attributions)
    role_counts = Counter(item.role.value for item in artifacts)
    return {
        "schema_version": "firmatlas.mapping.x5000r-set-difference/v1alpha1",
        "source": {
            "dispatcher_path": BINARY_PATH,
            "dispatcher_sha256": native_source.content_sha256,
            "dispatcher_size": native_source.size,
        },
        "profile": {
            "frontend": "cross-resource shared-cgi.topicurl operations",
            "native": "mips32-inline-route-handler-table/v1",
            "attribution": result.producer.name + "@" + result.producer.version,
        },
        "coverage": {
            "status": result.coverage_status.value,
            "processed_bytes": result.processed_bytes,
            "frontend_token_count": result.frontend_token_count,
            "native_token_count": result.native_token_count,
            "auxiliary_artifact_count": len(artifacts),
            "auxiliary_role_counts": dict(sorted(role_counts.items())),
            "diagnostics": [
                {
                    "code": item.code,
                    "message": item.message,
                    "source_path": item.source_path,
                }
                for item in result.diagnostics
            ],
        },
        "side_counts": dict(sorted(sides.items())),
        "attribution_counts": dict(sorted(counts.items())),
        "attributions": [
            {
                "attribution_id": item.attribution_id,
                "token": item.token,
                "side": item.side.value,
                "kind": item.kind.value,
                "matched_artifact_paths": list(item.matched_artifact_paths),
                "upstream_evidence_ids": list(item.upstream_evidence_ids),
                "evidence_ids": list(item.evidence_ids),
                "interpretation": item.interpretation,
                "open_obligation": item.open_obligation,
            }
            for item in result.attributions
        ],
        "evidence_atoms": [atom.to_dict() for atom in result.evidence_atoms],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=X5000R_ROOT)
    args = parser.parse_args()
    print(json.dumps(build_summary(args.root), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
