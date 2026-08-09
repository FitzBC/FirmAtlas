#!/usr/bin/env python3
"""Replay X5000R frontend scope expansion and the resulting set difference."""

from __future__ import annotations

from collections import Counter
import argparse
import json
from pathlib import Path

from firmatlas.mapping import (
    attribute_frontend_native_set_difference,
    discover_frontend_asset_graph,
    discover_mips_inline_route_bindings,
)

if __package__:
    from scripts.build_x5000r_set_difference_report import (
        BINARY_PATH,
        FRONTEND_PATHS as BASELINE_FRONTEND_PATHS,
        X5000R_ROOT,
        _auxiliary_artifacts,
        _frontend_asset,
        _probe_anchors,
        _source,
    )
else:
    from build_x5000r_set_difference_report import (
        BINARY_PATH,
        FRONTEND_PATHS as BASELINE_FRONTEND_PATHS,
        X5000R_ROOT,
        _auxiliary_artifacts,
        _frontend_asset,
        _probe_anchors,
        _source,
    )


EXPANDED_FRONTEND_PATHS = (
    *BASELINE_FRONTEND_PATHS,
    "www/static/js/kr.js",
    "www/wan_ie.html",
    "www/advance/config.html",
)
TARGET_OPERATIONS = frozenset({
    "getWanIeCfg", "setWanIeCfg", "setUploadSetting", "upload"
})


def build_analysis(root: Path = X5000R_ROOT):
    assets = tuple(
        _frontend_asset(root, path) for path in EXPANDED_FRONTEND_PATHS
    )
    frontend = discover_frontend_asset_graph(assets)
    binary = (root / BINARY_PATH).read_bytes()
    native_source = _source(BINARY_PATH, binary)
    native = discover_mips_inline_route_bindings(
        native_source, binary, _probe_anchors(binary)
    )
    artifacts = _auxiliary_artifacts(root, EXPANDED_FRONTEND_PATHS)
    difference = attribute_frontend_native_set_difference(
        frontend, native, artifacts
    )
    return assets, frontend, native_source, native, artifacts, difference


def build_summary(root: Path = X5000R_ROOT) -> dict:
    assets, frontend, native_source, native, artifacts, difference = (
        build_analysis(root)
    )
    candidates = {
        item.candidate_id: item
        for result in frontend.results
        for item in result.candidates
    }
    operations = []
    for result in frontend.results:
        for parameter in result.parameters:
            if not (
                parameter.is_operation_selector
                and parameter.literal_value in TARGET_OPERATIONS
            ):
                continue
            candidate = candidates[parameter.request_candidate_id]
            operations.append({
                "operation": parameter.literal_value,
                "endpoint": candidate.endpoint,
                "method": candidate.method,
                "representation": candidate.representation,
                "source_path": result.source_path,
                "source_construct": candidate.source_construct,
                "request_evidence_ids": list(candidate.evidence_ids),
                "selector_evidence_ids": list(parameter.evidence_ids),
            })
    operations.sort(key=lambda item: (item["operation"], item["source_path"]))
    counts = Counter(item.kind.value for item in difference.attributions)
    sides = Counter(item.side.value for item in difference.attributions)
    return {
        "schema_version": (
            "firmatlas.mapping.x5000r-expanded-frontend/v1alpha1"
        ),
        "source": {
            "dispatcher_path": BINARY_PATH,
            "dispatcher_sha256": native_source.content_sha256,
            "dispatcher_size": native_source.size,
        },
        "frontend_scope": {
            "baseline_paths": list(BASELINE_FRONTEND_PATHS),
            "expanded_paths": [
                {
                    "source_path": item.source.canonical_path,
                    "content_sha256": item.source.content_sha256,
                    "size": item.source.size,
                }
                for item in assets
            ],
            "coverage_status": frontend.coverage_status.value,
            "processed_bytes": frontend.processed_bytes,
            "binding_count": len(frontend.bindings),
            "operation_count": difference.frontend_token_count,
        },
        "scope_closure": {
            "previous_frontend_token_count": 199,
            "current_frontend_token_count": difference.frontend_token_count,
            "recovered_operations": operations,
        },
        "native": {
            "profile": native.profile,
            "operation_count": difference.native_token_count,
        },
        "difference": {
            "coverage_status": difference.coverage_status.value,
            "side_counts": dict(sorted(sides.items())),
            "attribution_counts": dict(sorted(counts.items())),
            "diagnostics": [
                {
                    "code": item.code,
                    "message": item.message,
                    "source_path": item.source_path,
                }
                for item in difference.diagnostics
            ],
        },
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
            for item in difference.attributions
        ],
        "evidence_atoms": [
            atom.to_dict() for atom in difference.evidence_atoms
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=X5000R_ROOT)
    args = parser.parse_args()
    print(json.dumps(build_summary(args.root), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
