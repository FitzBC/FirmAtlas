#!/usr/bin/env python3
"""Build the replayable X5000R cross-resource frontend graph summary."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from firmatlas.mapping import (
    FrontendAssetInput,
    SourceArtifactEntry,
    discover_frontend_asset_graph,
)


X5000R_ROOT = Path(
    "var/mapping-work/x5000r-v9.1.0u.6118/extractions/firmware.bin.extracted/"
    "1004C/C8343R-6118.bin.extracted/184C70/squashfs-root"
)


PATHS = (
    "www/static/js/config.js",
    "www/static/js/config_ie.js",
    "www/static/js/topicurl.js",
)


def _asset(root: Path, path: str) -> FrontendAssetInput:
    content = (root / path).read_bytes()
    return FrontendAssetInput(
        SourceArtifactEntry(
            path, path, "file", len(content), hashlib.sha256(content).hexdigest()
        ),
        content,
    )


def build_summary(root: Path = X5000R_ROOT) -> dict:
    assets = tuple(_asset(root, path) for path in PATHS)
    graph = discover_frontend_asset_graph(assets)
    candidates = {
        candidate.candidate_id: candidate
        for result in graph.results
        for candidate in result.candidates
    }
    operations = []
    for result in graph.results:
        for parameter in result.parameters:
            if not (
                parameter.is_operation_selector
                and parameter.source_construct == "shared-cgi.topicurl"
            ):
                continue
            candidate = candidates[parameter.request_candidate_id]
            operations.append({
                "selector": parameter.literal_value,
                "endpoint": candidate.endpoint,
                "method": candidate.method,
                "method_status": (
                    "resolved" if candidate.method is not None else "unresolved_dynamic"
                ),
                "request_candidate_id": candidate.candidate_id,
                "request_evidence_ids": list(candidate.evidence_ids),
                "selector_evidence_ids": list(parameter.evidence_ids),
            })
    operations.sort(key=lambda item: (item["selector"], item["request_candidate_id"]))
    return {
        "schema_version": "firmatlas.mapping.frontend-asset-graph-summary/v1alpha1",
        "coverage_status": graph.coverage_status.value,
        "processed_bytes": graph.processed_bytes,
        "sources": [
            {
                "source_path": asset.source.canonical_path,
                "content_sha256": asset.source.content_sha256,
                "size": asset.source.size,
            }
            for asset in assets
        ],
        "bindings": [
            {
                "binding_id": binding.binding_id,
                "symbol": binding.symbol,
                "value": binding.value,
                "definition_source_path": binding.definition_source_path,
                "consumer_source_path": binding.consumer_source_path,
                "request_candidate_count": len(binding.request_candidate_ids),
                "request_candidate_ids": list(binding.request_candidate_ids),
                "evidence_ids": list(binding.evidence_ids),
            }
            for binding in graph.bindings
        ],
        "operation_count": len(operations),
        "operations": operations,
        "open_obligations": [
            {
                "capability": "binds_handler",
                "statement": (
                    "Bind each topicurl selector to native cstecgi.cgi dispatch code "
                    "and downstream value flow."
                ),
            },
            {
                "capability": "resolves_method",
                "statement": (
                    "Resolve per-call HTTP method selected dynamically through this.type."
                ),
            },
        ],
        "diagnostics": [
            {"code": item.code, "message": item.message}
            for item in graph.diagnostics
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
