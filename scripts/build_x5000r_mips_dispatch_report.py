#!/usr/bin/env python3
"""Build the replayable X5000R frontend/native dispatcher comparison."""

from __future__ import annotations

from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
import re

from firmatlas.mapping import (
    FrontendAssetInput,
    NativeRouteAnchor,
    SourceArtifactEntry,
    discover_frontend_asset_graph,
    discover_mips_inline_route_bindings,
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
BINARY_PATH = "www/cgi-bin/cstecgi.cgi"


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )


def _printable_probe_anchors(content: bytes) -> tuple:
    """Enumerate broad clues; the Native Profile remains the acceptance gate."""

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


def build_summary(root: Path = X5000R_ROOT) -> dict:
    assets = []
    for path in PATHS:
        content = (root / path).read_bytes()
        assets.append(FrontendAssetInput(_source(path, content), content))
    frontend = discover_frontend_asset_graph(tuple(assets))
    frontend_parameters = tuple(
        parameter
        for result in frontend.results
        for parameter in result.parameters
        if parameter.is_operation_selector
        and parameter.source_construct == "shared-cgi.topicurl"
    )
    frontend_tokens = {parameter.literal_value for parameter in frontend_parameters}
    frontend_anchors = tuple(
        NativeRouteAnchor(
            parameter.request_candidate_id, parameter.literal_value
        )
        for parameter in frontend_parameters
    )
    binary = (root / BINARY_PATH).read_bytes()
    source = _source(BINARY_PATH, binary)
    frontend_bindings = discover_mips_inline_route_bindings(
        source, binary, frontend_anchors
    )
    table_inventory = discover_mips_inline_route_bindings(
        source, binary, _printable_probe_anchors(binary)
    )
    native_tokens = {binding.route_token for binding in table_inventory.bindings}
    duplicates = Counter(binding.route_token for binding in table_inventory.bindings)
    table_counts = Counter(
        binding.source_construct.rsplit(":", 1)[-1]
        for binding in table_inventory.bindings
    )
    return {
        "schema_version": "firmatlas.mapping.x5000r-mips-dispatch/v1alpha1",
        "source": {
            "source_path": source.canonical_path,
            "content_sha256": source.content_sha256,
            "size": source.size,
        },
        "profile": frontend_bindings.profile,
        "coverage": {
            "frontend_binding": frontend_bindings.coverage_status.value,
            "native_table_inventory": table_inventory.coverage_status.value,
        },
        "counts": {
            "frontend_selector": len(frontend_tokens),
            "native_registration": len(table_inventory.bindings),
            "native_unique_route": len(native_tokens),
            "bound_frontend_selector": len(
                {binding.route_token for binding in frontend_bindings.bindings}
            ),
            "binding_proof": len(frontend_bindings.bindings),
            "frontend_only": len(frontend_tokens - native_tokens),
            "native_only": len(native_tokens - frontend_tokens),
        },
        "table_registration_counts": dict(sorted(table_counts.items())),
        "duplicate_native_routes": {
            route: count for route, count in sorted(duplicates.items()) if count > 1
        },
        "frontend_only_selectors": sorted(frontend_tokens - native_tokens),
        "native_only_routes": sorted(native_tokens - frontend_tokens),
        "bindings": [
            {
                "binding_id": binding.binding_id,
                "target_ref": binding.target_ref,
                "route_token": binding.route_token,
                "registration_address": "0x{:08x}".format(
                    binding.registration_address
                ),
                "handler_address": "0x{:08x}".format(binding.handler_address),
                "handler_identity": binding.handler_identity,
                "source_construct": binding.source_construct,
                "evidence_ids": list(binding.evidence_ids),
            }
            for binding in frontend_bindings.bindings
        ],
        "open_obligations": [
            {
                "capability": "binds_handler",
                "count": len(frontend_tokens - native_tokens),
                "statement": (
                    "Explain or bind frontend selectors absent from the profiled "
                    "native tables."
                ),
            },
            {
                "capability": "traces_value_flow",
                "count": len({binding.route_token for binding in frontend_bindings.bindings}),
                "statement": (
                    "Recover parameter getters and sensitive data flow from each "
                    "verified handler entry."
                ),
            },
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
