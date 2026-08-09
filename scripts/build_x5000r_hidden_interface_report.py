#!/usr/bin/env python3
"""Build the coverage-gated X5000R potential hidden-interface report."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

from firmatlas.mapping import build_potential_hidden_interface_index

if __package__:
    from scripts.build_mapping_corpus_report import X5000R_ROOT, _x5000r_catalog
else:
    from build_mapping_corpus_report import X5000R_ROOT, _x5000r_catalog


def build_summary(root: Path = X5000R_ROOT) -> dict:
    catalog = _x5000r_catalog(root)
    if catalog is None:
        raise ValueError("X5000R representative root is incomplete")
    index = build_potential_hidden_interface_index(catalog)
    artifact_counts = Counter(
        item.registration_artifact_path for item in index.items
    )
    return {
        "schema_version": (
            "firmatlas.mapping.x5000r-potential-hidden-interfaces/v1alpha1"
        ),
        "catalog_id": catalog.catalog_id,
        "firmware_artifact_sha256": catalog.firmware_artifact_sha256,
        "coverage": {
            "status": index.coverage_status.value,
            "frontend_scopes": sorted({
                scope for item in index.items
                for scope in item.frontend_coverage_scopes
            }),
            "diagnostics": [item.__dict__ for item in index.diagnostics],
        },
        "summary": {
            "potential_hidden_interface_count": len(index.items),
            "registration_artifact_count": len(artifact_counts),
            "handler_count": len({
                handler for item in index.items
                for handler in item.handler_identities
            }),
            "runtime_verified_count": sum(
                item.runtime_reachability_verified for item in index.items
            ),
        },
        "artifact_distribution": [
            {"path": path, "count": count}
            for path, count in sorted(
                artifact_counts.items(), key=lambda item: (-item[1], item[0])
            )
        ],
        "items": [
            {
                **item.__dict__,
                "binding_ids": list(item.binding_ids),
                "handler_identities": list(item.handler_identities),
                "frontend_coverage_scopes": list(item.frontend_coverage_scopes),
                "evidence_ids": list(item.evidence_ids),
            }
            for item in index.items
        ],
        "interpretation_boundary": {
            "supported": (
                "each item has a replayable native registration and handler, "
                "completed declared frontend/set-difference coverage, and no "
                "observed frontend or auxiliary native reference"
            ),
            "not_claimed": (
                "a backdoor, undocumented product feature, runtime-reachable "
                "endpoint, missing authorization, vulnerability, or exploitability"
            ),
            "remaining_hypotheses": [
                "hidden or dynamically generated clients",
                "direct requests outside shipped frontend assets",
                "dead or version-skewed registrations",
                "runtime registration and reachability differences",
            ],
        },
        "cross_firmware_contract": {
            "projection": "latest eligible discovery catalog per firmware",
            "required_coverage": [
                "source_inventory", "frontend", "set_difference"
            ],
            "excluded_shapes": [
                "frontend_scope_gap",
                "cross_native_literal",
                "cross_native_token_variant",
                "incomplete_coverage",
            ],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=X5000R_ROOT)
    args = parser.parse_args()
    print(json.dumps(build_summary(args.root), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
