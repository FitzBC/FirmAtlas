"""Command-line helpers for inspecting the mapping snapshot contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Optional, Sequence

from .domain import FirmwareMappingSnapshot, ObligationStatus
from .inventory import InventoryPolicy, build_inventory
from .analysis_run import MappingAnalysisRequest, analyze_extracted_root


def _summary(snapshot: FirmwareMappingSnapshot) -> dict:
    entity_counts = {}
    for entity in snapshot.entities:
        entity_counts[entity.entity_kind] = entity_counts.get(entity.entity_kind, 0) + 1
    coverage_counts = {}
    for entry in snapshot.coverage:
        coverage_counts[entry.status.value] = coverage_counts.get(entry.status.value, 0) + 1
    return {
        "schema_version": snapshot.schema_version,
        "snapshot_id": snapshot.snapshot_id,
        "firmware_artifact_sha256": snapshot.firmware_artifact_sha256,
        "status": snapshot.status.value,
        "interface_count": entity_counts.get("exposed_interface", 0),
        "parameter_count": entity_counts.get("parameter_identity", 0),
        "handler_count": entity_counts.get("handler_identity", 0),
        "relation_count": len(snapshot.relations),
        "evidence_count": len(snapshot.evidence_atoms),
        "coverage_counts": coverage_counts,
        "open_obligation_count": sum(
            obligation.status is ObligationStatus.OPEN
            for obligation in snapshot.unresolved_obligations
        ),
    }


def _inventory_summary(root: str, args: argparse.Namespace) -> dict:
    inventory = build_inventory(
        Path(root),
        InventoryPolicy(
            max_files=args.max_files,
            max_total_bytes=args.max_total_bytes,
            max_file_bytes=args.max_file_bytes,
            max_expanded_bytes=args.max_expanded_bytes,
            max_archive_depth=args.max_archive_depth,
        ),
    )
    return {
        "inventory_sha256": inventory.inventory_sha256,
        "coverage_status": inventory.coverage_status.value,
        "observed_count": inventory.observed_count,
        "processed_count": inventory.processed_count,
        "processed_bytes": inventory.processed_bytes,
        "expanded_bytes": inventory.expanded_bytes,
        "diagnostic_codes": sorted({item.code for item in inventory.diagnostics}),
        "sample_entries": [
            {
                "kind": item.kind,
                "path": item.canonical_path,
                "size": item.size,
                "content_sha256": item.content_sha256,
            }
            for item in inventory.entries[: args.sample_limit]
        ],
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m firmatlas.mapping")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser(
        "validate-snapshot", help="validate and summarize a mapping snapshot JSON file"
    )
    validate.add_argument("path")
    inventory = subparsers.add_parser(
        "inventory", help="build and summarize a safe extracted-root inventory"
    )
    defaults = InventoryPolicy()
    inventory.add_argument("root")
    inventory.add_argument("--max-files", type=int, default=defaults.max_files)
    inventory.add_argument(
        "--max-total-bytes", type=int, default=defaults.max_total_bytes
    )
    inventory.add_argument("--max-file-bytes", type=int, default=defaults.max_file_bytes)
    inventory.add_argument(
        "--max-expanded-bytes", type=int, default=defaults.max_expanded_bytes
    )
    inventory.add_argument(
        "--max-archive-depth", type=int, default=defaults.max_archive_depth
    )
    inventory.add_argument("--sample-limit", type=int, default=10)
    analyze = subparsers.add_parser(
        "analyze-root",
        help="run deterministic cold-start mapping against an extracted firmware root",
    )
    analyze.add_argument("root")
    analyze.add_argument("--artifact-sha256", required=True)
    analyze.add_argument("--output", required=True)
    analyze.add_argument("--max-files", type=int, default=defaults.max_files)
    analyze.add_argument(
        "--max-total-bytes", type=int, default=defaults.max_total_bytes
    )
    analyze.add_argument("--max-file-bytes", type=int, default=defaults.max_file_bytes)
    analyze.add_argument(
        "--max-expanded-bytes", type=int, default=defaults.max_expanded_bytes
    )
    analyze.add_argument(
        "--max-archive-depth", type=int, default=defaults.max_archive_depth
    )
    args = parser.parse_args(argv)

    try:
        if args.command == "inventory":
            if args.sample_limit < 0:
                raise ValueError("sample-limit must be nonnegative")
            result = _inventory_summary(args.root, args)
        elif args.command == "analyze-root":
            run = analyze_extracted_root(MappingAnalysisRequest(
                root=Path(args.root),
                firmware_artifact_sha256=args.artifact_sha256,
                inventory_policy=InventoryPolicy(
                    max_files=args.max_files,
                    max_total_bytes=args.max_total_bytes,
                    max_file_bytes=args.max_file_bytes,
                    max_expanded_bytes=args.max_expanded_bytes,
                    max_archive_depth=args.max_archive_depth,
                ),
            ))
            output = Path(args.output)
            output.write_text(
                json.dumps(run.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            result = {
                "schema_version": run.schema_version,
                "analysis_run_id": run.analysis_run_id,
                "catalog_id": run.catalog.catalog_id,
                "coverage_status": run.coverage_status.value,
                "candidate_count": len(run.catalog.candidates),
                "parameter_count": len(run.catalog.parameters),
                "evidence_count": len(run.catalog.evidence_atoms),
                "open_obligation_count": len(run.catalog.open_obligations),
                "output": str(output),
            }
        else:
            payload = json.loads(Path(args.path).read_text(encoding="utf-8"))
            snapshot = FirmwareMappingSnapshot.from_dict(payload)
            result = _summary(snapshot)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("mapping command failed: {}".format(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
