"""Command-line helpers for inspecting the mapping snapshot contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Optional, Sequence

from .domain import FirmwareMappingSnapshot, ObligationStatus


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


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m firmatlas.mapping")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser(
        "validate-snapshot", help="validate and summarize a mapping snapshot JSON file"
    )
    validate.add_argument("path")
    args = parser.parse_args(argv)

    try:
        payload = json.loads(Path(args.path).read_text(encoding="utf-8"))
        snapshot = FirmwareMappingSnapshot.from_dict(payload)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("mapping snapshot validation failed: {}".format(exc), file=sys.stderr)
        return 1
    print(json.dumps(_summary(snapshot), ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
