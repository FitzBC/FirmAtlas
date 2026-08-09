#!/usr/bin/env python3
"""Extract one firmware artifact with the hardened Container Binwalk Adapter."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from firmatlas.mapping import (
    BinwalkExtractor,
    ContainerBinwalkConfig,
    ContainerBinwalkWorker,
    ExtractionPolicy,
    ExtractionRequest,
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--max-seconds", type=int, default=900)
    args = parser.parse_args()

    artifact_sha256 = _sha256(args.artifact)
    worker = ContainerBinwalkWorker(ContainerBinwalkConfig(
        runtime_path=args.runtime,
        image_ref=args.image_ref,
    ))
    result = BinwalkExtractor(worker).extract(ExtractionRequest(
        artifact_path=args.artifact,
        artifact_sha256=artifact_sha256,
        destination=args.destination,
        policy=ExtractionPolicy(max_seconds=args.max_seconds),
    ))
    print(json.dumps({
        "schema_version": "firmatlas.mapping.extraction-summary/v1alpha1",
        "artifact_path": str(args.artifact),
        "artifact_sha256": artifact_sha256,
        "status": result.status.value,
        "tool": result.to_dict()["tool"],
        "execution_fingerprint": result.execution_fingerprint,
        "exit_code": result.execution.exit_code,
        "inventory_sha256": (
            result.inventory.inventory_sha256 if result.inventory else None
        ),
        "inventory_coverage_status": (
            result.inventory.coverage_status.value if result.inventory else None
        ),
        "inventory_entry_count": (
            len(result.inventory.entries) if result.inventory else 0
        ),
        "diagnostics": [item.__dict__ for item in result.diagnostics],
    }, ensure_ascii=False, indent=2))
    return 0 if result.inventory is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
