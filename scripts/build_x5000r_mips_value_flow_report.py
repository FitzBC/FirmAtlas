#!/usr/bin/env python3
"""Build the replayable X5000R setLanCfg handler-prefix value-flow report."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from firmatlas.mapping import SourceArtifactEntry, discover_mips_handler_value_flows


X5000R_ROOT = Path(
    "var/mapping-work/x5000r-v9.1.0u.6118/extractions/firmware.bin.extracted/"
    "1004C/C8343R-6118.bin.extracted/184C70/squashfs-root"
)
BINARY_PATH = "www/cgi-bin/cstecgi.cgi"
HANDLER_ADDRESS = 0x004209B8


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        path, path, "file", len(content), hashlib.sha256(content).hexdigest()
    )


def build_summary(root: Path = X5000R_ROOT) -> dict:
    content = (root / BINARY_PATH).read_bytes()
    source = _source(BINARY_PATH, content)
    result = discover_mips_handler_value_flows(
        source, content, HANDLER_ADDRESS
    )
    return {
        "schema_version": "firmatlas.mapping.x5000r-mips-value-flow/v1alpha1",
        "source": {
            "source_path": source.canonical_path,
            "content_sha256": source.content_sha256,
            "size": source.size,
        },
        "handler": {
            "route_token": "setLanCfg",
            "address": "0x{:08x}".format(HANDLER_ADDRESS),
            "identity": "{}@0x{:08x}".format(BINARY_PATH, HANDLER_ADDRESS),
        },
        "profile": result.profile,
        "coverage": {
            "status": result.coverage_status.value,
            "scope": "branch-free handler prefix",
            "boundary_reason": result.boundary_reason,
            "boundary_address": (
                "0x{:08x}".format(result.boundary_address)
                if result.boundary_address is not None else None
            ),
            "processed_instructions": result.processed_instructions,
        },
        "counts": {
            "validated_parameter_state_flows": len(result.flows),
            "evidence_atoms": len(result.evidence_atoms),
        },
        "validated_pairs": [
            [flow.parameter_name, flow.state_key] for flow in result.flows
        ],
        "flows": [
            {
                "flow_id": flow.flow_id,
                "parameter_name": flow.parameter_name,
                "state_key": flow.state_key,
                "getter_symbol": flow.getter_symbol,
                "setter_symbol": flow.setter_symbol,
                "getter_callsite": "0x{:08x}".format(flow.getter_callsite),
                "setter_callsite": "0x{:08x}".format(flow.setter_callsite),
                "evidence_ids": list(flow.evidence_ids),
            }
            for flow in result.flows
        ],
        "evidence_atoms": [atom.to_dict() for atom in result.evidence_atoms],
        "open_obligations": [
            {
                "capability": "traces_branched_value_flow",
                "statement": (
                    "Analyze branch-dependent DHCP parameters and configuration "
                    "writes after the first control-flow boundary."
                ),
            },
            {
                "capability": "finds_sensitive_sink",
                "statement": (
                    "Continue from validated state writes into commit, network "
                    "reconfiguration, command, and other sensitive sinks."
                ),
            },
            {
                "capability": "attributes_set_difference",
                "statement": (
                    "Explain the 76 frontend-only and 14 native-only dispatcher "
                    "operations without forcing a synthetic match."
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
