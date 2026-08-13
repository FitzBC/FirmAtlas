#!/usr/bin/env python3
"""Build the AC9 R2-24 configuration-image IPC/state-flow report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from firmatlas.mapping import (
    CommunicationGraphEdgeKind,
    DiscoveryCandidateKind,
    MappingAnalysisProfile,
    BUILTIN_ANALYZER_REGISTRY_V16,
    MappingAnalysisRequest,
    analyze_extracted_root,
    project_communication_architecture_graph,
)
try:
    from build_vendor_tenda_ac9_registrar_inventory_report import ARTIFACT_SHA256, ROOT
except ModuleNotFoundError:  # imported as scripts.* by contract tests
    from scripts.build_vendor_tenda_ac9_registrar_inventory_report import (
        ARTIFACT_SHA256,
        ROOT,
    )


def build() -> dict:
    # R2-24 is a frozen historical replay.  Current auto-v17 intentionally
    # supersedes this interpretation with a configuration text-import flow.
    run = analyze_extracted_root(
        MappingAnalysisRequest(
            ROOT, ARTIFACT_SHA256, profile=MappingAnalysisProfile.auto_v16()
        ),
        BUILTIN_ANALYZER_REGISTRY_V16,
    )
    graph = project_communication_architecture_graph(run.catalog)
    candidate = next(
        item for item in run.catalog.candidates
        if item.candidate_kind
        is DiscoveryCandidateKind.NATIVE_CONFIGURATION_BLOB_FLOW
    )
    attributes = dict(candidate.attributes)
    state_edge = next(
        item for item in graph.edges
        if item.edge_kind is CommunicationGraphEdgeKind.WRITES_STATE
        and item.source_ref == candidate.candidate_id
    )
    state_node = next(
        item for item in graph.nodes if item.node_id == state_edge.target_ref
    )
    stage = next(
        item for item in run.stages
        if item.stage_name == "native_configuration_blob_flow"
    )
    return {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-24/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-configuration-blob-state-flow",
        "firmware_artifact_sha256": ARTIFACT_SHA256,
        "analysis_run_id": run.analysis_run_id,
        "catalog_id": run.catalog.catalog_id,
        "graph_id": graph.graph_id,
        "profile_id": run.profile_id,
        "analyzer_registry_id": run.analyzer_registry_id,
        "stage": {
            "coverage_status": stage.coverage_status.value,
            "input_count": stage.input_count,
            "output_count": stage.output_count,
            "diagnostics": list(stage.diagnostics),
        },
        "flow": {
            "candidate_id": candidate.candidate_id,
            "canonical_identity": candidate.canonical_identity,
            "client_identity": attributes["client_identity"],
            "client_symbol": attributes["client_symbol"],
            "dispatcher_identity": attributes["dispatcher_identity"],
            "request_opcode": int(attributes["request_opcode"]),
            "response_opcode": int(attributes["response_opcode"]),
            "message_size": int(attributes["message_size"]),
            "payload_offset": int(attributes["payload_offset"]),
            "payload_literal": attributes["payload_literal"],
            "decoder_symbol": attributes["decoder_symbol"],
            "state_writer_symbol": attributes["state_writer_symbol"],
            "state_scope": attributes["state_scope"],
            "write_granularity": attributes["write_granularity"],
            "evidence_ids": list(candidate.evidence_ids),
        },
        "graph_projection": {
            "edge_kind": state_edge.edge_kind.value,
            "state_node_id": state_node.node_id,
            "state_node_kind": state_node.node_kind.value,
            "state_label": state_node.label,
        },
        "closed_obligation": "configuration-blob-wildcard-state-write",
        "remaining_obligations": [
            "recover RestoreMTD implementation and per-key parser, if present",
            "link whole-image state scope to historical configuration-key sinks",
            "obtain runtime observation before claiming execution",
        ],
        "not_claimed": [
            "payload offset 516 is an HTTP request parameter",
            "the upload format exposes individual configuration keys",
            "the static state flow executed at runtime",
            "a historical vulnerability is present or exploitable",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(
        json.dumps(build(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
