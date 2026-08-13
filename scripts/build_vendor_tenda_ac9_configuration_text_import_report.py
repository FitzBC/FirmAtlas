#!/usr/bin/env python3
"""Build the AC9 R2-25 corrected configuration text-import report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from firmatlas.mapping import (
    CommunicationGraphEdgeKind,
    CommunicationGraphNodeKind,
    DiscoveryCandidateKind,
    MappingAnalysisRequest,
    analyze_extracted_root,
    project_communication_architecture_graph,
)
try:
    from build_vendor_tenda_ac9_registrar_inventory_report import ARTIFACT_SHA256, ROOT
except ModuleNotFoundError:
    from scripts.build_vendor_tenda_ac9_registrar_inventory_report import (
        ARTIFACT_SHA256, ROOT,
    )


HISTORICAL_KEYS = (
    "security.ddos.map",
    "sys.schedulereboot.enable",
    "sys.schedulereboot.end_time",
    "sys.schedulereboot.interval",
    "sys.schedulereboot.max_speed",
    "sys.schedulereboot.start_time",
    "sys.schedulereboot.type",
    "sys.schedulereboot.wday",
)


def build() -> dict:
    run = analyze_extracted_root(MappingAnalysisRequest(ROOT, ARTIFACT_SHA256))
    graph = project_communication_architecture_graph(run.catalog)
    candidate = next(
        item for item in run.catalog.candidates
        if item.candidate_kind
        is DiscoveryCandidateKind.NATIVE_CONFIGURATION_TEXT_IMPORT_FLOW
    )
    attributes = dict(candidate.attributes)
    states = {
        item.label: item for item in graph.nodes
        if item.node_kind is CommunicationGraphNodeKind.STATE
    }
    imports = {
        graph_node.label: edge
        for edge in graph.edges
        if edge.edge_kind is CommunicationGraphEdgeKind.IMPORTS_STATE
        and edge.source_ref == candidate.candidate_id
        for graph_node in graph.nodes
        if graph_node.node_id == edge.target_ref
    }
    stage = next(
        item for item in run.stages
        if item.stage_name == "native_configuration_text_import_flow"
    )
    return {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-25/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-configuration-text-import",
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
            "upload_identity": attributes["upload_identity"],
            "restore_identity": attributes["restore_identity"],
            "ipc_client_identity": attributes["ipc_client_identity"],
            "ipc_dispatcher_identity": attributes["ipc_dispatcher_identity"],
            "request_opcode": int(attributes["request_opcode"]),
            "payload_literal": attributes["payload_literal"],
            "parser_identity": attributes["parser_identity"],
            "primary_runtime_path": attributes["primary_runtime_path"],
            "secondary_runtime_path": attributes["secondary_runtime_path"],
            "source_document_path": attributes["source_document_path"],
            "section_delimiter": attributes["section_delimiter"],
            "import_command": attributes["import_command"],
            "state_scope": attributes["state_scope"],
            "write_granularity": attributes["write_granularity"],
            "declared_key_count": int(attributes["declared_key_count"]),
            "unique_declared_key_count": int(
                attributes["unique_declared_key_count"]
            ),
            "evidence_ids": list(candidate.evidence_ids),
        },
        "historical_configuration_keys": [
            {
                "key": key,
                "state_node_id": states[key].node_id,
                "state_evidence_ids": list(states[key].evidence_ids),
                "import_edge_id": imports[key].edge_id,
                "classification": "configuration_state_key",
                "http_parameter": False,
            }
            for key in HISTORICAL_KEYS
        ],
        "corrects_r2_24": {
            "previous_interpretation": (
                "selector 0 was treated as configuration_partition[0] and "
                "RestoreMTD as a whole_configuration_image write"
            ),
            "current_interpretation": (
                "selector 0 chooses the default_mib restore path; uploaded text "
                "is split into configuration documents and imported key by key"
            ),
            "latest_graph_contains_configuration_partition_0": (
                "configuration_partition[0]" in states
            ),
            "frozen_replay_profile": "firmatlas.mapping.profile/auto-v16",
            "current_profile": "firmatlas.mapping.profile/auto-v17",
        },
        "resolved_obligations": [
            "configuration-key-parser",
            "historical-configuration-key-state-classification",
        ],
        "remaining_obligations": [
            "observe one configuration import at runtime before claiming execution",
            "recover the distinct default_url.cfg parser and consumers",
            "bind individual configuration keys to every downstream runtime read",
        ],
        "not_claimed": [
            "configuration keys are HTTP request parameters",
            "all default values are active at runtime",
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
