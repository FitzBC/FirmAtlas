#!/usr/bin/env python3
"""Build the AC9 R2-26 latent URL-configuration document report."""

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


def build() -> dict:
    run = analyze_extracted_root(MappingAnalysisRequest(ROOT, ARTIFACT_SHA256))
    graph = project_communication_architecture_graph(run.catalog)
    candidate = next(
        item for item in run.catalog.candidates
        if item.candidate_kind
        is DiscoveryCandidateKind.NATIVE_CONFIGURATION_URL_DOCUMENT_FLOW
    )
    attributes = dict(candidate.attributes)
    obligation = next(
        item for item in run.catalog.open_obligations
        if item.target_ref == candidate.candidate_id
        and item.required_capability == "binds_configuration_url_loader_activation"
    )
    state = next(
        item for item in graph.nodes
        if item.node_kind is CommunicationGraphNodeKind.STATE
        and item.label == attributes["state_scope"]
    )
    edge = next(
        item for item in graph.edges
        if item.edge_kind is CommunicationGraphEdgeKind.IMPORTS_STATE
        and item.source_ref == candidate.candidate_id
        and item.target_ref == state.node_id
    )
    obligation_node = next(
        item for item in graph.nodes if item.node_id == obligation.obligation_id
    )
    stage = next(
        item for item in run.stages
        if item.stage_name == "native_configuration_url_document_flow"
    )
    return {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-26/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-latent-url-document-consumer",
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
            "claim_status": candidate.claim_status.value,
            "canonical_identity": candidate.canonical_identity,
            "writer_identity": attributes["writer_identity"],
            "runtime_path": attributes["runtime_path"],
            "loader_identity": attributes["loader_identity"],
            "parser_identity": attributes["parser_identity"],
            "reload_identity": attributes["reload_identity"],
            "state_scope": attributes["state_scope"],
            "write_granularity": attributes["write_granularity"],
            "activation_status": attributes["activation_status"],
            "declared_key_count": 0,
            "evidence_ids": list(candidate.evidence_ids),
        },
        "graph_projection": {
            "state_node_id": state.node_id,
            "state_label": state.label,
            "import_edge_id": edge.edge_id,
            "import_edge_status": edge.status,
            "obligation_node_id": obligation_node.node_id,
            "obligation_node_status": obligation_node.status,
        },
        "open_obligation": {
            "obligation_id": obligation.obligation_id,
            "required_capability": obligation.required_capability,
            "reason": obligation.reason,
            "priority": obligation.priority,
        },
        "negative_evidence": {
            "static_default_url_document_present": False,
            "declared_keys_known": False,
            "writer_to_loader_activation_proven": False,
            "reload_url_mib_importer_or_callsite_count": 0,
        },
        "not_claimed": [
            "cfm Upload executes load_url_mib or reload_url_mib",
            "the primary default.cfg key set belongs to cfm/url_mib/*",
            "known urlgroup.* consumers prove uploaded document declarations",
            "runtime execution, vulnerability presence, or exploitability",
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
