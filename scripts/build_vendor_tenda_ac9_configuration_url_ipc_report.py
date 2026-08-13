#!/usr/bin/env python3
"""Build the AC9 R2-27 URL-store IPC and consumer report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from firmatlas.mapping import (
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
    operations = tuple(sorted((
        item for item in run.catalog.candidates
        if item.candidate_kind
        is DiscoveryCandidateKind.NATIVE_CONFIGURATION_URL_IPC_FLOW
    ), key=lambda item: dict(item.attributes)["operation"]))
    consumers = tuple(sorted((
        item for item in run.catalog.candidates
        if item.candidate_kind
        is DiscoveryCandidateKind.NATIVE_CONFIGURATION_URL_CONSUMER
    ), key=lambda item: dict(item.attributes)["function_identity"]))
    stage = next(
        item for item in run.stages
        if item.stage_name == "native_configuration_url_ipc_flow"
    )
    url_candidate_ids = {
        item.candidate_id for item in (*operations, *consumers)
    }
    url_state_ids = {
        edge.target_ref for edge in graph.edges
        if edge.source_ref in url_candidate_ids
        and edge.edge_kind.value in {
            "reads_state", "writes_state", "deletes_state", "persists_state"
        }
    }
    state_labels = {
        node.label for node in graph.nodes if node.node_id in url_state_ids
    }
    primary_state_labels = {
        node.label for node in graph.nodes
        if node.label in {"urlgroup.rule.listnum", "urlgroup.rule.list1"}
        and node.node_id not in url_state_ids
    }
    return {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-27/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-url-store-ipc-and-consumers",
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
        "channel": {
            "path": "/var/cfm_socket",
            "message_size": 2016,
            "layout": {"opcode": 0, "key_or_path": 4, "value": 516},
        },
        "operations": [
            {
                "candidate_id": item.candidate_id,
                "canonical_identity": item.canonical_identity,
                "claim_status": item.claim_status.value,
                **dict(item.attributes),
                "evidence_ids": list(item.evidence_ids),
            }
            for item in operations
        ],
        "consumers": [
            {
                "candidate_id": item.candidate_id,
                "canonical_identity": item.canonical_identity,
                "claim_status": item.claim_status.value,
                **dict(item.attributes),
                "evidence_ids": list(item.evidence_ids),
            }
            for item in consumers
        ],
        "graph_projection": {
            "state_labels": sorted(state_labels),
            "url_scope_edge_kinds": sorted({
                edge.edge_kind.value for edge in graph.edges
                if edge.source_ref in url_candidate_ids
                and edge.target_ref in url_state_ids
            }),
        },
        "cross_store_boundary": {
            "url_store_templates": sorted(
                label for label in state_labels if label.startswith("urlgroup.")
            ),
            "excluded_from_url_store": [
                "urlgroup.rule.list%d",
                "urlgroup.rule.listnum",
                "urlgroup.flag",
                "urlgroup.name",
            ],
            "observed_primary_store_exact_keys": sorted(primary_state_labels),
            "reason": (
                "rule.* and flag call primary GetValue/UnSetValue/CommitCfm; "
                "name has no per-callsite URL-store binding"
            ),
        },
        "activation_obligation": {
            "status": "open",
            "required_capability": "binds_configuration_url_loader_activation",
            "daily_ipc_does_not_resolve_document_import": True,
        },
        "not_claimed": [
            "the UploadWebsite selector is a complete HTTP path or method",
            "URL IPC key templates are declarations from default_url.cfg",
            "daily URL IPC activates load_url_mib or reload_url_mib",
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
