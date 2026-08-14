#!/usr/bin/env python3
"""Build the AC9 R2-28 CGI namespace and selector report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from firmatlas.mapping import (
    BUILTIN_ANALYZER_REGISTRY_V20,
    CommunicationGraphEdgeKind,
    DiscoveryCandidateKind,
    MappingAnalysisProfile,
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
    run = analyze_extracted_root(
        MappingAnalysisRequest(
            ROOT, ARTIFACT_SHA256, profile=MappingAnalysisProfile.auto_v20()
        ),
        BUILTIN_ANALYZER_REGISTRY_V20,
    )
    graph = project_communication_architecture_graph(run.catalog)
    selectors = tuple(sorted((
        item for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.NATIVE_CGI_SELECTOR
    ), key=lambda item: item.canonical_identity))
    upload = next(
        item for item in selectors
        if item.canonical_identity == "/cgi-bin/UploadWebsite"
    )
    consumer = next(
        item for item in run.catalog.candidates
        if item.candidate_kind
        is DiscoveryCandidateKind.NATIVE_CONFIGURATION_URL_CONSUMER
        and dict(item.attributes)["function_identity"] == "bin/httpd@0x0003e564"
    )
    stage = next(
        item for item in run.stages
        if item.stage_name == "native_cgi_selector_dispatch"
    )
    focus_edges = tuple(edge for edge in graph.edges if (
        edge.source_ref == upload.candidate_id
        and edge.target_ref == consumer.candidate_id
        and edge.edge_kind is CommunicationGraphEdgeKind.CALLS
    ))
    obligations = tuple(sorted((
        item for item in run.catalog.open_obligations
        if item.target_ref == upload.candidate_id
    ), key=lambda item: item.required_capability))
    return {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-28/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-cgi-selector-transport",
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
        "namespace_binding": {
            "prefix": "/cgi-bin",
            "registration_address": "0x0002eb64",
            "registrar_address": "0x000178f0",
            "owner_identity": "bin/httpd@0x0003a678",
            "route_derivation": "prefix_plus_path_segment",
        },
        "selectors": [{
            "candidate_id": item.candidate_id,
            "canonical_identity": item.canonical_identity,
            "claim_status": item.claim_status.value,
            **dict(item.attributes),
            "evidence_ids": list(item.evidence_ids),
        } for item in selectors],
        "uploadwebsite_chain": {
            "route_candidate_id": upload.candidate_id,
            "handler_consumer_candidate_id": consumer.candidate_id,
            "graph_edge_ids": [item.edge_id for item in focus_edges],
            "daily_url_symbols": json.loads(
                dict(consumer.attributes)["client_symbols"]
            ),
            "state_key_templates": json.loads(
                dict(consumer.attributes)["state_key_templates"]
            ),
        },
        "open_obligations": [
            {
                "obligation_id": item.obligation_id,
                "required_capability": item.required_capability,
                "reason": item.reason,
                "priority": item.priority,
            }
            for item in obligations
        ],
        "not_claimed": [
            "/goform/UploadWebsite",
            "POST or another HTTP method",
            "frontend reachability, authentication, or runtime execution",
            "UploadWebsite activates load_url_mib or reload_url_mib",
            "vulnerability presence or exploitability",
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
