#!/usr/bin/env python3
"""Build the R2-18 persisted AC9 communication-graph query report."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from firmatlas.mapping import (
    BUILTIN_ANALYZER_REGISTRY_V13,
    CommunicationGraphPolicy,
    CommunicationGraphQuery,
    DiscoveryCatalogRepository,
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    analyze_extracted_root,
    project_communication_architecture_graph,
)
from build_vendor_tenda_ac9_registrar_inventory_report import (
    ARTIFACT_SHA256,
    ROOT,
)


_DLNA_ENDPOINTS = (
    "goform/GetDlnaCfg",
    "goform/SetDlnaCfg",
    "goform/expandDlnaFile?",
    "/goform/refreshDLNA",
)
_R2_17_REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-17-vendor-tenda-ac9-ac18-dlna-communication-graph.json"
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _query_summary(result: dict) -> dict:
    return {
        "schema_version": result["schema_version"],
        "query_id": result["query_id"],
        "query_status": result["query_status"],
        "total_node_count": result["total_node_count"],
        "total_edge_count": result["total_edge_count"],
        "selected_node_count": result["selected_node_count"],
        "selected_edge_count": result["selected_edge_count"],
        "node_kind_counts": result["facets"]["node_kinds"],
        "edge_kind_counts": result["facets"]["edge_kinds"],
        "evidence_atom_count": len(result["evidence_atoms"]),
        "diagnostics": result["diagnostics"],
    }


def _parameter_evidence_id(parameter_query: dict) -> str:
    parameter = next(
        item for item in parameter_query["nodes"]
        if item["node_kind"] == "parameter" and item["label"] == "dlnaEn"
    )
    if not parameter["evidence_ids"]:
        raise RuntimeError("dlnaEn parameter has no evidence")
    return parameter["evidence_ids"][0]


def _stable_listing(listing: dict) -> dict:
    return {
        **listing,
        "items": [
            {key: value for key, value in item.items() if key != "published_at"}
            for item in listing["items"]
        ],
    }


def build() -> dict:
    run = analyze_extracted_root(
        MappingAnalysisRequest(
            ROOT,
            ARTIFACT_SHA256,
            profile=MappingAnalysisProfile.auto_v13(),
        ),
        registry=BUILTIN_ANALYZER_REGISTRY_V13,
    )
    graph = project_communication_architecture_graph(
        run.catalog, CommunicationGraphPolicy()
    )
    with tempfile.TemporaryDirectory() as directory:
        database = Path(directory) / "mapping.db"
        first = DiscoveryCatalogRepository(str(database))
        try:
            catalog_publish = first.publish(run.catalog)
            graph_publish = first.publish_communication_graph(graph)
            graph_republish = first.publish_communication_graph(graph)
        finally:
            first.close()
        repository = DiscoveryCatalogRepository(str(database))
        try:
            listing = repository.list_communication_graphs()
            interface_query = repository.query_communication_graph(
                graph.graph_id,
                CommunicationGraphQuery(
                    preset_id="interface_structure",
                    focus_canonical_identities=_DLNA_ENDPOINTS,
                    max_hops=4,
                    max_nodes=500,
                    max_edges=1_000,
                ),
            )
            parameter_query = repository.query_communication_graph(
                graph.graph_id,
                CommunicationGraphQuery(
                    preset_id="parameter_state",
                    focus_canonical_identities=_DLNA_ENDPOINTS,
                    max_hops=2,
                    max_nodes=200,
                    max_edges=400,
                ),
            )
            completeness_query = repository.query_communication_graph(
                graph.graph_id,
                CommunicationGraphQuery(
                    preset_id="completeness",
                    focus_canonical_identities=_DLNA_ENDPOINTS,
                    max_hops=4,
                    max_nodes=500,
                    max_edges=1_000,
                ),
            )
            component_search = repository.query_communication_graph(
                graph.graph_id,
                CommunicationGraphQuery(
                    text="minidlna",
                    node_kinds=(
                        "artifact", "component", "communication_relation",
                        "evidence_candidate", "service_assembly",
                    ),
                    max_nodes=100,
                    max_edges=200,
                ),
            )
            evidence_id = _parameter_evidence_id(parameter_query)
            evidence_query = repository.query_communication_graph(
                graph.graph_id,
                CommunicationGraphQuery(
                    evidence_id=evidence_id,
                    max_nodes=100,
                    max_edges=200,
                ),
            )
        finally:
            repository.close()
    if interface_query is None or parameter_query is None:
        raise RuntimeError("persisted AC9 graph could not be queried")
    if completeness_query is None or component_search is None:
        raise RuntimeError("persisted AC9 graph query view is missing")
    if evidence_query is None:
        raise RuntimeError("persisted AC9 evidence query is missing")
    if not catalog_publish["created"] or not graph_publish["created"]:
        raise RuntimeError("first AC9 graph publication was not created")
    if graph_republish["created"]:
        raise RuntimeError("AC9 graph publication is not idempotent")
    if listing["total"] != 1:
        raise RuntimeError("AC9 graph did not survive repository reopen")
    return {
        "schema_version": (
            "firmatlas.mapping.vendor-tenda-ac9-r2-18/"
            "persisted-graph-query-v1alpha1"
        ),
        "sample_role": "tenda-ac9-primary",
        "evidence_boundary": (
            "Persistence and query reuse one immutable graph and its source "
            "Catalog. Query filters, focus hops, and view presets select facts; "
            "they do not create endpoint, parameter, owner, runtime, history, "
            "or vulnerability claims."
        ),
        "analysis": {
            "analysis_run_id": run.analysis_run_id,
            "profile_id": run.profile_id,
            "analyzer_registry_id": run.analyzer_registry_id,
            "catalog_id": run.catalog.catalog_id,
            "catalog_coverage_status": run.catalog.coverage_status.value,
            "graph_id": graph.graph_id,
            "graph_projection_status": graph.projection_status.value,
            "full_graph_node_count": len(graph.nodes),
            "full_graph_edge_count": len(graph.edges),
        },
        "persistence": {
            "catalog_publish": catalog_publish,
            "graph_publish": graph_publish,
            "graph_republish": graph_republish,
            # Publication time is repository metadata, not graph identity. Keep
            # this checked by the repository tests but omit it from the
            # reproducible sample artifact.
            "reopened_listing": _stable_listing(listing),
        },
        "queries": {
            "interface_structure": {
                "summary": _query_summary(interface_query),
                "result": interface_query,
            },
            "parameter_state": {
                "summary": _query_summary(parameter_query),
                "result": parameter_query,
            },
            "completeness": {
                "summary": _query_summary(completeness_query),
                "result": completeness_query,
            },
            "minidlna_component_search": {
                "summary": _query_summary(component_search),
                "result": component_search,
            },
            "dlnaEn_evidence_drilldown": {
                "evidence_id": evidence_id,
                "summary": _query_summary(evidence_query),
                "result": evidence_query,
            },
        },
        "prior_round": {
            "report": _R2_17_REPORT.as_posix(),
            "report_sha256": _sha(_R2_17_REPORT),
        },
        "open_obligations": [
            "expose this repository query through the product HTTP adapter",
            "render the same presets and evidence bundle in the Console",
            "repeat persisted-query validation on HNAP, shared-CGI, and ubus",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    payload = build()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
