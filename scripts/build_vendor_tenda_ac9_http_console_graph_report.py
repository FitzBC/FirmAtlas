#!/usr/bin/env python3
"""Build the R2-19 real-AC9 HTTP and Console graph acceptance report."""

from __future__ import annotations

import argparse
import hashlib
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
from urllib.parse import urlencode
from urllib.request import urlopen

from firmatlas.intelligence.api import create_handler
from firmatlas.intelligence.repository import IntelligenceRepository
from firmatlas.intelligence.service import IntelligenceService
from firmatlas.mapping import (
    BUILTIN_ANALYZER_REGISTRY_V13,
    CommunicationGraphPolicy,
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


_CONSOLE_SOURCES = (
    Path("apps/console/src/components/CommunicationGraphWorkspace.tsx"),
    Path("apps/console/src/components/MappingCatalogWorkspace.tsx"),
    Path("apps/console/src/api/client.ts"),
    Path("apps/console/src/types.ts"),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _get(port: int, path: str) -> dict:
    with urlopen("http://127.0.0.1:{}{}".format(port, path), timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))["data"]


def _query_path(graph_id: str, values: list) -> str:
    return "/api/mappings/graphs/{}?{}".format(
        graph_id, urlencode(values),
    )


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
        mappings = DiscoveryCatalogRepository(str(database))
        intelligence = IntelligenceRepository(":memory:")
        service = IntelligenceService(intelligence)
        server = None
        thread = None
        try:
            mappings.publish(run.catalog)
            mappings.publish_communication_graph(graph)
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                create_handler(
                    service,
                    static_dir="apps/console/dist",
                    mapping_repository=mappings,
                ),
            )
            thread = threading.Thread(
                target=server.serve_forever, daemon=True
            )
            thread.start()
            port = server.server_port
            health = _get(port, "/api/health")
            listing = _get(port, "/api/mappings/graphs?page_size=10")
            interface_index = _get(port, _query_path(graph.graph_id, [
                ("q", "dlna"),
                ("node_kind", "interface"),
                ("max_hops", "0"),
                ("max_nodes", "200"),
                ("max_edges", "1"),
            ]))
            focused = _get(port, _query_path(graph.graph_id, [
                ("preset", "interface_structure"),
                ("focus_identity", "goform/SetDlnaCfg"),
                ("max_hops", "3"),
                ("max_nodes", "160"),
                ("max_edges", "320"),
            ]))
            parameters = _get(port, _query_path(graph.graph_id, [
                ("preset", "parameter_state"),
                ("focus_identity", "goform/SetDlnaCfg"),
                ("max_hops", "2"),
                ("max_nodes", "160"),
                ("max_edges", "320"),
            ]))
            with urlopen(
                "http://127.0.0.1:{}/".format(port), timeout=10
            ) as response:
                console_document = response.read().decode("utf-8")
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            if thread is not None:
                thread.join(timeout=2)
            mappings.close()
            intelligence.close()

    interface_labels = sorted(item["label"] for item in interface_index["nodes"])
    parameter_labels = sorted(
        item["label"] for item in parameters["nodes"]
        if item["node_kind"] == "parameter"
    )
    open_obligations = [
        item for item in focused["nodes"]
        if item["node_kind"] == "obligation" and item["status"] == "open"
    ]
    dlna_parameter = next(
        item for item in focused["nodes"]
        if item["node_kind"] == "parameter" and item["label"] == "dlnaEn"
    )
    dlna_evidence = [
        item for item in focused["evidence_atoms"]
        if item["evidence_id"] in dlna_parameter["evidence_ids"]
    ]
    if health != {"status": "ok"}:
        raise RuntimeError("AC9 product API health check failed")
    if listing["total"] != 1 or len(graph.nodes) != 5_674:
        raise RuntimeError("AC9 graph listing contract drifted")
    if len(graph.edges) != 7_212 or focused["query_status"] != "completed":
        raise RuntimeError("AC9 focused graph contract drifted")
    if len(interface_labels) != 4 or len(open_obligations) != 4:
        raise RuntimeError("AC9 DLNA interface or obligation contract drifted")
    if "dlnaEn" not in parameter_labels or not dlna_evidence:
        raise RuntimeError("AC9 dlnaEn evidence contract drifted")
    if '<div id="root"></div>' not in console_document:
        raise RuntimeError("built Console document was not served")

    return {
        "schema_version": (
            "firmatlas.mapping.vendor-tenda-ac9-r2-19/"
            "http-console-graph-v1alpha1"
        ),
        "sample_role": "tenda-ac9-primary",
        "evidence_boundary": (
            "The HTTP adapter translates request parameters into the shared "
            "CommunicationGraphQuery. The Console selects and renders returned "
            "facts; neither layer creates interface, owner, runtime, or "
            "vulnerability conclusions."
        ),
        "analysis": {
            "analysis_run_id": run.analysis_run_id,
            "catalog_id": run.catalog.catalog_id,
            "graph_id": graph.graph_id,
            "profile_id": run.profile_id,
            "analyzer_registry_id": run.analyzer_registry_id,
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
            "catalog_coverage_status": run.catalog.coverage_status.value,
            "graph_projection_status": graph.projection_status.value,
        },
        "http_acceptance": {
            "health": health,
            "listed_graph_count": listing["total"],
            "dlna_interface_index": {
                "query_id": interface_index["query_id"],
                "labels": interface_labels,
            },
            "focused_interface_structure": {
                "query_id": focused["query_id"],
                "query_status": focused["query_status"],
                "node_count": focused["selected_node_count"],
                "edge_count": focused["selected_edge_count"],
                "node_kind_counts": focused["facets"]["node_kinds"],
                "open_obligation_count": len(open_obligations),
                "open_obligation_labels": sorted(
                    item["label"] for item in open_obligations
                ),
                "dlnaEn_evidence": [
                    {
                        "evidence_id": item["evidence_id"],
                        "capability": item["capability"],
                        "source_path": item["source_span"]["artifact_path"],
                        "locator": item["source_span"]["locator"],
                    }
                    for item in dlna_evidence
                ],
            },
            "parameter_state": {
                "query_id": parameters["query_id"],
                "node_count": parameters["selected_node_count"],
                "edge_count": parameters["selected_edge_count"],
                "parameter_labels": parameter_labels,
            },
        },
        "console_acceptance": {
            "production_document_served": True,
            "source_sha256": {
                path.as_posix(): _sha256(path) for path in _CONSOLE_SOURCES
            },
            "interaction_contract": [
                "graph_selection",
                "interface_search_and_exact_focus",
                "interface_structure_preset",
                "parameter_state_preset",
                "communication_topology_preset",
                "completeness_and_obligation_preset",
                "evidence_atom_drilldown",
                "partial_and_coverage_diagnostics",
                "responsive_three-pane_layout",
            ],
        },
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
