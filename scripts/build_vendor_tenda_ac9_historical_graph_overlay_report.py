#!/usr/bin/env python3
"""Build the R2-20 real-AC9 historical graph overlay acceptance report."""

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
    DiscoveryCatalogRepository,
    HistoricalVulnerabilityRecord,
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    analyze_extracted_root,
    build_historical_vulnerability_audit,
    compare_historical_expectations,
    compare_historical_route_bindings,
    load_historical_expectations,
    project_communication_architecture_graph,
    project_historical_graph_overlay,
)
from build_vendor_tenda_ac9_registrar_inventory_report import (
    ARTIFACT_SHA256,
    ROOT,
)


EXPECTATIONS = Path(
    "docs/firmware-mapping/samples/"
    "r2-03-vendor-tenda-ac9-historical-expectations.json"
)
VULNERABILITY_SCOPE = Path(
    "docs/firmware-mapping/samples/"
    "r2-04-vendor-tenda-ac9-vulnerability-scope.json"
)
CONSOLE_SOURCES = (
    Path("apps/console/src/components/CommunicationGraphWorkspace.tsx"),
    Path("apps/console/src/api/client.ts"),
    Path("apps/console/src/types.ts"),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _get(port: int, path: str) -> dict:
    with urlopen(
        "http://127.0.0.1:{}{}".format(port, path), timeout=30
    ) as response:
        return json.loads(response.read().decode("utf-8"))["data"]


def _overlay_path(graph_id: str, values=()) -> str:
    query = urlencode(values)
    return "/api/mappings/graphs/{}/historical-overlay{}".format(
        graph_id, "?" + query if query else "",
    )


def build() -> dict:
    expectation_document = json.loads(EXPECTATIONS.read_text(encoding="utf-8"))
    expectations = load_historical_expectations(expectation_document)
    scope_document = json.loads(VULNERABILITY_SCOPE.read_text(encoding="utf-8"))
    records = tuple(
        HistoricalVulnerabilityRecord(**item)
        for item in scope_document["records"]
    )
    run = analyze_extracted_root(
        MappingAnalysisRequest(
            ROOT,
            ARTIFACT_SHA256,
            profile=MappingAnalysisProfile.auto_v13(),
        ),
        registry=BUILTIN_ANALYZER_REGISTRY_V13,
    )
    graph = project_communication_architecture_graph(run.catalog)
    diff = compare_historical_expectations(run.catalog, expectations)
    routes = compare_historical_route_bindings(run.catalog, expectations)
    audit = build_historical_vulnerability_audit(diff, records)
    overlay = project_historical_graph_overlay(
        graph, diff, routes, audit
    )

    with tempfile.TemporaryDirectory() as directory:
        mappings = DiscoveryCatalogRepository(
            str(Path(directory) / "mapping.db")
        )
        intelligence = IntelligenceRepository(":memory:")
        server = None
        thread = None
        try:
            mappings.publish(run.catalog)
            mappings.publish_communication_graph(graph)
            publication = mappings.publish_historical_graph_overlay(overlay)
            repeated_publication = mappings.publish_historical_graph_overlay(
                overlay
            )
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                create_handler(
                    IntelligenceService(intelligence),
                    static_dir="apps/console/dist",
                    mapping_repository=mappings,
                ),
            )
            thread = threading.Thread(
                target=server.serve_forever, daemon=True
            )
            thread.start()
            port = server.server_port
            all_entries = _get(port, _overlay_path(graph.graph_id))
            exact_observed = _get(port, _overlay_path(graph.graph_id, (
                ("status", "observed"),
                ("applicability", "exact_artifact"),
            )))
            cross_version = _get(port, _overlay_path(graph.graph_id, (
                ("applicability", "out_of_scope"),
            )))
            unresolved = _get(port, _overlay_path(graph.graph_id, (
                ("status", "not_assessable"),
            )))
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

    if diff.summary != {"not_assessable": 5, "observed": 8}:
        raise RuntimeError("AC9 historical expectation summary drifted")
    if audit.total_vulnerability_count != 71:
        raise RuntimeError("AC9 vulnerability denominator drifted")
    if exact_observed["selected_entry_count"] != 2:
        raise RuntimeError("AC9 exact-artifact expectation contract drifted")
    if cross_version["selected_entry_count"] != 11:
        raise RuntimeError("AC9 cross-version expectation contract drifted")
    if unresolved["selected_entry_count"] != 5:
        raise RuntimeError("AC9 unresolved expectation contract drifted")
    if repeated_publication["created"]:
        raise RuntimeError("historical overlay publication is not idempotent")
    if '<div id="root"></div>' not in console_document:
        raise RuntimeError("built Console document was not served")

    entries_by_cve = {
        item["vulnerability_identifier"]: item
        for item in all_entries["entries"]
    }
    selected_cves = (
        "CVE-2025-22946", "CVE-2025-22949", "CVE-2025-5836",
        "CVE-2025-5847", "CVE-2026-6015",
    )
    return {
        "schema_version": (
            "firmatlas.mapping.vendor-tenda-ac9-r2-20/"
            "historical-graph-overlay-v1alpha1"
        ),
        "sample_role": "tenda-ac9-primary",
        "evidence_boundary": overlay.claim_boundary,
        "analysis": {
            "analysis_run_id": run.analysis_run_id,
            "catalog_id": run.catalog.catalog_id,
            "graph_id": graph.graph_id,
            "overlay_id": overlay.overlay_id,
            "expectation_diff_id": diff.report_id,
            "route_binding_report_id": routes.report_id,
            "vulnerability_audit_id": audit.audit_id,
            "profile_id": run.profile_id,
            "analyzer_registry_id": run.analyzer_registry_id,
            "catalog_coverage_status": run.catalog.coverage_status.value,
            "graph_projection_status": graph.projection_status.value,
            "graph_node_count": len(graph.nodes),
            "graph_edge_count": len(graph.edges),
        },
        "historical_comparison": {
            "expectation_count": len(diff.entries),
            "status_summary": diff.summary,
            "applicability_summary": overlay.summary["applicability"],
            "gap_reason_summary": overlay.summary["gap_reason"],
            "route_binding_summary": routes.summary,
            "vulnerability_denominator": audit.to_dict(),
            "selected_cases": {
                cve: {
                    key: entries_by_cve[cve][key]
                    for key in (
                        "interface_value", "status", "applicability",
                        "gap_reason", "expected_parameters",
                        "observed_parameters", "missing_parameters",
                        "route_binding_status", "observed_handlers",
                        "graph_node_ids", "graph_edge_ids",
                        "graph_link_bases", "applicability_basis",
                    )
                }
                for cve in selected_cves
            },
        },
        "http_acceptance": {
            "all_entry_count": all_entries["selected_entry_count"],
            "exact_artifact_observed_count": exact_observed[
                "selected_entry_count"
            ],
            "cross_version_count": cross_version["selected_entry_count"],
            "not_assessable_count": unresolved["selected_entry_count"],
            "facets": all_entries["facets"],
            "query_ids": {
                "all": all_entries["query_id"],
                "exact_observed": exact_observed["query_id"],
                "cross_version": cross_version["query_id"],
                "not_assessable": unresolved["query_id"],
            },
            "publication": publication,
            "repeated_publication": repeated_publication,
        },
        "console_acceptance": {
            "production_document_served": True,
            "source_sha256": {
                path.as_posix(): _sha256(path) for path in CONSOLE_SOURCES
            },
            "interaction_contract": [
                "interface_and_history_index_switch",
                "historical_status_and_applicability_are_separate",
                "exact_graph_reference_focus",
                "expected_observed_and_missing_parameters",
                "route_handler_evidence",
                "gap_reason_explanation",
                "version_scope_boundary",
                "vulnerability_denominator_visible",
            ],
        },
        "diagnostics": list(overlay.diagnostics),
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
