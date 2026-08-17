#!/usr/bin/env python3
"""Build the R2-29 complete AC9 historical coverage ledger report."""

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
    DiscoveryCatalogRepository,
    HistoricalVulnerabilityRecord,
    MappingAnalysisRequest,
    analyze_extracted_root,
    build_historical_coverage_ledger,
    build_historical_coverage_queue,
    build_historical_vulnerability_audit,
    compare_historical_expectations,
    compare_historical_route_bindings,
    load_historical_expectations,
    load_historical_semantic_clues,
    project_communication_architecture_graph,
    project_historical_graph_overlay,
)
from build_vendor_tenda_ac9_registrar_inventory_report import ARTIFACT_SHA256, ROOT


SAMPLES = Path("docs/firmware-mapping/samples")
EXPECTATION_PATHS = (
    SAMPLES / "r2-03-vendor-tenda-ac9-historical-expectations.json",
    SAMPLES / "r2-21-vendor-tenda-ac9-historical-expectation-supplement.json",
)
VULNERABILITY_SCOPE = SAMPLES / "r2-04-vendor-tenda-ac9-vulnerability-scope.json"
SEMANTIC_CLUES = SAMPLES / "r2-21-vendor-tenda-ac9-historical-semantic-clues.json"
CONSOLE_SOURCES = (
    Path("apps/console/src/components/CommunicationGraphWorkspace.tsx"),
    Path("apps/console/src/api/client.ts"),
    Path("apps/console/src/types.ts"),
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_historical_context(run, graph):
    expectations = tuple(
        expectation
        for path in EXPECTATION_PATHS
        for expectation in load_historical_expectations(
            json.loads(path.read_text(encoding="utf-8"))
        )
    )
    records = tuple(
        HistoricalVulnerabilityRecord(**item)
        for item in json.loads(
            VULNERABILITY_SCOPE.read_text(encoding="utf-8")
        )["records"]
    )
    clues = load_historical_semantic_clues(json.loads(
        SEMANTIC_CLUES.read_text(encoding="utf-8")
    ))
    diff = compare_historical_expectations(run.catalog, expectations)
    audit = build_historical_vulnerability_audit(diff, records)
    overlay = project_historical_graph_overlay(
        graph,
        diff,
        compare_historical_route_bindings(run.catalog, expectations),
        audit,
    )
    queue = build_historical_coverage_queue(audit, clues, run.catalog)
    ledger = build_historical_coverage_ledger(overlay, queue)
    return diff, audit, overlay, queue, ledger


def _get(port: int, path: str) -> dict:
    with urlopen("http://127.0.0.1:{}{}".format(port, path), timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))["data"]


def build() -> dict:
    run = analyze_extracted_root(MappingAnalysisRequest(ROOT, ARTIFACT_SHA256))
    graph = project_communication_architecture_graph(run.catalog)
    diff, audit, overlay, queue, ledger = build_historical_context(run, graph)

    with tempfile.TemporaryDirectory() as directory:
        mappings = DiscoveryCatalogRepository(str(Path(directory) / "mapping.db"))
        intelligence = IntelligenceRepository(":memory:")
        server = None
        thread = None
        try:
            mappings.publish(run.catalog)
            mappings.publish_communication_graph(graph)
            mappings.publish_historical_graph_overlay(overlay)
            publication = mappings.publish_historical_coverage_ledger(ledger)
            repeated = mappings.publish_historical_coverage_ledger(ledger)
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0),
                create_handler(
                    IntelligenceService(intelligence),
                    static_dir="apps/console/dist",
                    mapping_repository=mappings,
                ),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_port
            all_entries = _get(
                port,
                "/api/mappings/graphs/{}/historical-coverage".format(graph.graph_id),
            )
            parameter_gap = _get(
                port,
                "/api/mappings/graphs/{}/historical-coverage?{}".format(
                    graph.graph_id,
                    urlencode({
                        "q": "security.ddos.map",
                        "status": "partial",
                        "audit_category": "parameter_only",
                    }),
                ),
            )
            with urlopen("http://127.0.0.1:{}/".format(port), timeout=10) as response:
                console_document = response.read().decode("utf-8")
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            if thread is not None:
                thread.join(timeout=2)
            mappings.close()
            intelligence.close()

    expected_status = {"not_assessable": 60, "observed": 9, "partial": 2}
    if ledger.total_vulnerability_count != 71 or ledger.summary["status"] != expected_status:
        raise RuntimeError("AC9 complete historical denominator drifted")
    if audit.exact_artifact_expectation_count != 3 or audit.exact_artifact_observed_count != 3:
        raise RuntimeError("AC9 exact-artifact historical coverage drifted")
    if len(queue.entries) != 57:
        raise RuntimeError("AC9 unresolved historical queue drifted")
    if parameter_gap["selected_entry_count"] != 1:
        raise RuntimeError("AC9 parameter-only explanation query drifted")
    if '<div id="root"></div>' not in console_document:
        raise RuntimeError("built Console document was not served")

    by_cve = {
        item["vulnerability_identifier"]: item for item in all_entries["entries"]
    }
    selected = ("CVE-2021-42659", "CVE-2026-2191", "CVE-2026-2192")
    return {
        "schema_version": (
            "firmatlas.mapping.vendor-tenda-ac9-r2-29/"
            "historical-coverage-ledger-v1alpha1"
        ),
        "sample_role": "tenda-ac9-primary-complete-historical-denominator",
        "analysis": {
            "analysis_run_id": run.analysis_run_id,
            "catalog_id": run.catalog.catalog_id,
            "graph_id": graph.graph_id,
            "overlay_id": overlay.overlay_id,
            "queue_id": queue.queue_id,
            "ledger_id": ledger.ledger_id,
            "profile_id": run.profile_id,
            "analyzer_registry_id": run.analyzer_registry_id,
            "catalog_coverage_status": run.catalog.coverage_status.value,
        },
        "coverage_ledger": {
            "total_vulnerability_count": ledger.total_vulnerability_count,
            "status_summary": ledger.summary["status"],
            "audit_category_summary": ledger.summary["audit_category"],
            "evidence_state_summary": ledger.summary["evidence_state"],
            "exact_artifact_expectation_count": audit.exact_artifact_expectation_count,
            "exact_artifact_observed_count": audit.exact_artifact_observed_count,
            "structured_expectation_count": len(diff.entries),
            "open_queue_count": len(queue.entries),
            "selected_cases": {identifier: by_cve[identifier] for identifier in selected},
            "claim_boundary": ledger.claim_boundary,
        },
        "http_acceptance": {
            "all_entry_count": all_entries["selected_entry_count"],
            "parameter_gap_query_count": parameter_gap["selected_entry_count"],
            "facets": all_entries["facets"],
            "publication": publication,
            "repeated_publication": repeated,
        },
        "console_acceptance": {
            "production_document_served": True,
            "source_sha256": {
                path.as_posix(): _sha256(path) for path in CONSOLE_SOURCES
            },
            "interaction_contract": [
                "complete_71_record_denominator",
                "status_summary_visible",
                "search_by_cve_interface_parameter_reason",
                "configuration_key_not_http_parameter",
                "graph_focus_only_when_graph_references_exist",
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
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
