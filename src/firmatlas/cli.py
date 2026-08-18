"""Small executable proving the initial analysis interface is usable."""

import argparse
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Optional, Sequence

from .domain import (
    AnalysisReport,
    AnalysisStatus,
    AnalyzerIdentity,
    ArtifactRef,
    Confidence,
    EvidenceRef,
    Observation,
)


def demo_report() -> AnalysisReport:
    digest = "a" * 64
    when = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return AnalysisReport(
        run_id="demo-run",
        artifact=ArtifactRef(sha256=digest, size=4096),
        analyzer=AnalyzerIdentity(
            name="demo.inventory", version="0.1.0", rules_version="2026.01"
        ),
        status=AnalysisStatus.SUCCEEDED,
        started_at=when,
        finished_at=when,
        observations=(
            Observation(
                kind="software-component",
                subject="busybox",
                attributes={"version": "unknown"},
                confidence=Confidence.MEDIUM,
                evidence=(
                    EvidenceRef(
                        artifact_sha256=digest,
                        locator="filesystem:/bin/busybox",
                        description="executable path",
                    ),
                ),
            ),
        ),
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="firmatlas")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("demo-report", help="print a minimal analysis report")
    intelligence = subparsers.add_parser(
        "intelligence", help="acquire and serve firmware vulnerability intelligence"
    )
    intelligence_subparsers = intelligence.add_subparsers(
        dest="intelligence_command", required=True
    )

    serve_parser = intelligence_subparsers.add_parser("serve", help="start the HTTP API")
    _database_argument(serve_parser)
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8787)
    serve_parser.add_argument(
        "--static-dir",
        help="serve the built console from this directory on non-API routes",
    )

    sync_parser = intelligence_subparsers.add_parser(
        "sync", help="incrementally update official intelligence sources"
    )
    _database_argument(sync_parser)
    sync_parser.add_argument(
        "--source",
        action="append",
        choices=("nvd", "cisa-kev"),
        dest="sources",
        help="source to update; repeat to select multiple",
    )
    sync_parser.add_argument("--days", type=int, default=1)

    bootstrap_parser = intelligence_subparsers.add_parser(
        "bootstrap-feeds", help="download and import all NVD yearly JSON 2.0 feeds"
    )
    _database_argument(bootstrap_parser)
    bootstrap_parser.add_argument("--cache-dir", default="var/nvd-feeds")
    bootstrap_parser.add_argument("--year", action="append", dest="years")
    bootstrap_parser.add_argument("--force", action="store_true")

    update_parser = intelligence_subparsers.add_parser(
        "update-feeds", help="apply the NVD modified feed and reconcile long gaps"
    )
    _database_argument(update_parser)
    update_parser.add_argument("--cache-dir", default="var/nvd-feeds")
    update_parser.add_argument("--force", action="store_true")

    seed_parser = intelligence_subparsers.add_parser(
        "seed-demo", help="load deterministic UI development records"
    )
    _database_argument(seed_parser)

    firmware = subparsers.add_parser(
        "firmware", help="discover and query firmware sample metadata"
    )
    firmware_subparsers = firmware.add_subparsers(
        dest="firmware_command", required=True
    )
    catalog_parser = firmware_subparsers.add_parser(
        "bootstrap-catalog",
        help="import public firmware sample URLs and vulnerability leads",
    )
    _database_argument(catalog_parser)
    link_parser = firmware_subparsers.add_parser(
        "link-vulnerabilities",
        help="derive explainable sample links from affected product version claims",
    )
    _database_argument(link_parser)
    mapping = subparsers.add_parser(
        "mapping", help="publish and inspect evidence-backed discovery catalogs"
    )
    mapping_subparsers = mapping.add_subparsers(
        dest="mapping_command", required=True
    )
    publish_parser = mapping_subparsers.add_parser(
        "publish-catalog", help="publish a versioned discovery catalog JSON document"
    )
    _database_argument(publish_parser)
    publish_parser.add_argument("document", help="path to a discovery catalog JSON file")
    list_parser = mapping_subparsers.add_parser(
        "list-catalogs", help="list published discovery catalog summaries"
    )
    _database_argument(list_parser)
    publish_graph_parser = mapping_subparsers.add_parser(
        "publish-graph",
        help="publish a graph with its source Catalog from an analysis run",
    )
    _database_argument(publish_graph_parser)
    publish_graph_parser.add_argument(
        "--catalog-document", required=True,
        help="path to a Discovery Catalog or AnalyzeRun JSON document",
    )
    publish_graph_parser.add_argument(
        "document", help="path to a communication graph JSON document",
    )
    list_graphs_parser = mapping_subparsers.add_parser(
        "list-graphs", help="list persisted communication graph summaries",
    )
    _database_argument(list_graphs_parser)
    query_graph_parser = mapping_subparsers.add_parser(
        "query-graph", help="query one persisted communication graph",
    )
    _database_argument(query_graph_parser)
    query_graph_parser.add_argument("graph_id")
    query_graph_parser.add_argument("--query", default="")
    query_graph_parser.add_argument("--preset", default="")
    query_graph_parser.add_argument(
        "--node-kind", action="append", default=[]
    )
    query_graph_parser.add_argument(
        "--edge-kind", action="append", default=[]
    )
    query_graph_parser.add_argument("--status", action="append", default=[])
    query_graph_parser.add_argument("--evidence-id", default="")
    query_graph_parser.add_argument(
        "--focus-node", action="append", default=[]
    )
    query_graph_parser.add_argument(
        "--focus-identity", action="append", default=[]
    )
    query_graph_parser.add_argument("--max-hops", type=int, default=2)
    query_graph_parser.add_argument("--max-nodes", type=int, default=500)
    query_graph_parser.add_argument("--max-edges", type=int, default=1000)
    publish_overlay_parser = mapping_subparsers.add_parser(
        "publish-history-overlay",
        help="publish an immutable historical expectation graph overlay",
    )
    _database_argument(publish_overlay_parser)
    publish_overlay_parser.add_argument(
        "document", help="path to a historical graph overlay JSON document"
    )
    query_overlay_parser = mapping_subparsers.add_parser(
        "query-history-overlay",
        help="query the latest historical expectation overlay for a graph",
    )
    _database_argument(query_overlay_parser)
    query_overlay_parser.add_argument("graph_id")
    query_overlay_parser.add_argument("--query", default="")
    query_overlay_parser.add_argument("--status", action="append", default=[])
    query_overlay_parser.add_argument(
        "--applicability", action="append", default=[]
    )
    query_overlay_parser.add_argument(
        "--gap-reason", action="append", default=[]
    )
    query_overlay_parser.add_argument(
        "--route-binding-status", action="append", default=[]
    )
    publish_ledger_parser = mapping_subparsers.add_parser(
        "publish-history-ledger",
        help="publish an immutable complete historical coverage ledger",
    )
    _database_argument(publish_ledger_parser)
    publish_ledger_parser.add_argument(
        "document", help="path to a historical coverage ledger JSON document"
    )
    query_ledger_parser = mapping_subparsers.add_parser(
        "query-history-ledger",
        help="query the complete historical coverage ledger for a graph",
    )
    _database_argument(query_ledger_parser)
    query_ledger_parser.add_argument("graph_id")
    query_ledger_parser.add_argument("--query", default="")
    query_ledger_parser.add_argument("--status", action="append", default=[])
    query_ledger_parser.add_argument(
        "--audit-category", action="append", default=[]
    )
    query_ledger_parser.add_argument(
        "--evidence-state", action="append", default=[]
    )
    args = parser.parse_args(argv)

    if args.command == "demo-report":
        print(json.dumps(demo_report().to_dict(), ensure_ascii=False, indent=2))
        return 0
    if args.command == "intelligence":
        if args.intelligence_command == "serve":
            from .intelligence.api import serve

            logging.basicConfig(level=logging.INFO, format="%(message)s")
            serve(args.database, args.host, args.port, args.static_dir)
            return 0

        from .intelligence.relevance import FirmwareRelevanceClassifier
        from .intelligence.repository import IntelligenceRepository

        repository = IntelligenceRepository(args.database)
        try:
            if args.intelligence_command == "sync":
                from .intelligence.service import IntelligenceService

                result = IntelligenceService(repository).sync(
                    args.sources or ("nvd", "cisa-kev"), args.days
                )
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.intelligence_command in ("bootstrap-feeds", "update-feeds"):
                from .intelligence.feeds import NvdFeedMirror
                from .intelligence.service import IntelligenceService

                service = IntelligenceService(
                    repository, feed_mirror=NvdFeedMirror(args.cache_dir)
                )
                if args.intelligence_command == "bootstrap-feeds":
                    result = service.bootstrap_feeds(args.years, args.force)
                else:
                    result = service.update_feeds(args.force)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.intelligence_command == "seed-demo":
                from .intelligence.sample_data import demo_records

                classifier = FirmwareRelevanceClassifier()
                policy = repository.get_policy()
                for record in demo_records():
                    repository.upsert(record, classifier.classify(record, policy))
                repository.refresh_analytics()
                print(
                    json.dumps(repository.overview(), ensure_ascii=False, indent=2)
                )
                return 0
        finally:
            repository.close()
    if args.command == "firmware":
        from .firmware_catalog import bootstrap_public_catalog
        from .firmware_version_linking import FirmwareVersionLinker
        from .intelligence.repository import IntelligenceRepository

        repository = IntelligenceRepository(args.database)
        try:
            if args.firmware_command == "bootstrap-catalog":
                result = bootstrap_public_catalog(repository)
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
            if args.firmware_command == "link-vulnerabilities":
                result = FirmwareVersionLinker(repository).rebuild()
                print(json.dumps(result, ensure_ascii=False, indent=2))
                return 0
        finally:
            repository.close()
    if args.command == "mapping":
        from .mapping.communication_graph import (
            CommunicationArchitectureGraph,
        )
        from .mapping.historical_graph_overlay import HistoricalGraphOverlay
        from .mapping.historical_coverage_ledger import HistoricalCoverageLedger
        from .mapping.repository import (
            CommunicationGraphQuery,
            DiscoveryCatalogRepository,
            HistoricalCoverageLedgerQuery,
            HistoricalGraphOverlayQuery,
        )

        repository = DiscoveryCatalogRepository(args.database)
        try:
            if args.mapping_command == "publish-catalog":
                document = json.loads(Path(args.document).read_text(encoding="utf-8"))
                result = repository.publish_dict(_catalog_document(document))
            elif args.mapping_command == "list-catalogs":
                result = repository.list_catalogs()
            elif args.mapping_command == "publish-graph":
                catalog_document = json.loads(
                    Path(args.catalog_document).read_text(encoding="utf-8")
                )
                catalog = _catalog_document(catalog_document)
                graph = CommunicationArchitectureGraph.from_dict(json.loads(
                    Path(args.document).read_text(encoding="utf-8")
                ))
                result = {
                    "catalog": repository.publish_dict(catalog),
                    "graph": repository.publish_communication_graph(graph),
                }
            elif args.mapping_command == "list-graphs":
                result = repository.list_communication_graphs()
            elif args.mapping_command == "query-graph":
                result = repository.query_communication_graph(
                    args.graph_id,
                    CommunicationGraphQuery(
                        text=args.query,
                        preset_id=args.preset,
                        node_kinds=tuple(args.node_kind),
                        edge_kinds=tuple(args.edge_kind),
                        statuses=tuple(args.status),
                        evidence_id=args.evidence_id,
                        focus_node_ids=tuple(args.focus_node),
                        focus_canonical_identities=tuple(
                            args.focus_identity
                        ),
                        max_hops=args.max_hops,
                        max_nodes=args.max_nodes,
                        max_edges=args.max_edges,
                    ),
                )
                if result is None:
                    raise ValueError("communication graph does not exist")
            elif args.mapping_command == "publish-history-overlay":
                overlay = HistoricalGraphOverlay.from_dict(json.loads(
                    Path(args.document).read_text(encoding="utf-8")
                ))
                result = repository.publish_historical_graph_overlay(overlay)
            elif args.mapping_command == "query-history-overlay":
                result = repository.query_historical_graph_overlay(
                    args.graph_id,
                    HistoricalGraphOverlayQuery(
                        text=args.query,
                        statuses=tuple(args.status),
                        applicabilities=tuple(args.applicability),
                        gap_reasons=tuple(args.gap_reason),
                        route_binding_statuses=tuple(
                            args.route_binding_status
                        ),
                    ),
                )
                if result is None:
                    raise ValueError(
                        "historical graph overlay does not exist"
                    )
            elif args.mapping_command == "publish-history-ledger":
                ledger = HistoricalCoverageLedger.from_dict(json.loads(
                    Path(args.document).read_text(encoding="utf-8")
                ))
                result = repository.publish_historical_coverage_ledger(ledger)
            else:
                result = repository.query_historical_coverage_ledger(
                    args.graph_id,
                    HistoricalCoverageLedgerQuery(
                        text=args.query,
                        statuses=tuple(args.status),
                        audit_categories=tuple(args.audit_category),
                        evidence_states=tuple(args.evidence_state),
                    ),
                )
                if result is None:
                    raise ValueError(
                        "historical coverage ledger does not exist"
                    )
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        finally:
            repository.close()
    return 2


def _catalog_document(document: dict) -> dict:
    """Accept a Catalog, AnalyzeRun, or raw-artifact analysis document."""
    mapping_run = document.get("mapping_run")
    if mapping_run is not None:
        if not isinstance(mapping_run, dict):
            raise ValueError("raw artifact analysis has no publishable mapping run")
        document = mapping_run
    catalog = document.get("catalog", document)
    if not isinstance(catalog, dict) or "catalog_id" not in catalog:
        raise ValueError("document does not contain a publishable discovery catalog")
    return catalog


def _database_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--database", default="var/firmatlas.db", help="SQLite database path"
    )


if __name__ == "__main__":
    raise SystemExit(main())
