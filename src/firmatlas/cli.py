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
        from .mapping.repository import DiscoveryCatalogRepository

        repository = DiscoveryCatalogRepository(args.database)
        try:
            if args.mapping_command == "publish-catalog":
                document = json.loads(Path(args.document).read_text(encoding="utf-8"))
                result = repository.publish_dict(document)
            else:
                result = repository.list_catalogs()
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        finally:
            repository.close()
    return 2


def _database_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--database", default="var/firmatlas.db", help="SQLite database path"
    )


if __name__ == "__main__":
    raise SystemExit(main())
