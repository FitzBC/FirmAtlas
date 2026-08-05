"""Small executable proving the initial analysis interface is usable."""

import argparse
from datetime import datetime, timezone
import json
import logging
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
    args = parser.parse_args(argv)

    if args.command == "demo-report":
        print(json.dumps(demo_report().to_dict(), ensure_ascii=False, indent=2))
        return 0
    if args.command == "intelligence":
        if args.intelligence_command == "serve":
            from .intelligence.api import serve

            logging.basicConfig(level=logging.INFO, format="%(message)s")
            serve(args.database, args.host, args.port)
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
    return 2


def _database_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--database", default="var/firmatlas.db", help="SQLite database path"
    )


if __name__ == "__main__":
    raise SystemExit(main())
