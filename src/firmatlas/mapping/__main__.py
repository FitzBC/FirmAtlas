"""Command-line helpers for inspecting the mapping snapshot contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Optional, Sequence

from .domain import FirmwareMappingSnapshot, ObligationStatus
from .inventory import InventoryPolicy, build_inventory
from .analysis_run import (
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    analyze_extracted_root,
)
from .historical_expectation import (
    HistoricalVulnerabilityRecord,
    build_historical_vulnerability_audit,
    compare_historical_expectations,
    compare_historical_route_bindings,
    load_historical_expectations,
)
from .historical_graph_overlay import project_historical_graph_overlay
from .historical_coverage_queue import (
    build_historical_coverage_queue,
    load_historical_semantic_clues,
)
from .historical_coverage_ledger import build_historical_coverage_ledger
from .communication_graph import (
    CommunicationGraphPolicy,
    project_communication_architecture_graph,
)


def _summary(snapshot: FirmwareMappingSnapshot) -> dict:
    entity_counts = {}
    for entity in snapshot.entities:
        entity_counts[entity.entity_kind] = entity_counts.get(entity.entity_kind, 0) + 1
    coverage_counts = {}
    for entry in snapshot.coverage:
        coverage_counts[entry.status.value] = coverage_counts.get(entry.status.value, 0) + 1
    return {
        "schema_version": snapshot.schema_version,
        "snapshot_id": snapshot.snapshot_id,
        "firmware_artifact_sha256": snapshot.firmware_artifact_sha256,
        "status": snapshot.status.value,
        "interface_count": entity_counts.get("exposed_interface", 0),
        "parameter_count": entity_counts.get("parameter_identity", 0),
        "handler_count": entity_counts.get("handler_identity", 0),
        "relation_count": len(snapshot.relations),
        "evidence_count": len(snapshot.evidence_atoms),
        "coverage_counts": coverage_counts,
        "open_obligation_count": sum(
            obligation.status is ObligationStatus.OPEN
            for obligation in snapshot.unresolved_obligations
        ),
    }


def _inventory_summary(root: str, args: argparse.Namespace) -> dict:
    inventory = build_inventory(
        Path(root),
        InventoryPolicy(
            max_files=args.max_files,
            max_total_bytes=args.max_total_bytes,
            max_file_bytes=args.max_file_bytes,
            max_expanded_bytes=args.max_expanded_bytes,
            max_archive_depth=args.max_archive_depth,
        ),
    )
    return {
        "inventory_sha256": inventory.inventory_sha256,
        "coverage_status": inventory.coverage_status.value,
        "observed_count": inventory.observed_count,
        "processed_count": inventory.processed_count,
        "processed_bytes": inventory.processed_bytes,
        "expanded_bytes": inventory.expanded_bytes,
        "diagnostic_codes": sorted({item.code for item in inventory.diagnostics}),
        "sample_entries": [
            {
                "kind": item.kind,
                "path": item.canonical_path,
                "size": item.size,
                "content_sha256": item.content_sha256,
            }
            for item in inventory.entries[: args.sample_limit]
        ],
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m firmatlas.mapping")
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser(
        "validate-snapshot", help="validate and summarize a mapping snapshot JSON file"
    )
    validate.add_argument("path")
    inventory = subparsers.add_parser(
        "inventory", help="build and summarize a safe extracted-root inventory"
    )
    defaults = InventoryPolicy()
    inventory.add_argument("root")
    inventory.add_argument("--max-files", type=int, default=defaults.max_files)
    inventory.add_argument(
        "--max-total-bytes", type=int, default=defaults.max_total_bytes
    )
    inventory.add_argument("--max-file-bytes", type=int, default=defaults.max_file_bytes)
    inventory.add_argument(
        "--max-expanded-bytes", type=int, default=defaults.max_expanded_bytes
    )
    inventory.add_argument(
        "--max-archive-depth", type=int, default=defaults.max_archive_depth
    )
    inventory.add_argument("--sample-limit", type=int, default=10)
    analyze = subparsers.add_parser(
        "analyze-root",
        help="run deterministic cold-start mapping against an extracted firmware root",
    )
    analyze.add_argument("root")
    analyze.add_argument("--artifact-sha256", required=True)
    analyze.add_argument("--output", required=True)
    analyze.add_argument(
        "--profile", choices=("auto", "base"), default="auto",
        help="versioned analyzer profile (default: auto)",
    )
    analyze.add_argument("--max-files", type=int, default=defaults.max_files)
    analyze.add_argument(
        "--max-total-bytes", type=int, default=defaults.max_total_bytes
    )
    analyze.add_argument("--max-file-bytes", type=int, default=defaults.max_file_bytes)
    analyze.add_argument(
        "--max-expanded-bytes", type=int, default=defaults.max_expanded_bytes
    )
    analyze.add_argument(
        "--max-archive-depth", type=int, default=defaults.max_archive_depth
    )
    graph_defaults = CommunicationGraphPolicy()
    analyze.add_argument(
        "--graph-output",
        help="write a deterministic communication-architecture graph JSON file",
    )
    analyze.add_argument(
        "--graph-focus", action="append", default=[],
        help="focus graph on an exact candidate canonical identity; repeatable",
    )
    analyze.add_argument(
        "--graph-max-hops", type=int, default=graph_defaults.max_hops,
    )
    analyze.add_argument(
        "--graph-max-nodes", type=int, default=graph_defaults.max_nodes,
    )
    analyze.add_argument(
        "--graph-max-edges", type=int, default=graph_defaults.max_edges,
    )
    compare_history = subparsers.add_parser(
        "compare-history",
        help="analyze a root and compare its catalog with historical expectations",
    )
    compare_history.add_argument("root")
    compare_history.add_argument("--artifact-sha256", required=True)
    compare_history.add_argument(
        "--expectations", required=True, action="append",
        help="historical expectations JSON; repeat to add immutable supplements",
    )
    compare_history.add_argument("--output", required=True)
    compare_history.add_argument(
        "--graph-output",
        help="write the communication graph used by the historical overlay",
    )
    compare_history.add_argument(
        "--overlay-output",
        help="write an immutable historical expectation graph overlay",
    )
    compare_history.add_argument(
        "--vulnerability-scope",
        help="optional vulnerability denominator records JSON for audit context",
    )
    compare_history.add_argument(
        "--semantic-clues",
        help="versioned semantic clues JSON used to classify historical gaps",
    )
    compare_history.add_argument(
        "--coverage-queue-output",
        help="write the deterministic historical coverage work queue",
    )
    compare_history.add_argument(
        "--coverage-ledger-output",
        help="write the complete historical denominator coverage ledger",
    )
    compare_history.add_argument(
        "--profile", choices=("auto", "base"), default="auto",
        help="versioned analyzer profile (default: auto)",
    )
    compare_history.add_argument("--max-files", type=int, default=defaults.max_files)
    compare_history.add_argument(
        "--max-total-bytes", type=int, default=defaults.max_total_bytes
    )
    compare_history.add_argument(
        "--max-file-bytes", type=int, default=defaults.max_file_bytes
    )
    compare_history.add_argument(
        "--max-expanded-bytes", type=int, default=defaults.max_expanded_bytes
    )
    compare_history.add_argument(
        "--max-archive-depth", type=int, default=defaults.max_archive_depth
    )
    args = parser.parse_args(argv)

    try:
        if args.command == "compare-history":
            if args.overlay_output and not args.graph_output:
                raise ValueError("overlay-output requires graph-output")
            if args.vulnerability_scope and not args.overlay_output:
                raise ValueError(
                    "vulnerability-scope requires overlay-output"
                )
            if args.coverage_queue_output and not (
                args.vulnerability_scope and args.semantic_clues
            ):
                raise ValueError(
                    "coverage-queue-output requires vulnerability-scope and semantic-clues"
                )
            if args.coverage_ledger_output and not (
                args.overlay_output and args.coverage_queue_output
            ):
                raise ValueError(
                    "coverage-ledger-output requires overlay-output and coverage-queue-output"
                )
            history_paths = [Path(args.output).resolve()]
            if args.graph_output:
                history_paths.append(Path(args.graph_output).resolve())
            if args.overlay_output:
                history_paths.append(Path(args.overlay_output).resolve())
            if args.coverage_queue_output:
                history_paths.append(Path(args.coverage_queue_output).resolve())
            if args.coverage_ledger_output:
                history_paths.append(Path(args.coverage_ledger_output).resolve())
            if len(history_paths) != len(set(history_paths)):
                raise ValueError(
                    "history, graph, overlay, and coverage queue outputs must differ"
                )
        if args.command == "inventory":
            if args.sample_limit < 0:
                raise ValueError("sample-limit must be nonnegative")
            result = _inventory_summary(args.root, args)
        elif args.command in ("analyze-root", "compare-history"):
            run = analyze_extracted_root(MappingAnalysisRequest(
                root=Path(args.root),
                firmware_artifact_sha256=args.artifact_sha256,
                profile=(
                    MappingAnalysisProfile.auto()
                    if args.profile == "auto"
                    else MappingAnalysisProfile.base()
                ),
                inventory_policy=InventoryPolicy(
                    max_files=args.max_files,
                    max_total_bytes=args.max_total_bytes,
                    max_file_bytes=args.max_file_bytes,
                    max_expanded_bytes=args.max_expanded_bytes,
                    max_archive_depth=args.max_archive_depth,
                ),
            ))
            output = Path(args.output)
            if args.command == "compare-history":
                expectation_documents = tuple(
                    json.loads(Path(path).read_text(encoding="utf-8"))
                    for path in args.expectations
                )
                expectations = tuple(
                    expectation
                    for document in expectation_documents
                    for expectation in load_historical_expectations(document)
                )
                if len({item.expectation_id for item in expectations}) != len(
                    expectations
                ):
                    raise ValueError("duplicate historical expectation across inputs")
                diff = compare_historical_expectations(
                    run.catalog,
                    expectations,
                )
                document = {
                    **diff.to_dict(),
                    "analysis_run_id": run.analysis_run_id,
                    "firmware_artifact_sha256": run.firmware_artifact_sha256,
                    "profile_id": run.profile_id,
                    "analyzer_registry_id": run.analyzer_registry_id,
                }
                output.write_text(
                    json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True)
                    + "\n",
                    encoding="utf-8",
                )
                graph = None
                overlay = None
                queue = None
                ledger = None
                audit = None
                if args.graph_output:
                    graph_output = Path(args.graph_output)
                    overlay_output = (
                        Path(args.overlay_output) if args.overlay_output else None
                    )
                    graph = project_communication_architecture_graph(run.catalog)
                    graph_output.write_text(
                        json.dumps(
                            graph.to_dict(), ensure_ascii=False,
                            indent=2, sort_keys=True,
                        ) + "\n",
                        encoding="utf-8",
                    )
                    if overlay_output:
                        routes = compare_historical_route_bindings(
                            run.catalog, expectations
                        )
                        if args.vulnerability_scope:
                            scope = json.loads(Path(
                                args.vulnerability_scope
                            ).read_text(encoding="utf-8"))
                            audit = build_historical_vulnerability_audit(
                                diff,
                                tuple(
                                    HistoricalVulnerabilityRecord(**item)
                                    for item in scope["records"]
                                ),
                            )
                        overlay = project_historical_graph_overlay(
                            graph, diff, routes, audit
                        )
                        overlay_output.write_text(
                            json.dumps(
                                overlay.to_dict(), ensure_ascii=False,
                                indent=2, sort_keys=True,
                            ) + "\n",
                            encoding="utf-8",
                        )
                if args.coverage_queue_output:
                    if audit is None:
                        raise ValueError("historical audit is required for coverage queue")
                    clues = load_historical_semantic_clues(json.loads(
                        Path(args.semantic_clues).read_text(encoding="utf-8")
                    ))
                    queue = build_historical_coverage_queue(
                        audit, clues, run.catalog
                    )
                    Path(args.coverage_queue_output).write_text(
                        json.dumps(
                            queue.to_dict(), ensure_ascii=False,
                            indent=2, sort_keys=True,
                        ) + "\n",
                        encoding="utf-8",
                    )
                if args.coverage_ledger_output:
                    if overlay is None or queue is None:
                        raise ValueError(
                            "historical overlay and coverage queue are required for ledger"
                        )
                    ledger = build_historical_coverage_ledger(overlay, queue)
                    Path(args.coverage_ledger_output).write_text(
                        json.dumps(
                            ledger.to_dict(), ensure_ascii=False,
                            indent=2, sort_keys=True,
                        ) + "\n",
                        encoding="utf-8",
                    )
                result = {
                    "schema_version": diff.schema_version,
                    "report_id": diff.report_id,
                    "analysis_run_id": run.analysis_run_id,
                    "catalog_id": run.catalog.catalog_id,
                    "summary": diff.summary,
                    "output": str(output),
                }
                if graph is not None:
                    result.update({
                        "graph_id": graph.graph_id,
                        "graph_output": str(args.graph_output),
                    })
                if overlay is not None:
                    result.update({
                        "overlay_id": overlay.overlay_id,
                        "overlay_output": str(args.overlay_output),
                    })
                if queue is not None:
                    result.update({
                        "coverage_queue_id": queue.queue_id,
                        "coverage_queue_output": str(args.coverage_queue_output),
                        "coverage_queue_summary": queue.summary,
                    })
                if ledger is not None:
                    result.update({
                        "coverage_ledger_id": ledger.ledger_id,
                        "coverage_ledger_output": str(args.coverage_ledger_output),
                        "coverage_ledger_summary": ledger.summary,
                    })
                print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
                return 0
            if args.graph_focus and not args.graph_output:
                raise ValueError("graph-focus requires graph-output")
            graph = None
            graph_output = None
            if args.graph_output:
                graph_output = Path(args.graph_output)
                if graph_output.resolve() == output.resolve():
                    raise ValueError("graph-output must differ from output")
                graph = project_communication_architecture_graph(
                    run.catalog,
                    CommunicationGraphPolicy(
                        max_nodes=args.graph_max_nodes,
                        max_edges=args.graph_max_edges,
                        focus_canonical_identities=tuple(args.graph_focus),
                        max_hops=args.graph_max_hops,
                    ),
                )
            output.write_text(
                json.dumps(run.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            if graph is not None and graph_output is not None:
                graph_output.write_text(
                    json.dumps(
                        graph.to_dict(), ensure_ascii=False,
                        indent=2, sort_keys=True,
                    ) + "\n",
                    encoding="utf-8",
                )
            result = {
                "schema_version": run.schema_version,
                "analysis_run_id": run.analysis_run_id,
                "catalog_id": run.catalog.catalog_id,
                "coverage_status": run.coverage_status.value,
                "profile_id": run.profile_id,
                "analyzer_registry_id": run.analyzer_registry_id,
                "candidate_count": len(run.catalog.candidates),
                "parameter_count": len(run.catalog.parameters),
                "evidence_count": len(run.catalog.evidence_atoms),
                "open_obligation_count": len(run.catalog.open_obligations),
                "output": str(output),
            }
            if graph is not None and graph_output is not None:
                result.update({
                    "graph_id": graph.graph_id,
                    "graph_projection_status": graph.projection_status.value,
                    "graph_node_count": len(graph.nodes),
                    "graph_edge_count": len(graph.edges),
                    "graph_output": str(graph_output),
                })
        else:
            payload = json.loads(Path(args.path).read_text(encoding="utf-8"))
            snapshot = FirmwareMappingSnapshot.from_dict(payload)
            result = _summary(snapshot)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("mapping command failed: {}".format(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
