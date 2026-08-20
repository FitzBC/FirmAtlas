"""SQLite adapter for immutable discovery catalogs and their query projections."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any, Optional

from .discovery_catalog import DiscoveryCatalog
from .communication_graph import (
    CommunicationArchitectureGraph,
    CommunicationGraphEdgeKind,
    CommunicationGraphNodeKind,
)
from .corpus_report import CorpusReport
from .historical_expectation import (
    HistoricalApplicability,
    HistoricalGapReason,
    HistoricalMatchStatus,
    HistoricalRouteBindingStatus,
)
from .historical_graph_overlay import HistoricalGraphOverlay
from .historical_coverage_ledger import (
    HistoricalCoverageLedger,
    HistoricalCoverageLedgerStatus,
)
from .hidden_interface import project_potential_hidden_interface_document
from .interface_force_graph import project_interface_force_graph
from .snapshot_diff import MappingReleaseContext, compare_mapping_catalog_documents


COMMUNICATION_GRAPH_QUERY_RESULT_SCHEMA_VERSION = (
    "firmatlas.mapping.communication-graph-query-result/v1alpha1"
)
HISTORICAL_GRAPH_OVERLAY_QUERY_RESULT_SCHEMA_VERSION = (
    "firmatlas.mapping.historical-graph-overlay-query-result/v1alpha1"
)
HISTORICAL_COVERAGE_LEDGER_QUERY_RESULT_SCHEMA_VERSION = (
    "firmatlas.mapping.historical-coverage-ledger-query-result/v1alpha1"
)


class CatalogConflictError(RuntimeError):
    """A catalog identity was reused for content with a different digest."""


class CommunicationGraphConflictError(RuntimeError):
    """A graph identity was reused for content with a different digest."""


class HistoricalGraphOverlayConflictError(RuntimeError):
    """An overlay identity was reused for content with a different digest."""


@dataclass(frozen=True)
class CommunicationGraphQuery:
    text: str = ""
    preset_id: str = ""
    node_kinds: tuple = ()
    edge_kinds: tuple = ()
    statuses: tuple = ()
    evidence_id: str = ""
    focus_node_ids: tuple = ()
    focus_canonical_identities: tuple = ()
    max_hops: int = 2
    max_nodes: int = 500
    max_edges: int = 1_000

    def __post_init__(self) -> None:
        if self.max_hops < 0 or self.max_nodes <= 0 or self.max_edges <= 0:
            raise ValueError("communication graph query budgets are invalid")
        for values in (
            self.node_kinds, self.edge_kinds, self.statuses,
            self.focus_node_ids, self.focus_canonical_identities,
        ):
            if len(values) != len(set(values)):
                raise ValueError("communication graph query filters must be unique")
        if not set(self.node_kinds).issubset(
            item.value for item in CommunicationGraphNodeKind
        ):
            raise ValueError("communication graph query has unknown node kind")
        if not set(self.edge_kinds).issubset(
            item.value for item in CommunicationGraphEdgeKind
        ):
            raise ValueError("communication graph query has unknown edge kind")


@dataclass(frozen=True)
class HistoricalGraphOverlayQuery:
    text: str = ""
    statuses: tuple = ()
    applicabilities: tuple = ()
    gap_reasons: tuple = ()
    route_binding_statuses: tuple = ()

    def __post_init__(self) -> None:
        selections = (
            (self.statuses, {item.value for item in HistoricalMatchStatus}),
            (
                self.applicabilities,
                {item.value for item in HistoricalApplicability},
            ),
            (self.gap_reasons, {item.value for item in HistoricalGapReason}),
            (
                self.route_binding_statuses,
                {item.value for item in HistoricalRouteBindingStatus},
            ),
        )
        for values, allowed in selections:
            if len(values) != len(set(values)):
                raise ValueError("historical overlay query filters must be unique")
            if not set(values).issubset(allowed):
                raise ValueError("historical overlay query has unknown filter")


@dataclass(frozen=True)
class HistoricalCoverageLedgerQuery:
    text: str = ""
    statuses: tuple = ()
    audit_categories: tuple = ()
    evidence_states: tuple = ()

    def __post_init__(self) -> None:
        selections = (
            (self.statuses, {item.value for item in HistoricalCoverageLedgerStatus}),
            (self.audit_categories, {
                "compared_interface", "parameter_only",
                "no_structured_communication", "not_analyzed",
            }),
        )
        for values, allowed in selections:
            if len(values) != len(set(values)):
                raise ValueError("historical ledger query filters must be unique")
            if not set(values).issubset(allowed):
                raise ValueError("historical ledger query has unknown filter")
        if len(self.evidence_states) != len(set(self.evidence_states)):
            raise ValueError("historical ledger query filters must be unique")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encoded(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _reachable_graph_neighbors(frontier: set, edges: tuple) -> set:
    """Expand a query frontier without reversing directed call semantics."""
    reached = set()
    for edge in edges:
        if edge.source_ref in frontier:
            reached.add(edge.target_ref)
        if (
            edge.edge_kind is not CommunicationGraphEdgeKind.CALLS
            and edge.target_ref in frontier
        ):
            reached.add(edge.source_ref)
    return reached


def _search_text(value: str) -> str:
    expanded = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return " ".join(re.findall(r"[a-z0-9]+", expanded.casefold()))


class DiscoveryCatalogRepository:
    """Persist full catalog documents and query evidence-preserving projections."""

    def __init__(self, database: str = "var/firmatlas.db") -> None:
        if database != ":memory:":
            Path(database).parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(database, check_same_thread=False, timeout=10)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._lock = threading.RLock()
        self._migrate()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _migrate(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS mapping_discovery_catalogs (
                    catalog_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    firmware_artifact_sha256 TEXT NOT NULL,
                    source_inventory_sha256 TEXT NOT NULL,
                    coverage_status TEXT NOT NULL,
                    scheduler_termination TEXT,
                    content_sha256 TEXT NOT NULL,
                    document_json TEXT NOT NULL,
                    published_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_mapping_catalog_firmware
                    ON mapping_discovery_catalogs(firmware_artifact_sha256, published_at DESC);
                CREATE TABLE IF NOT EXISTS mapping_catalog_release_contexts (
                    catalog_id TEXT PRIMARY KEY,
                    context_sha256 TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    FOREIGN KEY(catalog_id) REFERENCES mapping_discovery_catalogs(catalog_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS mapping_discovery_candidates (
                    catalog_id TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    candidate_kind TEXT NOT NULL,
                    canonical_identity TEXT NOT NULL,
                    claim_status TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    source_construct TEXT NOT NULL,
                    search_text TEXT NOT NULL,
                    parameter_count INTEGER NOT NULL,
                    association_count INTEGER NOT NULL,
                    open_obligation_count INTEGER NOT NULL,
                    candidate_json TEXT NOT NULL,
                    PRIMARY KEY(catalog_id, candidate_id),
                    FOREIGN KEY(catalog_id) REFERENCES mapping_discovery_catalogs(catalog_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_mapping_candidate_kind
                    ON mapping_discovery_candidates(catalog_id, candidate_kind, canonical_identity);
                CREATE TABLE IF NOT EXISTS mapping_hidden_interface_indexes (
                    catalog_id TEXT PRIMARY KEY,
                    firmware_artifact_sha256 TEXT NOT NULL,
                    coverage_status TEXT NOT NULL,
                    item_count INTEGER NOT NULL,
                    diagnostics_json TEXT NOT NULL,
                    FOREIGN KEY(catalog_id) REFERENCES mapping_discovery_catalogs(catalog_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS mapping_potential_hidden_interfaces (
                    interface_id TEXT PRIMARY KEY,
                    catalog_id TEXT NOT NULL,
                    firmware_artifact_sha256 TEXT NOT NULL,
                    operation_token TEXT NOT NULL,
                    registration_artifact_path TEXT NOT NULL,
                    search_text TEXT NOT NULL,
                    item_json TEXT NOT NULL,
                    FOREIGN KEY(catalog_id) REFERENCES mapping_discovery_catalogs(catalog_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_mapping_hidden_interface_catalog
                    ON mapping_potential_hidden_interfaces(catalog_id, operation_token);
                CREATE INDEX IF NOT EXISTS idx_mapping_hidden_interface_firmware
                    ON mapping_potential_hidden_interfaces(
                        firmware_artifact_sha256, registration_artifact_path
                    );
                CREATE TABLE IF NOT EXISTS mapping_communication_graphs (
                    graph_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    source_catalog_id TEXT NOT NULL,
                    firmware_artifact_sha256 TEXT NOT NULL,
                    source_catalog_coverage_status TEXT NOT NULL,
                    projection_status TEXT NOT NULL,
                    node_count INTEGER NOT NULL,
                    edge_count INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    document_json TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    FOREIGN KEY(source_catalog_id)
                        REFERENCES mapping_discovery_catalogs(catalog_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_mapping_graph_catalog
                    ON mapping_communication_graphs(
                        source_catalog_id, published_at DESC
                    );
                CREATE INDEX IF NOT EXISTS idx_mapping_graph_firmware
                    ON mapping_communication_graphs(
                        firmware_artifact_sha256, published_at DESC
                    );
                CREATE TABLE IF NOT EXISTS mapping_communication_graph_nodes (
                    graph_id TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    node_kind TEXT NOT NULL,
                    label TEXT NOT NULL,
                    status TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    search_text TEXT NOT NULL,
                    node_json TEXT NOT NULL,
                    PRIMARY KEY(graph_id, node_id),
                    FOREIGN KEY(graph_id)
                        REFERENCES mapping_communication_graphs(graph_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_mapping_graph_node_kind
                    ON mapping_communication_graph_nodes(
                        graph_id, node_kind, label
                    );
                CREATE TABLE IF NOT EXISTS mapping_communication_graph_edges (
                    graph_id TEXT NOT NULL,
                    edge_id TEXT NOT NULL,
                    edge_kind TEXT NOT NULL,
                    source_ref TEXT NOT NULL,
                    target_ref TEXT NOT NULL,
                    status TEXT NOT NULL,
                    edge_json TEXT NOT NULL,
                    PRIMARY KEY(graph_id, edge_id),
                    FOREIGN KEY(graph_id)
                        REFERENCES mapping_communication_graphs(graph_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_mapping_graph_edge_kind
                    ON mapping_communication_graph_edges(
                        graph_id, edge_kind, source_ref, target_ref
                    );
                CREATE TABLE IF NOT EXISTS mapping_historical_graph_overlays (
                    overlay_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    graph_id TEXT NOT NULL,
                    catalog_id TEXT NOT NULL,
                    expectation_diff_id TEXT NOT NULL,
                    entry_count INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    document_json TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    FOREIGN KEY(graph_id)
                        REFERENCES mapping_communication_graphs(graph_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_mapping_history_overlay_graph
                    ON mapping_historical_graph_overlays(
                        graph_id, published_at DESC, overlay_id
                    );
                CREATE TABLE IF NOT EXISTS mapping_historical_coverage_ledgers (
                    ledger_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    graph_id TEXT NOT NULL,
                    catalog_id TEXT NOT NULL,
                    overlay_id TEXT NOT NULL,
                    audit_id TEXT NOT NULL,
                    entry_count INTEGER NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    document_json TEXT NOT NULL,
                    published_at TEXT NOT NULL,
                    FOREIGN KEY(graph_id)
                        REFERENCES mapping_communication_graphs(graph_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_mapping_history_ledger_graph
                    ON mapping_historical_coverage_ledgers(
                        graph_id, published_at DESC, ledger_id
                    );
                CREATE TABLE IF NOT EXISTS mapping_corpus_reports (
                    report_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    corpus_version TEXT NOT NULL,
                    gate_status TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    document_json TEXT NOT NULL,
                    published_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_mapping_corpus_report_latest
                    ON mapping_corpus_reports(published_at DESC, report_id DESC);
                """
            )
            rows = self._connection.execute(
                """SELECT c.document_json FROM mapping_discovery_catalogs c
                   LEFT JOIN mapping_hidden_interface_indexes h
                     ON h.catalog_id = c.catalog_id
                   WHERE h.catalog_id IS NULL"""
            ).fetchall()
            for row in rows:
                self._replace_hidden_interface_projection(
                    json.loads(row["document_json"])
                )

    def _replace_hidden_interface_projection(self, document: dict) -> None:
        index = project_potential_hidden_interface_document(document)
        self._connection.execute(
            "DELETE FROM mapping_potential_hidden_interfaces WHERE catalog_id = ?",
            (index.catalog_id,),
        )
        self._connection.execute(
            """INSERT OR REPLACE INTO mapping_hidden_interface_indexes (
                catalog_id, firmware_artifact_sha256, coverage_status,
                item_count, diagnostics_json
            ) VALUES (?, ?, ?, ?, ?)""",
            (
                index.catalog_id,
                index.firmware_artifact_sha256,
                index.coverage_status.value,
                len(index.items),
                _encoded([item.__dict__ for item in index.diagnostics]),
            ),
        )
        for item in index.items:
            value = item.__dict__
            searchable = " ".join((
                item.operation_token,
                item.registration_artifact_path,
                " ".join(item.handler_identities),
                item.interpretation,
                item.open_obligation,
            ))
            self._connection.execute(
                """INSERT INTO mapping_potential_hidden_interfaces (
                    interface_id, catalog_id, firmware_artifact_sha256,
                    operation_token, registration_artifact_path,
                    search_text, item_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    item.interface_id,
                    item.catalog_id,
                    item.firmware_artifact_sha256,
                    item.operation_token,
                    item.registration_artifact_path,
                    _search_text(searchable),
                    _encoded(value),
                ),
            )

    def publish(self, catalog: DiscoveryCatalog) -> dict:
        return self.publish_dict(catalog.to_dict())

    def publish_corpus_report(self, report: CorpusReport) -> dict:
        """Publish one content-addressed representative corpus gate report."""

        document = report.to_dict()
        payload = _encoded(document)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT content_sha256 FROM mapping_corpus_reports WHERE report_id = ?",
                (report.report_id,),
            ).fetchone()
            if existing is not None:
                if existing["content_sha256"] != digest:
                    raise ValueError(
                        "corpus report identity contains different content"
                    )
                return {
                    "report_id": report.report_id,
                    "created": False,
                    "content_sha256": digest,
                }
            self._connection.execute(
                """INSERT INTO mapping_corpus_reports (
                       report_id, schema_version, corpus_version, gate_status,
                       content_sha256, document_json, published_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    report.report_id, report.schema_version,
                    report.corpus_version, report.gate_status.value,
                    digest, payload, _utc_now(),
                ),
            )
        return {
            "report_id": report.report_id,
            "created": True,
            "content_sha256": digest,
        }

    def latest_corpus_report(self) -> Optional[dict]:
        """Return the newest immutable corpus gate report, if published."""

        with self._lock:
            row = self._connection.execute(
                """SELECT document_json FROM mapping_corpus_reports
                   ORDER BY published_at DESC, report_id DESC LIMIT 1"""
            ).fetchone()
        return json.loads(row["document_json"]) if row else None

    def publish_communication_graph(
        self, graph: CommunicationArchitectureGraph
    ) -> dict:
        """Publish one validated graph and its query indexes atomically."""

        document = graph.to_dict()
        payload = _encoded(document)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        with self._lock, self._connection:
            catalog_row = self._connection.execute(
                """SELECT firmware_artifact_sha256, document_json
                   FROM mapping_discovery_catalogs WHERE catalog_id = ?""",
                (graph.source_catalog_id,),
            ).fetchone()
            if catalog_row is None:
                raise ValueError("communication graph source catalog is not published")
            if (
                catalog_row["firmware_artifact_sha256"]
                != graph.firmware_artifact_sha256
            ):
                raise ValueError("communication graph firmware does not match source catalog")
            catalog = json.loads(catalog_row["document_json"])
            if (
                catalog.get("coverage_status")
                != graph.source_catalog_coverage_status.value
            ):
                raise ValueError(
                    "communication graph source coverage does not match catalog"
                )
            catalog_evidence_ids = {
                item["evidence_id"] for item in catalog.get("evidence_atoms", [])
            }
            if any(
                evidence_id not in catalog_evidence_ids
                for item in (*graph.nodes, *graph.edges)
                for evidence_id in item.evidence_ids
            ):
                raise ValueError("communication graph references unknown catalog evidence")
            existing = self._connection.execute(
                """SELECT content_sha256 FROM mapping_communication_graphs
                   WHERE graph_id = ?""",
                (graph.graph_id,),
            ).fetchone()
            if existing is not None:
                if existing["content_sha256"] != digest:
                    raise CommunicationGraphConflictError(
                        "communication graph identity already contains different content"
                    )
                return {
                    "graph_id": graph.graph_id,
                    "created": False,
                    "content_sha256": digest,
                }
            self._connection.execute(
                """INSERT INTO mapping_communication_graphs (
                    graph_id, schema_version, source_catalog_id,
                    firmware_artifact_sha256,
                    source_catalog_coverage_status, projection_status,
                    node_count, edge_count, content_sha256, document_json,
                    published_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    graph.graph_id, graph.schema_version,
                    graph.source_catalog_id, graph.firmware_artifact_sha256,
                    graph.source_catalog_coverage_status.value,
                    graph.projection_status.value, len(graph.nodes),
                    len(graph.edges), digest, payload, _utc_now(),
                ),
            )
            for node in document["nodes"]:
                searchable = " ".join((
                    node["label"], node["source_path"], node["status"],
                    " ".join(
                        str(part)
                        for pair in node.get("attributes", [])
                        for part in pair
                    ),
                ))
                self._connection.execute(
                    """INSERT INTO mapping_communication_graph_nodes (
                        graph_id, node_id, node_kind, label, status,
                        source_path, search_text, node_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        graph.graph_id, node["node_id"], node["node_kind"],
                        node["label"], node["status"], node["source_path"],
                        _search_text(searchable), _encoded(node),
                    ),
                )
            for edge in document["edges"]:
                self._connection.execute(
                    """INSERT INTO mapping_communication_graph_edges (
                        graph_id, edge_id, edge_kind, source_ref,
                        target_ref, status, edge_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        graph.graph_id, edge["edge_id"], edge["edge_kind"],
                        edge["source_ref"], edge["target_ref"],
                        edge["status"], _encoded(edge),
                    ),
                )
        return {
            "graph_id": graph.graph_id,
            "created": True,
            "content_sha256": digest,
        }

    def list_communication_graphs(
        self, limit: int = 50, offset: int = 0
    ) -> dict:
        limit, offset = max(1, min(limit, 100)), max(0, offset)
        with self._lock:
            total = self._connection.execute(
                "SELECT COUNT(*) FROM mapping_communication_graphs"
            ).fetchone()[0]
            rows = self._connection.execute(
                """SELECT graph_id, schema_version, source_catalog_id,
                          firmware_artifact_sha256,
                          source_catalog_coverage_status, projection_status,
                          node_count, edge_count, published_at
                   FROM mapping_communication_graphs
                   ORDER BY published_at DESC, graph_id
                   LIMIT ? OFFSET ?""",
                (limit, offset),
            ).fetchall()
        return {
            "items": [dict(row) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    def publish_historical_graph_overlay(
        self, overlay: HistoricalGraphOverlay
    ) -> dict:
        """Publish a validated contextual overlay without changing its graph."""

        document = overlay.to_dict()
        payload = _encoded(document)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        with self._lock, self._connection:
            graph_row = self._connection.execute(
                """SELECT source_catalog_id, document_json
                   FROM mapping_communication_graphs WHERE graph_id = ?""",
                (overlay.graph_id,),
            ).fetchone()
            if graph_row is None:
                raise ValueError("historical overlay graph is not published")
            if graph_row["source_catalog_id"] != overlay.catalog_id:
                raise ValueError(
                    "historical overlay catalog does not match graph"
                )
            graph_document = json.loads(graph_row["document_json"])
            graph_node_ids = {
                item["node_id"] for item in graph_document["nodes"]
            }
            graph_edge_ids = {
                item["edge_id"] for item in graph_document["edges"]
            }
            catalog_row = self._connection.execute(
                """SELECT document_json FROM mapping_discovery_catalogs
                   WHERE catalog_id = ?""",
                (overlay.catalog_id,),
            ).fetchone()
            catalog_document = json.loads(catalog_row["document_json"])
            catalog_candidate_ids = {
                item["candidate_id"]
                for item in catalog_document.get("candidates", ())
            }
            catalog_evidence_ids = {
                item["evidence_id"]
                for item in catalog_document.get("evidence_atoms", ())
            }
            for entry in overlay.entries:
                unknown_nodes = set(entry.graph_node_ids) - graph_node_ids
                if unknown_nodes:
                    raise ValueError(
                        "historical overlay references unknown graph node"
                    )
                unknown_edges = set(entry.graph_edge_ids) - graph_edge_ids
                if unknown_edges:
                    raise ValueError(
                        "historical overlay references unknown graph edge"
                    )
                if (
                    set(entry.catalog_candidate_ids)
                    | set(entry.unmapped_catalog_reference_ids)
                ) - catalog_candidate_ids:
                    raise ValueError(
                        "historical overlay references unknown catalog candidate"
                    )
                if (
                    set(entry.catalog_evidence_ids)
                    | set(entry.unmapped_catalog_evidence_ids)
                ) - catalog_evidence_ids:
                    raise ValueError(
                        "historical overlay references unknown catalog evidence"
                    )
            existing = self._connection.execute(
                """SELECT content_sha256
                   FROM mapping_historical_graph_overlays
                   WHERE overlay_id = ?""",
                (overlay.overlay_id,),
            ).fetchone()
            if existing is not None:
                if existing["content_sha256"] != digest:
                    raise HistoricalGraphOverlayConflictError(
                        "historical graph overlay identity already contains "
                        "different content"
                    )
                return {
                    "overlay_id": overlay.overlay_id,
                    "created": False,
                    "content_sha256": digest,
                }
            self._connection.execute(
                """INSERT INTO mapping_historical_graph_overlays (
                    overlay_id, schema_version, graph_id, catalog_id,
                    expectation_diff_id, entry_count, content_sha256,
                    document_json, published_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    overlay.overlay_id, overlay.schema_version,
                    overlay.graph_id, overlay.catalog_id,
                    overlay.expectation_diff_id, len(overlay.entries),
                    digest, payload, _utc_now(),
                ),
            )
        return {
            "overlay_id": overlay.overlay_id,
            "created": True,
            "content_sha256": digest,
        }

    def query_historical_graph_overlay(
        self,
        graph_id: str,
        query: HistoricalGraphOverlayQuery = HistoricalGraphOverlayQuery(),
    ) -> Optional[dict]:
        """Query the latest immutable historical context layer for a graph."""

        with self._lock:
            row = self._connection.execute(
                """SELECT document_json
                   FROM mapping_historical_graph_overlays
                   WHERE graph_id = ?
                   ORDER BY published_at DESC, overlay_id DESC
                   LIMIT 1""",
                (graph_id,),
            ).fetchone()
        if row is None:
            return None
        overlay = HistoricalGraphOverlay.from_dict(
            json.loads(row["document_json"])
        )
        entries = list(overlay.to_dict()["entries"])
        text_tokens = _search_text(query.text).split()
        selected = [
            item for item in entries
            if (
                not query.statuses or item["status"] in query.statuses
            )
            and (
                not query.applicabilities
                or item["applicability"] in query.applicabilities
            )
            and (
                not query.gap_reasons
                or item["gap_reason"] in query.gap_reasons
            )
            and (
                not query.route_binding_statuses
                or item["route_binding_status"]
                in query.route_binding_statuses
            )
            and all(
                token in _search_text(" ".join((
                    item["vulnerability_identifier"],
                    item["interface_value"], item["handler_value"],
                    " ".join(item["expected_parameters"]),
                    item["gap_reason"], item["applicability"],
                )))
                for token in text_tokens
            )
        ]

        def facets(key: str) -> dict:
            values = sorted({item[key] for item in entries if item[key]})
            return {
                value: sum(item[key] == value for item in entries)
                for value in values
            }

        query_document = asdict(query)
        identity = {
            "schema_version": (
                HISTORICAL_GRAPH_OVERLAY_QUERY_RESULT_SCHEMA_VERSION
            ),
            "overlay_id": overlay.overlay_id,
            "query": query_document,
            "expectation_ids": [
                item["expectation_id"] for item in selected
            ],
        }
        query_id = "historical-graph-overlay-query:" + hashlib.sha256(
            _encoded(identity).encode("utf-8")
        ).hexdigest()
        overlay_document = overlay.to_dict()
        return {
            "schema_version": (
                HISTORICAL_GRAPH_OVERLAY_QUERY_RESULT_SCHEMA_VERSION
            ),
            "query_id": query_id,
            "overlay": {
                key: value for key, value in overlay_document.items()
                if key not in {"entries", "diagnostics"}
            },
            "query": query_document,
            "entries": selected,
            "total_entry_count": len(entries),
            "selected_entry_count": len(selected),
            "facets": {
                "status": facets("status"),
                "applicability": facets("applicability"),
                "gap_reason": facets("gap_reason"),
                "route_binding_status": facets("route_binding_status"),
            },
            "diagnostics": list(overlay.diagnostics),
        }

    def publish_historical_coverage_ledger(
        self, ledger: HistoricalCoverageLedger
    ) -> dict:
        """Publish one complete contextual denominator for an existing graph."""

        document = ledger.to_dict()
        payload = _encoded(document)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        with self._lock, self._connection:
            graph_row = self._connection.execute(
                "SELECT source_catalog_id FROM mapping_communication_graphs WHERE graph_id = ?",
                (ledger.graph_id,),
            ).fetchone()
            if graph_row is None:
                raise ValueError("historical coverage ledger graph is not published")
            if graph_row["source_catalog_id"] != ledger.catalog_id:
                raise ValueError("historical coverage ledger catalog does not match graph")
            overlay_row = self._connection.execute(
                "SELECT graph_id FROM mapping_historical_graph_overlays WHERE overlay_id = ?",
                (ledger.overlay_id,),
            ).fetchone()
            if overlay_row is None or overlay_row["graph_id"] != ledger.graph_id:
                raise ValueError("historical coverage ledger overlay is not published")
            existing = self._connection.execute(
                "SELECT content_sha256 FROM mapping_historical_coverage_ledgers WHERE ledger_id = ?",
                (ledger.ledger_id,),
            ).fetchone()
            if existing is not None:
                if existing["content_sha256"] != digest:
                    raise ValueError(
                        "historical coverage ledger identity contains different content"
                    )
                return {
                    "ledger_id": ledger.ledger_id,
                    "created": False,
                    "content_sha256": digest,
                }
            self._connection.execute(
                """INSERT INTO mapping_historical_coverage_ledgers (
                       ledger_id, schema_version, graph_id, catalog_id,
                       overlay_id, audit_id, entry_count, content_sha256,
                       document_json, published_at
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ledger.ledger_id, ledger.schema_version, ledger.graph_id,
                    ledger.catalog_id, ledger.overlay_id, ledger.audit_id,
                    len(ledger.entries), digest, payload, _utc_now(),
                ),
            )
        return {
            "ledger_id": ledger.ledger_id,
            "created": True,
            "content_sha256": digest,
        }

    def query_historical_coverage_ledger(
        self,
        graph_id: str,
        query: HistoricalCoverageLedgerQuery = HistoricalCoverageLedgerQuery(),
    ) -> Optional[dict]:
        """Query all explained and unexplained CVEs for one graph."""

        with self._lock:
            row = self._connection.execute(
                """SELECT document_json
                   FROM mapping_historical_coverage_ledgers
                   WHERE graph_id = ?
                   ORDER BY published_at DESC, ledger_id DESC
                   LIMIT 1""",
                (graph_id,),
            ).fetchone()
        if row is None:
            return None
        ledger = HistoricalCoverageLedger.from_dict(json.loads(row["document_json"]))
        document = ledger.to_dict()
        entries = document["entries"]
        text_tokens = _search_text(query.text).split()
        selected = [
            item for item in entries
            if (not query.statuses or item["status"] in query.statuses)
            and (
                not query.audit_categories
                or item["audit_category"] in query.audit_categories
            )
            and (
                not query.evidence_states
                or item["evidence_state"] in query.evidence_states
            )
            and all(
                token in _search_text(" ".join((
                    item["vulnerability_identifier"],
                    " ".join(item["interface_values"]),
                    " ".join(item["handler_values"]),
                    " ".join(item["expected_parameters"]),
                    " ".join(item["observed_parameters"]),
                    " ".join(item["configuration_keys"]),
                    " ".join(item["reason_codes"]),
                )))
                for token in text_tokens
            )
        ]

        def facets(key: str) -> dict:
            values = sorted({item[key] or "structured" for item in entries})
            return {
                value: sum((item[key] or "structured") == value for item in entries)
                for value in values
            }

        identity = {
            "schema_version": HISTORICAL_COVERAGE_LEDGER_QUERY_RESULT_SCHEMA_VERSION,
            "ledger_id": ledger.ledger_id,
            "query": asdict(query),
            "vulnerability_identifiers": [
                item["vulnerability_identifier"] for item in selected
            ],
        }
        return {
            "schema_version": HISTORICAL_COVERAGE_LEDGER_QUERY_RESULT_SCHEMA_VERSION,
            "query_id": "historical-coverage-ledger-query:" + hashlib.sha256(
                _encoded(identity).encode("utf-8")
            ).hexdigest(),
            "ledger": {
                key: value for key, value in document.items() if key != "entries"
            },
            "query": asdict(query),
            "entries": selected,
            "total_entry_count": len(entries),
            "selected_entry_count": len(selected),
            "facets": {
                "status": facets("status"),
                "audit_category": facets("audit_category"),
                "evidence_state": facets("evidence_state"),
            },
        }

    def query_communication_graph(
        self, graph_id: str,
        query: CommunicationGraphQuery = CommunicationGraphQuery(),
    ) -> Optional[dict]:
        """Query one immutable graph and resolve evidence from its source Catalog."""

        with self._lock:
            row = self._connection.execute(
                """SELECT document_json, source_catalog_id
                   FROM mapping_communication_graphs WHERE graph_id = ?""",
                (graph_id,),
            ).fetchone()
            if row is None:
                return None
            catalog_row = self._connection.execute(
                """SELECT document_json FROM mapping_discovery_catalogs
                   WHERE catalog_id = ?""",
                (row["source_catalog_id"],),
            ).fetchone()
        graph = CommunicationArchitectureGraph.from_dict(
            json.loads(row["document_json"])
        )
        preset_by_id = {
            item.preset_id: item for item in graph.view_presets
        }
        if query.preset_id and query.preset_id not in preset_by_id:
            raise ValueError("communication graph query has unknown preset")
        preset = preset_by_id.get(query.preset_id)
        allowed_node_kinds = (
            set(preset.node_kinds) if preset is not None
            else {item.value for item in CommunicationGraphNodeKind}
        )
        allowed_edge_kinds = (
            set(preset.edge_kinds) if preset is not None
            else {item.value for item in CommunicationGraphEdgeKind}
        )
        if query.node_kinds:
            allowed_node_kinds.intersection_update(query.node_kinds)
        if query.edge_kinds:
            allowed_edge_kinds.intersection_update(query.edge_kinds)
        allowed_nodes = {
            item.node_id: item for item in graph.nodes
            if item.node_kind.value in allowed_node_kinds
            and (not query.statuses or item.status in query.statuses)
        }
        allowed_edges = tuple(
            item for item in graph.edges
            if item.edge_kind.value in allowed_edge_kinds
            and item.source_ref in allowed_nodes
            and item.target_ref in allowed_nodes
            and (not query.statuses or item.status in query.statuses)
        )
        diagnostics = []
        seeds = set()
        for node_id in query.focus_node_ids:
            if node_id in allowed_nodes:
                seeds.add(node_id)
            else:
                diagnostics.append(
                    "communication_graph_query.focus_node_not_found:{}".format(
                        node_id
                    )
                )
        for identity in query.focus_canonical_identities:
            matching = {
                item.node_id for item in allowed_nodes.values()
                if dict(item.attributes).get("canonical_identity") == identity
            }
            if not matching:
                diagnostics.append(
                    "communication_graph_query.focus_identity_not_found:{}".format(
                        identity
                    )
                )
            seeds.update(matching)
        text_tokens = _search_text(query.text).split()
        if text_tokens:
            text_matches = {
                item.node_id for item in allowed_nodes.values()
                if all(
                    token in _search_text(" ".join((
                        item.label, item.source_path, item.status,
                        item.node_kind.value,
                        " ".join(
                            str(part)
                            for pair in item.attributes for part in pair
                        ),
                    )))
                    for token in text_tokens
                )
            }
            seeds = seeds & text_matches if seeds else text_matches
        if query.evidence_id:
            evidence_matches = {
                item.node_id for item in allowed_nodes.values()
                if query.evidence_id in item.evidence_ids
            }
            for edge in allowed_edges:
                if query.evidence_id in edge.evidence_ids:
                    evidence_matches.update((edge.source_ref, edge.target_ref))
            seeds = seeds & evidence_matches if seeds else evidence_matches
        focus_requested = bool(
            query.focus_node_ids or query.focus_canonical_identities
        )
        selection_filter = bool(
            focus_requested or text_tokens or query.evidence_id
        )
        distances = {}
        if selection_filter:
            distances.update((node_id, 0) for node_id in seeds)
            frontier = set(seeds)
            if focus_requested:
                for distance in range(1, query.max_hops + 1):
                    reached = _reachable_graph_neighbors(
                        frontier, allowed_edges
                    ) - distances.keys()
                    if not reached:
                        break
                    distances.update(
                        (node_id, distance) for node_id in reached
                    )
                    frontier = reached
        else:
            distances.update((node_id, 0) for node_id in allowed_nodes)
        selected_ids = set(distances)
        pre_budget_nodes = tuple(sorted(
            (allowed_nodes[node_id] for node_id in selected_ids),
            key=lambda item: (distances[item.node_id], item.node_id),
        ))
        pre_budget_edges = tuple(sorted(
            (
                item for item in allowed_edges
                if item.source_ref in selected_ids
                and item.target_ref in selected_ids
            ),
            key=lambda item: item.edge_id,
        ))
        selected_nodes = pre_budget_nodes[:query.max_nodes]
        selected_node_ids = {item.node_id for item in selected_nodes}
        eligible_edges = tuple(
            item for item in pre_budget_edges
            if item.source_ref in selected_node_ids
            and item.target_ref in selected_node_ids
        )
        selected_edges = eligible_edges[:query.max_edges]
        if (
            len(pre_budget_nodes) > query.max_nodes
            or len(eligible_edges) > query.max_edges
        ):
            diagnostics.append("communication_graph_query.budget_exceeded")
        query_status = "partial" if diagnostics else "completed"
        graph_document = graph.to_dict()
        node_document_by_id = {
            item["node_id"]: item for item in graph_document["nodes"]
        }
        nodes = [
            node_document_by_id[item.node_id] for item in selected_nodes
        ]
        selected_edge_ids = {item.edge_id for item in selected_edges}
        edge_document_by_id = {
            item["edge_id"]: item for item in graph_document["edges"]
        }
        edges = [
            edge_document_by_id[item.edge_id] for item in selected_edges
            if item.edge_id in selected_edge_ids
        ]
        evidence_ids = {
            evidence_id
            for item in (*selected_nodes, *selected_edges)
            for evidence_id in item.evidence_ids
        }
        catalog = json.loads(catalog_row["document_json"])
        graph_summary = {
            "schema_version": graph.schema_version,
            "graph_id": graph.graph_id,
            "source_catalog_id": graph.source_catalog_id,
            "firmware_artifact_sha256": graph.firmware_artifact_sha256,
            "source_catalog_coverage_status": (
                graph.source_catalog_coverage_status.value
            ),
            "projection_status": graph.projection_status.value,
        }
        combined_diagnostics = sorted(dict.fromkeys((
            *graph.diagnostics, *diagnostics,
        )))
        query_document = asdict(query)
        query_identity = {
            "schema_version": COMMUNICATION_GRAPH_QUERY_RESULT_SCHEMA_VERSION,
            "graph_id": graph.graph_id,
            "query": query_document,
            "query_status": query_status,
            "node_ids": [item.node_id for item in selected_nodes],
            "edge_ids": [item.edge_id for item in selected_edges],
            "diagnostics": combined_diagnostics,
        }
        query_id = "communication-graph-query:{}".format(hashlib.sha256(
            _encoded(query_identity).encode("utf-8")
        ).hexdigest())
        return {
            "schema_version": COMMUNICATION_GRAPH_QUERY_RESULT_SCHEMA_VERSION,
            "query_id": query_id,
            "graph": graph_summary,
            "query": query_document,
            "query_status": query_status,
            "nodes": nodes,
            "edges": edges,
            "total_node_count": len(pre_budget_nodes),
            "total_edge_count": len(pre_budget_edges),
            "selected_node_count": len(nodes),
            "selected_edge_count": len(edges),
            "evidence_atoms": [
                item for item in catalog.get("evidence_atoms", [])
                if item.get("evidence_id") in evidence_ids
            ],
            "facets": {
                "node_kinds": dict(sorted(
                    (
                        kind,
                        sum(item.node_kind.value == kind for item in pre_budget_nodes),
                    )
                    for kind in sorted({
                        item.node_kind.value for item in pre_budget_nodes
                    })
                )),
                "edge_kinds": dict(sorted(
                    (
                        kind,
                        sum(item.edge_kind.value == kind for item in eligible_edges),
                    )
                    for kind in sorted({
                        item.edge_kind.value for item in eligible_edges
                    })
                )),
                "statuses": dict(sorted(
                    (
                        status,
                        sum(item.status == status for item in pre_budget_nodes),
                    )
                    for status in sorted({item.status for item in pre_budget_nodes})
                )),
            },
            "coverage": graph_document["coverage"],
            "view_presets": graph_document["view_presets"],
            "diagnostics": combined_diagnostics,
        }

    def publish_dict(self, document: dict) -> dict:
        catalog_id = str(document.get("catalog_id", ""))
        if not catalog_id or not str(document.get("schema_version", "")):
            raise ValueError("catalog_id and schema_version are required")
        payload = _encoded(document)
        digest = hashlib.sha256(payload.encode()).hexdigest()
        with self._lock, self._connection:
            existing = self._connection.execute(
                "SELECT content_sha256 FROM mapping_discovery_catalogs WHERE catalog_id = ?",
                (catalog_id,),
            ).fetchone()
            if existing:
                if existing["content_sha256"] != digest:
                    raise CatalogConflictError("catalog identity already contains different content")
                return {"catalog_id": catalog_id, "created": False, "content_sha256": digest}

            self._connection.execute(
                """INSERT INTO mapping_discovery_catalogs (
                    catalog_id, schema_version, firmware_artifact_sha256,
                    source_inventory_sha256, coverage_status, scheduler_termination,
                    content_sha256, document_json, published_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    catalog_id, document["schema_version"],
                    document["firmware_artifact_sha256"], document["source_inventory_sha256"],
                    document["coverage_status"], document.get("scheduler_termination"),
                    digest, payload, _utc_now(),
                ),
            )
            parameters = document.get("parameters", [])
            associations = document.get("associations", [])
            obligations = document.get("open_obligations", [])
            deep_candidates = [
                item for item in document.get("candidates", [])
                if dict(item.get("attributes", [])).get("target_ref")
            ]
            for candidate in document.get("candidates", []):
                candidate_id = candidate["candidate_id"]
                candidate_target = dict(candidate.get("attributes", [])).get("target_ref")
                touching = [
                    item for item in associations
                    if candidate_id in (
                        item.get("frontend_candidate_id"), item.get("native_hint_id")
                    ) or item.get("association_id") == candidate_target
                ]
                association_ids = {item.get("association_id") for item in touching}
                related_deep = [
                    item for item in deep_candidates
                    if item.get("candidate_id") != candidate_id
                    and dict(item.get("attributes", [])).get("target_ref")
                    in ({candidate_id} | association_ids)
                ]
                open_count = sum(
                    item.get("target_ref") == candidate_id
                    or item.get("target_ref") in association_ids
                    for item in obligations
                )
                attributes = candidate.get("attributes", [])
                searchable = " ".join([
                    candidate.get("canonical_identity", ""), candidate.get("source_path", ""),
                    candidate.get("source_construct", ""),
                    " ".join(str(part) for pair in attributes for part in pair),
                ])
                self._connection.execute(
                    """INSERT INTO mapping_discovery_candidates (
                        catalog_id, candidate_id, candidate_kind, canonical_identity,
                        claim_status, source_path, source_construct, search_text,
                        parameter_count, association_count, open_obligation_count, candidate_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        catalog_id, candidate_id, candidate["candidate_kind"],
                        candidate["canonical_identity"], candidate["claim_status"],
                        candidate["source_path"], candidate["source_construct"],
                        _search_text(searchable),
                        sum(x.get("owner_ref") == candidate_id for x in parameters),
                        len(touching) + len(related_deep), open_count, _encoded(candidate),
                    ),
                )
            self._replace_hidden_interface_projection(document)
        return {"catalog_id": catalog_id, "created": True, "content_sha256": digest}

    def list_catalogs(self, limit: int = 50, offset: int = 0) -> dict:
        limit, offset = max(1, min(limit, 100)), max(0, offset)
        with self._lock:
            total = self._connection.execute(
                "SELECT COUNT(*) FROM mapping_discovery_catalogs"
            ).fetchone()[0]
            rows = self._connection.execute(
                """SELECT c.*, r.context_json,
                    (SELECT COUNT(*) FROM mapping_discovery_candidates x WHERE x.catalog_id=c.catalog_id) candidate_count,
                    COALESCE(json_array_length(c.document_json, '$.parameters'), 0) parameter_count,
                    COALESCE(json_array_length(c.document_json, '$.associations'), 0) association_count,
                    COALESCE(json_array_length(c.document_json, '$.open_obligations'), 0) open_obligation_count
                FROM mapping_discovery_catalogs c
                LEFT JOIN mapping_catalog_release_contexts r
                  ON r.catalog_id = c.catalog_id
                ORDER BY published_at DESC, c.catalog_id LIMIT ? OFFSET ?""",
                (limit, offset),
            ).fetchall()
        return {"items": [self._catalog_summary(x) for x in rows], "total": total,
                "limit": limit, "offset": offset}

    @staticmethod
    def _catalog_summary(row: sqlite3.Row) -> dict:
        keys = set(row.keys())
        summary = {
            key: row[key] for key in (
                "catalog_id", "schema_version", "firmware_artifact_sha256",
                "source_inventory_sha256", "coverage_status", "scheduler_termination",
                "published_at", "candidate_count", "parameter_count",
                "association_count", "open_obligation_count",
            ) if key in keys
        }
        if "document_json" in keys:
            document = json.loads(row["document_json"])
            summary["source_inventory_coverage_status"] = document.get(
                "source_inventory_coverage_status", "completed"
            )
        if "context_json" in keys:
            summary["release_context"] = (
                json.loads(row["context_json"])
                if row["context_json"] is not None else None
            )
        return summary

    def register_release_context(
        self, catalog_id: str, context: MappingReleaseContext
    ) -> dict:
        """Attach one immutable, evidence-backed release identity to a catalog."""

        payload = context.to_dict()
        encoded = _encoded(payload)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        with self._lock, self._connection:
            catalog = self._connection.execute(
                "SELECT 1 FROM mapping_discovery_catalogs WHERE catalog_id = ?",
                (catalog_id,),
            ).fetchone()
            if catalog is None:
                raise ValueError("mapping catalog does not exist")
            existing = self._connection.execute(
                """SELECT context_sha256 FROM mapping_catalog_release_contexts
                   WHERE catalog_id = ?""",
                (catalog_id,),
            ).fetchone()
            if existing is not None:
                if existing["context_sha256"] != digest:
                    raise CatalogConflictError(
                        "mapping release context is immutable"
                    )
                return {"catalog_id": catalog_id, "created": False}
            self._connection.execute(
                """INSERT INTO mapping_catalog_release_contexts (
                    catalog_id, context_sha256, context_json
                ) VALUES (?, ?, ?)""",
                (catalog_id, digest, encoded),
            )
        return {"catalog_id": catalog_id, "created": True}

    def get_catalog(self, catalog_id: str) -> Optional[dict]:
        with self._lock:
            row = self._connection.execute(
                "SELECT document_json FROM mapping_discovery_catalogs WHERE catalog_id = ?",
                (catalog_id,),
            ).fetchone()
        return json.loads(row["document_json"]) if row else None

    def get_interface_force_graph(self, catalog_id: str) -> Optional[dict]:
        """Return the evidence-preserving expandable interface hierarchy."""

        with self._lock:
            row = self._connection.execute(
                """SELECT c.document_json, r.context_json
                   FROM mapping_discovery_catalogs c
                   LEFT JOIN mapping_catalog_release_contexts r
                     ON r.catalog_id = c.catalog_id
                   WHERE c.catalog_id = ?""",
                (catalog_id,),
            ).fetchone()
        if row is None:
            return None
        return project_interface_force_graph(
            json.loads(row["document_json"]),
            release_context=(
                json.loads(row["context_json"])
                if row["context_json"] is not None else None
            ),
        )

    def compare_catalogs(
        self, base_catalog_id: str, target_catalog_id: str
    ) -> Optional[dict]:
        """Compare two immutable published catalogs through the domain seam."""

        with self._lock:
            rows = self._connection.execute(
                """SELECT c.catalog_id, c.document_json, r.context_json
                   FROM mapping_discovery_catalogs c
                   LEFT JOIN mapping_catalog_release_contexts r
                     ON r.catalog_id = c.catalog_id
                   WHERE c.catalog_id IN (?, ?)""",
                (base_catalog_id, target_catalog_id),
            ).fetchall()
        documents = {
            row["catalog_id"]: json.loads(row["document_json"]) for row in rows
        }
        if base_catalog_id not in documents or target_catalog_id not in documents:
            return None
        contexts = {
            row["catalog_id"]: (
                MappingReleaseContext(**json.loads(row["context_json"]))
                if row["context_json"] is not None else None
            )
            for row in rows
        }
        return compare_mapping_catalog_documents(
            documents[base_catalog_id], documents[target_catalog_id],
            contexts[base_catalog_id], contexts[target_catalog_id],
        ).to_dict()

    def query_candidates(
        self, catalog_id: str, query: str = "", candidate_kind: str = "",
        limit: int = 30, offset: int = 0,
    ) -> dict:
        limit, offset = max(1, min(limit, 500)), max(0, offset)
        clauses, values = ["catalog_id = ?"], [catalog_id]
        if candidate_kind:
            clauses.append("candidate_kind = ?")
            values.append(candidate_kind)
        for token in _search_text(query).split():
            clauses.append("search_text LIKE ?")
            values.append(f"%{token}%")
        where = " AND ".join(clauses)
        with self._lock:
            total = self._connection.execute(
                f"SELECT COUNT(*) FROM mapping_discovery_candidates WHERE {where}", values
            ).fetchone()[0]
            rows = self._connection.execute(
                f"""SELECT * FROM mapping_discovery_candidates WHERE {where}
                    ORDER BY candidate_kind, canonical_identity, candidate_id LIMIT ? OFFSET ?""",
                (*values, limit, offset),
            ).fetchall()
        return {"items": [self._candidate_projection(x) for x in rows], "total": total,
                "limit": limit, "offset": offset}

    @staticmethod
    def _candidate_projection(row: sqlite3.Row) -> dict:
        value = json.loads(row["candidate_json"])
        value.update({
            "parameter_count": row["parameter_count"],
            "association_count": row["association_count"],
            "open_obligation_count": row["open_obligation_count"],
        })
        return value

    def get_candidate(self, catalog_id: str, candidate_id: str) -> Optional[dict]:
        with self._lock:
            row = self._connection.execute(
                """SELECT * FROM mapping_discovery_candidates
                   WHERE catalog_id = ? AND candidate_id = ?""",
                (catalog_id, candidate_id),
            ).fetchone()
            document_row = self._connection.execute(
                "SELECT document_json FROM mapping_discovery_catalogs WHERE catalog_id = ?",
                (catalog_id,),
            ).fetchone()
        if not row or not document_row:
            return None
        document = json.loads(document_row["document_json"])
        candidate = self._candidate_projection(row)
        evidence_ids = set(candidate.get("evidence_ids", []))
        candidate_target = dict(candidate.get("attributes", [])).get("target_ref")
        associations = [
            item for item in document.get("associations", [])
            if candidate_id in (
                item.get("association_id"), item.get("frontend_candidate_id"),
                item.get("native_hint_id"),
            ) or item.get("association_id") == candidate_target
        ]
        association_ids = {item.get("association_id") for item in associations}
        related_targets = {candidate_id, *association_ids}
        related_candidates = [
            item for item in document.get("candidates", [])
            if item.get("candidate_id") != candidate_id
            and dict(item.get("attributes", [])).get("target_ref") in related_targets
        ]
        principal_ids = {
            dict(item.get("attributes", [])).get("principal_id")
            for item in related_candidates
            if dict(item.get("attributes", [])).get("principal_id")
        }
        related_candidate_ids = {
            item.get("candidate_id") for item in related_candidates
        }
        related_candidates.extend(
            item for item in document.get("candidates", [])
            if item.get("candidate_id") in principal_ids
            and item.get("candidate_id") not in related_candidate_ids
        )
        obligations = [
            item for item in document.get("open_obligations", [])
            if item.get("target_ref") == candidate_id or item.get("target_ref") in association_ids
        ]
        parameters = [x for x in document.get("parameters", []) if x.get("owner_ref") == candidate_id]
        for item in parameters + associations + related_candidates:
            evidence_ids.update(item.get("evidence_ids", []))
        return {
            "catalog": {
                "catalog_id": catalog_id,
                "coverage_status": document["coverage_status"],
                "source_inventory_coverage_status": document.get(
                    "source_inventory_coverage_status", "completed"
                ),
                "scheduler_termination": document.get("scheduler_termination"),
            },
            "candidate": candidate,
            "parameters": parameters,
            "associations": associations,
            "related_candidates": related_candidates,
            "open_obligations": obligations,
            "evidence_atoms": [
                x for x in document.get("evidence_atoms", []) if x.get("evidence_id") in evidence_ids
            ],
            "coverage": document.get("coverage", []),
        }

    def query_potential_hidden_interfaces(
        self, query: str = "", firmware_sha256: str = "",
        limit: int = 100, offset: int = 0,
    ) -> dict:
        """Query the latest conservative hidden-interface projection per firmware."""

        limit, offset = max(1, min(limit, 200)), max(0, offset)
        with self._lock:
            index_rows = self._connection.execute(
                """SELECT h.*, c.published_at
                   FROM mapping_hidden_interface_indexes h
                   JOIN mapping_discovery_catalogs c ON c.catalog_id=h.catalog_id
                   ORDER BY c.published_at DESC, c.catalog_id DESC"""
            ).fetchall()
            latest = {}
            for row in index_rows:
                latest.setdefault(row["firmware_artifact_sha256"], row)
            eligible_ids = tuple(
                row["catalog_id"] for row in latest.values()
                if row["coverage_status"] == "completed"
                and (not firmware_sha256
                     or row["firmware_artifact_sha256"] == firmware_sha256)
            )
            rows = []
            total = 0
            firmware_distribution = []
            artifact_distribution = []
            firmware_count = 0
            handler_count = 0
            if eligible_ids:
                placeholders = ",".join("?" for _ in eligible_ids)
                clauses = ["catalog_id IN ({})".format(placeholders)]
                values = list(eligible_ids)
                for token in _search_text(query).split():
                    clauses.append("search_text LIKE ?")
                    values.append("%{}%".format(token))
                where = " AND ".join(clauses)
                total = self._connection.execute(
                    "SELECT COUNT(*) FROM mapping_potential_hidden_interfaces "
                    "WHERE {}".format(where),
                    values,
                ).fetchone()[0]
                rows = self._connection.execute(
                    """SELECT * FROM mapping_potential_hidden_interfaces
                       WHERE {}
                       ORDER BY firmware_artifact_sha256, operation_token,
                                interface_id LIMIT ? OFFSET ?""".format(where),
                    (*values, limit, offset),
                ).fetchall()
                firmware_distribution = self._connection.execute(
                    """SELECT firmware_artifact_sha256, catalog_id, COUNT(*) count
                       FROM mapping_potential_hidden_interfaces WHERE {}
                       GROUP BY firmware_artifact_sha256, catalog_id
                       ORDER BY count DESC, firmware_artifact_sha256, catalog_id""".format(
                        where
                    ),
                    values,
                ).fetchall()
                artifact_distribution = self._connection.execute(
                    """SELECT registration_artifact_path path, COUNT(*) count
                       FROM mapping_potential_hidden_interfaces WHERE {}
                       GROUP BY registration_artifact_path
                       ORDER BY count DESC, registration_artifact_path""".format(where),
                    values,
                ).fetchall()
                firmware_count = self._connection.execute(
                    """SELECT COUNT(DISTINCT firmware_artifact_sha256)
                       FROM mapping_potential_hidden_interfaces WHERE {}""".format(where),
                    values,
                ).fetchone()[0]
                handler_count = self._connection.execute(
                    """SELECT COUNT(DISTINCT handlers.value)
                       FROM mapping_potential_hidden_interfaces h,
                            json_each(h.item_json, '$.handler_identities') handlers
                       WHERE {}""".format(where),
                    values,
                ).fetchone()[0]
        items = [json.loads(row["item_json"]) for row in rows]
        current_rows = tuple(latest.values())
        return {
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
            "summary": {
                "firmware_count": firmware_count,
                "handler_count": handler_count,
                "eligible_firmware_count": sum(
                    row["coverage_status"] == "completed" for row in current_rows
                ),
                "coverage_gap_firmware_count": sum(
                    row["coverage_status"] != "completed" for row in current_rows
                ),
            },
            "distributions": {
                "firmware": [
                    dict(row) for row in firmware_distribution
                ],
                "artifact": [
                    dict(row) for row in artifact_distribution
                ],
            },
        }
