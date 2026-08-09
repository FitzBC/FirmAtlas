"""SQLite adapter for immutable discovery catalogs and their query projections."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any, Optional

from .discovery_catalog import DiscoveryCatalog
from .hidden_interface import project_potential_hidden_interface_document
from .snapshot_diff import MappingReleaseContext, compare_mapping_catalog_documents


class CatalogConflictError(RuntimeError):
    """A catalog identity was reused for content with a different digest."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _encoded(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


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
        limit, offset = max(1, min(limit, 100)), max(0, offset)
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
