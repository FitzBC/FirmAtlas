"""SQLite persistence for normalized and source vulnerability records."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from .models import RelevanceDecision, RelevancePolicy, VulnerabilityRecord
from .semantic import (
    INTERFACE_SUBTYPE_VERSION,
    INTERFACE_STYLE_CATEGORIES,
    classify_interface_style,
    classify_interface_subtype,
    interface_subtype_metadata,
    normalize_firmware_model,
)
from .sources import is_meaningful_identity, vendors_and_products_from_cpes


IDENTITY_NORMALIZATION_VERSION = "cpe-fallback-2026.08.1"
ANALYTICS_CACHE_VERSION = "casefolded-vendor-counts-2026.08.2"
FIRMWARE_FTS_VERSION = "firmware-candidates-2026.08.1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _loads(value: Optional[str], fallback: Any) -> Any:
    return json.loads(value) if value else fallback


class IntelligenceRepository:
    def __init__(self, database: str = "var/firmatlas.db") -> None:
        if database != ":memory:":
            Path(database).parent.mkdir(parents=True, exist_ok=True)
        self._database = database
        self._connection = sqlite3.connect(database, check_same_thread=False, timeout=10)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute("PRAGMA synchronous = NORMAL")
        self._connection.execute("PRAGMA temp_store = MEMORY")
        self._connection.execute("PRAGMA cache_size = -131072")
        self._lock = threading.RLock()
        self.migrate()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                yield self._connection
                self._connection.commit()
            except BaseException:
                self._connection.rollback()
                raise

    @contextmanager
    def read_connection(self) -> Iterator[sqlite3.Connection]:
        """Give file-backed reads their own WAL snapshot instead of waiting on the writer."""
        if self._database == ":memory:":
            with self._lock:
                yield self._connection
            return
        connection = sqlite3.connect(self._database, timeout=2)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 2000")
        try:
            yield connection
        finally:
            connection.close()

    def migrate(self) -> None:
        with self.transaction() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    identifier TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    published_at TEXT,
                    modified_at TEXT,
                    vendor TEXT,
                    product TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    aliases_json TEXT NOT NULL,
                    cwes_json TEXT NOT NULL,
                    cpes_json TEXT NOT NULL,
                    references_json TEXT NOT NULL,
                    sources_json TEXT NOT NULL,
                    kev INTEGER NOT NULL DEFAULT 0,
                    kev_date_added TEXT,
                    kev_due_date TEXT,
                    ransomware_use TEXT,
                    required_action TEXT,
                    relevance_score INTEGER NOT NULL,
                    relevance_level TEXT NOT NULL,
                    relevance_signals_json TEXT NOT NULL,
                    policy_version TEXT NOT NULL,
                    ingested_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_vuln_relevance
                    ON vulnerabilities(relevance_level, modified_at DESC);
                CREATE INDEX IF NOT EXISTS idx_vuln_severity
                    ON vulnerabilities(severity, cvss_score DESC);
                CREATE INDEX IF NOT EXISTS idx_vuln_kev
                    ON vulnerabilities(kev, kev_date_added DESC);

                CREATE TABLE IF NOT EXISTS source_records (
                    source TEXT NOT NULL,
                    source_identifier TEXT NOT NULL,
                    vulnerability_identifier TEXT NOT NULL,
                    modified_at TEXT,
                    fetched_at TEXT NOT NULL,
                    raw_json TEXT NOT NULL,
                    PRIMARY KEY(source, source_identifier),
                    FOREIGN KEY(vulnerability_identifier)
                        REFERENCES vulnerabilities(identifier) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS sync_runs (
                    run_id TEXT PRIMARY KEY,
                    sources_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    fetched_count INTEGER NOT NULL DEFAULT 0,
                    relevant_count INTEGER NOT NULL DEFAULT 0,
                    error TEXT
                );

                CREATE TABLE IF NOT EXISTS sync_cursors (
                    source TEXT PRIMARY KEY,
                    cursor TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS feed_states (
                    feed_name TEXT PRIMARY KEY,
                    last_modified TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    local_path TEXT,
                    status TEXT NOT NULL,
                    imported_count INTEGER NOT NULL DEFAULT 0,
                    relevant_count INTEGER NOT NULL DEFAULT 0,
                    checked_at TEXT NOT NULL,
                    imported_at TEXT,
                    error TEXT
                );

                CREATE TABLE IF NOT EXISTS vulnerability_cwes (
                    vulnerability_identifier TEXT NOT NULL,
                    cwe_id TEXT NOT NULL,
                    PRIMARY KEY(vulnerability_identifier, cwe_id),
                    FOREIGN KEY(vulnerability_identifier)
                        REFERENCES vulnerabilities(identifier) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_vulnerability_cwes_cwe
                    ON vulnerability_cwes(cwe_id);

                CREATE TABLE IF NOT EXISTS firmware_sources (
                    source_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    base_url TEXT NOT NULL,
                    vendor TEXT,
                    trust_level TEXT NOT NULL,
                    access_notes TEXT NOT NULL DEFAULT '',
                    evidence_url TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_firmware_sources_type
                    ON firmware_sources(source_type, trust_level);

                CREATE TABLE IF NOT EXISTS firmware_sample_candidates (
                    candidate_id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL,
                    external_id TEXT,
                    vendor TEXT NOT NULL,
                    product TEXT NOT NULL,
                    model TEXT NOT NULL,
                    firmware_version TEXT,
                    filename TEXT NOT NULL,
                    download_url TEXT NOT NULL,
                    download_host TEXT NOT NULL DEFAULT '',
                    source_page_url TEXT NOT NULL,
                    evidence_url TEXT NOT NULL,
                    url_status TEXT NOT NULL DEFAULT 'listed',
                    download_kind TEXT NOT NULL DEFAULT 'direct',
                    notes TEXT NOT NULL DEFAULT '',
                    version_identities_json TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(source_id) REFERENCES firmware_sources(source_id)
                );
                CREATE INDEX IF NOT EXISTS idx_firmware_candidates_vendor
                    ON firmware_sample_candidates(vendor COLLATE NOCASE, model COLLATE NOCASE);
                CREATE INDEX IF NOT EXISTS idx_firmware_candidates_source
                    ON firmware_sample_candidates(source_id, updated_at DESC);

                CREATE TABLE IF NOT EXISTS firmware_sample_vulnerabilities (
                    candidate_id TEXT NOT NULL,
                    vulnerability_identifier TEXT NOT NULL,
                    relationship TEXT NOT NULL,
                    confidence TEXT NOT NULL,
                    evidence_url TEXT NOT NULL,
                    notes TEXT NOT NULL DEFAULT '',
                    association_origin TEXT NOT NULL DEFAULT 'curated',
                    match_method TEXT NOT NULL DEFAULT 'curated_evidence',
                    match_score INTEGER NOT NULL DEFAULT 100,
                    candidate_version TEXT,
                    affected_constraint TEXT,
                    matched_criteria TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(candidate_id, vulnerability_identifier),
                    FOREIGN KEY(candidate_id) REFERENCES firmware_sample_candidates(candidate_id)
                        ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_firmware_leads_vulnerability
                    ON firmware_sample_vulnerabilities(vulnerability_identifier, candidate_id);

                CREATE TABLE IF NOT EXISTS analytics_cache (
                    cache_key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS semantic_analyses (
                    analysis_id TEXT PRIMARY KEY,
                    vulnerability_identifier TEXT NOT NULL,
                    input_sha256 TEXT NOT NULL,
                    analyzer_fingerprint TEXT NOT NULL,
                    strategy TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    warning TEXT,
                    prompt_tokens INTEGER NOT NULL DEFAULT 0,
                    completion_tokens INTEGER NOT NULL DEFAULT 0,
                    interface_count INTEGER NOT NULL DEFAULT 0,
                    parameter_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    is_current INTEGER NOT NULL DEFAULT 1,
                    FOREIGN KEY(vulnerability_identifier)
                        REFERENCES vulnerabilities(identifier) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_semantic_vulnerability_latest
                    ON semantic_analyses(vulnerability_identifier, finished_at DESC);

                CREATE TABLE IF NOT EXISTS semantic_interface_observations (
                    analysis_id TEXT NOT NULL,
                    value TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    method TEXT,
                    protocol TEXT,
                    component TEXT,
                    confidence REAL NOT NULL,
                    evidence TEXT NOT NULL,
                    source TEXT NOT NULL,
                    style_category TEXT NOT NULL DEFAULT '',
                    style_subtype TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(analysis_id, value, kind),
                    FOREIGN KEY(analysis_id) REFERENCES semantic_analyses(analysis_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_semantic_interface_value
                    ON semantic_interface_observations(value);

                CREATE TABLE IF NOT EXISTS semantic_parameter_observations (
                    analysis_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    interface_value TEXT,
                    location TEXT,
                    security_effect TEXT,
                    confidence REAL NOT NULL,
                    evidence TEXT NOT NULL,
                    source TEXT NOT NULL,
                    PRIMARY KEY(analysis_id, name, interface_value),
                    FOREIGN KEY(analysis_id) REFERENCES semantic_analyses(analysis_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_semantic_parameter_name
                    ON semantic_parameter_observations(name);

                CREATE TABLE IF NOT EXISTS semantic_analysis_jobs (
                    job_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    strategy TEXT NOT NULL,
                    force INTEGER NOT NULL DEFAULT 0,
                    total_count INTEGER NOT NULL DEFAULT 0,
                    processed_count INTEGER NOT NULL DEFAULT 0,
                    analyzed_count INTEGER NOT NULL DEFAULT 0,
                    cached_count INTEGER NOT NULL DEFAULT 0,
                    failed_count INTEGER NOT NULL DEFAULT 0,
                    interfaces_count INTEGER NOT NULL DEFAULT 0,
                    parameters_count INTEGER NOT NULL DEFAULT 0,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    error TEXT
                );
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(vulnerabilities)")}
            additions = {
                "cvss_version": "TEXT",
                "impact_score": "REAL",
                "exploitability_score": "REAL",
                "attack_vector": "TEXT",
                "attack_complexity": "TEXT",
                "privileges_required": "TEXT",
                "user_interaction": "TEXT",
                "scope": "TEXT",
                "cvss_metrics_json": "TEXT NOT NULL DEFAULT '[]'",
                "reference_details_json": "TEXT NOT NULL DEFAULT '[]'",
                "exploit_references_json": "TEXT NOT NULL DEFAULT '[]'",
                "has_exploit": "INTEGER NOT NULL DEFAULT 0",
                "cwe_details_json": "TEXT NOT NULL DEFAULT '[]'",
                "affected_products_json": "TEXT NOT NULL DEFAULT '[]'",
            }
            for name, definition in additions.items():
                if name not in columns:
                    connection.execute(
                        "ALTER TABLE vulnerabilities ADD COLUMN {} {}".format(name, definition)
                    )
            firmware_columns = {
                row[1] for row in connection.execute(
                    "PRAGMA table_info(firmware_sample_candidates)"
                )
            }
            if "download_host" not in firmware_columns:
                connection.execute(
                    "ALTER TABLE firmware_sample_candidates "
                    "ADD COLUMN download_host TEXT NOT NULL DEFAULT ''"
                )
            if "version_identities_json" not in firmware_columns:
                connection.execute(
                    "ALTER TABLE firmware_sample_candidates "
                    "ADD COLUMN version_identities_json TEXT NOT NULL DEFAULT '[]'"
                )
            lead_columns = {
                row[1] for row in connection.execute(
                    "PRAGMA table_info(firmware_sample_vulnerabilities)"
                )
            }
            lead_additions = {
                "association_origin": "TEXT NOT NULL DEFAULT 'curated'",
                "match_method": "TEXT NOT NULL DEFAULT 'curated_evidence'",
                "match_score": "INTEGER NOT NULL DEFAULT 100",
                "candidate_version": "TEXT",
                "affected_constraint": "TEXT",
                "matched_criteria": "TEXT",
            }
            for name, definition in lead_additions.items():
                if name not in lead_columns:
                    connection.execute(
                        "ALTER TABLE firmware_sample_vulnerabilities ADD COLUMN {} {}".format(
                            name, definition
                        )
                    )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_firmware_leads_match "
                "ON firmware_sample_vulnerabilities(match_method,match_score DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_firmware_candidates_host "
                "ON firmware_sample_candidates(download_host, vendor COLLATE NOCASE)"
            )
            missing_hosts = connection.execute(
                "SELECT candidate_id,download_url FROM firmware_sample_candidates "
                "WHERE download_host=''"
            ).fetchall()
            if missing_hosts:
                connection.executemany(
                    "UPDATE firmware_sample_candidates SET download_host=? "
                    "WHERE candidate_id=?",
                    [
                        (
                            (urlsplit(row["download_url"]).hostname or "").lower(),
                            row["candidate_id"],
                        )
                        for row in missing_hosts
                    ],
                )
            semantic_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(semantic_analyses)")
            }
            if "is_current" not in semantic_columns:
                connection.execute(
                    "ALTER TABLE semantic_analyses ADD COLUMN is_current INTEGER NOT NULL DEFAULT 1"
                )
            semantic_counts_added = False
            if "interface_count" not in semantic_columns:
                connection.execute(
                    "ALTER TABLE semantic_analyses ADD COLUMN interface_count INTEGER NOT NULL DEFAULT 0"
                )
                semantic_counts_added = True
            if "parameter_count" not in semantic_columns:
                connection.execute(
                    "ALTER TABLE semantic_analyses ADD COLUMN parameter_count INTEGER NOT NULL DEFAULT 0"
                )
                semantic_counts_added = True
            interface_columns = {
                row[1] for row in connection.execute(
                    "PRAGMA table_info(semantic_interface_observations)"
                )
            }
            style_category_added = "style_category" not in interface_columns
            if style_category_added:
                connection.execute(
                    "ALTER TABLE semantic_interface_observations "
                    "ADD COLUMN style_category TEXT NOT NULL DEFAULT ''"
                )
            style_subtype_added = "style_subtype" not in interface_columns
            if style_subtype_added:
                connection.execute(
                    "ALTER TABLE semantic_interface_observations "
                    "ADD COLUMN style_subtype TEXT NOT NULL DEFAULT ''"
                )
            if semantic_counts_added:
                connection.execute(
                    """UPDATE semantic_analyses SET
                       interface_count=(SELECT COUNT(*) FROM semantic_interface_observations o
                                         WHERE o.analysis_id=semantic_analyses.analysis_id),
                       parameter_count=(SELECT COUNT(*) FROM semantic_parameter_observations p
                                         WHERE p.analysis_id=semantic_analyses.analysis_id)
                       WHERE interface_count=0 AND parameter_count=0"""
                )
            if style_category_added:
                connection.execute(
                    """UPDATE semantic_interface_observations SET style_category=CASE
                       WHEN lower(value) LIKE 'tcp://%' OR lower(value) LIKE 'udp://%'
                            OR kind='network_listener' THEN ''
                       WHEN lower(value) LIKE '/goform/%' OR lower(value) LIKE '/form/%'
                            THEN 'form_handler'
                       WHEN lower(value) LIKE '/cgi-bin/%' OR lower(value) LIKE '/scgi-bin/%'
                            OR lower(value) LIKE '%.cgi%' THEN 'cgi_gateway'
                       WHEN lower(value) LIKE '%hnap%' OR lower(value) LIKE '%soap%'
                            THEN 'hnap_soap'
                       WHEN lower(value) LIKE '/api/%' OR lower(value) LIKE '/rest/%'
                            OR lower(value) LIKE '/v1/%' OR lower(value) LIKE '/v2/%'
                            THEN 'resource_api'
                       WHEN lower(value) GLOB '*.asp' OR lower(value) GLOB '*.aspx'
                            OR lower(value) GLOB '*.php' OR lower(value) GLOB '*.jsp'
                            OR lower(value) GLOB '*.do' OR lower(value) GLOB '*.action'
                            THEN 'web_action'
                       WHEN kind IN ('rpc','command','topic','socket','device_node')
                            THEN 'rpc_command'
                       ELSE 'management_route' END
                       WHERE style_category='' AND kind!='network_listener'
                         AND lower(value) NOT LIKE 'tcp://%' AND lower(value) NOT LIKE 'udp://%'"""
                )
            subtype_marker = connection.execute(
                "SELECT value_json FROM settings WHERE key='semantic_subtype_classifier_version'"
            ).fetchone()
            subtype_backfill_required = (
                style_subtype_added
                or not subtype_marker
                or _loads(subtype_marker[0], "") != INTERFACE_SUBTYPE_VERSION
            )
            if subtype_backfill_required:
                observations = connection.execute(
                    "SELECT analysis_id,value,kind,component,style_category "
                    "FROM semantic_interface_observations"
                ).fetchall()
                connection.executemany(
                    "UPDATE semantic_interface_observations SET style_subtype=? "
                    "WHERE analysis_id=? AND value=? AND kind=?",
                    [
                        (
                            classify_interface_subtype(
                                row["value"], row["kind"], row["component"] or "",
                                row["style_category"],
                            ),
                            row["analysis_id"], row["value"], row["kind"],
                        )
                        for row in observations
                    ],
                )
                connection.execute(
                    """INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?)
                       ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,
                           updated_at=excluded.updated_at""",
                    (
                        "semantic_subtype_classifier_version",
                        _json(INTERFACE_SUBTYPE_VERSION), _utc_now(),
                    ),
                )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_vuln_exploit ON vulnerabilities(has_exploit, modified_at DESC)"
            )
            connection.executescript(
                """
                CREATE INDEX IF NOT EXISTS idx_vuln_firmware_rank
                    ON vulnerabilities(kev DESC, cvss_score DESC, modified_at DESC)
                    WHERE relevance_level IN ('strong','likely');
                CREATE INDEX IF NOT EXISTS idx_vuln_firmware_severity_rank
                    ON vulnerabilities(severity, kev DESC, cvss_score DESC, modified_at DESC)
                    WHERE relevance_level IN ('strong','likely');
                CREATE INDEX IF NOT EXISTS idx_vuln_firmware_vendor_rank
                    ON vulnerabilities(vendor COLLATE NOCASE, kev DESC, cvss_score DESC, modified_at DESC)
                    WHERE relevance_level IN ('strong','likely');
                CREATE INDEX IF NOT EXISTS idx_vuln_firmware_exploit_rank
                    ON vulnerabilities(kev DESC, cvss_score DESC, modified_at DESC)
                    WHERE relevance_level IN ('strong','likely') AND has_exploit = 1;
                CREATE INDEX IF NOT EXISTS idx_vuln_firmware_kev_rank
                    ON vulnerabilities(cvss_score DESC, modified_at DESC)
                    WHERE relevance_level IN ('strong','likely') AND kev = 1;
                CREATE INDEX IF NOT EXISTS idx_vuln_firmware_time
                    ON vulnerabilities(
                        COALESCE(published_at,modified_at) DESC,
                        COALESCE(modified_at,published_at) DESC,
                        identifier DESC)
                    WHERE relevance_level IN ('strong','likely');
                CREATE INDEX IF NOT EXISTS idx_vuln_firmware_vendor_time
                    ON vulnerabilities(
                        vendor COLLATE NOCASE,
                        COALESCE(published_at,modified_at) DESC,
                        COALESCE(modified_at,published_at) DESC,
                        identifier DESC)
                    WHERE relevance_level IN ('strong','likely');
                CREATE INDEX IF NOT EXISTS idx_vuln_firmware_severity_time
                    ON vulnerabilities(
                        severity,
                        COALESCE(published_at,modified_at) DESC,
                        COALESCE(modified_at,published_at) DESC,
                        identifier DESC)
                    WHERE relevance_level IN ('strong','likely');
                CREATE INDEX IF NOT EXISTS idx_vuln_firmware_exploit_time
                    ON vulnerabilities(
                        COALESCE(published_at,modified_at) DESC,
                        COALESCE(modified_at,published_at) DESC,
                        identifier DESC)
                    WHERE relevance_level IN ('strong','likely') AND has_exploit=1;
                CREATE INDEX IF NOT EXISTS idx_vuln_firmware_kev_time
                    ON vulnerabilities(
                        COALESCE(published_at,modified_at) DESC,
                        COALESCE(modified_at,published_at) DESC,
                        identifier DESC)
                    WHERE relevance_level IN ('strong','likely') AND kev=1;
                CREATE INDEX IF NOT EXISTS idx_semantic_interface_category
                    ON semantic_interface_observations(style_category, value);
                CREATE INDEX IF NOT EXISTS idx_semantic_interface_subtype
                    ON semantic_interface_observations(style_category, style_subtype, value);
                """
            )
            try:
                connection.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS vulnerabilities_fts USING fts5(identifier UNINDEXED, title, summary, vendor, product)"
                )
            except sqlite3.OperationalError:
                pass
            try:
                connection.executescript(
                    """
                    CREATE VIRTUAL TABLE IF NOT EXISTS firmware_candidates_fts USING fts5(
                        external_id,vendor,product,model,firmware_version,filename,download_url,
                        content='firmware_sample_candidates',content_rowid='rowid'
                    );
                    CREATE TRIGGER IF NOT EXISTS firmware_candidates_fts_ai AFTER INSERT
                    ON firmware_sample_candidates BEGIN
                      INSERT INTO firmware_candidates_fts(
                        rowid,external_id,vendor,product,model,firmware_version,filename,download_url)
                      VALUES(new.rowid,new.external_id,new.vendor,new.product,new.model,
                        new.firmware_version,new.filename,new.download_url);
                    END;
                    CREATE TRIGGER IF NOT EXISTS firmware_candidates_fts_ad AFTER DELETE
                    ON firmware_sample_candidates BEGIN
                      INSERT INTO firmware_candidates_fts(
                        firmware_candidates_fts,rowid,external_id,vendor,product,model,
                        firmware_version,filename,download_url)
                      VALUES('delete',old.rowid,old.external_id,old.vendor,old.product,old.model,
                        old.firmware_version,old.filename,old.download_url);
                    END;
                    CREATE TRIGGER IF NOT EXISTS firmware_candidates_fts_au AFTER UPDATE
                    ON firmware_sample_candidates BEGIN
                      INSERT INTO firmware_candidates_fts(
                        firmware_candidates_fts,rowid,external_id,vendor,product,model,
                        firmware_version,filename,download_url)
                      VALUES('delete',old.rowid,old.external_id,old.vendor,old.product,old.model,
                        old.firmware_version,old.filename,old.download_url);
                      INSERT INTO firmware_candidates_fts(
                        rowid,external_id,vendor,product,model,firmware_version,filename,download_url)
                      VALUES(new.rowid,new.external_id,new.vendor,new.product,new.model,
                        new.firmware_version,new.filename,new.download_url);
                    END;
                    """
                )
                firmware_fts_marker = connection.execute(
                    "SELECT value_json FROM settings WHERE key='firmware_fts_version'"
                ).fetchone()
                if (
                    not firmware_fts_marker
                    or _loads(firmware_fts_marker[0], "") != FIRMWARE_FTS_VERSION
                ):
                    connection.execute(
                        "INSERT INTO firmware_candidates_fts(firmware_candidates_fts) VALUES('rebuild')"
                    )
                    connection.execute(
                        """INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?)
                           ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,
                               updated_at=excluded.updated_at""",
                        ("firmware_fts_version", _json(FIRMWARE_FTS_VERSION), _utc_now()),
                    )
            except sqlite3.OperationalError:
                pass
            identity_marker = connection.execute(
                "SELECT value_json FROM settings WHERE key='identity_normalization_version'"
            ).fetchone()
            if (
                not identity_marker
                or _loads(identity_marker[0], "") != IDENTITY_NORMALIZATION_VERSION
            ):
                self._repair_vulnerability_identities(connection)
                self._save_identity_normalization_marker(connection)
            analytics_marker = connection.execute(
                "SELECT value_json FROM settings WHERE key='analytics_cache_version'"
            ).fetchone()
            if (
                not analytics_marker
                or _loads(analytics_marker[0], "") != ANALYTICS_CACHE_VERSION
            ):
                connection.execute("DELETE FROM analytics_cache")
                connection.execute(
                    """INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?)
                       ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,
                           updated_at=excluded.updated_at""",
                    (
                        "analytics_cache_version",
                        _json(ANALYTICS_CACHE_VERSION),
                        _utc_now(),
                    ),
                )

    def repair_vulnerability_identities(self, force: bool = False) -> int:
        """Restore missing vendor/product identities from existing CPE evidence."""
        with self.transaction() as connection:
            marker = connection.execute(
                "SELECT value_json FROM settings WHERE key='identity_normalization_version'"
            ).fetchone()
            if (
                not force and marker
                and _loads(marker[0], "") == IDENTITY_NORMALIZATION_VERSION
            ):
                return 0
            repaired = self._repair_vulnerability_identities(connection)
            self._save_identity_normalization_marker(connection)
            return repaired

    @staticmethod
    def _save_identity_normalization_marker(connection: sqlite3.Connection) -> None:
        connection.execute(
            """INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?)
               ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,
                   updated_at=excluded.updated_at""",
            (
                "identity_normalization_version",
                _json(IDENTITY_NORMALIZATION_VERSION),
                _utc_now(),
            ),
        )

    @staticmethod
    def _repair_vulnerability_identities(connection: sqlite3.Connection) -> int:
        rows = connection.execute(
            """SELECT identifier,title,vendor,product,cpes_json
               FROM vulnerabilities
               WHERE lower(trim(COALESCE(vendor,''))) IN ('','n/a','na','unknown','unspecified')
                  OR lower(trim(COALESCE(product,''))) IN ('','n/a','na','unknown','unspecified')"""
        ).fetchall()
        updates: List[Tuple[Optional[str], Optional[str], str, str, str]] = []
        for row in rows:
            cpe_vendors, cpe_products = vendors_and_products_from_cpes(
                _loads(row["cpes_json"], [])
            )
            vendor = (
                row["vendor"] if is_meaningful_identity(row["vendor"])
                else cpe_vendors[0] if cpe_vendors else None
            )
            product = (
                row["product"] if is_meaningful_identity(row["product"])
                else cpe_products[0] if cpe_products else None
            )
            if vendor == row["vendor"] and product == row["product"]:
                continue
            title = row["title"] or row["identifier"]
            title_suffix = title.split("·", 1)[1] if "·" in title else ""
            if title_suffix and not any(
                is_meaningful_identity(value)
                for value in title_suffix.strip().split()
            ):
                identity = " ".join(value for value in (vendor, product) if value)
                title = "{} · {}".format(row["identifier"], identity or "未知厂商")
            updates.append((vendor, product, title, _utc_now(), row["identifier"]))
        if not updates:
            return 0
        connection.executemany(
            """UPDATE vulnerabilities SET vendor=?,product=?,title=?,updated_at=?
               WHERE identifier=?""",
            updates,
        )
        fts_exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='vulnerabilities_fts'"
        ).fetchone()
        if fts_exists:
            connection.execute("DELETE FROM vulnerabilities_fts")
            connection.execute(
                """INSERT INTO vulnerabilities_fts(identifier,title,summary,vendor,product)
                   SELECT identifier,title,summary,vendor,product FROM vulnerabilities"""
            )
        connection.execute("DELETE FROM analytics_cache")
        return len(updates)

    def upsert_firmware_sources(self, sources: Sequence[Dict[str, Any]]) -> int:
        now = _utc_now()
        with self.transaction() as connection:
            connection.executemany(
                """INSERT INTO firmware_sources(
                       source_id,name,source_type,base_url,vendor,trust_level,
                       access_notes,evidence_url,created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(source_id) DO UPDATE SET
                       name=excluded.name,source_type=excluded.source_type,
                       base_url=excluded.base_url,vendor=excluded.vendor,
                       trust_level=excluded.trust_level,
                       access_notes=excluded.access_notes,
                       evidence_url=excluded.evidence_url,
                       updated_at=excluded.updated_at""",
                [
                    (
                        item["source_id"], item["name"], item["source_type"],
                        item["base_url"], item.get("vendor"), item["trust_level"],
                        item.get("access_notes", ""), item["evidence_url"], now, now,
                    )
                    for item in sources
                ],
            )
        return len(sources)

    def upsert_firmware_candidates(self, candidates: Sequence[Dict[str, Any]]) -> int:
        now = _utc_now()
        with self.transaction() as connection:
            connection.executemany(
                """INSERT INTO firmware_sample_candidates(
                       candidate_id,source_id,external_id,vendor,product,model,
                       firmware_version,filename,download_url,download_host,
                       source_page_url,evidence_url,url_status,download_kind,notes,
                       created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(candidate_id) DO UPDATE SET
                       source_id=excluded.source_id,external_id=excluded.external_id,
                       vendor=excluded.vendor,product=excluded.product,model=excluded.model,
                       firmware_version=excluded.firmware_version,filename=excluded.filename,
                       download_url=excluded.download_url,
                       download_host=excluded.download_host,
                       source_page_url=excluded.source_page_url,
                       evidence_url=excluded.evidence_url,url_status=excluded.url_status,
                       download_kind=excluded.download_kind,notes=excluded.notes,
                       updated_at=excluded.updated_at""",
                [
                    (
                        item["candidate_id"], item["source_id"], item.get("external_id"),
                        item["vendor"], item["product"], item["model"],
                        item.get("firmware_version"), item["filename"],
                        item["download_url"], item.get("download_host") or (
                            urlsplit(item["download_url"]).hostname or ""
                        ).lower(), item["source_page_url"],
                        item["evidence_url"], item.get("url_status", "listed"),
                        item.get("download_kind", "direct"), item.get("notes", ""),
                        now, now,
                    )
                    for item in candidates
                ],
            )
        return len(candidates)

    def upsert_firmware_vulnerability_leads(
        self, leads: Sequence[Dict[str, Any]]
    ) -> int:
        now = _utc_now()
        with self.transaction() as connection:
            connection.executemany(
                """INSERT INTO firmware_sample_vulnerabilities(
                       candidate_id,vulnerability_identifier,relationship,confidence,
                       evidence_url,notes,association_origin,match_method,match_score,
                       candidate_version,affected_constraint,matched_criteria,
                       created_at,updated_at
                   ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(candidate_id,vulnerability_identifier) DO UPDATE SET
                       relationship=excluded.relationship,confidence=excluded.confidence,
                       evidence_url=excluded.evidence_url,notes=excluded.notes,
                       association_origin=excluded.association_origin,
                       match_method=excluded.match_method,match_score=excluded.match_score,
                       candidate_version=excluded.candidate_version,
                       affected_constraint=excluded.affected_constraint,
                       matched_criteria=excluded.matched_criteria,
                       updated_at=excluded.updated_at""",
                [
                    (
                        item["candidate_id"], item["vulnerability_identifier"],
                        item["relationship"], item["confidence"], item["evidence_url"],
                        item.get("notes", ""), item.get("association_origin", "curated"),
                        item.get("match_method", "curated_evidence"),
                        item.get("match_score", 100), item.get("candidate_version"),
                        item.get("affected_constraint"), item.get("matched_criteria"),
                        now, now,
                    )
                    for item in leads
                ],
            )
        return len(leads)

    def firmware_catalog_overview(self) -> Dict[str, Any]:
        with self.read_connection() as connection:
            counts = connection.execute(
                """SELECT
                     (SELECT COUNT(*) FROM firmware_sources) source_count,
                     (SELECT COUNT(*) FROM firmware_sources WHERE source_type='official') official_source_count,
                     (SELECT COUNT(DISTINCT download_host)
                        FROM firmware_sample_candidates WHERE download_host!='') download_host_count,
                     (SELECT COUNT(*) FROM firmware_sample_candidates) candidate_count,
                     (SELECT COUNT(DISTINCT candidate_id) FROM firmware_sample_vulnerabilities) linked_candidate_count,
                     (SELECT COUNT(*) FROM firmware_sample_vulnerabilities) vulnerability_lead_count,
                     (SELECT COUNT(*) FROM firmware_sample_vulnerabilities
                       WHERE match_method='exact_version') exact_version_link_count,
                     (SELECT COUNT(*) FROM firmware_sample_vulnerabilities
                       WHERE match_method='version_range') version_range_link_count,
                     (SELECT COUNT(*) FROM firmware_sample_vulnerabilities
                       WHERE match_method='product_scope') product_scope_link_count,
                     (SELECT COUNT(*) FROM firmware_sample_candidates
                       WHERE version_identities_json!='[]') version_identified_candidate_count"""
            ).fetchone()
            vendors = connection.execute(
                """SELECT MIN(vendor) label,COUNT(*) value
                   FROM firmware_sample_candidates
                   WHERE lower(trim(vendor)) NOT IN ('', 'unknown', 'others', 'n/a')
                   GROUP BY vendor COLLATE NOCASE ORDER BY value DESC,label LIMIT 250"""
            ).fetchall()
            sources = connection.execute(
                """SELECT s.source_id,s.name,s.source_type,s.trust_level,
                          COUNT(c.candidate_id) candidate_count
                   FROM firmware_sources s LEFT JOIN firmware_sample_candidates c
                     ON c.source_id=s.source_id
                   GROUP BY s.source_id ORDER BY candidate_count DESC,s.name LIMIT 12"""
            ).fetchall()
            hosts = connection.execute(
                """SELECT download_host label,COUNT(*) value
                   FROM firmware_sample_candidates WHERE download_host!=''
                   GROUP BY download_host ORDER BY value DESC,label LIMIT 16"""
            ).fetchall()
        return {
            "counts": {key: counts[key] or 0 for key in counts.keys()},
            "vendors": [dict(row) for row in vendors],
            "sources": [dict(row) for row in sources],
            "hosts": [dict(row) for row in hosts],
        }

    def list_firmware_sources(self) -> List[Dict[str, Any]]:
        with self.read_connection() as connection:
            rows = connection.execute(
                """SELECT s.*,
                          COUNT(DISTINCT c.candidate_id) candidate_count,
                          COUNT(DISTINCT l.vulnerability_identifier) vulnerability_count
                   FROM firmware_sources s
                   LEFT JOIN firmware_sample_candidates c ON c.source_id=s.source_id
                   LEFT JOIN firmware_sample_vulnerabilities l ON l.candidate_id=c.candidate_id
                   GROUP BY s.source_id
                   ORDER BY CASE s.trust_level WHEN 'primary' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
                            candidate_count DESC,s.name"""
            ).fetchall()
        return [dict(row) for row in rows]

    def list_firmware_candidates(
        self,
        query: str = "",
        vendor: str = "",
        source_id: str = "",
        download_host: str = "",
        has_vulnerability: bool = False,
        match_method: str = "",
        limit: int = 30,
        offset: int = 0,
    ) -> Dict[str, Any]:
        clauses: List[str] = []
        values: List[Any] = []
        if query:
            vulnerability_query = re.fullmatch(
                r"(?:CVE|CNVD)-\d{4}-\d+", query.strip(), flags=re.IGNORECASE
            )
            if vulnerability_query:
                clauses.append(
                    "EXISTS(SELECT 1 FROM firmware_sample_vulnerabilities ql "
                    "       WHERE ql.candidate_id=c.candidate_id "
                    "         AND ql.vulnerability_identifier=? COLLATE NOCASE)"
                )
                values.append(query.strip())
            elif self._firmware_fts_available():
                terms = re.findall(r"[\w.-]+", query, flags=re.UNICODE)
                if terms:
                    clauses.append(
                        "c.rowid IN (SELECT rowid FROM firmware_candidates_fts "
                        "            WHERE firmware_candidates_fts MATCH ?)"
                    )
                    values.append(
                        " AND ".join(
                            '"{}"*'.format(term.replace('"', '""')) for term in terms
                        )
                    )
                else:
                    clauses.append("0=1")
            else:
                clauses.append(
                    "(c.external_id LIKE ? OR c.vendor LIKE ? OR c.product LIKE ? "
                    "OR c.model LIKE ? OR c.firmware_version LIKE ? OR c.filename LIKE ? "
                    "OR c.download_url LIKE ?)"
                )
                wildcard = "%{}%".format(query)
                values.extend([wildcard] * 7)
        if vendor:
            clauses.append("c.vendor = ? COLLATE NOCASE")
            values.append(vendor)
        if source_id:
            clauses.append("c.source_id = ?")
            values.append(source_id)
        if download_host:
            clauses.append("c.download_host = ? COLLATE NOCASE")
            values.append(download_host)
        if has_vulnerability:
            clauses.append(
                "EXISTS(SELECT 1 FROM firmware_sample_vulnerabilities hl "
                "       WHERE hl.candidate_id=c.candidate_id)"
            )
        if match_method:
            if match_method == "version":
                clauses.append(
                    "EXISTS(SELECT 1 FROM firmware_sample_vulnerabilities ml "
                    "       WHERE ml.candidate_id=c.candidate_id "
                    "         AND ml.match_method IN ('exact_version','version_range'))"
                )
            elif match_method in ("exact_version", "version_range", "product_scope", "curated_evidence"):
                clauses.append(
                    "EXISTS(SELECT 1 FROM firmware_sample_vulnerabilities ml "
                    "       WHERE ml.candidate_id=c.candidate_id AND ml.match_method=?)"
                )
                values.append(match_method)
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        limit = max(1, min(limit, 100))
        offset = max(0, offset)
        base = " FROM firmware_sample_candidates c JOIN firmware_sources s ON s.source_id=c.source_id"
        with self.read_connection() as connection:
            total = connection.execute("SELECT COUNT(*)" + base + where, values).fetchone()[0]
            rows = connection.execute(
                """SELECT c.*,s.name source_name,s.source_type,s.trust_level,
                          (SELECT COUNT(*) FROM firmware_sample_vulnerabilities l
                           WHERE l.candidate_id=c.candidate_id) vulnerability_count,
                          (SELECT GROUP_CONCAT(vulnerability_identifier, ',')
                           FROM firmware_sample_vulnerabilities l
                           WHERE l.candidate_id=c.candidate_id) vulnerability_identifiers,
                          (SELECT COUNT(*) FROM firmware_sample_vulnerabilities vl
                           WHERE vl.candidate_id=c.candidate_id
                             AND vl.match_method IN ('exact_version','version_range')) version_link_count,
                          (SELECT match_method FROM firmware_sample_vulnerabilities sl
                           WHERE sl.candidate_id=c.candidate_id
                           ORDER BY sl.match_score DESC LIMIT 1) strongest_match_method"""
                + base + where
                + " ORDER BY vulnerability_count DESC,c.vendor COLLATE NOCASE,c.model COLLATE NOCASE,c.external_id LIMIT ? OFFSET ?",
                values + [limit, offset],
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["version_identities"] = _loads(item.pop("version_identities_json", "[]"), [])
            item["vulnerability_identifiers"] = [
                value for value in (item["vulnerability_identifiers"] or "").split(",") if value
            ]
            items.append(item)
        pages = (total + limit - 1) // limit if total else 0
        return {
            "items": items,
            "total": total,
            "limit": limit,
            "offset": offset,
            "page": offset // limit + 1,
            "pages": pages,
            "has_previous": offset > 0,
            "has_next": offset + limit < total,
        }

    def get_firmware_candidate(self, candidate_id: str) -> Optional[Dict[str, Any]]:
        with self.read_connection() as connection:
            row = connection.execute(
                """SELECT c.*,s.name source_name,s.source_type,s.trust_level,
                          s.base_url source_base_url,s.access_notes source_access_notes
                   FROM firmware_sample_candidates c JOIN firmware_sources s
                     ON s.source_id=c.source_id WHERE c.candidate_id=?""",
                (candidate_id,),
            ).fetchone()
            if not row:
                return None
            leads = connection.execute(
                """SELECT l.*,v.title,v.vendor vulnerability_vendor,
                          v.product vulnerability_product,v.severity,v.cvss_score
                   FROM firmware_sample_vulnerabilities l
                   LEFT JOIN vulnerabilities v ON v.identifier=l.vulnerability_identifier
                   WHERE l.candidate_id=? ORDER BY l.vulnerability_identifier""",
                (candidate_id,),
            ).fetchall()
        result = dict(row)
        result["version_identities"] = _loads(
            result.pop("version_identities_json", "[]"), []
        )
        result["vulnerabilities"] = [dict(item) for item in leads]
        result["vulnerability_count"] = len(leads)
        result["vulnerability_identifiers"] = [
            item["vulnerability_identifier"] for item in leads
        ]
        return result

    def firmware_candidates_for_vulnerability(
        self, identifier: str, limit: int = 50, offset: int = 0
    ) -> Dict[str, Any]:
        limit = max(1, min(limit, 100))
        offset = max(0, offset)
        with self.read_connection() as connection:
            total = connection.execute(
                "SELECT COUNT(*) FROM firmware_sample_vulnerabilities "
                "WHERE vulnerability_identifier=?", (identifier,)
            ).fetchone()[0]
            rows = connection.execute(
                """SELECT c.*,s.name source_name,s.source_type,s.trust_level,
                          l.relationship,l.confidence,l.evidence_url lead_evidence_url,l.notes lead_notes,
                          l.association_origin,l.match_method,l.match_score,
                          l.candidate_version,l.affected_constraint,l.matched_criteria
                   FROM firmware_sample_vulnerabilities l
                   JOIN firmware_sample_candidates c ON c.candidate_id=l.candidate_id
                   JOIN firmware_sources s ON s.source_id=c.source_id
                   WHERE l.vulnerability_identifier=?
                   ORDER BY CASE l.confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                            c.vendor COLLATE NOCASE,c.model COLLATE NOCASE LIMIT ? OFFSET ?""",
                (identifier, limit, offset),
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row)
            item["version_identities"] = _loads(item.pop("version_identities_json", "[]"), [])
            item["vulnerability_count"] = 1
            item["vulnerability_identifiers"] = [identifier]
            items.append(item)
        pages = (total + limit - 1) // limit if total else 0
        return {
            "identifier": identifier, "items": items, "total": total,
            "limit": limit, "offset": offset, "page": offset // limit + 1,
            "pages": pages, "has_previous": offset > 0,
            "has_next": offset + limit < total,
        }

    def _firmware_fts_available(self) -> bool:
        with self.read_connection() as connection:
            row = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='firmware_candidates_fts'"
            ).fetchone()
        return bool(row)

    def get_policy(self) -> RelevancePolicy:
        with self._lock:
            row = self._connection.execute(
                "SELECT value_json FROM settings WHERE key = 'relevance_policy'"
            ).fetchone()
        return RelevancePolicy.from_dict(_loads(row[0], {})) if row else RelevancePolicy()

    def save_policy(self, policy: RelevancePolicy) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO settings(key, value_json, updated_at) VALUES(?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value_json = excluded.value_json,
                    updated_at = excluded.updated_at
                """,
                ("relevance_policy", _json(policy.to_dict()), _utc_now()),
            )

    def get_cursor(self, source: str) -> Optional[str]:
        with self._lock:
            row = self._connection.execute(
                "SELECT cursor FROM sync_cursors WHERE source = ?", (source,)
            ).fetchone()
        return str(row[0]) if row else None

    def save_cursor(self, source: str, cursor: str) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO sync_cursors(source, cursor, updated_at) VALUES(?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    cursor = excluded.cursor, updated_at = excluded.updated_at
                """,
                (source, cursor, _utc_now()),
            )

    def upsert(
        self, record: VulnerabilityRecord, decision: RelevanceDecision
    ) -> Dict[str, Any]:
        with self.transaction() as connection:
            self._write_record(connection, record, decision)
        return self.get(record.identifier) or {}

    def upsert_many(
        self,
        items: Sequence[Tuple[VulnerabilityRecord, RelevanceDecision]],
        maintain_fts: bool = True,
        maintain_cwes: bool = True,
    ) -> Tuple[int, int]:
        imported = 0
        relevant = 0
        with self.transaction() as connection:
            for record, decision in items:
                if not record.identifier:
                    continue
                self._write_record(
                    connection, record, decision,
                    maintain_fts=maintain_fts, maintain_cwes=maintain_cwes,
                )
                imported += 1
                relevant += int(decision.is_firmware_related)
        return imported, relevant

    def _write_record(
        self,
        connection: sqlite3.Connection,
        record: VulnerabilityRecord,
        decision: RelevanceDecision,
        maintain_fts: bool = True,
        maintain_cwes: bool = True,
    ) -> None:
        now = _utc_now()
        existing_row = connection.execute(
            "SELECT * FROM vulnerabilities WHERE identifier = ?", (record.identifier,)
        ).fetchone()
        merged = self._merge(existing_row, record)
        connection.execute(
                """
                INSERT INTO vulnerabilities(
                    identifier, title, summary, published_at, modified_at, vendor,
                    product, severity, cvss_score, cvss_vector, aliases_json,
                    cwes_json, cpes_json, references_json, sources_json, kev,
                    kev_date_added, kev_due_date, ransomware_use, required_action,
                    relevance_score, relevance_level, relevance_signals_json,
                    policy_version, ingested_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(identifier) DO UPDATE SET
                    title=excluded.title, summary=excluded.summary,
                    published_at=excluded.published_at, modified_at=excluded.modified_at,
                    vendor=excluded.vendor, product=excluded.product,
                    severity=excluded.severity, cvss_score=excluded.cvss_score,
                    cvss_vector=excluded.cvss_vector, aliases_json=excluded.aliases_json,
                    cwes_json=excluded.cwes_json, cpes_json=excluded.cpes_json,
                    references_json=excluded.references_json,
                    sources_json=excluded.sources_json, kev=excluded.kev,
                    kev_date_added=excluded.kev_date_added,
                    kev_due_date=excluded.kev_due_date,
                    ransomware_use=excluded.ransomware_use,
                    required_action=excluded.required_action,
                    relevance_score=excluded.relevance_score,
                    relevance_level=excluded.relevance_level,
                    relevance_signals_json=excluded.relevance_signals_json,
                    policy_version=excluded.policy_version, updated_at=excluded.updated_at
                """,
                (
                    merged.identifier,
                    merged.title,
                    merged.summary,
                    merged.published_at,
                    merged.modified_at,
                    merged.vendor,
                    merged.product,
                    merged.severity,
                    merged.cvss_score,
                    merged.cvss_vector,
                    _json(merged.aliases),
                    _json(merged.cwes),
                    _json(merged.cpes),
                    _json(merged.references),
                    _json(merged.raw.get("sources", (record.source,))),
                    int(merged.kev),
                    merged.kev_date_added,
                    merged.kev_due_date,
                    merged.ransomware_use,
                    merged.required_action,
                    decision.score,
                    decision.level.value,
                    _json([signal.__dict__ for signal in decision.signals]),
                    decision.policy_version,
                    existing_row["ingested_at"] if existing_row else now,
                    now,
                ),
            )
        connection.execute(
            """
            UPDATE vulnerabilities SET cvss_version=?, impact_score=?,
                exploitability_score=?, attack_vector=?, attack_complexity=?,
                privileges_required=?, user_interaction=?, scope=?,
                cvss_metrics_json=?, reference_details_json=?,
                exploit_references_json=?, has_exploit=?, cwe_details_json=?,
                affected_products_json=? WHERE identifier=?
            """,
            (
                merged.cvss_version,
                merged.impact_score,
                merged.exploitability_score,
                merged.attack_vector,
                merged.attack_complexity,
                merged.privileges_required,
                merged.user_interaction,
                merged.scope,
                _json(merged.cvss_metrics),
                _json(merged.reference_details),
                _json(merged.exploit_references),
                int(bool(merged.exploit_references)),
                _json(merged.cwe_details),
                _json(merged.affected_products),
                merged.identifier,
            ),
        )
        if maintain_cwes:
            connection.execute("DELETE FROM vulnerability_cwes WHERE vulnerability_identifier=?", (merged.identifier,))
            connection.executemany(
                "INSERT OR IGNORE INTO vulnerability_cwes(vulnerability_identifier, cwe_id) VALUES(?, ?)",
                ((merged.identifier, cwe) for cwe in merged.cwes),
            )
        if maintain_fts:
            try:
                connection.execute("DELETE FROM vulnerabilities_fts WHERE identifier=?", (merged.identifier,))
                connection.execute(
                    "INSERT INTO vulnerabilities_fts(identifier,title,summary,vendor,product) VALUES(?,?,?,?,?)",
                    (merged.identifier, merged.title, merged.summary, merged.vendor, merged.product),
                )
            except sqlite3.OperationalError:
                pass
        connection.execute(
                """
                INSERT INTO source_records(
                    source, source_identifier, vulnerability_identifier,
                    modified_at, fetched_at, raw_json
                ) VALUES(?,?,?,?,?,?)
                ON CONFLICT(source, source_identifier) DO UPDATE SET
                    vulnerability_identifier=excluded.vulnerability_identifier,
                    modified_at=excluded.modified_at,
                    fetched_at=excluded.fetched_at,
                    raw_json=excluded.raw_json
                """,
                (
                    record.source,
                    record.source_identifier,
                    record.identifier,
                    record.modified_at,
                    now,
                    _json(record.raw),
                ),
            )

    def reclassify(self, classifier: Any, policy: RelevancePolicy) -> int:
        with self._lock:
            rows = self._connection.execute("SELECT * FROM vulnerabilities").fetchall()
        updates: List[Tuple[Any, ...]] = []
        for row in rows:
            record = self._row_to_record(row)
            decision = classifier.classify(record, policy)
            updates.append(
                (
                    decision.score,
                    decision.level.value,
                    _json([signal.__dict__ for signal in decision.signals]),
                    decision.policy_version,
                    _utc_now(),
                    record.identifier,
                )
            )
        with self.transaction() as connection:
            connection.executemany(
                """
                UPDATE vulnerabilities SET relevance_score=?, relevance_level=?,
                    relevance_signals_json=?, policy_version=?, updated_at=?
                WHERE identifier=?
                """,
                updates,
            )
        return len(updates)

    def list(
        self,
        query: str = "",
        severity: str = "",
        source: str = "",
        vendor: str = "",
        relevance: str = "firmware",
        kev_only: bool = False,
        exploit_only: bool = False,
        cwe: str = "",
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        clauses: List[str] = []
        values: List[Any] = []
        if relevance == "firmware":
            clauses.append("relevance_level IN ('strong','likely')")
        elif relevance == "review":
            clauses.append("relevance_level = 'review'")
        elif relevance in ("strong", "likely", "unrelated"):
            clauses.append("relevance_level = ?")
            values.append(relevance)
        if query:
            terms = re.findall(r"[\w.-]+", query, flags=re.UNICODE)
            if terms and self._fts_available():
                clauses.append("identifier IN (SELECT identifier FROM vulnerabilities_fts WHERE vulnerabilities_fts MATCH ?)")
                values.append(" AND ".join('"{}"'.format(term.replace('"', '""')) for term in terms))
            else:
                clauses.append(
                    "(identifier LIKE ? OR title LIKE ? OR summary LIKE ? OR vendor LIKE ? OR product LIKE ?)"
                )
                wildcard = "%{}%".format(query)
                values.extend([wildcard] * 5)
        if severity:
            clauses.append("severity = ?")
            values.append(severity.upper())
        if source:
            clauses.append("sources_json LIKE ?")
            values.append('%"{}"%'.format(source))
        if vendor:
            clauses.append("vendor = ? COLLATE NOCASE")
            values.append(vendor)
        if kev_only:
            clauses.append("kev = 1")
        if exploit_only:
            clauses.append("has_exploit = 1")
        if cwe:
            clauses.append(
                "identifier IN (SELECT vulnerability_identifier FROM vulnerability_cwes WHERE cwe_id = ?)"
            )
            values.append(cwe.upper())
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        table = "vulnerabilities"
        if relevance == "firmware":
            if kev_only:
                table += " INDEXED BY idx_vuln_firmware_kev_time"
            elif vendor:
                table += " INDEXED BY idx_vuln_firmware_vendor_time"
            elif severity:
                table += " INDEXED BY idx_vuln_firmware_severity_time"
            elif exploit_only:
                table += " INDEXED BY idx_vuln_firmware_exploit_time"
            else:
                table += " INDEXED BY idx_vuln_firmware_time"
        limit = max(1, min(limit, 200))
        offset = max(0, offset)
        with self.read_connection() as connection:
            total = connection.execute(
                "SELECT COUNT(*) FROM " + table + where, values
            ).fetchone()[0]
            rows = connection.execute(
                "SELECT vulnerabilities.*, "
                "COALESCE((SELECT interface_count FROM semantic_analyses a "
                "          WHERE a.vulnerability_identifier=vulnerabilities.identifier "
                "            AND a.is_current=1 LIMIT 1),0) semantic_interface_count, "
                "COALESCE((SELECT parameter_count FROM semantic_analyses a "
                "          WHERE a.vulnerability_identifier=vulnerabilities.identifier "
                "            AND a.is_current=1 LIMIT 1),0) semantic_parameter_count "
                "FROM " + table
                + where
                + " ORDER BY COALESCE(published_at,modified_at,'') DESC, "
                  "COALESCE(modified_at,published_at,'') DESC, identifier DESC "
                  "LIMIT ? OFFSET ?",
                values + [limit, offset],
            ).fetchall()
        pages = (total + limit - 1) // limit if total else 0
        page = offset // limit + 1
        return {
            "items": [self._serialize_row(row) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
            "page": page,
            "pages": pages,
            "has_previous": offset > 0,
            "has_next": offset + limit < total,
        }

    def get(self, identifier: str) -> Optional[Dict[str, Any]]:
        with self.read_connection() as connection:
            row = connection.execute(
                """SELECT v.*,
                     COALESCE((SELECT interface_count FROM semantic_analyses a
                       WHERE a.vulnerability_identifier=v.identifier AND a.is_current=1 LIMIT 1),0)
                       semantic_interface_count,
                     COALESCE((SELECT parameter_count FROM semantic_analyses a
                       WHERE a.vulnerability_identifier=v.identifier AND a.is_current=1 LIMIT 1),0)
                       semantic_parameter_count
                   FROM vulnerabilities v WHERE v.identifier = ?""", (identifier,)
            ).fetchone()
        return self._serialize_row(row) if row else None

    def overview(self) -> Dict[str, Any]:
        cached = self._get_analytics_cache("overview")
        if cached is not None:
            return cached
        with self.read_connection() as connection:
            row = connection.execute(
                """
                SELECT
                    SUM(CASE WHEN relevance_level IN ('strong','likely') THEN 1 ELSE 0 END) relevant,
                    SUM(CASE WHEN relevance_level IN ('strong','likely') AND severity = 'CRITICAL' THEN 1 ELSE 0 END) critical,
                    SUM(CASE WHEN relevance_level IN ('strong','likely') AND kev = 1 THEN 1 ELSE 0 END) kev,
                    SUM(CASE WHEN relevance_level IN ('strong','likely') AND has_exploit = 1 THEN 1 ELSE 0 END) exploit,
                    MAX(updated_at) last_updated
                FROM vulnerabilities
                """
            ).fetchone()
            levels = connection.execute(
                """
                SELECT relevance_level label, COUNT(*) value FROM vulnerabilities
                GROUP BY relevance_level ORDER BY value DESC
                """
            ).fetchall()
            vendors = connection.execute(
                """
                SELECT MIN(vendor) label, COUNT(*) value
                FROM vulnerabilities
                WHERE relevance_level IN ('strong','likely')
                  AND lower(COALESCE(vendor, '')) NOT IN ('', 'n/a', 'unknown', 'linux', 'erlang')
                GROUP BY vendor COLLATE NOCASE ORDER BY value DESC LIMIT 10
                """
            ).fetchall()
        recent = self.list(limit=6)
        result = {
            "counts": {
                "relevant": row["relevant"] or 0,
                "critical": row["critical"] or 0,
                "kev": row["kev"] or 0,
                "exploit": row["exploit"] or 0,
            },
            "last_updated": row["last_updated"],
            "levels": [dict(item) for item in levels],
            "vendors": [dict(item) for item in vendors],
            "recent": recent["items"],
        }
        self._save_analytics_cache("overview", result)
        return result

    def statistics(self) -> Dict[str, Any]:
        cached = self._get_analytics_cache("statistics")
        if cached is not None:
            return cached
        with self.read_connection() as connection:
            totals = connection.execute(
                """
                SELECT COUNT(*) total,
                    SUM(CASE WHEN relevance_level IN ('strong','likely') THEN 1 ELSE 0 END) relevant,
                    SUM(CASE WHEN has_exploit=1 THEN 1 ELSE 0 END) exploit,
                    SUM(CASE WHEN kev=1 THEN 1 ELSE 0 END) kev,
                    SUM(CASE WHEN cwes_json != '[]' THEN 1 ELSE 0 END) with_cwe
                FROM vulnerabilities
                """
            ).fetchone()
            severity = connection.execute(
                """SELECT COALESCE(severity, 'UNKNOWN') label, COUNT(*) value
                   FROM vulnerabilities WHERE relevance_level IN ('strong','likely')
                   GROUP BY severity ORDER BY value DESC"""
            ).fetchall()
            versions = connection.execute(
                """SELECT COALESCE(cvss_version, 'Unknown') label, COUNT(*) value
                   FROM vulnerabilities WHERE relevance_level IN ('strong','likely')
                   GROUP BY cvss_version ORDER BY value DESC"""
            ).fetchall()
            cwes = connection.execute(
                """SELECT cwe_id label, COUNT(*) value FROM vulnerability_cwes vc
                   JOIN vulnerabilities v ON v.identifier=vc.vulnerability_identifier
                   WHERE v.relevance_level IN ('strong','likely')
                     AND vc.cwe_id GLOB 'CWE-[0-9]*'
                   GROUP BY cwe_id ORDER BY value DESC LIMIT 10"""
            ).fetchall()
            years = connection.execute(
                """SELECT substr(published_at,1,4) label, COUNT(*) value
                   FROM vulnerabilities WHERE relevance_level IN ('strong','likely')
                     AND published_at IS NOT NULL
                   GROUP BY substr(published_at,1,4) ORDER BY label DESC LIMIT 12"""
            ).fetchall()
        result = {
            "counts": {key: totals[key] or 0 for key in totals.keys()},
            "severity": [dict(row) for row in severity],
            "cvss_versions": [dict(row) for row in versions],
            "cwes": [dict(row) for row in cwes],
            "years": list(reversed([dict(row) for row in years])),
        }
        self._save_analytics_cache("statistics", result)
        return result

    def refresh_analytics(self) -> Dict[str, Any]:
        with self.transaction() as connection:
            connection.execute("DELETE FROM analytics_cache")
        statistics = self.statistics()
        overview = self.overview()
        return {"statistics": statistics, "overview": overview}

    def get_semantic_settings(self) -> Optional[Dict[str, Any]]:
        with self.read_connection() as connection:
            row = connection.execute(
                "SELECT value_json FROM settings WHERE key='semantic_model_settings'"
            ).fetchone()
        return _loads(row[0], {}) if row else None

    def save_semantic_settings(self, value: Dict[str, Any]) -> None:
        with self.transaction() as connection:
            connection.execute(
                """INSERT INTO settings(key,value_json,updated_at) VALUES(?,?,?)
                   ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json,
                       updated_at=excluded.updated_at""",
                ("semantic_model_settings", _json(value), _utc_now()),
            )

    def get_semantic_analysis(
        self,
        identifier: str,
        input_sha256: str = "",
        analyzer_fingerprint: str = "",
    ) -> Optional[Dict[str, Any]]:
        clauses = ["vulnerability_identifier=?"]
        values: List[Any] = [identifier]
        if input_sha256:
            clauses.append("input_sha256=?")
            values.append(input_sha256)
        if analyzer_fingerprint:
            clauses.append("analyzer_fingerprint=?")
            values.append(analyzer_fingerprint)
        with self.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM semantic_analyses WHERE {} ORDER BY finished_at DESC LIMIT 1".format(
                    " AND ".join(clauses)
                ),
                values,
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["result"] = _loads(result.pop("result_json"), {})
        return result

    def save_semantic_analysis(self, value: Dict[str, Any]) -> Dict[str, Any]:
        result = value["result"]
        with self.transaction() as connection:
            connection.execute(
                "UPDATE semantic_analyses SET is_current=0 WHERE vulnerability_identifier=?",
                (value["vulnerability_identifier"],),
            )
            connection.execute(
                """INSERT INTO semantic_analyses(
                       analysis_id,vulnerability_identifier,input_sha256,
                       analyzer_fingerprint,strategy,status,result_json,warning,
                       prompt_tokens,completion_tokens,interface_count,parameter_count,
                       created_at,finished_at,is_current)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""",
                (
                    value["analysis_id"], value["vulnerability_identifier"],
                    value["input_sha256"], value["analyzer_fingerprint"],
                    value["strategy"], value["status"], _json(result),
                    value.get("warning"), value.get("prompt_tokens", 0),
                    value.get("completion_tokens", 0),
                    len(result.get("interfaces", [])),
                    len(result.get("parameters", [])), value["created_at"],
                    value["finished_at"],
                ),
            )
            for item in result.get("interfaces", []):
                connection.execute(
                    """INSERT OR IGNORE INTO semantic_interface_observations(
                           analysis_id,value,kind,method,protocol,component,
                           confidence,evidence,source,style_category,style_subtype)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        value["analysis_id"], item["value"], item["kind"],
                        item.get("method"), item.get("protocol"), item.get("component"),
                        item["confidence"], item["evidence"], item["source"],
                        classify_interface_style(
                            item["value"], item["kind"], item.get("component") or ""
                        ),
                        classify_interface_subtype(
                            item["value"], item["kind"], item.get("component") or ""
                        ),
                    ),
                )
            for item in result.get("parameters", []):
                connection.execute(
                    """INSERT OR IGNORE INTO semantic_parameter_observations(
                           analysis_id,name,interface_value,location,security_effect,
                           confidence,evidence,source) VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        value["analysis_id"], item["name"], item.get("interface"),
                        item.get("location"), item.get("security_effect"),
                        item["confidence"], item["evidence"], item["source"],
                    ),
                )
        return self.get_semantic_analysis(
            value["vulnerability_identifier"], value["input_sha256"],
            value["analyzer_fingerprint"],
        ) or value

    def semantic_candidates(
        self, after_identifier: str = "", limit: int = 500
    ) -> List[Dict[str, Any]]:
        with self.read_connection() as connection:
            rows = connection.execute(
                """SELECT identifier,title,summary,vendor,product,modified_at
                   FROM vulnerabilities INDEXED BY idx_vuln_firmware_rank
                   WHERE relevance_level IN ('strong','likely') AND identifier>?
                   ORDER BY identifier LIMIT ?""",
                (after_identifier, max(1, min(limit, 2000))),
            ).fetchall()
        return [dict(row) for row in rows]

    def semantic_overview(self) -> Dict[str, Any]:
        with self.read_connection() as connection:
            totals = connection.execute(
                """SELECT
                     (SELECT COUNT(*) FROM vulnerabilities
                       WHERE relevance_level IN ('strong','likely')) total,
                     COUNT(DISTINCT vulnerability_identifier) analyzed,
                     COALESCE(SUM(prompt_tokens),0) prompt_tokens,
                     COALESCE(SUM(completion_tokens),0) completion_tokens
                   FROM semantic_analyses WHERE status IN ('succeeded','partial')
                     AND is_current=1"""
            ).fetchone()
            interface_count = connection.execute(
                """SELECT COUNT(*) FROM semantic_interface_observations o
                   JOIN semantic_analyses a USING(analysis_id) WHERE a.is_current=1"""
            ).fetchone()[0]
            parameter_count = connection.execute(
                """SELECT COUNT(*) FROM semantic_parameter_observations o
                   JOIN semantic_analyses a USING(analysis_id) WHERE a.is_current=1"""
            ).fetchone()[0]
            top_interfaces = connection.execute(
                """SELECT o.value label,COUNT(*) value
                   FROM semantic_interface_observations o
                   JOIN semantic_analyses a USING(analysis_id)
                   WHERE a.is_current=1 GROUP BY o.value ORDER BY value DESC LIMIT 8"""
            ).fetchall()
            top_parameters = connection.execute(
                """SELECT o.name label,COUNT(*) value
                   FROM semantic_parameter_observations o
                   JOIN semantic_analyses a USING(analysis_id)
                   WHERE a.is_current=1 GROUP BY o.name ORDER BY value DESC LIMIT 8"""
            ).fetchall()
        total = totals["total"] or 0
        analyzed = totals["analyzed"] or 0
        return {
            "total": total, "analyzed": analyzed, "pending": max(0, total - analyzed),
            "interfaces": interface_count, "parameters": parameter_count,
            "prompt_tokens": totals["prompt_tokens"],
            "completion_tokens": totals["completion_tokens"],
            "top_interfaces": [dict(row) for row in top_interfaces],
            "top_parameters": [dict(row) for row in top_parameters],
        }

    def semantic_explore(
        self,
        kind: str,
        value: str = "",
        query: str = "",
        subtype: str = "",
        limit: int = 25,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Browse semantic facts or drill into their associated vulnerabilities."""
        if kind not in {"interface", "parameter", "category"}:
            raise ValueError("semantic explorer kind must be interface, parameter or category")
        limit = max(1, min(int(limit), 100))
        offset = max(0, int(offset))
        if value and kind == "category":
            return self._semantic_category_interfaces(
                value, query, subtype, limit, offset
            )
        if value:
            return self._semantic_associations(kind, value, limit, offset)

        search = "%{}%".format(query.strip())
        with self.read_connection() as connection:
            if kind == "interface":
                where = "a.is_current=1 AND o.style_category!=''"
                values: List[Any] = []
                if query.strip():
                    where += " AND (o.value LIKE ? OR o.component LIKE ?)"
                    values.extend([search, search])
                total = connection.execute(
                    """SELECT COUNT(DISTINCT o.value)
                       FROM semantic_interface_observations o
                       JOIN semantic_analyses a USING(analysis_id)
                       WHERE {}""".format(where), values,
                ).fetchone()[0]
                rows = connection.execute(
                    """SELECT o.value,MIN(o.kind) kind,MIN(o.method) method,
                              MIN(o.protocol) protocol,MIN(o.component) component,
                              MIN(o.style_category) category,COUNT(*) occurrence_count,
                              COUNT(DISTINCT a.vulnerability_identifier) vulnerability_count,
                              COUNT(DISTINCT CASE WHEN lower(COALESCE(v.vendor,''))
                                NOT IN ('','n/a','unknown') THEN v.vendor END) vendor_count,
                              GROUP_CONCAT(DISTINCT CASE WHEN lower(COALESCE(v.vendor,''))
                                NOT IN ('','n/a','unknown') THEN v.vendor END) vendors,
                              MAX(COALESCE(v.published_at,v.modified_at)) latest_at
                       FROM semantic_interface_observations o
                       JOIN semantic_analyses a USING(analysis_id)
                       JOIN vulnerabilities v ON v.identifier=a.vulnerability_identifier
                       WHERE {} GROUP BY o.value
                       ORDER BY vulnerability_count DESC,o.value ASC LIMIT ? OFFSET ?""".format(where),
                    values + [limit, offset],
                ).fetchall()
            elif kind == "parameter":
                where = "a.is_current=1"
                values = []
                if query.strip():
                    where += " AND (p.name LIKE ? OR p.security_effect LIKE ?)"
                    values.extend([search, search])
                total = connection.execute(
                    """SELECT COUNT(DISTINCT p.name)
                       FROM semantic_parameter_observations p
                       JOIN semantic_analyses a USING(analysis_id)
                       WHERE {}""".format(where), values,
                ).fetchone()[0]
                rows = connection.execute(
                    """SELECT p.name value,MIN(p.interface_value) interface_value,
                              MIN(p.location) location,MIN(p.security_effect) security_effect,
                              COALESCE(MAX(i.style_category),'management_route') category,
                              COUNT(*) occurrence_count,
                              COUNT(DISTINCT a.vulnerability_identifier) vulnerability_count,
                              COUNT(DISTINCT CASE WHEN lower(COALESCE(v.vendor,''))
                                NOT IN ('','n/a','unknown') THEN v.vendor END) vendor_count,
                              GROUP_CONCAT(DISTINCT CASE WHEN lower(COALESCE(v.vendor,''))
                                NOT IN ('','n/a','unknown') THEN v.vendor END) vendors,
                              MAX(COALESCE(v.published_at,v.modified_at)) latest_at
                       FROM semantic_parameter_observations p
                       JOIN semantic_analyses a USING(analysis_id)
                       JOIN vulnerabilities v ON v.identifier=a.vulnerability_identifier
                       LEFT JOIN semantic_interface_observations i
                         ON i.analysis_id=p.analysis_id AND i.value=p.interface_value
                       WHERE {} GROUP BY p.name
                       ORDER BY vulnerability_count DESC,p.name ASC LIMIT ? OFFSET ?""".format(where),
                    values + [limit, offset],
                ).fetchall()
            else:
                categories = self.semantic_categories()
                items = categories["items"]
                if query.strip():
                    needle = query.strip().lower()
                    items = [
                        item for item in items
                        if needle in item["label"].lower()
                        or needle in item["description"].lower()
                    ]
                total = len(items)
                rows = items[offset : offset + limit]

        items = [dict(row) for row in rows]
        for item in items:
            vendors = item.get("vendors")
            if isinstance(vendors, str):
                item["vendors"] = [value for value in vendors.split(",") if value][:5]
            elif not isinstance(vendors, list):
                item["vendors"] = []
        return self._semantic_page(items, total, limit, offset)

    def _semantic_category_interfaces(
        self, category: str, query: str, subtype: str, limit: int, offset: int
    ) -> Dict[str, Any]:
        where = "a.is_current=1 AND o.style_category=?"
        values: List[Any] = [category]
        if subtype.strip():
            where += " AND o.style_subtype=?"
            values.append(subtype.strip())
        if query.strip():
            search = "%{}%".format(query.strip())
            where += " AND (o.value LIKE ? OR o.component LIKE ?)"
            values.extend([search, search])
        with self.read_connection() as connection:
            total = connection.execute(
                """SELECT COUNT(DISTINCT o.value)
                   FROM semantic_interface_observations o
                   JOIN semantic_analyses a USING(analysis_id)
                   WHERE {}""".format(where), values,
            ).fetchone()[0]
            rows = connection.execute(
                """SELECT o.value,MIN(o.kind) kind,MIN(o.method) method,
                          MIN(o.protocol) protocol,MIN(o.component) component,
                          MIN(o.style_category) category,MIN(o.style_subtype) subtype,
                          COUNT(*) occurrence_count,
                          COUNT(DISTINCT a.vulnerability_identifier) vulnerability_count,
                          COUNT(DISTINCT CASE WHEN lower(COALESCE(v.vendor,''))
                            NOT IN ('','n/a','unknown') THEN v.vendor END) vendor_count,
                          GROUP_CONCAT(DISTINCT CASE WHEN lower(COALESCE(v.vendor,''))
                            NOT IN ('','n/a','unknown') THEN v.vendor END) vendors,
                          MAX(COALESCE(v.published_at,v.modified_at)) latest_at
                   FROM semantic_interface_observations o
                   JOIN semantic_analyses a USING(analysis_id)
                   JOIN vulnerabilities v ON v.identifier=a.vulnerability_identifier
                   WHERE {} GROUP BY o.value
                   ORDER BY vulnerability_count DESC,o.value ASC LIMIT ? OFFSET ?""".format(where),
                values + [limit, offset],
            ).fetchall()
        items = [dict(row) for row in rows]
        for item in items:
            item["vendors"] = [
                vendor for vendor in (item.get("vendors") or "").split(",") if vendor
            ][:5]
            item["subtype_label"] = interface_subtype_metadata(
                category, item.get("subtype") or ""
            )["label"]
        result = self._semantic_page(items, total, limit, offset)
        result["selection"] = self._semantic_category_profile(category, subtype)
        return result

    def _semantic_category_profile(
        self, category: str, active_subtype: str = ""
    ) -> Dict[str, Any]:
        category_item = next(
            (item for item in self.semantic_categories()["items"] if item["key"] == category),
            {"key": category, "label": category, "description": "接口风格关联"},
        )
        active_subtype = active_subtype.strip()
        scoped_clause = " AND o.style_subtype=?" if active_subtype else ""
        scoped_values: Tuple[Any, ...] = (
            (category, active_subtype) if active_subtype else (category,)
        )
        with self.read_connection() as connection:
            subtype_rows = connection.execute(
                """SELECT o.style_subtype subtype,COUNT(DISTINCT o.value) interface_count,
                          COUNT(DISTINCT a.vulnerability_identifier) vulnerability_count,
                          COUNT(DISTINCT CASE WHEN lower(COALESCE(v.vendor,''))
                            NOT IN ('','n/a','unknown') THEN v.vendor END) vendor_count,
                          COUNT(DISTINCT CASE WHEN lower(COALESCE(v.product,''))
                            NOT IN ('','n/a','unknown') THEN v.product END) model_count
                   FROM semantic_interface_observations o
                   JOIN semantic_analyses a USING(analysis_id)
                   JOIN vulnerabilities v ON v.identifier=a.vulnerability_identifier
                   WHERE a.is_current=1 AND o.style_category=?
                   GROUP BY o.style_subtype ORDER BY vulnerability_count DESC,subtype""",
                (category,),
            ).fetchall()
            example_rows = connection.execute(
                """SELECT o.style_subtype subtype,o.value,
                          COUNT(DISTINCT a.vulnerability_identifier) vulnerability_count
                   FROM semantic_interface_observations o
                   JOIN semantic_analyses a USING(analysis_id)
                   WHERE a.is_current=1 AND o.style_category=?
                   GROUP BY o.style_subtype,o.value
                   ORDER BY o.style_subtype,vulnerability_count DESC,o.value""",
                (category,),
            ).fetchall()
            scope_row = connection.execute(
                """SELECT COUNT(DISTINCT o.value) interface_count,
                          COUNT(DISTINCT a.vulnerability_identifier) vulnerability_count,
                          COUNT(DISTINCT CASE WHEN lower(COALESCE(v.vendor,''))
                            NOT IN ('','n/a','unknown') THEN v.vendor END) vendor_count,
                          COUNT(DISTINCT CASE WHEN lower(COALESCE(v.product,''))
                            NOT IN ('','n/a','unknown') THEN v.product END) model_count
                   FROM semantic_interface_observations o
                   JOIN semantic_analyses a USING(analysis_id)
                   JOIN vulnerabilities v ON v.identifier=a.vulnerability_identifier
                   WHERE a.is_current=1 AND o.style_category=?{}""".format(scoped_clause),
                scoped_values,
            ).fetchone()
            vendor_rows = connection.execute(
                """SELECT v.vendor,COUNT(DISTINCT v.identifier) vulnerability_count,
                          COUNT(DISTINCT v.product) model_count
                   FROM semantic_interface_observations o
                   JOIN semantic_analyses a USING(analysis_id)
                   JOIN vulnerabilities v ON v.identifier=a.vulnerability_identifier
                   WHERE a.is_current=1 AND o.style_category=?{}
                     AND lower(COALESCE(v.vendor,'')) NOT IN ('','n/a','unknown')
                   GROUP BY v.vendor ORDER BY vulnerability_count DESC,v.vendor LIMIT 12""".format(scoped_clause),
                scoped_values,
            ).fetchall()
            firmware_rows = connection.execute(
                """SELECT DISTINCT v.identifier,v.vendor,v.product,v.title,v.summary,v.cpes_json
                   FROM semantic_interface_observations o
                   JOIN semantic_analyses a USING(analysis_id)
                   JOIN vulnerabilities v ON v.identifier=a.vulnerability_identifier
                   WHERE a.is_current=1 AND o.style_category=?{}""".format(scoped_clause),
                scoped_values,
            ).fetchall()
        profile = dict(category_item)
        examples: Dict[str, List[Dict[str, Any]]] = {}
        for row in example_rows:
            bucket = examples.setdefault(row["subtype"] or "", [])
            if len(bucket) < 3:
                bucket.append({
                    "value": row["value"],
                    "vulnerability_count": row["vulnerability_count"],
                })
        profile["subtypes"] = []
        for row in subtype_rows:
            item = interface_subtype_metadata(category, row["subtype"] or "")
            item.update({
                "interface_count": row["interface_count"],
                "vulnerability_count": row["vulnerability_count"],
                "vendor_count": row["vendor_count"],
                "model_count": row["model_count"],
                "examples": examples.get(row["subtype"] or "", []),
            })
            profile["subtypes"].append(item)
        profile["active_subtype"] = (
            interface_subtype_metadata(category, active_subtype)
            if active_subtype else None
        )
        profile.update({
            "scope_interface_count": scope_row["interface_count"],
            "scope_vulnerability_count": scope_row["vulnerability_count"],
            "scope_vendor_count": scope_row["vendor_count"],
            "scope_model_count": scope_row["model_count"],
        })
        profile["top_vendors"] = [dict(row) for row in vendor_rows]
        models: Dict[str, Dict[str, Any]] = {}
        for row in firmware_rows:
            model = normalize_firmware_model(
                row["vendor"] or "", row["product"] or "", row["title"] or "",
                row["summary"] or "", tuple(_loads(row["cpes_json"], [])),
            )
            stored = models.setdefault(model["key"], {**model, "vulnerability_count": 0})
            stored["vulnerability_count"] += 1
        profile["top_models"] = sorted(
            models.values(), key=lambda item: (-item["vulnerability_count"], item["label"])
        )[:12]
        return profile

    def semantic_categories(self) -> Dict[str, Any]:
        metadata = {item["key"]: dict(item) for item in INTERFACE_STYLE_CATEGORIES}
        with self.read_connection() as connection:
            rows = connection.execute(
                """SELECT o.style_category key,COUNT(DISTINCT o.value) interface_count,
                          COUNT(DISTINCT a.vulnerability_identifier) vulnerability_count,
                          COUNT(DISTINCT CASE WHEN lower(COALESCE(v.vendor,''))
                            NOT IN ('','n/a','unknown') THEN v.vendor END) vendor_count,
                          COUNT(DISTINCT CASE WHEN lower(COALESCE(v.product,''))
                            NOT IN ('','n/a','unknown') THEN v.product END) firmware_count,
                          GROUP_CONCAT(DISTINCT CASE WHEN lower(COALESCE(v.vendor,''))
                            NOT IN ('','n/a','unknown') THEN v.vendor END) vendors,
                          MAX(COALESCE(v.published_at,v.modified_at)) latest_at
                   FROM semantic_interface_observations o
                   JOIN semantic_analyses a USING(analysis_id)
                   JOIN vulnerabilities v ON v.identifier=a.vulnerability_identifier
                   WHERE a.is_current=1 AND o.style_category!=''
                   GROUP BY o.style_category ORDER BY vulnerability_count DESC"""
            ).fetchall()
            items = []
            for row in rows:
                item = metadata.get(row["key"], {
                    "key": row["key"], "label": row["key"],
                    "description": "基于接口形态自动归纳的通信入口。", "tone": "slate",
                })
                item.update(dict(row))
                item["vendors"] = [
                    value for value in (row["vendors"] or "").split(",") if value
                ][:5]
                top = connection.execute(
                    """SELECT o.value,COUNT(*) value_count
                       FROM semantic_interface_observations o
                       JOIN semantic_analyses a USING(analysis_id)
                       WHERE a.is_current=1 AND o.style_category=?
                       GROUP BY o.value ORDER BY value_count DESC,o.value LIMIT 5""",
                    (row["key"],),
                ).fetchall()
                item["top_interfaces"] = [dict(value) for value in top]
                items.append(item)
        return {"items": items, "total": len(items)}

    def recommend_interface_structure(
        self, value: str, limit: int = 20, offset: int = 0
    ) -> Dict[str, Any]:
        """Recommend observed interfaces with the same inferred backend structure."""
        raw_value = (value or "").strip()
        if not raw_value:
            raise ValueError("interface value is required")
        if len(raw_value) > 1000:
            raise ValueError("interface value is too long")
        parsed = urlsplit(raw_value)
        normalized = parsed.path or raw_value
        category = classify_interface_style(normalized)
        if not category:
            raise ValueError("interface value does not describe an exposed route")
        architecture = classify_interface_subtype(
            normalized, category=category
        )
        limit = max(1, min(int(limit), 100))
        offset = max(0, int(offset))

        with self.read_connection() as connection:
            observed = bool(connection.execute(
                """SELECT 1 FROM semantic_interface_observations o
                   JOIN semantic_analyses a USING(analysis_id)
                   WHERE a.is_current=1 AND o.value=? LIMIT 1""",
                (normalized,),
            ).fetchone())
            candidate_rows = connection.execute(
                """SELECT o.value,MIN(o.kind) kind,MIN(o.method) method,
                          MIN(o.protocol) protocol,MIN(o.component) component,
                          MIN(o.style_category) category,MIN(o.style_subtype) subtype,
                          COUNT(*) occurrence_count,
                          COUNT(DISTINCT a.vulnerability_identifier) vulnerability_count,
                          COUNT(DISTINCT CASE WHEN lower(COALESCE(v.vendor,''))
                            NOT IN ('','n/a','unknown') THEN v.vendor END) vendor_count,
                          GROUP_CONCAT(DISTINCT CASE WHEN lower(COALESCE(v.vendor,''))
                            NOT IN ('','n/a','unknown') THEN v.vendor END) vendors,
                          MAX(COALESCE(v.published_at,v.modified_at)) latest_at
                   FROM semantic_interface_observations o
                   JOIN semantic_analyses a USING(analysis_id)
                   JOIN vulnerabilities v ON v.identifier=a.vulnerability_identifier
                   WHERE a.is_current=1 AND o.style_category=? AND o.style_subtype=?
                     AND o.value!=?
                   GROUP BY o.value""",
                (category, architecture, normalized),
            ).fetchall()
            vulnerability_rows = connection.execute(
                """SELECT DISTINCT v.identifier,v.title,v.summary,v.vendor,v.product,
                          v.severity,v.cvss_score,v.published_at,v.modified_at
                   FROM semantic_interface_observations o
                   JOIN semantic_analyses a USING(analysis_id)
                   JOIN vulnerabilities v ON v.identifier=a.vulnerability_identifier
                   WHERE a.is_current=1 AND o.style_category=? AND o.style_subtype=?
                   ORDER BY COALESCE(v.cvss_score,0) DESC,
                            COALESCE(v.published_at,v.modified_at,'') DESC LIMIT 8""",
                (category, architecture),
            ).fetchall()

        query_path = normalized.split("?", 1)[0]
        query_prefix = query_path.strip("/").split("/", 1)[0].lower()
        query_depth = len([part for part in query_path.split("/") if part])
        query_extension = query_path.rsplit(".", 1)[-1].lower() if "." in query_path else ""
        candidates: List[Dict[str, Any]] = []
        for row in candidate_rows:
            item = dict(row)
            candidate_path = item["value"].split("?", 1)[0]
            candidate_prefix = candidate_path.strip("/").split("/", 1)[0].lower()
            candidate_depth = len([part for part in candidate_path.split("/") if part])
            candidate_extension = (
                candidate_path.rsplit(".", 1)[-1].lower()
                if "." in candidate_path else ""
            )
            score = 80
            signals = ["后端通信架构风格一致"]
            if query_prefix and query_prefix == candidate_prefix:
                score += 10
                signals.append("入口命名空间一致")
            if query_depth == candidate_depth:
                score += 5
                signals.append("路径层级一致")
            if query_extension and query_extension == candidate_extension:
                score += 5
                signals.append("处理器后缀一致")
            item["similarity_score"] = min(score, 100)
            item["similarity_signals"] = signals
            item["vendors"] = [
                vendor for vendor in (item.get("vendors") or "").split(",") if vendor
            ][:5]
            item["subtype_label"] = interface_subtype_metadata(
                category, architecture
            )["label"]
            candidates.append(item)
        candidates.sort(
            key=lambda item: (
                -item["similarity_score"],
                -item["vulnerability_count"],
                item["value"],
            )
        )
        total = len(candidates)
        result = self._semantic_page(
            candidates[offset : offset + limit], total, limit, offset
        )
        category_metadata = next(
            (dict(item) for item in INTERFACE_STYLE_CATEGORIES if item["key"] == category),
            {"key": category, "label": category, "description": "接口风格关联"},
        )
        profile = self._semantic_category_profile(category, architecture)
        result["selection"] = {
            "value": raw_value,
            "normalized_value": normalized,
            "observed": observed,
            "category": category_metadata,
            "architecture": interface_subtype_metadata(category, architecture),
            "rationale": [
                "先按调用入口形态确定顶层类别",
                "再按路径语法、命名空间和分发形态确定后端架构风格",
                "推荐结果仅表示结构相似，不构成代码同源或组件身份结论",
            ],
        }
        result["related_vendors"] = profile["top_vendors"]
        result["related_firmware"] = profile["top_models"]
        result["related_vulnerabilities"] = [dict(row) for row in vulnerability_rows]
        result["scope"] = {
            "interface_count": profile["scope_interface_count"],
            "vulnerability_count": profile["scope_vulnerability_count"],
            "vendor_count": profile["scope_vendor_count"],
            "model_count": profile["scope_model_count"],
        }
        return result

    def _semantic_associations(
        self, kind: str, value: str, limit: int, offset: int
    ) -> Dict[str, Any]:
        if kind == "interface":
            join = "JOIN semantic_interface_observations o USING(analysis_id)"
            condition = "o.value=?"
            matched = "o.value"
        elif kind == "parameter":
            join = "JOIN semantic_parameter_observations o USING(analysis_id)"
            condition = "o.name=?"
            matched = "o.name"
        else:
            join = "JOIN semantic_interface_observations o USING(analysis_id)"
            condition = "o.style_category=?"
            matched = "o.value"
        with self.read_connection() as connection:
            total = connection.execute(
                """SELECT COUNT(DISTINCT a.vulnerability_identifier)
                   FROM semantic_analyses a {} WHERE a.is_current=1 AND {}""".format(
                    join, condition
                ),
                (value,),
            ).fetchone()[0]
            rows = connection.execute(
                """SELECT v.*,GROUP_CONCAT(DISTINCT {}) matched_values,
                          MAX(o.evidence) semantic_evidence,
                          MAX(o.confidence) semantic_confidence
                   FROM semantic_analyses a {} JOIN vulnerabilities v
                     ON v.identifier=a.vulnerability_identifier
                   WHERE a.is_current=1 AND {}
                   GROUP BY v.identifier
                   ORDER BY COALESCE(v.published_at,v.modified_at,'') DESC,
                            v.identifier DESC LIMIT ? OFFSET ?""".format(
                    matched, join, condition
                ),
                (value, limit, offset),
            ).fetchall()
            if kind == "interface":
                selected = connection.execute(
                    """SELECT value,MIN(kind) kind,MIN(method) method,
                              MIN(protocol) protocol,MIN(component) component,
                              MIN(style_category) category,COUNT(*) occurrence_count
                       FROM semantic_interface_observations o
                       JOIN semantic_analyses a USING(analysis_id)
                       WHERE a.is_current=1 AND o.value=? GROUP BY o.value""",
                    (value,),
                ).fetchone()
                selection = dict(selected) if selected else {"value": value}
            elif kind == "parameter":
                selected = connection.execute(
                    """SELECT p.name value,MIN(p.interface_value) interface_value,
                              MIN(p.location) location,MIN(p.security_effect) security_effect,
                              COALESCE(MAX(i.style_category),'management_route') category,
                              COUNT(*) occurrence_count
                       FROM semantic_parameter_observations p
                       JOIN semantic_analyses a USING(analysis_id)
                       LEFT JOIN semantic_interface_observations i
                         ON i.analysis_id=p.analysis_id AND i.value=p.interface_value
                       WHERE a.is_current=1 AND p.name=? GROUP BY p.name""",
                    (value,),
                ).fetchone()
                selection = dict(selected) if selected else {"value": value}
            else:
                selection = next(
                    (item for item in self.semantic_categories()["items"] if item["key"] == value),
                    {"key": value, "label": value},
                )
        items = [self._serialize_row(row) for row in rows]
        for item in items:
            item["firmware_model"] = normalize_firmware_model(
                item.get("vendor") or "", item.get("product") or "",
                item.get("title") or "", item.get("summary") or "",
                tuple(item.get("cpes") or ()),
            )
        result = self._semantic_page(items, total, limit, offset)
        result["selection"] = selection
        return result

    @staticmethod
    def _semantic_page(
        items: List[Dict[str, Any]], total: int, limit: int, offset: int
    ) -> Dict[str, Any]:
        pages = (total + limit - 1) // limit if total else 0
        return {
            "items": items, "total": total, "limit": limit, "offset": offset,
            "page": offset // limit + 1, "pages": pages,
            "has_previous": offset > 0, "has_next": offset + limit < total,
        }

    def start_semantic_job(self, job_id: str, strategy: str, force: bool, total: int) -> None:
        with self.transaction() as connection:
            connection.execute(
                """INSERT INTO semantic_analysis_jobs(
                       job_id,status,strategy,force,total_count,started_at)
                   VALUES(?,'running',?,?,?,?)""",
                (job_id, strategy, int(force), total, _utc_now()),
            )

    def update_semantic_job(self, job_id: str, **values: Any) -> None:
        allowed = {
            "status", "processed_count", "analyzed_count", "cached_count",
            "failed_count", "interfaces_count", "parameters_count",
            "finished_at", "error",
        }
        items = [(key, value) for key, value in values.items() if key in allowed]
        if not items:
            return
        with self.transaction() as connection:
            connection.execute(
                "UPDATE semantic_analysis_jobs SET {} WHERE job_id=?".format(
                    ",".join("{}=?".format(key) for key, _ in items)
                ),
                [value for _, value in items] + [job_id],
            )

    def latest_semantic_job(self) -> Optional[Dict[str, Any]]:
        with self.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM semantic_analysis_jobs ORDER BY started_at DESC LIMIT 1"
            ).fetchone()
        return dict(row) if row else None

    def fail_interrupted_semantic_jobs(self) -> int:
        with self.transaction() as connection:
            cursor = connection.execute(
                """UPDATE semantic_analysis_jobs SET status='failed',finished_at=?,
                       error=COALESCE(error,'service restarted before analysis completed')
                   WHERE status='running'""",
                (_utc_now(),),
            )
        return cursor.rowcount

    def _get_analytics_cache(self, key: str) -> Optional[Dict[str, Any]]:
        with self.read_connection() as connection:
            row = connection.execute(
                "SELECT value_json FROM analytics_cache WHERE cache_key=?", (key,)
            ).fetchone()
        return _loads(row[0], {}) if row else None

    def _save_analytics_cache(self, key: str, value: Dict[str, Any]) -> None:
        with self.transaction() as connection:
            connection.execute(
                """INSERT INTO analytics_cache(cache_key,value_json,updated_at) VALUES(?,?,?)
                   ON CONFLICT(cache_key) DO UPDATE SET value_json=excluded.value_json,
                       updated_at=excluded.updated_at""",
                (key, _json(value), _utc_now()),
            )

    def get_feed_state(self, feed_name: str) -> Optional[Dict[str, Any]]:
        with self.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM feed_states WHERE feed_name=?", (feed_name,)
            ).fetchone()
        return dict(row) if row else None

    def save_feed_state(
        self,
        feed_name: str,
        last_modified: str,
        sha256: str,
        status: str,
        local_path: Optional[str] = None,
        imported_count: int = 0,
        relevant_count: int = 0,
        error: Optional[str] = None,
    ) -> None:
        now = _utc_now()
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO feed_states(feed_name,last_modified,sha256,local_path,status,
                    imported_count,relevant_count,checked_at,imported_at,error)
                VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(feed_name) DO UPDATE SET last_modified=excluded.last_modified,
                    sha256=excluded.sha256, local_path=excluded.local_path,
                    status=excluded.status, imported_count=excluded.imported_count,
                    relevant_count=excluded.relevant_count, checked_at=excluded.checked_at,
                    imported_at=excluded.imported_at, error=excluded.error
                """,
                (feed_name,last_modified,sha256,local_path,status,imported_count,
                 relevant_count,now,now if status == "imported" else None,error),
            )

    def list_feed_states(self) -> List[Dict[str, Any]]:
        with self.read_connection() as connection:
            rows = connection.execute(
                "SELECT * FROM feed_states ORDER BY feed_name"
            ).fetchall()
        return [dict(row) for row in rows]

    def _fts_available(self) -> bool:
        with self.read_connection() as connection:
            row = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='vulnerabilities_fts'"
            ).fetchone()
        return bool(row)

    def rebuild_fts(self) -> None:
        if not self._fts_available():
            return
        with self.transaction() as connection:
            connection.execute("DELETE FROM vulnerabilities_fts")
            connection.execute(
                """INSERT INTO vulnerabilities_fts(identifier,title,summary,vendor,product)
                   SELECT identifier,title,summary,vendor,product FROM vulnerabilities"""
            )

    def rebuild_cwe_index(self) -> None:
        with self.transaction() as connection:
            connection.execute("DELETE FROM vulnerability_cwes")
            connection.execute(
                """INSERT OR IGNORE INTO vulnerability_cwes(vulnerability_identifier,cwe_id)
                   SELECT v.identifier, CAST(j.value AS TEXT)
                   FROM vulnerabilities v, json_each(v.cwes_json) j"""
            )

    def start_sync_run(self, run_id: str, sources: Sequence[str]) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO sync_runs(run_id, sources_json, status, started_at)
                VALUES(?, ?, 'running', ?)
                """,
                (run_id, _json(sources), _utc_now()),
            )

    def finish_sync_run(
        self,
        run_id: str,
        status: str,
        fetched_count: int,
        relevant_count: int,
        error: Optional[str] = None,
    ) -> None:
        with self.transaction() as connection:
            connection.execute(
                """
                UPDATE sync_runs SET status=?, finished_at=?, fetched_count=?,
                    relevant_count=?, error=? WHERE run_id=?
                """,
                (status, _utc_now(), fetched_count, relevant_count, error, run_id),
            )

    def latest_sync_run(self) -> Optional[Dict[str, Any]]:
        with self.read_connection() as connection:
            row = connection.execute(
                "SELECT * FROM sync_runs ORDER BY started_at DESC LIMIT 1"
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        result["sources"] = _loads(result.pop("sources_json"), [])
        return result

    def fail_interrupted_sync_runs(self) -> int:
        with self.transaction() as connection:
            cursor = connection.execute(
                """UPDATE sync_runs SET status='failed', finished_at=?,
                       error=COALESCE(error, 'service restarted before sync completed')
                   WHERE status='running'""",
                (_utc_now(),),
            )
        return cursor.rowcount

    def _merge(
        self, existing: Optional[sqlite3.Row], incoming: VulnerabilityRecord
    ) -> VulnerabilityRecord:
        if not existing:
            return replace(
                incoming,
                vendor=incoming.vendor if is_meaningful_identity(incoming.vendor) else None,
                product=incoming.product if is_meaningful_identity(incoming.product) else None,
                raw={"sources": (incoming.source,)},
            )
        current = self._row_to_record(existing)
        existing_sources = tuple(_loads(existing["sources_json"], []))
        sources = tuple(dict.fromkeys(existing_sources + (incoming.source,)))
        prefer_incoming_text = incoming.source == "cisa-kev" or not current.summary
        return VulnerabilityRecord(
            identifier=incoming.identifier,
            source=incoming.source,
            source_identifier=incoming.source_identifier,
            title=incoming.title if prefer_incoming_text else current.title,
            summary=incoming.summary if prefer_incoming_text else current.summary,
            published_at=current.published_at or incoming.published_at,
            modified_at=max(
                filter(None, (current.modified_at, incoming.modified_at)), default=None
            ),
            vendor=(
                incoming.vendor if is_meaningful_identity(incoming.vendor)
                else current.vendor if is_meaningful_identity(current.vendor)
                else None
            ),
            product=(
                incoming.product if is_meaningful_identity(incoming.product)
                else current.product if is_meaningful_identity(current.product)
                else None
            ),
            severity=incoming.severity or current.severity,
            cvss_score=(
                incoming.cvss_score
                if incoming.cvss_score is not None
                else current.cvss_score
            ),
            cvss_vector=incoming.cvss_vector or current.cvss_vector,
            cvss_version=incoming.cvss_version or current.cvss_version,
            impact_score=incoming.impact_score if incoming.impact_score is not None else current.impact_score,
            exploitability_score=incoming.exploitability_score if incoming.exploitability_score is not None else current.exploitability_score,
            attack_vector=incoming.attack_vector or current.attack_vector,
            attack_complexity=incoming.attack_complexity or current.attack_complexity,
            privileges_required=incoming.privileges_required or current.privileges_required,
            user_interaction=incoming.user_interaction or current.user_interaction,
            scope=incoming.scope or current.scope,
            cvss_metrics=incoming.cvss_metrics or current.cvss_metrics,
            aliases=tuple(dict.fromkeys(current.aliases + incoming.aliases)),
            cwes=tuple(dict.fromkeys(current.cwes + incoming.cwes)),
            cpes=tuple(dict.fromkeys(current.cpes + incoming.cpes)),
            references=tuple(
                dict.fromkeys(current.references + incoming.references)
            ),
            reference_details=incoming.reference_details or current.reference_details,
            exploit_references=tuple(dict.fromkeys(current.exploit_references + incoming.exploit_references)),
            cwe_details=incoming.cwe_details or current.cwe_details,
            affected_products=incoming.affected_products or current.affected_products,
            kev=current.kev or incoming.kev,
            kev_date_added=incoming.kev_date_added or current.kev_date_added,
            kev_due_date=incoming.kev_due_date or current.kev_due_date,
            ransomware_use=incoming.ransomware_use or current.ransomware_use,
            required_action=incoming.required_action or current.required_action,
            raw={"sources": sources},
        )

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> VulnerabilityRecord:
        sources = tuple(_loads(row["sources_json"], []))
        return VulnerabilityRecord(
            identifier=row["identifier"],
            source=sources[0] if sources else "stored",
            source_identifier=row["identifier"],
            title=row["title"],
            summary=row["summary"],
            published_at=row["published_at"],
            modified_at=row["modified_at"],
            vendor=row["vendor"],
            product=row["product"],
            severity=row["severity"],
            cvss_score=row["cvss_score"],
            cvss_vector=row["cvss_vector"],
            cvss_version=row["cvss_version"],
            impact_score=row["impact_score"],
            exploitability_score=row["exploitability_score"],
            attack_vector=row["attack_vector"],
            attack_complexity=row["attack_complexity"],
            privileges_required=row["privileges_required"],
            user_interaction=row["user_interaction"],
            scope=row["scope"],
            cvss_metrics=tuple(_loads(row["cvss_metrics_json"], [])),
            aliases=tuple(_loads(row["aliases_json"], [])),
            cwes=tuple(_loads(row["cwes_json"], [])),
            cpes=tuple(_loads(row["cpes_json"], [])),
            references=tuple(_loads(row["references_json"], [])),
            reference_details=tuple(_loads(row["reference_details_json"], [])),
            exploit_references=tuple(_loads(row["exploit_references_json"], [])),
            cwe_details=tuple(_loads(row["cwe_details_json"], [])),
            affected_products=tuple(_loads(row["affected_products_json"], [])),
            kev=bool(row["kev"]),
            kev_date_added=row["kev_date_added"],
            kev_due_date=row["kev_due_date"],
            ransomware_use=row["ransomware_use"],
            required_action=row["required_action"],
            raw={"sources": sources},
        )

    @staticmethod
    def _serialize_row(row: sqlite3.Row) -> Dict[str, Any]:
        result = dict(row)
        for key in (
            "aliases_json",
            "cwes_json",
            "cpes_json",
            "references_json",
            "sources_json",
            "relevance_signals_json",
            "cvss_metrics_json",
            "reference_details_json",
            "exploit_references_json",
            "cwe_details_json",
            "affected_products_json",
        ):
            result[key[:-5]] = _loads(result.pop(key), [])
        result["kev"] = bool(result["kev"])
        result["has_exploit"] = bool(result["has_exploit"])
        result["is_firmware_related"] = result["relevance_level"] in (
            "strong",
            "likely",
        )
        return result
