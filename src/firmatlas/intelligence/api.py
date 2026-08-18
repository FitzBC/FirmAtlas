"""HTTP adapter for the intelligence application service."""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
import mimetypes
from pathlib import Path
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, unquote, urlparse

from firmatlas.mapping.repository import (
    CommunicationGraphQuery,
    DiscoveryCatalogRepository,
    HistoricalCoverageLedgerQuery,
    HistoricalGraphOverlayQuery,
)
from firmatlas.mapping.job_service import (
    FirmwareMappingJobService,
    FirmwareMappingRuntimeConfig,
    create_container_firmware_mapping_job_service,
)
from firmatlas.mapping.reasoning import (
    MappingReasoningRunStore,
    MappingReasoningService,
    MiniMaxReasonerAdapter,
    MiniMaxReasonerConfig,
)

from .repository import IntelligenceRepository
from .service import IntelligenceService, SyncAlreadyRunning
from .semantic_service import (
    SemanticAnalysisAlreadyRunning,
    SemanticAnalysisService,
)


LOGGER = logging.getLogger("firmatlas.api")


class ApiError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def create_handler(
    service: IntelligenceService,
    semantic_service: SemanticAnalysisService = None,
    static_dir: str = None,
    mapping_repository: DiscoveryCatalogRepository = None,
    mapping_job_service: FirmwareMappingJobService = None,
    mapping_reasoning_service: MappingReasoningService = None,
):
    semantic = semantic_service or SemanticAnalysisService(service.repository)
    mappings = mapping_repository or service.repository.mapping_catalogs
    static_root = Path(static_dir).resolve() if static_dir else None

    class IntelligenceHandler(BaseHTTPRequestHandler):
        server_version = "FirmAtlas/0.1"

        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_POST(self) -> None:
            self._dispatch("POST")

        def do_PUT(self) -> None:
            self._dispatch("PUT")

        def do_OPTIONS(self) -> None:
            self.send_response(HTTPStatus.NO_CONTENT)
            self._cors_headers()
            self.end_headers()

        def _dispatch(self, method: str) -> None:
            request_id = self.headers.get("X-Request-ID", "-")
            try:
                if method == "GET" and static_root and not urlparse(self.path).path.startswith("/api/"):
                    self._serve_static(static_root)
                    return
                status, payload = self._route(method)
                self._send_json(status, {"data": payload, "request_id": request_id})
            except (BrokenPipeError, ConnectionResetError):
                LOGGER.info("client disconnected before response completed")
            except ApiError as error:
                self._send_json(
                    error.status, {"error": str(error), "request_id": request_id}
                )
            except (ValueError, json.JSONDecodeError) as error:
                self._send_json(
                    HTTPStatus.BAD_REQUEST,
                    {"error": str(error), "request_id": request_id},
                )
            except Exception:
                LOGGER.exception("unhandled request error")
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": "internal server error", "request_id": request_id},
                )

        def _serve_static(self, root: Path) -> None:
            requested_path = unquote(urlparse(self.path).path).lstrip("/")
            candidate = (root / (requested_path or "index.html")).resolve()
            try:
                candidate.relative_to(root)
            except ValueError:
                raise ApiError(HTTPStatus.NOT_FOUND, "route not found")

            if not candidate.is_file():
                candidate = root / "index.html"
            if not candidate.is_file():
                raise ApiError(HTTPStatus.NOT_FOUND, "route not found")

            encoded = candidate.read_bytes()
            content_type = mimetypes.guess_type(str(candidate))[0] or "application/octet-stream"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header(
                "Cache-Control",
                "no-cache" if candidate.name == "index.html" else "public, max-age=31536000, immutable",
            )
            self.end_headers()
            self.wfile.write(encoded)

        def _route(self, method: str) -> Tuple[int, Any]:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query)
            if method == "GET" and path == "/api/health":
                return HTTPStatus.OK, {"status": "ok"}
            if method == "GET" and path == "/api/mappings/catalogs":
                page_size = max(1, min(_integer(query, "page_size", 30), 100))
                page = max(1, _integer(query, "page", 1))
                return HTTPStatus.OK, mappings.list_catalogs(
                    limit=page_size, offset=(page - 1) * page_size,
                )
            if method == "GET" and path == "/api/mappings/jobs":
                return HTTPStatus.OK, {
                    "enabled": mapping_job_service is not None,
                    "max_upload_bytes": (
                        mapping_job_service.max_upload_bytes
                        if mapping_job_service is not None else 0
                    ),
                    "items": [
                        item.to_dict() for item in (
                            mapping_job_service.list(limit=20)
                            if mapping_job_service is not None else ()
                        )
                    ],
                }
            if method == "POST" and path == "/api/mappings/jobs":
                if mapping_job_service is None:
                    raise ApiError(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        "firmware mapping jobs are not configured",
                    )
                if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/octet-stream":
                    raise ApiError(
                        HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                        "firmware artifact upload must be application/octet-stream",
                    )
                try:
                    content_length = int(self.headers.get("Content-Length", ""))
                except ValueError:
                    raise ApiError(
                        HTTPStatus.LENGTH_REQUIRED,
                        "firmware artifact upload requires Content-Length",
                    )
                if content_length > mapping_job_service.max_upload_bytes:
                    raise ApiError(
                        HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                        "firmware artifact upload exceeds size budget",
                    )
                snapshot = mapping_job_service.submit(
                    self.rfile,
                    unquote(self.headers.get("X-Firmware-Filename", "")),
                    content_length,
                )
                return HTTPStatus.ACCEPTED, snapshot.to_dict()
            mapping_job_prefix = "/api/mappings/jobs/"
            if method == "GET" and path.startswith(mapping_job_prefix):
                if mapping_job_service is None:
                    raise ApiError(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        "firmware mapping jobs are not configured",
                    )
                snapshot = mapping_job_service.get(
                    unquote(path[len(mapping_job_prefix):])
                )
                if snapshot is None:
                    raise ApiError(HTTPStatus.NOT_FOUND, "firmware mapping job not found")
                return HTTPStatus.OK, snapshot.to_dict()
            if method == "GET" and path == "/api/mappings/potential-hidden-interfaces":
                page_size = max(1, min(_integer(query, "page_size", 100), 200))
                page = max(1, _integer(query, "page", 1))
                return HTTPStatus.OK, mappings.query_potential_hidden_interfaces(
                    query=_one(query, "q"),
                    firmware_sha256=_one(query, "firmware"),
                    limit=page_size,
                    offset=(page - 1) * page_size,
                )
            if method == "GET" and path == "/api/mappings/compare":
                result = mappings.compare_catalogs(
                    _one(query, "base"), _one(query, "target")
                )
                if result is None:
                    raise ApiError(
                        HTTPStatus.NOT_FOUND,
                        "base or target mapping catalog not found",
                    )
                return HTTPStatus.OK, result
            mapping_reasoning_prefix = "/api/mappings/catalogs/"
            mapping_reasoning_suffix = "/reasoning"
            if (
                path.startswith(mapping_reasoning_prefix)
                and path.endswith(mapping_reasoning_suffix)
            ):
                catalog_id = unquote(
                    path[
                        len(mapping_reasoning_prefix):-len(mapping_reasoning_suffix)
                    ].rstrip("/")
                )
                if not catalog_id:
                    raise ApiError(HTTPStatus.NOT_FOUND, "mapping catalog not found")
                if method == "GET":
                    latest = (
                        mapping_reasoning_service.latest(catalog_id)
                        if mapping_reasoning_service is not None else None
                    )
                    return HTTPStatus.OK, {
                        "enabled": mapping_reasoning_service is not None,
                        "adapter_id": (
                            mapping_reasoning_service.adapter_id
                            if mapping_reasoning_service is not None else None
                        ),
                        "latest": latest.to_dict() if latest is not None else None,
                    }
                if method == "POST":
                    self._body()
                    if mapping_reasoning_service is None:
                        raise ApiError(
                            HTTPStatus.SERVICE_UNAVAILABLE,
                            "mapping reasoning is not configured",
                        )
                    try:
                        run = mapping_reasoning_service.submit(catalog_id)
                    except KeyError:
                        raise ApiError(
                            HTTPStatus.NOT_FOUND, "mapping catalog not found",
                        )
                    return HTTPStatus.ACCEPTED, run.to_dict()
            if method == "GET" and path == "/api/mappings/graphs":
                page_size = max(1, min(_integer(query, "page_size", 30), 100))
                page = max(1, _integer(query, "page", 1))
                return HTTPStatus.OK, mappings.list_communication_graphs(
                    limit=page_size, offset=(page - 1) * page_size,
                )
            graph_prefix = "/api/mappings/graphs/"
            if method == "GET" and path.startswith(graph_prefix):
                graph_remainder = path[len(graph_prefix):]
                graph_segment, coverage_separator, coverage_nested = (
                    graph_remainder.partition("/historical-coverage")
                )
                if coverage_separator:
                    if coverage_nested:
                        raise ApiError(HTTPStatus.NOT_FOUND, "route not found")
                    result = mappings.query_historical_coverage_ledger(
                        unquote(graph_segment),
                        HistoricalCoverageLedgerQuery(
                            text=_one(query, "q"),
                            statuses=_many(query, "status"),
                            audit_categories=_many(query, "audit_category"),
                            evidence_states=_many(query, "evidence_state"),
                        ),
                    )
                    if result is None:
                        raise ApiError(
                            HTTPStatus.NOT_FOUND,
                            "historical coverage ledger not found",
                        )
                    return HTTPStatus.OK, result
                graph_segment, overlay_separator, overlay_nested = (
                    graph_remainder.partition("/historical-overlay")
                )
                graph_id = unquote(graph_segment)
                if overlay_separator:
                    if overlay_nested:
                        raise ApiError(HTTPStatus.NOT_FOUND, "route not found")
                    result = mappings.query_historical_graph_overlay(
                        graph_id,
                        HistoricalGraphOverlayQuery(
                            text=_one(query, "q"),
                            statuses=_many(query, "status"),
                            applicabilities=_many(query, "applicability"),
                            gap_reasons=_many(query, "gap_reason"),
                            route_binding_statuses=_many(
                                query, "route_binding_status"
                            ),
                        ),
                    )
                    if result is None:
                        raise ApiError(
                            HTTPStatus.NOT_FOUND,
                            "historical graph overlay not found",
                        )
                    return HTTPStatus.OK, result
                result = mappings.query_communication_graph(
                    graph_id,
                    CommunicationGraphQuery(
                        text=_one(query, "q"),
                        preset_id=_one(query, "preset"),
                        node_kinds=_many(query, "node_kind"),
                        edge_kinds=_many(query, "edge_kind"),
                        statuses=_many(query, "status"),
                        evidence_id=_one(query, "evidence_id"),
                        focus_node_ids=_many(query, "focus_node"),
                        focus_canonical_identities=_many(
                            query, "focus_identity"
                        ),
                        max_hops=_integer(query, "max_hops", 2),
                        max_nodes=_integer(query, "max_nodes", 500),
                        max_edges=_integer(query, "max_edges", 1_000),
                    ),
                )
                if result is None:
                    raise ApiError(
                        HTTPStatus.NOT_FOUND,
                        "communication graph not found",
                    )
                return HTTPStatus.OK, result
            mapping_prefix = "/api/mappings/catalogs/"
            if method == "GET" and path.startswith(mapping_prefix):
                remainder = path[len(mapping_prefix):]
                catalog_segment, separator, nested = remainder.partition("/candidates")
                catalog_id = unquote(catalog_segment.rstrip("/"))
                if separator and nested:
                    candidate = mappings.get_candidate(
                        catalog_id, unquote(nested.lstrip("/"))
                    )
                    if not candidate:
                        raise ApiError(HTTPStatus.NOT_FOUND, "mapping candidate not found")
                    return HTTPStatus.OK, candidate
                if separator:
                    page_size = max(1, min(_integer(query, "page_size", 30), 100))
                    page = max(1, _integer(query, "page", 1))
                    if not mappings.get_catalog(catalog_id):
                        raise ApiError(HTTPStatus.NOT_FOUND, "mapping catalog not found")
                    return HTTPStatus.OK, mappings.query_candidates(
                        catalog_id, query=_one(query, "q"),
                        candidate_kind=_one(query, "kind"), limit=page_size,
                        offset=(page - 1) * page_size,
                    )
                catalog = mappings.get_catalog(catalog_id)
                if not catalog:
                    raise ApiError(HTTPStatus.NOT_FOUND, "mapping catalog not found")
                return HTTPStatus.OK, catalog
            if method == "GET" and path == "/api/intelligence/overview":
                return HTTPStatus.OK, service.repository.overview()
            if method == "GET" and path == "/api/intelligence/statistics":
                return HTTPStatus.OK, service.repository.statistics()
            if method == "GET" and path == "/api/firmware/overview":
                return HTTPStatus.OK, service.repository.firmware_catalog_overview()
            if method == "GET" and path == "/api/firmware/sources":
                return HTTPStatus.OK, {
                    "items": service.repository.list_firmware_sources()
                }
            if method == "GET" and path == "/api/firmware/candidates":
                page_size = max(1, min(_integer(query, "page_size", 30), 100))
                page = max(1, _integer(query, "page", 1))
                return HTTPStatus.OK, service.repository.list_firmware_candidates(
                    query=_one(query, "q"),
                    vendor=_one(query, "vendor"),
                    source_id=_one(query, "source"),
                    download_host=_one(query, "host"),
                    has_vulnerability=_one(query, "has_vulnerability") == "true",
                    match_method=_one(query, "match"),
                    limit=page_size,
                    offset=(page - 1) * page_size,
                )
            firmware_vulnerability_prefix = "/api/firmware/vulnerabilities/"
            if (
                method == "GET"
                and path.startswith(firmware_vulnerability_prefix)
                and path.endswith("/samples")
            ):
                identifier = unquote(
                    path[len(firmware_vulnerability_prefix) : -len("/samples")]
                ).rstrip("/")
                sample_size = max(1, min(_integer(query, "page_size", 50), 100))
                sample_page = max(1, _integer(query, "page", 1))
                return HTTPStatus.OK, service.repository.firmware_candidates_for_vulnerability(
                    identifier, limit=sample_size,
                    offset=(sample_page - 1) * sample_size,
                )
            firmware_candidate_prefix = "/api/firmware/candidates/"
            if method == "GET" and path.startswith(firmware_candidate_prefix):
                candidate = service.repository.get_firmware_candidate(
                    unquote(path[len(firmware_candidate_prefix) :])
                )
                if not candidate:
                    raise ApiError(HTTPStatus.NOT_FOUND, "firmware candidate not found")
                return HTTPStatus.OK, candidate
            if method == "GET" and path == "/api/intelligence/feeds":
                return HTTPStatus.OK, service.repository.list_feed_states()
            if method == "GET" and path == "/api/intelligence/semantic/settings":
                return HTTPStatus.OK, semantic.get_settings()
            if method == "PUT" and path == "/api/intelligence/semantic/settings":
                return HTTPStatus.OK, semantic.update_settings(self._body())
            if method == "POST" and path == "/api/intelligence/semantic/settings/test":
                return HTTPStatus.OK, semantic.test_model(self._body())
            if method == "GET" and path == "/api/intelligence/semantic/overview":
                return HTTPStatus.OK, semantic.overview()
            if method == "GET" and path == "/api/intelligence/semantic/categories":
                return HTTPStatus.OK, service.repository.semantic_categories()
            if method == "GET" and path == "/api/intelligence/semantic/interface-recommendation":
                recommend_size = max(1, min(_integer(query, "page_size", 20), 100))
                recommend_page = max(1, _integer(query, "page", 1))
                try:
                    return HTTPStatus.OK, service.repository.recommend_interface_structure(
                        value=_one(query, "value"),
                        limit=recommend_size,
                        offset=(recommend_page - 1) * recommend_size,
                    )
                except ValueError as error:
                    raise ApiError(HTTPStatus.BAD_REQUEST, str(error))
            if method == "GET" and path == "/api/intelligence/semantic/explore":
                explore_size = max(1, min(_integer(query, "page_size", 25), 100))
                explore_page = max(1, _integer(query, "page", 1))
                try:
                    return HTTPStatus.OK, service.repository.semantic_explore(
                        kind=_one(query, "kind", "interface"),
                        value=_one(query, "value"),
                        query=_one(query, "q"),
                        subtype=_one(query, "subtype"),
                        limit=explore_size,
                        offset=(explore_page - 1) * explore_size,
                    )
                except ValueError as error:
                    raise ApiError(HTTPStatus.BAD_REQUEST, str(error))
            if method == "GET" and path == "/api/intelligence/semantic/jobs/latest":
                return HTTPStatus.OK, semantic.latest_job()
            if method == "POST" and path == "/api/intelligence/semantic/jobs":
                body = self._body()
                try:
                    request_id = semantic.start_batch(
                        bool(body.get("force", False)),
                        use_llm=body.get("use_llm") is True,
                    )
                except SemanticAnalysisAlreadyRunning as error:
                    raise ApiError(HTTPStatus.CONFLICT, str(error))
                return HTTPStatus.ACCEPTED, {
                    "request_id": request_id, "status": "accepted"
                }
            if method == "GET" and path == "/api/intelligence/vulnerabilities":
                page_size = _integer(
                    query, "page_size", _integer(query, "limit", 50)
                )
                requested_page = _integer(query, "page", 0)
                return HTTPStatus.OK, service.repository.list(
                    query=_one(query, "q"),
                    severity=_one(query, "severity"),
                    source=_one(query, "source"),
                    vendor=_one(query, "vendor"),
                    relevance=_one(query, "relevance", "firmware"),
                    kev_only=_one(query, "kev") == "true",
                    exploit_only=_one(query, "exploit") == "true",
                    cwe=_one(query, "cwe"),
                    limit=page_size,
                    offset=(requested_page - 1) * page_size
                    if requested_page > 0 else _integer(query, "offset", 0),
                )
            prefix = "/api/intelligence/vulnerabilities/"
            semantic_suffix = "/semantic-analysis"
            if path.startswith(prefix) and path.endswith(semantic_suffix):
                identifier = unquote(path[len(prefix) : -len(semantic_suffix)]).rstrip("/")
                if method == "GET":
                    return HTTPStatus.OK, service.repository.get_semantic_analysis(identifier)
                if method == "POST":
                    try:
                        return HTTPStatus.OK, semantic.analyze_identifier(
                            identifier, bool(self._body().get("force", False))
                        )
                    except KeyError:
                        raise ApiError(HTTPStatus.NOT_FOUND, "vulnerability not found")
            if method == "GET" and path.startswith(prefix):
                item = service.repository.get(unquote(path[len(prefix) :]))
                if not item:
                    raise ApiError(HTTPStatus.NOT_FOUND, "vulnerability not found")
                return HTTPStatus.OK, item
            if method == "GET" and path == "/api/intelligence/sync/latest":
                return HTTPStatus.OK, service.repository.latest_sync_run()
            if method == "POST" and path == "/api/intelligence/sync":
                body = self._body()
                try:
                    sync_request_id = service.start_sync(
                        body.get("sources", ["nvd", "cisa-kev"]),
                        body.get("days", 1),
                    )
                except SyncAlreadyRunning as error:
                    raise ApiError(HTTPStatus.CONFLICT, str(error))
                return HTTPStatus.ACCEPTED, {
                    "request_id": sync_request_id,
                    "status": "accepted",
                }
            if method == "GET" and path == "/api/intelligence/settings":
                return HTTPStatus.OK, service.repository.get_policy().to_dict()
            if method == "PUT" and path == "/api/intelligence/settings":
                return HTTPStatus.OK, service.update_policy(self._body())
            raise ApiError(HTTPStatus.NOT_FOUND, "route not found")

        def _body(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 1024 * 1024:
                raise ApiError(
                    HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request body too large"
                )
            if length == 0:
                return {}
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("JSON body must be an object")
            return payload

        def _send_json(self, status: int, payload: Dict[str, Any]) -> None:
            encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self._cors_headers()
            self.end_headers()
            self.wfile.write(encoded)

        def _cors_headers(self) -> None:
            origin = self.headers.get("Origin")
            if origin in ("http://localhost:5173", "http://127.0.0.1:5173"):
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
                self.send_header(
                    "Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS"
                )
                self.send_header(
                    "Access-Control-Allow-Headers",
                    "Content-Type, X-Request-ID, X-Firmware-Filename",
                )

        def log_message(self, format: str, *args: Any) -> None:
            LOGGER.info("%s - %s", self.address_string(), format % args)

    return IntelligenceHandler


def serve(
    database: str,
    host: str = "127.0.0.1",
    port: int = 8787,
    static_dir: str = None,
    mapping_runtime_config: FirmwareMappingRuntimeConfig = None,
    mapping_reasoning_config: MiniMaxReasonerConfig = None,
) -> None:
    repository = IntelligenceRepository(database)
    service = IntelligenceService(repository)
    mapping_jobs = (
        create_container_firmware_mapping_job_service(
            database, repository.mapping_catalogs, mapping_runtime_config,
        )
        if mapping_runtime_config is not None else None
    )
    mapping_reasoning = (
        MappingReasoningService(
            repository.mapping_catalogs,
            MappingReasoningRunStore(database),
            MiniMaxReasonerAdapter(mapping_reasoning_config),
        )
        if mapping_reasoning_config is not None else None
    )
    server = ThreadingHTTPServer(
        (host, port), create_handler(
            service, static_dir=static_dir, mapping_job_service=mapping_jobs,
            mapping_reasoning_service=mapping_reasoning,
        )
    )
    LOGGER.info("FirmAtlas API listening on http://%s:%s", host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if mapping_jobs is not None:
            mapping_jobs.close()
        if mapping_reasoning is not None:
            mapping_reasoning.close()
        repository.close()


def _one(query: Dict[str, Any], name: str, default: str = "") -> str:
    values = query.get(name)
    return str(values[0]) if values else default


def _integer(query: Dict[str, Any], name: str, default: int) -> int:
    try:
        return int(_one(query, name, str(default)))
    except ValueError:
        raise ValueError("{} must be an integer".format(name))


def _many(query: Dict[str, Any], name: str) -> tuple:
    return tuple(str(value) for value in query.get(name, ()))
