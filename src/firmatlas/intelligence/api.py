"""HTTP adapter for the intelligence application service."""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, unquote, urlparse

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
):
    semantic = semantic_service or SemanticAnalysisService(service.repository)

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
            except BaseException:
                LOGGER.exception("unhandled request error")
                self._send_json(
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                    {"error": "internal server error", "request_id": request_id},
                )

        def _route(self, method: str) -> Tuple[int, Any]:
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/") or "/"
            query = parse_qs(parsed.query)
            if method == "GET" and path == "/api/health":
                return HTTPStatus.OK, {"status": "ok"}
            if method == "GET" and path == "/api/intelligence/overview":
                return HTTPStatus.OK, service.repository.overview()
            if method == "GET" and path == "/api/intelligence/statistics":
                return HTTPStatus.OK, service.repository.statistics()
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
                    "Access-Control-Allow-Headers", "Content-Type, X-Request-ID"
                )

        def log_message(self, format: str, *args: Any) -> None:
            LOGGER.info("%s - %s", self.address_string(), format % args)

    return IntelligenceHandler


def serve(database: str, host: str = "127.0.0.1", port: int = 8787) -> None:
    repository = IntelligenceRepository(database)
    service = IntelligenceService(repository)
    server = ThreadingHTTPServer((host, port), create_handler(service))
    LOGGER.info("FirmAtlas API listening on http://%s:%s", host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        repository.close()


def _one(query: Dict[str, Any], name: str, default: str = "") -> str:
    values = query.get(name)
    return str(values[0]) if values else default


def _integer(query: Dict[str, Any], name: str, default: int) -> int:
    try:
        return int(_one(query, name, str(default)))
    except ValueError:
        raise ValueError("{} must be an integer".format(name))
