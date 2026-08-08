"""Deterministic frontend request evidence producer."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
from html.parser import HTMLParser
import json
import re
from typing import Optional, Tuple

from .domain import (
    AnalyzerIdentity,
    CoverageStatus,
    EvidenceAtom,
    ObservationKind,
    SpanKind,
)
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry


FRONTEND_RESULT_SCHEMA_VERSION = "firmatlas.mapping.frontend-result/v1alpha1"
_PRODUCER = AnalyzerIdentity(name="frontend-request-producer", version="0.1.0")
_SUPPORTED_CONSTRUCTS = (
    "R.pageModel",
    "R.moduleModel.getSubmitData",
    "jQuery.getJSON",
    "jQuery.post",
    "jQuery.ajax",
    "HTML.form",
)


class FrontendRequestRole(str, Enum):
    READ = "read"
    WRITE = "write"
    UNSPECIFIED = "unspecified"


class FrontendEndpointShape(str, Enum):
    EXACT_LITERAL = "exact_literal"
    LITERAL_PREFIX = "literal_prefix"


class FrontendParameterNamespace(str, Enum):
    QUERY = "query"
    FORM = "form"
    JSON = "json"
    HEADER = "header"


class FrontendParameterDirection(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"


@dataclass(frozen=True)
class FrontendPolicy:
    max_source_bytes: int = 8 * 1024 * 1024
    max_candidates: int = 10_000

    def __post_init__(self) -> None:
        if self.max_source_bytes <= 0 or self.max_candidates <= 0:
            raise ValueError("frontend producer limits must be positive")


@dataclass(frozen=True)
class FrontendRequestCandidate:
    candidate_id: str
    endpoint: str
    endpoint_shape: FrontendEndpointShape
    request_role: FrontendRequestRole
    method: Optional[str]
    representation: Optional[str]
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class FrontendParameterCandidate:
    parameter_id: str
    request_candidate_id: str
    name: str
    namespace: FrontendParameterNamespace
    direction: FrontendParameterDirection
    literal_value: Optional[str]
    is_operation_selector: bool
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class FrontendDiagnostic:
    code: str
    message: str


@dataclass(frozen=True)
class _Token:
    kind: str
    value: bytes
    start: int
    end: int


@dataclass(frozen=True)
class _ParameterLiteral:
    name: str
    name_start: int
    name_end: int
    namespace: FrontendParameterNamespace
    literal_value: Optional[str]
    value_start: Optional[int]
    value_end: Optional[int]
    is_operation_selector: bool
    source_construct: str


class _HtmlFormParser(HTMLParser):
    def __init__(self, text: str):
        super().__init__(convert_charrefs=False)
        self._text = text
        self._cursor = 0
        self._current = None
        self.requests = []

    def _start_tag_location(self) -> tuple:
        raw = self.get_starttag_text()
        char_start = self._text.find(raw, self._cursor)
        if char_start < 0:
            char_start = self._text.find(raw)
        self._cursor = max(self._cursor, char_start + len(raw))
        return raw, char_start

    def _attribute(self, raw: str, char_start: int, name: str) -> tuple:
        match = re.search(
            r"\b{}\s*=\s*([\"'])(.*?)\1".format(re.escape(name)),
            raw,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if match is None:
            return None
        value_start_character = char_start + match.start(2)
        value_end_character = char_start + match.end(2)
        return (
            match.group(2),
            len(self._text[:value_start_character].encode("utf-8")),
            len(self._text[:value_end_character].encode("utf-8")),
        )

    def handle_starttag(self, tag: str, attrs: list) -> None:
        raw, char_start = self._start_tag_location()
        if tag.lower() == "form":
            action = self._attribute(raw, char_start, "action")
            if action is None:
                return
            attributes = {name.lower(): value for name, value in attrs}
            method = (attributes.get("method") or "GET").upper()
            enctype = (attributes.get("enctype") or "").lower()
            representation = (
                "multipart_form"
                if enctype == "multipart/form-data"
                else "form_urlencoded"
            )
            self._current = {
                "endpoint": action[0],
                "start": action[1],
                "end": action[2],
                "method": method,
                "representation": representation,
                "parameters": [],
            }
            return
        if tag.lower() == "input" and self._current is not None:
            name = self._attribute(raw, char_start, "name")
            if name is not None:
                self._current["parameters"].append(
                    _ParameterLiteral(
                        name=name[0],
                        name_start=name[1],
                        name_end=name[2],
                        namespace=FrontendParameterNamespace.FORM,
                        literal_value=None,
                        value_start=None,
                        value_end=None,
                        is_operation_selector=False,
                        source_construct="HTML.input",
                    )
                )

    def handle_startendtag(self, tag: str, attrs: list) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self._current is None:
            return
        method = self._current["method"]
        role = (
            FrontendRequestRole.READ
            if method == "GET"
            else FrontendRequestRole.WRITE
        )
        self.requests.append(
            (
                self._current["endpoint"],
                self._current["start"],
                self._current["end"],
                role,
                method,
                self._current["representation"],
                tuple(self._current["parameters"]),
            )
        )
        self._current = None


@dataclass(frozen=True)
class FrontendProducerResult:
    source_path: str
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    candidates: Tuple[FrontendRequestCandidate, ...]
    parameters: Tuple[FrontendParameterCandidate, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[FrontendDiagnostic, ...] = ()
    supported_constructs: Tuple[str, ...] = _SUPPORTED_CONSTRUCTS
    schema_version: str = FRONTEND_RESULT_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "source_path": self.source_path,
            "coverage_status": self.coverage_status.value,
            "processed_bytes": self.processed_bytes,
            "producer": asdict(self.producer),
            "candidates": [
                {
                    **asdict(item),
                    "request_role": item.request_role.value,
                    "endpoint_shape": item.endpoint_shape.value,
                }
                for item in self.candidates
            ],
            "parameters": [
                {
                    **asdict(item),
                    "namespace": item.namespace.value,
                    "direction": item.direction.value,
                }
                for item in self.parameters
            ],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
            "diagnostics": [asdict(item) for item in self.diagnostics],
            "supported_constructs": list(self.supported_constructs),
        }


def _candidate_id(
    source_path: str,
    endpoint: str,
    endpoint_shape: FrontendEndpointShape,
    role: FrontendRequestRole,
    method: Optional[str],
    representation: Optional[str],
    source_construct: str,
    parameters: tuple,
) -> str:
    payload = json.dumps(
        {
            "endpoint": endpoint,
            "endpoint_shape": endpoint_shape.value,
            "method": method,
            "request_role": role.value,
            "representation": representation,
            "selectors": sorted(
                (item.name, item.literal_value)
                for item in parameters
                if item.is_operation_selector
            ),
            "source_construct": source_construct,
            "source_path": source_path,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "frontend-request:{}".format(hashlib.sha256(payload).hexdigest())


def _parameter_id(
    request_candidate_id: str,
    name: str,
    namespace: FrontendParameterNamespace,
    direction: FrontendParameterDirection,
) -> str:
    payload = json.dumps(
        {
            "direction": direction.value,
            "name": name,
            "namespace": namespace.value,
            "request_candidate_id": request_candidate_id,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "frontend-parameter:{}".format(hashlib.sha256(payload).hexdigest())


def _tokenize_javascript(content: bytes) -> Tuple[_Token, ...]:
    tokens = []
    index = 0
    while index < len(content):
        byte = content[index]
        if byte in b" \t\r\n":
            index += 1
            continue
        if content[index : index + 2] == b"//":
            newline = content.find(b"\n", index + 2)
            index = len(content) if newline < 0 else newline + 1
            continue
        if content[index : index + 2] == b"/*":
            closing = content.find(b"*/", index + 2)
            index = len(content) if closing < 0 else closing + 2
            continue
        if byte in (ord('"'), ord("'"), ord("`")):
            quote = byte
            start = index + 1
            index += 1
            while index < len(content):
                if content[index] == ord("\\"):
                    index += 2
                    continue
                if content[index] == quote:
                    break
                index += 1
            end = min(index, len(content))
            tokens.append(_Token("string", content[start:end], start, end))
            index = min(index + 1, len(content))
            continue
        if byte == ord("_") or byte == ord("$") or chr(byte).isalpha():
            start = index
            index += 1
            while index < len(content):
                current = content[index]
                if not (
                    current == ord("_")
                    or current == ord("$")
                    or chr(current).isalnum()
                ):
                    break
                index += 1
            tokens.append(_Token("identifier", content[start:index], start, index))
            continue
        tokens.append(_Token("punctuation", bytes((byte,)), index, index + 1))
        index += 1
    return tuple(tokens)


def _page_model_url_properties(content: bytes) -> tuple:
    tokens = _tokenize_javascript(content)
    results = []
    index = 0
    prefix = (b"R", b".", b"pageModel", b"(", b"{")
    while index + len(prefix) <= len(tokens):
        if tuple(item.value for item in tokens[index : index + 5]) != prefix:
            index += 1
            continue
        cursor = index + 5
        depth = 1
        while cursor < len(tokens) and depth > 0:
            token = tokens[cursor]
            if token.value == b"{":
                depth += 1
            elif token.value == b"}":
                depth -= 1
            elif (
                depth == 1
                and token.kind == "identifier"
                and token.value in {b"getUrl", b"setUrl"}
                and cursor + 2 < len(tokens)
                and tokens[cursor + 1].value == b":"
                and tokens[cursor + 2].kind == "string"
            ):
                value = tokens[cursor + 2]
                results.append(
                    (
                        token.value.decode("ascii"),
                        value.value.decode("utf-8"),
                        value.start,
                        value.end,
                    )
                )
                cursor += 2
            cursor += 1
        index = max(cursor, index + 1)
    return tuple(results)


def _matching_close(tokens: Tuple[_Token, ...], open_index: int) -> int:
    depth = 1
    cursor = open_index + 1
    while cursor < len(tokens):
        if tokens[cursor].value == b"{":
            depth += 1
        elif tokens[cursor].value == b"}":
            depth -= 1
            if depth == 0:
                return cursor
        cursor += 1
    return len(tokens)


def _module_model_parameters(content: bytes) -> tuple:
    tokens = _tokenize_javascript(content)
    prefix = (b"R", b".", b"moduleModel", b"(", b"{")
    parameters = []
    for index in range(0, max(0, len(tokens) - len(prefix) + 1)):
        if tuple(item.value for item in tokens[index : index + 5]) != prefix:
            continue
        object_end = _matching_close(tokens, index + 4)
        cursor = index + 5
        while cursor < object_end:
            if (
                tokens[cursor].value == b"getSubmitData"
                and cursor + 2 < object_end
                and tokens[cursor + 1].value == b":"
            ):
                block_open = cursor + 2
                while (
                    block_open < object_end
                    and tokens[block_open].value != b"{"
                ):
                    block_open += 1
                block_end = _matching_close(tokens, block_open)
                for token in tokens[block_open + 1 : block_end]:
                    if token.kind != "string":
                        continue
                    for match in re.finditer(
                        rb"(?:^|[&?])([A-Za-z_][A-Za-z0-9_.-]*)=",
                        token.value,
                    ):
                        parameters.append(
                            _ParameterLiteral(
                                name=match.group(1).decode("ascii"),
                                name_start=token.start + match.start(1),
                                name_end=token.start + match.end(1),
                                namespace=FrontendParameterNamespace.FORM,
                                literal_value=None,
                                value_start=None,
                                value_end=None,
                                is_operation_selector=False,
                                source_construct="R.moduleModel.getSubmitData",
                            )
                        )
                cursor = block_end
            cursor += 1
    unique = {}
    for parameter in parameters:
        unique[(parameter.name, parameter.name_start)] = parameter
    return tuple(unique.values())


def _assigned_parameters(tokens: Tuple[_Token, ...]) -> dict:
    assignments = {}
    for index in range(0, max(0, len(tokens) - 2)):
        if (
            tokens[index].kind != "identifier"
            or tokens[index + 1].value != b"="
        ):
            continue
        cursor = index + 2
        parameters = []
        while cursor < len(tokens) and tokens[cursor].value != b";":
            token = tokens[cursor]
            if token.kind == "string":
                for match in re.finditer(
                    rb"(?:^|[&?])([A-Za-z_][A-Za-z0-9_.-]*)=",
                    token.value,
                ):
                    start = token.start + match.start(1)
                    end = token.start + match.end(1)
                    parameters.append(
                        _ParameterLiteral(
                            name=match.group(1).decode("ascii"),
                            name_start=start,
                            name_end=end,
                            namespace=FrontendParameterNamespace.FORM,
                            literal_value=None,
                            value_start=None,
                            value_end=None,
                            is_operation_selector=False,
                            source_construct="string-concatenation",
                        )
                    )
            cursor += 1
        if parameters:
            assignments.setdefault(tokens[index].value, []).append(
                (index, tuple(parameters))
            )
    return assignments


def _jquery_post_calls(content: bytes) -> tuple:
    tokens = _tokenize_javascript(content)
    assignments = _assigned_parameters(tokens)
    results = []
    prefix = (b"$", b".", b"post", b"(")
    for index in range(0, max(0, len(tokens) - len(prefix))):
        if tuple(item.value for item in tokens[index : index + 4]) != prefix:
            continue
        value = tokens[index + 4]
        if value.kind == "string":
            parameters = ()
            if (
                index + 6 < len(tokens)
                and tokens[index + 5].value == b","
                and tokens[index + 6].kind == "identifier"
            ):
                assignments_for_name = assignments.get(
                    tokens[index + 6].value, ()
                )
                parameters = next(
                    (
                        value
                        for assignment_index, value in reversed(assignments_for_name)
                        if assignment_index < index
                    ),
                    (),
                )
            results.append(
                (
                    value.value.decode("utf-8"),
                    value.start,
                    value.end,
                    parameters,
                )
            )
    return tuple(results)


def _jquery_get_json_calls(content: bytes) -> tuple:
    tokens = _tokenize_javascript(content)
    results = []
    prefix = (b"$", b".", b"getJSON", b"(")
    for index in range(0, max(0, len(tokens) - len(prefix))):
        if tuple(item.value for item in tokens[index : index + 4]) != prefix:
            continue
        value = tokens[index + 4]
        if value.kind != "string":
            continue
        shape = (
            FrontendEndpointShape.LITERAL_PREFIX
            if index + 5 < len(tokens) and tokens[index + 5].value == b"+"
            else FrontendEndpointShape.EXACT_LITERAL
        )
        results.append(
            (value.value.decode("utf-8"), value.start, value.end, shape)
        )
    return tuple(results)


def _object_string_properties(
    tokens: Tuple[_Token, ...], open_index: int
) -> tuple:
    properties = []
    cursor = open_index + 1
    depth = 1
    while cursor < len(tokens) and depth > 0:
        token = tokens[cursor]
        if token.value == b"{":
            depth += 1
        elif token.value == b"}":
            depth -= 1
        elif (
            depth == 1
            and token.kind in {"identifier", "string"}
            and cursor + 2 < len(tokens)
            and tokens[cursor + 1].value == b":"
            and tokens[cursor + 2].kind == "string"
        ):
            properties.append((token, tokens[cursor + 2]))
            cursor += 2
        cursor += 1
    return tuple(properties), cursor


def _object_properties(tokens: Tuple[_Token, ...], open_index: int) -> tuple:
    properties = []
    cursor = open_index + 1
    depth = 1
    while cursor < len(tokens) and depth > 0:
        token = tokens[cursor]
        if token.value == b"{":
            depth += 1
        elif token.value == b"}":
            depth -= 1
        elif (
            depth == 1
            and token.kind in {"identifier", "string"}
            and cursor + 2 < len(tokens)
            and tokens[cursor + 1].value == b":"
        ):
            properties.append((token, tokens[cursor + 2]))
            cursor += 2
        cursor += 1
    return tuple(properties), cursor


def _jquery_ajax_calls(content: bytes) -> tuple:
    tokens = _tokenize_javascript(content)
    results = []
    prefix = (b"$", b".", b"ajax", b"(", b"{")
    for index in range(0, max(0, len(tokens) - len(prefix) + 1)):
        if tuple(item.value for item in tokens[index : index + 5]) != prefix:
            continue
        properties, _ = _object_string_properties(tokens, index + 4)
        direct = {key.value.lower(): value for key, value in properties}
        url = direct.get(b"url")
        if url is None:
            continue
        method_token = direct.get(b"type") or direct.get(b"method")
        method = method_token.value.decode("ascii").upper() if method_token else None
        content_type = direct.get(b"contenttype")
        normalized_content_type = (
            content_type.value.decode("ascii").lower() if content_type else ""
        )
        if "xml" in normalized_content_type:
            representation = "xml"
        elif "json" in normalized_content_type:
            representation = "json"
        elif "x-www-form-urlencoded" in normalized_content_type:
            representation = "form_urlencoded"
        else:
            representation = None
        parameters = []
        cursor = index + 5
        depth = 1
        while cursor < len(tokens) and depth > 0:
            token = tokens[cursor]
            if token.value == b"{":
                depth += 1
            elif token.value == b"}":
                depth -= 1
            elif (
                depth == 1
                and token.value.lower() == b"headers"
                and cursor + 2 < len(tokens)
                and tokens[cursor + 1].value == b":"
                and tokens[cursor + 2].value == b"{"
            ):
                header_properties, after_headers = _object_string_properties(
                    tokens, cursor + 2
                )
                for header_name, header_value in header_properties:
                    parameters.append(
                        _ParameterLiteral(
                            name=header_name.value.decode("utf-8"),
                            name_start=header_name.start,
                            name_end=header_name.end,
                            namespace=FrontendParameterNamespace.HEADER,
                            literal_value=header_value.value.decode("utf-8"),
                            value_start=header_value.start,
                            value_end=header_value.end,
                            is_operation_selector=(
                                header_name.value.lower() == b"soapaction"
                            ),
                            source_construct="jQuery.ajax.headers",
                        )
                    )
                cursor = after_headers - 1
            elif (
                depth == 1
                and token.value.lower() == b"data"
                and cursor + 6 < len(tokens)
                and tuple(
                    item.value for item in tokens[cursor + 1 : cursor + 7]
                )
                == (b":", b"JSON", b".", b"stringify", b"(", b"{")
            ):
                data_properties, after_data = _object_properties(
                    tokens, cursor + 6
                )
                selector_names = {
                    b"action",
                    b"cmd",
                    b"command",
                    b"method",
                    b"operation",
                    b"topicurl",
                }
                for parameter_name, parameter_value in data_properties:
                    literal_value = (
                        parameter_value.value.decode("utf-8")
                        if parameter_value.kind == "string"
                        else None
                    )
                    is_selector = (
                        parameter_name.value.lower() in selector_names
                        and literal_value is not None
                    )
                    parameters.append(
                        _ParameterLiteral(
                            name=parameter_name.value.decode("utf-8"),
                            name_start=parameter_name.start,
                            name_end=parameter_name.end,
                            namespace=FrontendParameterNamespace.JSON,
                            literal_value=literal_value,
                            value_start=(
                                parameter_value.start
                                if parameter_value.kind == "string"
                                else None
                            ),
                            value_end=(
                                parameter_value.end
                                if parameter_value.kind == "string"
                                else None
                            ),
                            is_operation_selector=is_selector,
                            source_construct="jQuery.ajax.JSON.stringify",
                        )
                    )
                cursor = after_data - 1
            cursor += 1
        role = (
            FrontendRequestRole.READ
            if method == "GET"
            else FrontendRequestRole.WRITE
            if method in {"POST", "PUT", "PATCH", "DELETE"}
            else FrontendRequestRole.UNSPECIFIED
        )
        results.append(
            (
                url.value.decode("utf-8"),
                url.start,
                url.end,
                role,
                method,
                representation,
                tuple(parameters),
            )
        )
    return tuple(results)


def _html_form_requests(content: bytes) -> tuple:
    parser = _HtmlFormParser(content.decode("utf-8"))
    parser.feed(content.decode("utf-8"))
    parser.close()
    return tuple(parser.requests)


def _request_literals(content: bytes, source_path: str) -> tuple:
    discoveries = []
    page_model_discoveries = []
    for key, endpoint, start_byte, end_byte in _page_model_url_properties(content):
        role = (
            FrontendRequestRole.READ
            if key == "getUrl"
            else FrontendRequestRole.WRITE
        )
        page_model_discoveries.append(
            (
                endpoint,
                start_byte,
                end_byte,
                FrontendEndpointShape.EXACT_LITERAL,
                role,
                None,
                None,
                "R.pageModel.{}".format(key),
                (),
            )
        )
    module_parameters = _module_model_parameters(content)
    write_indexes = [
        index
        for index, item in enumerate(page_model_discoveries)
        if item[7] == "R.pageModel.setUrl"
    ]
    if len(write_indexes) == 1 and module_parameters:
        write_index = write_indexes[0]
        page_model_discoveries[write_index] = (
            *page_model_discoveries[write_index][:-1],
            module_parameters,
        )
    discoveries.extend(page_model_discoveries)
    for endpoint, start_byte, end_byte, parameters in _jquery_post_calls(content):
        discoveries.append(
            (
                endpoint,
                start_byte,
                end_byte,
                FrontendEndpointShape.EXACT_LITERAL,
                FrontendRequestRole.WRITE,
                "POST",
                "form_urlencoded",
                "jQuery.post",
                parameters,
            )
        )
    for endpoint, start_byte, end_byte, shape in _jquery_get_json_calls(content):
        discoveries.append(
            (
                endpoint,
                start_byte,
                end_byte,
                shape,
                FrontendRequestRole.READ,
                "GET",
                "json",
                "jQuery.getJSON",
                (),
            )
        )
    for (
        endpoint,
        start_byte,
        end_byte,
        role,
        method,
        representation,
        parameters,
    ) in _jquery_ajax_calls(content):
        discoveries.append(
            (
                endpoint,
                start_byte,
                end_byte,
                FrontendEndpointShape.EXACT_LITERAL,
                role,
                method,
                representation,
                "jQuery.ajax",
                parameters,
            )
        )
    if source_path.lower().endswith((".htm", ".html", ".xhtml", ".asp", ".php")):
        for (
            endpoint,
            start_byte,
            end_byte,
            role,
            method,
            representation,
            parameters,
        ) in _html_form_requests(content):
            discoveries.append(
                (
                    endpoint,
                    start_byte,
                    end_byte,
                    FrontendEndpointShape.EXACT_LITERAL,
                    role,
                    method,
                    representation,
                    "HTML.form",
                    parameters,
                )
            )
    return tuple(sorted(discoveries, key=lambda item: item[1]))


def discover_frontend_requests(
    source: SourceArtifactEntry,
    content: bytes,
    policy: FrontendPolicy = FrontendPolicy(),
) -> FrontendProducerResult:
    """Discover explainable request candidates without publishing interfaces."""

    if source.kind not in {"file", "hardlink", "archive_member"}:
        raise ValueError("frontend source must be a readable content entry")
    if source.content_sha256 is None:
        raise ValueError("frontend source must have a content SHA-256")
    if len(content) != source.size:
        raise ValueError("frontend content size does not match source inventory")
    if hashlib.sha256(content).hexdigest() != source.content_sha256:
        raise ValueError("frontend content digest does not match source inventory")
    if len(content) > policy.max_source_bytes:
        return FrontendProducerResult(
            source_path=source.canonical_path,
            coverage_status=CoverageStatus.SKIPPED_BY_POLICY,
            processed_bytes=0,
            producer=_PRODUCER,
            candidates=(),
            parameters=(),
            evidence_atoms=(),
            diagnostics=(
                FrontendDiagnostic(
                    code="frontend.source_byte_budget_exceeded",
                    message="source was not parsed because max_source_bytes was exceeded",
                ),
            ),
        )
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return FrontendProducerResult(
            source_path=source.canonical_path,
            coverage_status=CoverageStatus.FAILED,
            processed_bytes=0,
            producer=_PRODUCER,
            candidates=(),
            parameters=(),
            evidence_atoms=(),
            diagnostics=(
                FrontendDiagnostic(
                    code="frontend.invalid_utf8",
                    message="source could not be parsed as UTF-8 frontend content",
                ),
            ),
        )

    candidates = {}
    parameter_candidates = {}
    evidence_atoms = {}
    diagnostics = []
    matches = _request_literals(content, source.canonical_path)
    selected_matches = matches[: policy.max_candidates]
    if len(matches) > len(selected_matches):
        diagnostics.append(
            FrontendDiagnostic(
                code="frontend.candidate_budget_exceeded",
                message="additional request candidates were not published",
            )
        )
    for (
        endpoint,
        start_byte,
        end_byte,
        endpoint_shape,
        role,
        method,
        representation,
        source_construct,
        parameter_spans,
    ) in selected_matches:
        candidate_id = _candidate_id(
            source.canonical_path,
            endpoint,
            endpoint_shape,
            role,
            method,
            representation,
            source_construct,
            parameter_spans,
        )
        evidence = capture_evidence(
            source=source,
            content=content,
            selection=SpanSelection(
                kind=SpanKind.TEXT_UTF8,
                start_byte=start_byte,
                end_byte=end_byte,
            ),
            claim=EvidenceClaim(
                subject_ref=candidate_id,
                predicate="constructs_request",
                object_value=endpoint,
                observation_kind=ObservationKind.DIRECT_STATIC,
                capability="constructs_request",
                confidence=1.0,
            ),
            producer=_PRODUCER,
        )
        existing_candidate = candidates.get(candidate_id)
        if existing_candidate is None:
            candidates[candidate_id] = FrontendRequestCandidate(
                candidate_id=candidate_id,
                endpoint=endpoint,
                endpoint_shape=endpoint_shape,
                request_role=role,
                method=method,
                representation=representation,
                source_construct=source_construct,
                evidence_ids=(evidence.evidence_id,),
            )
        elif evidence.evidence_id not in existing_candidate.evidence_ids:
            candidates[candidate_id] = FrontendRequestCandidate(
                candidate_id=existing_candidate.candidate_id,
                endpoint=existing_candidate.endpoint,
                endpoint_shape=existing_candidate.endpoint_shape,
                request_role=existing_candidate.request_role,
                method=existing_candidate.method,
                representation=existing_candidate.representation,
                source_construct=existing_candidate.source_construct,
                evidence_ids=(
                    *existing_candidate.evidence_ids,
                    evidence.evidence_id,
                ),
            )
        evidence_atoms[evidence.evidence_id] = evidence
        for parameter in parameter_spans:
            parameter_name = parameter.name
            namespace = parameter.namespace
            direction = FrontendParameterDirection.REQUEST
            parameter_id = _parameter_id(
                candidate_id,
                parameter_name,
                namespace,
                direction,
            )
            parameter_evidence = capture_evidence(
                source=source,
                content=content,
                selection=SpanSelection(
                    kind=SpanKind.TEXT_UTF8,
                    start_byte=parameter.name_start,
                    end_byte=parameter.name_end,
                ),
                claim=EvidenceClaim(
                    subject_ref=parameter_id,
                    predicate="serializes",
                    object_value=parameter_name,
                    observation_kind=ObservationKind.DIRECT_STATIC,
                    capability="serializes_parameter",
                    confidence=1.0,
                ),
                producer=_PRODUCER,
            )
            parameter_evidence_ids = [parameter_evidence.evidence_id]
            evidence_atoms[parameter_evidence.evidence_id] = parameter_evidence
            if (
                parameter.is_operation_selector
                and parameter.literal_value is not None
                and parameter.value_start is not None
                and parameter.value_end is not None
            ):
                selector_evidence = capture_evidence(
                    source=source,
                    content=content,
                    selection=SpanSelection(
                        kind=SpanKind.TEXT_UTF8,
                        start_byte=parameter.value_start,
                        end_byte=parameter.value_end,
                    ),
                    claim=EvidenceClaim(
                        subject_ref=parameter_id,
                        predicate="selects",
                        object_value=parameter.literal_value,
                        observation_kind=ObservationKind.DIRECT_STATIC,
                        capability="selects_operation",
                        confidence=1.0,
                    ),
                    producer=_PRODUCER,
                )
                parameter_evidence_ids.append(selector_evidence.evidence_id)
                evidence_atoms[selector_evidence.evidence_id] = selector_evidence
            existing_parameter = parameter_candidates.get(parameter_id)
            if existing_parameter is None:
                parameter_candidates[parameter_id] = FrontendParameterCandidate(
                    parameter_id=parameter_id,
                    request_candidate_id=candidate_id,
                    name=parameter_name,
                    namespace=namespace,
                    direction=direction,
                    literal_value=parameter.literal_value,
                    is_operation_selector=parameter.is_operation_selector,
                    source_construct=parameter.source_construct,
                    evidence_ids=tuple(parameter_evidence_ids),
                )
            else:
                merged_evidence_ids = (
                    *existing_parameter.evidence_ids,
                    *(
                        evidence_id
                        for evidence_id in parameter_evidence_ids
                        if evidence_id not in existing_parameter.evidence_ids
                    ),
                )
                parameter_candidates[parameter_id] = FrontendParameterCandidate(
                    parameter_id=existing_parameter.parameter_id,
                    request_candidate_id=existing_parameter.request_candidate_id,
                    name=existing_parameter.name,
                    namespace=existing_parameter.namespace,
                    direction=existing_parameter.direction,
                    literal_value=existing_parameter.literal_value,
                    is_operation_selector=existing_parameter.is_operation_selector,
                    source_construct=existing_parameter.source_construct,
                    evidence_ids=merged_evidence_ids,
                )

    return FrontendProducerResult(
        source_path=source.canonical_path,
        coverage_status=(
            CoverageStatus.PARTIAL if diagnostics else CoverageStatus.COMPLETED
        ),
        processed_bytes=len(content),
        producer=_PRODUCER,
        candidates=tuple(candidates.values()),
        parameters=tuple(parameter_candidates.values()),
        evidence_atoms=tuple(evidence_atoms.values()),
        diagnostics=tuple(diagnostics),
    )
