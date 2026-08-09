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
_PRODUCER = AnalyzerIdentity(name="frontend-request-producer", version="0.4.0")
_SUPPORTED_CONSTRUCTS = (
    "R.pageModel",
    "R.moduleModel.getSubmitData",
    "jQuery.getJSON",
    "jQuery.post",
    "jQuery.ajax",
    "custom.request",
    "custom.GetSetData.setData",
    "custom.file-upload-property",
    "shared-cgi.topicurl",
    "LuCI.rpc.declare",
    "HTML.form",
)


class FrontendRequestRole(str, Enum):
    READ = "read"
    WRITE = "write"
    UNSPECIFIED = "unspecified"


class FrontendEndpointShape(str, Enum):
    EXACT_LITERAL = "exact_literal"
    LITERAL_PREFIX = "literal_prefix"
    LOGICAL_OPERATION = "logical_operation"
    LOGICAL_OPERATION_TEMPLATE = "logical_operation_template"


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
    enable_inline_form_literal: bool = True
    enable_tenda_get_set_data: bool = True

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
class FrontendAssetInput:
    source: SourceArtifactEntry
    content: bytes


@dataclass(frozen=True)
class FrontendAssetBinding:
    binding_id: str
    symbol: str
    value: str
    definition_source_path: str
    consumer_source_path: str
    request_candidate_ids: Tuple[str, ...]
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class FrontendAssetGraphResult:
    coverage_status: CoverageStatus
    processed_bytes: int
    results: Tuple["FrontendProducerResult", ...]
    bindings: Tuple[FrontendAssetBinding, ...]
    diagnostics: Tuple[FrontendDiagnostic, ...] = ()


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
                and tokens[cursor + 2].value
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


def _matching_delimiter(
    tokens: Tuple[_Token, ...], open_index: int, opening: bytes, closing: bytes
) -> int:
    depth = 1
    cursor = open_index + 1
    while cursor < len(tokens):
        if tokens[cursor].value == opening:
            depth += 1
        elif tokens[cursor].value == closing:
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


def _page_model_object_parameters(content: bytes) -> tuple:
    """Recover bounded object payload keys consumed by a page-model write."""

    tokens = _tokenize_javascript(content)
    configurations = (
        ((b"R", b".", b"moduleModel", b"(", b"{"), b"getSubmitData",
         "R.moduleModel.getSubmitData.object"),
        ((b"R", b".", b"pageModel", b"(", b"{"), b"beforeSubmit",
         "R.pageModel.beforeSubmit.object"),
    )
    parameters = []
    for prefix, function_name, construct in configurations:
        for index in range(0, max(0, len(tokens) - len(prefix) + 1)):
            if tuple(item.value for item in tokens[index:index + 5]) != prefix:
                continue
            object_end = _matching_close(tokens, index + 4)
            cursor = index + 5
            while cursor < object_end:
                if (
                    tokens[cursor].value != function_name
                    or cursor + 1 >= object_end
                    or tokens[cursor + 1].value != b":"
                ):
                    cursor += 1
                    continue
                block_open = cursor + 2
                while block_open < object_end and tokens[block_open].value != b"{":
                    block_open += 1
                if block_open >= object_end:
                    break
                block_end = _matching_close(tokens, block_open)
                inner = block_open + 1
                while inner < block_end:
                    if (
                        tokens[inner].value == b"{"
                        and inner > block_open
                        and tokens[inner - 1].value in {b"=", b"return"}
                    ):
                        properties, object_cursor = _object_properties(tokens, inner)
                        for key, _value in properties:
                            if not re.fullmatch(
                                rb"[A-Za-z_][A-Za-z0-9_.-]*", key.value
                            ):
                                continue
                            parameters.append(_ParameterLiteral(
                                name=key.value.decode("ascii"),
                                name_start=key.start,
                                name_end=key.end,
                                namespace=FrontendParameterNamespace.FORM,
                                literal_value=None,
                                value_start=None,
                                value_end=None,
                                is_operation_selector=False,
                                source_construct=construct,
                            ))
                        inner = object_cursor
                    else:
                        inner += 1
                cursor = block_end
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


def _jquery_post_calls(
    content: bytes, enable_inline_form_literal: bool = True
) -> tuple:
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
                and tokens[index + 6].kind == "string"
                and enable_inline_form_literal
            ):
                payload = tokens[index + 6]
                parameters = tuple(
                    _ParameterLiteral(
                        name=match.group(1).decode("ascii"),
                        name_start=payload.start + match.start(1),
                        name_end=payload.start + match.end(1),
                        namespace=FrontendParameterNamespace.FORM,
                        literal_value=match.group(2).decode("utf-8"),
                        value_start=payload.start + match.start(2),
                        value_end=payload.start + match.end(2),
                        is_operation_selector=(
                            match.group(1).lower() in {b"action", b"cmd", b"operation", b"op"}
                        ),
                        source_construct="jQuery.post.form-urlencoded",
                    )
                    for match in re.finditer(
                        rb"(?:^|&)([A-Za-z_][A-Za-z0-9_.-]*)=([^&]*)",
                        payload.value,
                    )
                )
            elif (
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


def _get_set_data_calls(content: bytes) -> tuple:
    """Recover Tenda's bounded ``$.GetSetData.setData`` request wrapper."""
    tokens = _tokenize_javascript(content)
    results = []
    prefix = (b"$", b".", b"GetSetData", b".", b"setData", b"(")
    for index in range(0, max(0, len(tokens) - len(prefix) + 1)):
        if tuple(item.value for item in tokens[index:index + 6]) != prefix:
            continue
        endpoint = tokens[index + 6] if index + 6 < len(tokens) else None
        if endpoint is None or endpoint.kind != "string":
            continue
        comma_index = index + 7
        while comma_index < len(tokens) and tokens[comma_index].value != b",":
            comma_index += 1
        if comma_index + 1 >= len(tokens):
            continue
        payload = tokens[comma_index + 1]
        properties = ()
        if payload.value == b"{":
            properties, _ = _object_properties(tokens, comma_index + 1)
        elif payload.kind == "identifier":
            properties = _identifier_object_properties(tokens, payload.value, 0, index)
        parameters = tuple(
            _ParameterLiteral(
                name=key.value.decode("utf-8"),
                name_start=key.start,
                name_end=key.end,
                namespace=FrontendParameterNamespace.FORM,
                literal_value=value.value.decode("utf-8") if value.kind == "string" else None,
                value_start=value.start if value.kind == "string" else None,
                value_end=value.end if value.kind == "string" else None,
                is_operation_selector=False,
                source_construct="custom.GetSetData.setData",
            )
            for key, value in properties
        )
        shape = (
            FrontendEndpointShape.LITERAL_PREFIX
            if index + 7 < len(tokens) and tokens[index + 7].value == b"+"
            else FrontendEndpointShape.EXACT_LITERAL
        )
        results.append((endpoint.value.decode("utf-8"), endpoint.start, endpoint.end, shape, parameters))
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


def _bounded_luci_rpc_value(
    tokens: Tuple[_Token, ...], value_index: int, object_end: int
) -> Optional[tuple]:
    """Return a literal or a single-placeholder ``String.format`` template."""

    value = tokens[value_index]
    following = tokens[value_index + 1].value if value_index + 1 < object_end else b"}"
    if value.kind == "string" and following in {b",", b"}"}:
        return value.value.decode("utf-8"), value.start, value.end, False
    if not (
        value.kind == "string"
        and value.value.count(b"%s") == 1
        and value_index + 3 < object_end
        and tuple(item.value for item in tokens[value_index + 1:value_index + 4])
        == (b".", b"format", b"(")
    ):
        return None
    close_index = _matching_delimiter(
        tokens, value_index + 3, b"(", b")"
    )
    if close_index >= object_end:
        return None
    after = tokens[close_index + 1].value if close_index + 1 <= object_end else b"}"
    if after not in {b",", b"}"}:
        return None
    argument_tokens = tokens[value_index + 4:close_index]
    if not argument_tokens or any(item.value == b"," for item in argument_tokens):
        return None
    template = value.value.decode("utf-8").replace("%s", "{dynamic}")
    return template, value.start, value.end, True


def _luci_rpc_declarations(content: bytes) -> tuple:
    """Recover statically named LuCI ``rpc.declare`` ubus operations.

    LuCI resolves the physical HTTP path at runtime, so the published identity is
    deliberately a logical ``ubus://object/method`` operation rather than a
    guessed URL. Dynamic object or method expressions remain an explicit gap.
    """

    tokens = _tokenize_javascript(content)
    results = []
    unsupported = 0
    template_count = 0
    prefix = (b"rpc", b".", b"declare", b"(", b"{")
    for index in range(0, max(0, len(tokens) - len(prefix) + 1)):
        if tuple(item.value for item in tokens[index:index + 5]) != prefix:
            continue
        object_end = _matching_close(tokens, index + 4)
        direct = {}
        params = []
        cursor = index + 5
        depth = 1
        while cursor < object_end:
            token = tokens[cursor]
            if token.value == b"{":
                depth += 1
            elif token.value == b"}":
                depth -= 1
            elif (
                depth == 1
                and token.kind in {"identifier", "string"}
                and cursor + 2 < object_end
                and tokens[cursor + 1].value == b":"
            ):
                key = token.value.lower()
                value = tokens[cursor + 2]
                if key in {b"object", b"method"}:
                    resolved = _bounded_luci_rpc_value(
                        tokens, cursor + 2, object_end
                    )
                    if resolved is not None:
                        direct[key] = (token, *resolved)
                elif key == b"params" and value.value == b"[":
                    param_cursor = cursor + 3
                    array_depth = 1
                    while param_cursor < object_end and array_depth > 0:
                        current = tokens[param_cursor]
                        if current.value == b"[":
                            array_depth += 1
                        elif current.value == b"]":
                            array_depth -= 1
                        elif array_depth == 1 and current.kind == "string":
                            params.append(current)
                        param_cursor += 1
                cursor += 2
            cursor += 1
        if b"object" not in direct or b"method" not in direct:
            unsupported += 1
            continue
        object_key, object_value, object_start, object_end_byte, object_template = (
            direct[b"object"]
        )
        method_key, method_value, method_start, method_end, method_template = (
            direct[b"method"]
        )
        is_template = object_template or method_template
        if is_template:
            template_count += 1
        endpoint = "ubus://{}/{}".format(
            object_value,
            method_value,
        )
        parameters = [
            _ParameterLiteral(
                name=name,
                name_start=key.start,
                name_end=key.end,
                namespace=FrontendParameterNamespace.JSON,
                literal_value=value,
                value_start=value_start,
                value_end=value_end,
                is_operation_selector=True,
                source_construct="LuCI.rpc.declare",
            )
            for name, key, value, value_start, value_end in (
                ("object", object_key, object_value, object_start, object_end_byte),
                ("method", method_key, method_value, method_start, method_end),
            )
        ]
        parameters.extend(
            _ParameterLiteral(
                name=value.value.decode("utf-8"),
                name_start=value.start,
                name_end=value.end,
                namespace=FrontendParameterNamespace.JSON,
                literal_value=None,
                value_start=None,
                value_end=None,
                is_operation_selector=False,
                source_construct="LuCI.rpc.declare.params",
            )
            for value in params
        )
        results.append((
            endpoint,
            min(object_start, method_start),
            max(object_end_byte, method_end),
            FrontendRequestRole.UNSPECIFIED,
            "POST",
            "json_rpc",
            tuple(parameters),
            is_template,
        ))
    return tuple(results), unsupported, template_count


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


def _contains_token_sequence(
    tokens: Tuple[_Token, ...], start: int, end: int, sequence: tuple
) -> bool:
    width = len(sequence)
    return any(
        tuple(token.value for token in tokens[index : index + width]) == sequence
        for index in range(start, max(start, end - width + 1))
    )


def _function_owner(tokens: Tuple[_Token, ...], function_index: int) -> Optional[bytes]:
    if (
        function_index + 1 < len(tokens)
        and tokens[function_index + 1].kind == "identifier"
    ):
        return tokens[function_index + 1].value
    if (
        function_index >= 2
        and tokens[function_index - 1].value == b"="
        and tokens[function_index - 2].kind == "identifier"
    ):
        return tokens[function_index - 2].value
    return None


def _shared_cgi_topicurl_calls(
    content: bytes, external_bindings: Optional[dict] = None
) -> tuple:
    """Resolve a shared CGI wrapper plus prototype-level operation selectors.

    Some firmware frontends keep one physical CGI URL in configuration, assign it
    to an instance field, and place the logical operation in ``topicurl`` before
    JSON serialization.  The endpoint and selector are only published when the
    complete wrapper contract is present in the same constructor function.
    """

    tokens = _tokenize_javascript(content)
    endpoint_properties = {}
    for index in range(0, max(0, len(tokens) - 3)):
        if (
            tokens[index].kind == "identifier"
            and tokens[index + 1].value == b"="
            and tokens[index + 2].value == b"{"
        ):
            properties, _ = _object_string_properties(tokens, index + 2)
            for key, value in properties:
                if key.value.lower() == b"cgiurl":
                    endpoint_properties[(tokens[index].value, b"cgiurl")] = value
    for identity, endpoint in (external_bindings or {}).items():
        endpoint_properties.setdefault(identity, endpoint)

    wrappers = {}
    for function_index, token in enumerate(tokens):
        if token.value != b"function":
            continue
        owner = _function_owner(tokens, function_index)
        if owner is None:
            continue
        body_open = function_index + 1
        while body_open < len(tokens) and tokens[body_open].value != b"{":
            body_open += 1
        if body_open >= len(tokens):
            continue
        body_end = _matching_close(tokens, body_open)
        endpoint_token = None
        endpoint_value = None
        endpoint_identity = None
        cross_resource = False
        for index in range(body_open + 1, max(body_open + 1, body_end - 6)):
            if (
                tuple(item.value for item in tokens[index : index + 4])
                == (b"this", b".", b"srcUrl", b"=")
                and tokens[index + 4].kind == "identifier"
                and tokens[index + 5].value == b"."
                and tokens[index + 6].value.lower() == b"cgiurl"
            ):
                resolved = endpoint_properties.get(
                    (tokens[index + 4].value, tokens[index + 6].value.lower())
                )
                endpoint_identity = (
                    tokens[index + 4].value, tokens[index + 6].value.lower()
                )
                if isinstance(resolved, _Token):
                    endpoint_token = resolved
                    endpoint_value = resolved.value
                elif isinstance(resolved, bytes):
                    endpoint_token = _Token(
                        "identifier", resolved,
                        tokens[index + 4].start, tokens[index + 6].end,
                    )
                    endpoint_value = resolved
                    cross_resource = True
                break
        if endpoint_token is None:
            continue
        required_sequences = (
            (b".", b"topicurl", b"=", b"this", b".", b"topicurl"),
            (b"JSON", b".", b"stringify", b"("),
            (b"$", b".", b"ajax", b"("),
            (b"url", b":", b"this", b".", b"srcUrl"),
            (b"dataType", b":", b"json"),
        )
        if not all(
            _contains_token_sequence(tokens, body_open + 1, body_end, sequence)
            for sequence in required_sequences
        ):
            continue
        literal_post = _contains_token_sequence(
            tokens, body_open + 1, body_end, (b"type", b":", b"POST")
        )
        dynamic_method = _contains_token_sequence(
            tokens, body_open + 1, body_end,
            (b"type", b":", b"this", b".", b"type"),
        )
        if not literal_post and not dynamic_method:
            continue
        wrappers[owner] = (
            endpoint_token, endpoint_value, endpoint_identity, cross_resource,
            "POST" if literal_post else None,
        )

    results = []
    for index in range(0, max(0, len(tokens) - 7)):
        if not (
            tokens[index].kind == "identifier"
            and tuple(item.value for item in tokens[index + 1 : index + 4])
            == (b".", b"prototype", b".")
            and tokens[index + 4].kind == "identifier"
            and tokens[index + 5].value == b"="
            and tokens[index + 6].value == b"function"
        ):
            continue
        wrapper = wrappers.get(tokens[index].value)
        if wrapper is None:
            continue
        endpoint_token, endpoint_value, endpoint_identity, cross_resource, method = wrapper
        body_open = index + 7
        while body_open < len(tokens) and tokens[body_open].value != b"{":
            body_open += 1
        if body_open >= len(tokens):
            continue
        body_end = _matching_close(tokens, body_open)
        if not _contains_token_sequence(
            tokens, body_open + 1, body_end, (b"this", b".", b"post", b"(")
        ):
            continue
        for cursor in range(body_open + 1, max(body_open + 1, body_end - 4)):
            if not (
                tuple(item.value for item in tokens[cursor : cursor + 4])
                == (b"this", b".", b"topicurl", b"=")
                and tokens[cursor + 4].kind == "string"
            ):
                continue
            name_token = tokens[cursor + 2]
            selector_token = tokens[cursor + 4]
            parameter = _ParameterLiteral(
                name="topicurl",
                name_start=name_token.start,
                name_end=name_token.end,
                namespace=FrontendParameterNamespace.JSON,
                literal_value=selector_token.value.decode("utf-8"),
                value_start=selector_token.start,
                value_end=selector_token.end,
                is_operation_selector=True,
                source_construct="shared-cgi.topicurl",
            )
            results.append(
                (
                    endpoint_value.decode("utf-8"),
                    endpoint_token.start,
                    endpoint_token.end,
                    (
                        FrontendRequestRole.WRITE
                        if method == "POST"
                        else FrontendRequestRole.UNSPECIFIED
                    ),
                    method,
                    "json",
                    (parameter,),
                    (
                        "shared-cgi.topicurl.cross-resource"
                        if cross_resource else "shared-cgi.topicurl"
                    ),
                    endpoint_identity,
                )
            )
            break
    return tuple(results)


def _identifier_object_properties(
    tokens: Tuple[_Token, ...], identifier: bytes, start_index: int,
    before_index: int,
) -> tuple:
    """Return bounded object-literal assignments reaching a request call."""

    assignments = []
    for index in range(start_index, before_index):
        if not (
            tokens[index].value == identifier
            and index + 2 < before_index
            and tokens[index + 1].value == b"="
            and tokens[index + 2].value == b"{"
        ):
            continue
        properties, _ = _object_properties(tokens, index + 2)
        assignments.extend(properties)
    return tuple(assignments)


def _enclosing_function_body_start(
    tokens: Tuple[_Token, ...], before_index: int
) -> int:
    stack = []
    for index in range(before_index):
        if tokens[index].value == b"{":
            stack.append(index)
        elif tokens[index].value == b"}" and stack:
            stack.pop()
    for open_index in reversed(stack):
        cursor = open_index - 1
        while cursor >= 0 and tokens[cursor].value not in {b";", b"{", b"}"}:
            if tokens[cursor].value == b"function":
                return open_index + 1
            cursor -= 1
    return 0


def _custom_request_calls(
    content: bytes, external_bindings: Optional[dict] = None
) -> tuple:
    tokens = _tokenize_javascript(content)
    results = []
    selector_names = {
        b"action", b"cmd", b"command", b"method", b"operation", b"topicurl"
    }
    for index in range(0, max(0, len(tokens) - 6)):
        if not (
            tokens[index].kind == "identifier"
            and tuple(item.value for item in tokens[index + 1 : index + 5])
            == (b".", b"request", b"(", b"{")
        ):
            continue
        properties, _ = _object_properties(tokens, index + 4)
        direct = {key.value.lower(): value for key, value in properties}
        receiver = tokens[index].value
        url = direct.get(b"url")
        endpoint_identity = None
        cross_resource_default = False
        if url is not None and url.kind == "string":
            endpoint = url
        else:
            endpoint_identity = (b"request_default", receiver)
            resolved = (external_bindings or {}).get(endpoint_identity)
            if not isinstance(resolved, bytes):
                continue
            endpoint = _Token(
                "identifier", resolved, tokens[index].start,
                tokens[index + 2].end,
            )
            cross_resource_default = True
        if endpoint.kind not in {"string", "identifier"}:
            continue
        method_token = direct.get(b"type") or direct.get(b"method")
        method = (
            method_token.value.decode("ascii").upper()
            if method_token is not None and method_token.kind == "string"
            else None
        )
        data = direct.get(b"data")
        parameters = []
        data_properties = ()
        if data is not None and data.value == b"{":
            data_index = tokens.index(data)
            data_properties, _ = _object_properties(tokens, data_index)
        elif data is not None and data.kind == "identifier":
            data_properties = _identifier_object_properties(
                tokens, data.value,
                _enclosing_function_body_start(tokens, index), index,
            )
        if data_properties:
            for name, value in data_properties:
                literal_value = (
                    value.value.decode("utf-8") if value.kind == "string" else None
                )
                parameters.append(_ParameterLiteral(
                    name=name.value.decode("utf-8"),
                    name_start=name.start,
                    name_end=name.end,
                    namespace=FrontendParameterNamespace.JSON,
                    literal_value=literal_value,
                    value_start=value.start if value.kind == "string" else None,
                    value_end=value.end if value.kind == "string" else None,
                    is_operation_selector=(
                        name.value.lower() in selector_names
                        and literal_value is not None
                    ),
                    source_construct="custom.request.data",
                ))
        role = (
            FrontendRequestRole.READ if method == "GET"
            else FrontendRequestRole.WRITE
            if method in {"POST", "PUT", "PATCH", "DELETE"}
            else FrontendRequestRole.UNSPECIFIED
        )
        results.append((
            endpoint.value.decode("utf-8"), endpoint.start, endpoint.end,
            role, method, "json" if parameters else None, tuple(parameters),
            endpoint_identity if cross_resource_default else None,
        ))
    return tuple(results)


def _upload_url_parameters(value: _Token) -> tuple:
    raw = value.value
    question = raw.find(b"?")
    if question < 0:
        return ()
    parameters = []
    cursor = question + 1
    for segment in raw[question + 1:].split(b"&"):
        segment_start = cursor
        cursor += len(segment) + 1
        if b"=" in segment:
            name, literal = segment.split(b"=", 1)
            separator = 1
        elif b"/" in segment:
            name, literal = segment.split(b"/", 1)
            separator = 1
        else:
            continue
        if not name or not literal:
            continue
        name_start = value.start + segment_start
        value_start = name_start + len(name) + separator
        parameters.append(_ParameterLiteral(
            name=name.decode("utf-8"),
            name_start=name_start,
            name_end=name_start + len(name),
            namespace=FrontendParameterNamespace.QUERY,
            literal_value=literal.decode("utf-8"),
            value_start=value_start,
            value_end=value_start + len(literal),
            is_operation_selector=True,
            source_construct="custom.file-upload-property.url",
        ))
    return tuple(parameters)


def _file_upload_property_calls(content: bytes) -> tuple:
    """Recover upload URLs stored in a page property and consumed by a helper."""

    tokens = _tokenize_javascript(content)
    definitions = {}
    for index in range(max(0, len(tokens) - 2)):
        if not (
            tokens[index].kind in {"identifier", "string"}
            and tokens[index + 1].value == b":"
            and tokens[index + 2].kind == "string"
            and b"/" in tokens[index + 2].value
        ):
            continue
        definitions.setdefault(tokens[index].value, []).append(tokens[index + 2])

    results = []
    for index in range(max(0, len(tokens) - 5)):
        if not (
            tokens[index].kind == "identifier"
            and tuple(item.value for item in tokens[index + 1:index + 5])
            == (b".", b"fileUpload", b"(", b"{")
        ):
            continue
        object_end = _matching_close(tokens, index + 4)
        properties, _ = _object_properties(tokens, index + 4)
        if not any(key.value.lower() == b"data" for key, _ in properties):
            continue
        property_name = None
        for cursor in range(index + 5, max(index + 5, object_end - 4)):
            if (
                tokens[cursor].value.lower() == b"url"
                and tuple(item.value for item in tokens[cursor + 1:cursor + 4])
                == (b":", b"this", b".")
                and tokens[cursor + 4].kind == "identifier"
            ):
                property_name = tokens[cursor + 4].value
                break
        values = definitions.get(property_name, ())
        unique = {item.value for item in values}
        if len(unique) != 1:
            continue
        value = values[0]
        endpoint = value.value.split(b"?", 1)[0]
        if not endpoint.startswith(b"/"):
            continue
        results.append((
            endpoint.decode("utf-8"), value.start,
            value.start + len(endpoint), FrontendRequestRole.WRITE, "POST",
            "multipart_form", _upload_url_parameters(value),
        ))
    return tuple(results)


def _html_form_requests(content: bytes) -> tuple:
    parser = _HtmlFormParser(content.decode("utf-8"))
    parser.feed(content.decode("utf-8"))
    parser.close()
    return tuple(parser.requests)


def _request_literals(
    content: bytes,
    source_path: str,
    external_bindings: Optional[dict] = None,
    page_model_set_method: Optional[str] = None,
    policy: FrontendPolicy = FrontendPolicy(),
) -> tuple:
    discoveries = []
    luci_rpc, _, _ = _luci_rpc_declarations(content)
    for (
        endpoint,
        start_byte,
        end_byte,
        role,
        method,
        representation,
        parameters,
        is_template,
    ) in luci_rpc:
        discoveries.append((
            endpoint,
            start_byte,
            end_byte,
            (
                FrontendEndpointShape.LOGICAL_OPERATION_TEMPLATE
                if is_template else FrontendEndpointShape.LOGICAL_OPERATION
            ),
            role,
            method,
            representation,
            (
                "LuCI.rpc.declare.template"
                if is_template else "LuCI.rpc.declare"
            ),
            parameters,
        ))
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
                page_model_set_method if key == "setUrl" else None,
                None,
                (
                    "R.pageModel.setUrl.framework"
                    if key == "setUrl" and page_model_set_method
                    else "R.pageModel.{}".format(key)
                ),
                (),
            )
        )
    module_parameters = (
        _module_model_parameters(content) + _page_model_object_parameters(content)
    )
    write_indexes = [
        index
        for index, item in enumerate(page_model_discoveries)
        if item[7] in {
            "R.pageModel.setUrl", "R.pageModel.setUrl.framework"
        }
    ]
    if len(write_indexes) == 1 and module_parameters:
        write_index = write_indexes[0]
        page_model_discoveries[write_index] = (
            *page_model_discoveries[write_index][:-1],
            module_parameters,
        )
    discoveries.extend(page_model_discoveries)
    for endpoint, start_byte, end_byte, parameters in _jquery_post_calls(
        content, policy.enable_inline_form_literal
    ):
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
    if policy.enable_tenda_get_set_data:
        for endpoint, start_byte, end_byte, shape, parameters in _get_set_data_calls(content):
            discoveries.append(
                (
                    endpoint,
                    start_byte,
                    end_byte,
                    shape,
                    FrontendRequestRole.WRITE,
                    "POST",
                    "form_urlencoded",
                    "custom.GetSetData.setData",
                    parameters,
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
    for (
        endpoint,
        start_byte,
        end_byte,
        role,
        method,
        representation,
        parameters,
        endpoint_identity,
    ) in _custom_request_calls(content, external_bindings):
        discoveries.append((
            endpoint, start_byte, end_byte,
            FrontendEndpointShape.EXACT_LITERAL, role, method, representation,
            (
                "custom.request.cross-resource-default"
                if endpoint_identity is not None else "custom.request"
            ),
            parameters,
        ))
    for (
        endpoint,
        start_byte,
        end_byte,
        role,
        method,
        representation,
        parameters,
    ) in _file_upload_property_calls(content):
        discoveries.append((
            endpoint, start_byte, end_byte,
            FrontendEndpointShape.EXACT_LITERAL, role, method, representation,
            "custom.file-upload-property", parameters,
        ))
    for (
        endpoint,
        start_byte,
        end_byte,
        role,
        method,
        representation,
        parameters,
        source_construct,
        _endpoint_identity,
    ) in _shared_cgi_topicurl_calls(content, external_bindings):
        discoveries.append(
            (
                endpoint,
                start_byte,
                end_byte,
                FrontendEndpointShape.EXACT_LITERAL,
                role,
                method,
                representation,
                source_construct,
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

    return _discover_frontend_requests(source, content, policy, None, None)


def _discover_frontend_requests(
    source: SourceArtifactEntry,
    content: bytes,
    policy: FrontendPolicy,
    external_bindings: Optional[dict],
    page_model_set_method: Optional[str],
) -> FrontendProducerResult:
    candidates = {}
    parameter_candidates = {}
    evidence_atoms = {}
    diagnostics = []
    _, unsupported_luci_rpc, template_luci_rpc = _luci_rpc_declarations(content)
    if unsupported_luci_rpc:
        diagnostics.append(FrontendDiagnostic(
            code="frontend.luci_rpc_dynamic_operation",
            message=(
                "{} LuCI rpc.declare operation(s) used a dynamic object or "
                "method expression and were not published"
            ).format(unsupported_luci_rpc),
        ))
    if template_luci_rpc:
        diagnostics.append(FrontendDiagnostic(
            code="frontend.luci_rpc_operation_template",
            message=(
                "{} LuCI rpc.declare operation(s) were published as bounded "
                "templates; concrete runtime object or method values remain "
                "unresolved"
            ).format(template_luci_rpc),
        ))
    matches = _request_literals(
        content,
        source.canonical_path,
        external_bindings,
        page_model_set_method,
        policy,
    )
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
                observation_kind=(
                    ObservationKind.DETERMINISTIC_DERIVED
                    if source_construct in {
                        "shared-cgi.topicurl.cross-resource",
                        "custom.request.cross-resource-default",
                        "custom.file-upload-property",
                        "LuCI.rpc.declare",
                        "LuCI.rpc.declare.template",
                    }
                    else ObservationKind.DIRECT_STATIC
                ),
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
                        observation_kind=(
                            ObservationKind.DETERMINISTIC_DERIVED
                            if "{dynamic}" in parameter.literal_value
                            else ObservationKind.DIRECT_STATIC
                        ),
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


def _asset_symbol_definitions(asset: FrontendAssetInput) -> tuple:
    try:
        asset.content.decode("utf-8")
    except UnicodeDecodeError:
        return ()
    definitions = []
    pattern = re.compile(
        rb"(?<![A-Za-z0-9_$])(?P<owner>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\{"
        rb"[^{}]{0,8192}?(?P<key>\bcgiUrl)\s*:\s*"
        rb"(?P<quote>[\"'])(?P<value>[^\"']+)(?P=quote)",
        re.DOTALL,
    )
    matches = tuple(pattern.finditer(asset.content))
    code_offsets = _javascript_code_offsets(
        asset.content,
        tuple(
            offset
            for match in matches
            for offset in (match.start("owner"), match.start("key"))
        ),
    )
    for match in matches:
        if not {
            match.start("owner"), match.start("key")
        } <= code_offsets:
            continue
        owner = match.group("owner")
        value = _Token(
            "string", match.group("value"),
            match.start("value"), match.end("value"),
        )
        definitions.append((
            (owner, b"cgiurl"),
            "{}.cgiUrl".format(owner.decode("utf-8")),
            value,
        ))
    return tuple(definitions)


def _request_default_definitions(asset: FrontendAssetInput) -> tuple:
    """Resolve constructor-backed ``receiver.request`` default URL literals."""

    try:
        asset.content.decode("utf-8")
    except UnicodeDecodeError:
        return ()
    tokens = _tokenize_javascript(asset.content)
    constructor_defaults = {}
    for index in range(max(0, len(tokens) - 8)):
        if not (
            tokens[index].kind == "identifier"
            and tuple(item.value for item in tokens[index + 1:index + 6])
            == (b".", b"prototype", b".", b"request", b"=")
            and tokens[index + 6].value == b"function"
        ):
            continue
        body_open = index + 7
        while body_open < len(tokens) and tokens[body_open].value != b"{":
            body_open += 1
        if body_open >= len(tokens):
            continue
        body_end = _matching_close(tokens, body_open)
        for cursor in range(body_open + 1, max(body_open + 1, body_end - 4)):
            if not (
                tokens[cursor].kind == "identifier"
                and tuple(item.value for item in tokens[cursor + 1:cursor + 5])
                == (b".", b"url", b"|", b"|")
                and tokens[cursor + 5].kind == "string"
            ):
                continue
            constructor_defaults[tokens[index].value] = tokens[cursor + 5]
            break

    definitions = []
    for index in range(max(0, len(tokens) - 4)):
        if not (
            tokens[index].kind == "identifier"
            and (index == 0 or tokens[index - 1].value != b".")
            and tokens[index + 1].value == b"="
            and tokens[index + 2].value == b"new"
            and tokens[index + 3].kind == "identifier"
        ):
            continue
        receiver = tokens[index].value
        constructor = tokens[index + 3].value
        default = constructor_defaults.get(constructor)
        if default is not None:
            definitions.append((
                (b"request_default", receiver),
                "{}.request.default_url".format(receiver.decode("utf-8")),
                default,
            ))
    for index in range(max(0, len(tokens) - 6)):
        if not (
            tokens[index].kind == "identifier"
            and tokens[index + 1].value == b"."
            and tokens[index + 2].kind == "identifier"
            and tokens[index + 3].value == b"="
            and tokens[index + 4].value == b"new"
            and tokens[index + 5].kind == "identifier"
        ):
            continue
        receiver = tokens[index + 2].value
        constructor = tokens[index + 5].value
        default = constructor_defaults.get(constructor)
        if default is not None:
            definitions.append((
                (b"request_default", receiver),
                "{}.request.default_url".format(receiver.decode("utf-8")),
                default,
            ))
    return tuple(definitions)


def _page_model_framework_methods(asset: FrontendAssetInput) -> tuple:
    """Prove the transport method used by a RouterPage page-model framework."""

    try:
        asset.content.decode("utf-8")
    except UnicodeDecodeError:
        return ()
    tokens = _tokenize_javascript(asset.content)
    definitions = []
    page_prefix = (b"this", b".", b"page", b"=", b"function", b"(")
    post_prefix = (
        b"$", b".", b"post", b"(", b"pageModel", b".", b"setUrl", b",",
    )
    for index in range(max(0, len(tokens) - len(page_prefix) + 1)):
        if tuple(item.value for item in tokens[index:index + 6]) != page_prefix:
            continue
        parameters_end = _matching_delimiter(tokens, index + 5, b"(", b")")
        if not any(
            item.kind == "identifier" and item.value == b"pageModel"
            for item in tokens[index + 6:parameters_end]
        ):
            continue
        body_open = parameters_end + 1
        while body_open < len(tokens) and tokens[body_open].value != b"{":
            body_open += 1
        if body_open >= len(tokens):
            continue
        body_end = _matching_close(tokens, body_open)
        for cursor in range(body_open + 1, max(body_open + 1, body_end - 7)):
            if tuple(item.value for item in tokens[cursor:cursor + 8]) == post_prefix:
                definitions.append(("POST", tokens[cursor + 2]))
    return tuple(definitions)


def _javascript_code_offsets(content: bytes, offsets: tuple) -> set:
    """Return requested offsets that begin in JavaScript code.

    Asset binding discovery deliberately uses a bounded pattern instead of a
    full JavaScript parser because representative firmware ships old, minified
    sources.  This small lexical guard prevents assignment-shaped text inside
    comments, strings, templates, and regular-expression literals from becoming
    endpoint definitions while preserving byte offsets for evidence capture.
    """

    requested = set(offsets)
    if not requested:
        return set()
    accepted = set()
    state = "code"
    quote = None
    escaped = False
    regex_class = False
    previous_significant = None
    index = 0
    limit = max(requested)
    regex_prefix = b"=(:,![{;?&|+-*%^~<>"
    while index <= limit and index < len(content):
        if index in requested and state == "code":
            accepted.add(index)
        byte = content[index]
        following = content[index + 1] if index + 1 < len(content) else None
        if state == "line_comment":
            if byte in (ord("\n"), ord("\r")):
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if byte == ord("*") and following == ord("/"):
                state = "code"
                index += 2
            else:
                index += 1
            continue
        if state in {"string", "template"}:
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == quote:
                state = "code"
                previous_significant = byte
            index += 1
            continue
        if state == "regex":
            if escaped:
                escaped = False
            elif byte == ord("\\"):
                escaped = True
            elif byte == ord("["):
                regex_class = True
            elif byte == ord("]"):
                regex_class = False
            elif byte == ord("/") and not regex_class:
                state = "code"
                previous_significant = byte
            index += 1
            continue
        if byte == ord("/") and following == ord("/"):
            state = "line_comment"
            index += 2
            continue
        if byte == ord("/") and following == ord("*"):
            state = "block_comment"
            index += 2
            continue
        if byte in (ord('"'), ord("'")):
            state = "string"
            quote = byte
            escaped = False
            index += 1
            continue
        if byte == ord("`"):
            state = "template"
            quote = byte
            escaped = False
            index += 1
            continue
        if byte == ord("/") and (
            previous_significant is None
            or previous_significant in regex_prefix
        ):
            state = "regex"
            regex_class = False
            escaped = False
            index += 1
            continue
        if byte not in b" \t\r\n":
            previous_significant = byte
        index += 1
    return accepted


def _asset_binding_id(
    symbol: str, value: str, definition_path: str, consumer_path: str
) -> str:
    payload = json.dumps(
        {
            "consumer": consumer_path,
            "definition": definition_path,
            "symbol": symbol,
            "value": value,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "frontend-asset-binding:{}".format(hashlib.sha256(payload).hexdigest())


def discover_frontend_asset_graph(
    assets: Tuple[FrontendAssetInput, ...],
    policy: FrontendPolicy = FrontendPolicy(),
) -> FrontendAssetGraphResult:
    """Resolve conservative cross-resource request bindings for an asset set."""

    paths = tuple(asset.source.canonical_path for asset in assets)
    if len(paths) != len(set(paths)):
        raise ValueError("frontend asset graph requires unique source paths")

    baseline = tuple(
        discover_frontend_requests(asset.source, asset.content, policy)
        for asset in assets
    )
    definitions = {}
    framework_methods = []
    for asset, result in zip(assets, baseline):
        if result.coverage_status is not CoverageStatus.COMPLETED:
            continue
        for identity, symbol, token in (
            *_asset_symbol_definitions(asset),
            *_request_default_definitions(asset),
        ):
            definitions.setdefault(identity, []).append((asset, symbol, token))
        for method, token in _page_model_framework_methods(asset):
            framework_methods.append((asset, method, token))

    resolved = {}
    diagnostics = []
    for identity, candidates in definitions.items():
        values = {token.value for _, _, token in candidates}
        if len(values) == 1 and len(candidates) == 1:
            resolved[identity] = candidates[0]
        else:
            diagnostics.append(FrontendDiagnostic(
                (
                    "frontend.asset_symbol_conflict"
                    if len(values) > 1
                    else "frontend.asset_symbol_ambiguous"
                ),
                (
                    "conflicting endpoint definitions prevented cross-resource resolution"
                    if len(values) > 1
                    else "repeated endpoint definitions prevented cross-resource resolution"
                ),
            ))

    results = []
    bindings = []
    framework_method = None
    if framework_methods:
        methods = {method for _, method, _ in framework_methods}
        if len(methods) == 1:
            framework_method = next(iter(methods))
        else:
            diagnostics.append(FrontendDiagnostic(
                "frontend.page_model_method_conflict",
                "conflicting page-model framework methods prevented resolution",
            ))
    for asset, original in zip(assets, baseline):
        external = {
            identity: token.value
            for identity, (definition_asset, _, token) in resolved.items()
            if definition_asset.source.canonical_path != asset.source.canonical_path
        }
        applicable_framework = tuple(
            item for item in framework_methods
            if item[0].source.canonical_path != asset.source.canonical_path
        )
        if (
            not external and not (framework_method and applicable_framework)
        ) or original.coverage_status is not CoverageStatus.COMPLETED:
            results.append(original)
            continue
        enriched = _discover_frontend_requests(
            asset.source,
            asset.content,
            policy,
            external,
            framework_method if applicable_framework else None,
        )
        candidate_identities = {
            _candidate_id(
                asset.source.canonical_path,
                endpoint,
                FrontendEndpointShape.EXACT_LITERAL,
                role,
                method,
                representation,
                source_construct,
                parameters,
            ): identity
            for (
                endpoint, _start, _end, role, method, representation,
                parameters, source_construct, identity,
            ) in _shared_cgi_topicurl_calls(asset.content, external)
            if source_construct == "shared-cgi.topicurl.cross-resource"
        }
        candidate_identities.update({
            _candidate_id(
                asset.source.canonical_path,
                endpoint,
                FrontendEndpointShape.EXACT_LITERAL,
                role,
                method,
                representation,
                "custom.request.cross-resource-default",
                parameters,
            ): identity
            for (
                endpoint, _start, _end, role, method, representation,
                parameters, identity,
            ) in _custom_request_calls(asset.content, external)
            if identity is not None
        })
        candidates = list(enriched.candidates)
        evidence_atoms = {atom.evidence_id: atom for atom in enriched.evidence_atoms}
        for candidate_index, candidate in enumerate(candidates):
            if candidate.source_construct == "R.pageModel.setUrl.framework":
                for definition_asset, method, token in applicable_framework:
                    atom = capture_evidence(
                        source=definition_asset.source,
                        content=definition_asset.content,
                        selection=SpanSelection(
                            SpanKind.TEXT_UTF8, token.start, token.end
                        ),
                        claim=EvidenceClaim(
                            subject_ref=candidate.candidate_id,
                            predicate="uses_transport_method",
                            object_value=method,
                            observation_kind=ObservationKind.DETERMINISTIC_DERIVED,
                            capability="resolves_transport_method",
                            confidence=1.0,
                        ),
                        producer=_PRODUCER,
                    )
                    evidence_atoms[atom.evidence_id] = atom
                    candidate = FrontendRequestCandidate(
                        candidate.candidate_id,
                        candidate.endpoint,
                        candidate.endpoint_shape,
                        candidate.request_role,
                        candidate.method,
                        candidate.representation,
                        candidate.source_construct,
                        tuple(dict.fromkeys((*candidate.evidence_ids, atom.evidence_id))),
                    )
                    candidates[candidate_index] = candidate
                    bindings.append(FrontendAssetBinding(
                        _asset_binding_id(
                            "R.pageModel.setUrl.method",
                            method,
                            definition_asset.source.canonical_path,
                            asset.source.canonical_path,
                        ),
                        "R.pageModel.setUrl.method",
                        method,
                        definition_asset.source.canonical_path,
                        asset.source.canonical_path,
                        (candidate.candidate_id,),
                        (atom.evidence_id,),
                    ))
            if candidate.source_construct not in {
                "shared-cgi.topicurl.cross-resource",
                "custom.request.cross-resource-default",
            }:
                continue
            identity = candidate_identities.get(candidate.candidate_id)
            resolved_definition = resolved.get(identity)
            matching = (
                ((identity, *resolved_definition),)
                if resolved_definition is not None
                and resolved_definition[0].source.canonical_path
                != asset.source.canonical_path
                else ()
            )
            for _, definition_asset, symbol, token in matching:
                atom = capture_evidence(
                    source=definition_asset.source,
                    content=definition_asset.content,
                    selection=SpanSelection(
                        SpanKind.TEXT_UTF8, token.start, token.end
                    ),
                    claim=EvidenceClaim(
                        subject_ref=candidate.candidate_id,
                        predicate="resolves_endpoint",
                        object_value=candidate.endpoint,
                        observation_kind=ObservationKind.DIRECT_STATIC,
                        capability="resolves_endpoint_binding",
                        confidence=1.0,
                    ),
                    producer=_PRODUCER,
                )
                evidence_atoms[atom.evidence_id] = atom
                evidence_ids = tuple(dict.fromkeys(
                    (*candidate.evidence_ids, atom.evidence_id)
                ))
                candidate = FrontendRequestCandidate(
                    candidate.candidate_id, candidate.endpoint,
                    candidate.endpoint_shape, candidate.request_role,
                    candidate.method, candidate.representation,
                    candidate.source_construct, evidence_ids,
                )
                candidates[candidate_index] = candidate
                binding_id = _asset_binding_id(
                    symbol, candidate.endpoint,
                    definition_asset.source.canonical_path,
                    asset.source.canonical_path,
                )
                bindings.append(FrontendAssetBinding(
                    binding_id, symbol, candidate.endpoint,
                    definition_asset.source.canonical_path,
                    asset.source.canonical_path,
                    (candidate.candidate_id,), (atom.evidence_id,),
                ))
        results.append(FrontendProducerResult(
            source_path=enriched.source_path,
            coverage_status=enriched.coverage_status,
            processed_bytes=enriched.processed_bytes,
            producer=enriched.producer,
            candidates=tuple(candidates),
            parameters=enriched.parameters,
            evidence_atoms=tuple(evidence_atoms.values()),
            diagnostics=enriched.diagnostics,
        ))

    statuses = tuple(result.coverage_status for result in results)
    coverage_status = (
        CoverageStatus.PARTIAL
        if diagnostics or any(status is not CoverageStatus.COMPLETED for status in statuses)
        else CoverageStatus.COMPLETED
    )
    binding_map = {}
    for binding in bindings:
        existing = binding_map.get(binding.binding_id)
        if existing is None:
            binding_map[binding.binding_id] = binding
            continue
        binding_map[binding.binding_id] = FrontendAssetBinding(
            binding.binding_id, binding.symbol, binding.value,
            binding.definition_source_path, binding.consumer_source_path,
            tuple(dict.fromkeys(
                (*existing.request_candidate_ids, *binding.request_candidate_ids)
            )),
            tuple(dict.fromkeys((*existing.evidence_ids, *binding.evidence_ids))),
        )
    return FrontendAssetGraphResult(
        coverage_status=coverage_status,
        processed_bytes=sum(result.processed_bytes for result in results),
        results=tuple(results),
        bindings=tuple(binding_map.values()),
        diagnostics=tuple(diagnostics),
    )
