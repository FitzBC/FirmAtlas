"""Deterministic evidence producer for text-based firmware backends."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Optional, Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry


SCRIPT_BACKEND_RESULT_SCHEMA_VERSION = "firmatlas.mapping.script-backend-result/v1alpha1"
_PRODUCER = AnalyzerIdentity(name="script-backend-producer", version="0.2.0")
_CONTENT_KINDS = frozenset({"file", "hardlink", "archive", "archive_member"})
_SUPPORTED_CONSTRUCTS = (
    "vendor_asp.Request_Form",
    "vendor_asp.TCWebApi_set",
    "vendor_asp.TCWebApi_commit",
    "vendor_asp.tcWebApi_get",
    "php.superglobal",
    "php.xgi_action_selector",
    "php.xgi_query",
    "php.xgi_query_encrypted",
    "php.xgi_set",
    "php.xgi_set_encrypted",
    "php.slim_route",
    "luci.dispatcher.entry",
    "luci.http.formvalue",
    "posix_cgi.environment",
)


class ScriptBackendLanguage(str, Enum):
    VENDOR_ASP = "vendor_asp"
    PHP = "php"
    LUA = "lua"
    SHELL_CGI = "shell_cgi"
    SHELL = "shell"


class BackendEntryKind(str, Enum):
    CGI_PROGRAM = "cgi_program"


class ScriptParameterNamespace(str, Enum):
    QUERY = "query"
    FORM = "form"
    REQUEST = "request"
    JSON = "json"
    HEADER = "header"
    CGI_ENVIRONMENT = "cgi_environment"


@dataclass(frozen=True)
class ScriptBackendPolicy:
    max_source_bytes: int = 8 * 1024 * 1024
    max_findings: int = 10_000

    def __post_init__(self) -> None:
        if self.max_source_bytes <= 0 or self.max_findings <= 0:
            raise ValueError("script backend producer limits must be positive")


@dataclass(frozen=True)
class BackendEntryCandidate:
    entry_id: str
    kind: BackendEntryKind
    route: Optional[str]
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class BackendRouteCandidate:
    route_id: str
    route: str
    method: Optional[str]
    handler: Optional[str]
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class ScriptParameterCandidate:
    parameter_id: str
    name: str
    namespace: ScriptParameterNamespace
    selector_values: Tuple[str, ...]
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class BackendStateAccess:
    access_id: str
    operation: str
    object_name: str
    field_name: Optional[str]
    parameter_name: Optional[str]
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class BackendTemplateRead:
    read_id: str
    object_name: str
    field_name: str
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class ScriptBackendDiagnostic:
    code: str
    message: str


@dataclass(frozen=True)
class ScriptBackendProducerResult:
    source_path: str
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    language: Optional[ScriptBackendLanguage]
    entries: Tuple[BackendEntryCandidate, ...]
    routes: Tuple[BackendRouteCandidate, ...]
    parameters: Tuple[ScriptParameterCandidate, ...]
    state_accesses: Tuple[BackendStateAccess, ...]
    template_reads: Tuple[BackendTemplateRead, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[ScriptBackendDiagnostic, ...] = ()
    supported_constructs: Tuple[str, ...] = _SUPPORTED_CONSTRUCTS
    schema_version: str = SCRIPT_BACKEND_RESULT_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "source_path": self.source_path,
            "coverage_status": self.coverage_status.value,
            "processed_bytes": self.processed_bytes,
            "producer": asdict(self.producer),
            "language": self.language.value if self.language else None,
            "entries": [{**asdict(x), "kind": x.kind.value} for x in self.entries],
            "routes": [asdict(x) for x in self.routes],
            "parameters": [
                {**asdict(x), "namespace": x.namespace.value} for x in self.parameters
            ],
            "state_accesses": [asdict(x) for x in self.state_accesses],
            "template_reads": [asdict(x) for x in self.template_reads],
            "evidence_atoms": [x.to_dict() for x in self.evidence_atoms],
            "diagnostics": [asdict(x) for x in self.diagnostics],
            "supported_constructs": list(self.supported_constructs),
        }


@dataclass(frozen=True)
class _RawFinding:
    category: str
    start: int
    end: int
    values: tuple
    construct: str


def _stable_id(prefix: str, source_path: str, values: tuple) -> str:
    encoded = json.dumps(
        [source_path, *values], ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return "{}:{}".format(prefix, hashlib.sha256(encoded).hexdigest())


def _verify_source(source: SourceArtifactEntry, content: bytes) -> None:
    if source.kind not in _CONTENT_KINDS or source.content_sha256 is None:
        raise ValueError("script backend source cannot publish content evidence")
    if len(content) != source.size:
        raise ValueError("script backend content size does not match source inventory")
    if hashlib.sha256(content).hexdigest() != source.content_sha256:
        raise ValueError("script backend content digest does not match source inventory")


def _language(source_path: str, content: bytes) -> Optional[ScriptBackendLanguage]:
    lower = source_path.lower()
    if lower.endswith(".php"):
        return ScriptBackendLanguage.PHP
    if lower.endswith(".lua"):
        return ScriptBackendLanguage.LUA
    if lower.endswith(".asp"):
        return ScriptBackendLanguage.VENDOR_ASP
    if content.startswith((b"#!/bin/sh", b"#!/bin/bash", b"#!/usr/bin/env sh")):
        if "/cgi-bin/" in "/{}".format(lower) or lower.endswith(".cgi"):
            return ScriptBackendLanguage.SHELL_CGI
        return ScriptBackendLanguage.SHELL
    return None


def _mask_comments(content: bytes, language: ScriptBackendLanguage) -> bytes:
    masked = bytearray(content)
    patterns = []
    if language is ScriptBackendLanguage.PHP:
        patterns = [rb"/\*.*?\*/", rb"//[^\r\n]*", rb"#[^\r\n]*"]
    elif language is ScriptBackendLanguage.LUA:
        patterns = [rb"--\[\[.*?\]\]", rb"--[^\r\n]*"]
    elif language in {ScriptBackendLanguage.SHELL, ScriptBackendLanguage.SHELL_CGI}:
        patterns = [rb"(?m)^(?!#!)[ \t]*#[^\r\n]*"]
    elif language is ScriptBackendLanguage.VENDOR_ASP:
        patterns = [
            rb"<%--.*?--%>",
            rb"(?im)^[ \t]*(?:'|Rem\b)[^\r\n]*",
        ]
    for pattern in patterns:
        for match in re.finditer(pattern, content, flags=re.DOTALL):
            for index in range(match.start(), match.end()):
                if masked[index] not in (10, 13):
                    masked[index] = 32
    return bytes(masked)


def _scan(language: ScriptBackendLanguage, content: bytes, masked: bytes) -> list:
    findings = []
    if language is ScriptBackendLanguage.VENDOR_ASP:
        request = re.compile(
            rb"Request_Form\s*\(\s*([\"'])([^\"']+)\1\s*\)"
            rb"(?:\s*(=|<>)\s*([\"'])([^\"']*)\4)?",
            re.IGNORECASE,
        )
        for match in request.finditer(masked):
            selector = (
                match.group(5).decode("utf-8")
                if match.group(3) == b"=" and match.group(5) is not None
                else None
            )
            findings.append(_RawFinding("parameter", match.start(), match.end(),
                                        (match.group(2).decode("utf-8"), ScriptParameterNamespace.FORM, selector),
                                        "vendor_asp.Request_Form"))
        state = re.compile(
            rb"TCWebApi_(set|commit)\s*\(\s*([\"'])([^\"']+)\2"
            rb"(?:\s*,\s*([\"'])([^\"']+)\4\s*,\s*([\"'])([^\"']+)\6)?\s*\)",
            re.IGNORECASE,
        )
        for match in state.finditer(masked):
            operation = match.group(1).decode("utf-8").lower()
            findings.append(_RawFinding("state", match.start(), match.end(),
                                        (operation, match.group(3).decode("utf-8"),
                                         match.group(5).decode("utf-8") if match.group(5) else None,
                                         match.group(7).decode("utf-8") if match.group(7) else None),
                                        "vendor_asp.TCWebApi_{}".format(operation)))
        template = re.compile(
            rb"tcWebApi_get\s*\(\s*([\"'])([^\"']+)\1\s*,\s*([\"'])([^\"']+)\3\s*,\s*([\"'])[^\"']+\5\s*\)",
            re.IGNORECASE,
        )
        for match in template.finditer(masked):
            findings.append(_RawFinding("template", match.start(), match.end(),
                                        (match.group(2).decode("utf-8"), match.group(4).decode("utf-8")),
                                        "vendor_asp.tcWebApi_get"))
    elif language is ScriptBackendLanguage.PHP:
        route = re.compile(
            rb"\$[A-Za-z_]\w*\s*->\s*(get|post|put|delete|patch|any)\s*\(\s*([\"'])([^\"']+)\2\s*,\s*([\"'])([^\"']+)\4",
            re.IGNORECASE,
        )
        for match in route.finditer(masked):
            findings.append(_RawFinding("route", match.start(), match.end(),
                                        (match.group(3).decode(), match.group(1).decode().upper(), match.group(5).decode()),
                                        "php.slim_route"))
        parameter = re.compile(rb"\$_(GET|POST|REQUEST|SERVER)\s*\[\s*([\"'])([^\"']+)\2\s*\]", re.IGNORECASE)
        namespaces = {b"GET": ScriptParameterNamespace.QUERY, b"POST": ScriptParameterNamespace.FORM,
                      b"REQUEST": ScriptParameterNamespace.REQUEST}
        for match in parameter.finditer(masked):
            group = match.group(1).upper()
            raw_name = match.group(3).decode()
            if group == b"SERVER" and raw_name.startswith("HTTP_"):
                name = raw_name[5:].replace("_", "-").title()
                namespace = ScriptParameterNamespace.HEADER
            elif group == b"SERVER":
                continue
            else:
                name, namespace = raw_name, namespaces[group]
            findings.append(_RawFinding("parameter", match.start(), match.end(),
                                        (name, namespace, None), "php.superglobal"))
        if b"$ACTION_POST" in masked:
            action_selector = re.compile(
                rb"\$ACTION_POST\s*={2,3}\s*([\"'])([^\"']+)\1"
            )
            for match in action_selector.finditer(masked):
                findings.append(_RawFinding(
                    "parameter", match.start(), match.end(),
                    (
                        "ACTION_POST", ScriptParameterNamespace.FORM,
                        match.group(2).decode("utf-8"),
                    ),
                    "php.xgi_action_selector",
                ))
            state_read = re.compile(
                rb"(?<![A-Za-z0-9_])(query|queryEnc)\s*\(\s*"
                rb"([\"'])([^\"']+)\2\s*\)",
                re.IGNORECASE,
            )
            for match in state_read.finditer(masked):
                operation = (
                    "query_encrypted"
                    if match.group(1).lower() == b"queryenc"
                    else "query"
                )
                findings.append(_RawFinding(
                    "state", match.start(), match.end(),
                    (operation, match.group(3).decode("utf-8"), None, None),
                    "php.xgi_{}".format(operation),
                ))
            state_write = re.compile(
                rb"(?<![A-Za-z0-9_])(set|setEnc)\s*\(\s*"
                rb"([\"'])([^\"']+)\2\s*,\s*"
                rb"(?:\$([A-Za-z_]\w*)|[^\r\n;)]+)\s*\)",
                re.IGNORECASE,
            )
            for match in state_write.finditer(masked):
                operation = (
                    "set_encrypted"
                    if match.group(1).lower() == b"setenc"
                    else "set"
                )
                findings.append(_RawFinding(
                    "state", match.start(), match.end(),
                    (
                        operation, match.group(3).decode("utf-8"), None,
                        match.group(4).decode("utf-8") if match.group(4) else None,
                    ),
                    "php.xgi_{}".format(operation),
                ))
    elif language is ScriptBackendLanguage.LUA:
        route = re.compile(
            rb"entry\s*\(\s*\{([^}]*)\}\s*,\s*call\s*\(\s*([\"'])([^\"']+)\2\s*\)", re.IGNORECASE
        )
        for match in route.finditer(masked):
            segments = re.findall(rb"[\"']([^\"']+)[\"']", match.group(1))
            if segments:
                findings.append(_RawFinding("route", match.start(), match.end(),
                                            ("/" + "/".join(x.decode() for x in segments), None, match.group(3).decode()),
                                            "luci.dispatcher.entry"))
        parameter = re.compile(rb"luci\.http\.formvalue\s*\(\s*([\"'])([^\"']+)\1\s*\)")
        for match in parameter.finditer(masked):
            findings.append(_RawFinding("parameter", match.start(), match.end(),
                                        (match.group(2).decode(), ScriptParameterNamespace.REQUEST, None),
                                        "luci.http.formvalue"))
    elif language in {ScriptBackendLanguage.SHELL, ScriptBackendLanguage.SHELL_CGI}:
        if language is ScriptBackendLanguage.SHELL_CGI:
            line_end = content.find(b"\n")
            line_end = len(content) if line_end < 0 else line_end
            if line_end:
                findings.append(_RawFinding(
                    "entry", 0, line_end,
                    (content[:line_end].decode("utf-8"),), "posix_cgi.shebang"
                ))
        env = re.compile(rb"\$(?:\{)?(QUERY_STRING|CONTENT_LENGTH|CONTENT_TYPE|REQUEST_METHOD|HTTP_[A-Z0-9_]+)(?:\})?")
        for match in env.finditer(masked):
            findings.append(_RawFinding("parameter", match.start(), match.end(),
                                        (match.group(1).decode(), ScriptParameterNamespace.CGI_ENVIRONMENT, None),
                                        "posix_cgi.environment"))
    return sorted(findings, key=lambda x: (x.start, x.end, x.category, x.values))


def _claim(source: SourceArtifactEntry, content: bytes, finding: _RawFinding,
           subject: str, predicate: str, object_value: str, capability: str) -> EvidenceAtom:
    excerpt = content[finding.start:finding.end]
    observation_kind = (
        ObservationKind.DIRECT_STATIC
        if object_value.encode("utf-8") in excerpt
        else ObservationKind.DETERMINISTIC_DERIVED
    )
    return capture_evidence(
        source, content, SpanSelection(SpanKind.TEXT_UTF8, finding.start, finding.end),
        EvidenceClaim(subject, predicate, object_value, observation_kind,
                      capability, 1.0), _PRODUCER,
    )


def discover_script_backend(
    source: SourceArtifactEntry,
    content: bytes,
    policy: ScriptBackendPolicy = ScriptBackendPolicy(),
) -> ScriptBackendProducerResult:
    """Extract bounded, replayable facts without executing firmware code."""

    _verify_source(source, content)
    language = _language(source.canonical_path, content)
    if language is None:
        return ScriptBackendProducerResult(
            source.canonical_path, CoverageStatus.UNSUPPORTED, 0, _PRODUCER, None,
            (), (), (), (), (), (),
            (ScriptBackendDiagnostic("unsupported_language", "source is not a supported text backend"),),
        )
    processed = min(len(content), policy.max_source_bytes)
    diagnostics = []
    status = CoverageStatus.COMPLETED
    if processed < len(content):
        status = CoverageStatus.PARTIAL
        diagnostics.append(ScriptBackendDiagnostic(
            "source_budget_exceeded", "source was truncated at max_source_bytes"
        ))
    working = content[:processed]
    try:
        working.decode("utf-8")
    except UnicodeDecodeError:
        return ScriptBackendProducerResult(
            source.canonical_path, CoverageStatus.FAILED, 0, _PRODUCER, language,
            (), (), (), (), (), (),
            (ScriptBackendDiagnostic("invalid_utf8", "text backend is not valid UTF-8"),),
        )
    findings = _scan(language, working, _mask_comments(working, language))
    if len(findings) > policy.max_findings:
        findings = findings[:policy.max_findings]
        status = CoverageStatus.PARTIAL
        diagnostics = [ScriptBackendDiagnostic(
            "finding_budget_exceeded", "findings were truncated at max_findings"
        )]

    evidence = []
    entries = []
    routes = []
    parameter_groups = {}
    states = []
    template_groups = {}
    for finding in findings:
        if finding.category == "entry":
            shebang = finding.values[0]
            item_id = _stable_id("script-entry", source.canonical_path,
                                 ("cgi_program", shebang))
            atom = _claim(source, content, finding, item_id, "declares", shebang,
                          "declares_cgi_program")
            evidence.append(atom)
            entries.append(BackendEntryCandidate(item_id, BackendEntryKind.CGI_PROGRAM, None,
                                                 finding.construct, (atom.evidence_id,)))
        elif finding.category == "route":
            route_value, method, handler = finding.values
            item_id = _stable_id("script-route", source.canonical_path, finding.values)
            atom = _claim(source, content, finding, item_id, "registers_route", route_value, "registers_route")
            evidence.append(atom)
            routes.append(BackendRouteCandidate(item_id, route_value, method, handler,
                                                finding.construct, (atom.evidence_id,)))
        elif finding.category == "parameter":
            name, namespace, selector = finding.values
            key = (name, namespace, finding.construct)
            item_id = _stable_id("script-parameter", source.canonical_path,
                                 (name, namespace.value, finding.construct))
            atom = _claim(source, content, finding, item_id, "reads_parameter", name, "reads_parameter")
            evidence.append(atom)
            selector_atom = None
            if selector is not None:
                selector_atom = _claim(source, content, finding, item_id, "selects_operation", selector, "selects_operation")
                evidence.append(selector_atom)
            current = parameter_groups.setdefault(key, {"id": item_id, "selectors": set(), "evidence": []})
            current["evidence"].append(atom.evidence_id)
            if selector_atom:
                current["evidence"].append(selector_atom.evidence_id)
                current["selectors"].add(selector)
        elif finding.category == "state":
            operation, object_name, field_name, parameter_name = finding.values
            item_id = _stable_id("script-state", source.canonical_path,
                                 (finding.start, *finding.values))
            if operation in {"set", "set_encrypted", "delete"}:
                capability = "writes_configuration"
            elif operation in {"query", "query_encrypted"}:
                capability = "reads_configuration"
            else:
                capability = "commits_configuration"
            atom = _claim(source, content, finding, item_id, operation, object_name, capability)
            evidence.append(atom)
            states.append(BackendStateAccess(item_id, operation, object_name, field_name,
                                             parameter_name, finding.construct, (atom.evidence_id,)))
        elif finding.category == "template":
            object_name, field_name = finding.values
            key = finding.values
            item_id = _stable_id("script-template-read", source.canonical_path, key)
            atom = _claim(source, content, finding, item_id, "reads_template_state", object_name,
                          "reads_template_state")
            evidence.append(atom)
            group = template_groups.setdefault(key, {"id": item_id, "evidence": []})
            group["evidence"].append(atom.evidence_id)

    parameters = tuple(
        ScriptParameterCandidate(
            value["id"], key[0], key[1], tuple(sorted(value["selectors"])), key[2],
            tuple(dict.fromkeys(value["evidence"])),
        )
        for key, value in parameter_groups.items()
    )
    template_reads = tuple(
        BackendTemplateRead(value["id"], key[0], key[1], "vendor_asp.tcWebApi_get",
                            tuple(dict.fromkeys(value["evidence"])))
        for key, value in template_groups.items()
    )
    return ScriptBackendProducerResult(
        source.canonical_path, status, processed, _PRODUCER, language,
        tuple(entries), tuple(routes), parameters, tuple(states), template_reads,
        tuple(evidence), tuple(diagnostics),
    )
