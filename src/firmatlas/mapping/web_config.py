"""Deterministic web configuration and startup evidence producer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import hashlib
import json
import posixpath
import re
import shlex
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


WEB_CONFIG_RESULT_SCHEMA_VERSION = "firmatlas.mapping.web-config-result/v1alpha1"
_PRODUCER = AnalyzerIdentity(name="web-configuration-producer", version="0.4.0")
_SUPPORTED_FORMATS = (
    "lighttpd", "nginx", "posix_shell", "proprietary_httpd", "uci_uhttpd"
)


class WebConfigFindingKind(str, Enum):
    LISTENER = "listener"
    DOCUMENT_ROOT = "document_root"
    NAMESPACE_MAPPING = "namespace_mapping"
    AUTH_REQUIREMENT = "auth_requirement"
    SERVICE_START = "service_start"


@dataclass(frozen=True)
class WebConfigPolicy:
    max_source_bytes: int = 4 * 1024 * 1024
    max_findings: int = 5_000

    def __post_init__(self) -> None:
        if self.max_source_bytes <= 0 or self.max_findings <= 0:
            raise ValueError("web configuration producer limits must be positive")


@dataclass(frozen=True)
class WebConfigFinding:
    finding_id: str
    kind: WebConfigFindingKind
    value: str
    namespace: Optional[str]
    qualifier: Optional[str]
    related_value: Optional[str]
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class WebConfigDiagnostic:
    code: str
    message: str


@dataclass(frozen=True)
class WebConfigProducerResult:
    source_path: str
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    detected_format: Optional[str]
    findings: Tuple[WebConfigFinding, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[WebConfigDiagnostic, ...] = ()
    supported_formats: Tuple[str, ...] = _SUPPORTED_FORMATS
    schema_version: str = WEB_CONFIG_RESULT_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "source_path": self.source_path,
            "coverage_status": self.coverage_status.value,
            "processed_bytes": self.processed_bytes,
            "producer": asdict(self.producer),
            "detected_format": self.detected_format,
            "findings": [
                {**asdict(item), "kind": item.kind.value} for item in self.findings
            ],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
            "diagnostics": [asdict(item) for item in self.diagnostics],
            "supported_formats": list(self.supported_formats),
        }


@dataclass(frozen=True)
class _Token:
    value: str
    start: int
    end: int
    kind: str = "word"


@dataclass
class _Block:
    kind: str
    namespace: Optional[str] = None
    internal: bool = False
    auth_value: Optional[_Token] = None
    auth_user_file: Optional[_Token] = None
    mappings: list = field(default_factory=list)


def _finding_id(
    source_path: str,
    kind: WebConfigFindingKind,
    value: str,
    namespace: Optional[str],
    qualifier: Optional[str],
    related_value: Optional[str],
    source_construct: str,
) -> str:
    payload = json.dumps(
        {
            "kind": kind.value,
            "namespace": namespace,
            "qualifier": qualifier,
            "related_value": related_value,
            "source_construct": source_construct,
            "source_path": source_path,
            "value": value,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "web-config:{}".format(hashlib.sha256(payload).hexdigest())


def _empty_result(
    source: SourceArtifactEntry,
    status: CoverageStatus,
    processed_bytes: int,
    detected_format: Optional[str],
    code: str,
    message: str,
) -> WebConfigProducerResult:
    return WebConfigProducerResult(
        source_path=source.canonical_path,
        coverage_status=status,
        processed_bytes=processed_bytes,
        producer=_PRODUCER,
        detected_format=detected_format,
        findings=(),
        evidence_atoms=(),
        diagnostics=(WebConfigDiagnostic(code, message),),
    )


def _detect_format(path: str, text: str) -> Optional[str]:
    basename = posixpath.basename(path).lower()
    normalized = path.lower()
    static_text = re.sub(r"<\?.*?\?>", "", text, flags=re.DOTALL)
    if (
        normalized == "etc/config/uhttpd"
        and re.search(r"(?m)^\s*config\s+uhttpd(?:\s|$)", text)
    ):
        return "uci_uhttpd"
    if basename in {"lighttpd.conf", "lighttp.conf"} or (
        "lighttp" in normalized
        and re.search(r"(?m)^\s*server\.(?:port|document-root)\s*=", text)
    ):
        return "lighttpd"
    if "nginx" in normalized and (
        basename.endswith(".conf") or basename == "nginx.conf"
    ):
        return "nginx"
    if basename.endswith(".sh") or normalized.startswith("etc/init.d/"):
        return "posix_shell"
    if (
        "/templates/httpd/" in "/{}".format(normalized)
        and re.search(r"(?m)^\s*Control\s*\{", static_text)
        and re.search(r"(?m)^\s*Alias\s+/", static_text)
        and re.search(r"(?m)^\s*Location\s+/", static_text)
    ):
        return "proprietary_httpd"
    if re.search(r"(?m)^\s*(?:http|server|events)\s*\{", text):
        return "nginx"
    if text.startswith("#!") or text.startswith("#/bin/sh"):
        return "posix_shell"
    return None


def _lighttpd_namespace(expression: str) -> Optional[str]:
    literals = re.findall(r"/(?:[A-Za-z0-9._~-]+/)+", expression)
    return literals[-1] if literals else None


def _parse_lighttpd(
    source: SourceArtifactEntry, content: bytes, policy: WebConfigPolicy
) -> tuple:
    findings = []
    evidence_atoms = {}
    namespaces = []
    cursor = 0
    for raw_line in content.splitlines(keepends=True):
        line = raw_line.decode("utf-8")
        stripped = re.sub(r"#.*$", "", line).strip()
        url_scope = re.search(
            r'^\$HTTP\[\s*["\']url["\']\s*\]\s*=~\s*["\'](.+?)["\']\s*\{',
            stripped,
        )
        if url_scope is not None:
            namespaces.append(_lighttpd_namespace(url_scope.group(1)))
            cursor += len(raw_line)
            continue
        socket = re.search(
            r'^\$SERVER\[\s*["\']socket["\']\s*\]\s*==\s*["\'](?:[^"\']*:)?(\d+)["\']',
            stripped,
        )
        if socket is not None:
            token = _line_token(content, cursor, socket.group(1))
            _publish(
                source, content, findings, evidence_atoms,
                WebConfigFindingKind.LISTENER, socket.group(1), token,
                "listens_on", source_construct="lighttpd.socket",
            )
            cursor += len(raw_line)
            continue
        port = re.match(r"^server\.port\s*=\s*(\d+)", stripped)
        if port is not None:
            token = _line_token(content, cursor, port.group(1))
            _publish(
                source, content, findings, evidence_atoms,
                WebConfigFindingKind.LISTENER, port.group(1), token,
                "listens_on", source_construct="lighttpd.server.port",
            )
        root = re.match(
            r'^server\.document-root\s*=\s*["\']([^"\']+)["\']', stripped
        )
        if root is not None:
            token = _line_token(content, cursor, root.group(1))
            _publish(
                source, content, findings, evidence_atoms,
                WebConfigFindingKind.DOCUMENT_ROOT, root.group(1), token,
                "maps_namespace", namespace="/",
                source_construct="lighttpd.server.document-root",
            )
        if re.match(r"^cgi\.assign\s*=", stripped) and namespaces:
            namespace = namespaces[-1]
            if namespace is not None:
                token = _line_token(content, cursor, "cgi.assign")
                _publish(
                    source, content, findings, evidence_atoms,
                    WebConfigFindingKind.NAMESPACE_MAPPING, "cgi", token,
                    "binds_handler", namespace=namespace,
                    qualifier="cgi_executor", source_construct="lighttpd.cgi.assign",
                )
        if stripped.startswith("}") and namespaces:
            namespaces.pop()
        cursor += len(raw_line)
        if len(findings) >= policy.max_findings:
            return findings, evidence_atoms, (
                WebConfigDiagnostic(
                    "finding_budget_exceeded",
                    "finding budget truncated lighttpd analysis",
                ),
            )
    return findings, evidence_atoms, ()


def _nginx_tokens(content: bytes) -> Tuple[_Token, ...]:
    tokens = []
    index = 0
    punctuation = {
        ord("{"): "brace_open",
        ord("}"): "brace_close",
        ord(";"): "semicolon",
    }
    while index < len(content):
        byte = content[index]
        if byte in b" \t\r\n":
            index += 1
            continue
        if byte == ord("#"):
            newline = content.find(b"\n", index + 1)
            index = len(content) if newline < 0 else newline + 1
            continue
        if byte in punctuation:
            tokens.append(_Token(chr(byte), index, index + 1, punctuation[byte]))
            index += 1
            continue
        if byte in (ord('"'), ord("'")):
            quote = byte
            start = index + 1
            index += 1
            while index < len(content) and content[index] != quote:
                if content[index] == ord("\\") and index + 1 < len(content):
                    index += 2
                else:
                    index += 1
            end = index
            value = content[start:end].decode("utf-8")
            tokens.append(_Token(value, start, end))
            index = min(index + 1, len(content))
            continue
        start = index
        while index < len(content):
            current = content[index]
            if current in b" \t\r\n{};#":
                break
            index += 1
        tokens.append(_Token(content[start:index].decode("utf-8"), start, index))
    return tuple(tokens)


def _nearest_location(blocks: list) -> Optional[_Block]:
    for block in reversed(blocks):
        if block.kind == "location":
            return block
    return None


def _nearest_configuration_scope(blocks: list) -> Optional[_Block]:
    for block in reversed(blocks):
        if block.kind in {"location", "server"}:
            return block
    return None


def _publish(
    source: SourceArtifactEntry,
    content: bytes,
    findings: list,
    evidence_atoms: dict,
    kind: WebConfigFindingKind,
    value: str,
    token: _Token,
    capability: str,
    namespace: Optional[str] = None,
    qualifier: Optional[str] = None,
    related_value: Optional[str] = None,
    source_construct: str = "",
    observation_kind: ObservationKind = ObservationKind.DIRECT_STATIC,
    extra_tokens: tuple = (),
) -> None:
    finding_id = _finding_id(
        source.canonical_path, kind, value, namespace, qualifier,
        related_value, source_construct,
    )
    evidence_ids = []
    for index, evidence_token in enumerate((token, *extra_tokens)):
        object_value = evidence_token.value
        predicate = capability if index == 0 else "configures_{}".format(capability)
        atom = capture_evidence(
            source=source,
            content=content,
            selection=SpanSelection(
                SpanKind.TEXT_UTF8, evidence_token.start, evidence_token.end
            ),
            claim=EvidenceClaim(
                subject_ref=finding_id,
                predicate=predicate,
                object_value=object_value,
                observation_kind=(
                    observation_kind
                    if index == 0
                    else ObservationKind.DIRECT_STATIC
                ),
                capability=capability,
                confidence=1.0,
            ),
            producer=_PRODUCER,
        )
        evidence_atoms[atom.evidence_id] = atom
        evidence_ids.append(atom.evidence_id)
    finding = WebConfigFinding(
        finding_id=finding_id,
        kind=kind,
        value=value,
        namespace=namespace,
        qualifier=qualifier,
        related_value=related_value,
        source_construct=source_construct,
        evidence_ids=tuple(evidence_ids),
    )
    for index, existing in enumerate(findings):
        if existing.finding_id != finding_id:
            continue
        findings[index] = WebConfigFinding(
            finding_id=existing.finding_id,
            kind=existing.kind,
            value=existing.value,
            namespace=existing.namespace,
            qualifier=existing.qualifier,
            related_value=existing.related_value,
            source_construct=existing.source_construct,
            evidence_ids=tuple(dict.fromkeys(
                (*existing.evidence_ids, *finding.evidence_ids)
            )),
        )
        return
    findings.append(finding)


def _parse_nginx(
    source: SourceArtifactEntry, content: bytes, policy: WebConfigPolicy
) -> tuple:
    tokens = _nginx_tokens(content)
    blocks = []
    pending = []
    findings = []
    evidence_atoms = {}

    def process_statement(statement: list) -> None:
        if not statement:
            return
        directive = statement[0].value
        arguments = statement[1:]
        location = _nearest_location(blocks)
        scope = _nearest_configuration_scope(blocks)
        namespace = scope.namespace if scope else None
        if directive == "listen" and arguments:
            _publish(source, content, findings, evidence_atoms,
                     WebConfigFindingKind.LISTENER, arguments[0].value,
                     arguments[0], "listens_on", source_construct="nginx.listen")
        elif directive == "root" and arguments:
            _publish(source, content, findings, evidence_atoms,
                     WebConfigFindingKind.DOCUMENT_ROOT, arguments[0].value,
                     arguments[0], "maps_namespace", namespace=namespace,
                     source_construct="nginx.root")
        elif (
            directive in {"alias", "fastcgi_pass", "proxy_pass"}
            and arguments
            and namespace
        ):
            if location:
                location.mappings.append((directive, arguments[0]))
        elif directive == "internal" and location:
            location.internal = True
        elif directive == "auth_basic" and arguments and scope:
            scope.auth_value = arguments[0]
        elif directive == "auth_basic_user_file" and arguments and scope:
            scope.auth_user_file = arguments[0]

    def close_block(block: _Block) -> None:
        for directive, argument in block.mappings:
            qualifier = {
                "alias": "internal_alias" if block.internal else "alias",
                "fastcgi_pass": "fastcgi",
                "proxy_pass": "reverse_proxy",
            }[directive]
            _publish(
                source,
                content,
                findings,
                evidence_atoms,
                WebConfigFindingKind.NAMESPACE_MAPPING,
                argument.value,
                argument,
                "maps_namespace",
                namespace=block.namespace,
                qualifier=qualifier,
                source_construct="nginx.{}".format(directive),
            )
        if block.kind not in {"location", "server"} or block.auth_value is None:
            return
        raw = block.auth_value.value
        value = "off" if raw.lower() == "off" else "basic"
        related = block.auth_user_file.value if block.auth_user_file else None
        extras = (block.auth_user_file,) if block.auth_user_file else ()
        _publish(source, content, findings, evidence_atoms,
                 WebConfigFindingKind.AUTH_REQUIREMENT, value,
                 block.auth_value, "requires_auth", namespace=block.namespace,
                 related_value=related, source_construct="nginx.auth_basic",
                 extra_tokens=extras)

    for token in tokens:
        if token.kind == "semicolon":
            process_statement(pending)
            pending = []
        elif token.kind == "brace_open":
            kind = pending[0].value if pending else "anonymous"
            namespace = "/" if kind == "server" else None
            if kind == "location" and len(pending) >= 2:
                namespace = pending[-1].value
            blocks.append(_Block(kind=kind, namespace=namespace))
            pending = []
        elif token.kind == "brace_close":
            process_statement(pending)
            pending = []
            if blocks:
                close_block(blocks.pop())
        else:
            pending.append(token)
        if len(findings) >= policy.max_findings:
            return findings, evidence_atoms, (
                WebConfigDiagnostic(
                    "finding_budget_exceeded",
                    "finding budget truncated nginx analysis",
                ),
            )
    process_statement(pending)
    while blocks:
        close_block(blocks.pop())
    return findings, evidence_atoms, ()


def _line_token(
    content: bytes, line_start: int, value: str, search_start: int = 0
) -> _Token:
    encoded = value.encode("utf-8")
    offset = content.find(encoded, line_start + search_start)
    return _Token(value, offset, offset + len(encoded))


def _parse_uci_uhttpd(
    source: SourceArtifactEntry, content: bytes, policy: WebConfigPolicy
) -> tuple:
    directives = []
    cursor = 0
    for raw_line in content.splitlines(keepends=True):
        line = raw_line.decode("utf-8")
        try:
            words = shlex.split(line, comments=True, posix=True)
        except ValueError:
            words = []
        if len(words) >= 3 and words[0] in {"list", "option"}:
            directives.append((words[0], words[1], words[2], cursor))
        cursor += len(raw_line)

    findings = []
    evidence_atoms = {}
    document_root = next(
        (value for _, key, value, _ in directives if key == "home"), None
    )
    for directive, key, value, line_start in directives:
        token = _line_token(content, line_start, value)
        if directive == "list" and key in {"listen_http", "listen_https"}:
            _publish(
                source, content, findings, evidence_atoms,
                WebConfigFindingKind.LISTENER, value, token, "listens_on",
                qualifier="https" if key == "listen_https" else "http",
                related_value="uhttpd",
                source_construct="uci_uhttpd.{}".format(key),
            )
        elif directive == "option" and key == "home":
            _publish(
                source, content, findings, evidence_atoms,
                WebConfigFindingKind.DOCUMENT_ROOT, value, token,
                "maps_namespace", namespace="/",
                source_construct="uci_uhttpd.home",
            )
        elif directive == "option" and key == "cgi_prefix":
            _publish(
                source, content, findings, evidence_atoms,
                WebConfigFindingKind.NAMESPACE_MAPPING, "cgi", token,
                "maps_namespace", namespace=value, qualifier="cgi_executor",
                related_value=document_root,
                source_construct="uci_uhttpd.cgi_prefix",
            )
        elif directive == "list" and key == "lua_prefix" and "=" in value:
            namespace, handler = value.split("=", 1)
            handler_token = _line_token(content, line_start, handler)
            namespace_token = _line_token(content, line_start, namespace)
            _publish(
                source, content, findings, evidence_atoms,
                WebConfigFindingKind.NAMESPACE_MAPPING, handler, handler_token,
                "binds_handler", namespace=namespace, qualifier="lua_handler",
                source_construct="uci_uhttpd.lua_prefix",
                extra_tokens=(namespace_token,),
            )
        if len(findings) >= policy.max_findings:
            return findings, evidence_atoms, (
                WebConfigDiagnostic(
                    "finding_budget_exceeded",
                    "finding budget truncated UCI uhttpd analysis",
                ),
            )
    return findings, evidence_atoms, ()


def _parse_shell(
    source: SourceArtifactEntry, content: bytes, policy: WebConfigPolicy
) -> tuple:
    findings = []
    evidence_atoms = {}
    cursor = 0
    for raw_line in content.splitlines(keepends=True):
        line = raw_line.decode("utf-8")
        try:
            words = shlex.split(line, comments=True, posix=True)
        except ValueError:
            cursor += len(raw_line)
            continue
        if not words:
            cursor += len(raw_line)
            continue
        command = posixpath.basename(words[0])
        if command == "nginx":
            prefix = None
            if "-p" in words and words.index("-p") + 1 < len(words):
                prefix = words[words.index("-p") + 1]
            token = _line_token(content, cursor, words[0])
            _publish(source, content, findings, evidence_atoms,
                     WebConfigFindingKind.SERVICE_START, "nginx", token,
                     "starts", related_value=prefix,
                     source_construct="posix_shell.nginx")
        elif command == "spawn-fcgi":
            address = None
            port = None
            if "-a" in words and words.index("-a") + 1 < len(words):
                address = words[words.index("-a") + 1]
            if "-p" in words and words.index("-p") + 1 < len(words):
                port = words[words.index("-p") + 1]
            executable = next(
                (
                    word
                    for word in reversed(words[1:])
                    if not word.startswith("-") and word not in {address, port}
                ),
                None,
            )
            if executable and address and port:
                endpoint = "{}:{}".format(address, port)
                executable_token = _line_token(content, cursor, executable)
                _publish(source, content, findings, evidence_atoms,
                         WebConfigFindingKind.SERVICE_START, executable,
                         executable_token, "starts", related_value=endpoint,
                         qualifier="fastcgi", source_construct="posix_shell.spawn-fcgi")
                line_token = _Token(
                    line.rstrip("\r\n"),
                    cursor,
                    cursor + len(raw_line.rstrip(b"\r\n")),
                )
                _publish(source, content, findings, evidence_atoms,
                         WebConfigFindingKind.LISTENER, endpoint, line_token,
                         "listens_on", qualifier="fastcgi",
                         related_value=executable,
                         source_construct="posix_shell.spawn-fcgi",
                         observation_kind=ObservationKind.DETERMINISTIC_DERIVED)
        cursor += len(raw_line)
        if len(findings) >= policy.max_findings:
            return findings, evidence_atoms, (
                WebConfigDiagnostic(
                    "finding_budget_exceeded",
                    "finding budget truncated shell analysis",
                ),
            )
    return findings, evidence_atoms, ()


def _mask_httpd_dynamic_regions(content: bytes) -> bytes:
    masked = bytearray(content)
    for pattern in (rb"<\?.*?\?>", rb"/\*.*?\*/", rb"//[^\r\n]*"):
        for match in re.finditer(pattern, content, flags=re.DOTALL):
            for index in range(match.start(), match.end()):
                if masked[index] not in (10, 13):
                    masked[index] = 32
    return bytes(masked)


def _parse_proprietary_httpd(
    source: SourceArtifactEntry, content: bytes, policy: WebConfigPolicy
) -> tuple:
    """Parse static Control blocks without evaluating embedded template PHP."""

    masked = _mask_httpd_dynamic_regions(content)
    findings = []
    evidence_atoms = {}
    stack = []
    cursor = 0

    def nearest_control():
        return next(
            (item for item in reversed(stack) if item["kind"] == "control"),
            None,
        )

    def publish_control(control) -> None:
        alias = control.get("alias")
        location = control.get("location")
        if alias is not None and location is not None:
            _publish(
                source, content, findings, evidence_atoms,
                WebConfigFindingKind.NAMESPACE_MAPPING,
                location.value, location, "maps_namespace",
                namespace=alias.value, qualifier="alias",
                source_construct="proprietary_httpd.alias_location",
                extra_tokens=(alias,),
            )
        if alias is None:
            return
        for executable, extensions in control["external"]:
            _publish(
                source, content, findings, evidence_atoms,
                WebConfigFindingKind.NAMESPACE_MAPPING,
                executable.value, executable, "binds_handler",
                namespace=alias.value, qualifier="external_handler",
                related_value=extensions.value,
                source_construct="proprietary_httpd.external",
                extra_tokens=(alias, extensions),
            )

    for raw_line in masked.splitlines(keepends=True):
        line = raw_line.decode("utf-8")
        control = nearest_control()
        external_active = bool(stack and stack[-1]["kind"] == "external")
        handler_match = None
        if external_active:
            handler_match = re.match(
                r"^\s*(/\S+)\s*\{\s*([^{}]+?)\s*\}\s*$", line
            )
        if handler_match is not None and control is not None:
            executable = _Token(
                handler_match.group(1),
                cursor + handler_match.start(1),
                cursor + handler_match.end(1),
            )
            extensions = _Token(
                handler_match.group(2).strip(),
                cursor + handler_match.start(2),
                cursor + handler_match.end(2),
            )
            control["external"].append((executable, extensions))
            cursor += len(raw_line)
            continue

        if control is not None and not external_active:
            for key, directive in (("alias", "Alias"), ("location", "Location")):
                match = re.match(r"^\s*{}\s+(\S+)\s*$".format(directive), line)
                if match is not None:
                    control[key] = _Token(
                        match.group(1),
                        cursor + match.start(1),
                        cursor + match.end(1),
                    )

        opening = re.match(r"^\s*([A-Za-z][\w-]*)\s*\{\s*$", line)
        if opening is not None:
            kind = opening.group(1).lower()
            entry = {"kind": kind}
            if kind == "control":
                entry.update(alias=None, location=None, external=[])
            stack.append(entry)

        closing = re.match(r"^\s*(}+)", line)
        for _ in range(len(closing.group(1)) if closing is not None else 0):
            if not stack:
                break
            closed = stack.pop()
            if closed["kind"] == "control":
                publish_control(closed)
        cursor += len(raw_line)
        if len(findings) > policy.max_findings:
            return findings, evidence_atoms, (
                WebConfigDiagnostic(
                    "finding_budget_exceeded",
                    "finding budget truncated proprietary httpd analysis",
                ),
            )
    while stack:
        closed = stack.pop()
        if closed["kind"] == "control":
            publish_control(closed)
    return findings, evidence_atoms, ()


def discover_web_configuration(
    source: SourceArtifactEntry,
    content: bytes,
    policy: WebConfigPolicy = WebConfigPolicy(),
) -> WebConfigProducerResult:
    """Discover replayable web-server configuration facts from one source."""

    if len(content) > policy.max_source_bytes:
        return _empty_result(source, CoverageStatus.SKIPPED_BY_POLICY, 0, None,
                             "source_budget_exceeded", "source exceeds configured byte budget")
    if source.kind not in {"file", "hardlink", "archive", "archive_member"}:
        return _empty_result(source, CoverageStatus.FAILED, 0, None,
                             "unsupported_source_kind", "source kind cannot publish content evidence")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return _empty_result(source, CoverageStatus.FAILED, 0, None,
                             "invalid_utf8", "supported web configuration formats require UTF-8")
    if len(content) != source.size or hashlib.sha256(content).hexdigest() != source.content_sha256:
        return _empty_result(source, CoverageStatus.FAILED, 0, None,
                             "source_mismatch", "content does not match source inventory")

    detected_format = _detect_format(source.canonical_path, text)
    if detected_format is None:
        return _empty_result(source, CoverageStatus.NOT_APPLICABLE, len(content), None,
                             "unsupported_format", "source does not match a declared web configuration format")
    if detected_format == "lighttpd":
        findings, evidence_atoms, diagnostics = _parse_lighttpd(
            source, content, policy
        )
    elif detected_format == "nginx":
        findings, evidence_atoms, diagnostics = _parse_nginx(source, content, policy)
    elif detected_format == "uci_uhttpd":
        findings, evidence_atoms, diagnostics = _parse_uci_uhttpd(
            source, content, policy
        )
    elif detected_format == "proprietary_httpd":
        findings, evidence_atoms, diagnostics = _parse_proprietary_httpd(
            source, content, policy
        )
    else:
        findings, evidence_atoms, diagnostics = _parse_shell(source, content, policy)
    if len(findings) > policy.max_findings:
        findings = findings[: policy.max_findings]
        retained_ids = {
            evidence_id for finding in findings for evidence_id in finding.evidence_ids
        }
        evidence_atoms = {
            evidence_id: atom
            for evidence_id, atom in evidence_atoms.items()
            if evidence_id in retained_ids
        }
        if not diagnostics:
            diagnostics = (
                WebConfigDiagnostic(
                    "finding_budget_exceeded",
                    "finding budget truncated configuration analysis",
                ),
            )
    return WebConfigProducerResult(
        source_path=source.canonical_path,
        coverage_status=CoverageStatus.PARTIAL if diagnostics else CoverageStatus.COMPLETED,
        processed_bytes=len(content),
        producer=_PRODUCER,
        detected_format=detected_format,
        findings=tuple(findings),
        evidence_atoms=tuple(evidence_atoms.values()),
        diagnostics=tuple(diagnostics),
    )
