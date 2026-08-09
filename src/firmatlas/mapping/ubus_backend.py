"""Evidence-backed LuCI/ubus backend ownership and access-policy mapping."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import fnmatch
import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Optional, Tuple

from .domain import (
    AnalyzerIdentity,
    CoverageStatus,
    EvidenceAtom,
    ObligationStatus,
    ObservationKind,
    SpanKind,
    UnresolvedObligation,
)
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry
from .frontend import FrontendProducerResult


UBUS_BACKEND_RESULT_SCHEMA_VERSION = "firmatlas.mapping.ubus-backend/v1alpha1"
_PRODUCER = AnalyzerIdentity("ubus-backend-producer", "0.1.0")


class UbusPrincipalKind(str, Enum):
    RPCD_EXEC_PLUGIN = "rpcd_exec_plugin"
    RPCD_NATIVE_PLUGIN = "rpcd_native_plugin"


class UbusBackendBindingStatus(str, Enum):
    STATIC_PLUGIN_DISPATCH = "static_plugin_dispatch"
    NATIVE_PLUGIN_CANDIDATE = "native_plugin_candidate"


class UbusAccessMode(str, Enum):
    READ = "read"
    WRITE = "write"


@dataclass(frozen=True)
class UbusArtifactInput:
    source: SourceArtifactEntry
    content: bytes


@dataclass(frozen=True)
class UbusOperationReference:
    operation_ref: str
    object_name: str
    method_name: str
    evidence_ids: Tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.operation_ref.strip():
            raise ValueError("ubus operation reference requires an identity")
        if not self.object_name.strip() or not self.method_name.strip():
            raise ValueError("ubus operation requires object and method names")

    @property
    def logical_operation(self) -> str:
        return "ubus://{}/{}".format(self.object_name, self.method_name)


@dataclass(frozen=True)
class UbusBackendPrincipal:
    principal_id: str
    artifact_path: str
    principal_kind: UbusPrincipalKind
    object_names: Tuple[str, ...]
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class UbusBackendBinding:
    binding_id: str
    operation_ref: str
    logical_operation: str
    principal_id: str
    status: UbusBackendBindingStatus
    parameter_names: Tuple[str, ...]
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class UbusAccessGrant:
    grant_id: str
    operation_ref: str
    logical_operation: str
    policy_group: str
    access_mode: UbusAccessMode
    object_pattern: str
    source_path: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class UbusBackendDiagnostic:
    code: str
    message: str
    source_path: Optional[str] = None


@dataclass(frozen=True)
class UbusBackendGraphResult:
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    principals: Tuple[UbusBackendPrincipal, ...]
    bindings: Tuple[UbusBackendBinding, ...]
    access_grants: Tuple[UbusAccessGrant, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    open_obligations: Tuple[UnresolvedObligation, ...]
    diagnostics: Tuple[UbusBackendDiagnostic, ...] = ()
    schema_version: str = UBUS_BACKEND_RESULT_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "coverage_status": self.coverage_status.value,
            "processed_bytes": self.processed_bytes,
            "producer": asdict(self.producer),
            "principals": [
                {**asdict(item), "principal_kind": item.principal_kind.value}
                for item in self.principals
            ],
            "bindings": [
                {**asdict(item), "status": item.status.value}
                for item in self.bindings
            ],
            "access_grants": [
                {**asdict(item), "access_mode": item.access_mode.value}
                for item in self.access_grants
            ],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
            "open_obligations": [
                {**asdict(item), "status": item.status.value}
                for item in self.open_obligations
            ],
            "diagnostics": [asdict(item) for item in self.diagnostics],
        }


def ubus_operation_references_from_frontend(
    results: Tuple[FrontendProducerResult, ...],
) -> Tuple[UbusOperationReference, ...]:
    """Adapt published LuCI frontend candidates into backend graph references."""

    operations = {}
    for result in results:
        for candidate in result.candidates:
            if not candidate.endpoint.startswith("ubus://"):
                continue
            remainder = candidate.endpoint[len("ubus://"):]
            object_name, separator, method_name = remainder.partition("/")
            if not separator or not object_name or not method_name:
                continue
            operation = UbusOperationReference(
                candidate.candidate_id,
                object_name,
                method_name,
                candidate.evidence_ids,
            )
            existing = operations.get(operation.operation_ref)
            if existing is not None and existing != operation:
                raise ValueError("conflicting frontend ubus operation identity")
            operations[operation.operation_ref] = operation
    return tuple(operations[key] for key in sorted(operations))


def _stable_id(prefix: str, *values: str) -> str:
    payload = json.dumps(values, separators=(",", ":"), ensure_ascii=False)
    return "{}:{}".format(prefix, hashlib.sha256(payload.encode()).hexdigest())


def _verify_artifact(value: UbusArtifactInput) -> None:
    source = value.source
    if source.kind not in {"file", "hardlink", "archive_member"}:
        raise ValueError("ubus backend source must be readable content")
    if source.content_sha256 is None:
        raise ValueError("ubus backend source requires a content SHA-256")
    if len(value.content) != source.size:
        raise ValueError("ubus backend content size does not match inventory")
    if hashlib.sha256(value.content).hexdigest() != source.content_sha256:
        raise ValueError("ubus backend content digest does not match inventory")


def _capture(
    artifact: UbusArtifactInput,
    start: int,
    end: int,
    subject: str,
    predicate: str,
    object_value: str,
    capability: str,
    observation: ObservationKind = ObservationKind.DIRECT_STATIC,
    confidence: float = 1.0,
) -> EvidenceAtom:
    return capture_evidence(
        artifact.source,
        artifact.content,
        SpanSelection(
            SpanKind.TEXT_UTF8 if _is_utf8(artifact.content) else SpanKind.BINARY,
            start,
            end,
        ),
        EvidenceClaim(
            subject,
            predicate,
            object_value,
            observation,
            capability,
            confidence,
        ),
        _PRODUCER,
    )


def _is_utf8(content: bytes) -> bool:
    try:
        content.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def _lua_methods(content: bytes) -> dict:
    """Return top-level methods and statically named ``args`` keys."""

    text = content.decode("utf-8")
    start_match = re.search(r"\blocal\s+methods\s*=\s*\{", text)
    if start_match is None:
        return {}
    byte_offsets = [0]
    for character in text:
        byte_offsets.append(byte_offsets[-1] + len(character.encode("utf-8")))
    methods = {}
    depth = 1
    cursor = start_match.end()
    method_start = None
    method_name = None
    quote = None
    escaped = False
    while cursor < len(text) and depth > 0:
        character = text[cursor]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            cursor += 1
            continue
        if character in {'"', "'"}:
            quote = character
            cursor += 1
            continue
        if depth == 1 and method_name is None:
            match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{", text[cursor:])
            if match is not None:
                method_name = match.group(1)
                name_character_start = cursor + match.start(1)
                method_start = cursor + match.end() - 1
                depth += 1
                cursor = method_start + 1
                methods[method_name] = {
                    "name_start": byte_offsets[name_character_start],
                    "name_end": byte_offsets[name_character_start + len(method_name)],
                    "block_start": byte_offsets[method_start],
                }
                continue
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if method_name is not None and depth == 1:
                block_end = byte_offsets[cursor + 1]
                block = content[methods[method_name]["block_start"]:block_end]
                args_match = re.search(rb"\bargs\s*=\s*\{([^}]*)\}", block, re.DOTALL)
                parameters = ()
                if args_match is not None:
                    parameters = tuple(dict.fromkeys(
                        item.decode("utf-8")
                        for item in re.findall(
                            rb"\b([A-Za-z_][A-Za-z0-9_]*)\s*=",
                            args_match.group(1),
                        )
                    ))
                methods[method_name]["parameters"] = parameters
                method_name = None
                method_start = None
        cursor += 1
    return methods


def _object_matches(pattern: str, object_name: str) -> bool:
    concrete = object_name.replace("{dynamic}", "firmatlas-instance")
    return fnmatch.fnmatchcase(concrete, pattern)


def _plausible_native_object(path: str, object_name: str) -> bool:
    """Apply a conservative plugin-name prior before literal co-occurrence."""

    plugin_name = PurePosixPath(path).stem
    return object_name == plugin_name or object_name.startswith(plugin_name + "-")


def _acl_grants(
    artifact: UbusArtifactInput,
    operations: Tuple[UbusOperationReference, ...],
) -> tuple:
    try:
        document = json.loads(artifact.content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return (), (), UbusBackendDiagnostic(
            "ubus.acl_invalid_json",
            "rpcd ACL document could not be parsed as JSON",
            artifact.source.canonical_path,
        )
    grants = []
    atoms = []
    for policy_group, policy in document.items():
        if not isinstance(policy, dict):
            continue
        for mode in (UbusAccessMode.READ, UbusAccessMode.WRITE):
            section = policy.get(mode.value)
            ubus = section.get("ubus") if isinstance(section, dict) else None
            if not isinstance(ubus, dict):
                continue
            for object_pattern, methods in ubus.items():
                if not isinstance(methods, list):
                    continue
                for operation in operations:
                    if not _object_matches(object_pattern, operation.object_name):
                        continue
                    if operation.method_name not in methods and "*" not in methods:
                        continue
                    grant_id = _stable_id(
                        "ubus-access-grant",
                        operation.operation_ref,
                        policy_group,
                        mode.value,
                        object_pattern,
                        artifact.source.canonical_path,
                    )
                    method_literal = json.dumps(operation.method_name).encode()
                    method_start = artifact.content.find(method_literal)
                    if method_start < 0:
                        method_start = artifact.content.find(
                            operation.method_name.encode()
                        )
                        method_end = method_start + len(operation.method_name)
                    else:
                        method_start += 1
                        method_end = method_start + len(operation.method_name)
                    atom = _capture(
                        artifact,
                        method_start,
                        method_end,
                        grant_id,
                        "grants_access",
                        operation.method_name,
                        "maps_ubus_access_policy",
                    )
                    atoms.append(atom)
                    grants.append(UbusAccessGrant(
                        grant_id,
                        operation.operation_ref,
                        operation.logical_operation,
                        policy_group,
                        mode,
                        object_pattern,
                        artifact.source.canonical_path,
                        (atom.evidence_id,),
                    ))
    return tuple(grants), tuple(atoms), None


def discover_ubus_backend_graph(
    operations: Tuple[UbusOperationReference, ...],
    artifacts: Tuple[UbusArtifactInput, ...],
) -> UbusBackendGraphResult:
    """Map observed logical operations to static backend and ACL evidence.

    Lua rpcd exec plugins can support a static dispatch binding. Native plugin
    string evidence remains a candidate until a registration table or callsite
    adapter proves the object/method/handler relationship.
    """

    if len({item.operation_ref for item in operations}) != len(operations):
        raise ValueError("duplicate ubus operation reference")
    for artifact in artifacts:
        _verify_artifact(artifact)
    principals = {}
    bindings = {}
    grants = {}
    evidence = {}
    diagnostics = []
    bound = {item.operation_ref: [] for item in operations}

    for artifact in sorted(artifacts, key=lambda item: item.source.canonical_path):
        path = artifact.source.canonical_path
        if "/usr/share/rpcd/acl.d/" in "/{}".format(path) or path.startswith(
            "usr/share/rpcd/acl.d/"
        ):
            found, atoms, diagnostic = _acl_grants(artifact, operations)
            for item in found:
                grants[item.grant_id] = item
            for atom in atoms:
                evidence[atom.evidence_id] = atom
            if diagnostic is not None:
                diagnostics.append(diagnostic)
            continue

        if path.startswith("usr/libexec/rpcd/") and _is_utf8(artifact.content):
            methods = _lua_methods(artifact.content)
            if not methods or b'arg[1] == "list"' not in artifact.content or b'arg[1] == "call"' not in artifact.content:
                continue
            object_name = PurePosixPath(path).name
            principal_id = _stable_id("ubus-principal", path, object_name)
            marker_end = min(len(artifact.content), max(1, artifact.content.find(b"\n") + 1))
            principal_atom = _capture(
                artifact,
                0,
                marker_end,
                principal_id,
                "defines_runtime_principal",
                object_name,
                "identifies_rpcd_exec_plugin",
                ObservationKind.DETERMINISTIC_DERIVED,
                1.0,
            )
            evidence[principal_atom.evidence_id] = principal_atom
            for operation in operations:
                method = methods.get(operation.method_name)
                if operation.object_name != object_name or method is None:
                    continue
                binding_id = _stable_id(
                    "ubus-backend-binding", operation.operation_ref, principal_id
                )
                method_atom = _capture(
                    artifact,
                    method["name_start"],
                    method["name_end"],
                    binding_id,
                    "binds_operation",
                    operation.method_name,
                    "binds_ubus_exec_plugin_method",
                )
                evidence[method_atom.evidence_id] = method_atom
                bindings[binding_id] = UbusBackendBinding(
                    binding_id,
                    operation.operation_ref,
                    operation.logical_operation,
                    principal_id,
                    UbusBackendBindingStatus.STATIC_PLUGIN_DISPATCH,
                    method.get("parameters", ()),
                    (principal_atom.evidence_id, method_atom.evidence_id),
                )
                bound[operation.operation_ref].append(
                    UbusBackendBindingStatus.STATIC_PLUGIN_DISPATCH
                )
            principals[principal_id] = UbusBackendPrincipal(
                principal_id,
                path,
                UbusPrincipalKind.RPCD_EXEC_PLUGIN,
                (object_name,),
                (principal_atom.evidence_id,),
            )
            continue

        if path.startswith("usr/lib/rpcd/") and b"rpc_plugin" in artifact.content:
            matched_operations = []
            for operation in operations:
                if not _plausible_native_object(path, operation.object_name):
                    continue
                object_start = artifact.content.find(operation.object_name.encode())
                method_start = artifact.content.find(operation.method_name.encode())
                if object_start < 0 or method_start < 0:
                    continue
                matched_operations.append((operation, object_start, method_start))
            if not matched_operations:
                continue
            object_names = tuple(sorted({item[0].object_name for item in matched_operations}))
            principal_id = _stable_id("ubus-principal", path, *object_names)
            marker_start = artifact.content.find(b"rpc_plugin")
            marker_atom = _capture(
                artifact,
                marker_start,
                marker_start + len(b"rpc_plugin"),
                principal_id,
                "defines_runtime_principal",
                "rpc_plugin",
                "identifies_rpcd_native_plugin",
            )
            evidence[marker_atom.evidence_id] = marker_atom
            for operation, object_start, method_start in matched_operations:
                binding_id = _stable_id(
                    "ubus-backend-binding", operation.operation_ref, principal_id
                )
                object_atom = _capture(
                    artifact,
                    object_start,
                    object_start + len(operation.object_name.encode()),
                    binding_id,
                    "mentions_object",
                    operation.object_name,
                    "mentions_ubus_object",
                )
                method_atom = _capture(
                    artifact,
                    method_start,
                    method_start + len(operation.method_name.encode()),
                    binding_id,
                    "mentions_method",
                    operation.method_name,
                    "mentions_ubus_method",
                )
                for atom in (object_atom, method_atom):
                    evidence[atom.evidence_id] = atom
                bindings[binding_id] = UbusBackendBinding(
                    binding_id,
                    operation.operation_ref,
                    operation.logical_operation,
                    principal_id,
                    UbusBackendBindingStatus.NATIVE_PLUGIN_CANDIDATE,
                    (),
                    (marker_atom.evidence_id, object_atom.evidence_id, method_atom.evidence_id),
                )
                bound[operation.operation_ref].append(
                    UbusBackendBindingStatus.NATIVE_PLUGIN_CANDIDATE
                )
            principals[principal_id] = UbusBackendPrincipal(
                principal_id,
                path,
                UbusPrincipalKind.RPCD_NATIVE_PLUGIN,
                object_names,
                (marker_atom.evidence_id,),
            )

    obligations = []
    for operation in operations:
        statuses = bound[operation.operation_ref]
        if UbusBackendBindingStatus.STATIC_PLUGIN_DISPATCH in statuses:
            continue
        if UbusBackendBindingStatus.NATIVE_PLUGIN_CANDIDATE in statuses:
            capability = "resolve_ubus_registration_table"
            reason = (
                "Native rpcd plugin contains the object and method literals, but "
                "their registration-table and handler relationship is not proven."
            )
            analyzers = ("native-ubus-registration-adapter", "ghidra-adapter")
        else:
            capability = "resolve_ubus_runtime_owner"
            reason = (
                "No declared artifact scope statically binds this logical ubus "
                "operation to a runtime principal."
            )
            analyzers = (
                "rpcd-plugin-analyzer", "ubus-daemon-analyzer", "runtime-ubus-probe"
            )
        obligations.append(UnresolvedObligation(
            _stable_id("obligation", operation.operation_ref, capability),
            operation.operation_ref,
            capability,
            reason,
            80,
            analyzers,
            ObligationStatus.OPEN,
        ))

    coverage = (
        CoverageStatus.COMPLETED
        if not obligations and not diagnostics
        else CoverageStatus.PARTIAL
    )
    return UbusBackendGraphResult(
        coverage,
        sum(len(item.content) for item in artifacts),
        _PRODUCER,
        tuple(sorted(principals.values(), key=lambda item: item.principal_id)),
        tuple(sorted(bindings.values(), key=lambda item: item.binding_id)),
        tuple(sorted(grants.values(), key=lambda item: item.grant_id)),
        tuple(sorted(evidence.values(), key=lambda item: item.evidence_id)),
        tuple(sorted(obligations, key=lambda item: item.obligation_id)),
        tuple(diagnostics),
    )
