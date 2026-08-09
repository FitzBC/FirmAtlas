"""Deterministic cross-artifact proof of a statically assembled MIPS web service."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import posixpath
import struct
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
from .native_deep import (
    _ALLOC,
    _EXEC,
    _MIPS_MACHINE,
    _contains_address,
    _file_offset_for_address,
    _parse_elf,
    _read_dynamic_symbols,
    _word_at_address,
)
from .native_nested_dispatch import (
    _A0,
    _A1,
    _A2,
    _A3,
    _S0,
    _ZERO,
    _call_records,
    _constant_registers,
    _gp_value,
    _is_addiu,
    _is_move,
)
from .native_value_flow import _got_target_resolver, _read_ascii
from .web_config import (
    WebConfigFindingKind,
    discover_web_configuration,
)


MIPS_SERVICE_ASSEMBLY_RESULT_SCHEMA_VERSION = (
    "firmatlas.mapping.mips-service-assembly-result/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("native-mips-service-assembly", "0.1.0")
_CONTENT_KINDS = frozenset({"file", "hardlink", "archive", "archive_member"})


class StaticAssemblyStatus(str, Enum):
    PROVED = "proved"


@dataclass(frozen=True)
class ServiceAssemblyArtifact:
    source: SourceArtifactEntry
    content: bytes


@dataclass(frozen=True)
class MipsServiceAssemblyAnchor:
    target_ref: str
    request_path: str

    def __post_init__(self) -> None:
        if not self.target_ref.strip() or not self.request_path.startswith("/"):
            raise ValueError("service assembly anchor requires target and absolute path")
        if (
            any(character.isspace() for character in self.request_path)
            or ".." in self.request_path.split("/")
        ):
            raise ValueError("service assembly path must be canonical")


@dataclass(frozen=True)
class MipsServiceAssemblyProfile:
    name: str = "mips32-lighttpd-eval-argv-cgi/v1"
    launcher_path: str = "sbin/rc"
    bootstrap_symbol: str = "init_router"
    service_group_symbol: str = "start_services_once"
    launcher_symbol: str = "start_httpd"
    argument_copy_symbol: str = "memcpy"
    executor_symbol: str = "_eval"
    config_option: str = "-f"
    max_argument_bytes: int = 256

    def __post_init__(self) -> None:
        values = (
            self.name,
            self.launcher_path,
            self.bootstrap_symbol,
            self.service_group_symbol,
            self.launcher_symbol,
            self.argument_copy_symbol,
            self.executor_symbol,
            self.config_option,
        )
        if any(not value.strip() for value in values) or self.max_argument_bytes <= 0:
            raise ValueError("service assembly profile is invalid")


@dataclass(frozen=True)
class MipsServiceAssemblyPolicy:
    max_artifacts: int = 10_000
    max_anchors: int = 10_000
    max_total_bytes: int = 256 * 1024 * 1024
    max_instructions: int = 4_096
    max_assemblies: int = 10_000

    def __post_init__(self) -> None:
        if any(value <= 0 for value in (
            self.max_artifacts,
            self.max_anchors,
            self.max_total_bytes,
            self.max_instructions,
            self.max_assemblies,
        )):
            raise ValueError("service assembly budgets must be positive")


@dataclass(frozen=True)
class MipsServiceAssembly:
    assembly_id: str
    target_ref: str
    request_path: str
    assembly_status: StaticAssemblyStatus
    bootstrap_symbol: str
    bootstrap_identity: str
    bootstrap_address: int
    bootstrap_callsite: int
    service_group_symbol: str
    service_group_identity: str
    service_group_address: int
    service_group_callsite: int
    launcher_symbol: str
    launcher_identity: str
    launcher_address: int
    launch_callsite: int
    argument_table_address: int
    launch_arguments: Tuple[str, ...]
    executor_symbol: str
    server_artifact_path: str
    config_artifact_path: str
    listeners: Tuple[int, ...]
    document_root: str
    cgi_namespace: str
    target_artifact_path: str
    runtime_reachability_verified: bool
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class MipsServiceAssemblyDiagnostic:
    code: str
    message: str
    target_ref: Optional[str] = None


@dataclass(frozen=True)
class MipsServiceAssemblyResult:
    artifact_digests: Tuple[Tuple[str, str], ...]
    coverage_status: CoverageStatus
    producer: AnalyzerIdentity
    profile: str
    processed_instructions: int
    assemblies: Tuple[MipsServiceAssembly, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[MipsServiceAssemblyDiagnostic, ...] = ()
    schema_version: str = MIPS_SERVICE_ASSEMBLY_RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_result(self)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "artifact_digests": [
                {"path": path, "content_sha256": digest}
                for path, digest in self.artifact_digests
            ],
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "profile": self.profile,
            "processed_instructions": self.processed_instructions,
            "assemblies": [
                {
                    **asdict(item),
                    "assembly_status": item.assembly_status.value,
                    "launch_arguments": list(item.launch_arguments),
                    "listeners": list(item.listeners),
                    "evidence_ids": list(item.evidence_ids),
                }
                for item in self.assemblies
            ],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
            "diagnostics": [asdict(item) for item in self.diagnostics],
        }


def _validate_result(result: MipsServiceAssemblyResult) -> None:
    if result.schema_version != MIPS_SERVICE_ASSEMBLY_RESULT_SCHEMA_VERSION:
        raise ValueError("unsupported MIPS service assembly result schema")
    if not result.profile.strip() or result.processed_instructions < 0:
        raise ValueError("service assembly result metadata is invalid")
    source_digests = dict(result.artifact_digests)
    if len(source_digests) != len(result.artifact_digests):
        raise ValueError("duplicate service assembly artifact path")
    atoms = {item.evidence_id: item for item in result.evidence_atoms}
    if len(atoms) != len(result.evidence_atoms):
        raise ValueError("duplicate service assembly evidence identity")
    required = {
        "enters_service_bootstrap",
        "schedules_service_launcher",
        "defines_service_arguments",
        "orders_service_arguments",
        "invokes_service_launcher",
        "resolves_server_artifact",
        "loads_server_configuration",
        "exposes_listeners",
        "maps_document_root",
        "binds_cgi_namespace",
        "resolves_request_artifact",
    }
    identities = set()
    for item in result.assemblies:
        if item.assembly_id in identities:
            raise ValueError("duplicate service assembly identity")
        identities.add(item.assembly_id)
        if item.assembly_status is not StaticAssemblyStatus.PROVED:
            raise ValueError("service assembly result may publish proved paths only")
        if item.runtime_reachability_verified:
            raise ValueError("static service assembly cannot verify runtime reachability")
        expected_prefix = result.artifact_digests[0][0]
        if item.bootstrap_identity != "{}@0x{:08x}".format(
            expected_prefix, item.bootstrap_address
        ) or item.service_group_identity != "{}@0x{:08x}".format(
            expected_prefix, item.service_group_address
        ):
            raise ValueError("service assembly initialization identity is inconsistent")
        if item.launcher_identity != "{}@0x{:08x}".format(
            expected_prefix, item.launcher_address
        ):
            raise ValueError("service assembly launcher identity is inconsistent")
        if (
            len(item.launch_arguments) != 3
            or item.server_artifact_path != item.launch_arguments[0].lstrip("/")
            or item.config_artifact_path != item.launch_arguments[2].lstrip("/")
            or not item.listeners
            or tuple(sorted(set(item.listeners))) != item.listeners
            or not item.request_path.startswith(item.cgi_namespace)
            or item.target_artifact_path != posixpath.normpath(posixpath.join(
                item.document_root.lstrip("/"), item.request_path.lstrip("/")
            ))
        ):
            raise ValueError("service assembly path or argument relation is inconsistent")
        if len(item.evidence_ids) != len(required) or len(set(item.evidence_ids)) != len(required):
            raise ValueError("service assembly requires an eleven-part proof")
        by_capability = {}
        for evidence_id in item.evidence_ids:
            atom = atoms.get(evidence_id)
            if atom is None or atom.subject_ref != item.assembly_id:
                raise ValueError("service assembly references invalid evidence")
            if source_digests.get(
                atom.source_span.artifact_path
            ) != atom.source_span.artifact_sha256:
                raise ValueError("service assembly evidence source is inconsistent")
            if (atom.producer, atom.producer_version) != (
                result.producer.name,
                result.producer.version,
            ) or atom.confidence != 1.0:
                raise ValueError("service assembly proof must be deterministic")
            by_capability[atom.capability] = atom
        if set(by_capability) != required:
            raise ValueError("service assembly proof capabilities are incomplete")
        vector = "|".join(item.launch_arguments)
        expected_objects = {
            "enters_service_bootstrap": "{}->{}".format(
                item.bootstrap_symbol, item.service_group_symbol
            ),
            "schedules_service_launcher": "{}->{}".format(
                item.service_group_symbol, item.launcher_symbol
            ),
            "defines_service_arguments": vector,
            "orders_service_arguments": vector,
            "invokes_service_launcher": item.executor_symbol,
            "resolves_server_artifact": item.server_artifact_path,
            "loads_server_configuration": item.config_artifact_path,
            "exposes_listeners": "|".join(str(value) for value in item.listeners),
            "maps_document_root": item.document_root,
            "binds_cgi_namespace": item.cgi_namespace,
            "resolves_request_artifact": item.target_artifact_path,
        }
        if any(
            by_capability[capability].object_value != object_value
            for capability, object_value in expected_objects.items()
        ):
            raise ValueError("service assembly proof object is inconsistent")


def _empty(
    artifacts: Tuple[ServiceAssemblyArtifact, ...],
    profile: MipsServiceAssemblyProfile,
    status: CoverageStatus,
    code: str,
    message: str,
    processed: int = 0,
) -> MipsServiceAssemblyResult:
    return MipsServiceAssemblyResult(
        tuple(sorted(
            (item.source.canonical_path, item.source.content_sha256 or "")
            for item in artifacts
        )),
        status,
        _PRODUCER,
        profile.name,
        processed,
        (),
        (),
        (MipsServiceAssemblyDiagnostic(code, message),),
    )


def _binary_selection(elf, start: int, end: int) -> SpanSelection:
    start_offset = _file_offset_for_address(elf, start)
    end_offset = _file_offset_for_address(elf, end - 1)
    if start_offset is None or end_offset is None:
        raise ValueError("service assembly span is not file backed")
    return SpanSelection(SpanKind.BINARY, start_offset, end_offset + 1)


def _assessment_id(
    artifact_digests: Tuple[Tuple[str, str], ...],
    anchor: MipsServiceAssemblyAnchor,
) -> str:
    payload = json.dumps(
        (artifact_digests, anchor.target_ref, anchor.request_path),
        separators=(",", ":"),
    ).encode("utf-8")
    return "mips-service-assembly:" + hashlib.sha256(payload).hexdigest()


def _direct_call_records(words: tuple, base: int, symbols_by_address: dict) -> tuple:
    records = []
    for index, word in enumerate(words):
        if word >> 26 != 0x03:
            continue
        address = base + index * 4
        target = ((address + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        symbol = symbols_by_address.get(target)
        if symbol is not None:
            records.append((index, address, symbol))
    return tuple(records)


def _all_calls(words: tuple, base: int, gp: int, resolver, symbols: dict) -> tuple:
    calls = _call_records(words, base, gp, resolver)
    calls += _direct_call_records(words, base, symbols)
    return tuple(sorted(set(calls), key=lambda item: (item[0], item[2])))


def _capture(
    artifact: ServiceAssemblyArtifact,
    selection: SpanSelection,
    subject_ref: str,
    capability: str,
    object_value: str,
) -> EvidenceAtom:
    return capture_evidence(
        artifact.source,
        artifact.content,
        selection,
        EvidenceClaim(
            subject_ref,
            capability,
            object_value,
            ObservationKind.DETERMINISTIC_DERIVED,
            capability,
            1.0,
        ),
        _PRODUCER,
    )


def discover_mips_service_assembly(
    artifacts: Tuple[ServiceAssemblyArtifact, ...],
    anchors: Tuple[MipsServiceAssemblyAnchor, ...],
    profile: MipsServiceAssemblyProfile = MipsServiceAssemblyProfile(),
    policy: MipsServiceAssemblyPolicy = MipsServiceAssemblyPolicy(),
) -> MipsServiceAssemblyResult:
    """Prove launcher argv, server config, CGI namespace, and target artifact."""

    if len(artifacts) > policy.max_artifacts:
        return _empty(
            artifacts,
            profile,
            CoverageStatus.SKIPPED_BY_POLICY,
            "artifact_budget_exceeded",
            "artifacts exceed configured budget",
        )
    if len(anchors) > policy.max_anchors:
        return _empty(
            artifacts,
            profile,
            CoverageStatus.SKIPPED_BY_POLICY,
            "anchor_budget_exceeded",
            "anchors exceed configured budget",
        )
    if sum(len(item.content) for item in artifacts) > policy.max_total_bytes:
        return _empty(
            artifacts,
            profile,
            CoverageStatus.SKIPPED_BY_POLICY,
            "source_budget_exceeded",
            "artifact bytes exceed configured budget",
        )
    by_path = {}
    for artifact in artifacts:
        source = artifact.source
        if source.canonical_path in by_path:
            return _empty(
                artifacts,
                profile,
                CoverageStatus.FAILED,
                "duplicate_artifact_path",
                "artifact paths must be unique",
            )
        by_path[source.canonical_path] = artifact
        if (
            source.kind not in _CONTENT_KINDS
            or source.size != len(artifact.content)
            or source.content_sha256 != hashlib.sha256(artifact.content).hexdigest()
        ):
            return _empty(
                artifacts,
                profile,
                CoverageStatus.FAILED,
                "source_mismatch",
                "artifact content does not match source inventory",
            )
    artifact_digests = tuple(
        (path, by_path[path].source.content_sha256 or "")
        for path in sorted(by_path)
    )
    launcher = by_path.get(profile.launcher_path)
    if launcher is None:
        return _empty(
            artifacts,
            profile,
            CoverageStatus.PARTIAL,
            "launcher_missing",
            "profiled launcher artifact is unavailable",
        )

    try:
        elf = _parse_elf(launcher.content)
        if elf.pointer_size != 4 or elf.machine != _MIPS_MACHINE:
            return _empty(
                artifacts,
                profile,
                CoverageStatus.UNSUPPORTED,
                "unsupported_architecture",
                "adapter requires a MIPS32 launcher ELF",
            )
        symbols = tuple(
            symbol
            for table in _read_dynamic_symbols(elf, launcher.content).values()
            for symbol in table
            if symbol.name
        )
        by_name = {symbol.name: symbol for symbol in symbols}
        selected_names = (
            profile.bootstrap_symbol,
            profile.service_group_symbol,
            profile.launcher_symbol,
        )
        selected = tuple(by_name.get(name) for name in selected_names)
        if any(
            symbol is None
            or not symbol.size
            or not _contains_address(elf.sections, symbol.address, _ALLOC | _EXEC)
            for symbol in selected
        ):
            return _empty(
                artifacts,
                profile,
                CoverageStatus.PARTIAL,
                "launcher_symbol_unavailable",
                "profiled initialization functions are not bounded executable symbols",
            )
        words_by_name = {
            symbol.name: tuple(
                _word_at_address(
                    elf, launcher.content, symbol.address + index * 4
                )
                for index in range((symbol.size + 3) // 4)
            )
            for symbol in selected
        }
        if any(
            any(word is None for word in words)
            for words in words_by_name.values()
        ):
            raise ValueError("initialization function bytes are incomplete")
        processed = sum(len(words) for words in words_by_name.values())
        if processed > policy.max_instructions:
            return _empty(
                artifacts,
                profile,
                CoverageStatus.PARTIAL,
                "instruction_budget",
                "launcher function exceeds instruction budget",
                processed,
            )
        resolver = _got_target_resolver(elf, launcher.content)
        symbols_by_address = {
            symbol.address: symbol.name for symbol in symbols if symbol.address
        }
        calls_by_name = {}
        for symbol in selected:
            words = words_by_name[symbol.name]
            gp = _gp_value(words)
            if gp is None:
                return _empty(
                    artifacts,
                    profile,
                    CoverageStatus.PARTIAL,
                    "gp_setup_missing",
                    "profiled initialization function lacks GP setup",
                    processed,
                )
            calls_by_name[symbol.name] = _all_calls(
                words, symbol.address, gp, resolver, symbols_by_address
            )
        bootstrap, service_group, function = selected
        bootstrap_call = next((
            item for item in calls_by_name[profile.bootstrap_symbol]
            if item[2] == profile.service_group_symbol
        ), None)
        service_group_call = next((
            item for item in calls_by_name[profile.service_group_symbol]
            if item[2] == profile.launcher_symbol
        ), None)
        if bootstrap_call is None or service_group_call is None:
            return _empty(
                artifacts,
                profile,
                CoverageStatus.PARTIAL,
                "initialization_chain_not_proven",
                "bootstrap does not schedule the profiled service launcher",
                processed,
            )
        words = words_by_name[profile.launcher_symbol]
        calls = calls_by_name[profile.launcher_symbol]
        copy_call = next(
            (item for item in calls if item[2] == profile.argument_copy_symbol),
            None,
        )
        launch_call = next(
            (item for item in calls if item[2] == profile.executor_symbol),
            None,
        )
        if copy_call is None or launch_call is None or copy_call[0] >= launch_call[0]:
            return _empty(
                artifacts,
                profile,
                CoverageStatus.PARTIAL,
                "launch_calls_not_proven",
                "argument copy and service executor call are incomplete",
                processed,
            )
        copy_constants = _constant_registers(words, copy_call[0])
        table_address = copy_constants.get(_A1)
        table_bytes = copy_constants.get(_A2)
        launch_index, launch_callsite, _ = launch_call
        if (
            table_address is None
            or table_bytes is None
            or table_bytes < 16
            or table_bytes % 4
            or len(words) <= launch_index + 1
            or copy_call[0] < 2
            or launch_index < 4
            or not _is_addiu(words[6], _S0, 29, 24)
            or not _is_move(words[copy_call[0] - 2], _A0, _S0)
            or not _is_move(words[launch_index - 4], _A0, _S0)
            or not _is_move(words[launch_index - 3], _A1, _ZERO)
            or not _is_move(words[launch_index - 1], _A2, _ZERO)
            or not _is_move(words[launch_index + 1], _A3, _ZERO)
        ):
            return _empty(
                artifacts,
                profile,
                CoverageStatus.PARTIAL,
                "launch_argv_flow_not_proven",
                "argv table does not flow into the service executor",
                processed,
            )
        pointers = tuple(
            _word_at_address(elf, launcher.content, table_address + index * 4)
            for index in range(table_bytes // 4)
        )
        if any(pointer is None for pointer in pointers):
            raise ValueError("argv table bytes are incomplete")
        terminator = pointers.index(0) if 0 in pointers else -1
        if terminator < 3 or any(pointers[terminator:]):
            return _empty(
                artifacts,
                profile,
                CoverageStatus.PARTIAL,
                "launch_argv_not_terminated",
                "service argv is not a bounded null-terminated vector",
                processed,
            )
        argument_records = tuple(
            _read_ascii(
                elf,
                launcher.content,
                pointer,
                profile.max_argument_bytes,
            )
            for pointer in pointers[:terminator]
        )
        if any(record is None for record in argument_records):
            return _empty(
                artifacts,
                profile,
                CoverageStatus.PARTIAL,
                "launch_argument_not_proven",
                "service argv contains a nonliteral argument",
                processed,
            )
        arguments = tuple(record[0] for record in argument_records)
        if len(arguments) != 3 or arguments[1] != profile.config_option:
            return _empty(
                artifacts,
                profile,
                CoverageStatus.PARTIAL,
                "launch_argument_shape_not_proven",
                "service argv does not contain executable, config option, and config",
                processed,
            )
    except TypeError:
        return _empty(
            artifacts,
            profile,
            CoverageStatus.UNSUPPORTED,
            "unsupported_binary_format",
            "adapter supports ELF only",
        )
    except (ValueError, struct.error) as exc:
        return _empty(
            artifacts,
            profile,
            CoverageStatus.FAILED,
            "malformed_launcher",
            str(exc),
        )

    server_path = arguments[0].lstrip("/")
    config_path = arguments[2].lstrip("/")
    server = by_path.get(server_path)
    config = by_path.get(config_path)
    if server is None or config is None:
        return _empty(
            artifacts,
            profile,
            CoverageStatus.PARTIAL,
            "launch_artifact_missing",
            "launched server or selected configuration is unavailable",
            processed,
        )
    try:
        for artifact in (server,):
            selected_elf = _parse_elf(artifact.content)
            if selected_elf.pointer_size != 4 or selected_elf.machine != _MIPS_MACHINE:
                raise ValueError("launched server is not MIPS32 ELF")
    except (TypeError, ValueError, struct.error) as exc:
        return _empty(
            artifacts,
            profile,
            CoverageStatus.PARTIAL,
            "server_artifact_invalid",
            str(exc),
            processed,
        )

    config_result = discover_web_configuration(config.source, config.content)
    if config_result.coverage_status is not CoverageStatus.COMPLETED:
        return _empty(
            artifacts,
            profile,
            CoverageStatus.PARTIAL,
            "configuration_not_proven",
            "selected server configuration is not completely parsed",
            processed,
        )
    listeners = tuple(sorted({
        int(item.value)
        for item in config_result.findings
        if item.kind is WebConfigFindingKind.LISTENER
    }))
    root_finding = next((
        item for item in config_result.findings
        if item.kind is WebConfigFindingKind.DOCUMENT_ROOT
        and item.namespace == "/"
    ), None)
    namespace_finding = next((
        item for item in config_result.findings
        if item.kind is WebConfigFindingKind.NAMESPACE_MAPPING
        and item.qualifier == "cgi_executor"
        and any(anchor.request_path.startswith(item.namespace or "\0") for anchor in anchors)
    ), None)
    if not listeners or root_finding is None or namespace_finding is None:
        return _empty(
            artifacts,
            profile,
            CoverageStatus.PARTIAL,
            "cgi_configuration_not_proven",
            "listeners, document root, and CGI namespace are incomplete",
            processed,
        )
    config_atoms = {item.evidence_id: item for item in config_result.evidence_atoms}
    listener_atoms = tuple(
        config_atoms[evidence_id]
        for finding in config_result.findings
        if finding.kind is WebConfigFindingKind.LISTENER
        for evidence_id in finding.evidence_ids
    )
    root_atom = config_atoms[root_finding.evidence_ids[0]]
    namespace_atom = config_atoms[namespace_finding.evidence_ids[0]]

    assemblies = []
    evidence_atoms = []
    diagnostics = []
    literal_offsets = tuple(record[1] for record in argument_records)
    literal_start = min(literal_offsets)
    literal_end = max(
        offset + len(argument.encode("ascii")) + 1
        for offset, argument in zip(literal_offsets, arguments)
    )
    for anchor in sorted(set(anchors), key=lambda item: (item.target_ref, item.request_path)):
        if len(assemblies) >= policy.max_assemblies:
            diagnostics.append(MipsServiceAssemblyDiagnostic(
                "assembly_budget_exceeded",
                "assembly budget truncated static service analysis",
            ))
            break
        normalized = posixpath.normpath(
            posixpath.join(root_finding.value.lstrip("/"), anchor.request_path.lstrip("/"))
        )
        target = by_path.get(normalized)
        if target is None or not anchor.request_path.startswith(
            namespace_finding.namespace or "\0"
        ):
            diagnostics.append(MipsServiceAssemblyDiagnostic(
                "request_artifact_not_proven",
                "request path does not resolve through the configured CGI namespace",
                anchor.target_ref,
            ))
            continue
        try:
            target_elf = _parse_elf(target.content)
            if target_elf.pointer_size != 4 or target_elf.machine != _MIPS_MACHINE:
                raise ValueError("request artifact is not MIPS32 ELF")
        except (TypeError, ValueError, struct.error) as exc:
            diagnostics.append(MipsServiceAssemblyDiagnostic(
                "request_artifact_invalid", str(exc), anchor.target_ref
            ))
            continue
        relevant_digests = tuple(
            (path, by_path[path].source.content_sha256 or "")
            for path in (
                profile.launcher_path,
                server_path,
                config_path,
                normalized,
            )
        )
        identity = _assessment_id(relevant_digests, anchor)
        vector = "|".join(arguments)
        listener_span = SpanSelection(
            SpanKind.TEXT_UTF8,
            min(item.source_span.start_byte for item in listener_atoms),
            max(item.source_span.end_byte for item in listener_atoms),
        )
        specs = (
            (launcher, _binary_selection(
                elf, bootstrap_call[1] - 4, bootstrap_call[1] + 8
            ), "enters_service_bootstrap", "{}->{}".format(
                profile.bootstrap_symbol, profile.service_group_symbol
            )),
            (launcher, _binary_selection(
                elf, service_group_call[1] - 4, service_group_call[1] + 8
            ), "schedules_service_launcher", "{}->{}".format(
                profile.service_group_symbol, profile.launcher_symbol
            )),
            (launcher, SpanSelection(SpanKind.BINARY, literal_start, literal_end),
             "defines_service_arguments", vector),
            (launcher, _binary_selection(elf, table_address, table_address + table_bytes),
             "orders_service_arguments", vector),
            (launcher, _binary_selection(elf, launch_callsite - 16, launch_callsite + 8),
             "invokes_service_launcher", profile.executor_symbol),
            (server, SpanSelection(SpanKind.BINARY, 0, min(64, len(server.content))),
             "resolves_server_artifact", server_path),
            (config, SpanSelection(SpanKind.TEXT_UTF8, 0, min(64, len(config.content))),
             "loads_server_configuration", config_path),
            (config, listener_span, "exposes_listeners",
             "|".join(str(item) for item in listeners)),
            (config, SpanSelection(
                SpanKind.TEXT_UTF8,
                root_atom.source_span.start_byte,
                root_atom.source_span.end_byte,
            ), "maps_document_root", root_finding.value),
            (config, SpanSelection(
                SpanKind.TEXT_UTF8,
                namespace_atom.source_span.start_byte,
                namespace_atom.source_span.end_byte,
            ), "binds_cgi_namespace", namespace_finding.namespace or ""),
            (target, SpanSelection(SpanKind.BINARY, 0, min(64, len(target.content))),
             "resolves_request_artifact", normalized),
        )
        proof = tuple(
            _capture(artifact, selection, identity, capability, object_value)
            for artifact, selection, capability, object_value in specs
        )
        evidence_atoms.extend(proof)
        assemblies.append(MipsServiceAssembly(
            identity,
            anchor.target_ref,
            anchor.request_path,
            StaticAssemblyStatus.PROVED,
            profile.bootstrap_symbol,
            "{}@0x{:08x}".format(profile.launcher_path, bootstrap.address),
            bootstrap.address,
            bootstrap_call[1],
            profile.service_group_symbol,
            "{}@0x{:08x}".format(profile.launcher_path, service_group.address),
            service_group.address,
            service_group_call[1],
            profile.launcher_symbol,
            "{}@0x{:08x}".format(profile.launcher_path, function.address),
            function.address,
            launch_callsite,
            table_address,
            arguments,
            profile.executor_symbol,
            server_path,
            config_path,
            listeners,
            root_finding.value,
            namespace_finding.namespace or "",
            normalized,
            False,
            "elf.{}:static-service-assembly".format(profile.name),
            tuple(item.evidence_id for item in proof),
        ))

    ordered_digests = (
        (profile.launcher_path, by_path[profile.launcher_path].source.content_sha256 or ""),
        *((path, digest) for path, digest in artifact_digests if path != profile.launcher_path),
    )
    return MipsServiceAssemblyResult(
        tuple(ordered_digests),
        CoverageStatus.PARTIAL if diagnostics else CoverageStatus.COMPLETED,
        _PRODUCER,
        profile.name,
        processed,
        tuple(assemblies),
        tuple(evidence_atoms),
        tuple(diagnostics),
    )
