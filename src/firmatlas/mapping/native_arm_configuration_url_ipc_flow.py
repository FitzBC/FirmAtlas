"""Deterministic ARM URL-store IPC and business-consumer recovery."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import struct
from typing import Optional, Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry
from .native_arm_configuration_blob_flow import _call_symbol, _immediate, _word
from .native_arm_configuration_blob_flow import _pic_base
from .native_arm_configuration_text_import_flow import (
    _calls,
    _pic_literals,
    _stable_id,
    _symbol,
)
from .native_arm_xref import _function_start
from .native_cross_elf_call import ArmCrossElfArtifact, _function_end, _parse
from .native_deep import _parse_elf
from .native_deep import _read_route_literal


ARM_CONFIGURATION_URL_IPC_FLOW_SCHEMA_VERSION = (
    "firmatlas.mapping.arm-configuration-url-ipc-flow/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("native-arm-configuration-url-ipc-flow", "0.1.0")


@dataclass(frozen=True)
class ArmConfigurationUrlIpcArtifact:
    source: SourceArtifactEntry
    content: bytes


@dataclass(frozen=True)
class ArmConfigurationUrlIpcProfile:
    name: str = "arm32-cfm-url-ipc/v1"
    state_scope: str = "cfm/url_mib/*"
    state_key_prefix: str = "urlgroup."
    unbound_state_key_templates: Tuple[str, ...] = ("urlgroup.name",)
    channel_path: str = "/var/cfm_socket"
    message_size: int = 2016
    maximum_function_bytes: int = 16 * 1024

    def __post_init__(self) -> None:
        if (
            not self.name.strip()
            or not self.state_scope.strip()
            or not self.state_key_prefix.strip()
            or not self.channel_path.strip()
            or min(self.message_size, self.maximum_function_bytes) <= 0
        ):
            raise ValueError("configuration URL IPC profile requires identity")


@dataclass(frozen=True)
class ArmConfigurationUrlIpcPolicy:
    max_artifacts: int = 256
    max_total_bytes: int = 256 * 1024 * 1024
    max_instructions: int = 1_000_000

    def __post_init__(self) -> None:
        if min(self.max_artifacts, self.max_total_bytes, self.max_instructions) <= 0:
            raise ValueError("configuration URL IPC budgets must be positive")


@dataclass(frozen=True)
class ArmConfigurationUrlIpcOperation:
    operation_id: str
    operation: str
    client_path: str
    client_identity: str
    client_symbol: str
    request_opcode: int
    response_opcodes: Tuple[int, ...]
    message_size: int
    channel_path: str
    key_offset: Optional[int]
    value_offset: Optional[int]
    dispatcher_path: str
    dispatcher_identity: str
    server_wrapper_symbol: str
    store_primitive_symbol: str
    state_scope: str
    access_mode: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class ArmConfigurationUrlConsumer:
    consumer_id: str
    source_path: str
    function_identity: str
    client_symbols: Tuple[str, ...]
    state_key_templates: Tuple[str, ...]
    state_accesses: Tuple[Tuple[str, str], ...]
    access_modes: Tuple[str, ...]
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class ArmConfigurationUrlIpcFlowResult:
    coverage_status: CoverageStatus
    processed_bytes: int
    processed_instructions: int
    producer: AnalyzerIdentity
    profile: str
    operations: Tuple[ArmConfigurationUrlIpcOperation, ...]
    consumers: Tuple[ArmConfigurationUrlConsumer, ...]
    client_call_counts: Tuple[Tuple[str, str, int], ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[str, ...] = ()
    schema_version: str = ARM_CONFIGURATION_URL_IPC_FLOW_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "operations": [asdict(item) for item in self.operations],
            "consumers": [asdict(item) for item in self.consumers],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
        }


_OPERATION_SPECS = (
    ("get", "GetUrlValue", 32, (33,), "GetCfmUrlValue", "url_mib_get_value", 4, 516, "read"),
    ("set", "SetUrlValue", 30, (31,), "SetCfmUrlValue", "url_mib_set_value", 4, 516, "write"),
    ("unset", "UnSetUrlValue", 36, (37,), "UnSetCfmUrlValue", "url_mib_unset_value", 4, None, "delete"),
    ("commit", "CommitUrlCfm", 34, (16, 35), "SaveCfmUrl2Flash", "save_url_mib", None, None, "persist"),
    ("show", "ShowUrlValue", 38, (39,), "ShowCfmUrlValue", "url_mib_list", 4, None, "read"),
)


def _verify_source(artifact: ArmConfigurationUrlIpcArtifact) -> None:
    source, content = artifact.source, artifact.content
    if (
        source.kind not in {"file", "hardlink", "archive_member"}
        or source.content_sha256 is None
        or source.size != len(content)
        or hashlib.sha256(content).hexdigest() != source.content_sha256
    ):
        raise ValueError("source_mismatch")


def _atom(parsed, subject: str, start: int, end: int,
          predicate: str, value: str, capability: str) -> EvidenceAtom:
    offset = parsed.elf.address_offset(start, end - start)
    return capture_evidence(
        parsed.artifact.source,
        parsed.artifact.content,
        SpanSelection(SpanKind.BINARY, offset, offset + end - start),
        EvidenceClaim(
            subject, predicate, value, ObservationKind.DETERMINISTIC_DERIVED,
            capability, 1.0,
        ),
        _PRODUCER,
    )


def _literal_atom(parsed, subject: str, literal: str, span,
                  predicate: str, capability: str) -> EvidenceAtom:
    return capture_evidence(
        parsed.artifact.source,
        parsed.artifact.content,
        SpanSelection(SpanKind.BINARY, span[1], span[2]),
        EvidenceClaim(
            subject, predicate, literal, ObservationKind.DETERMINISTIC_DERIVED,
            capability, 1.0,
        ),
        _PRODUCER,
    )


def _operation(parsed, daemon, spec, profile):
    (operation, client_symbol, request, responses, wrapper_symbol,
     primitive_symbol, key_offset, value_offset, access_mode) = spec
    client = _symbol(parsed, client_symbol)
    wrapper = _symbol(parsed, wrapper_symbol)
    primitive = _symbol(parsed, primitive_symbol)
    connector = _symbol(parsed, "ConnectServer")
    if client is None or wrapper is None or primitive is None or connector is None:
        return None, (), "url_ipc_symbol_missing:{}".format(operation)
    client_end = _function_end(parsed, client.address, profile.maximum_function_bytes)
    client_calls = {name for _, name, _ in _calls(parsed, client.address, client_end)}
    if not {"SendMsg", "RecvMsg"}.issubset(client_calls):
        return None, (), "url_ipc_transport_missing:{}".format(operation)
    client_words = tuple(_word(parsed, address) for address in range(
        client.address, client_end, 4
    ))
    if not any(_immediate(word, 0xA) == profile.message_size for word in client_words):
        return None, (), "url_ipc_message_size_missing:{}".format(operation)
    observed_offsets = {
        _immediate(word, 0x4) for word in client_words
    }
    if key_offset is not None and key_offset not in observed_offsets:
        return None, (), "url_ipc_key_offset_missing:{}".format(operation)
    if value_offset is not None and value_offset not in observed_offsets:
        return None, (), "url_ipc_value_offset_missing:{}".format(operation)
    wrapper_end = _function_end(parsed, wrapper.address, profile.maximum_function_bytes)
    wrapper_calls = {name for _, name, _ in _calls(parsed, wrapper.address, wrapper_end)}
    if primitive_symbol not in wrapper_calls:
        return None, (), "url_ipc_store_primitive_missing:{}".format(operation)
    connector_end = _function_end(
        parsed, connector.address, profile.maximum_function_bytes
    )
    connector_literals = _pic_literals(parsed, connector.address, connector_end)
    if profile.channel_path not in connector_literals:
        return None, (), "url_ipc_channel_missing:{}".format(operation)

    dispatch_sites = []
    for segment in daemon.elf.segments:
        if segment.segment_type != 1 or not segment.flags & 1:
            continue
        for address in range(segment.address, segment.address + segment.file_size, 4):
            if _call_symbol(daemon, address) == wrapper_symbol:
                dispatch_sites.append(address)
    if len(dispatch_sites) != 1:
        return None, (), "url_ipc_dispatch_{}:{}".format(
            "missing" if not dispatch_sites else "ambiguous", operation
        )
    dispatch_site = dispatch_sites[0]
    deep = _parse_elf(daemon.artifact.content)
    owner = _function_start(
        deep, daemon.artifact.content, dispatch_site, profile.maximum_function_bytes
    )
    if owner is None:
        return None, (), "url_ipc_dispatch_owner_missing:{}".format(operation)
    dispatcher_start = owner[0]
    window_start = max(dispatcher_start, dispatch_site - 64)
    window_end = min(
        _function_end(daemon, dispatcher_start, 64 * 1024),
        dispatch_site + 96,
    )
    window_words = tuple(_word(daemon, address) for address in range(window_start, window_end, 4))
    if not any(word & 0xFFFFF000 == 0xE3530000 and word & 0xFFF == request
               for word in window_words):
        return None, (), "url_ipc_request_opcode_missing:{}".format(operation)
    for response in responses:
        if not any(
            (word & 0xFFFFF000 == 0xE3A03000 and word & 0xFFF == response)
            or (word & 0xFFFFF000 == 0xE3530000 and word & 0xFFF == response)
            for word in window_words
        ):
            return None, (), "url_ipc_response_opcode_missing:{}:{}".format(
                operation, response
            )
    operation_id = _stable_id(
        "native-configuration-url-ipc-flow",
        parsed.artifact.source.canonical_path, client.address,
        daemon.artifact.source.canonical_path, dispatcher_start,
        request, wrapper_symbol, profile.state_scope,
    )
    proof = (
        _atom(
            parsed, operation_id, client.address, client_end,
            "frames_url_store_request",
            "opcode={};message_size={}".format(request, profile.message_size),
            "frames_configuration_url_ipc_request",
        ),
        _atom(
            daemon, operation_id, window_start, window_end,
            "dispatches_url_store_request",
            "opcode={};responses={}".format(
                request, ",".join(str(item) for item in responses)
            ),
            "dispatches_configuration_url_ipc_request",
        ),
        _atom(
            parsed, operation_id, wrapper.address, wrapper_end,
            "accesses_url_store",
            "{}->{}".format(wrapper_symbol, primitive_symbol),
            "accesses_configuration_url_state",
        ),
        _literal_atom(
            parsed, operation_id, profile.channel_path,
            connector_literals[profile.channel_path],
            "uses_url_store_channel", "uses_configuration_url_ipc_channel",
        ),
    )
    return ArmConfigurationUrlIpcOperation(
        operation_id,
        operation,
        parsed.artifact.source.canonical_path,
        "{}@0x{:08x}".format(parsed.artifact.source.canonical_path, client.address),
        client_symbol,
        request,
        responses,
        profile.message_size,
        profile.channel_path,
        key_offset,
        value_offset,
        daemon.artifact.source.canonical_path,
        "{}@0x{:08x}".format(daemon.artifact.source.canonical_path, dispatcher_start),
        wrapper_symbol,
        primitive_symbol,
        profile.state_scope,
        access_mode,
        tuple(item.evidence_id for item in proof),
    ), proof, None


def _pic_literal_occurrences(parsed, start: int, end: int):
    """Return every PIC literal occurrence instead of collapsing equal strings."""
    base = _pic_base(parsed, start, end)
    if base is None:
        return ()
    deep = _parse_elf(parsed.artifact.content)
    found = []
    for address in range(start, end - 4, 4):
        instruction = _word(parsed, address)
        register = instruction >> 12 & 0xF
        if instruction & 0xFFFF0000 != 0xE59F0000:
            continue
        if _word(parsed, address + 4) != 0xE0840000 | register << 12 | register:
            continue
        delta = parsed.elf.read_u32(address + 8 + (instruction & 0xFFF))
        literal = _read_route_literal(
            deep, parsed.artifact.content, (base + delta) & 0xFFFFFFFF, 256
        )
        if literal is not None:
            found.append((literal[0], (address, literal[1], literal[1] + len(literal[0]))))
    return tuple(found)


def _consumers(parsed, profile, operation_symbols, instruction_budget):
    deep = _parse_elf(parsed.artifact.content)
    groups = {}
    processed = 0
    for segment in parsed.elf.segments:
        if segment.segment_type != 1 or not segment.flags & 1:
            continue
        for address in range(segment.address, segment.address + segment.file_size, 4):
            processed += 1
            if processed > instruction_budget:
                return (), (), processed, True
            symbol = _call_symbol(parsed, address)
            if symbol not in operation_symbols:
                continue
            owner = _function_start(
                deep, parsed.artifact.content, address, profile.maximum_function_bytes
            )
            if owner is not None:
                groups.setdefault(owner[0], []).append((address, symbol))
    consumers = []
    atoms = []
    for start, calls in sorted(groups.items()):
        end = _function_end(parsed, start, profile.maximum_function_bytes)
        literal_occurrences = tuple(
            (literal, span)
            for literal, span in _pic_literal_occurrences(parsed, start, end)
            if literal.startswith(profile.state_key_prefix)
            and literal not in profile.unbound_state_key_templates
        )
        if not literal_occurrences:
            continue
        # Bind literals to the closest following store call.  A shared function
        # may cross from URL IPC to the primary CFM store, so function-level
        # co-occurrence is insufficient (AC9 urlgroup.rule.* is the regression).
        callsites = tuple(sorted(calls))
        access_by_symbol = {
            "GetUrlValue": "read",
            "SetUrlValue": "write",
            "UnSetUrlValue": "delete",
            "CommitUrlCfm": "persist",
            "ShowUrlValue": "read",
        }
        bound_occurrences = []
        for literal, span in literal_occurrences:
            following = [item for item in callsites if item[0] >= span[0]]
            if following:
                nearest = following[0]
                if nearest[0] - span[0] <= 160:
                    bound_occurrences.append((literal, span, nearest[1]))
        if not bound_occurrences:
            continue
        literals = tuple(sorted({item[0] for item in bound_occurrences}))
        state_accesses = tuple(sorted({
            (literal, access_by_symbol[symbol])
            for literal, _, symbol in bound_occurrences
        }))
        symbols = tuple(sorted({item[1] for item in calls}))
        access_modes = tuple(sorted({mode for _, mode in state_accesses}))
        consumer_id = _stable_id(
            "native-configuration-url-consumer",
            parsed.artifact.source.canonical_path, start,
            literals, state_accesses, symbols,
        )
        proof = [
            _atom(
                parsed, consumer_id, start, end,
                "calls_url_store_clients", ",".join(symbols),
                "binds_configuration_url_consumer",
            )
        ]
        proof.extend(
            _literal_atom(
                parsed, consumer_id, literal, span,
                "references_url_state_key_template",
                "references_configuration_url_state",
            )
            for literal, span, _ in sorted(bound_occurrences)
        )
        proof = list({item.evidence_id: item for item in proof}.values())
        atoms.extend(proof)
        consumers.append(ArmConfigurationUrlConsumer(
            consumer_id,
            parsed.artifact.source.canonical_path,
            "{}@0x{:08x}".format(parsed.artifact.source.canonical_path, start),
            symbols,
            literals,
            state_accesses,
            access_modes,
            tuple(item.evidence_id for item in proof),
        ))
    return tuple(consumers), tuple(atoms), processed, False


def discover_arm_configuration_url_ipc_flows(
    artifacts: Tuple[ArmConfigurationUrlIpcArtifact, ...],
    profile: ArmConfigurationUrlIpcProfile = ArmConfigurationUrlIpcProfile(),
    policy: ArmConfigurationUrlIpcPolicy = ArmConfigurationUrlIpcPolicy(),
) -> ArmConfigurationUrlIpcFlowResult:
    """Recover URL-store IPC operations and exact native key-template consumers."""
    total = sum(len(item.content) for item in artifacts)
    if len(artifacts) > policy.max_artifacts:
        return ArmConfigurationUrlIpcFlowResult(
            CoverageStatus.SKIPPED_BY_POLICY, 0, 0, _PRODUCER, profile.name,
            (), (), (), (), ("artifact_budget_exceeded",),
        )
    if total > policy.max_total_bytes:
        return ArmConfigurationUrlIpcFlowResult(
            CoverageStatus.SKIPPED_BY_POLICY, 0, 0, _PRODUCER, profile.name,
            (), (), (), (), ("byte_budget_exceeded",),
        )
    try:
        for artifact in artifacts:
            _verify_source(artifact)
    except ValueError:
        return ArmConfigurationUrlIpcFlowResult(
            CoverageStatus.FAILED, total, 0, _PRODUCER, profile.name,
            (), (), (), (), ("source_mismatch",),
        )
    parsed = []
    diagnostics = []
    for artifact in artifacts:
        if not artifact.content.startswith(b"\x7fELF"):
            continue
        try:
            parsed.append(_parse(ArmCrossElfArtifact(artifact.source, artifact.content)))
        except (KeyError, TypeError, ValueError, struct.error) as exc:
            diagnostics.append("artifact_parse_failed:{}:{}".format(
                artifact.source.canonical_path, exc
            ))
    owner = next((item for item in parsed if all(
        _symbol(item, spec[1]) is not None and _symbol(item, spec[4]) is not None
        for spec in _OPERATION_SPECS
    )), None)
    daemon = next((item for item in parsed if all(
        any(name == spec[4] for name, _ in item.plt.values())
        for spec in _OPERATION_SPECS
    )), None)
    if owner is None:
        diagnostics.append("url_ipc_owner_missing")
    if daemon is None:
        diagnostics.append("url_ipc_dispatcher_missing")
    operations = []
    atoms = []
    if owner is not None and daemon is not None:
        for spec in _OPERATION_SPECS:
            operation, proof, diagnostic = _operation(owner, daemon, spec, profile)
            if operation is not None:
                operations.append(operation)
                atoms.extend(proof)
            if diagnostic is not None:
                diagnostics.append(diagnostic)
    operation_symbols = {spec[1] for spec in _OPERATION_SPECS}
    consumers = []
    call_counts = []
    processed = 0
    limited = False
    for item in parsed:
        if not any(name in operation_symbols for name, _ in item.plt.values()):
            continue
        found, proof, count, exhausted = _consumers(
            item, profile, operation_symbols, max(1, policy.max_instructions - processed)
        )
        processed += count
        limited = limited or exhausted
        consumers.extend(found)
        atoms.extend(proof)
        per_artifact = {symbol: 0 for symbol in operation_symbols}
        for segment in item.elf.segments:
            if segment.segment_type != 1 or not segment.flags & 1:
                continue
            for address in range(segment.address, segment.address + segment.file_size, 4):
                symbol = _call_symbol(item, address)
                if symbol in per_artifact:
                    per_artifact[symbol] += 1
        call_counts.extend(
            (item.artifact.source.canonical_path, symbol, count)
            for symbol, count in per_artifact.items() if count
        )
    if limited:
        diagnostics.append("instruction_budget_exhausted")
    if len(operations) != len(_OPERATION_SPECS):
        diagnostics.append("url_ipc_operation_set_incomplete")
    if not consumers:
        diagnostics.append("url_ipc_consumer_missing")
    status = CoverageStatus.COMPLETED if not diagnostics else CoverageStatus.PARTIAL
    return ArmConfigurationUrlIpcFlowResult(
        status,
        total,
        processed,
        _PRODUCER,
        profile.name,
        tuple(sorted(operations, key=lambda item: item.operation)),
        tuple(sorted(consumers, key=lambda item: item.function_identity)),
        tuple(sorted(call_counts)),
        tuple(sorted({item.evidence_id: item for item in atoms}.values(),
                     key=lambda item: item.evidence_id)),
        tuple(sorted(set(diagnostics))),
    )
