"""Deterministic ARM configuration-image IPC-to-state flow recovery."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import struct
from typing import Optional, Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry
from .native_cross_elf_call import (
    ArmCrossElfArtifact,
    _branch_target,
    _function_end,
    _parse,
)
from .native_deep import _parse_elf, _read_route_literal


ARM_CONFIGURATION_BLOB_FLOW_SCHEMA_VERSION = (
    "firmatlas.mapping.arm-configuration-blob-flow/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("native-arm-configuration-blob-flow", "0.1.0")


@dataclass(frozen=True)
class ArmConfigurationBlobArtifact:
    source: SourceArtifactEntry
    content: bytes


@dataclass(frozen=True)
class ArmConfigurationBlobFlowProfile:
    name: str = "arm32-framed-ipc-restore-mtd/v1"
    client_symbols: Tuple[str, ...] = ("UploadValue",)
    decoder_symbols: Tuple[str, ...] = ("atoi",)
    state_writer_symbols: Tuple[str, ...] = ("RestoreMTD",)
    maximum_function_bytes: int = 16 * 1024

    def __post_init__(self) -> None:
        if not self.name.strip() or self.maximum_function_bytes <= 0:
            raise ValueError("configuration blob profile requires identity and budget")
        for values in (
            self.client_symbols, self.decoder_symbols, self.state_writer_symbols,
        ):
            if not values or any(not item.strip() for item in values):
                raise ValueError("configuration blob symbols must be nonblank")
            if len(values) != len(set(values)):
                raise ValueError("configuration blob symbols must be unique")


@dataclass(frozen=True)
class ArmConfigurationBlobFlowPolicy:
    max_artifacts: int = 256
    max_total_bytes: int = 256 * 1024 * 1024
    max_instructions: int = 250_000

    def __post_init__(self) -> None:
        if min(self.max_artifacts, self.max_total_bytes, self.max_instructions) <= 0:
            raise ValueError("configuration blob budgets must be positive")


@dataclass(frozen=True)
class ArmConfigurationBlobFlow:
    flow_id: str
    client_path: str
    client_identity: str
    client_symbol: str
    dispatcher_path: str
    dispatcher_identity: str
    request_opcode: int
    response_opcode: int
    message_size: int
    payload_offset: int
    payload_literal: str
    decoder_symbol: str
    state_writer_symbol: str
    state_scope: str
    write_granularity: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class ArmConfigurationBlobFlowResult:
    coverage_status: CoverageStatus
    processed_bytes: int
    processed_instructions: int
    producer: AnalyzerIdentity
    profile: str
    flows: Tuple[ArmConfigurationBlobFlow, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[str, ...] = ()
    schema_version: str = ARM_CONFIGURATION_BLOB_FLOW_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "flows": [asdict(item) for item in self.flows],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
        }


def _stable_id(prefix: str, *values: object) -> str:
    encoded = json.dumps(
        values, ensure_ascii=False, separators=(",", ":")
    ).encode()
    return prefix + ":" + hashlib.sha256(encoded).hexdigest()


def _ror32(value: int, amount: int) -> int:
    amount %= 32
    return ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF


def _immediate(instruction: int, opcode: int, register: int = 3) -> Optional[int]:
    if not instruction & (1 << 25):
        return None
    if instruction >> 21 & 0xF != opcode:
        return None
    if opcode == 0xD:
        if instruction >> 12 & 0xF != register:
            return None
    elif instruction >> 16 & 0xF != register:
        return None
    rotate = (instruction >> 8 & 0xF) * 2
    return _ror32(instruction & 0xFF, rotate)


def _word(parsed, address: int) -> int:
    return struct.unpack_from(
        "<I", parsed.artifact.content, parsed.elf.address_offset(address, 4)
    )[0]


def _call_symbol(parsed, address: int) -> Optional[str]:
    imported = parsed.plt.get(_branch_target(address, _word(parsed, address)))
    return imported[0] if imported is not None else None


def _pic_base(parsed, start: int, end: int) -> Optional[int]:
    for address in range(start, min(end, start + 128) - 4, 4):
        instruction = _word(parsed, address)
        if instruction & 0xFFFFF000 != 0xE59F4000:
            continue
        if _word(parsed, address + 4) != 0xE08F4004:
            continue
        literal_address = address + 8 + (instruction & 0xFFF)
        return (address + 12 + parsed.elf.read_u32(literal_address)) & 0xFFFFFFFF
    return None


def _client_spec(parsed, profile):
    export = next((
        item for item in parsed.exports if item.name in profile.client_symbols
    ), None)
    if export is None:
        return None
    end = _function_end(parsed, export.address, profile.maximum_function_bytes)
    pic_base = _pic_base(parsed, export.address, end)
    calls = []
    request = message_size = payload_offset = None
    request_address = message_address = payload_address = None
    literal = None
    literal_span = None
    for address in range(export.address, end, 4):
        instruction = _word(parsed, address)
        symbol = _call_symbol(parsed, address)
        if symbol:
            calls.append((address, symbol))
        value = _immediate(instruction, 0xD)
        if value is not None and request is None and 2 < value < 256:
            if address + 4 < end and _word(parsed, address + 4) >> 20 & 0xFF == 0x50:
                request, request_address = value, address
        value = _immediate(instruction, 0xA)
        if value is not None and value >= 256:
            message_size, message_address = value, address
        value = _immediate(instruction, 0x4)
        if value is not None and value >= 4:
            payload_offset, payload_address = value, address
        if (
            pic_base is not None
            and instruction & 0xFFFFF000 == 0xE59F3000
            and address + 4 < end
            and _word(parsed, address + 4) == 0xE0843003
        ):
            delta = parsed.elf.read_u32(address + 8 + (instruction & 0xFFF))
            deep = _parse_elf(parsed.artifact.content)
            found = _read_route_literal(
                deep, parsed.artifact.content,
                (pic_base + delta) & 0xFFFFFFFF, 32,
            )
            if found is not None:
                literal, offset = found
                literal_span = (offset, offset + len(literal))
    symbols = {item[1] for item in calls}
    required = {"memcpy", "SendMsg", "RecvMsg"}
    if (
        request is None or message_size is None or payload_offset is None
        or literal is None or not required.issubset(symbols)
    ):
        return None
    memcpy_address = next(address for address, symbol in calls if symbol == "memcpy")
    return {
        "parsed": parsed, "export": export, "end": end,
        "request": request, "request_address": request_address,
        "message_size": message_size, "message_address": message_address,
        "payload_offset": payload_offset, "payload_address": payload_address,
        "literal": literal, "literal_span": literal_span,
        "memcpy_address": memcpy_address,
    }


def _dispatcher_spec(parsed, client, profile, instruction_budget: int):
    decoder_calls = []
    writer_calls = []
    processed = 0
    for section in parsed.elf.segments:
        if section.segment_type != 1 or not section.flags & 0x1:
            continue
        for address in range(
            section.address, section.address + section.file_size, 4
        ):
            processed += 1
            if processed > instruction_budget:
                return None, processed, True
            symbol = _call_symbol(parsed, address)
            if symbol in profile.decoder_symbols:
                decoder_calls.append((address, symbol))
            if symbol in profile.state_writer_symbols:
                writer_calls.append((address, symbol))
    for decoder_address, decoder_symbol in decoder_calls:
        choices = [
            item for item in writer_calls
            if decoder_address < item[0] <= decoder_address + 32
        ]
        if len(choices) != 1:
            continue
        writer_address, writer_symbol = choices[0]
        cmp_address = request_opcode = None
        payload_address = payload_offset = None
        for address in range(max(0, decoder_address - 128), decoder_address, 4):
            instruction = _word(parsed, address)
            value = _immediate(instruction, 0xA)
            if value == client["request"]:
                cmp_address, request_opcode = address, value
            value = _immediate(instruction, 0x4)
            if value == client["payload_offset"]:
                payload_address, payload_offset = address, value
        if cmp_address is None or payload_address is None:
            continue
        response_address = response_opcode = None
        for address in range(writer_address + 4, writer_address + 32, 4):
            value = _immediate(_word(parsed, address), 0xD)
            if value is not None and value != request_opcode:
                response_address, response_opcode = address, value
                break
        if response_address is None:
            continue
        function_address = cmp_address
        for address in range(cmp_address, max(0, cmp_address - 4096), -4):
            if _word(parsed, address) & 0xFFFF0000 == 0xE92D0000:
                function_address = address
                break
        return ({
            "parsed": parsed, "function_address": function_address,
            "cmp_address": cmp_address,
            "payload_address": payload_address,
            "decoder_address": decoder_address, "decoder_symbol": decoder_symbol,
            "writer_address": writer_address, "writer_symbol": writer_symbol,
            "response_address": response_address,
            "response_opcode": response_opcode,
        }, processed, False)
    return None, processed, False


def _atom(parsed, flow_id, start, end, predicate, value, capability):
    return capture_evidence(
        parsed.artifact.source, parsed.artifact.content,
        SpanSelection(SpanKind.BINARY, parsed.elf.address_offset(start, end - start),
                      parsed.elf.address_offset(start, end - start) + end - start),
        EvidenceClaim(
            flow_id, predicate, str(value), ObservationKind.DETERMINISTIC_DERIVED,
            capability, 1.0,
        ),
        _PRODUCER,
    )


def discover_arm_configuration_blob_flows(
    artifacts: Tuple[ArmConfigurationBlobArtifact, ...],
    profile: ArmConfigurationBlobFlowProfile = ArmConfigurationBlobFlowProfile(),
    policy: ArmConfigurationBlobFlowPolicy = ArmConfigurationBlobFlowPolicy(),
) -> ArmConfigurationBlobFlowResult:
    """Recover framed client IPC that dispatches to whole-image state restore."""
    if len(artifacts) > policy.max_artifacts:
        return ArmConfigurationBlobFlowResult(
            CoverageStatus.SKIPPED_BY_POLICY, 0, 0, _PRODUCER, profile.name,
            (), (), ("artifact_budget_exceeded",),
        )
    total = sum(len(item.content) for item in artifacts)
    if total > policy.max_total_bytes:
        return ArmConfigurationBlobFlowResult(
            CoverageStatus.SKIPPED_BY_POLICY, 0, 0, _PRODUCER, profile.name,
            (), (), ("byte_budget_exceeded",),
        )
    parsed = []
    diagnostics = []
    for artifact in artifacts:
        try:
            parsed.append(_parse(ArmCrossElfArtifact(
                artifact.source, artifact.content
            )))
        except (KeyError, TypeError, ValueError, struct.error) as exc:
            if str(exc) == "source_mismatch":
                return ArmConfigurationBlobFlowResult(
                    CoverageStatus.FAILED, total, 0, _PRODUCER, profile.name,
                    (), (), ("source_mismatch",),
                )
            diagnostics.append("artifact_parse_failed:{}:{}".format(
                artifact.source.canonical_path, exc
            ))
    clients = tuple(filter(None, (
        _client_spec(item, profile) for item in parsed
    )))
    flows = []
    atoms = []
    processed = 0
    limited = False
    for client in clients:
        dispatchers = []
        for item in parsed:
            if item is client["parsed"]:
                continue
            dispatcher, count, exhausted = _dispatcher_spec(
                item, client, profile, max(1, policy.max_instructions - processed)
            )
            processed += count
            limited = limited or exhausted
            if dispatcher is not None:
                dispatchers.append(dispatcher)
        if len(dispatchers) != 1:
            diagnostics.append(
                "dispatcher_{}".format("missing" if not dispatchers else "ambiguous")
            )
            continue
        dispatcher = dispatchers[0]
        state_scope = (
            "configuration_partition[{}]".format(int(client["literal"]))
            if client["literal"].isdigit()
            else "configuration_partition[*]"
        )
        flow_id = _stable_id(
            "native-configuration-blob-flow",
            client["parsed"].artifact.source.canonical_path,
            client["export"].address,
            dispatcher["parsed"].artifact.source.canonical_path,
            dispatcher["function_address"],
            client["request"], state_scope,
        )
        client_parsed = client["parsed"]
        daemon_parsed = dispatcher["parsed"]
        export_start, export_end = client["export"].symbol_span
        export_atom = capture_evidence(
            client_parsed.artifact.source, client_parsed.artifact.content,
            SpanSelection(SpanKind.BINARY, export_start, export_end),
            EvidenceClaim(
                flow_id, "resolves_client", client["export"].name,
                ObservationKind.DETERMINISTIC_DERIVED,
                "resolves_configuration_blob_client", 1.0,
            ), _PRODUCER,
        )
        frame_atom = _atom(
            client_parsed, flow_id, client["request_address"],
            client["memcpy_address"] + 4, "frames_request",
            "opcode={};payload_offset={}".format(
                client["request"], client["payload_offset"]
            ), "frames_configuration_blob_request",
        )
        literal_atom = capture_evidence(
            client_parsed.artifact.source, client_parsed.artifact.content,
            SpanSelection(SpanKind.BINARY, *client["literal_span"]),
            EvidenceClaim(
                flow_id, "selects_state_scope", client["literal"],
                ObservationKind.DETERMINISTIC_DERIVED,
                "selects_configuration_partition", 1.0,
            ), _PRODUCER,
        )
        size_atom = _atom(
            client_parsed, flow_id, client["message_address"],
            client["message_address"] + 4, "requires_message_size",
            client["message_size"], "constrains_configuration_message_size",
        )
        dispatch_atom = _atom(
            daemon_parsed, flow_id, dispatcher["cmp_address"],
            dispatcher["response_address"] + 4, "dispatches_request",
            "opcode={};response={}".format(
                client["request"], dispatcher["response_opcode"]
            ), "dispatches_configuration_blob_request",
        )
        decoder_atom = _atom(
            daemon_parsed, flow_id, dispatcher["decoder_address"],
            dispatcher["decoder_address"] + 4, "decodes_state_selector",
            dispatcher["decoder_symbol"], "decodes_configuration_partition",
        )
        writer_atom = _atom(
            daemon_parsed, flow_id, dispatcher["writer_address"],
            dispatcher["writer_address"] + 4, "writes_state",
            dispatcher["writer_symbol"], "writes_configuration_state",
        )
        proof = (
            export_atom, frame_atom, literal_atom, size_atom,
            dispatch_atom, decoder_atom, writer_atom,
        )
        atoms.extend(proof)
        flows.append(ArmConfigurationBlobFlow(
            flow_id,
            client_parsed.artifact.source.canonical_path,
            "{}@0x{:08x}".format(
                client_parsed.artifact.source.canonical_path,
                client["export"].address,
            ),
            client["export"].name,
            daemon_parsed.artifact.source.canonical_path,
            "{}@0x{:08x}".format(
                daemon_parsed.artifact.source.canonical_path,
                dispatcher["function_address"],
            ),
            client["request"], dispatcher["response_opcode"],
            client["message_size"], client["payload_offset"],
            client["literal"], dispatcher["decoder_symbol"],
            dispatcher["writer_symbol"], state_scope,
            "whole_configuration_image",
            tuple(item.evidence_id for item in proof),
        ))
    if limited:
        diagnostics.append("instruction_budget_exhausted")
    status = (
        CoverageStatus.PARTIAL if diagnostics or limited
        else CoverageStatus.COMPLETED
    )
    return ArmConfigurationBlobFlowResult(
        status, total, processed, _PRODUCER, profile.name,
        tuple(sorted(flows, key=lambda item: item.flow_id)),
        tuple(sorted({item.evidence_id: item for item in atoms}.values(),
                     key=lambda item: item.evidence_id)),
        tuple(sorted(set(diagnostics))),
    )
