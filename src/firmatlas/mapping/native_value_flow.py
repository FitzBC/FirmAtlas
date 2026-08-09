"""Deterministic MIPS handler-prefix parameter-to-state value-flow proofs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import struct
from typing import Optional, Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
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
    _section_by_index,
    _word_at_address,
)


MIPS_VALUE_FLOW_RESULT_SCHEMA_VERSION = (
    "firmatlas.mapping.mips-handler-value-flow-result/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("native-mips-handler-value-flow", "0.1.0")
_CONTENT_KINDS = frozenset({"file", "hardlink", "archive", "archive_member"})
_DT_NULL = 0
_DT_PLTGOT = 3
_DT_MIPS_LOCAL_GOTNO = 0x7000000A
_DT_MIPS_SYMTABNO = 0x70000011
_DT_MIPS_GOTSYM = 0x70000013

_ZERO = 0
_V0 = 2
_A0 = 4
_A1 = 5
_A3 = 7
_T0 = 8
_T9 = 25
_GP = 28
_SP = 29
_RA = 31


@dataclass(frozen=True)
class MipsHandlerValueFlowProfile:
    name: str = "mips32-gp-straight-line-getter-setter/v1"
    getter_symbols: Tuple[str, ...] = ("websGetVar",)
    setter_symbols: Tuple[str, ...] = ("nvram_set",)
    max_string_bytes: int = 128

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.getter_symbols or not self.setter_symbols:
            raise ValueError("MIPS value-flow profile requires identity, getters, and setters")
        if self.max_string_bytes <= 0:
            raise ValueError("MIPS value-flow string budget must be positive")
        for values in (self.getter_symbols, self.setter_symbols):
            if any(not value.strip() for value in values) or len(values) != len(set(values)):
                raise ValueError("MIPS value-flow symbols must be unique and nonblank")


@dataclass(frozen=True)
class MipsHandlerValueFlowPolicy:
    max_source_bytes: int = 64 * 1024 * 1024
    max_instructions: int = 512
    max_flows: int = 256

    def __post_init__(self) -> None:
        if self.max_source_bytes <= 0 or self.max_instructions <= 0 or self.max_flows <= 0:
            raise ValueError("MIPS value-flow budgets must be positive")


@dataclass(frozen=True)
class MipsParameterStateFlow:
    flow_id: str
    handler_identity: str
    parameter_name: str
    state_key: str
    getter_symbol: str
    setter_symbol: str
    getter_callsite: int
    setter_callsite: int
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class MipsHandlerValueFlowDiagnostic:
    code: str
    message: str


@dataclass(frozen=True)
class MipsHandlerValueFlowResult:
    source_path: str
    coverage_status: CoverageStatus
    producer: AnalyzerIdentity
    profile: str
    handler_address: int
    boundary_reason: str
    boundary_address: Optional[int]
    processed_instructions: int
    flows: Tuple[MipsParameterStateFlow, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[MipsHandlerValueFlowDiagnostic, ...] = ()
    schema_version: str = MIPS_VALUE_FLOW_RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_result(self)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "source_path": self.source_path,
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "profile": self.profile,
            "handler_address": self.handler_address,
            "boundary_reason": self.boundary_reason,
            "boundary_address": self.boundary_address,
            "processed_instructions": self.processed_instructions,
            "flows": [asdict(flow) for flow in self.flows],
            "evidence_atoms": [atom.to_dict() for atom in self.evidence_atoms],
            "diagnostics": [asdict(item) for item in self.diagnostics],
        }


@dataclass(frozen=True)
class _CallTarget:
    symbol: str
    address: int


@dataclass(frozen=True)
class _ParameterValue:
    name: str
    literal_address: int
    literal_offset: int
    getter_symbol: str
    getter_callsite: int
    getter_offset: int


@dataclass(frozen=True)
class _FlowCandidate:
    parameter: _ParameterValue
    state_key: str
    state_address: int
    state_offset: int
    setter_symbol: str
    setter_callsite: int
    setter_offset: int


def _validate_result(result: MipsHandlerValueFlowResult) -> None:
    if result.schema_version != MIPS_VALUE_FLOW_RESULT_SCHEMA_VERSION:
        raise ValueError("unsupported MIPS value-flow result schema")
    if not result.source_path.strip() or not result.profile.strip():
        raise ValueError("MIPS value-flow result requires source and profile")
    if result.handler_address < 0 or result.processed_instructions < 0:
        raise ValueError("MIPS value-flow addresses and counts must be nonnegative")
    atoms = {atom.evidence_id: atom for atom in result.evidence_atoms}
    if len(atoms) != len(result.evidence_atoms):
        raise ValueError("duplicate MIPS value-flow evidence identity")
    flow_ids = set()
    required = {
        "reads_request_parameter",
        "calls_parameter_getter",
        "writes_configuration_state",
        "calls_state_setter",
        "maps_parameter_to_state",
    }
    for flow in result.flows:
        if flow.flow_id in flow_ids:
            raise ValueError("duplicate MIPS value-flow identity")
        flow_ids.add(flow.flow_id)
        if flow.handler_identity != "{}@0x{:08x}".format(
            result.source_path, result.handler_address
        ):
            raise ValueError("MIPS value-flow handler identity is inconsistent")
        if len(flow.evidence_ids) != 5 or len(set(flow.evidence_ids)) != 5:
            raise ValueError("MIPS value-flow requires a five-part proof")
        capabilities = set()
        for evidence_id in flow.evidence_ids:
            atom = atoms.get(evidence_id)
            if atom is None or atom.subject_ref != flow.flow_id:
                raise ValueError("MIPS value-flow references invalid evidence")
            if atom.source_span.artifact_path != result.source_path:
                raise ValueError("MIPS value-flow evidence source is inconsistent")
            if (atom.producer, atom.producer_version) != (
                result.producer.name, result.producer.version
            ) or atom.confidence != 1.0:
                raise ValueError("MIPS value-flow proof must be deterministic")
            capabilities.add(atom.capability)
        if capabilities != required:
            raise ValueError("MIPS value-flow proof capabilities are incomplete")


def _empty(
    source: SourceArtifactEntry,
    profile: MipsHandlerValueFlowProfile,
    handler_address: int,
    status: CoverageStatus,
    code: str,
    message: str,
) -> MipsHandlerValueFlowResult:
    return MipsHandlerValueFlowResult(
        source.canonical_path, status, _PRODUCER, profile.name, handler_address,
        code, None, 0, (), (), (MipsHandlerValueFlowDiagnostic(code, message),),
    )


def _signed(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def _read_ascii(elf, content: bytes, address: int, maximum: int):
    section = next((
        item for item in elf.sections
        if item.section_type != 8
        and item.flags & _ALLOC
        and not item.flags & _EXEC
        and item.address <= address < item.address + item.size
    ), None)
    if section is None:
        return None
    offset = section.offset + address - section.address
    available = min(maximum, section.offset + section.size - offset)
    raw = content[offset:offset + available]
    end = raw.find(b"\x00")
    if end <= 0:
        return None
    value = raw[:end]
    if any(byte < 0x20 or byte > 0x7E for byte in value):
        return None
    return value.decode("ascii"), offset


def _dynamic_tags(elf, content: bytes) -> dict:
    sections = [section for section in elf.sections if section.section_type == 6]
    if len(sections) != 1:
        raise ValueError("MIPS value-flow requires one dynamic section")
    section = sections[0]
    tags = {}
    for offset in range(section.offset, section.offset + section.size, 8):
        if offset + 8 > section.offset + section.size:
            raise ValueError("ELF dynamic entry is truncated")
        tag, value = struct.unpack_from(elf.endian_prefix + "II", content, offset)
        if tag == _DT_NULL:
            break
        tags[tag] = value
    required = {
        _DT_PLTGOT, _DT_MIPS_LOCAL_GOTNO, _DT_MIPS_SYMTABNO, _DT_MIPS_GOTSYM,
    }
    if not required.issubset(tags):
        raise ValueError("MIPS GOT metadata is incomplete")
    if not 0 <= tags[_DT_MIPS_GOTSYM] <= tags[_DT_MIPS_SYMTABNO]:
        raise ValueError("MIPS GOT symbol range is malformed")
    return tags


def _got_target_resolver(elf, content: bytes):
    tags = _dynamic_tags(elf, content)
    got = next((
        section for section in elf.sections
        if section.name == ".got" and section.address == tags[_DT_PLTGOT]
        and section.flags & _ALLOC and not section.flags & _EXEC
    ), None)
    if got is None:
        raise ValueError("MIPS GOT section is missing or inconsistent")
    symbols_by_section = _read_dynamic_symbols(elf, content)
    if len(symbols_by_section) != 1:
        raise ValueError("MIPS value-flow requires one dynamic symbol table")
    symbols = next(iter(symbols_by_section.values()))
    if len(symbols) != tags[_DT_MIPS_SYMTABNO]:
        raise ValueError("MIPS dynamic symbol count does not match metadata")
    by_address = {
        symbol.address: symbol for symbol in symbols
        if symbol.name and symbol.section_index != 0
    }
    local_count = tags[_DT_MIPS_LOCAL_GOTNO]
    first_global = tags[_DT_MIPS_GOTSYM]

    def resolve(slot_address: int) -> Optional[_CallTarget]:
        delta = slot_address - got.address
        if delta < 0 or delta % 4 or delta + 4 > got.size:
            return None
        slot = delta // 4
        if slot < local_count:
            value = _word_at_address(elf, content, slot_address)
            symbol = by_address.get(value)
        else:
            index = first_global + slot - local_count
            symbol = symbols[index] if 0 <= index < len(symbols) else None
        if symbol is None or not symbol.name:
            return None
        return _CallTarget(symbol.name, symbol.address)

    return resolve


def _is_move(word: int):
    if word >> 26 != 0 or (word & 0x3F) not in (0x21, 0x25):
        return None
    rs, rt, rd = (word >> 21) & 0x1F, (word >> 16) & 0x1F, (word >> 11) & 0x1F
    if rt == _ZERO:
        return rd, rs
    if rs == _ZERO:
        return rd, rt
    return None


def _apply_non_call(word: int, constants: dict, provenance: dict, call_targets: dict,
                    stack_constants: dict, resolve_target) -> bool:
    op = word >> 26
    rs, rt, immediate = (word >> 21) & 0x1F, (word >> 16) & 0x1F, word & 0xFFFF
    move = _is_move(word)
    if move is not None:
        destination, source = move
        if source in constants:
            constants[destination] = constants[source]
        else:
            constants.pop(destination, None)
        if source in provenance:
            provenance[destination] = provenance[source]
        else:
            provenance.pop(destination, None)
        if source in call_targets:
            call_targets[destination] = call_targets[source]
        else:
            call_targets.pop(destination, None)
        return True
    if word == 0:  # nop / sll $zero,$zero,0
        return True
    if op == 0x0F:  # lui
        constants[rt] = (immediate << 16) & 0xFFFFFFFF
        provenance.pop(rt, None)
        call_targets.pop(rt, None)
        return True
    if op in (0x08, 0x09):  # addi/addiu
        if rs in constants:
            constants[rt] = (constants[rs] + _signed(immediate)) & 0xFFFFFFFF
        else:
            constants.pop(rt, None)
        if rs in provenance:
            provenance[rt] = provenance[rs]
        else:
            provenance.pop(rt, None)
        call_targets.pop(rt, None)
        return True
    if op == 0x2B:  # sw; retain only explicit stack-relative constant saves
        slot = _signed(immediate)
        if rs == _SP and rt in constants:
            stack_constants[slot] = constants[rt]
        elif rs == _SP:
            stack_constants.pop(slot, None)
        return True
    if op == 0x23:  # lw
        constants.pop(rt, None)
        provenance.pop(rt, None)
        call_targets.pop(rt, None)
        if rs == _SP and _signed(immediate) in stack_constants:
            constants[rt] = stack_constants[_signed(immediate)]
            return True
        if rs in constants:
            target = resolve_target((constants[rs] + _signed(immediate)) & 0xFFFFFFFF)
            if target is not None:
                call_targets[rt] = target
        return True
    return False


def _flow_id(source_path: str, handler: int, candidate: _FlowCandidate) -> str:
    payload = "\0".join((
        source_path, "{:08x}".format(handler), candidate.parameter.name,
        candidate.state_key, "{:08x}".format(candidate.parameter.getter_callsite),
        "{:08x}".format(candidate.setter_callsite),
    )).encode("utf-8")
    return "mips-flow:" + hashlib.sha256(payload).hexdigest()


def discover_mips_handler_value_flows(
    source: SourceArtifactEntry,
    content: bytes,
    handler_address: int,
    profile: MipsHandlerValueFlowProfile = MipsHandlerValueFlowProfile(),
    policy: MipsHandlerValueFlowPolicy = MipsHandlerValueFlowPolicy(),
) -> MipsHandlerValueFlowResult:
    """Prove getter-result to state-setter flows in one branch-free MIPS prefix."""

    if len(content) > policy.max_source_bytes:
        return _empty(source, profile, handler_address, CoverageStatus.SKIPPED_BY_POLICY,
                      "source_budget_exceeded", "source exceeds configured byte budget")
    if source.kind not in _CONTENT_KINDS:
        return _empty(source, profile, handler_address, CoverageStatus.FAILED,
                      "unsupported_source_kind", "source kind cannot publish binary evidence")
    if len(content) != source.size or hashlib.sha256(content).hexdigest() != source.content_sha256:
        return _empty(source, profile, handler_address, CoverageStatus.FAILED,
                      "source_mismatch", "content does not match source inventory")
    try:
        elf = _parse_elf(content)
        if elf.pointer_size != 4 or elf.machine != _MIPS_MACHINE:
            return _empty(source, profile, handler_address, CoverageStatus.UNSUPPORTED,
                          "unsupported_architecture", "adapter requires MIPS32 ELF")
        if not _contains_address(elf.sections, handler_address, _ALLOC | _EXEC):
            return _empty(source, profile, handler_address, CoverageStatus.FAILED,
                          "handler_not_executable", "handler is outside executable sections")
        resolve_target = _got_target_resolver(elf, content)
    except TypeError:
        return _empty(source, profile, handler_address, CoverageStatus.UNSUPPORTED,
                      "unsupported_binary_format", "adapter currently supports ELF only")
    except (ValueError, struct.error) as exc:
        return _empty(source, profile, handler_address, CoverageStatus.FAILED,
                      "malformed_elf", str(exc))

    constants, provenance, call_targets, stack_constants = {}, {}, {}, {}
    candidates = []
    processed = 0
    address = handler_address
    boundary_reason = "instruction_budget"
    boundary_address = None
    diagnostics = []
    while processed < policy.max_instructions:
        word = _word_at_address(elf, content, address)
        if word is None:
            boundary_reason, boundary_address = "executable_boundary", address
            break
        op = word >> 26
        rs, rt, rd, function = (
            (word >> 21) & 0x1F, (word >> 16) & 0x1F,
            (word >> 11) & 0x1F, word & 0x3F,
        )
        if op in (0x01, 0x04, 0x05, 0x06, 0x07):
            boundary_reason, boundary_address = "first_conditional_branch", address
            break
        if op == 0 and function == 0x08 and rs == _RA:
            boundary_reason, boundary_address = "jr_ra", address
            processed += 1
            break
        if op == 0 and function == 0x09:
            if processed + 1 >= policy.max_instructions:
                break
            delay = _word_at_address(elf, content, address + 4)
            if delay is None:
                boundary_reason, boundary_address = "truncated_delay_slot", address + 4
                diagnostics.append(MipsHandlerValueFlowDiagnostic(
                    "truncated_delay_slot", "call delay slot is outside file-backed executable data"
                ))
                break
            delay_supported = _apply_non_call(
                delay, constants, provenance, call_targets, stack_constants, resolve_target
            )
            if not delay_supported:
                boundary_reason, boundary_address = "unsupported_instruction", address + 4
                diagnostics.append(MipsHandlerValueFlowDiagnostic(
                    "unsupported_instruction",
                    "call delay slot is outside the declared instruction Profile",
                ))
                break
            target = call_targets.get(rs)
            call_offset = _file_offset_for_address(elf, address)
            if target is not None and call_offset is not None:
                if target.symbol in profile.getter_symbols:
                    literal = constants.get(_A1)
                    value = _read_ascii(elf, content, literal, profile.max_string_bytes) \
                        if literal is not None else None
                    if value is not None:
                        provenance[_V0] = _ParameterValue(
                            value[0], literal, value[1], target.symbol, address, call_offset,
                        )
                    else:
                        provenance.pop(_V0, None)
                elif target.symbol in profile.setter_symbols:
                    parameter = provenance.get(_A1)
                    state_address = constants.get(_A0)
                    state = _read_ascii(elf, content, state_address, profile.max_string_bytes) \
                        if state_address is not None else None
                    if isinstance(parameter, _ParameterValue) and state is not None:
                        candidates.append(_FlowCandidate(
                            parameter, state[0], state_address, state[1],
                            target.symbol, address, call_offset,
                        ))
                    provenance.pop(_V0, None)
                else:
                    provenance.pop(_V0, None)
            for register in range(_A0, _A3 + 1):
                constants.pop(register, None)
                provenance.pop(register, None)
                call_targets.pop(register, None)
            for register in tuple(range(_T0, 16)) + (24, _T9):
                constants.pop(register, None)
                provenance.pop(register, None)
                call_targets.pop(register, None)
            processed += 2
            address += 8
            continue
        supported = _apply_non_call(
            word, constants, provenance, call_targets, stack_constants, resolve_target
        )
        if not supported:
            boundary_reason, boundary_address = "unsupported_instruction", address
            diagnostics.append(MipsHandlerValueFlowDiagnostic(
                "unsupported_instruction",
                "instruction is outside the declared straight-line Profile",
            ))
            break
        processed += 1
        address += 4
    else:
        boundary_address = address

    truncated_flows = len(candidates) > policy.max_flows
    candidates = candidates[:policy.max_flows]
    if truncated_flows:
        diagnostics.append(MipsHandlerValueFlowDiagnostic(
            "flow_budget_exceeded", "flow budget truncated deterministic candidates"
        ))
    atoms = []
    flows = []
    handler_identity = "{}@0x{:08x}".format(source.canonical_path, handler_address)
    for candidate in candidates:
        identity = _flow_id(source.canonical_path, handler_address, candidate)
        mapping = "{}->{}".format(candidate.parameter.name, candidate.state_key)
        parameter_atom = capture_evidence(
            source, content,
            SpanSelection(
                SpanKind.BINARY, candidate.parameter.literal_offset,
                candidate.parameter.literal_offset + len(candidate.parameter.name.encode("ascii")),
            ),
            EvidenceClaim(identity, "reads_request_parameter", candidate.parameter.name,
                          ObservationKind.DIRECT_STATIC, "reads_request_parameter", 1.0),
            _PRODUCER,
        )
        getter_atom = capture_evidence(
            source, content,
            SpanSelection(SpanKind.BINARY, candidate.parameter.getter_offset,
                          candidate.parameter.getter_offset + 8),
            EvidenceClaim(identity, "calls_parameter_getter", candidate.parameter.getter_symbol,
                          ObservationKind.DETERMINISTIC_DERIVED,
                          "calls_parameter_getter", 1.0),
            _PRODUCER,
        )
        state_atom = capture_evidence(
            source, content,
            SpanSelection(SpanKind.BINARY, candidate.state_offset,
                          candidate.state_offset + len(candidate.state_key.encode("ascii"))),
            EvidenceClaim(identity, "writes_configuration_state", candidate.state_key,
                          ObservationKind.DIRECT_STATIC,
                          "writes_configuration_state", 1.0),
            _PRODUCER,
        )
        setter_selection = SpanSelection(
            SpanKind.BINARY, candidate.setter_offset, candidate.setter_offset + 8
        )
        setter_atom = capture_evidence(
            source, content, setter_selection,
            EvidenceClaim(identity, "calls_state_setter", candidate.setter_symbol,
                          ObservationKind.DETERMINISTIC_DERIVED,
                          "calls_state_setter", 1.0),
            _PRODUCER,
        )
        mapping_atom = capture_evidence(
            source, content, setter_selection,
            EvidenceClaim(identity, "maps_parameter_to_state", mapping,
                          ObservationKind.DETERMINISTIC_DERIVED,
                          "maps_parameter_to_state", 1.0),
            _PRODUCER,
        )
        proof = (parameter_atom, getter_atom, state_atom, setter_atom, mapping_atom)
        atoms.extend(proof)
        flows.append(MipsParameterStateFlow(
            identity, handler_identity, candidate.parameter.name, candidate.state_key,
            candidate.parameter.getter_symbol, candidate.setter_symbol,
            candidate.parameter.getter_callsite, candidate.setter_callsite,
            tuple(atom.evidence_id for atom in proof),
        ))
    status = CoverageStatus.PARTIAL if (
        boundary_reason in {
            "instruction_budget", "truncated_delay_slot", "unsupported_instruction",
        } or truncated_flows
    ) else CoverageStatus.COMPLETED
    return MipsHandlerValueFlowResult(
        source.canonical_path, status, _PRODUCER, profile.name, handler_address,
        boundary_reason, boundary_address, processed, tuple(flows), tuple(atoms),
        tuple(diagnostics),
    )
