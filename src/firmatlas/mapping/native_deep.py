"""Conservative Native route-table binding and scheduler adapter."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
import struct
from typing import Optional, Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry
from .scheduler import (
    SchedulerAnalyzer,
    SchedulerDisposition,
    SchedulerOutcome,
)


NATIVE_DEEP_RESULT_SCHEMA_VERSION = "firmatlas.mapping.native-deep-result/v1alpha1"
_PRODUCER = AnalyzerIdentity("native-deep-route-table", "0.1.0")
_CALLSITE_PRODUCER = AnalyzerIdentity("native-deep-arm-pic-callsite", "0.1.0")
_MIPS_INLINE_PRODUCER = AnalyzerIdentity(
    "native-deep-mips-inline-route-table", "0.1.0"
)
_ALLOC = 0x2
_EXEC = 0x4
_ARM_MACHINE = 40
_MIPS_MACHINE = 8
_R_ARM_GLOB_DAT = 21
_CONTENT_KINDS = frozenset({"file", "hardlink", "archive", "archive_member"})


@dataclass(frozen=True)
class NativeRouteAnchor:
    target_ref: str
    route_token: str

    def __post_init__(self) -> None:
        if not self.target_ref.strip() or not self.route_token.strip():
            raise ValueError("native route anchor requires target_ref and route_token")


@dataclass(frozen=True)
class NativeRouteTableProfile:
    name: str = "named-route-handler-pairs/v1"
    table_section_names: Tuple[str, ...] = (".routes", ".route_table", ".webs_routes")
    entry_pointer_slots: int = 2
    route_pointer_slot: int = 0
    handler_pointer_slot: int = 1

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.table_section_names:
            raise ValueError("native route table profile requires identity and section names")
        if len(self.table_section_names) != len(set(self.table_section_names)):
            raise ValueError("duplicate route table section name")
        if self.entry_pointer_slots <= 0:
            raise ValueError("route table entry must have pointer slots")
        if not all(
            0 <= value < self.entry_pointer_slots
            for value in (self.route_pointer_slot, self.handler_pointer_slot)
        ):
            raise ValueError("route and handler slots must fit the table entry")
        if self.route_pointer_slot == self.handler_pointer_slot:
            raise ValueError("route and handler slots must be distinct")


@dataclass(frozen=True)
class NativeDeepPolicy:
    max_source_bytes: int = 64 * 1024 * 1024
    max_anchors: int = 10_000
    max_bindings: int = 20_000

    def __post_init__(self) -> None:
        if self.max_source_bytes <= 0 or self.max_anchors <= 0 or self.max_bindings <= 0:
            raise ValueError("native deep budgets must be positive")


@dataclass(frozen=True)
class ArmPicCallsiteProfile:
    name: str = "arm32-pic-r0-r1-bl/v1"
    min_registrar_pairs: int = 2
    max_pic_base_distance: int = 16 * 1024
    max_route_bytes: int = 256
    relocation_types: Tuple[int, ...] = (_R_ARM_GLOB_DAT,)

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("ARM PIC callsite profile requires identity")
        if self.min_registrar_pairs < 2:
            raise ValueError("ARM PIC registrar inference requires at least two pairs")
        if self.max_pic_base_distance <= 0 or self.max_route_bytes <= 0:
            raise ValueError("ARM PIC callsite budgets must be positive")
        if not self.relocation_types or any(value <= 0 for value in self.relocation_types):
            raise ValueError("ARM PIC callsite profile requires relocation types")
        if len(self.relocation_types) != len(set(self.relocation_types)):
            raise ValueError("duplicate ARM PIC relocation type")


@dataclass(frozen=True)
class MipsInlineRouteTableProfile:
    name: str = "mips32-inline-route-handler-table/v1"
    table_symbol_names: Tuple[str, ...] = (
        "get_handle_t", "set_handle_t", "del_handle_t", "other_handle_t",
    )
    route_field_bytes: int = 64
    min_valid_entries: int = 2

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.table_symbol_names:
            raise ValueError("MIPS inline route-table profile requires identity and symbols")
        if any(not name.strip() for name in self.table_symbol_names):
            raise ValueError("MIPS inline route-table symbols must not be blank")
        if len(self.table_symbol_names) != len(set(self.table_symbol_names)):
            raise ValueError("duplicate MIPS inline route-table symbol")
        if self.route_field_bytes <= 1 or self.min_valid_entries < 2:
            raise ValueError("MIPS inline route-table dimensions are invalid")


@dataclass(frozen=True)
class NativeRouteBinding:
    binding_id: str
    target_ref: str
    route_token: str
    handler_identity: str
    registration_address: int
    handler_address: int
    source_construct: str
    evidence_ids: Tuple[str, ...]
    handler_symbol: Optional[str] = None
    registrar_address: Optional[int] = None
    registrar_pair_count: Optional[int] = None


@dataclass(frozen=True)
class NativeDeepDiagnostic:
    code: str
    message: str
    target_ref: Optional[str] = None


@dataclass(frozen=True)
class NativeDeepResult:
    source_path: str
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    profile: str
    bindings: Tuple[NativeRouteBinding, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[NativeDeepDiagnostic, ...] = ()
    schema_version: str = NATIVE_DEEP_RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_result_contract(self)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "source_path": self.source_path,
            "coverage_status": self.coverage_status.value,
            "processed_bytes": self.processed_bytes,
            "producer": asdict(self.producer),
            "profile": self.profile,
            "bindings": [asdict(item) for item in self.bindings],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
            "diagnostics": [asdict(item) for item in self.diagnostics],
        }


def _validate_result_contract(result: NativeDeepResult) -> None:
    if result.schema_version != NATIVE_DEEP_RESULT_SCHEMA_VERSION:
        raise ValueError("unsupported native deep result schema_version")
    if not result.source_path.strip() or not result.profile.strip():
        raise ValueError("native deep result requires source path and profile")
    if not result.producer.name.strip() or not result.producer.version.strip():
        raise ValueError("native deep result requires producer identity")
    if result.processed_bytes < 0:
        raise ValueError("native deep processed bytes must not be negative")
    evidence = {}
    for atom in result.evidence_atoms:
        existing = evidence.get(atom.evidence_id)
        if existing is not None and existing != atom:
            raise ValueError("conflicting native deep evidence identity")
        evidence[atom.evidence_id] = atom
    binding_ids = set()
    for binding in result.bindings:
        if binding.binding_id in binding_ids:
            raise ValueError("duplicate native deep binding identity")
        binding_ids.add(binding.binding_id)
        handler_path, separator, handler_hex = binding.handler_identity.rpartition("@0x")
        try:
            parsed_handler_address = int(handler_hex, 16)
        except ValueError:
            parsed_handler_address = -1
        if (
            not separator or handler_path != result.source_path
            or parsed_handler_address != binding.handler_address
        ):
            raise ValueError("native deep handler identity is inconsistent")
        if binding.handler_symbol is not None and not binding.handler_symbol.strip():
            raise ValueError("native deep handler symbol must not be blank")
        if binding.registrar_address is not None and binding.registrar_address < 0:
            raise ValueError("native deep registrar address must not be negative")
        if binding.registrar_pair_count is not None and binding.registrar_pair_count < 2:
            raise ValueError("native deep registrar requires at least two pairs")
        if not binding.evidence_ids or len(binding.evidence_ids) != len(set(binding.evidence_ids)):
            raise ValueError("native deep binding requires unique evidence")
        atoms = []
        for evidence_id in binding.evidence_ids:
            atom = evidence.get(evidence_id)
            if atom is None:
                raise ValueError("native deep binding references unknown evidence")
            if atom.subject_ref != binding.binding_id:
                raise ValueError("native deep evidence subject does not match binding")
            if (atom.producer, atom.producer_version) != (
                result.producer.name, result.producer.version,
            ):
                raise ValueError("native deep evidence producer does not match result")
            if atom.source_span.artifact_path != result.source_path:
                raise ValueError("native deep evidence source does not match result")
            if atom.confidence != 1.0:
                raise ValueError("native deep deterministic proof requires confidence 1.0")
            atoms.append(atom)
        by_capability = {}
        for atom in atoms:
            by_capability.setdefault(atom.capability, []).append(atom)
        required_capabilities = {
            "mentions_endpoint", "registers_route", "binds_handler",
        }
        supporting_capabilities = {
            "establishes_pic_base", "resolves_handler_symbol",
            "resolves_table_symbol",
        }
        if not required_capabilities.issubset(by_capability) or not set(by_capability).issubset(
            required_capabilities | supporting_capabilities
        ):
            raise ValueError("native deep binding requires the complete three-part proof")
        if any(
            atom.observation_kind is not ObservationKind.DIRECT_STATIC
            or atom.object_value != binding.route_token
            for atom in by_capability["mentions_endpoint"]
        ):
            raise ValueError("native deep route literal proof is invalid")
        if any(
            atom.observation_kind is not ObservationKind.DETERMINISTIC_DERIVED
            or atom.object_value != binding.route_token
            for atom in by_capability["registers_route"]
        ):
            raise ValueError("native deep route registration proof is invalid")
        if any(
            atom.observation_kind is not ObservationKind.DETERMINISTIC_DERIVED
            or atom.object_value != binding.handler_identity
            for atom in by_capability["binds_handler"]
        ):
            raise ValueError("native deep handler binding proof is invalid")
        if any(
            atom.observation_kind is not ObservationKind.DETERMINISTIC_DERIVED
            for capability in supporting_capabilities
            for atom in by_capability.get(capability, ())
        ):
            raise ValueError("native deep supporting proof must be deterministic")
        table_symbol_atoms = by_capability.get("resolves_table_symbol", ())
        if (
            result.producer == _MIPS_INLINE_PRODUCER
            and len(table_symbol_atoms) != 1
        ):
            raise ValueError("MIPS inline binding requires one table symbol proof")
        expected_table_name = binding.source_construct.rpartition(":")[2]
        for atom in table_symbol_atoms:
            match = re.fullmatch(
                r"([^@]+)@0x([0-9a-f]+):size=0x([0-9a-f]+)",
                atom.object_value,
            )
            if match is None:
                raise ValueError("native deep table symbol proof is invalid")
            table_address = int(match.group(2), 16)
            table_size = int(match.group(3), 16)
            if (
                match.group(1) != expected_table_name
                or table_size <= 0
                or not table_address <= binding.registration_address
                < table_address + table_size
            ):
                raise ValueError("native deep table symbol proof is invalid")
        expected_symbol_proof = (
            "{}|{}".format(binding.handler_symbol, binding.handler_identity)
            if binding.handler_symbol is not None else binding.handler_identity
        )
        if any(
            atom.object_value != expected_symbol_proof
            for atom in by_capability.get("resolves_handler_symbol", ())
        ):
            raise ValueError("native deep handler symbol proof is invalid")
        for atom in by_capability.get("establishes_pic_base", ()):
            prefix, separator, address = atom.object_value.partition("@0x")
            try:
                int(address, 16)
            except ValueError as exc:
                raise ValueError("native deep PIC base proof is invalid") from exc
            if prefix != "got" or not separator:
                raise ValueError("native deep PIC base proof is invalid")


@dataclass(frozen=True)
class _Section:
    index: int
    name: str
    section_type: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    entry_size: int


@dataclass(frozen=True)
class _Elf:
    pointer_size: int
    endian_prefix: str
    machine: int
    sections: Tuple[_Section, ...]


def _checked_range(content: bytes, offset: int, size: int) -> None:
    if offset < 0 or size < 0 or offset + size > len(content):
        raise ValueError("ELF range exceeds source bytes")


def _string_at(table: bytes, offset: int) -> str:
    if not 0 <= offset < len(table):
        raise ValueError("ELF section name offset is invalid")
    end = table.find(b"\x00", offset)
    if end < 0:
        raise ValueError("ELF section name is not terminated")
    try:
        return table[offset:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("ELF section name is not ASCII") from exc


def _parse_elf(content: bytes) -> _Elf:
    if len(content) < 16 or content[:4] != b"\x7fELF":
        raise TypeError("unsupported binary format")
    elf_class, data_encoding = content[4], content[5]
    if elf_class not in (1, 2) or data_encoding not in (1, 2):
        raise ValueError("unsupported ELF class or data encoding")
    pointer_size = 4 if elf_class == 1 else 8
    endian = "<" if data_encoding == 1 else ">"
    header_format = endian + ("HHIIIIIHHHHHH" if pointer_size == 4 else "HHIQQQIHHHHHH")
    header_size = 52 if pointer_size == 4 else 64
    if len(content) < header_size:
        raise ValueError("truncated ELF header")
    header = struct.unpack_from(header_format, content, 16)
    section_offset, section_size, section_count, name_index = (
        header[5], header[10], header[11], header[12]
    )
    expected_size = 40 if pointer_size == 4 else 64
    if section_count <= 0 or section_size < expected_size or not 0 < name_index < section_count:
        raise ValueError("ELF section table is missing or malformed")
    _checked_range(content, section_offset, section_size * section_count)
    section_format = endian + ("IIIIIIIIII" if pointer_size == 4 else "IIQQQQIIQQ")
    raw_sections = []
    for index in range(section_count):
        item = struct.unpack_from(section_format, content, section_offset + index * section_size)
        name_offset, section_type, flags, address, offset, size = item[:6]
        if section_type != 8:
            _checked_range(content, offset, size)
        raw_sections.append(
            (name_offset, section_type, flags, address, offset, size, item[6], item[9])
        )
    name_section = raw_sections[name_index]
    if name_section[1] != 3:
        raise ValueError("ELF section name table has an invalid type")
    names = content[name_section[4] : name_section[4] + name_section[5]]
    sections = tuple(
        _Section(index, _string_at(names, item[0]), *item[1:])
        for index, item in enumerate(raw_sections)
    )
    return _Elf(pointer_size, endian, header[1], sections)


def _empty(
    source: SourceArtifactEntry, profile: NativeRouteTableProfile,
    status: CoverageStatus, code: str, message: str,
) -> NativeDeepResult:
    return NativeDeepResult(
        source.canonical_path, status, 0, _PRODUCER, profile.name, (), (),
        (NativeDeepDiagnostic(code, message),),
    )


def _binding_id(source_path: str, target_ref: str, route: str, address: int) -> str:
    payload = json.dumps(
        [source_path, target_ref, route, address], separators=(",", ":")
    ).encode()
    return "native-route-binding:{}".format(hashlib.sha256(payload).hexdigest())


def _contains_address(sections: tuple, address: int, required_flags: int) -> bool:
    return any(
        section.flags & required_flags == required_flags
        and section.address <= address < section.address + section.size
        for section in sections
    )


def discover_native_route_bindings(
    source: SourceArtifactEntry,
    content: bytes,
    anchors: Tuple[NativeRouteAnchor, ...],
    profile: NativeRouteTableProfile = NativeRouteTableProfile(),
    policy: NativeDeepPolicy = NativeDeepPolicy(),
) -> NativeDeepResult:
    """Resolve profiled ELF route-pointer pairs into replayable binding proofs."""

    if len(content) > policy.max_source_bytes:
        return _empty(source, profile, CoverageStatus.SKIPPED_BY_POLICY,
                      "source_budget_exceeded", "source exceeds configured byte budget")
    if len(anchors) > policy.max_anchors:
        return _empty(source, profile, CoverageStatus.SKIPPED_BY_POLICY,
                      "anchor_budget_exceeded", "anchors exceed configured budget")
    if source.kind not in _CONTENT_KINDS:
        return _empty(source, profile, CoverageStatus.FAILED,
                      "unsupported_source_kind", "source kind cannot publish binary evidence")
    if len(content) != source.size or hashlib.sha256(content).hexdigest() != source.content_sha256:
        return _empty(source, profile, CoverageStatus.FAILED,
                      "source_mismatch", "content does not match source inventory")
    try:
        elf = _parse_elf(content)
    except TypeError:
        return _empty(source, profile, CoverageStatus.UNSUPPORTED,
                      "unsupported_binary_format", "native deep adapter currently supports ELF only")
    except (ValueError, struct.error) as exc:
        return _empty(source, profile, CoverageStatus.FAILED, "malformed_elf", str(exc))

    pointer_format = elf.endian_prefix + ("I" if elf.pointer_size == 4 else "Q")
    table_sections = tuple(
        section for section in elf.sections
        if section.name in profile.table_section_names
        and section.section_type == 1
        and section.flags & _ALLOC
        and not section.flags & _EXEC
    )
    route_sections = tuple(
        section for section in elf.sections
        if section.section_type == 1 and section.flags & _ALLOC and not section.flags & _EXEC
    )
    executable_sections = tuple(
        section for section in elf.sections if section.flags & (_ALLOC | _EXEC) == (_ALLOC | _EXEC)
    )
    entry_size = profile.entry_pointer_slots * elf.pointer_size
    bindings = []
    atoms = []
    diagnostics = []
    seen = set()
    truncated = False
    for anchor in sorted(set(anchors), key=lambda item: (item.target_ref, item.route_token)):
        needle = anchor.route_token.encode("utf-8") + b"\x00"
        route_locations = []
        for section in route_sections:
            section_bytes = content[section.offset : section.offset + section.size]
            cursor = 0
            while True:
                relative = section_bytes.find(needle, cursor)
                if relative < 0:
                    break
                route_locations.append((section.address + relative, section.offset + relative))
                cursor = relative + 1
        for table in table_sections:
            for entry_relative in range(0, table.size - entry_size + 1, entry_size):
                entry_offset = table.offset + entry_relative
                route_pointer = struct.unpack_from(
                    pointer_format, content,
                    entry_offset + profile.route_pointer_slot * elf.pointer_size,
                )[0]
                route_offsets = [
                    offset for address, offset in route_locations if address == route_pointer
                ]
                if not route_offsets:
                    continue
                handler_pointer = struct.unpack_from(
                    pointer_format, content,
                    entry_offset + profile.handler_pointer_slot * elf.pointer_size,
                )[0]
                if not _contains_address(executable_sections, handler_pointer, _ALLOC | _EXEC):
                    diagnostics.append(NativeDeepDiagnostic(
                        "handler_target_not_executable",
                        "profiled table entry handler does not point into executable ELF memory",
                        anchor.target_ref,
                    ))
                    continue
                registration_address = table.address + entry_relative
                identity = (anchor.target_ref, registration_address)
                if identity in seen:
                    continue
                if len(bindings) >= policy.max_bindings:
                    truncated = True
                    continue
                seen.add(identity)
                binding_id = _binding_id(
                    source.canonical_path, anchor.target_ref, anchor.route_token,
                    registration_address,
                )
                route_atom = capture_evidence(
                    source, content,
                    SpanSelection(
                        SpanKind.BINARY, route_offsets[0],
                        route_offsets[0] + len(anchor.route_token.encode("utf-8")),
                    ),
                    EvidenceClaim(
                        binding_id, "mentions_endpoint", anchor.route_token,
                        ObservationKind.DIRECT_STATIC, "mentions_endpoint", 1.0,
                    ), _PRODUCER,
                )
                selection = SpanSelection(SpanKind.BINARY, entry_offset, entry_offset + entry_size)
                registration_atom = capture_evidence(
                    source, content, selection,
                    EvidenceClaim(
                        binding_id, "registers_route", anchor.route_token,
                        ObservationKind.DETERMINISTIC_DERIVED, "registers_route", 1.0,
                    ), _PRODUCER,
                )
                handler_identity = "{}@0x{:0{}x}".format(
                    source.canonical_path, handler_pointer, elf.pointer_size * 2
                )
                handler_atom = capture_evidence(
                    source, content, selection,
                    EvidenceClaim(
                        binding_id, "binds_handler", handler_identity,
                        ObservationKind.DETERMINISTIC_DERIVED, "binds_handler", 1.0,
                    ), _PRODUCER,
                )
                atoms.extend((route_atom, registration_atom, handler_atom))
                bindings.append(NativeRouteBinding(
                    binding_id, anchor.target_ref, anchor.route_token,
                    handler_identity, registration_address, handler_pointer,
                    "elf.{}:{}".format(profile.name, table.name),
                    (
                        route_atom.evidence_id, registration_atom.evidence_id,
                        handler_atom.evidence_id,
                    ),
                ))
    if truncated:
        diagnostics.append(NativeDeepDiagnostic(
            "binding_budget_exceeded", "binding budget truncated native deep analysis"
        ))
    return NativeDeepResult(
        source.canonical_path,
        CoverageStatus.PARTIAL if truncated else CoverageStatus.COMPLETED,
        len(content), _PRODUCER, profile.name,
        tuple(bindings), tuple(atoms), tuple(diagnostics),
    )


@dataclass(frozen=True)
class _DynamicSymbol:
    index: int
    name: str
    address: int
    size: int
    section_index: int
    source_offset: int
    entry_size: int


@dataclass(frozen=True)
class _Relocation:
    slot_address: int
    relocation_type: int
    symbol: _DynamicSymbol
    source_offset: int


@dataclass(frozen=True)
class _ArmPicCandidate:
    route_token: str
    route_offset: int
    handler_symbol: _DynamicSymbol
    handler_relocation_offset: int
    pic_base_address: int
    pic_base_offset: int
    callsite_address: int
    callsite_offset: int
    registrar_address: int


def _section_by_index(elf: _Elf, index: int) -> Optional[_Section]:
    return next((section for section in elf.sections if section.index == index), None)


def _file_offset_for_address(elf: _Elf, address: int) -> Optional[int]:
    for section in elf.sections:
        if (
            section.section_type != 8
            and section.address <= address < section.address + section.size
        ):
            return section.offset + address - section.address
    return None


def _word_at_address(elf: _Elf, content: bytes, address: int) -> Optional[int]:
    offset = _file_offset_for_address(elf, address)
    if offset is None or offset + 4 > len(content):
        return None
    return struct.unpack_from(elf.endian_prefix + "I", content, offset)[0]


def _arm_branch_target(instruction_address: int, instruction: int) -> int:
    immediate = instruction & 0x00FFFFFF
    if immediate & 0x00800000:
        immediate -= 1 << 24
    return (instruction_address + 8 + (immediate << 2)) & 0xFFFFFFFF


def _read_dynamic_symbols(elf: _Elf, content: bytes) -> dict:
    symbols_by_section = {}
    for section in elf.sections:
        if section.section_type != 11 or section.entry_size < 16:
            continue
        strings_section = _section_by_index(elf, section.link)
        if strings_section is None or strings_section.section_type != 3:
            raise ValueError("ELF dynamic symbol table has an invalid string table")
        strings = content[
            strings_section.offset : strings_section.offset + strings_section.size
        ]
        symbols = []
        for index, offset in enumerate(
            range(section.offset, section.offset + section.size, section.entry_size)
        ):
            if offset + 16 > section.offset + section.size:
                raise ValueError("ELF dynamic symbol entry is truncated")
            name_offset, address, size, _, _, section_index = struct.unpack_from(
                elf.endian_prefix + "IIIBBH", content, offset
            )
            name = "" if name_offset == 0 else _string_at(strings, name_offset)
            symbols.append(_DynamicSymbol(
                index, name, address, size, section_index, offset,
                section.entry_size,
            ))
        symbols_by_section[section.index] = tuple(symbols)
    return symbols_by_section


def _empty_mips_inline(
    source: SourceArtifactEntry,
    profile: MipsInlineRouteTableProfile,
    status: CoverageStatus,
    code: str,
    message: str,
) -> NativeDeepResult:
    return NativeDeepResult(
        source.canonical_path, status, 0, _MIPS_INLINE_PRODUCER,
        profile.name, (), (), (NativeDeepDiagnostic(code, message),),
    )


def discover_mips_inline_route_bindings(
    source: SourceArtifactEntry,
    content: bytes,
    anchors: Tuple[NativeRouteAnchor, ...],
    profile: MipsInlineRouteTableProfile = MipsInlineRouteTableProfile(),
    policy: NativeDeepPolicy = NativeDeepPolicy(),
) -> NativeDeepResult:
    """Prove MIPS32 ``char route[N] + handler pointer`` table entries."""

    if len(content) > policy.max_source_bytes:
        return _empty_mips_inline(
            source, profile, CoverageStatus.SKIPPED_BY_POLICY,
            "source_budget_exceeded", "source exceeds configured byte budget",
        )
    if len(anchors) > policy.max_anchors:
        return _empty_mips_inline(
            source, profile, CoverageStatus.SKIPPED_BY_POLICY,
            "anchor_budget_exceeded", "anchors exceed configured budget",
        )
    if source.kind not in _CONTENT_KINDS:
        return _empty_mips_inline(
            source, profile, CoverageStatus.FAILED,
            "unsupported_source_kind", "source kind cannot publish binary evidence",
        )
    if len(content) != source.size or hashlib.sha256(content).hexdigest() != source.content_sha256:
        return _empty_mips_inline(
            source, profile, CoverageStatus.FAILED,
            "source_mismatch", "content does not match source inventory",
        )
    try:
        elf = _parse_elf(content)
        if elf.pointer_size != 4 or elf.machine != _MIPS_MACHINE:
            return _empty_mips_inline(
                source, profile, CoverageStatus.UNSUPPORTED,
                "unsupported_architecture",
                "inline route-table adapter currently supports MIPS32 ELF only",
            )
        symbols = tuple(
            symbol
            for table in _read_dynamic_symbols(elf, content).values()
            for symbol in table
        )
    except TypeError:
        return _empty_mips_inline(
            source, profile, CoverageStatus.UNSUPPORTED,
            "unsupported_binary_format", "inline route-table adapter supports ELF only",
        )
    except (ValueError, struct.error) as exc:
        return _empty_mips_inline(
            source, profile, CoverageStatus.FAILED, "malformed_elf", str(exc)
        )

    executable_sections = tuple(
        section for section in elf.sections
        if section.flags & (_ALLOC | _EXEC) == (_ALLOC | _EXEC)
    )
    data_sections = tuple(
        section for section in elf.sections
        if section.section_type == 1
        and section.flags & _ALLOC
        and not section.flags & _EXEC
    )
    entry_size = profile.route_field_bytes + elf.pointer_size
    pointer_format = elf.endian_prefix + "I"
    table_entries = []
    diagnostics = []
    for symbol in symbols:
        if symbol.name not in profile.table_symbol_names:
            continue
        if symbol.section_index == 0:
            continue
        section = _section_by_index(elf, symbol.section_index)
        if not (
            section in data_sections
            and symbol.size >= entry_size * profile.min_valid_entries
            and symbol.size % entry_size == 0
            and section.address <= symbol.address
            and symbol.address + symbol.size <= section.address + section.size
        ):
            diagnostics.append(NativeDeepDiagnostic(
                "invalid_inline_table_symbol",
                "profiled dynamic symbol does not describe a complete inline table",
            ))
            continue
        table_offset = _file_offset_for_address(elf, symbol.address)
        if table_offset is None:
            diagnostics.append(NativeDeepDiagnostic(
                "inline_table_not_file_backed",
                "profiled inline table is not backed by source bytes",
            ))
            continue
        valid = []
        invalid_entry_count = 0
        for relative in range(0, symbol.size, entry_size):
            entry_offset = table_offset + relative
            route_field = content[
                entry_offset : entry_offset + profile.route_field_bytes
            ]
            terminator = route_field.find(b"\x00")
            if (
                terminator <= 0
                or any(route_field[terminator + 1 :])
                or any(byte < 0x21 or byte > 0x7E for byte in route_field[:terminator])
            ):
                invalid_entry_count += 1
                continue
            handler = struct.unpack_from(
                pointer_format, content,
                entry_offset + profile.route_field_bytes,
            )[0]
            if not _contains_address(executable_sections, handler, _ALLOC | _EXEC):
                invalid_entry_count += 1
                continue
            valid.append((
                route_field[:terminator].decode("ascii"), handler,
                symbol.address + relative, entry_offset, symbol,
            ))
        if invalid_entry_count:
            diagnostics.append(NativeDeepDiagnostic(
                "inline_table_entry_invalid",
                "profiled table contains {} structurally invalid entries".format(
                    invalid_entry_count
                ),
            ))
        if len(valid) < profile.min_valid_entries:
            diagnostics.append(NativeDeepDiagnostic(
                "inline_table_validation_failed",
                "profiled table did not contain enough structurally valid entries",
            ))
            continue
        table_entries.extend(valid)

    anchors_by_route = {}
    for anchor in set(anchors):
        anchors_by_route.setdefault(anchor.route_token, []).append(anchor)
    bindings = []
    atoms = []
    truncated = False
    for route, handler, registration, entry_offset, table_symbol in table_entries:
        for anchor in sorted(
            anchors_by_route.get(route, ()), key=lambda item: item.target_ref
        ):
            if len(bindings) >= policy.max_bindings:
                truncated = True
                continue
            binding_id = _binding_id(
                source.canonical_path, anchor.target_ref, route, registration
            )
            handler_identity = "{}@0x{:08x}".format(
                source.canonical_path, handler
            )
            route_atom = capture_evidence(
                source, content,
                SpanSelection(
                    SpanKind.BINARY, entry_offset, entry_offset + len(route.encode("ascii"))
                ),
                EvidenceClaim(
                    binding_id, "mentions_endpoint", route,
                    ObservationKind.DIRECT_STATIC, "mentions_endpoint", 1.0,
                ),
                _MIPS_INLINE_PRODUCER,
            )
            entry_selection = SpanSelection(
                SpanKind.BINARY, entry_offset, entry_offset + entry_size
            )
            table_symbol_atom = capture_evidence(
                source, content,
                SpanSelection(
                    SpanKind.BINARY, table_symbol.source_offset,
                    table_symbol.source_offset + table_symbol.entry_size,
                ),
                EvidenceClaim(
                    binding_id, "resolves_table_symbol",
                    "{}@0x{:08x}:size=0x{:x}".format(
                        table_symbol.name, table_symbol.address, table_symbol.size
                    ),
                    ObservationKind.DETERMINISTIC_DERIVED,
                    "resolves_table_symbol", 1.0,
                ),
                _MIPS_INLINE_PRODUCER,
            )
            registration_atom = capture_evidence(
                source, content, entry_selection,
                EvidenceClaim(
                    binding_id, "registers_route", route,
                    ObservationKind.DETERMINISTIC_DERIVED,
                    "registers_route", 1.0,
                ),
                _MIPS_INLINE_PRODUCER,
            )
            handler_atom = capture_evidence(
                source, content, entry_selection,
                EvidenceClaim(
                    binding_id, "binds_handler", handler_identity,
                    ObservationKind.DETERMINISTIC_DERIVED,
                    "binds_handler", 1.0,
                ),
                _MIPS_INLINE_PRODUCER,
            )
            evidence_ids = tuple(
                atom.evidence_id
                for atom in (
                    route_atom, table_symbol_atom,
                    registration_atom, handler_atom,
                )
            )
            atoms.extend((
                route_atom, table_symbol_atom, registration_atom, handler_atom,
            ))
            bindings.append(NativeRouteBinding(
                binding_id, anchor.target_ref, route, handler_identity,
                registration, handler,
                "elf.{}:{}".format(profile.name, table_symbol.name), evidence_ids,
            ))
    if truncated:
        diagnostics.append(NativeDeepDiagnostic(
            "binding_budget_exceeded",
            "binding budget truncated MIPS inline route-table analysis",
        ))
    return NativeDeepResult(
        source.canonical_path,
        CoverageStatus.PARTIAL if diagnostics or truncated else CoverageStatus.COMPLETED,
        len(content), _MIPS_INLINE_PRODUCER, profile.name,
        tuple(bindings), tuple(atoms), tuple(diagnostics),
    )


def _read_arm_relocations(
    elf: _Elf, content: bytes, allowed_types: Tuple[int, ...],
) -> dict:
    symbols_by_section = _read_dynamic_symbols(elf, content)
    relocations = {}
    for section in elf.sections:
        if section.section_type != 9:
            continue
        symbols = symbols_by_section.get(section.link)
        if symbols is None:
            raise ValueError("ELF relocation section has an invalid symbol table")
        entry_size = section.entry_size or 8
        if entry_size < 8:
            raise ValueError("ELF relocation entry size is invalid")
        for offset in range(section.offset, section.offset + section.size, entry_size):
            if offset + 8 > section.offset + section.size:
                raise ValueError("ELF relocation entry is truncated")
            slot_address, info = struct.unpack_from(
                elf.endian_prefix + "II", content, offset
            )
            symbol_index, relocation_type = info >> 8, info & 0xFF
            if relocation_type not in allowed_types:
                continue
            if symbol_index >= len(symbols):
                raise ValueError("ELF relocation references an invalid dynamic symbol")
            relocations[slot_address] = _Relocation(
                slot_address, relocation_type, symbols[symbol_index], offset
            )
    return relocations


def _read_route_literal(
    elf: _Elf, content: bytes, address: int, max_bytes: int,
) -> Optional[Tuple[str, int]]:
    for section in elf.sections:
        if not (
            section.section_type == 1
            and section.flags & _ALLOC
            and not section.flags & _EXEC
            and section.address <= address < section.address + section.size
        ):
            continue
        offset = section.offset + address - section.address
        available = min(max_bytes, section.offset + section.size - offset)
        raw = content[offset : offset + available]
        end = raw.find(b"\x00")
        if end <= 0:
            return None
        value = raw[:end]
        if any(byte < 0x20 or byte == 0x7F for byte in value):
            return None
        try:
            return value.decode("utf-8"), offset
        except UnicodeDecodeError:
            return None
    return None


def _find_pic_base(
    elf: _Elf, content: bytes, callsite_address: int,
    got_address: int, max_distance: int,
) -> Optional[Tuple[int, int]]:
    executable = next(
        (
            section for section in elf.sections
            if section.section_type == 1
            and section.flags & (_ALLOC | _EXEC) == (_ALLOC | _EXEC)
            and section.address <= callsite_address < section.address + section.size
        ),
        None,
    )
    if executable is None:
        return None
    lower_bound = max(executable.address, callsite_address - max_distance)
    function_start = None
    address = callsite_address
    while address >= lower_bound:
        instruction = _word_at_address(elf, content, address)
        if (
            instruction is not None
            and instruction & 0xFFFF0000 == 0xE92D0000
            and instruction & (1 << 14)
        ):
            function_start = address
            break
        address -= 4
    if function_start is None:
        return None
    for address in range(function_start, callsite_address, 4):
        load = _word_at_address(elf, content, address)
        add = _word_at_address(elf, content, address + 4)
        if load is None or add is None:
            continue
        if load & 0xFFFFF000 != 0xE59F4000 or add != 0xE08F4004:
            continue
        literal_address = address + 8 + (load & 0xFFF)
        literal = _word_at_address(elf, content, literal_address)
        if literal is None:
            continue
        resolved = (address + 12 + literal) & 0xFFFFFFFF
        if resolved == got_address:
            offset = _file_offset_for_address(elf, address)
            if offset is not None:
                return address, offset
    return None


def _scan_arm_pic_candidates(
    elf: _Elf, content: bytes, profile: ArmPicCallsiteProfile,
) -> Tuple[_ArmPicCandidate, ...]:
    got = next(
        (
            section for section in elf.sections
            if section.name == ".got" and section.section_type == 1
            and section.flags & _ALLOC and not section.flags & _EXEC
        ),
        None,
    )
    if got is None:
        return ()
    relocations = _read_arm_relocations(elf, content, profile.relocation_types)
    executable_sections = tuple(
        section for section in elf.sections
        if section.flags & (_ALLOC | _EXEC) == (_ALLOC | _EXEC)
    )
    candidates = []
    for section in executable_sections:
        if section.section_type != 1:
            continue
        for relative in range(0, section.size - 28 + 1, 4):
            offset = section.offset + relative
            words = struct.unpack_from(elf.endian_prefix + "7I", content, offset)
            if not (
                words[0] & 0xFFFFF000 == 0xE59F3000
                and words[1] == 0xE0843003
                and words[2] == 0xE1A00003
                and words[3] & 0xFFFFF000 == 0xE59F3000
                and words[4] == 0xE7943003
                and words[5] == 0xE1A01003
                and words[6] & 0xFF000000 == 0xEB000000
            ):
                continue
            address = section.address + relative
            pic_base = _find_pic_base(
                elf, content, address, got.address, profile.max_pic_base_distance
            )
            if pic_base is None:
                continue
            route_delta = _word_at_address(
                elf, content, address + 8 + (words[0] & 0xFFF)
            )
            handler_offset = _word_at_address(
                elf, content, address + 20 + (words[3] & 0xFFF)
            )
            if route_delta is None or handler_offset is None:
                continue
            route_address = (got.address + route_delta) & 0xFFFFFFFF
            route = _read_route_literal(
                elf, content, route_address, profile.max_route_bytes
            )
            relocation = relocations.get((got.address + handler_offset) & 0xFFFFFFFF)
            if route is None or relocation is None or not relocation.symbol.name:
                continue
            symbol_section = _section_by_index(elf, relocation.symbol.section_index)
            if not (
                symbol_section is not None
                and symbol_section.flags & (_ALLOC | _EXEC) == (_ALLOC | _EXEC)
                and symbol_section.address <= relocation.symbol.address
                < symbol_section.address + symbol_section.size
            ):
                continue
            registrar = _arm_branch_target(address + 24, words[6])
            if not _contains_address(executable_sections, registrar, _ALLOC | _EXEC):
                continue
            candidates.append(_ArmPicCandidate(
                route[0], route[1], relocation.symbol, relocation.source_offset,
                pic_base[0], pic_base[1], address + 24, offset, registrar,
            ))
    return tuple(candidates)


def _empty_callsite(
    source: SourceArtifactEntry, profile: ArmPicCallsiteProfile,
    status: CoverageStatus, code: str, message: str,
) -> NativeDeepResult:
    return NativeDeepResult(
        source.canonical_path, status, 0, _CALLSITE_PRODUCER, profile.name, (), (),
        (NativeDeepDiagnostic(code, message),),
    )


def discover_arm_pic_callsite_bindings(
    source: SourceArtifactEntry,
    content: bytes,
    anchors: Tuple[NativeRouteAnchor, ...],
    profile: ArmPicCallsiteProfile = ArmPicCallsiteProfile(),
    policy: NativeDeepPolicy = NativeDeepPolicy(),
) -> NativeDeepResult:
    """Prove ARM32 PIC route/handler pairs at a shared registrar callsite."""

    if len(content) > policy.max_source_bytes:
        return _empty_callsite(
            source, profile, CoverageStatus.SKIPPED_BY_POLICY,
            "source_budget_exceeded", "source exceeds configured byte budget",
        )
    if len(anchors) > policy.max_anchors:
        return _empty_callsite(
            source, profile, CoverageStatus.SKIPPED_BY_POLICY,
            "anchor_budget_exceeded", "anchors exceed configured budget",
        )
    if source.kind not in _CONTENT_KINDS:
        return _empty_callsite(
            source, profile, CoverageStatus.FAILED,
            "unsupported_source_kind", "source kind cannot publish binary evidence",
        )
    if len(content) != source.size or hashlib.sha256(content).hexdigest() != source.content_sha256:
        return _empty_callsite(
            source, profile, CoverageStatus.FAILED,
            "source_mismatch", "content does not match source inventory",
        )
    try:
        elf = _parse_elf(content)
        if elf.pointer_size != 4 or elf.machine != _ARM_MACHINE:
            return _empty_callsite(
                source, profile, CoverageStatus.UNSUPPORTED,
                "unsupported_architecture", "callsite adapter currently supports ARM32 ELF only",
            )
        candidates = _scan_arm_pic_candidates(elf, content, profile)
    except TypeError:
        return _empty_callsite(
            source, profile, CoverageStatus.UNSUPPORTED,
            "unsupported_binary_format", "callsite adapter currently supports ELF only",
        )
    except (ValueError, struct.error) as exc:
        return _empty_callsite(
            source, profile, CoverageStatus.FAILED, "malformed_elf", str(exc)
        )

    registrar_pairs = {}
    for candidate in candidates:
        registrar_pairs.setdefault(candidate.registrar_address, set()).add(
            (candidate.route_token, candidate.handler_symbol.address)
        )
    anchors_by_route = {}
    for anchor in set(anchors):
        anchors_by_route.setdefault(anchor.route_token, []).append(anchor)
    bindings = []
    atoms = []
    diagnostics = []
    truncated = False
    for candidate in candidates:
        if len(registrar_pairs[candidate.registrar_address]) < profile.min_registrar_pairs:
            continue
        for anchor in sorted(
            anchors_by_route.get(candidate.route_token, ()), key=lambda item: item.target_ref
        ):
            if len(bindings) >= policy.max_bindings:
                truncated = True
                continue
            binding_id = _binding_id(
                source.canonical_path, anchor.target_ref, anchor.route_token,
                candidate.callsite_address,
            )
            handler_identity = "{}@0x{:08x}".format(
                source.canonical_path, candidate.handler_symbol.address
            )
            route_atom = capture_evidence(
                source, content,
                SpanSelection(
                    SpanKind.BINARY, candidate.route_offset,
                    candidate.route_offset + len(candidate.route_token.encode("utf-8")),
                ),
                EvidenceClaim(
                    binding_id, "mentions_endpoint", candidate.route_token,
                    ObservationKind.DIRECT_STATIC, "mentions_endpoint", 1.0,
                ), _CALLSITE_PRODUCER,
            )
            pic_atom = capture_evidence(
                source, content,
                SpanSelection(
                    SpanKind.BINARY, candidate.pic_base_offset,
                    candidate.pic_base_offset + 8,
                ),
                EvidenceClaim(
                    binding_id, "establishes_pic_base",
                    "got@0x{:08x}".format(
                        next(section.address for section in elf.sections if section.name == ".got")
                    ),
                    ObservationKind.DETERMINISTIC_DERIVED,
                    "establishes_pic_base", 1.0,
                ), _CALLSITE_PRODUCER,
            )
            relocation_atom = capture_evidence(
                source, content,
                SpanSelection(
                    SpanKind.BINARY, candidate.handler_relocation_offset,
                    candidate.handler_relocation_offset + 8,
                ),
                EvidenceClaim(
                    binding_id, "resolves_handler_symbol",
                    "{}|{}".format(candidate.handler_symbol.name, handler_identity),
                    ObservationKind.DETERMINISTIC_DERIVED,
                    "resolves_handler_symbol", 1.0,
                ), _CALLSITE_PRODUCER,
            )
            call_selection = SpanSelection(
                SpanKind.BINARY, candidate.callsite_offset, candidate.callsite_offset + 28
            )
            registration_atom = capture_evidence(
                source, content, call_selection,
                EvidenceClaim(
                    binding_id, "registers_route", candidate.route_token,
                    ObservationKind.DETERMINISTIC_DERIVED, "registers_route", 1.0,
                ), _CALLSITE_PRODUCER,
            )
            handler_atom = capture_evidence(
                source, content, call_selection,
                EvidenceClaim(
                    binding_id, "binds_handler", handler_identity,
                    ObservationKind.DETERMINISTIC_DERIVED, "binds_handler", 1.0,
                ), _CALLSITE_PRODUCER,
            )
            evidence_ids = tuple(
                atom.evidence_id for atom in (
                    route_atom, pic_atom, relocation_atom,
                    registration_atom, handler_atom,
                )
            )
            atoms.extend((
                route_atom, pic_atom, relocation_atom,
                registration_atom, handler_atom,
            ))
            bindings.append(NativeRouteBinding(
                binding_id, anchor.target_ref, candidate.route_token,
                handler_identity, candidate.callsite_address,
                candidate.handler_symbol.address,
                "elf.{}:registrar@0x{:08x}".format(
                    profile.name, candidate.registrar_address
                ),
                evidence_ids,
                handler_symbol=candidate.handler_symbol.name,
                registrar_address=candidate.registrar_address,
                registrar_pair_count=len(
                    registrar_pairs[candidate.registrar_address]
                ),
            ))
    if truncated:
        diagnostics.append(NativeDeepDiagnostic(
            "binding_budget_exceeded", "binding budget truncated ARM PIC callsite analysis"
        ))
    return NativeDeepResult(
        source.canonical_path,
        CoverageStatus.PARTIAL if truncated else CoverageStatus.COMPLETED,
        len(content), _CALLSITE_PRODUCER, profile.name,
        tuple(bindings), tuple(atoms), tuple(diagnostics),
    )


def native_deep_scheduler_analyzer(result: NativeDeepResult) -> SchedulerAnalyzer:
    """Adapt validated Native Deep proofs to the obligation scheduler seam."""

    _validate_result_contract(result)
    evidence = {atom.evidence_id: atom for atom in result.evidence_atoms}
    proof_index = {}
    for binding in result.bindings:
        for evidence_id in binding.evidence_ids:
            atom = evidence.get(evidence_id)
            if atom is None:
                raise ValueError("native deep binding references unknown evidence")
            if atom.subject_ref != binding.binding_id:
                raise ValueError("native deep evidence subject does not match binding")
            if atom.capability in {"registers_route", "binds_handler"}:
                proof_index.setdefault(
                    (binding.target_ref, atom.capability), []
                ).append(evidence_id)

    def analyze(obligation):
        evidence_ids = tuple(proof_index.get(
            (obligation.target_ref, obligation.required_capability), ()
        ))
        return SchedulerOutcome(
            SchedulerDisposition.RESOLVED if evidence_ids else SchedulerDisposition.UNCHANGED,
            evidence_ids=evidence_ids,
        )

    return SchedulerAnalyzer("native-deep", analyze)
