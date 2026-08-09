"""Replayable OpenWrt rpcd native ubus registration-table recovery."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import struct
from typing import Optional, Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry


NATIVE_UBUS_REGISTRATION_SCHEMA_VERSION = (
    "firmatlas.mapping.native-ubus-registration/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("native-ubus-registration", "0.1.0")
_PT_LOAD = 1
_PT_DYNAMIC = 2
_PF_X = 1
_DT_NULL = 0
_DT_PLTRELSZ = 2
_DT_HASH = 4
_DT_STRTAB = 5
_DT_SYMTAB = 6
_DT_STRSZ = 10
_DT_SYMENT = 11
_DT_PLTREL = 20
_DT_JMPREL = 23
_DT_REL = 17
_R_ARM_JUMP_SLOT = 22


@dataclass(frozen=True)
class NativeUbusRegistrationProfile:
    name: str = "openwrt-rpcd-arm32-static-object/v1"
    object_name_offset: int = 28
    object_type_offset: int = 40
    object_methods_offset: int = 52
    object_method_count_offset: int = 56
    type_name_offset: int = 0
    type_methods_offset: int = 8
    type_method_count_offset: int = 12
    method_entry_size: int = 24
    method_name_offset: int = 0
    method_handler_offset: int = 4
    plugin_init_offset: int = 8


@dataclass(frozen=True)
class NativeUbusRegistrationPolicy:
    max_source_bytes: int = 64 * 1024 * 1024
    max_methods: int = 4096
    max_string_bytes: int = 256
    max_init_instructions: int = 64


@dataclass(frozen=True)
class NativeUbusMethodRegistration:
    registration_id: str
    object_name: str
    method_name: str
    handler_address: int
    handler_identity: str
    table_address: int
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class NativeUbusObjectRegistration:
    registration_id: str
    object_name: str
    type_name: str
    object_address: int
    init_address: int
    registrar_address: int
    methods: Tuple[NativeUbusMethodRegistration, ...]
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class NativeUbusRegistrationDiagnostic:
    code: str
    message: str


@dataclass(frozen=True)
class NativeUbusRegistrationResult:
    source_path: str
    coverage_status: CoverageStatus
    registration_coverage_complete: bool
    processed_bytes: int
    producer: AnalyzerIdentity
    profile: str
    objects: Tuple[NativeUbusObjectRegistration, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[NativeUbusRegistrationDiagnostic, ...] = ()
    schema_version: str = NATIVE_UBUS_REGISTRATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.registration_coverage_complete != (
            self.coverage_status is CoverageStatus.COMPLETED
        ):
            raise ValueError("native ubus registration coverage is inconsistent")
        if self.registration_coverage_complete and not self.objects:
            raise ValueError("complete native ubus coverage requires a registration")
        evidence = {item.evidence_id: item for item in self.evidence_atoms}
        for obj in self.objects:
            if not obj.methods or not set(obj.evidence_ids) <= set(evidence):
                raise ValueError("native ubus object proof is incomplete")
            for method in obj.methods:
                if not set(method.evidence_ids) <= set(evidence):
                    raise ValueError("native ubus method proof is incomplete")

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "source_path": self.source_path,
            "coverage_status": self.coverage_status.value,
            "registration_coverage_complete": self.registration_coverage_complete,
            "processed_bytes": self.processed_bytes,
            "producer": asdict(self.producer),
            "profile": self.profile,
            "objects": [asdict(item) for item in self.objects],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
            "diagnostics": [asdict(item) for item in self.diagnostics],
        }


@dataclass(frozen=True)
class _Segment:
    segment_type: int
    offset: int
    address: int
    file_size: int
    memory_size: int
    flags: int


@dataclass(frozen=True)
class _Symbol:
    name: str
    value: int
    size: int


class _Elf32Arm:
    def __init__(self, content: bytes) -> None:
        if len(content) < 52 or content[:7] != b"\x7fELF\x01\x01\x01":
            raise ValueError("adapter requires a little-endian ELF32 image")
        header = struct.unpack_from("<HHIIIIIHHHHHH", content, 16)
        if header[1] != 40:
            raise ValueError("adapter requires an ARM ELF image")
        program_offset, program_size, program_count = header[4], header[8], header[9]
        if program_size < 32 or program_count <= 0:
            raise ValueError("ELF program headers are missing")
        if program_offset + program_size * program_count > len(content):
            raise ValueError("ELF program headers are truncated")
        self.content = content
        self.segments = tuple(
            _Segment(values[0], values[1], values[2], values[4], values[5], values[6])
            for values in (
                struct.unpack_from("<IIIIIIII", content, program_offset + index * program_size)
                for index in range(program_count)
            )
        )
        dynamic = next((item for item in self.segments if item.segment_type == _PT_DYNAMIC), None)
        if dynamic is None:
            raise ValueError("ELF dynamic segment is missing")
        self.dynamic = {}
        for offset in range(dynamic.offset, dynamic.offset + dynamic.file_size, 8):
            if offset + 8 > len(content):
                raise ValueError("ELF dynamic segment is truncated")
            tag, value = struct.unpack_from("<II", content, offset)
            if tag == _DT_NULL:
                break
            self.dynamic[tag] = value

    def address_offset(self, address: int, size: int = 1) -> int:
        for segment in self.segments:
            if segment.segment_type != _PT_LOAD:
                continue
            if segment.address <= address and address + size <= segment.address + segment.memory_size:
                relative = address - segment.address
                if relative >= segment.file_size:
                    raise ValueError("address only exists in zero-filled memory")
                return segment.offset + relative
        raise ValueError("address is outside loadable segments")

    def read_u32(self, address: int) -> int:
        offset = self.address_offset(address)
        segment = next(
            item for item in self.segments
            if item.segment_type == _PT_LOAD and item.address <= address < item.address + item.memory_size
        )
        available = min(4, segment.file_size - (address - segment.address))
        return int.from_bytes(self.content[offset : offset + available].ljust(4, b"\x00"), "little")

    def pointer_span(self, address: int) -> Tuple[int, int]:
        offset = self.address_offset(address)
        segment = next(
            item for item in self.segments
            if item.segment_type == _PT_LOAD and item.address <= address < item.address + item.memory_size
        )
        return offset, offset + min(4, segment.file_size - (address - segment.address))

    def read_string(self, address: int, limit: int) -> Tuple[str, int, int]:
        offset = self.address_offset(address)
        end = self.content.find(b"\x00", offset, min(len(self.content), offset + limit + 1))
        if end < 0 or end == offset:
            raise ValueError("registration string is empty or unterminated")
        value = self.content[offset:end].decode("utf-8")
        if any(ord(character) < 0x20 for character in value):
            raise ValueError("registration string contains control bytes")
        return value, offset, end

    def executable(self, address: int) -> bool:
        return any(
            item.segment_type == _PT_LOAD and item.flags & _PF_X
            and item.address <= address < item.address + item.memory_size
            for item in self.segments
        )

    def symbols(self) -> Tuple[_Symbol, ...]:
        required = (_DT_HASH, _DT_STRTAB, _DT_SYMTAB, _DT_STRSZ, _DT_SYMENT)
        if any(tag not in self.dynamic for tag in required):
            raise ValueError("ELF dynamic symbol metadata is incomplete")
        hash_offset = self.address_offset(self.dynamic[_DT_HASH], 8)
        _, symbol_count = struct.unpack_from("<II", self.content, hash_offset)
        if self.dynamic[_DT_SYMENT] != 16 or symbol_count > 100_000:
            raise ValueError("ELF dynamic symbol table dimensions are invalid")
        string_offset = self.address_offset(self.dynamic[_DT_STRTAB], self.dynamic[_DT_STRSZ])
        strings = self.content[string_offset : string_offset + self.dynamic[_DT_STRSZ]]
        symbol_offset = self.address_offset(self.dynamic[_DT_SYMTAB], symbol_count * 16)
        result = []
        for index in range(symbol_count):
            name_offset, value, size, _, _, _ = struct.unpack_from(
                "<IIIBBH", self.content, symbol_offset + index * 16
            )
            if name_offset >= len(strings):
                raise ValueError("ELF dynamic symbol name is invalid")
            end = strings.find(b"\x00", name_offset)
            if end < 0:
                raise ValueError("ELF dynamic symbol name is unterminated")
            result.append(_Symbol(strings[name_offset:end].decode("ascii"), value, size))
        return tuple(result)

    def plt_symbols(self, symbols: Tuple[_Symbol, ...]) -> Tuple[Tuple[int, str], ...]:
        if self.dynamic.get(_DT_PLTREL) != _DT_REL:
            raise ValueError("adapter requires ARM REL PLT relocations")
        size = self.dynamic.get(_DT_PLTRELSZ, 0)
        address = self.dynamic.get(_DT_JMPREL, 0)
        if not size or size % 8:
            raise ValueError("ELF PLT relocation table is malformed")
        offset = self.address_offset(address, size)
        names = []
        for cursor in range(offset, offset + size, 8):
            _, info = struct.unpack_from("<II", self.content, cursor)
            symbol_index, relocation_type = info >> 8, info & 0xFF
            if relocation_type != _R_ARM_JUMP_SLOT or symbol_index >= len(symbols):
                raise ValueError("ELF PLT relocation is unsupported")
            names.append(symbols[symbol_index].name)
        stubs = []
        for segment in self.segments:
            if segment.segment_type != _PT_LOAD or not segment.flags & _PF_X:
                continue
            for relative in range(0, max(0, segment.file_size - 11), 4):
                cursor = segment.offset + relative
                one, two, three = struct.unpack_from("<III", self.content, cursor)
                if (
                    one & 0xFFFFF000 == 0xE28FC000
                    and two & 0xFFFFF000 == 0xE28CC000
                    and three & 0xFFFFF000 == 0xE5BCF000
                ):
                    stubs.append(segment.address + relative)
        stubs = sorted(set(stubs))
        if len(stubs) < len(names):
            raise ValueError("ELF PLT stubs do not cover relocation table")
        return tuple(zip(stubs[:len(names)], names))


def _stable_id(prefix: str, *values: object) -> str:
    payload = json.dumps(values, separators=(",", ":"), ensure_ascii=False)
    return "{}:{}".format(prefix, hashlib.sha256(payload.encode()).hexdigest())


def _capture(
    source: SourceArtifactEntry, content: bytes, span: Tuple[int, int],
    subject: str, predicate: str, object_value: str, capability: str,
    observation: ObservationKind = ObservationKind.DETERMINISTIC_DERIVED,
) -> EvidenceAtom:
    return capture_evidence(
        source, content, SpanSelection(SpanKind.BINARY, *span),
        EvidenceClaim(subject, predicate, object_value, observation, capability, 1.0),
        _PRODUCER,
    )


def _empty(
    source: SourceArtifactEntry, profile: NativeUbusRegistrationProfile,
    status: CoverageStatus, code: str, message: str, processed: int = 0,
) -> NativeUbusRegistrationResult:
    return NativeUbusRegistrationResult(
        source.canonical_path, status, False, processed, _PRODUCER, profile.name,
        (), (), (NativeUbusRegistrationDiagnostic(code, message),),
    )


def _branch_target(address: int, instruction: int) -> Optional[int]:
    if instruction >> 24 & 0xF != 0xA:
        return None
    displacement = instruction & 0x00FFFFFF
    if displacement & 0x00800000:
        displacement -= 0x01000000
    return address + 8 + displacement * 4


def _object_from_init(
    elf: _Elf32Arm, init_address: int, registrar_stubs: frozenset,
    max_instructions: int,
) -> Tuple[int, int, Tuple[int, int]]:
    loaded_r1 = None
    object_address = None
    branch = None
    for index in range(max_instructions):
        address = init_address + index * 4
        if not elf.executable(address):
            break
        offset = elf.address_offset(address, 4)
        instruction = struct.unpack_from("<I", elf.content, offset)[0]
        # LDR r1, [pc, +/- imm12]
        if instruction & 0xFFFFF000 in (0xE59F1000, 0xE51F1000):
            delta = instruction & 0xFFF
            literal = address + 8 + (delta if instruction & (1 << 23) else -delta)
            loaded_r1 = elf.read_u32(literal)
        elif loaded_r1 is not None and instruction == 0xE08F1001:
            object_address = address + 8 + loaded_r1
        target = _branch_target(address, instruction)
        if target in registrar_stubs:
            branch = (target, (offset, offset + 4))
            break
    if object_address is None or branch is None:
        raise ValueError("plugin init does not prove ubus_add_object(ctx, &obj)")
    return object_address, branch[0], branch[1]


def discover_native_ubus_registrations(
    source: SourceArtifactEntry,
    content: bytes,
    profile: NativeUbusRegistrationProfile = NativeUbusRegistrationProfile(),
    policy: NativeUbusRegistrationPolicy = NativeUbusRegistrationPolicy(),
) -> NativeUbusRegistrationResult:
    """Recover exact rpcd object/method/handler registrations from an ARM ELF."""

    if len(content) > policy.max_source_bytes:
        return _empty(source, profile, CoverageStatus.SKIPPED_BY_POLICY,
                      "source_budget_exceeded", "source exceeds native ubus byte budget")
    if source.kind not in {"file", "hardlink", "archive_member"}:
        return _empty(source, profile, CoverageStatus.FAILED,
                      "unsupported_source_kind", "source kind has no readable bytes")
    if (
        len(content) != source.size or source.content_sha256 is None
        or hashlib.sha256(content).hexdigest() != source.content_sha256
    ):
        return _empty(source, profile, CoverageStatus.FAILED,
                      "source_mismatch", "content does not match source inventory")
    try:
        elf = _Elf32Arm(content)
        symbols = elf.symbols()
        by_name = {item.name: item for item in symbols}
        plugin = by_name.get("rpc_plugin")
        if plugin is None or plugin.value == 0 or plugin.size < profile.plugin_init_offset + 4:
            return _empty(source, profile, CoverageStatus.UNSUPPORTED,
                          "rpcd_plugin_symbol_missing", "rpc_plugin dynamic symbol is absent", len(content))
        init_pointer = plugin.value + profile.plugin_init_offset
        init_address = elf.read_u32(init_pointer)
        if not elf.executable(init_address):
            raise ValueError("rpc_plugin init target is not executable")
        plt = elf.plt_symbols(symbols)
        registrar_stubs = frozenset(
            address for address, name in plt if name == "ubus_add_object"
        )
        if not registrar_stubs:
            return _empty(source, profile, CoverageStatus.PARTIAL,
                          "ubus_registrar_not_verified",
                          "ubus_add_object is not present in the verified PLT", len(content))
        object_address, registrar_address, branch_span = _object_from_init(
            elf, init_address, registrar_stubs, policy.max_init_instructions
        )
        object_name_address = elf.read_u32(object_address + profile.object_name_offset)
        type_address = elf.read_u32(object_address + profile.object_type_offset)
        methods_address = elf.read_u32(object_address + profile.object_methods_offset)
        method_count = elf.read_u32(object_address + profile.object_method_count_offset)
        if not 0 < method_count <= policy.max_methods:
            raise ValueError("ubus object method count is invalid")
        type_name_address = elf.read_u32(type_address + profile.type_name_offset)
        if (
            elf.read_u32(type_address + profile.type_methods_offset) != methods_address
            or elf.read_u32(type_address + profile.type_method_count_offset) != method_count
        ):
            raise ValueError("ubus object and object-type method tables disagree")
        object_name, _, _ = elf.read_string(
            object_name_address, policy.max_string_bytes
        )
        type_name, _, _ = elf.read_string(type_name_address, policy.max_string_bytes)
        object_id = _stable_id(
            "native-ubus-object", source.canonical_path, object_address, object_name
        )
        init_span = elf.pointer_span(init_pointer)
        init_atom = _capture(
            source, content, init_span, object_id, "identifies_plugin_init",
            "{}@0x{:08x}".format(source.canonical_path, init_address),
            "identifies_rpcd_plugin_init",
        )
        call_atom = _capture(
            source, content, branch_span, object_id, "calls_registrar",
            "ubus_add_object@0x{:08x}".format(registrar_address),
            "calls_ubus_add_object",
        )
        object_pointer_span = elf.pointer_span(
            object_address + profile.object_name_offset
        )
        object_atom = _capture(
            source, content, object_pointer_span, object_id, "registers_object",
            object_name, "registers_ubus_object",
        )
        atoms = [init_atom, call_atom, object_atom]
        methods = []
        for index in range(method_count):
            entry_address = methods_address + index * profile.method_entry_size
            method_name_address = elf.read_u32(entry_address + profile.method_name_offset)
            handler_address = elf.read_u32(entry_address + profile.method_handler_offset)
            if not elf.executable(handler_address):
                raise ValueError("ubus method handler is not executable")
            method_name, _, _ = elf.read_string(
                method_name_address, policy.max_string_bytes
            )
            method_id = _stable_id(
                "native-ubus-method", source.canonical_path, object_name,
                method_name, entry_address, handler_address,
            )
            name_atom = _capture(
                source, content, elf.pointer_span(entry_address + profile.method_name_offset),
                method_id, "registers_method", method_name, "registers_ubus_method",
            )
            handler_identity = "{}@0x{:08x}".format(
                source.canonical_path, handler_address
            )
            handler_atom = _capture(
                source, content, elf.pointer_span(entry_address + profile.method_handler_offset),
                method_id, "binds_handler", handler_identity, "binds_ubus_handler",
            )
            atoms.extend((name_atom, handler_atom))
            methods.append(NativeUbusMethodRegistration(
                method_id, object_name, method_name, handler_address,
                handler_identity, entry_address,
                (name_atom.evidence_id, handler_atom.evidence_id),
            ))
        obj = NativeUbusObjectRegistration(
            object_id, object_name, type_name, object_address, init_address,
            registrar_address, tuple(methods),
            (init_atom.evidence_id, call_atom.evidence_id, object_atom.evidence_id),
        )
        return NativeUbusRegistrationResult(
            source.canonical_path, CoverageStatus.COMPLETED, True, len(content),
            _PRODUCER, profile.name, (obj,),
            tuple(sorted(atoms, key=lambda item: item.evidence_id)), (),
        )
    except (UnicodeDecodeError, ValueError, struct.error) as exc:
        message = str(exc)
        code = (
            "ubus_method_handler_not_executable"
            if message == "ubus method handler is not executable"
            else "native_ubus_registration_unresolved"
        )
        return _empty(source, profile, CoverageStatus.PARTIAL, code, message, len(content))
