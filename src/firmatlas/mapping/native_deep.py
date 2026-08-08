"""Conservative Native route-table binding and scheduler adapter."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
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
_ALLOC = 0x2
_EXEC = 0x4
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
class NativeRouteBinding:
    binding_id: str
    target_ref: str
    route_token: str
    handler_identity: str
    registration_address: int
    handler_address: int
    source_construct: str
    evidence_ids: Tuple[str, ...]


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
        by_capability = {atom.capability: atom for atom in atoms}
        if len(atoms) != 3 or set(by_capability) != {
            "mentions_endpoint", "registers_route", "binds_handler",
        }:
            raise ValueError("native deep binding requires the complete three-part proof")
        if (
            by_capability["mentions_endpoint"].observation_kind
            is not ObservationKind.DIRECT_STATIC
            or by_capability["mentions_endpoint"].object_value != binding.route_token
        ):
            raise ValueError("native deep route literal proof is invalid")
        if (
            by_capability["registers_route"].observation_kind
            is not ObservationKind.DETERMINISTIC_DERIVED
            or by_capability["registers_route"].object_value != binding.route_token
        ):
            raise ValueError("native deep route registration proof is invalid")
        if (
            by_capability["binds_handler"].observation_kind
            is not ObservationKind.DETERMINISTIC_DERIVED
            or by_capability["binds_handler"].object_value != binding.handler_identity
        ):
            raise ValueError("native deep handler binding proof is invalid")


@dataclass(frozen=True)
class _Section:
    name: str
    section_type: int
    flags: int
    address: int
    offset: int
    size: int


@dataclass(frozen=True)
class _Elf:
    pointer_size: int
    endian_prefix: str
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
        raw_sections.append((name_offset, section_type, flags, address, offset, size))
    name_section = raw_sections[name_index]
    if name_section[1] != 3:
        raise ValueError("ELF section name table has an invalid type")
    names = content[name_section[4] : name_section[4] + name_section[5]]
    sections = tuple(
        _Section(_string_at(names, item[0]), *item[1:]) for item in raw_sections
    )
    return _Elf(pointer_size, endian, sections)


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
