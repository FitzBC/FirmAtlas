"""Symbol-profiled Native command-table to handler bindings."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import struct
from typing import Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry
from .native_deep import (
    _ALLOC,
    _ARM_MACHINE,
    _EXEC,
    _contains_address,
    _parse_elf,
    _read_dynamic_symbols,
    _section_by_index,
)


NATIVE_COMMAND_BINDING_SCHEMA_VERSION = (
    "firmatlas.mapping.native-command-binding/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("native-symbol-command-table", "0.1.0")
_CONTENT_KINDS = frozenset({"file", "hardlink", "archive", "archive_member"})


class NativeCommandBindingStatus(str, Enum):
    TABLE_BOUND = "table_bound"


@dataclass(frozen=True)
class NativeCommandTableProfile:
    name: str = "daemon-exe-info-arm32/v1"
    symbol_names: Tuple[str, ...] = ("daemon_exe_info",)
    entry_size: int = 372
    process_name_offset: int = 0
    process_name_size: int = 100
    command_offset: int = 112
    command_size: int = 256
    handler_pointer_offset: int = 368
    command_prefixes: Tuple[str, ...] = ("cfm post ", "killall ")

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.symbol_names or not self.command_prefixes:
            raise ValueError("Native command-table profile requires identity and signatures")
        if len(self.symbol_names) != len(set(self.symbol_names)):
            raise ValueError("Native command-table symbols must be unique")
        if min(
            self.entry_size,
            self.process_name_size,
            self.command_size,
        ) <= 0:
            raise ValueError("Native command-table dimensions must be positive")
        if min(
            self.process_name_offset,
            self.command_offset,
            self.handler_pointer_offset,
        ) < 0:
            raise ValueError("Native command-table offsets must not be negative")
        if (
            self.process_name_offset + self.process_name_size > self.entry_size
            or self.command_offset + self.command_size > self.entry_size
            or self.handler_pointer_offset + 4 > self.entry_size
        ):
            raise ValueError("Native command-table fields exceed the entry")


@dataclass(frozen=True)
class NativeCommandBindingPolicy:
    max_source_bytes: int = 64 * 1024 * 1024
    max_bindings: int = 10_000

    def __post_init__(self) -> None:
        if min(self.max_source_bytes, self.max_bindings) <= 0:
            raise ValueError("Native command binding limits must be positive")


@dataclass(frozen=True)
class NativeCommandBinding:
    binding_id: str
    table_symbol: str
    registration_address: int
    process_name: str
    command: str
    handler_address: int
    handler_identity: str
    binding_status: NativeCommandBindingStatus
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class NativeCommandBindingResult:
    source_path: str
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    profile: str
    bindings: Tuple[NativeCommandBinding, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[str, ...] = ()
    schema_version: str = NATIVE_COMMAND_BINDING_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "bindings": [
                {
                    **asdict(item),
                    "binding_status": item.binding_status.value,
                }
                for item in self.bindings
            ],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
        }


def _empty(
    source: SourceArtifactEntry,
    profile: NativeCommandTableProfile,
    status: CoverageStatus,
    diagnostic: str,
    processed_bytes: int = 0,
) -> NativeCommandBindingResult:
    return NativeCommandBindingResult(
        source.canonical_path, status, processed_bytes, _PRODUCER, profile.name,
        (), (), (diagnostic,),
    )


def _fixed_string(raw: bytes) -> str:
    end = raw.find(b"\x00")
    value = raw if end < 0 else raw[:end]
    if not value or any(byte < 0x20 or byte > 0x7E for byte in value):
        raise ValueError("fixed-width command-table text is not printable ASCII")
    return value.decode("ascii")


def _identity(
    source_path: str, symbol_name: str, address: int, command: str,
) -> str:
    raw = json.dumps(
        [source_path, symbol_name, address, command], separators=(",", ":")
    ).encode()
    return "native-command-binding:" + hashlib.sha256(raw).hexdigest()


def discover_native_command_table_bindings(
    source: SourceArtifactEntry,
    content: bytes,
    profile: NativeCommandTableProfile = NativeCommandTableProfile(),
    policy: NativeCommandBindingPolicy = NativeCommandBindingPolicy(),
) -> NativeCommandBindingResult:
    """Bind profiled command-table entries to executable ARM32 handlers."""
    if source.kind not in _CONTENT_KINDS:
        return _empty(source, profile, CoverageStatus.UNSUPPORTED, "unsupported_source_kind")
    if source.content_sha256 is None or len(content) != source.size \
            or hashlib.sha256(content).hexdigest() != source.content_sha256:
        return _empty(source, profile, CoverageStatus.FAILED, "source_mismatch")
    if len(content) > policy.max_source_bytes:
        return _empty(source, profile, CoverageStatus.SKIPPED_BY_POLICY, "source_budget_exceeded")
    try:
        elf = _parse_elf(content)
        if elf.pointer_size != 4 or elf.machine != _ARM_MACHINE:
            return _empty(
                source, profile, CoverageStatus.UNSUPPORTED,
                "unsupported_architecture", len(content),
            )
        symbols = tuple(
            symbol
            for table in _read_dynamic_symbols(elf, content).values()
            for symbol in table
            if symbol.name in profile.symbol_names
        )
    except TypeError:
        return _empty(source, profile, CoverageStatus.UNSUPPORTED, "unsupported_binary_format")
    except (ValueError, struct.error) as exc:
        return _empty(
            source, profile, CoverageStatus.FAILED,
            "malformed_elf:{}".format(exc), len(content),
        )
    if not symbols:
        return _empty(
            source, profile, CoverageStatus.NOT_APPLICABLE,
            "profiled_symbol_not_found", len(content),
        )

    executable_sections = tuple(
        section for section in elf.sections
        if section.flags & (_ALLOC | _EXEC) == (_ALLOC | _EXEC)
    )
    bindings = []
    atoms = []
    diagnostics = []
    limited = False
    for symbol in sorted(symbols, key=lambda item: (item.address, item.name)):
        section = _section_by_index(elf, symbol.section_index)
        if (
            section is None or section.section_type == 8
            or not section.flags & _ALLOC or section.flags & _EXEC
            or symbol.address < section.address
            or symbol.address + symbol.size > section.address + section.size
            or symbol.size == 0 or symbol.size % profile.entry_size != 0
        ):
            diagnostics.append("profiled_symbol_layout_invalid")
            continue
        symbol_offset = section.offset + symbol.address - section.address
        for index in range(symbol.size // profile.entry_size):
            if len(bindings) >= policy.max_bindings:
                limited = True
                break
            entry_address = symbol.address + index * profile.entry_size
            entry_offset = symbol_offset + index * profile.entry_size
            try:
                process_name = _fixed_string(content[
                    entry_offset + profile.process_name_offset:
                    entry_offset + profile.process_name_offset + profile.process_name_size
                ])
                command = _fixed_string(content[
                    entry_offset + profile.command_offset:
                    entry_offset + profile.command_offset + profile.command_size
                ])
            except ValueError:
                diagnostics.append("entry_text_invalid")
                continue
            if not command.startswith(profile.command_prefixes):
                diagnostics.append("entry_command_signature_mismatch")
                continue
            pointer_offset = entry_offset + profile.handler_pointer_offset
            handler_address = struct.unpack_from(
                elf.endian_prefix + "I", content, pointer_offset
            )[0]
            if not _contains_address(
                executable_sections, handler_address, _ALLOC | _EXEC
            ):
                diagnostics.append("handler_not_executable")
                continue
            binding_id = _identity(
                source.canonical_path, symbol.name, entry_address, command
            )
            handler_identity = "{}@0x{:08x}".format(
                source.canonical_path, handler_address
            )
            symbol_atom = capture_evidence(
                source, content,
                SpanSelection(
                    SpanKind.BINARY, symbol.source_offset,
                    symbol.source_offset + symbol.entry_size,
                ),
                EvidenceClaim(
                    binding_id, "resolves_command_table_symbol", symbol.name,
                    ObservationKind.DETERMINISTIC_DERIVED,
                    "resolves_command_table_symbol", 1.0,
                ), _PRODUCER,
            )
            process_atom = capture_evidence(
                source, content,
                SpanSelection(
                    SpanKind.BINARY,
                    entry_offset + profile.process_name_offset,
                    entry_offset + profile.process_name_offset
                    + len(process_name.encode("ascii")),
                ),
                EvidenceClaim(
                    binding_id, "names_managed_process", process_name,
                    ObservationKind.DIRECT_STATIC,
                    "names_managed_process", 1.0,
                ), _PRODUCER,
            )
            command_atom = capture_evidence(
                source, content,
                SpanSelection(
                    SpanKind.BINARY, entry_offset + profile.command_offset,
                    entry_offset + profile.command_offset
                    + len(command.encode("ascii")),
                ),
                EvidenceClaim(
                    binding_id, "declares_bound_command", command,
                    ObservationKind.DIRECT_STATIC,
                    "declares_bound_command", 1.0,
                ), _PRODUCER,
            )
            handler_atom = capture_evidence(
                source, content,
                SpanSelection(SpanKind.BINARY, pointer_offset, pointer_offset + 4),
                EvidenceClaim(
                    binding_id, "binds_command_handler", handler_identity,
                    ObservationKind.DETERMINISTIC_DERIVED,
                    "binds_command_handler", 1.0,
                ), _PRODUCER,
            )
            evidence_ids = tuple(atom.evidence_id for atom in (
                symbol_atom, process_atom, command_atom, handler_atom,
            ))
            atoms.extend((symbol_atom, process_atom, command_atom, handler_atom))
            bindings.append(NativeCommandBinding(
                binding_id, symbol.name, entry_address, process_name, command,
                handler_address, handler_identity,
                NativeCommandBindingStatus.TABLE_BOUND,
                "elf.{}:{}[{}]".format(profile.name, symbol.name, index),
                evidence_ids,
            ))
        if limited:
            break
    if limited:
        diagnostics.append("binding_budget_exhausted")
    status = (
        CoverageStatus.PARTIAL
        if diagnostics or limited else CoverageStatus.COMPLETED
    )
    return NativeCommandBindingResult(
        source.canonical_path, status, len(content), _PRODUCER, profile.name,
        tuple(bindings), tuple(sorted(atoms, key=lambda item: item.evidence_id)),
        tuple(sorted(set(diagnostics))),
    )
