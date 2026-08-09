"""Deterministic shallow Native hint producer for ELF firmware binaries."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import re
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


NATIVE_RESULT_SCHEMA_VERSION = "firmatlas.mapping.native-result/v1alpha1"
_PRODUCER = AnalyzerIdentity(name="native-shallow-producer", version="0.1.0")
_CONTENT_KINDS = frozenset({"file", "hardlink", "archive", "archive_member"})
_ROUTE_TOKEN = re.compile(
    r"^(?:Get|Set|get|set|del|add|save|init|open)[A-Za-z0-9_]{3,}$"
)
_SYMBOL_HINT = re.compile(r"^(?:form|from|webs|asp)[A-Za-z0-9_]{3,}$")
_ENDPOINT_SUFFIXES = (".asp", ".cgi", ".php", ".htm", ".html")
_MACHINES = {
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    40: "ARM",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
}


class NativeHintKind(str, Enum):
    ENDPOINT_LITERAL = "endpoint_literal"
    ROUTE_TOKEN = "route_token"
    SYMBOL = "symbol"
    SERVER_HINT = "server_hint"


@dataclass(frozen=True)
class NativePolicy:
    max_source_bytes: int = 32 * 1024 * 1024
    max_hints: int = 20_000
    min_string_length: int = 4

    def __post_init__(self) -> None:
        if (
            self.max_source_bytes <= 0
            or self.max_hints <= 0
            or self.min_string_length < 4
        ):
            raise ValueError("native producer limits must be positive and bounded")


@dataclass(frozen=True)
class NativeHint:
    hint_id: str
    kind: NativeHintKind
    value: str
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class NativeDiagnostic:
    code: str
    message: str


@dataclass(frozen=True)
class NativeProducerResult:
    source_path: str
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    detected_format: Optional[str]
    bitness: Optional[int]
    endianness: Optional[str]
    machine: Optional[str]
    hints: Tuple[NativeHint, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[NativeDiagnostic, ...] = ()
    schema_version: str = NATIVE_RESULT_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "source_path": self.source_path,
            "coverage_status": self.coverage_status.value,
            "processed_bytes": self.processed_bytes,
            "producer": asdict(self.producer),
            "detected_format": self.detected_format,
            "bitness": self.bitness,
            "endianness": self.endianness,
            "machine": self.machine,
            "hints": [
                {**asdict(item), "kind": item.kind.value} for item in self.hints
            ],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
            "diagnostics": [asdict(item) for item in self.diagnostics],
        }


@dataclass(frozen=True)
class _ElfMetadata:
    bitness: int
    endianness: str
    endian_prefix: str
    machine: str
    sections: tuple


@dataclass(frozen=True)
class _Section:
    section_type: int
    offset: int
    size: int
    link: int
    entry_size: int


@dataclass(frozen=True)
class _LocatedValue:
    value: str
    start: int
    end: int
    construct: str


def _empty_result(
    source: SourceArtifactEntry,
    status: CoverageStatus,
    code: str,
    message: str,
    detected_format: Optional[str] = None,
) -> NativeProducerResult:
    return NativeProducerResult(
        source_path=source.canonical_path,
        coverage_status=status,
        processed_bytes=0,
        producer=_PRODUCER,
        detected_format=detected_format,
        bitness=None,
        endianness=None,
        machine=None,
        hints=(),
        evidence_atoms=(),
        diagnostics=(NativeDiagnostic(code, message),),
    )


def _checked_slice(content: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset + size > len(content):
        raise ValueError("ELF range exceeds source bytes")
    return content[offset : offset + size]


def _parse_elf(content: bytes) -> _ElfMetadata:
    if len(content) < 16 or content[:4] != b"\x7fELF":
        raise TypeError("unsupported binary format")
    elf_class = content[4]
    data_encoding = content[5]
    if elf_class not in {1, 2} or data_encoding not in {1, 2}:
        raise ValueError("unsupported ELF class or data encoding")
    bitness = 32 if elf_class == 1 else 64
    endian_prefix = "<" if data_encoding == 1 else ">"
    endianness = "little" if data_encoding == 1 else "big"
    header_format = endian_prefix + ("HHIIIIIHHHHHH" if bitness == 32 else "HHIQQQIHHHHHH")
    header_size = 52 if bitness == 32 else 64
    if len(content) < header_size:
        raise ValueError("truncated ELF header")
    values = struct.unpack_from(header_format, content, 16)
    machine_number = values[1]
    section_offset = values[5]
    section_entry_size = values[10]
    section_count = values[11]
    expected_section_size = 40 if bitness == 32 else 64
    if section_count == 0 and section_offset == 0:
        return _ElfMetadata(
            bitness=bitness,
            endianness=endianness,
            endian_prefix=endian_prefix,
            machine=_MACHINES.get(
                machine_number, "machine-{}".format(machine_number)
            ),
            sections=(),
        )
    if section_count <= 0 or section_entry_size < expected_section_size:
        raise ValueError("ELF section table is missing or malformed")
    _checked_slice(content, section_offset, section_entry_size * section_count)
    section_format = endian_prefix + (
        "IIIIIIIIII" if bitness == 32 else "IIQQQQIIQQ"
    )
    sections = []
    for index in range(section_count):
        offset = section_offset + index * section_entry_size
        section = struct.unpack_from(section_format, content, offset)
        section_type = section[1]
        file_offset = section[4]
        size = section[5]
        link = section[6]
        entry_size = section[9]
        if section_type != 8:
            _checked_slice(content, file_offset, size)
        sections.append(
            _Section(
                section_type=section_type,
                offset=file_offset,
                size=size,
                link=link,
                entry_size=entry_size,
            )
        )
    return _ElfMetadata(
        bitness=bitness,
        endianness=endianness,
        endian_prefix=endian_prefix,
        machine=_MACHINES.get(machine_number, "machine-{}".format(machine_number)),
        sections=tuple(sections),
    )


def _printable_strings(
    content: bytes, minimum: int, excluded_ranges: tuple = ()
) -> tuple:
    values = []
    index = 0
    while index < len(content):
        if not 0x20 <= content[index] <= 0x7E:
            index += 1
            continue
        start = index
        while index < len(content) and 0x20 <= content[index] <= 0x7E:
            index += 1
        excluded = any(
            range_start <= start < range_end
            for range_start, range_end in excluded_ranges
        )
        if index - start >= minimum and not excluded:
            values.append(
                _LocatedValue(
                    content[start:index].decode("ascii"),
                    start,
                    index,
                    "elf.printable_string",
                )
            )
    return tuple(values)


def _terminated_ascii(content: bytes, start: int, limit: int) -> _LocatedValue:
    if not 0 <= start < limit <= len(content):
        raise ValueError("ELF string offset is outside its table")
    end = content.find(b"\x00", start, limit)
    if end < 0:
        raise ValueError("ELF string is not NUL terminated")
    try:
        value = content[start:end].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("ELF symbol name is not ASCII") from exc
    return _LocatedValue(value, start, end, "elf.dynamic_symbol")


def _dynamic_symbols(content: bytes, metadata: _ElfMetadata) -> tuple:
    values = []
    for section in metadata.sections:
        if section.section_type != 11:
            continue
        if not 0 <= section.link < len(metadata.sections):
            raise ValueError("ELF symbol table has an invalid string-table link")
        string_table = metadata.sections[section.link]
        if string_table.section_type != 3:
            raise ValueError("ELF dynamic symbols do not link to a string table")
        minimum_entry_size = 16 if metadata.bitness == 32 else 24
        entry_size = section.entry_size or minimum_entry_size
        if entry_size < minimum_entry_size or section.size % entry_size:
            raise ValueError("ELF dynamic symbol table has invalid entry sizing")
        for relative in range(0, section.size, entry_size):
            entry_offset = section.offset + relative
            if metadata.bitness == 32:
                name_offset = struct.unpack_from(
                    metadata.endian_prefix + "I", content, entry_offset
                )[0]
            else:
                name_offset = struct.unpack_from(
                    metadata.endian_prefix + "I", content, entry_offset
                )[0]
            if name_offset == 0:
                continue
            values.append(
                _terminated_ascii(
                    content,
                    string_table.offset + name_offset,
                    string_table.offset + string_table.size,
                )
            )
    return tuple(values)


def _classify_string(value: str) -> Optional[NativeHintKind]:
    if value == "/webroot" or "httpd listen" in value.lower():
        return NativeHintKind.SERVER_HINT
    if value.startswith("/") and (
        value.startswith(("/goform/", "/cgi-bin/", "/HNAP"))
        or value.lower().endswith(_ENDPOINT_SUFFIXES)
    ):
        return NativeHintKind.ENDPOINT_LITERAL
    if _ROUTE_TOKEN.fullmatch(value):
        return NativeHintKind.ROUTE_TOKEN
    return None


def _hint_id(source_path: str, kind: NativeHintKind, value: str) -> str:
    payload = json.dumps(
        {"kind": kind.value, "source_path": source_path, "value": value},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "native-hint:{}".format(hashlib.sha256(payload).hexdigest())


def discover_native_hints(
    source: SourceArtifactEntry,
    content: bytes,
    policy: NativePolicy = NativePolicy(),
) -> NativeProducerResult:
    """Publish bounded ELF string/symbol hints without claiming route binding."""

    if len(content) > policy.max_source_bytes:
        return _empty_result(
            source,
            CoverageStatus.SKIPPED_BY_POLICY,
            "source_budget_exceeded",
            "source exceeds configured byte budget",
        )
    if source.kind not in _CONTENT_KINDS:
        return _empty_result(
            source,
            CoverageStatus.FAILED,
            "unsupported_source_kind",
            "source kind cannot publish content evidence",
        )
    if len(content) != source.size or hashlib.sha256(content).hexdigest() != source.content_sha256:
        return _empty_result(
            source,
            CoverageStatus.FAILED,
            "source_mismatch",
            "content does not match source inventory",
        )
    try:
        metadata = _parse_elf(content)
    except TypeError:
        return _empty_result(
            source,
            CoverageStatus.UNSUPPORTED,
            "unsupported_binary_format",
            "native shallow producer currently supports ELF only",
        )
    except (ValueError, struct.error) as exc:
        return _empty_result(
            source,
            CoverageStatus.FAILED,
            "malformed_elf",
            str(exc),
            detected_format="elf",
        )

    located_hints = []
    string_table_ranges = tuple(
        (section.offset, section.offset + section.size)
        for section in metadata.sections
        if section.section_type == 3
    )
    for located in _printable_strings(
        content, policy.min_string_length, string_table_ranges
    ):
        kind = _classify_string(located.value)
        if kind is not None:
            located_hints.append((kind, located))
    try:
        for located in _dynamic_symbols(content, metadata):
            if _SYMBOL_HINT.fullmatch(located.value):
                located_hints.append((NativeHintKind.SYMBOL, located))
    except (ValueError, struct.error) as exc:
        return _empty_result(
            source,
            CoverageStatus.FAILED,
            "malformed_elf",
            str(exc),
            detected_format="elf",
        )

    truncated = len({(kind, item.value) for kind, item in located_hints}) > policy.max_hints
    allowed_keys = []
    allowed_key_set = set()
    for kind, located in located_hints:
        key = (kind, located.value)
        if key not in allowed_key_set:
            if len(allowed_keys) >= policy.max_hints:
                continue
            allowed_keys.append(key)
            allowed_key_set.add(key)

    hints = {}
    evidence_atoms = {}
    for kind, located in located_hints:
        if (kind, located.value) not in allowed_key_set:
            continue
        hint_id = _hint_id(source.canonical_path, kind, located.value)
        capability = {
            NativeHintKind.ENDPOINT_LITERAL: "mentions_endpoint",
            NativeHintKind.ROUTE_TOKEN: "mentions_endpoint",
            NativeHintKind.SYMBOL: "declares_symbol",
            NativeHintKind.SERVER_HINT: "server_hint",
        }[kind]
        atom = capture_evidence(
            source=source,
            content=content,
            selection=SpanSelection(SpanKind.BINARY, located.start, located.end),
            claim=EvidenceClaim(
                subject_ref=hint_id,
                predicate=capability,
                object_value=located.value,
                observation_kind=ObservationKind.DIRECT_STATIC,
                capability=capability,
                confidence=1.0,
            ),
            producer=_PRODUCER,
        )
        evidence_atoms[atom.evidence_id] = atom
        existing = hints.get(hint_id)
        evidence_ids = (
            (atom.evidence_id,)
            if existing is None
            else (*existing.evidence_ids, atom.evidence_id)
        )
        hints[hint_id] = NativeHint(
            hint_id=hint_id,
            kind=kind,
            value=located.value,
            source_construct=located.construct,
            evidence_ids=evidence_ids,
        )

    diagnostics = (
        (
            NativeDiagnostic(
                "hint_budget_exceeded",
                "hint budget truncated native shallow analysis",
            ),
        )
        if truncated
        else ()
    )
    return NativeProducerResult(
        source_path=source.canonical_path,
        coverage_status=CoverageStatus.PARTIAL if diagnostics else CoverageStatus.COMPLETED,
        processed_bytes=len(content),
        producer=_PRODUCER,
        detected_format="elf",
        bitness=metadata.bitness,
        endianness=metadata.endianness,
        machine=metadata.machine,
        hints=tuple(hints.values()),
        evidence_atoms=tuple(evidence_atoms.values()),
        diagnostics=diagnostics,
    )
