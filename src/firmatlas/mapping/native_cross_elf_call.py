"""Evidence-backed ARM32 calls through ELF imports and matching exports."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import struct
from typing import Dict, Optional, Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry
from .native_ubus_registration import _Elf32Arm
from .native_deep import _find_pic_base, _parse_elf, _read_route_literal


NATIVE_CROSS_ELF_CALL_SCHEMA_VERSION = (
    "firmatlas.mapping.native-cross-elf-call/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("native-arm-cross-elf-call", "0.1.0")
_DT_SYMTAB = 6
_DT_SYMENT = 11
_DT_JMPREL = 23
_DT_NEEDED = 1
_DEFAULT_NON_RECURSIVE_RUNTIME_BASENAMES = (
    "ld-uClibc.so.0", "libc.so.0", "libcrypt.so.0", "libdl.so.0",
    "libgcc_s.so.1", "libm.so.0", "libpthread.so.0", "librt.so.0",
    "libutil.so.0",
)


@dataclass(frozen=True)
class ArmCrossElfArtifact:
    source: SourceArtifactEntry
    content: bytes


@dataclass(frozen=True)
class ArmCrossElfCallAnchor:
    target_ref: str
    source_path: str
    function_address: int

    def __post_init__(self) -> None:
        if not self.target_ref.strip() or not self.source_path.strip():
            raise ValueError("cross-ELF call anchor requires target and source")
        if self.function_address <= 0:
            raise ValueError("cross-ELF function address must be positive")


@dataclass(frozen=True)
class ArmCrossElfCallPolicy:
    max_artifacts: int = 4096
    max_total_bytes: int = 512 * 1024 * 1024
    max_functions: int = 20_000
    max_function_bytes: int = 16 * 1024
    max_hops: int = 5_000
    max_depth: int = 2
    non_recursive_runtime_basenames: Tuple[str, ...] = (
        _DEFAULT_NON_RECURSIVE_RUNTIME_BASENAMES
    )

    def __post_init__(self) -> None:
        if min(
            self.max_artifacts, self.max_total_bytes, self.max_functions,
            self.max_function_bytes, self.max_hops,
        ) <= 0:
            raise ValueError("cross-ELF call budgets must be positive")
        if self.max_depth < 0:
            raise ValueError("cross-ELF call depth must not be negative")
        if (
            len(self.non_recursive_runtime_basenames)
            != len(set(self.non_recursive_runtime_basenames))
            or any(not item.strip() for item in self.non_recursive_runtime_basenames)
        ):
            raise ValueError("cross-ELF runtime boundaries must be unique")


@dataclass(frozen=True)
class ArmCrossElfCallHop:
    hop_id: str
    origin_refs: Tuple[str, ...]
    source_path: str
    source_function_address: int
    source_function_identity: str
    callsite_address: int
    imported_symbol: str
    target_path: str
    target_function_address: int
    target_function_identity: str
    target_resolution_status: str
    argument_literals: Tuple[str, ...]
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class ArmCrossElfCallResult:
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    hops: Tuple[ArmCrossElfCallHop, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[str, ...] = ()
    schema_version: str = NATIVE_CROSS_ELF_CALL_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "hops": [asdict(item) for item in self.hops],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
        }


@dataclass(frozen=True)
class _Export:
    path: str
    name: str
    address: int
    size: int
    symbol_span: Tuple[int, int]


@dataclass(frozen=True)
class _Parsed:
    artifact: ArmCrossElfArtifact
    elf: _Elf32Arm
    symbols: tuple
    plt: Dict[int, Tuple[str, Tuple[int, int]]]
    exports: Tuple[_Export, ...]
    needed: Tuple[str, ...]


def _stable_id(prefix: str, *values: object) -> str:
    raw = json.dumps(values, separators=(",", ":"), ensure_ascii=False).encode()
    return prefix + ":" + hashlib.sha256(raw).hexdigest()


def _branch_target(address: int, instruction: int) -> Optional[int]:
    if instruction >> 24 & 0xF != 0xB:
        return None
    displacement = instruction & 0x00FFFFFF
    if displacement & 0x00800000:
        displacement -= 0x01000000
    return address + 8 + displacement * 4


def _parse(artifact: ArmCrossElfArtifact) -> _Parsed:
    source, content = artifact.source, artifact.content
    if (
        source.kind not in {"file", "hardlink", "archive_member"}
        or source.content_sha256 is None
        or len(content) != source.size
        or hashlib.sha256(content).hexdigest() != source.content_sha256
    ):
        raise ValueError("source_mismatch")
    elf = _Elf32Arm(content)
    symbols = elf.symbols()
    plt_pairs = elf.plt_symbols(symbols)
    relocation_offset = elf.address_offset(
        elf.dynamic[_DT_JMPREL], len(plt_pairs) * 8
    )
    plt = {
        address: (name, (relocation_offset + index * 8,
                         relocation_offset + index * 8 + 8))
        for index, (address, name) in enumerate(plt_pairs)
    }
    symbol_entry_size = elf.dynamic[_DT_SYMENT]
    symbol_offset = elf.address_offset(
        elf.dynamic[_DT_SYMTAB], len(symbols) * symbol_entry_size
    )
    exports = []
    for index, symbol in enumerate(symbols):
        entry = symbol_offset + index * symbol_entry_size
        _, value, size, _, _, section_index = struct.unpack_from(
            "<IIIBBH", content, entry
        )
        if symbol.name and section_index != 0 and value and elf.executable(value):
            exports.append(_Export(
                source.canonical_path, symbol.name, value, size,
                (entry, entry + symbol_entry_size),
            ))
    dynamic = next(item for item in elf.segments if item.segment_type == 2)
    needed_offsets = []
    for cursor in range(dynamic.offset, dynamic.offset + dynamic.file_size, 8):
        tag, value = struct.unpack_from("<II", content, cursor)
        if tag == 0:
            break
        if tag == _DT_NEEDED:
            needed_offsets.append(value)
    string_offset = elf.address_offset(elf.dynamic[5], elf.dynamic[10])
    strings = content[string_offset:string_offset + elf.dynamic[10]]
    needed = []
    for offset in needed_offsets:
        end = strings.find(b"\x00", offset)
        if end < 0:
            raise ValueError("ELF needed name is unterminated")
        needed.append(strings[offset:end].decode("ascii"))
    return _Parsed(artifact, elf, symbols, plt, tuple(exports), tuple(needed))


def _function_end(parsed: _Parsed, address: int, maximum: int) -> int:
    exact = next((
        item for item in parsed.exports
        if item.address == address and item.size > 0
    ), None)
    if exact is not None:
        return min(address + exact.size, address + maximum)
    for cursor in range(address, address + maximum, 4):
        if not parsed.elf.executable(cursor):
            return cursor
        try:
            instruction = struct.unpack_from(
                "<I", parsed.artifact.content,
                parsed.elf.address_offset(cursor, 4),
            )[0]
        except ValueError:
            return cursor
        # pop {..., pc} or bx lr closes the current ordinary ARM function.
        if cursor > address and (
            instruction == 0xE12FFF1E
            or instruction & 0xFFFF8000 == 0xE8BD8000
        ):
            return cursor + 4
    return address + maximum


def _resolve_export(
    current: _Parsed, name: str, exports: Dict[str, Tuple[_Export, ...]],
) -> Optional[_Export]:
    choices = exports.get(name, ())
    if not choices:
        return None
    current_path = current.artifact.source.canonical_path
    same = tuple(item for item in choices if item.path == current_path)
    if same:
        return sorted(same, key=lambda item: item.address)[0]
    needed = tuple(
        item for item in choices
        if item.path.rsplit("/", 1)[-1] in current.needed
    )
    if len(needed) == 1:
        return needed[0]
    return None


def _argument_literals(
    parsed: _Parsed, function_address: int, callsite: int,
) -> Tuple[Tuple[str, ...], Tuple[Tuple[int, int], ...]]:
    """Conservatively recover r0 PIC/GOT string loads near one ARM call."""
    try:
        deep_elf = _parse_elf(parsed.artifact.content)
    except (TypeError, ValueError, struct.error):
        return (), ()
    got = next((item for item in deep_elf.sections if item.name == ".got"), None)
    if got is None or _find_pic_base(
        deep_elf, parsed.artifact.content, callsite, got.address,
        callsite - function_address + 4,
    ) is None:
        return (), ()
    lower = max(function_address, callsite - 32)
    found = []
    for address in range(lower, callsite - 8, 4):
        try:
            one = struct.unpack_from(
                "<I", parsed.artifact.content,
                parsed.elf.address_offset(address, 4),
            )[0]
            two = struct.unpack_from(
                "<I", parsed.artifact.content,
                parsed.elf.address_offset(address + 4, 4),
            )[0]
            three = struct.unpack_from(
                "<I", parsed.artifact.content,
                parsed.elf.address_offset(address + 8, 4),
            )[0]
        except ValueError:
            continue
        if not (
            one & 0xFFFFF000 == 0xE59F3000
            and two == 0xE0843003
            and three == 0xE1A00003
        ):
            continue
        literal_address = address + 8 + (one & 0xFFF)
        try:
            delta = parsed.elf.read_u32(literal_address)
        except ValueError:
            continue
        literal = _read_route_literal(
            deep_elf, parsed.artifact.content,
            (got.address + delta) & 0xFFFFFFFF, 512,
        )
        if literal is not None:
            found.append((literal[0], (literal[1], literal[1] + len(literal[0]))))
    return (
        tuple(item[0] for item in found[-1:]),
        tuple(item[1] for item in found[-1:]),
    )


def discover_arm_cross_elf_calls(
    artifacts: Tuple[ArmCrossElfArtifact, ...],
    anchors: Tuple[ArmCrossElfCallAnchor, ...],
    policy: ArmCrossElfCallPolicy = ArmCrossElfCallPolicy(),
) -> ArmCrossElfCallResult:
    """Follow direct ARM BL calls through verified PLT imports to exports."""
    diagnostics = []
    if len(artifacts) > policy.max_artifacts:
        return ArmCrossElfCallResult(
            CoverageStatus.SKIPPED_BY_POLICY, 0, _PRODUCER, (), (),
            ("artifact_budget_exceeded",),
        )
    total = sum(len(item.content) for item in artifacts)
    if total > policy.max_total_bytes:
        return ArmCrossElfCallResult(
            CoverageStatus.SKIPPED_BY_POLICY, 0, _PRODUCER, (), (),
            ("byte_budget_exceeded",),
        )
    parsed = {}
    for artifact in artifacts:
        try:
            value = _parse(artifact)
        except (KeyError, TypeError, ValueError, struct.error) as exc:
            message = str(exc)
            if message not in {
                "ELF dynamic segment is missing",
                "ELF program headers are missing",
                "adapter requires ARM REL PLT relocations",
            }:
                diagnostics.append("artifact_parse_failed:{}:{}".format(
                    artifact.source.canonical_path, message
                ))
            continue
        if value.artifact.source.canonical_path in parsed:
            diagnostics.append("duplicate_artifact_path")
            continue
        parsed[value.artifact.source.canonical_path] = value
    exports: Dict[str, list] = {}
    for value in parsed.values():
        for item in value.exports:
            exports.setdefault(item.name, []).append(item)
    frozen_exports = {key: tuple(value) for key, value in exports.items()}

    pending: Dict[Tuple[str, int], set] = {}
    for anchor in sorted(anchors, key=lambda item: (
        item.target_ref, item.source_path, item.function_address
    )):
        if anchor.source_path not in parsed:
            diagnostics.append("anchor_artifact_missing")
            continue
        if not parsed[anchor.source_path].elf.executable(anchor.function_address):
            diagnostics.append("anchor_function_not_executable")
            continue
        pending.setdefault(
            (anchor.source_path, anchor.function_address), set()
        ).add(anchor.target_ref)
    queue = [(*key, 0) for key in sorted(pending)]
    propagated: Dict[Tuple[str, int], set] = {}
    hop_specs = {}
    atoms = []
    limited = False
    while queue:
        path, function_address, depth = queue.pop(0)
        function_key = (path, function_address)
        origins = pending.get(function_key, set())
        delta = origins - propagated.get(function_key, set())
        if not delta:
            continue
        if len(propagated) >= policy.max_functions and function_key not in propagated:
            limited = True
            diagnostics.append("function_budget_exhausted")
            break
        propagated.setdefault(function_key, set()).update(delta)
        value = parsed[path]
        end = _function_end(value, function_address, policy.max_function_bytes)
        for callsite in range(function_address, end, 4):
            try:
                call_offset = value.elf.address_offset(callsite, 4)
            except ValueError:
                break
            instruction = struct.unpack_from(
                "<I", value.artifact.content, call_offset
            )[0]
            target = _branch_target(callsite, instruction)
            imported = value.plt.get(target)
            if imported is None:
                continue
            symbol_name, relocation_span = imported
            export = _resolve_export(value, symbol_name, frozen_exports)
            argument_literals, argument_spans = (
                _argument_literals(value, function_address, callsite)
                if export is None else ((), ())
            )
            if export is None and not argument_literals:
                continue
            hop_id = _stable_id(
                "native-cross-elf-call", path, function_address,
                callsite, symbol_name,
                export.path if export is not None else "",
                export.address if export is not None else 0,
            )
            call_atom = capture_evidence(
                value.artifact.source, value.artifact.content,
                SpanSelection(SpanKind.BINARY, call_offset, call_offset + 4),
                EvidenceClaim(
                    hop_id, "calls_import", symbol_name,
                    ObservationKind.DETERMINISTIC_DERIVED,
                    "calls_verified_plt_import", 1.0,
                ), _PRODUCER,
            )
            export_atom = None
            if export is not None:
                export_value = parsed[export.path]
                export_atom = capture_evidence(
                    export_value.artifact.source, export_value.artifact.content,
                    SpanSelection(SpanKind.BINARY, *export.symbol_span),
                    EvidenceClaim(
                        hop_id, "resolves_export",
                        "{}@0x{:08x}".format(export.path, export.address),
                        ObservationKind.DETERMINISTIC_DERIVED,
                        "resolves_dynamic_export", 1.0,
                    ), _PRODUCER,
                )
            argument_atoms = tuple(
                capture_evidence(
                    value.artifact.source, value.artifact.content,
                    SpanSelection(SpanKind.BINARY, *span),
                    EvidenceClaim(
                        hop_id, "passes_literal_argument", literal,
                        ObservationKind.DETERMINISTIC_DERIVED,
                        "passes_import_argument_literal", 1.0,
                    ), _PRODUCER,
                )
                for literal, span in zip(argument_literals, argument_spans)
            )
            spec = hop_specs.setdefault(hop_id, {
                "origin_refs": set(),
                "path": path,
                "function_address": function_address,
                "callsite": callsite,
                "symbol_name": symbol_name,
                "export": export,
                "argument_literals": argument_literals,
                "evidence_ids": tuple(item.evidence_id for item in (
                    call_atom, *((export_atom,) if export_atom else ()),
                    *argument_atoms,
                )),
            })
            spec["origin_refs"].update(delta)
            atoms.extend((call_atom, *(
                (export_atom,) if export_atom is not None else ()
            ), *argument_atoms))
            if (
                export is not None
                and depth < policy.max_depth
                and export.path.rsplit("/", 1)[-1]
                not in policy.non_recursive_runtime_basenames
            ):
                target_key = (export.path, export.address)
                before = len(pending.setdefault(target_key, set()))
                pending[target_key].update(delta)
                if len(pending[target_key]) > before:
                    queue.append((*target_key, depth + 1))
            if len(hop_specs) >= policy.max_hops:
                limited = True
                diagnostics.append("hop_budget_exhausted")
                break
        if limited:
            break
    hops = tuple(
        ArmCrossElfCallHop(
            hop_id,
            tuple(sorted(spec["origin_refs"])),
            spec["path"],
            spec["function_address"],
            "{}@0x{:08x}".format(spec["path"], spec["function_address"]),
            spec["callsite"],
            spec["symbol_name"],
            spec["export"].path if spec["export"] is not None else "",
            spec["export"].address if spec["export"] is not None else 0,
            "{}@0x{:08x}".format(
                spec["export"].path, spec["export"].address
            ) if spec["export"] is not None else "",
            "resolved_export" if spec["export"] is not None
            else "unresolved_import_owner",
            spec["argument_literals"],
            spec["evidence_ids"],
        )
        for hop_id, spec in sorted(hop_specs.items())
    )
    status = CoverageStatus.PARTIAL if diagnostics or limited else CoverageStatus.COMPLETED
    return ArmCrossElfCallResult(
        status, total, _PRODUCER,
        hops,
        tuple(sorted({item.evidence_id: item for item in atoms}.values(),
                     key=lambda item: item.evidence_id)),
        tuple(sorted(set(diagnostics))),
    )
