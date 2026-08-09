"""Deterministic MIPS CGI nested-selector dispatch proofs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
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
    NativeRouteAnchor,
    discover_mips_inline_route_bindings,
)
from .native_value_flow import _got_target_resolver, _read_ascii


MIPS_NESTED_DISPATCH_RESULT_SCHEMA_VERSION = (
    "firmatlas.mapping.mips-nested-dispatch-result/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("native-mips-cgi-nested-dispatch", "0.1.0")
_CONTENT_KINDS = frozenset({"file", "hardlink", "archive", "archive_member"})

_ZERO = 0
_V0 = 2
_V1 = 3
_A0 = 4
_A1 = 5
_A2 = 6
_A3 = 7
_S0 = 16
_S1 = 17
_S2 = 18
_S3 = 19
_S4 = 20
_T9 = 25
_GP = 28
_SP = 29
_RA = 31


@dataclass(frozen=True)
class MipsNestedDispatchAnchor:
    target_ref: str
    transport_selector_name: str
    transport_selector_value: str
    operation_namespace: str
    operation_token: str

    def __post_init__(self) -> None:
        if any(not value.strip() for value in (
            self.target_ref,
            self.transport_selector_name,
            self.transport_selector_value,
            self.operation_namespace,
            self.operation_token,
        )):
            raise ValueError("nested dispatch anchor fields must not be blank")
        if any(separator in value for value in (
            self.transport_selector_name,
            self.transport_selector_value,
            self.operation_namespace,
            self.operation_token,
        ) for separator in ("&", "=", "/")):
            raise ValueError("nested dispatch anchor fields must be atomic tokens")


@dataclass(frozen=True)
class MipsNestedDispatchProfile:
    name: str = "mips32-cgi-query-json-table-dispatch/v1"
    dispatcher_symbol: str = "main"
    upload_parser_symbol: str = "cutUploadFile"
    table_symbols: Tuple[Tuple[str, str], ...] = (
        ("get", "get_handle_t"),
        ("set", "set_handle_t"),
        ("del", "del_handle_t"),
        ("other", "other_handle_t"),
    )
    max_string_bytes: int = 256

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.dispatcher_symbol.strip():
            raise ValueError("nested dispatch profile requires identity and dispatcher")
        if not self.upload_parser_symbol.strip() or not self.table_symbols:
            raise ValueError("nested dispatch profile requires upload parser and tables")
        prefixes = tuple(item[0] for item in self.table_symbols)
        symbols = tuple(item[1] for item in self.table_symbols)
        if (
            any(not value.strip() for value in (*prefixes, *symbols,))
            or len(prefixes) != len(set(prefixes))
            or len(symbols) != len(set(symbols))
            or self.max_string_bytes <= 0
        ):
            raise ValueError("nested dispatch profile table map is invalid")


@dataclass(frozen=True)
class MipsNestedDispatchPolicy:
    max_source_bytes: int = 64 * 1024 * 1024
    max_anchors: int = 10_000
    max_dispatcher_instructions: int = 2_048
    max_paths: int = 10_000

    def __post_init__(self) -> None:
        if any(value <= 0 for value in (
            self.max_source_bytes,
            self.max_anchors,
            self.max_dispatcher_instructions,
            self.max_paths,
        )):
            raise ValueError("nested dispatch budgets must be positive")


@dataclass(frozen=True)
class MipsNestedDispatchPath:
    path_id: str
    target_ref: str
    transport_selector: str
    nested_selector: str
    normalized_operation: str
    dispatcher_identity: str
    dispatcher_address: int
    transport_match_callsite: int
    selector_extract_callsite: int
    upload_parse_callsite: int
    suffix_normalization_address: int
    dispatch_table_symbol: str
    registration_address: int
    handler_address: int
    handler_identity: str
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class MipsNestedDispatchDiagnostic:
    code: str
    message: str
    target_ref: Optional[str] = None


@dataclass(frozen=True)
class MipsNestedDispatchResult:
    source_path: str
    coverage_status: CoverageStatus
    producer: AnalyzerIdentity
    profile: str
    processed_instructions: int
    paths: Tuple[MipsNestedDispatchPath, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[MipsNestedDispatchDiagnostic, ...] = ()
    schema_version: str = MIPS_NESTED_DISPATCH_RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_result(self)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "source_path": self.source_path,
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "profile": self.profile,
            "processed_instructions": self.processed_instructions,
            "paths": [
                {**asdict(item), "evidence_ids": list(item.evidence_ids)}
                for item in self.paths
            ],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
            "diagnostics": [asdict(item) for item in self.diagnostics],
        }


def _validate_result(result: MipsNestedDispatchResult) -> None:
    if result.schema_version != MIPS_NESTED_DISPATCH_RESULT_SCHEMA_VERSION:
        raise ValueError("unsupported MIPS nested dispatch result schema")
    if not result.source_path.strip() or not result.profile.strip():
        raise ValueError("MIPS nested dispatch result requires source and profile")
    if result.processed_instructions < 0:
        raise ValueError("processed instruction count must not be negative")
    atoms = {item.evidence_id: item for item in result.evidence_atoms}
    if len(atoms) != len(result.evidence_atoms):
        raise ValueError("duplicate MIPS nested dispatch evidence identity")
    path_ids = set()
    required = {
        "selects_transport_mode",
        "parses_upload_body",
        "constructs_dispatch_payload",
        "normalizes_operation_suffix",
        "selects_dispatch_table",
        "binds_handler",
    }
    for path in result.paths:
        if path.path_id in path_ids:
            raise ValueError("duplicate MIPS nested dispatch path identity")
        path_ids.add(path.path_id)
        if path.dispatcher_identity != "{}@0x{:08x}".format(
            result.source_path, path.dispatcher_address
        ):
            raise ValueError("nested dispatch dispatcher identity is inconsistent")
        if path.handler_identity != "{}@0x{:08x}".format(
            result.source_path, path.handler_address
        ):
            raise ValueError("nested dispatch handler identity is inconsistent")
        if len(path.evidence_ids) != len(required):
            raise ValueError("nested dispatch path requires a six-part proof")
        capabilities = set()
        by_capability = {}
        for evidence_id in path.evidence_ids:
            atom = atoms.get(evidence_id)
            if atom is None or atom.subject_ref != path.path_id:
                raise ValueError("nested dispatch path references invalid evidence")
            if atom.source_span.artifact_path != result.source_path:
                raise ValueError("nested dispatch evidence source is inconsistent")
            if (atom.producer, atom.producer_version) != (
                result.producer.name, result.producer.version
            ) or atom.confidence != 1.0:
                raise ValueError("nested dispatch proof must be deterministic")
            capabilities.add(atom.capability)
            by_capability[atom.capability] = atom
        if capabilities != required:
            raise ValueError("nested dispatch proof capabilities are incomplete")
        expected_objects = {
            "selects_transport_mode": path.transport_selector,
            "constructs_dispatch_payload": "topicurl={}".format(
                path.nested_selector
            ),
            "normalizes_operation_suffix": "{}->{}".format(
                path.nested_selector, path.normalized_operation
            ),
            "selects_dispatch_table": path.dispatch_table_symbol,
            "binds_handler": path.handler_identity,
        }
        for capability, expected in expected_objects.items():
            if by_capability[capability].object_value != expected:
                label = (
                    "dispatch table" if capability == "selects_dispatch_table"
                    else capability.replace("_", " ")
                )
                raise ValueError("{} proof is inconsistent".format(label))


def _empty(
    source: SourceArtifactEntry,
    profile: MipsNestedDispatchProfile,
    status: CoverageStatus,
    code: str,
    message: str,
) -> MipsNestedDispatchResult:
    return MipsNestedDispatchResult(
        source.canonical_path,
        status,
        _PRODUCER,
        profile.name,
        0,
        (),
        (),
        (MipsNestedDispatchDiagnostic(code, message),),
    )


def _signed(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def _is_move(word: int, destination: int, source: int) -> bool:
    if word >> 26 != 0 or (word & 0x3F) not in (0x21, 0x25):
        return False
    rs, rt, rd = (word >> 21) & 0x1F, (word >> 16) & 0x1F, (word >> 11) & 0x1F
    return rd == destination and (
        (rs == source and rt == _ZERO) or (rt == source and rs == _ZERO)
    )


def _is_addiu(word: int, destination: int, source: int, immediate: int) -> bool:
    return (
        word >> 26 == 0x09
        and (word >> 21) & 0x1F == source
        and (word >> 16) & 0x1F == destination
        and _signed(word & 0xFFFF) == immediate
    )


def _constant_registers(words: tuple, end_index: int, window: int = 32) -> dict:
    constants = {_ZERO: 0}
    for word in words[max(0, end_index - window):end_index + 2]:
        op = word >> 26
        rs, rt, rd, function = (
            (word >> 21) & 0x1F,
            (word >> 16) & 0x1F,
            (word >> 11) & 0x1F,
            word & 0x3F,
        )
        if op == 0x0F:
            constants[rt] = ((word & 0xFFFF) << 16) & 0xFFFFFFFF
        elif op in (0x08, 0x09):
            if rs in constants:
                constants[rt] = (constants[rs] + _signed(word & 0xFFFF)) & 0xFFFFFFFF
            else:
                constants.pop(rt, None)
        elif op == 0 and function in (0x21, 0x25):
            if rt == _ZERO and rs in constants:
                constants[rd] = constants[rs]
            elif rs == _ZERO and rt in constants:
                constants[rd] = constants[rt]
            else:
                constants.pop(rd, None)
        elif op in (0x20, 0x21, 0x23, 0x24, 0x25):
            constants.pop(rt, None)
        constants[_ZERO] = 0
    return constants


def _gp_value(words: tuple) -> Optional[int]:
    for index in range(min(32, len(words) - 1)):
        first, second = words[index], words[index + 1]
        if (
            first >> 26 == 0x0F
            and (first >> 16) & 0x1F == _GP
            and second >> 26 == 0x09
            and (second >> 21) & 0x1F == _GP
            and (second >> 16) & 0x1F == _GP
        ):
            return (((first & 0xFFFF) << 16) + _signed(second & 0xFFFF)) & 0xFFFFFFFF
    return None


def _jalr_t9(word: int) -> bool:
    return (
        word >> 26 == 0
        and word & 0x3F == 0x09
        and (word >> 21) & 0x1F == _T9
        and (word >> 11) & 0x1F == _RA
    )


def _call_records(words: tuple, base: int, gp: int, resolve_target) -> tuple:
    records = []
    for index, word in enumerate(words):
        if not _jalr_t9(word):
            continue
        target = None
        for prior in range(index - 1, max(-1, index - 8), -1):
            load = words[prior]
            if _jalr_t9(load):
                break
            if (
                load >> 26 == 0x23
                and (load >> 21) & 0x1F == _GP
                and (load >> 16) & 0x1F == _T9
            ):
                target = resolve_target((gp + _signed(load & 0xFFFF)) & 0xFFFFFFFF)
                break
        if target is not None:
            records.append((index, base + index * 4, target.symbol))
    return tuple(records)


def _literal_argument(
    elf, content: bytes, words: tuple, call_index: int, register: int,
    maximum: int,
) -> Optional[str]:
    address = _constant_registers(words, call_index).get(register)
    value = _read_ascii(elf, content, address, maximum) if address is not None else None
    return value[0] if value is not None else None


def _first_call(
    records: tuple,
    symbol: str,
    after: int = 0,
    before: int = 0xFFFFFFFF,
    predicate=None,
):
    return next((
        item for item in records
        if item[2] == symbol and after <= item[1] < before
        and (predicate is None or predicate(item))
    ), None)


def _selection(elf, start: int, end: int) -> SpanSelection:
    start_offset = _file_offset_for_address(elf, start)
    end_offset = _file_offset_for_address(elf, end - 1)
    if start_offset is None or end_offset is None:
        raise ValueError("proof span is not file backed")
    return SpanSelection(SpanKind.BINARY, start_offset, end_offset + 1)


def _path_id(source_path: str, anchor: MipsNestedDispatchAnchor, registration: int) -> str:
    payload = json.dumps((
        source_path,
        anchor.target_ref,
        anchor.transport_selector_name,
        anchor.transport_selector_value,
        anchor.operation_namespace,
        anchor.operation_token,
        registration,
    ), separators=(",", ":")).encode("utf-8")
    return "mips-nested-dispatch:" + hashlib.sha256(payload).hexdigest()


def discover_mips_cgi_nested_dispatch(
    source: SourceArtifactEntry,
    content: bytes,
    anchors: Tuple[MipsNestedDispatchAnchor, ...],
    profile: MipsNestedDispatchProfile = MipsNestedDispatchProfile(),
    policy: MipsNestedDispatchPolicy = MipsNestedDispatchPolicy(),
) -> MipsNestedDispatchResult:
    """Prove query-mode to normalized operation-table dispatch in MIPS CGI ELF."""

    if len(content) > policy.max_source_bytes:
        return _empty(source, profile, CoverageStatus.SKIPPED_BY_POLICY,
                      "source_budget_exceeded", "source exceeds configured byte budget")
    if len(anchors) > policy.max_anchors:
        return _empty(source, profile, CoverageStatus.SKIPPED_BY_POLICY,
                      "anchor_budget_exceeded", "anchors exceed configured budget")
    if source.kind not in _CONTENT_KINDS:
        return _empty(source, profile, CoverageStatus.FAILED,
                      "unsupported_source_kind", "source cannot publish binary evidence")
    if len(content) != source.size or hashlib.sha256(content).hexdigest() != source.content_sha256:
        return _empty(source, profile, CoverageStatus.FAILED,
                      "source_mismatch", "content does not match source inventory")
    try:
        elf = _parse_elf(content)
        if elf.pointer_size != 4 or elf.machine != _MIPS_MACHINE:
            return _empty(source, profile, CoverageStatus.UNSUPPORTED,
                          "unsupported_architecture", "adapter requires MIPS32 ELF")
        symbols = tuple(
            item for table in _read_dynamic_symbols(elf, content).values()
            for item in table if item.name
        )
        symbol_by_name = {item.name: item for item in symbols}
        dispatcher = symbol_by_name.get(profile.dispatcher_symbol)
        if dispatcher is None or not _contains_address(
            elf.sections, dispatcher.address, _ALLOC | _EXEC
        ):
            return _empty(source, profile, CoverageStatus.PARTIAL,
                          "dispatcher_symbol_missing", "profiled dispatcher is unavailable")
        instruction_count = (dispatcher.size + 3) // 4
        if instruction_count > policy.max_dispatcher_instructions:
            return _empty(source, profile, CoverageStatus.PARTIAL,
                          "instruction_budget", "dispatcher exceeds instruction budget")
        words = tuple(
            _word_at_address(elf, content, dispatcher.address + index * 4)
            for index in range(instruction_count)
        )
        if any(word is None for word in words):
            return _empty(source, profile, CoverageStatus.PARTIAL,
                          "dispatcher_not_file_backed", "dispatcher bytes are incomplete")
        gp = _gp_value(words)
        if gp is None:
            return _empty(source, profile, CoverageStatus.PARTIAL,
                          "gp_setup_missing", "dispatcher GP setup does not match profile")
        resolve_target = _got_target_resolver(elf, content)
        calls = _call_records(words, dispatcher.address, gp, resolve_target)
    except TypeError:
        return _empty(source, profile, CoverageStatus.UNSUPPORTED,
                      "unsupported_binary_format", "adapter supports ELF only")
    except (ValueError, struct.error) as exc:
        return _empty(source, profile, CoverageStatus.FAILED, "malformed_elf", str(exc))

    def literal_call(symbol: str, literal: str, register: int, after: int = 0):
        return _first_call(
            calls, symbol, after=after,
            predicate=lambda item: _literal_argument(
                elf, content, words, item[0], register, profile.max_string_bytes
            ) == literal,
        )

    transport_calls = {}
    for anchor in set(anchors):
        transport = "{}={}".format(
            anchor.transport_selector_name, anchor.transport_selector_value
        )
        transport_calls[transport] = literal_call("strstr", transport, _A1)
    first_transport = next((item for item in transport_calls.values() if item), None)
    if first_transport is None:
        return MipsNestedDispatchResult(
            source.canonical_path, CoverageStatus.PARTIAL, _PRODUCER, profile.name,
            instruction_count, (), (), (MipsNestedDispatchDiagnostic(
                "transport_dispatch_not_proven",
                "no anchored transport selector reaches the profiled upload branch",
            ),),
        )

    transport_index, transport_address, _ = first_transport
    branch_index = transport_index + 2
    branch = words[branch_index] if branch_index < len(words) else 0
    branch_target = (
        dispatcher.address + (branch_index + 1) * 4
        + (_signed(branch & 0xFFFF) << 2)
    ) & 0xFFFFFFFF
    if not (
        branch >> 26 == 0x04
        and (branch >> 21) & 0x1F == _V0
        and (branch >> 16) & 0x1F == _ZERO
        and branch_target > transport_address
    ):
        return MipsNestedDispatchResult(
            source.canonical_path, CoverageStatus.PARTIAL, _PRODUCER, profile.name,
            instruction_count, (), (), (MipsNestedDispatchDiagnostic(
                "transport_branch_not_proven",
                "transport match does not guard the profiled upload branch",
            ),),
        )
    extract = _first_call(
        calls,
        "getNthValueSafe",
        after=transport_address,
        predicate=lambda item: (
            _constant_registers(words, item[0]).get(_A0) == 1
            and _literal_argument(
                elf, content, words, item[0], _A2, profile.max_string_bytes
            ) == "&"
            and any(
                _is_move(words[index], _A1, _S1)
                for index in range(max(0, item[0] - 8), item[0])
            )
            and item[0] + 1 < len(words)
            and _is_move(words[item[0] + 1], _A3, _S4)
            and any(
                _is_addiu(words[index], _S4, _SP, 40)
                for index in range(max(0, item[0] - 8), item[0])
            )
        ),
    )
    if extract is None:
        return MipsNestedDispatchResult(
            source.canonical_path, CoverageStatus.PARTIAL, _PRODUCER, profile.name,
            instruction_count, (), (), (MipsNestedDispatchDiagnostic(
                "selector_extraction_not_proven",
                "the second query segment is not proven to feed the upload selector",
            ),),
        )
    upload_parse = _first_call(
        calls, profile.upload_parser_symbol,
        after=extract[1],
    )
    payload = _first_call(
        calls, "sprintf", after=upload_parse[1] if upload_parse else transport_address,
        predicate=lambda item: (
            _literal_argument(
                elf, content, words, item[0], _A1, profile.max_string_bytes
            ) or ""
        ).startswith('{"topicurl":"%s","FileName":"%s","ContentLength":"%d","flags"'),
    )
    parsed = _first_call(calls, "cJSON_Parse", after=payload[1] if payload else 0)
    topic = literal_call("websGetVar", "topicurl", _A1, parsed[1] if parsed else 0)
    slash = _first_call(
        calls, "strchr", after=topic[1] if topic else 0,
        predicate=lambda item: _constant_registers(words, item[0]).get(_A1) == ord("/"),
    )
    suffix_index = None
    if slash is not None:
        for index in range(slash[0] + 1, min(len(words), slash[0] + 8)):
            word = words[index]
            if (
                word >> 26 == 0 and word & 0x3F == 0x0B
                and (word >> 21) & 0x1F == _V1
                and (word >> 16) & 0x1F == _V0
                and (word >> 11) & 0x1F == _S3
            ):
                suffix_index = index
                break
    landmarks = (extract, upload_parse, payload, parsed, topic, slash, suffix_index)
    if any(item is None for item in landmarks):
        return MipsNestedDispatchResult(
            source.canonical_path, CoverageStatus.PARTIAL, _PRODUCER, profile.name,
            instruction_count, (), (), (MipsNestedDispatchDiagnostic(
                "nested_dispatch_profile_incomplete",
                "upload extraction, payload, parse, or suffix witness is missing",
            ),),
        )

    paths = []
    atoms = []
    diagnostics = []
    for anchor in sorted(set(anchors), key=lambda item: (
        item.target_ref, item.transport_selector_name,
        item.transport_selector_value, item.operation_namespace,
        item.operation_token,
    )):
        if len(paths) >= policy.max_paths:
            diagnostics.append(MipsNestedDispatchDiagnostic(
                "path_budget_exceeded", "path budget truncated nested dispatch analysis"
            ))
            break
        transport = "{}={}".format(
            anchor.transport_selector_name, anchor.transport_selector_value
        )
        match = transport_calls.get(transport)
        prefix = next((
            value for value, _ in profile.table_symbols
            if value != "other" and value in anchor.operation_token
        ), "other")
        table_symbol = dict(profile.table_symbols).get(prefix)
        prefix_match = literal_call(
            "strstr", prefix, _A1,
            dispatcher.address + suffix_index * 4,
        ) if prefix != "other" else None
        table_load = None
        if table_symbol is not None:
            start = prefix_match[0] if prefix_match else suffix_index
            for index in range(start, len(words)):
                word = words[index]
                if (
                    word >> 26 == 0x23
                    and (word >> 21) & 0x1F == _GP
                    and (word >> 16) & 0x1F in (_V0, _S1)
                ):
                    resolved = resolve_target(
                        (gp + _signed(word & 0xFFFF)) & 0xFFFFFFFF
                    )
                    if resolved is not None and resolved.symbol == table_symbol:
                        table_load = index
                        break
        binding_result = discover_mips_inline_route_bindings(
            source,
            content,
            (NativeRouteAnchor(anchor.target_ref, anchor.operation_token),),
        )
        binding = next((
            item for item in binding_result.bindings
            if item.route_token == anchor.operation_token
        ), None)
        table_dispatch_proven = False
        if table_load is not None:
            compare = _first_call(
                calls,
                "strncmp",
                after=dispatcher.address + table_load * 4,
                before=dispatcher.address + table_load * 4 + 0x80,
                predicate=lambda item: (
                    _constant_registers(words, item[0]).get(_A2) == 64
                ),
            )
            if compare is not None:
                for index in range(
                    compare[0] + 1, min(len(words) - 1, compare[0] + 12)
                ):
                    if (
                        _is_move(words[index], _T9, _S2)
                        and _jalr_t9(words[index + 1])
                    ):
                        table_dispatch_proven = True
                        break
        if not table_dispatch_proven:
            diagnostics.append(MipsNestedDispatchDiagnostic(
                "table_dispatch_not_proven",
                "the selected table is not proven to invoke its handler slot",
                anchor.target_ref,
            ))
            continue
        if match is None or prefix_match is None or table_load is None or binding is None:
            diagnostics.append(MipsNestedDispatchDiagnostic(
                "anchored_path_not_proven",
                "transport, prefix table, or exact handler binding is incomplete",
                anchor.target_ref,
            ))
            continue

        path_id = _path_id(source.canonical_path, anchor, binding.registration_address)
        dispatcher_identity = "{}@0x{:08x}".format(
            source.canonical_path, dispatcher.address
        )
        nested_selector = "{}/{}".format(
            anchor.operation_namespace, anchor.operation_token
        )
        source_construct = "elf.{}:{}".format(profile.name, table_symbol)
        proof_specs = (
            (
                "selects_transport_mode", transport,
                match[1] - 12, match[1] + 12,
            ),
            (
                "parses_upload_body", "getNthValueSafe+{}".format(
                    profile.upload_parser_symbol
                ),
                extract[1] - 24, upload_parse[1] + 12,
            ),
            (
                "constructs_dispatch_payload", "topicurl={}".format(nested_selector),
                payload[1] - 40, topic[1] + 12,
            ),
            (
                "normalizes_operation_suffix",
                "{}->{}".format(nested_selector, anchor.operation_token),
                slash[1] - 8, dispatcher.address + suffix_index * 4 + 4,
            ),
            (
                "selects_dispatch_table", table_symbol,
                prefix_match[1] - 12, dispatcher.address + table_load * 4 + 8,
            ),
            (
                "binds_handler", binding.handler_identity,
                binding.registration_address,
                binding.registration_address + 68,
            ),
        )
        path_atoms = []
        for capability, object_value, start, end in proof_specs:
            atom = capture_evidence(
                source,
                content,
                _selection(elf, start, end),
                EvidenceClaim(
                    path_id,
                    capability,
                    object_value,
                    ObservationKind.DETERMINISTIC_DERIVED,
                    capability,
                    1.0,
                ),
                _PRODUCER,
            )
            path_atoms.append(atom)
        evidence_ids = tuple(item.evidence_id for item in path_atoms)
        atoms.extend(path_atoms)
        paths.append(MipsNestedDispatchPath(
            path_id,
            anchor.target_ref,
            transport,
            nested_selector,
            anchor.operation_token,
            dispatcher_identity,
            dispatcher.address,
            match[1],
            extract[1],
            upload_parse[1],
            dispatcher.address + suffix_index * 4,
            table_symbol,
            binding.registration_address,
            binding.handler_address,
            binding.handler_identity,
            source_construct,
            evidence_ids,
        ))

    return MipsNestedDispatchResult(
        source.canonical_path,
        CoverageStatus.PARTIAL if diagnostics else CoverageStatus.COMPLETED,
        _PRODUCER,
        profile.name,
        instruction_count,
        tuple(paths),
        tuple(atoms),
        tuple(diagnostics),
    )
