"""Deterministic MIPS web-server request-protection scope proofs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
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
)
from .native_nested_dispatch import (
    _call_records,
    _constant_registers,
    _gp_value,
    _is_addiu,
    _signed,
)
from .native_value_flow import _got_target_resolver, _read_ascii


MIPS_REQUEST_PROTECTION_RESULT_SCHEMA_VERSION = (
    "firmatlas.mapping.mips-request-protection-result/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("native-mips-request-protection", "0.1.0")
_CONTENT_KINDS = frozenset({"file", "hardlink", "archive", "archive_member"})

_ZERO = 0
_V0 = 2
_V1 = 3
_A1 = 5
_S1 = 17


class RequestProtectionStatus(str, Enum):
    GUARDED_BY_PATH_GATE = "guarded_by_path_gate"
    EXCLUDED_FROM_PATH_GATE = "excluded_from_path_gate"


@dataclass(frozen=True)
class MipsRequestProtectionAnchor:
    target_ref: str
    request_path: str

    def __post_init__(self) -> None:
        if not self.target_ref.strip() or not self.request_path.startswith("/"):
            raise ValueError("request protection anchor requires target and absolute path")
        if any(character.isspace() for character in self.request_path):
            raise ValueError("request protection path must not contain whitespace")


@dataclass(frozen=True)
class MipsRequestProtectionProfile:
    name: str = "mips32-lighttpd-custom-session-path-gate/v1"
    response_hook_symbol: str = "http_response_write_header"
    auth_hook_symbol: str = "userloginAuth"
    authenticator_symbol: str = "checkLoginUser"
    cookie_reader_symbol: str = "ws_get_cookie"
    session_lookup_symbol: str = "form_get_idx_by_sessionid"
    cookie_name: str = "SESSION_ID"
    denial_status: int = 302
    max_guard_scan_instructions: int = 64
    max_string_bytes: int = 256

    def __post_init__(self) -> None:
        values = (
            self.name,
            self.response_hook_symbol,
            self.auth_hook_symbol,
            self.authenticator_symbol,
            self.cookie_reader_symbol,
            self.session_lookup_symbol,
            self.cookie_name,
        )
        if any(not value.strip() for value in values):
            raise ValueError("request protection profile fields must not be blank")
        if (
            self.denial_status < 100
            or self.denial_status > 599
            or self.max_guard_scan_instructions <= 0
            or self.max_string_bytes <= 0
        ):
            raise ValueError("request protection profile limits are invalid")


@dataclass(frozen=True)
class MipsRequestProtectionPolicy:
    max_source_bytes: int = 64 * 1024 * 1024
    max_anchors: int = 10_000
    max_instructions: int = 4_096
    max_assessments: int = 10_000

    def __post_init__(self) -> None:
        if any(value <= 0 for value in (
            self.max_source_bytes,
            self.max_anchors,
            self.max_instructions,
            self.max_assessments,
        )):
            raise ValueError("request protection budgets must be positive")


@dataclass(frozen=True)
class MipsRequestProtectionAssessment:
    assessment_id: str
    target_ref: str
    request_path: str
    protection_status: RequestProtectionStatus
    guard_patterns: Tuple[str, ...]
    response_hook_identity: str
    response_hook_address: int
    auth_hook_identity: str
    auth_hook_address: int
    auth_callsite: int
    enforcement_address: int
    denial_status: int
    authenticator_identity: str
    authenticator_address: int
    authenticator_callsite: int
    cookie_name: str
    cookie_callsite: int
    session_lookup_callsite: int
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class MipsRequestProtectionDiagnostic:
    code: str
    message: str
    target_ref: Optional[str] = None


@dataclass(frozen=True)
class MipsRequestProtectionResult:
    source_path: str
    coverage_status: CoverageStatus
    producer: AnalyzerIdentity
    profile: str
    processed_instructions: int
    assessments: Tuple[MipsRequestProtectionAssessment, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[MipsRequestProtectionDiagnostic, ...] = ()
    schema_version: str = MIPS_REQUEST_PROTECTION_RESULT_SCHEMA_VERSION

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
            "assessments": [
                {
                    **asdict(item),
                    "protection_status": item.protection_status.value,
                    "guard_patterns": list(item.guard_patterns),
                    "evidence_ids": list(item.evidence_ids),
                }
                for item in self.assessments
            ],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
            "diagnostics": [asdict(item) for item in self.diagnostics],
        }


def _validate_result(result: MipsRequestProtectionResult) -> None:
    if result.schema_version != MIPS_REQUEST_PROTECTION_RESULT_SCHEMA_VERSION:
        raise ValueError("unsupported MIPS request protection result schema")
    if not result.source_path.strip() or not result.profile.strip():
        raise ValueError("request protection result requires source and profile")
    if result.processed_instructions < 0:
        raise ValueError("processed instruction count must not be negative")
    atoms = {item.evidence_id: item for item in result.evidence_atoms}
    if len(atoms) != len(result.evidence_atoms):
        raise ValueError("duplicate request protection evidence identity")
    identities = set()
    required = {
        "selects_protection_scope",
        "invokes_authenticator",
        "validates_session_cookie",
        "enforces_auth_redirect",
        "classifies_request_scope",
    }
    for item in result.assessments:
        if item.assessment_id in identities:
            raise ValueError("duplicate request protection assessment identity")
        identities.add(item.assessment_id)
        expected_status = (
            RequestProtectionStatus.GUARDED_BY_PATH_GATE
            if any(pattern in item.request_path for pattern in item.guard_patterns)
            else RequestProtectionStatus.EXCLUDED_FROM_PATH_GATE
        )
        if item.protection_status is not expected_status:
            raise ValueError("request protection status contradicts path gate")
        expected_identities = (
            "{}@0x{:08x}".format(result.source_path, item.response_hook_address),
            "{}@0x{:08x}".format(result.source_path, item.auth_hook_address),
            "{}@0x{:08x}".format(result.source_path, item.authenticator_address),
        )
        if (
            item.response_hook_identity != expected_identities[0]
            or item.auth_hook_identity != expected_identities[1]
            or item.authenticator_identity != expected_identities[2]
        ):
            raise ValueError("request protection function identity is inconsistent")
        if item.denial_status < 100 or item.denial_status > 599:
            raise ValueError("request protection denial status is invalid")
        if len(item.evidence_ids) != len(required):
            raise ValueError("request protection assessment requires a five-part proof")
        by_capability = {}
        for evidence_id in item.evidence_ids:
            atom = atoms.get(evidence_id)
            if atom is None or atom.subject_ref != item.assessment_id:
                raise ValueError("request protection assessment references invalid evidence")
            if atom.source_span.artifact_path != result.source_path:
                raise ValueError("request protection evidence source is inconsistent")
            if (atom.producer, atom.producer_version) != (
                result.producer.name,
                result.producer.version,
            ) or atom.confidence != 1.0:
                raise ValueError("request protection proof must be deterministic")
            by_capability[atom.capability] = atom
        if set(by_capability) != required:
            raise ValueError("request protection proof capabilities are incomplete")
        expected_objects = {
            "selects_protection_scope": "|".join(item.guard_patterns),
            "invokes_authenticator": item.authenticator_identity,
            "validates_session_cookie": "{}->form_get_idx_by_sessionid".format(
                item.cookie_name
            ),
            "enforces_auth_redirect": "HTTP {}".format(item.denial_status),
            "classifies_request_scope": "{}->{}".format(
                item.request_path, item.protection_status.value
            ),
        }
        if any(
            by_capability[capability].object_value != object_value
            for capability, object_value in expected_objects.items()
        ):
            raise ValueError("request protection proof object is inconsistent")


def _empty(
    source: SourceArtifactEntry,
    profile: MipsRequestProtectionProfile,
    status: CoverageStatus,
    code: str,
    message: str,
    processed: int = 0,
) -> MipsRequestProtectionResult:
    return MipsRequestProtectionResult(
        source.canonical_path,
        status,
        _PRODUCER,
        profile.name,
        processed,
        (),
        (),
        (MipsRequestProtectionDiagnostic(code, message),),
    )


def _branch_target(base: int, index: int, word: int) -> int:
    return (base + (index + 1) * 4 + (_signed(word & 0xFFFF) << 2)) & 0xFFFFFFFF


def _direct_call_records(words: tuple, base: int, symbols_by_address: dict) -> tuple:
    records = []
    for index, word in enumerate(words):
        if word >> 26 != 0x03:
            continue
        address = base + index * 4
        target = ((address + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        symbol = symbols_by_address.get(target)
        if symbol is not None:
            records.append((index, address, symbol))
    return tuple(records)


def _function_words(elf, content: bytes, symbol) -> tuple:
    count = (symbol.size + 3) // 4
    return tuple(
        _word_at_address(elf, content, symbol.address + index * 4)
        for index in range(count)
    )


def _all_calls(words: tuple, base: int, gp: int, resolver, symbols: dict) -> tuple:
    records = _call_records(words, base, gp, resolver)
    records += _direct_call_records(words, base, symbols)
    return tuple(sorted(set(records), key=lambda item: (item[0], item[2])))


def _literal_argument(
    elf, content: bytes, words: tuple, call_index: int, register: int, maximum: int
) -> Optional[str]:
    address = _constant_registers(words, call_index).get(register)
    value = _read_ascii(elf, content, address, maximum) if address is not None else None
    return value[0] if value is not None else None


def _selection(elf, start: int, end: int) -> SpanSelection:
    start_offset = _file_offset_for_address(elf, start)
    end_offset = _file_offset_for_address(elf, end - 1)
    if start_offset is None or end_offset is None:
        raise ValueError("request protection proof span is not file backed")
    return SpanSelection(SpanKind.BINARY, start_offset, end_offset + 1)


def _assessment_id(source_path: str, anchor: MipsRequestProtectionAnchor) -> str:
    payload = json.dumps(
        (source_path, anchor.target_ref, anchor.request_path),
        separators=(",", ":"),
    ).encode("utf-8")
    return "mips-request-protection:" + hashlib.sha256(payload).hexdigest()


def discover_mips_request_protection(
    source: SourceArtifactEntry,
    content: bytes,
    anchors: Tuple[MipsRequestProtectionAnchor, ...],
    profile: MipsRequestProtectionProfile = MipsRequestProtectionProfile(),
    policy: MipsRequestProtectionPolicy = MipsRequestProtectionPolicy(),
) -> MipsRequestProtectionResult:
    """Classify request paths against a proved custom session path gate."""

    if len(content) > policy.max_source_bytes:
        return _empty(
            source, profile, CoverageStatus.SKIPPED_BY_POLICY,
            "source_budget_exceeded", "source exceeds configured byte budget",
        )
    if len(anchors) > policy.max_anchors:
        return _empty(
            source, profile, CoverageStatus.SKIPPED_BY_POLICY,
            "anchor_budget_exceeded", "anchors exceed configured budget",
        )
    if source.kind not in _CONTENT_KINDS:
        return _empty(
            source, profile, CoverageStatus.FAILED,
            "unsupported_source_kind", "source cannot publish binary evidence",
        )
    if len(content) != source.size or hashlib.sha256(content).hexdigest() != source.content_sha256:
        return _empty(
            source, profile, CoverageStatus.FAILED,
            "source_mismatch", "content does not match source inventory",
        )

    try:
        elf = _parse_elf(content)
        if elf.pointer_size != 4 or elf.machine != _MIPS_MACHINE:
            return _empty(
                source, profile, CoverageStatus.UNSUPPORTED,
                "unsupported_architecture", "adapter requires MIPS32 ELF",
            )
        dynamic_symbols = tuple(
            symbol
            for table in _read_dynamic_symbols(elf, content).values()
            for symbol in table
            if symbol.name
        )
        by_name = {symbol.name: symbol for symbol in dynamic_symbols}
        by_address = {
            symbol.address: symbol.name
            for symbol in dynamic_symbols
            if symbol.address
        }
        required_names = (
            profile.response_hook_symbol,
            profile.auth_hook_symbol,
            profile.authenticator_symbol,
            profile.cookie_reader_symbol,
            profile.session_lookup_symbol,
        )
        if any(name not in by_name for name in required_names):
            return _empty(
                source, profile, CoverageStatus.PARTIAL,
                "protection_symbols_missing",
                "profiled response, authentication, or session symbols are unavailable",
            )
        selected = tuple(by_name[name] for name in (
            profile.response_hook_symbol,
            profile.auth_hook_symbol,
            profile.authenticator_symbol,
        ))
        if any(
            not symbol.size
            or not _contains_address(elf.sections, symbol.address, _ALLOC | _EXEC)
            for symbol in selected
        ):
            return _empty(
                source, profile, CoverageStatus.PARTIAL,
                "protection_functions_unavailable",
                "profiled protection functions are not bounded executable symbols",
            )
        words_by_name = {
            symbol.name: _function_words(elf, content, symbol)
            for symbol in selected
        }
        if any(
            any(word is None for word in words)
            for words in words_by_name.values()
        ):
            return _empty(
                source, profile, CoverageStatus.PARTIAL,
                "protection_functions_not_file_backed",
                "profiled protection function bytes are incomplete",
            )
        processed = sum(len(words) for words in words_by_name.values())
        if processed > policy.max_instructions:
            return _empty(
                source, profile, CoverageStatus.PARTIAL,
                "instruction_budget", "protection functions exceed instruction budget",
                processed,
            )
        resolver = _got_target_resolver(elf, content)
        calls_by_name = {}
        for symbol in selected:
            words = words_by_name[symbol.name]
            gp = _gp_value(words)
            if gp is None:
                return _empty(
                    source, profile, CoverageStatus.PARTIAL,
                    "gp_setup_missing", "profiled protection function lacks GP setup",
                    processed,
                )
            calls_by_name[symbol.name] = _all_calls(
                words, symbol.address, gp, resolver, by_address
            )
    except TypeError:
        return _empty(
            source, profile, CoverageStatus.UNSUPPORTED,
            "unsupported_binary_format", "adapter supports ELF only",
        )
    except (ValueError, struct.error) as exc:
        return _empty(
            source, profile, CoverageStatus.FAILED, "malformed_elf", str(exc)
        )

    response = by_name[profile.response_hook_symbol]
    response_words = words_by_name[profile.response_hook_symbol]
    response_calls = calls_by_name[profile.response_hook_symbol]
    auth_call = next((
        item for item in response_calls if item[2] == profile.auth_hook_symbol
    ), None)
    if auth_call is None:
        return _empty(
            source, profile, CoverageStatus.PARTIAL,
            "auth_hook_not_proven", "response hook does not invoke profiled auth hook",
            processed,
        )
    auth_index, auth_callsite, _ = auth_call
    if auth_index + 6 >= len(response_words):
        return _empty(
            source, profile, CoverageStatus.PARTIAL,
            "auth_enforcement_not_proven", "auth result enforcement is truncated",
            processed,
        )
    compare = response_words[auth_index + 3]
    skip_address = _branch_target(response.address, auth_index + 3, compare)
    status_store = response_words[auth_index + 6]
    if not (
        _is_addiu(response_words[auth_index + 2], _V1, _ZERO, 1)
        and compare >> 26 == 0x05
        and (compare >> 21) & 0x1F == _V0
        and (compare >> 16) & 0x1F == _V1
        and _is_addiu(
            response_words[auth_index + 5],
            _V0,
            _ZERO,
            profile.denial_status,
        )
        and status_store >> 26 == 0x2B
        and (status_store >> 21) & 0x1F == _S1
        and (status_store >> 16) & 0x1F == _V0
    ):
        return _empty(
            source, profile, CoverageStatus.PARTIAL,
            "auth_enforcement_not_proven",
            "auth result is not proven to set the profiled denial status",
            processed,
        )
    auth_block_start = auth_callsite - 12
    gates = []
    for call in response_calls:
        index, address, symbol = call
        if (
            symbol != "strstr"
            or index < max(0, auth_index - profile.max_guard_scan_instructions)
            or index >= auth_index
            or index + 2 >= len(response_words)
        ):
            continue
        literal = _literal_argument(
            elf, content, response_words, index, _A1, profile.max_string_bytes
        )
        branch = response_words[index + 2]
        target = _branch_target(response.address, index + 2, branch)
        valid = (
            literal is not None
            and (branch >> 21) & 0x1F == _V0
            and (branch >> 16) & 0x1F == _ZERO
            and (
                (branch >> 26 == 0x05 and target == auth_block_start)
                or (branch >> 26 == 0x04 and target == skip_address)
            )
        )
        if valid:
            gates.append((index, address, literal, branch >> 26))
    if (
        not any(item[3] == 0x05 for item in gates)
        or not any(item[3] == 0x04 for item in gates)
    ):
        return _empty(
            source, profile, CoverageStatus.PARTIAL,
            "protection_scope_not_proven",
            "substring gates do not prove a complete auth/skip decision",
            processed,
        )

    auth = by_name[profile.auth_hook_symbol]
    auth_calls = calls_by_name[profile.auth_hook_symbol]
    authenticator_call = next((
        item for item in auth_calls if item[2] == profile.authenticator_symbol
    ), None)
    if authenticator_call is None:
        return _empty(
            source, profile, CoverageStatus.PARTIAL,
            "authenticator_not_proven", "auth hook does not invoke authenticator",
            processed,
        )

    authenticator = by_name[profile.authenticator_symbol]
    authenticator_words = words_by_name[profile.authenticator_symbol]
    authenticator_calls = calls_by_name[profile.authenticator_symbol]
    cookie_call = next((
        item
        for item in authenticator_calls
        if item[2] == profile.cookie_reader_symbol
        and _literal_argument(
            elf,
            content,
            authenticator_words,
            item[0],
            _A1,
            profile.max_string_bytes,
        ) == profile.cookie_name
    ), None)
    session_lookup = next((
        item
        for item in authenticator_calls
        if item[2] == profile.session_lookup_symbol
        and (cookie_call is None or item[0] > cookie_call[0])
    ), None)
    session_proven = False
    if cookie_call is not None and session_lookup is not None:
        cookie_branch = authenticator_words[cookie_call[0] + 2]
        denial_target = _branch_target(
            authenticator.address, cookie_call[0] + 2, cookie_branch
        )
        lookup_compare = authenticator_words[session_lookup[0] + 2]
        lookup_branch = authenticator_words[session_lookup[0] + 3]
        session_proven = (
            cookie_branch >> 26 == 0x05
            and (cookie_branch >> 21) & 0x1F == _V0
            and (cookie_branch >> 16) & 0x1F == _ZERO
            and _is_addiu(lookup_compare, _V1, _ZERO, -1)
            and lookup_branch >> 26 == 0x04
            and (lookup_branch >> 21) & 0x1F == _V0
            and (lookup_branch >> 16) & 0x1F == _V1
            and _branch_target(
                authenticator.address, session_lookup[0] + 3, lookup_branch
            ) == denial_target
        )
    if not session_proven:
        return _empty(
            source, profile, CoverageStatus.PARTIAL,
            "session_validation_not_proven",
            "SESSION_ID extraction and session lookup denial path are incomplete",
            processed,
        )

    patterns = tuple(item[2] for item in gates)
    assessments = []
    atoms = []
    diagnostics = []
    scope_start = gates[0][1] - 12
    scope_end = gates[-1][1] + 16
    for anchor in sorted(set(anchors), key=lambda item: (item.target_ref, item.request_path)):
        if len(assessments) >= policy.max_assessments:
            diagnostics.append(MipsRequestProtectionDiagnostic(
                "assessment_budget_exceeded",
                "assessment budget truncated request protection analysis",
            ))
            break
        status = (
            RequestProtectionStatus.GUARDED_BY_PATH_GATE
            if any(pattern in anchor.request_path for pattern in patterns)
            else RequestProtectionStatus.EXCLUDED_FROM_PATH_GATE
        )
        identity = _assessment_id(source.canonical_path, anchor)
        response_identity = "{}@0x{:08x}".format(
            source.canonical_path, response.address
        )
        auth_identity = "{}@0x{:08x}".format(source.canonical_path, auth.address)
        authenticator_identity = "{}@0x{:08x}".format(
            source.canonical_path, authenticator.address
        )
        specs = (
            (
                "selects_protection_scope",
                "|".join(patterns),
                scope_start,
                scope_end,
            ),
            (
                "invokes_authenticator",
                authenticator_identity,
                authenticator_call[1] - 4,
                authenticator_call[1] + 8,
            ),
            (
                "validates_session_cookie",
                "{}->{}".format(profile.cookie_name, profile.session_lookup_symbol),
                cookie_call[1] - 20,
                session_lookup[1] + 16,
            ),
            (
                "enforces_auth_redirect",
                "HTTP {}".format(profile.denial_status),
                auth_callsite - 12,
                skip_address,
            ),
            (
                "classifies_request_scope",
                "{}->{}".format(anchor.request_path, status.value),
                scope_start,
                scope_end,
            ),
        )
        proof = tuple(
            capture_evidence(
                source,
                content,
                _selection(elf, start, end),
                EvidenceClaim(
                    identity,
                    capability,
                    object_value,
                    ObservationKind.DETERMINISTIC_DERIVED,
                    capability,
                    1.0,
                ),
                _PRODUCER,
            )
            for capability, object_value, start, end in specs
        )
        atoms.extend(proof)
        assessments.append(MipsRequestProtectionAssessment(
            identity,
            anchor.target_ref,
            anchor.request_path,
            status,
            patterns,
            response_identity,
            response.address,
            auth_identity,
            auth.address,
            auth_callsite,
            response.address + (auth_index + 5) * 4,
            profile.denial_status,
            authenticator_identity,
            authenticator.address,
            authenticator_call[1],
            profile.cookie_name,
            cookie_call[1],
            session_lookup[1],
            "elf.{}:custom-session-path-gate".format(profile.name),
            tuple(atom.evidence_id for atom in proof),
        ))

    return MipsRequestProtectionResult(
        source.canonical_path,
        CoverageStatus.PARTIAL if diagnostics else CoverageStatus.COMPLETED,
        _PRODUCER,
        profile.name,
        processed,
        tuple(assessments),
        tuple(atoms),
        tuple(diagnostics),
    )
