"""Conservative static invocation reachability for frontend requests."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
from typing import Optional, Tuple

from .domain import (
    AnalyzerIdentity,
    CoverageStatus,
    EvidenceAtom,
    ObservationKind,
    SpanKind,
)
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .frontend import (
    FrontendProducerResult,
    _matching_close,
    _matching_delimiter,
    _tokenize_javascript,
)
from .inventory import SourceArtifactEntry


FRONTEND_REACHABILITY_SCHEMA_VERSION = (
    "firmatlas.mapping.frontend-invocation-reachability/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("frontend-invocation-reachability", "0.1.0")


class FrontendInvocationStatus(str, Enum):
    TOP_LEVEL_DECLARATION = "top_level_declaration"
    ACTIVE_CALL_PATH = "active_call_path"
    DECLARED_BUT_UNREACHED = "declared_but_unreached"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class FrontendReachabilityPolicy:
    max_source_bytes: int = 8 * 1024 * 1024
    max_functions: int = 10_000
    max_invocations: int = 10_000
    enable_regex_literals: bool = True

    def __post_init__(self) -> None:
        if min(
            self.max_source_bytes, self.max_functions, self.max_invocations
        ) <= 0:
            raise ValueError("frontend reachability limits must be positive")


@dataclass(frozen=True)
class FrontendRequestInvocation:
    invocation_id: str
    request_candidate_id: str
    endpoint: str
    status: FrontendInvocationStatus
    function_name: Optional[str]
    root_kind: Optional[str]
    call_path: Tuple[str, ...]
    commented_reference_count: int
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class FrontendReachabilityDiagnostic:
    code: str
    message: str


@dataclass(frozen=True)
class FrontendReachabilityResult:
    source_path: str
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    invocations: Tuple[FrontendRequestInvocation, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[FrontendReachabilityDiagnostic, ...] = ()
    schema_version: str = FRONTEND_REACHABILITY_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "invocations": [
                {**asdict(item), "status": item.status.value}
                for item in self.invocations
            ],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
        }


@dataclass(frozen=True)
class _Function:
    name: str
    display_name: Optional[str]
    name_start: int
    name_end: int
    body_start: int
    body_end: int
    token_start: int
    token_end: int


@dataclass(frozen=True)
class _CallProof:
    start: int
    end: int
    construct: str
    target_name: str


@dataclass(frozen=True)
class _ReachPath:
    root_kind: str
    function_names: Tuple[str, ...]
    proofs: Tuple[_CallProof, ...]


def _identity(prefix: str, *values: object) -> str:
    encoded = json.dumps(
        values, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "{}:{}".format(prefix, hashlib.sha256(encoded).hexdigest())


def _comment_spans(content: bytes) -> tuple:
    spans = []
    index = 0
    quote = None
    while index < len(content):
        byte = content[index]
        if quote is not None:
            if byte == ord("\\"):
                index += 2
                continue
            if byte == quote:
                quote = None
            index += 1
            continue
        if byte in {ord('"'), ord("'"), ord("`")}:
            quote = byte
            index += 1
            continue
        if content[index:index + 2] == b"//":
            end = content.find(b"\n", index + 2)
            end = len(content) if end < 0 else end
            spans.append((index, end))
            index = end
            continue
        if content[index:index + 2] == b"/*":
            end = content.find(b"*/", index + 2)
            end = len(content) if end < 0 else end + 2
            spans.append((index, end))
            index = end
            continue
        index += 1
    return tuple(spans)


def _functions(tokens: tuple) -> tuple:
    functions = []
    for index in range(max(0, len(tokens) - 2)):
        declared = (
            tokens[index].value == b"function"
            and tokens[index + 1].kind == "identifier"
            and tokens[index + 2].value == b"("
        )
        assigned = (
            tokens[index].value == b"function"
            and index >= 2
            and tokens[index - 1].value == b"="
            and tokens[index - 2].kind == "identifier"
            and tokens[index + 1].value == b"("
        )
        anonymous = (
            tokens[index].value == b"function"
            and not declared
            and not assigned
            and tokens[index + 1].value == b"("
        )
        if not declared and not assigned and not anonymous:
            continue
        name = (
            tokens[index + 1]
            if declared
            else tokens[index - 2]
            if assigned
            else tokens[index]
        )
        display_name = (
            name.value.decode("utf-8") if not anonymous else None
        )
        internal_name = "{}@{}".format(
            display_name or "anonymous", name.start
        )
        body_open = index + (3 if declared else 2 if assigned else 2)
        while body_open < len(tokens) and tokens[body_open].value != b"{":
            body_open += 1
        if body_open >= len(tokens):
            continue
        body_close = _matching_close(tokens, body_open)
        if body_close >= len(tokens):
            continue
        functions.append(_Function(
            internal_name,
            display_name,
            name.start,
            name.end,
            tokens[body_open].end,
            tokens[body_close].start,
            index,
            body_close,
        ))
    return tuple(functions)


def _owner(functions: tuple, byte_offset: int) -> Optional[_Function]:
    matches = tuple(
        item for item in functions
        if item.body_start <= byte_offset < item.body_end
    )
    return min(matches, key=lambda item: item.body_end - item.body_start) \
        if matches else None


def _direct_call_paths(tokens: tuple, functions: tuple) -> dict:
    named = {}
    for item in functions:
        if item.display_name is not None:
            named.setdefault(item.display_name.encode("utf-8"), []).append(item)
    by_name = {
        name: items[0] for name, items in named.items() if len(items) == 1
    }
    by_token_start = {item.token_start: item for item in functions}
    roots = {}
    edges = {}
    for index in range(max(0, len(tokens) - 4)):
        if tuple(item.value for item in tokens[index:index + 4]) != (
            b"R", b".", b"moduleView", b"(",
        ):
            continue
        cursor = index + 4
        while cursor + 2 < len(tokens) and tokens[cursor].value != b")":
            if (
                tokens[cursor].value == b"initEvent"
                and tokens[cursor + 1].value == b":"
                and tokens[cursor + 2].value in by_name
            ):
                target = by_name[tokens[cursor + 2].value]
                roots.setdefault(
                    target.name,
                    _ReachPath(
                        "framework_registered_callback",
                        (target.name,),
                        (_CallProof(
                            tokens[cursor + 2].start,
                            tokens[cursor + 2].end,
                            "R.moduleView.initEvent",
                            target.display_name or target.name,
                        ),),
                    ),
                )
            cursor += 1
    callback_methods = {
        b"addEventListener", b"delegate", b"on", b"one", b"ready",
    }
    for index in range(max(0, len(tokens) - 1)):
        if (
            tokens[index].value not in callback_methods
            or tokens[index + 1].value != b"("
        ):
            continue
        close = _matching_delimiter(tokens, index + 1, b"(", b")")
        if close >= len(tokens):
            continue
        caller = _owner(functions, tokens[index].start)
        depth = 1
        for cursor in range(index + 2, close):
            if tokens[cursor].value == b"(":
                depth += 1
                continue
            if tokens[cursor].value == b")":
                depth -= 1
                continue
            target = by_name.get(tokens[cursor].value)
            if tokens[cursor].value == b"function":
                target = by_token_start.get(cursor)
            if (
                depth != 1
                or target is None
                or (
                    cursor + 1 < close
                    and tokens[cursor + 1].value == b"("
                    and tokens[cursor].value != b"function"
                )
                or (
                    cursor > index + 1
                    and tokens[cursor - 1].value == b"."
                )
            ):
                continue
            if caller is None:
                roots.setdefault(
                    target.name,
                    _ReachPath(
                        "event_registered_callback",
                        (target.name,),
                        (_CallProof(
                            tokens[cursor].start,
                            tokens[cursor].end,
                            "javascript.event-registration",
                            target.display_name or target.name,
                        ),),
                    ),
                )
            else:
                edges.setdefault(caller.name, []).append((
                    target.name,
                    _CallProof(
                        tokens[cursor].start,
                        tokens[cursor].end,
                        "javascript.event-registration",
                        target.display_name or target.name,
                    ),
                ))
    for index in range(max(0, len(tokens) - 1)):
        token = tokens[index]
        target = by_name.get(token.value)
        if target is None or tokens[index + 1].value != b"(":
            continue
        if index > 0 and tokens[index - 1].value in {b"function", b"."}:
            continue
        caller = _owner(functions, token.start)
        proof = _CallProof(
            token.start,
            token.end,
            "javascript.direct-call",
            target.display_name or target.name,
        )
        if caller is None:
            roots.setdefault(target.name, _ReachPath(
                "top_level_direct_call", (target.name,), (proof,)
            ))
        else:
            edges.setdefault(caller.name, []).append((target.name, proof))
    changed = True
    while changed:
        changed = False
        for caller, targets in edges.items():
            path = roots.get(caller)
            if path is None:
                continue
            for target, proof in sorted(
                targets,
                key=lambda item: (
                    item[0], item[1].start, item[1].construct
                ),
            ):
                if target not in roots:
                    roots[target] = _ReachPath(
                        path.root_kind,
                        (*path.function_names, target),
                        (*path.proofs, proof),
                    )
                    changed = True
    return roots


def _commented_references(content: bytes, spans: tuple, name: str) -> tuple:
    matches = []
    for start, end in spans:
        body_start = start + 2
        body_end = end - 2 if content[start:start + 2] == b"/*" else end
        for token in _tokenize_javascript(content[body_start:body_end]):
            if token.kind == "identifier" and token.value == name.encode("utf-8"):
                matches.append((
                    body_start + token.start,
                    body_start + token.end,
                ))
    return tuple(matches)


def discover_frontend_invocation_reachability(
    source: SourceArtifactEntry,
    content: bytes,
    frontend: FrontendProducerResult,
    policy: FrontendReachabilityPolicy = FrontendReachabilityPolicy(),
) -> FrontendReachabilityResult:
    """Classify requests by bounded, static frontend invocation reachability."""

    if source.kind not in {"file", "hardlink", "archive_member"}:
        raise ValueError("frontend reachability source must be readable content")
    if frontend.source_path != source.canonical_path:
        raise ValueError("frontend reachability source does not match requests")
    if (
        source.content_sha256 is None
        or source.size != len(content)
        or hashlib.sha256(content).hexdigest() != source.content_sha256
    ):
        raise ValueError("frontend reachability content does not match inventory")
    if len(content) > policy.max_source_bytes:
        return FrontendReachabilityResult(
            source.canonical_path,
            CoverageStatus.SKIPPED_BY_POLICY,
            0,
            _PRODUCER,
            (),
            (),
            (FrontendReachabilityDiagnostic(
                "frontend_reachability.source_byte_budget_exceeded",
                "source was not parsed because max_source_bytes was exceeded",
            ),),
        )
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return FrontendReachabilityResult(
            source.canonical_path,
            CoverageStatus.FAILED,
            0,
            _PRODUCER,
            (),
            (),
            (FrontendReachabilityDiagnostic(
                "frontend_reachability.invalid_utf8",
                "source could not be parsed as UTF-8 frontend content",
            ),),
        )
    tokens = _tokenize_javascript(content, policy.enable_regex_literals)
    functions = _functions(tokens)
    if len(functions) > policy.max_functions:
        return FrontendReachabilityResult(
            source.canonical_path,
            CoverageStatus.SKIPPED_BY_POLICY,
            len(content),
            _PRODUCER,
            (),
            (),
            (FrontendReachabilityDiagnostic(
                "frontend_reachability.function_budget_exceeded",
                "function count exceeded max_functions",
            ),),
        )
    call_paths = _direct_call_paths(tokens, functions)
    function_name_counts = Counter(
        item.display_name for item in functions
        if item.display_name is not None
    )
    comments = _comment_spans(content)
    evidence_by_id = {
        item.evidence_id: item for item in frontend.evidence_atoms
    }
    invocations = []
    missing_request_spans = 0
    limited = len(frontend.candidates) > policy.max_invocations
    for candidate in frontend.candidates[:policy.max_invocations]:
        request_atoms = tuple(
            evidence_by_id[evidence_id]
            for evidence_id in candidate.evidence_ids
            if evidence_id in evidence_by_id
            and evidence_by_id[evidence_id].capability == "constructs_request"
            and evidence_by_id[evidence_id].source_span.artifact_path
            == source.canonical_path
            and evidence_by_id[evidence_id].source_span.start_byte is not None
        )
        if not request_atoms:
            missing_request_spans += 1
            continue
        request_atom = min(
            request_atoms,
            key=lambda item: item.source_span.start_byte or 0,
        )
        owner = _owner(
            functions, request_atom.source_span.start_byte or 0
        )
        invocation_id = _identity(
            "frontend-invocation",
            source.canonical_path,
            candidate.candidate_id,
        )
        evidence_ids = list(candidate.evidence_ids)
        if owner is None:
            status = FrontendInvocationStatus.TOP_LEVEL_DECLARATION
            root_kind = "top_level_declaration"
            call_path = ()
            commented = ()
            classification_start = request_atom.source_span.start_byte or 0
            classification_end = request_atom.source_span.end_byte or (
                classification_start + 1
            )
        else:
            raw_path = call_paths.get(owner.name)
            status = FrontendInvocationStatus.ACTIVE_CALL_PATH \
                if raw_path is not None \
                else FrontendInvocationStatus.DECLARED_BUT_UNREACHED \
                if (
                    owner.display_name is not None
                    and function_name_counts[owner.display_name] == 1
                ) \
                else FrontendInvocationStatus.UNRESOLVED
            root_kind = raw_path.root_kind if raw_path is not None else None
            display_names = {
                item.name: item.display_name for item in functions
            }
            call_path = tuple(
                display_names[name]
                for name in raw_path.function_names
                if display_names.get(name) is not None
            ) if raw_path is not None else ()
            commented = (
                _commented_references(
                    content, comments, owner.display_name
                )
                if owner.display_name is not None else ()
            )
            classification_start = owner.name_start
            classification_end = owner.name_end
            for start, end in commented:
                atom = capture_evidence(
                    source,
                    content,
                    SpanSelection(SpanKind.TEXT_UTF8, start, end),
                    EvidenceClaim(
                        invocation_id,
                        "has_commented_function_reference",
                        owner.display_name or owner.name,
                        ObservationKind.DIRECT_STATIC,
                        "observes_commented_function_reference",
                        1.0,
                    ),
                    _PRODUCER,
                )
                evidence_by_id[atom.evidence_id] = atom
                evidence_ids.append(atom.evidence_id)
            if raw_path is not None:
                for proof in raw_path.proofs:
                    atom = capture_evidence(
                        source,
                        content,
                        SpanSelection(
                            SpanKind.TEXT_UTF8, proof.start, proof.end
                        ),
                        EvidenceClaim(
                            invocation_id,
                            "has_static_call_edge",
                            "{}:{}".format(
                                proof.construct, proof.target_name
                            ),
                            ObservationKind.DETERMINISTIC_DERIVED,
                            "establishes_frontend_call_edge",
                            1.0,
                        ),
                        _PRODUCER,
                    )
                    evidence_by_id[atom.evidence_id] = atom
                    evidence_ids.append(atom.evidence_id)
        classification = capture_evidence(
            source,
            content,
            SpanSelection(
                SpanKind.TEXT_UTF8, classification_start, classification_end
            ),
            EvidenceClaim(
                invocation_id,
                "has_static_invocation_status",
                status.value,
                ObservationKind.DETERMINISTIC_DERIVED,
                "classifies_frontend_invocation",
                1.0,
            ),
            _PRODUCER,
        )
        evidence_by_id[classification.evidence_id] = classification
        evidence_ids.append(classification.evidence_id)
        invocations.append(FrontendRequestInvocation(
            invocation_id,
            candidate.candidate_id,
            candidate.endpoint,
            status,
            owner.display_name if owner is not None else None,
            root_kind,
            tuple(call_path),
            len(commented),
            "javascript.static-function-invocation/v1",
            tuple(dict.fromkeys(evidence_ids)),
        ))
    selected_ids = {
        evidence_id
        for item in invocations
        for evidence_id in item.evidence_ids
    }
    coverage = (
        CoverageStatus.PARTIAL
        if (
            limited
            or missing_request_spans
            or frontend.coverage_status is not CoverageStatus.COMPLETED
        )
        else CoverageStatus.COMPLETED
    )
    diagnostics = tuple(
        FrontendReachabilityDiagnostic(code, message)
        for code, message in sorted({
            *((
                (
                    "frontend_reachability.invocation_budget_exceeded",
                    "additional request invocations were not published",
                ),
            ) if limited else ()),
            *((
                (
                    "frontend_reachability.request_span_unavailable",
                    "one or more requests lacked a same-source evidence span",
                ),
            ) if missing_request_spans else ()),
            *(
                ((
                    "frontend_reachability.upstream_coverage_incomplete",
                    "frontend request coverage was incomplete",
                ),)
                if frontend.coverage_status is not CoverageStatus.COMPLETED else ()
            ),
        })
    )
    return FrontendReachabilityResult(
        source.canonical_path,
        coverage,
        len(content),
        _PRODUCER,
        tuple(sorted(invocations, key=lambda item: item.invocation_id)),
        tuple(sorted(
            (
                atom for evidence_id, atom in evidence_by_id.items()
                if evidence_id in selected_ids
            ),
            key=lambda item: item.evidence_id,
        )),
        diagnostics,
    )
