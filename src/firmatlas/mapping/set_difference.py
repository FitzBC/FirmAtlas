"""Evidence-backed attribution of frontend/native operation set differences."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
from typing import Tuple, Union

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .frontend import FrontendAssetGraphResult
from .inventory import SourceArtifactEntry
from .native_deep import NativeDeepResult


SET_DIFFERENCE_ATTRIBUTION_SCHEMA_VERSION = (
    "firmatlas.mapping.set-difference-attribution/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("frontend-native-set-difference", "0.1.0")
_ROUTE_AWARE_PRODUCER = AnalyzerIdentity("frontend-native-set-difference", "0.2.0")
_CONTENT_KINDS = frozenset({"file", "hardlink", "archive", "archive_member"})


class AttributionArtifactRole(str, Enum):
    WEB_AUXILIARY = "web_auxiliary"
    NATIVE_AUXILIARY = "native_auxiliary"


class DifferenceSide(str, Enum):
    FRONTEND_ONLY = "frontend_only"
    NATIVE_ONLY = "native_only"


class DifferenceAttributionKind(str, Enum):
    FRONTEND_DECLARATION_NATIVE_ABSENT = "frontend_declaration_native_absent"
    FRONTEND_OPERATION_NATIVE_ABSENT = "frontend_operation_native_absent"
    FRONTEND_CONSUMER_NATIVE_ABSENT = "frontend_consumer_native_absent"
    ALTERNATE_NATIVE_LITERAL = "alternate_native_literal"
    FRONTEND_SCOPE_GAP = "frontend_scope_gap"
    CROSS_NATIVE_LITERAL = "cross_native_literal"
    CROSS_NATIVE_TOKEN_VARIANT = "cross_native_token_variant"
    NATIVE_REGISTRATION_NO_FRONTEND_REFERENCE = (
        "native_registration_no_frontend_reference"
    )


@dataclass(frozen=True)
class AttributionArtifact:
    source: SourceArtifactEntry
    content: bytes
    role: AttributionArtifactRole

    def __post_init__(self) -> None:
        if not isinstance(self.role, AttributionArtifactRole):
            raise ValueError("attribution artifact role is invalid")


@dataclass(frozen=True)
class SetDifferencePolicy:
    max_artifacts: int = 10_000
    max_total_bytes: int = 256 * 1024 * 1024
    max_tokens: int = 20_000
    max_hits_per_token: int = 32
    include_request_action_tokens: bool = False
    request_action_prefixes: Tuple[str, ...] = ()
    scan_native_only_auxiliary: bool = True

    @classmethod
    def route_aware(
        cls, frontend_auxiliary_only: bool = False,
    ) -> "SetDifferencePolicy":
        return cls(
            include_request_action_tokens=True,
            request_action_prefixes=("/goform/", "goform/"),
            scan_native_only_auxiliary=not frontend_auxiliary_only,
        )

    def __post_init__(self) -> None:
        if (
            self.max_artifacts <= 0 or self.max_total_bytes <= 0
            or self.max_tokens <= 0 or self.max_hits_per_token <= 0
        ):
            raise ValueError("set-difference budgets must be positive")
        if self.include_request_action_tokens and not self.request_action_prefixes:
            raise ValueError("route-aware set difference requires path prefixes")
        if any(not value.strip() for value in self.request_action_prefixes):
            raise ValueError("request action prefixes must not be blank")


@dataclass(frozen=True)
class SetDifferenceAttribution:
    attribution_id: str
    token: str
    side: DifferenceSide
    kind: DifferenceAttributionKind
    upstream_evidence_ids: Tuple[str, ...]
    evidence_ids: Tuple[str, ...]
    matched_artifact_paths: Tuple[str, ...]
    interpretation: str
    open_obligation: str


@dataclass(frozen=True)
class SetDifferenceDiagnostic:
    code: str
    message: str
    source_path: str = ""


@dataclass(frozen=True)
class SetDifferenceAttributionResult:
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    frontend_token_count: int
    native_token_count: int
    attributions: Tuple[SetDifferenceAttribution, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    upstream_evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[SetDifferenceDiagnostic, ...] = ()
    schema_version: str = SET_DIFFERENCE_ATTRIBUTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_result(self)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "coverage_status": self.coverage_status.value,
            "processed_bytes": self.processed_bytes,
            "producer": asdict(self.producer),
            "frontend_token_count": self.frontend_token_count,
            "native_token_count": self.native_token_count,
            "attributions": [
                {
                    **asdict(item),
                    "side": item.side.value,
                    "kind": item.kind.value,
                }
                for item in self.attributions
            ],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
            "upstream_evidence_atoms": [
                item.to_dict() for item in self.upstream_evidence_atoms
            ],
            "diagnostics": [asdict(item) for item in self.diagnostics],
        }


@dataclass(frozen=True)
class _Hit:
    artifact: AttributionArtifact
    offset: int
    value: str
    capability: str


def _validate_result(result: SetDifferenceAttributionResult) -> None:
    if result.schema_version != SET_DIFFERENCE_ATTRIBUTION_SCHEMA_VERSION:
        raise ValueError("unsupported set-difference attribution schema")
    if result.processed_bytes < 0 or result.frontend_token_count < 0 \
            or result.native_token_count < 0:
        raise ValueError("set-difference counts must be nonnegative")
    atoms = {atom.evidence_id: atom for atom in result.evidence_atoms}
    if len(atoms) != len(result.evidence_atoms):
        raise ValueError("duplicate set-difference evidence identity")
    upstream_atoms = {
        atom.evidence_id: atom for atom in result.upstream_evidence_atoms
    }
    if len(upstream_atoms) != len(result.upstream_evidence_atoms):
        raise ValueError("duplicate upstream evidence identity")
    identities = set()
    for item in result.attributions:
        if item.attribution_id in identities:
            raise ValueError("duplicate set-difference attribution identity")
        identities.add(item.attribution_id)
        if not item.token or not item.upstream_evidence_ids:
            raise ValueError("attribution requires token and upstream evidence")
        if len(item.upstream_evidence_ids) != len(set(item.upstream_evidence_ids)):
            raise ValueError("duplicate upstream evidence reference")
        if any(identity not in upstream_atoms for identity in item.upstream_evidence_ids):
            raise ValueError("attribution references unknown upstream evidence")
        if len(item.evidence_ids) != len(set(item.evidence_ids)):
            raise ValueError("duplicate attribution evidence reference")
        if tuple(sorted(item.matched_artifact_paths)) != item.matched_artifact_paths:
            raise ValueError("matched artifact paths must be stable")
        for evidence_id in item.evidence_ids:
            atom = atoms.get(evidence_id)
            if atom is None or atom.subject_ref != item.attribution_id:
                raise ValueError("attribution references invalid evidence")
            if (atom.producer, atom.producer_version) != (
                result.producer.name, result.producer.version
            ) or atom.confidence != 1.0:
                raise ValueError("set-difference evidence must be deterministic")
            if atom.capability == "mentions_operation_token":
                valid = atom.object_value == item.token
            elif atom.capability == "mentions_operation_variant":
                valid = atom.object_value.endswith(item.token) \
                    and atom.object_value != item.token
            else:
                valid = False
            if not valid:
                raise ValueError("set-difference evidence capability is invalid")


def _source_matches(artifact: AttributionArtifact) -> bool:
    source = artifact.source
    return (
        source.kind in _CONTENT_KINDS
        and len(artifact.content) == source.size
        and hashlib.sha256(artifact.content).hexdigest() == source.content_sha256
    )


def _exact_offsets(content: bytes, token: str, maximum: int) -> tuple:
    needle = token.encode("ascii")
    offsets = []
    start = 0
    identifier = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    while len(offsets) < maximum:
        offset = content.find(needle, start)
        if offset < 0:
            break
        end = offset + len(needle)
        left_ok = offset == 0 or content[offset - 1] not in identifier
        right_ok = end == len(content) or content[end] not in identifier
        if left_ok and right_ok:
            offsets.append(offset)
        start = offset + 1
    return tuple(offsets)


def _suffix_variant_offsets(content: bytes, token: str, maximum: int) -> tuple:
    """Return bounded identifier suffix variants such as userloginAuth/loginAuth."""

    needle = token.encode("ascii")
    identifier = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    values = []
    cursor = 0
    while len(values) < maximum:
        offset = content.find(needle, cursor)
        if offset < 0:
            break
        end = offset + len(needle)
        cursor = offset + 1
        if end < len(content) and content[end] in identifier:
            continue
        start = offset
        while start > 0 and content[start - 1] in identifier:
            start -= 1
        prefix_size = offset - start
        if not 2 <= prefix_size <= 24:
            continue
        raw = content[start:end]
        try:
            value = raw.decode("ascii")
        except UnicodeDecodeError:
            continue
        values.append((start, value))
    return tuple(values)


def _identity(token: str, side: DifferenceSide, kind: DifferenceAttributionKind,
              paths: tuple) -> str:
    encoded = json.dumps(
        (token, side.value, kind.value, paths), separators=(",", ":")
    ).encode("utf-8")
    return "set-difference:" + hashlib.sha256(encoded).hexdigest()


def _classification(
    side: DifferenceSide,
    web_hits: tuple,
    native_hits: tuple,
    native_variant_hits: tuple,
    frontend_constructs: tuple = (),
):
    if side is DifferenceSide.FRONTEND_ONLY:
        if native_hits:
            return (
                DifferenceAttributionKind.ALTERNATE_NATIVE_LITERAL,
                "Token is absent from the profiled dispatcher tables but occurs in another native artifact.",
                "Determine whether the alternate native principal owns, forwards, or merely mentions the operation.",
            )
        if web_hits:
            return (
                DifferenceAttributionKind.FRONTEND_CONSUMER_NATIVE_ABSENT,
                "A web consumer uses the frontend operation, but the profiled native dispatcher has no registration.",
                "Test firmware-version skew, conditional builds, or an alternate backend before assigning ownership.",
            )
        if any(
            construct != "shared-cgi.topicurl"
            for construct in frontend_constructs
        ):
            return (
                DifferenceAttributionKind.FRONTEND_OPERATION_NATIVE_ABSENT,
                "A direct frontend request selects the operation, but the profiled native dispatcher has no registration.",
                "Resolve the request through alternate dispatch tables, upload modes, scripts, or another runtime principal.",
            )
        return (
            DifferenceAttributionKind.FRONTEND_DECLARATION_NATIVE_ABSENT,
            "The operation is declared by the analyzed frontend wrapper with no auxiliary consumer or native registration.",
            "Determine whether this is an unused shared wrapper capability or an omitted frontend consumer.",
        )
    if web_hits:
        return (
            DifferenceAttributionKind.FRONTEND_SCOPE_GAP,
            "The native registration has an auxiliary web reference outside the analyzed frontend asset scope.",
            "Ingest the referenced web artifact and rebuild the frontend operation inventory.",
        )
    if native_hits:
        return (
            DifferenceAttributionKind.CROSS_NATIVE_LITERAL,
            "The operation is registered by the dispatcher and also occurs in another native artifact.",
            "Resolve whether the second principal authenticates, forwards, invokes, or merely mentions the operation.",
        )
    if native_variant_hits:
        return (
            DifferenceAttributionKind.CROSS_NATIVE_TOKEN_VARIANT,
            "The dispatcher operation is a suffix of a longer identifier in another native artifact.",
            "Validate whether the longer identifier is an authentication/forwarding relation or an unrelated lexical variant.",
        )
    return (
        DifferenceAttributionKind.NATIVE_REGISTRATION_NO_FRONTEND_REFERENCE,
        "The dispatcher registration has no observed reference in auxiliary web or native artifacts.",
        "Test hidden clients, direct requests, dead registrations, and runtime reachability.",
    )


def attribute_frontend_native_set_difference(
    frontend: FrontendAssetGraphResult,
    native_inventory: Union[NativeDeepResult, Tuple[NativeDeepResult, ...]],
    artifacts: Tuple[AttributionArtifact, ...],
    policy: SetDifferencePolicy = SetDifferencePolicy(),
) -> SetDifferenceAttributionResult:
    """Explain both set differences without promoting a hypothesis to a binding."""

    producer = (
        _ROUTE_AWARE_PRODUCER
        if policy.include_request_action_tokens else _PRODUCER
    )
    diagnostics = []
    if len(artifacts) > policy.max_artifacts:
        return SetDifferenceAttributionResult(
            CoverageStatus.SKIPPED_BY_POLICY, 0, producer, 0, 0, (), (),
            (),
            (SetDifferenceDiagnostic(
                "artifact_budget_exceeded", "auxiliary artifacts exceed configured budget"
            ),),
        )
    if len({item.source.canonical_path for item in artifacts}) != len(artifacts):
        raise ValueError("duplicate auxiliary artifact path")
    total_bytes = sum(len(item.content) for item in artifacts)
    if total_bytes > policy.max_total_bytes:
        return SetDifferenceAttributionResult(
            CoverageStatus.SKIPPED_BY_POLICY, 0, producer, 0, 0, (), (),
            (),
            (SetDifferenceDiagnostic(
                "byte_budget_exceeded", "auxiliary bytes exceed configured budget"
            ),),
        )

    valid_artifacts = []
    partial = False
    for artifact in sorted(artifacts, key=lambda item: item.source.canonical_path):
        if not _source_matches(artifact):
            diagnostics.append(SetDifferenceDiagnostic(
                "source_mismatch", "auxiliary content does not match inventory",
                artifact.source.canonical_path,
            ))
            partial = True
            continue
        if artifact.role is AttributionArtifactRole.WEB_AUXILIARY:
            try:
                artifact.content.decode("utf-8")
            except UnicodeDecodeError:
                diagnostics.append(SetDifferenceDiagnostic(
                    "invalid_web_utf8", "web auxiliary artifact is not UTF-8",
                    artifact.source.canonical_path,
                ))
                partial = True
                continue
        valid_artifacts.append(artifact)

    frontend_members = {}
    frontend_constructs = {}
    frontend_evidence = {
        atom.evidence_id: atom
        for result in frontend.results
        for atom in result.evidence_atoms
    }
    for result in frontend.results:
        for parameter in result.parameters:
            if not parameter.is_operation_selector or parameter.literal_value is None:
                continue
            # Low-entropy scalar values (for example ``action=1``) are valid
            # parameter facts but not useful identities for cross-binary route
            # set comparison; scanning them would turn ubiquitous constants
            # into misleading associations and exhaust the evidence budget.
            if not any(character.isalpha() for character in parameter.literal_value):
                continue
            if any(evidence_id not in frontend_evidence for evidence_id in parameter.evidence_ids):
                raise ValueError("frontend selector references unknown evidence")
            frontend_members.setdefault(parameter.literal_value, set()).update(
                parameter.evidence_ids
            )
            frontend_constructs.setdefault(parameter.literal_value, set()).add(
                parameter.source_construct
            )
        if policy.include_request_action_tokens:
            for candidate in result.candidates:
                if candidate.endpoint_shape.value != "exact_literal":
                    continue
                path = candidate.endpoint.split("?", 1)[0].rstrip("/")
                if not any(
                    path.startswith(prefix)
                    for prefix in policy.request_action_prefixes
                ):
                    continue
                token = path.rsplit("/", 1)[-1]
                if not token or token == path and "/" not in path:
                    continue
                if any(
                    evidence_id not in frontend_evidence
                    for evidence_id in candidate.evidence_ids
                ):
                    raise ValueError("frontend request references unknown evidence")
                frontend_members.setdefault(token, set()).update(
                    candidate.evidence_ids
                )
                frontend_constructs.setdefault(token, set()).add(
                    candidate.source_construct
                )
    native_inventories = (
        native_inventory if isinstance(native_inventory, tuple)
        else (native_inventory,)
    )
    registration_paths = {
        inventory.source_path for inventory in native_inventories
    }
    native_evidence = {}
    for inventory in native_inventories:
        for atom in inventory.evidence_atoms:
            existing = native_evidence.get(atom.evidence_id)
            if existing is not None and existing != atom:
                raise ValueError("conflicting native inventory evidence identity")
            native_evidence[atom.evidence_id] = atom
    native_members = {}
    for inventory in native_inventories:
        for binding in inventory.bindings:
            if any(
                evidence_id not in native_evidence
                for evidence_id in binding.evidence_ids
            ):
                raise ValueError("native registration references unknown evidence")
            native_members.setdefault(binding.route_token, set()).update(
                binding.evidence_ids
            )
    all_tokens = set(frontend_members) | set(native_members)
    if len(all_tokens) > policy.max_tokens:
        return SetDifferenceAttributionResult(
            CoverageStatus.SKIPPED_BY_POLICY, 0, producer,
            len(frontend_members), len(native_members), (), (),
            (),
            (SetDifferenceDiagnostic(
                "token_budget_exceeded", "operation tokens exceed configured budget"
            ),),
        )

    records = []
    atoms = []
    differences = (
        (DifferenceSide.FRONTEND_ONLY, sorted(set(frontend_members) - set(native_members))),
        (DifferenceSide.NATIVE_ONLY, sorted(set(native_members) - set(frontend_members))),
    )
    for side, tokens in differences:
        for token in tokens:
            hits = []
            hit_budget_exhausted = False
            for artifact in valid_artifacts:
                if (
                    side is DifferenceSide.NATIVE_ONLY
                    and not policy.scan_native_only_auxiliary
                ):
                    continue
                remaining = policy.max_hits_per_token - len(hits)
                if remaining <= 0:
                    hit_budget_exhausted = True
                    break
                offsets = _exact_offsets(artifact.content, token, remaining + 1)
                if len(offsets) > remaining:
                    offsets = offsets[:remaining]
                    hit_budget_exhausted = True
                hits.extend(_Hit(
                    artifact, offset, token, "mentions_operation_token"
                ) for offset in offsets)
                if (
                    side is DifferenceSide.NATIVE_ONLY
                    and artifact.role is AttributionArtifactRole.NATIVE_AUXILIARY
                    and not offsets
                ):
                    variant_remaining = policy.max_hits_per_token - len(hits)
                    variants = _suffix_variant_offsets(
                        artifact.content, token, variant_remaining + 1
                    )
                    if len(variants) > variant_remaining:
                        variants = variants[:variant_remaining]
                        hit_budget_exhausted = True
                    hits.extend(_Hit(
                        artifact, offset, value, "mentions_operation_variant"
                    ) for offset, value in variants)
            if hit_budget_exhausted:
                partial = True
                diagnostics.append(SetDifferenceDiagnostic(
                    "hit_budget_exceeded",
                    "exact token occurrences exceed configured per-token budget",
                    token,
                ))
            web_hits = tuple(
                hit for hit in hits
                if hit.artifact.role is AttributionArtifactRole.WEB_AUXILIARY
            )
            native_hits = tuple(
                hit for hit in hits
                if hit.artifact.role is AttributionArtifactRole.NATIVE_AUXILIARY
                and hit.capability == "mentions_operation_token"
                and (
                    side is DifferenceSide.FRONTEND_ONLY
                    or hit.artifact.source.canonical_path not in registration_paths
                )
            )
            native_variant_hits = tuple(
                hit for hit in hits
                if hit.artifact.role is AttributionArtifactRole.NATIVE_AUXILIARY
                and hit.capability == "mentions_operation_variant"
                and (
                    side is DifferenceSide.FRONTEND_ONLY
                    or hit.artifact.source.canonical_path not in registration_paths
                )
            )
            kind, interpretation, obligation = _classification(
                side, web_hits, native_hits, native_variant_hits,
                tuple(sorted(frontend_constructs.get(token, ()))),
            )
            paths = tuple(sorted({
                hit.artifact.source.canonical_path for hit in hits
            }))
            attribution_id = _identity(token, side, kind, paths)
            proof = []
            for hit in hits:
                span_kind = (
                    SpanKind.TEXT_UTF8
                    if hit.artifact.role is AttributionArtifactRole.WEB_AUXILIARY
                    else SpanKind.BINARY
                )
                proof.append(capture_evidence(
                    hit.artifact.source,
                    hit.artifact.content,
                    SpanSelection(
                        span_kind, hit.offset,
                        hit.offset + len(hit.value.encode("ascii"))
                    ),
                    EvidenceClaim(
                        attribution_id, hit.capability, hit.value,
                        ObservationKind.DIRECT_STATIC,
                        hit.capability, 1.0,
                    ),
                    producer,
                ))
            atoms.extend(proof)
            upstream = (
                frontend_members[token]
                if side is DifferenceSide.FRONTEND_ONLY
                else native_members[token]
            )
            records.append(SetDifferenceAttribution(
                attribution_id, token, side, kind, tuple(sorted(upstream)),
                tuple(atom.evidence_id for atom in proof), paths,
                interpretation, obligation,
            ))

    inherited_partial = (
        frontend.coverage_status is not CoverageStatus.COMPLETED
        or any(
            inventory.coverage_status is not CoverageStatus.COMPLETED
            for inventory in native_inventories
        )
    )
    if inherited_partial:
        partial = True
        diagnostics.append(SetDifferenceDiagnostic(
            "upstream_coverage_incomplete",
            "frontend or native inventory coverage is incomplete",
        ))
    upstream_ids = {
        evidence_id
        for item in records
        for evidence_id in item.upstream_evidence_ids
    }
    upstream_atoms = {**frontend_evidence, **native_evidence}
    return SetDifferenceAttributionResult(
        CoverageStatus.PARTIAL if partial else CoverageStatus.COMPLETED,
        sum(len(item.content) for item in valid_artifacts),
        producer, len(frontend_members), len(native_members),
        tuple(records), tuple(atoms),
        tuple(upstream_atoms[key] for key in sorted(upstream_ids)),
        tuple(diagnostics),
    )
