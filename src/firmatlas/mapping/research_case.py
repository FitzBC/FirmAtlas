"""Evidence-backed case records for research and paper-writing reuse."""

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import posixpath
import re
from typing import Tuple


RESEARCH_CASE_SCHEMA_VERSION = "firmatlas.mapping.research-case/v1alpha1"
RESEARCH_CASE_CORPUS_VALIDATION_SCHEMA_VERSION = (
    "firmatlas.mapping.research-case-corpus-validation/v1alpha1"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _validate_unique_strings(values: Tuple[str, ...], label: str) -> None:
    if any(not isinstance(item, str) or not item.strip() for item in values):
        raise ValueError("{} must contain nonempty strings".format(label))
    if len(values) != len(set(values)):
        raise ValueError("{} must be unique".format(label))


class CaseEvidenceKind(str, Enum):
    FRONTEND_REQUEST = "frontend_request"
    RESPONSE_FIXTURE = "response_fixture"
    WEB_CONFIGURATION = "web_configuration"
    SCRIPT_BACKEND = "script_backend"
    NATIVE_HINT = "native_hint"
    NATIVE_BINDING = "native_binding"
    NATIVE_VALUE_FLOW = "native_value_flow"
    NATIVE_PROTECTION = "native_protection"
    NATIVE_SERVICE_ASSEMBLY = "native_service_assembly"
    NATIVE_RELATIONSHIP = "native_relationship"
    SET_DIFFERENCE = "set_difference"
    COVERAGE_LEDGER = "coverage_ledger"
    RUNTIME_OBSERVATION = "runtime_observation"
    VULNERABILITY_RECORD = "vulnerability_record"
    PATCH_DIFFERENCE = "patch_difference"


class CaseObligationStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    REJECTED = "rejected"


class CaseClaimStatus(str, Enum):
    SUPPORTED = "supported"
    UNRESOLVED = "unresolved"
    REJECTED = "rejected"


@dataclass(frozen=True)
class CaseEvidenceReference:
    evidence_ref: str
    kind: CaseEvidenceKind
    source_path: str
    source_artifact_sha256: str
    locator: str
    capability: str
    producer: str

    def __post_init__(self) -> None:
        if not self.evidence_ref.strip():
            raise ValueError("evidence_ref must not be empty")
        if not isinstance(self.kind, CaseEvidenceKind):
            raise ValueError("kind must be a CaseEvidenceKind")
        normalized = posixpath.normpath(self.source_path.replace("\\", "/"))
        if (
            not self.source_path
            or self.source_path.startswith(("/", "\\"))
            or normalized in {".", ".."}
            or normalized.startswith("../")
            or normalized != self.source_path
        ):
            raise ValueError(
                "source_path must be canonical evidence-relative POSIX path"
            )
        if not _SHA256.fullmatch(self.source_artifact_sha256):
            raise ValueError("source_artifact_sha256 must be a lowercase SHA-256")
        for name in ("locator", "capability", "producer"):
            if not getattr(self, name).strip():
                raise ValueError("{} must not be empty".format(name))


@dataclass(frozen=True)
class CaseClaim:
    claim_id: str
    statement: str
    evidence_refs: Tuple[str, ...]
    status: CaseClaimStatus = CaseClaimStatus.SUPPORTED

    def __post_init__(self) -> None:
        if not self.claim_id.strip() or not self.statement.strip():
            raise ValueError("claim id and statement must not be empty")
        if not self.evidence_refs:
            raise ValueError("claim must cite evidence")
        _validate_unique_strings(self.evidence_refs, "claim evidence references")
        if not isinstance(self.status, CaseClaimStatus):
            raise ValueError("status must be a CaseClaimStatus")


@dataclass(frozen=True)
class CaseStage:
    stage_id: str
    order: int
    interpretation: str
    claim_ids: Tuple[str, ...]
    creates_obligations: Tuple[str, ...] = ()
    resolves_obligations: Tuple[str, ...] = ()
    rejects_obligations: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.stage_id.strip() or not self.interpretation.strip():
            raise ValueError("stage id and interpretation must not be empty")
        if self.order < 1:
            raise ValueError("stage order must be positive")
        if not self.claim_ids:
            raise ValueError("stage must cite at least one claim")
        for name in (
            "claim_ids",
            "creates_obligations",
            "resolves_obligations",
            "rejects_obligations",
        ):
            _validate_unique_strings(
                getattr(self, name), "stage {}".format(name)
            )
        creates = set(self.creates_obligations)
        resolves = set(self.resolves_obligations)
        rejects = set(self.rejects_obligations)
        if creates & (resolves | rejects) or resolves & rejects:
            raise ValueError("stage obligation transitions must be disjoint")


@dataclass(frozen=True)
class CaseObligation:
    obligation_id: str
    statement: str
    required_capability: str
    status: CaseObligationStatus
    closure_evidence_refs: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not all((
            self.obligation_id.strip(),
            self.statement.strip(),
            self.required_capability.strip(),
        )):
            raise ValueError("obligation fields must not be empty")
        if not isinstance(self.status, CaseObligationStatus):
            raise ValueError("status must be a CaseObligationStatus")
        _validate_unique_strings(
            self.closure_evidence_refs,
            "obligation closure evidence references",
        )
        if self.status in {
            CaseObligationStatus.RESOLVED,
            CaseObligationStatus.REJECTED,
        } and not self.closure_evidence_refs:
            raise ValueError("closed obligation must cite closure evidence")
        if self.status is CaseObligationStatus.OPEN and self.closure_evidence_refs:
            raise ValueError("open obligation cannot cite closure evidence")


@dataclass(frozen=True)
class ResearchCaseInput:
    case_key: str
    title: str
    firmware_artifact_sha256: str
    architecture_tags: Tuple[str, ...]
    research_question: str
    evidence: Tuple[CaseEvidenceReference, ...]
    claims: Tuple[CaseClaim, ...]
    stages: Tuple[CaseStage, ...]
    obligations: Tuple[CaseObligation, ...]
    counterfactuals: Tuple[str, ...]
    paper_uses: Tuple[str, ...]
    limitations: Tuple[str, ...]

    def __post_init__(self) -> None:
        if not (
            self.case_key.strip()
            and self.title.strip()
            and self.research_question.strip()
        ):
            raise ValueError("case identity and research question must not be empty")
        if not _SHA256.fullmatch(self.firmware_artifact_sha256):
            raise ValueError("firmware_artifact_sha256 must be a lowercase SHA-256")
        for name in ("architecture_tags", "evidence", "claims", "stages"):
            if not getattr(self, name):
                raise ValueError("{} must not be empty".format(name))
        for name in ("architecture_tags", "counterfactuals", "paper_uses", "limitations"):
            values = getattr(self, name)
            if any(not item.strip() for item in values):
                raise ValueError("{} values must not be empty".format(name))
            if len(values) != len(set(values)):
                raise ValueError("{} values must be unique".format(name))


@dataclass(frozen=True)
class ResearchCase:
    case_id: str
    schema_version: str
    case_key: str
    title: str
    firmware_artifact_sha256: str
    architecture_tags: Tuple[str, ...]
    research_question: str
    evidence: Tuple[CaseEvidenceReference, ...]
    claims: Tuple[CaseClaim, ...]
    stages: Tuple[CaseStage, ...]
    obligations: Tuple[CaseObligation, ...]
    counterfactuals: Tuple[str, ...]
    paper_uses: Tuple[str, ...]
    limitations: Tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "schema_version": self.schema_version,
            "case_key": self.case_key,
            "title": self.title,
            "firmware_artifact_sha256": self.firmware_artifact_sha256,
            "architecture_tags": list(self.architecture_tags),
            "research_question": self.research_question,
            "evidence": [{**asdict(item), "kind": item.kind.value} for item in self.evidence],
            "claims": [
                {**asdict(item), "status": item.status.value} for item in self.claims
            ],
            "stages": [asdict(item) for item in self.stages],
            "obligations": [
                {**asdict(item), "status": item.status.value} for item in self.obligations
            ],
            "counterfactuals": list(self.counterfactuals),
            "paper_uses": list(self.paper_uses),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class ResearchCaseCorpusValidation:
    schema_version: str
    paper_ready: bool
    case_count: int
    evidence_line_count: int
    issues: Tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "paper_ready": self.paper_ready,
            "case_count": self.case_count,
            "evidence_line_count": self.evidence_line_count,
            "issues": list(self.issues),
        }


def _require_unique(values: tuple, attribute: str, label: str) -> None:
    identities = tuple(getattr(value, attribute) for value in values)
    if len(identities) != len(set(identities)):
        raise ValueError("duplicate {}".format(label))


def _case_payload(value: ResearchCaseInput, stages: tuple) -> dict:
    return {
        "schema_version": RESEARCH_CASE_SCHEMA_VERSION,
        "case_key": value.case_key,
        "title": value.title,
        "firmware_artifact_sha256": value.firmware_artifact_sha256,
        "architecture_tags": list(value.architecture_tags),
        "research_question": value.research_question,
        "evidence": [{**asdict(item), "kind": item.kind.value} for item in value.evidence],
        "claims": [
            {**asdict(item), "status": item.status.value} for item in value.claims
        ],
        "stages": [asdict(item) for item in stages],
        "obligations": [
            {**asdict(item), "status": item.status.value} for item in value.obligations
        ],
        "counterfactuals": list(value.counterfactuals),
        "paper_uses": list(value.paper_uses),
        "limitations": list(value.limitations),
    }


def build_research_case(value: ResearchCaseInput) -> ResearchCase:
    """Validate references and preserve the temporal path to a conclusion."""

    _require_unique(value.evidence, "evidence_ref", "evidence reference")
    _require_unique(value.claims, "claim_id", "claim")
    _require_unique(value.stages, "stage_id", "stage")
    _require_unique(value.stages, "order", "stage order")
    _require_unique(value.obligations, "obligation_id", "obligation")
    evidence_ids = {item.evidence_ref for item in value.evidence}
    claim_ids = {item.claim_id for item in value.claims}
    obligation_ids = {item.obligation_id for item in value.obligations}
    for claim in value.claims:
        unknown = set(claim.evidence_refs) - evidence_ids
        if unknown:
            raise ValueError("claim cites unknown evidence: {}".format(sorted(unknown)))
    for obligation in value.obligations:
        unknown = set(obligation.closure_evidence_refs) - evidence_ids
        if unknown:
            raise ValueError("obligation cites unknown evidence: {}".format(sorted(unknown)))

    stages = tuple(sorted(value.stages, key=lambda item: item.order))
    created = set()
    resolved = set()
    rejected = set()
    for stage in stages:
        if set(stage.claim_ids) - claim_ids:
            raise ValueError("stage cites unknown claim")
        if set(stage.creates_obligations) - obligation_ids:
            raise ValueError("stage creates unknown obligation")
        if set(stage.resolves_obligations) - obligation_ids:
            raise ValueError("stage resolves unknown obligation")
        if set(stage.rejects_obligations) - obligation_ids:
            raise ValueError("stage rejects unknown obligation")
        closed_here = set(stage.resolves_obligations) | set(stage.rejects_obligations)
        if closed_here - created:
            raise ValueError("stage closes obligation before it is created")
        if closed_here & (resolved | rejected):
            raise ValueError("stage closes an already closed obligation")
        created.update(stage.creates_obligations)
        resolved.update(stage.resolves_obligations)
        rejected.update(stage.rejects_obligations)
    for obligation in value.obligations:
        if obligation.obligation_id not in created:
            raise ValueError("obligation is not created by any stage")
        if (
            obligation.status is CaseObligationStatus.RESOLVED
            and obligation.obligation_id not in resolved
        ):
            raise ValueError("resolved obligation is not resolved by any stage")
        if (
            obligation.status is CaseObligationStatus.REJECTED
            and obligation.obligation_id not in rejected
        ):
            raise ValueError("rejected obligation is not rejected by any stage")
        if (
            obligation.status is CaseObligationStatus.OPEN
            and obligation.obligation_id in resolved | rejected
        ):
            raise ValueError("stage closure contradicts open obligation status")
        if (
            obligation.status is CaseObligationStatus.RESOLVED
            and obligation.obligation_id in rejected
        ):
            raise ValueError("stage rejection contradicts resolved obligation status")
        if (
            obligation.status is CaseObligationStatus.REJECTED
            and obligation.obligation_id in resolved
        ):
            raise ValueError("stage resolution contradicts rejected obligation status")

    payload = _case_payload(value, stages)
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return ResearchCase(
        case_id="research-case:{}".format(digest),
        schema_version=RESEARCH_CASE_SCHEMA_VERSION,
        case_key=value.case_key,
        title=value.title,
        firmware_artifact_sha256=value.firmware_artifact_sha256,
        architecture_tags=value.architecture_tags,
        research_question=value.research_question,
        evidence=value.evidence,
        claims=value.claims,
        stages=stages,
        obligations=value.obligations,
        counterfactuals=value.counterfactuals,
        paper_uses=value.paper_uses,
        limitations=value.limitations,
    )


def validate_research_case_corpus(cases: Tuple[ResearchCase, ...]) -> ResearchCaseCorpusValidation:
    """Check whether cases carry enough context for responsible paper reuse."""

    issues = []
    if not cases:
        issues.append("case corpus is empty")
    case_keys = tuple(case.case_key for case in cases)
    if len(case_keys) != len(set(case_keys)):
        issues.append("duplicate case_key")
    case_ids = tuple(case.case_id for case in cases)
    if len(case_ids) != len(set(case_ids)):
        issues.append("duplicate case_id")
    all_kinds = set()
    for case in cases:
        try:
            replayed = build_research_case(ResearchCaseInput(
                case_key=case.case_key,
                title=case.title,
                firmware_artifact_sha256=case.firmware_artifact_sha256,
                architecture_tags=case.architecture_tags,
                research_question=case.research_question,
                evidence=case.evidence,
                claims=case.claims,
                stages=case.stages,
                obligations=case.obligations,
                counterfactuals=case.counterfactuals,
                paper_uses=case.paper_uses,
                limitations=case.limitations,
            ))
        except (TypeError, ValueError) as exc:
            issues.append(
                "{}: invalid case contract ({})".format(case.case_key, exc)
            )
            replayed = None
        if replayed is not None and (
            case.schema_version != RESEARCH_CASE_SCHEMA_VERSION
            or replayed.case_id != case.case_id
        ):
            issues.append("{}: case identity does not replay".format(case.case_key))
        kinds = {item.kind for item in case.evidence}
        all_kinds.update(kinds)
        if len(kinds) < 2:
            issues.append("{}: fewer than two independent evidence lines".format(case.case_key))
        if not case.counterfactuals:
            issues.append("{}: counterfactual missing".format(case.case_key))
        if not case.paper_uses:
            issues.append("{}: paper use missing".format(case.case_key))
        if not case.limitations:
            issues.append("{}: limitation missing".format(case.case_key))
    return ResearchCaseCorpusValidation(
        schema_version=RESEARCH_CASE_CORPUS_VALIDATION_SCHEMA_VERSION,
        paper_ready=bool(cases) and not issues,
        case_count=len(cases),
        evidence_line_count=len(all_kinds),
        issues=tuple(issues),
    )
