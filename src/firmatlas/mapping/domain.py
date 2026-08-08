"""Versioned domain contract published by the firmware mapping module."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import re
from typing import Any, Dict, Optional, Tuple


SNAPSHOT_SCHEMA_VERSION = "firmatlas.mapping.snapshot/v1alpha1"
EVIDENCE_SCHEMA_VERSION = "firmatlas.mapping.evidence/v1alpha1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class MappingMode(str, Enum):
    DISCOVER = "discover"
    STANDARD = "standard"
    DEEP = "deep"


class SnapshotStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"


class ClaimStatus(str, Enum):
    SUPPORTED = "supported"
    REFUTED = "refuted"
    UNKNOWN = "unknown"
    CONFLICT = "conflict"


class ObservationKind(str, Enum):
    DIRECT_STATIC = "direct_static"
    DETERMINISTIC_DERIVED = "deterministic_derived"
    MODEL_SUGGESTED = "model_suggested"
    RUNTIME_OBSERVED = "runtime_observed"
    HUMAN_ASSERTED = "human_asserted"


class SpanKind(str, Enum):
    TEXT_UTF8 = "text_utf8"
    BINARY = "binary"


class CoverageStatus(str, Enum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED_BY_POLICY = "skipped_by_policy"
    UNSUPPORTED = "unsupported"
    NOT_APPLICABLE = "not_applicable"


class ObligationStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    BLOCKED = "blocked"


class DiagnosticSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class AnalyzerIdentity:
    name: str
    version: str


@dataclass(frozen=True)
class MappingPolicy:
    name: str
    mode: MappingMode
    allow_model: bool = False
    allow_runtime: bool = False


@dataclass(frozen=True)
class MappingBudget:
    max_files: int
    max_bytes: int
    max_seconds: int
    max_deep_targets: int


@dataclass(frozen=True)
class EvidenceSpan:
    artifact_path: str
    artifact_sha256: str
    locator: str
    span_kind: Optional[SpanKind] = None
    start_byte: Optional[int] = None
    end_byte: Optional[int] = None
    excerpt_sha256: Optional[str] = None
    start_line: Optional[int] = None
    start_column: Optional[int] = None
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return _primitive(asdict(self))

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "EvidenceSpan":
        return cls(
            **{
                **value,
                "span_kind": (
                    SpanKind(value["span_kind"])
                    if value.get("span_kind")
                    else None
                ),
            }
        )


@dataclass(frozen=True)
class EvidenceAtom:
    evidence_id: str
    subject_ref: str
    predicate: str
    object_value: str
    source_span: EvidenceSpan
    producer: str
    producer_version: str
    observation_kind: ObservationKind
    capability: str
    confidence: float
    schema_version: str = EVIDENCE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != EVIDENCE_SCHEMA_VERSION:
            raise ValueError("unsupported evidence schema_version")

    def to_dict(self) -> Dict[str, Any]:
        return _primitive(asdict(self))

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "EvidenceAtom":
        return cls(
            evidence_id=value["evidence_id"],
            subject_ref=value["subject_ref"],
            predicate=value["predicate"],
            object_value=value["object_value"],
            source_span=EvidenceSpan.from_dict(value["source_span"]),
            producer=value["producer"],
            producer_version=value["producer_version"],
            observation_kind=ObservationKind(value["observation_kind"]),
            capability=value["capability"],
            confidence=value["confidence"],
            schema_version=value.get("schema_version", EVIDENCE_SCHEMA_VERSION),
        )


@dataclass(frozen=True)
class MappingEntity:
    entity_id: str
    entity_kind: str
    canonical_identity: str
    claim_status: ClaimStatus
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class SemanticRelation:
    relation_id: str
    source_ref: str
    predicate: str
    target_ref: str
    claim_status: ClaimStatus
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class CoverageEntry:
    scope: str
    capability: str
    status: CoverageStatus
    producer: str
    producer_version: str
    required: bool
    diagnostic: Optional[str] = None


@dataclass(frozen=True)
class UnresolvedObligation:
    obligation_id: str
    target_ref: str
    required_capability: str
    reason: str
    priority: int
    candidate_analyzers: Tuple[str, ...]
    status: ObligationStatus


@dataclass(frozen=True)
class MappingDiagnostic:
    code: str
    severity: DiagnosticSeverity
    message: str
    producer: Optional[str] = None


def _primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {key: _primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_primitive(item) for item in value]
    return value


def _require_unique(values: Tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError("duplicate {}".format(label))


@dataclass(frozen=True)
class FirmwareMappingSnapshot:
    schema_version: str
    snapshot_id: str
    firmware_artifact_sha256: str
    source_inventory_sha256: str
    status: SnapshotStatus
    policy: MappingPolicy
    budget: MappingBudget
    analyzers: Tuple[AnalyzerIdentity, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    entities: Tuple[MappingEntity, ...]
    relations: Tuple[SemanticRelation, ...]
    coverage: Tuple[CoverageEntry, ...]
    unresolved_obligations: Tuple[UnresolvedObligation, ...]
    diagnostics: Tuple[MappingDiagnostic, ...] = ()

    def __post_init__(self) -> None:
        _require_unique(
            tuple(item.evidence_id for item in self.evidence_atoms), "evidence_id"
        )
        _require_unique(
            tuple(item.entity_id for item in self.entities), "entity_id"
        )
        _require_unique(
            tuple(item.relation_id for item in self.relations), "relation_id"
        )
        _require_unique(
            tuple(item.obligation_id for item in self.unresolved_obligations),
            "obligation_id",
        )
        if self.status is SnapshotStatus.FAILED and not self.diagnostics:
            raise ValueError("failed snapshot requires diagnostics")
        for entry in self.coverage:
            if (
                entry.status in {
                    CoverageStatus.PARTIAL,
                    CoverageStatus.FAILED,
                    CoverageStatus.SKIPPED_BY_POLICY,
                    CoverageStatus.UNSUPPORTED,
                }
                and not (entry.diagnostic or "").strip()
            ):
                raise ValueError(
                    "{} coverage requires diagnostic for {}".format(
                        entry.status.value, entry.scope
                    )
                )
        if self.schema_version != SNAPSHOT_SCHEMA_VERSION:
            raise ValueError("unsupported mapping snapshot schema_version")
        for field_name, digest in (
            ("firmware_artifact_sha256", self.firmware_artifact_sha256),
            ("source_inventory_sha256", self.source_inventory_sha256),
        ):
            if not _SHA256.fullmatch(digest):
                raise ValueError("{} must be a lowercase SHA-256".format(field_name))
        for evidence in self.evidence_atoms:
            if not 0.0 <= float(evidence.confidence) <= 1.0:
                raise ValueError(
                    "evidence {} confidence must be between 0 and 1".format(
                        evidence.evidence_id
                    )
                )
            if not _SHA256.fullmatch(evidence.source_span.artifact_sha256):
                raise ValueError(
                    "evidence {} artifact_sha256 must be a lowercase SHA-256".format(
                        evidence.evidence_id
                    )
                )
        if self.status is SnapshotStatus.SUCCESS:
            incomplete = tuple(
                entry for entry in self.coverage
                if entry.required and entry.status not in {
                    CoverageStatus.COMPLETED,
                    CoverageStatus.NOT_APPLICABLE,
                }
            )
            if incomplete:
                raise ValueError(
                    "success requires completed coverage for every required scope"
                )
        evidence_by_id = {
            evidence.evidence_id: evidence for evidence in self.evidence_atoms
        }
        entity_ids = {entity.entity_id for entity in self.entities}
        for entity in self.entities:
            for evidence_id in entity.evidence_ids:
                if evidence_id not in evidence_by_id:
                    raise ValueError(
                        "entity {} references unknown evidence {}".format(
                            entity.entity_id, evidence_id
                        )
                    )
            if (
                entity.claim_status is ClaimStatus.SUPPORTED
                and entity.evidence_ids
                and all(
                    evidence_by_id[evidence_id].observation_kind
                    is ObservationKind.MODEL_SUGGESTED
                    for evidence_id in entity.evidence_ids
                )
            ):
                raise ValueError(
                    "entity {} has only model-suggested evidence".format(
                        entity.entity_id
                    )
                )
        for relation in self.relations:
            if relation.source_ref not in entity_ids:
                raise ValueError(
                    "relation {} references unknown source {}".format(
                        relation.relation_id, relation.source_ref
                    )
                )
            if relation.target_ref not in entity_ids:
                raise ValueError(
                    "relation {} references unknown target {}".format(
                        relation.relation_id, relation.target_ref
                    )
                )
            for evidence_id in relation.evidence_ids:
                if evidence_id not in evidence_by_id:
                    raise ValueError(
                        "relation {} references unknown evidence {}".format(
                            relation.relation_id, evidence_id
                        )
                    )
            if (
                relation.claim_status is ClaimStatus.SUPPORTED
                and relation.evidence_ids
                and all(
                    evidence_by_id[evidence_id].observation_kind
                    is ObservationKind.MODEL_SUGGESTED
                    for evidence_id in relation.evidence_ids
                )
            ):
                raise ValueError(
                    "relation {} has only model-suggested evidence".format(
                        relation.relation_id
                    )
                )
        for obligation in self.unresolved_obligations:
            if obligation.target_ref not in entity_ids:
                raise ValueError(
                    "obligation {} references unknown target {}".format(
                        obligation.obligation_id, obligation.target_ref
                    )
                )

    def to_dict(self) -> Dict[str, Any]:
        return _primitive(asdict(self))

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "FirmwareMappingSnapshot":
        evidence_atoms = tuple(
            EvidenceAtom.from_dict(item)
            for item in value.get("evidence_atoms", ())
        )
        entities = tuple(
            MappingEntity(
                entity_id=item["entity_id"],
                entity_kind=item["entity_kind"],
                canonical_identity=item["canonical_identity"],
                claim_status=ClaimStatus(item["claim_status"]),
                evidence_ids=tuple(item.get("evidence_ids", ())),
            )
            for item in value.get("entities", ())
        )
        relations = tuple(
            SemanticRelation(
                relation_id=item["relation_id"],
                source_ref=item["source_ref"],
                predicate=item["predicate"],
                target_ref=item["target_ref"],
                claim_status=ClaimStatus(item["claim_status"]),
                evidence_ids=tuple(item.get("evidence_ids", ())),
            )
            for item in value.get("relations", ())
        )
        coverage = tuple(
            CoverageEntry(
                scope=item["scope"],
                capability=item["capability"],
                status=CoverageStatus(item["status"]),
                producer=item["producer"],
                producer_version=item["producer_version"],
                required=item["required"],
                diagnostic=item.get("diagnostic"),
            )
            for item in value.get("coverage", ())
        )
        obligations = tuple(
            UnresolvedObligation(
                obligation_id=item["obligation_id"],
                target_ref=item["target_ref"],
                required_capability=item["required_capability"],
                reason=item["reason"],
                priority=item["priority"],
                candidate_analyzers=tuple(item.get("candidate_analyzers", ())),
                status=ObligationStatus(item["status"]),
            )
            for item in value.get("unresolved_obligations", ())
        )
        diagnostics = tuple(
            MappingDiagnostic(
                code=item["code"],
                severity=DiagnosticSeverity(item["severity"]),
                message=item["message"],
                producer=item.get("producer"),
            )
            for item in value.get("diagnostics", ())
        )
        policy = value["policy"]
        return cls(
            schema_version=value["schema_version"],
            snapshot_id=value["snapshot_id"],
            firmware_artifact_sha256=value["firmware_artifact_sha256"],
            source_inventory_sha256=value["source_inventory_sha256"],
            status=SnapshotStatus(value["status"]),
            policy=MappingPolicy(
                name=policy["name"],
                mode=MappingMode(policy["mode"]),
                allow_model=policy.get("allow_model", False),
                allow_runtime=policy.get("allow_runtime", False),
            ),
            budget=MappingBudget(**value["budget"]),
            analyzers=tuple(
                AnalyzerIdentity(**item) for item in value.get("analyzers", ())
            ),
            evidence_atoms=evidence_atoms,
            entities=entities,
            relations=relations,
            coverage=coverage,
            unresolved_obligations=obligations,
            diagnostics=diagnostics,
        )
