"""Turn historical vulnerability coverage gaps into deterministic work items.

The queue intentionally separates source claims from firmware catalog clues.  A
route observed in the current artifact can guide research, but it cannot become
a historical expectation until a cited primary source states the interface.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Dict, Optional, Tuple

from .discovery_catalog import (
    DiscoveryCandidateKind,
    DiscoveryCatalog,
)
from .historical_expectation import HistoricalVulnerabilityAudit


HISTORICAL_COVERAGE_QUEUE_SCHEMA_VERSION = (
    "firmatlas.mapping.historical-coverage-queue/v1alpha1"
)


class HistoricalCoverageAction(str, Enum):
    REPAIR_PARAMETER_EXTRACTION = "repair_parameter_extraction"
    VERIFY_SOURCE_EXPECTATION = "verify_source_expectation"
    RESOLVE_HANDLER_TO_ROUTE = "resolve_handler_to_route"
    RECOVER_INTERFACE = "recover_interface"
    EXTRACT_STRUCTURED_COMMUNICATION = "extract_structured_communication"
    ANALYZE_SEMANTICS = "analyze_semantics"


class HistoricalEvidenceState(str, Enum):
    SOURCE_VERIFIED = "source_verified"
    SOURCE_PARTIAL = "source_partial"
    CATALOG_CLUE_ONLY = "catalog_clue_only"
    NEEDS_PRIMARY_SOURCE = "needs_primary_source"
    SEMANTIC_ANALYSIS_MISSING = "semantic_analysis_missing"


@dataclass(frozen=True)
class HistoricalSemanticClue:
    vulnerability_identifier: str
    description: str
    parameters: Tuple[str, ...] = ()
    handler_names: Tuple[str, ...] = ()
    source_refs: Tuple[str, ...] = ()
    source_verified_interfaces: Tuple[str, ...] = ()
    parameter_classifications: Tuple[Tuple[str, str], ...] = ()
    source_verified_route_tokens: Tuple[str, ...] = ()
    source_verified_parameters: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.vulnerability_identifier.strip() or not self.description.strip():
            raise ValueError("historical semantic clue requires identifier and description")
        for value in (
            self.parameters + self.handler_names + self.source_refs
            + self.source_verified_interfaces + self.source_verified_route_tokens
            + self.source_verified_parameters
        ):
            if not value.strip():
                raise ValueError("historical semantic clue values must not be blank")
        for name, role in self.parameter_classifications:
            if not name.strip() or role not in {"request_parameter", "configuration_key"}:
                raise ValueError("unsupported historical parameter classification")
        if len(self.parameter_classifications) != len(dict(self.parameter_classifications)):
            raise ValueError("duplicate historical parameter classification")

    @classmethod
    def from_dict(cls, value: dict) -> "HistoricalSemanticClue":
        return cls(
            vulnerability_identifier=value["vulnerability_identifier"],
            description=value["description"],
            parameters=tuple(value.get("parameters", ())),
            handler_names=tuple(value.get("handler_names", ())),
            source_refs=tuple(value.get("source_refs", ())),
            source_verified_interfaces=tuple(
                value.get("source_verified_interfaces", ())
            ),
            parameter_classifications=tuple(
                (item["name"], item["role"])
                for item in value.get("parameter_classifications", ())
            ),
            source_verified_route_tokens=tuple(
                value.get("source_verified_route_tokens", ())
            ),
            source_verified_parameters=tuple(
                value.get("source_verified_parameters", ())
            ),
        )


@dataclass(frozen=True)
class HistoricalCoverageQueueEntry:
    vulnerability_identifier: str
    audit_category: str
    action: HistoricalCoverageAction
    priority: int
    evidence_state: HistoricalEvidenceState
    reason_codes: Tuple[str, ...]
    observed_parameters: Tuple[str, ...]
    source_verified_parameters: Tuple[str, ...]
    suspicious_parameters: Tuple[str, ...]
    missing_compound_parameters: Tuple[str, ...]
    configuration_keys: Tuple[str, ...]
    misclassified_parameters: Tuple[str, ...]
    handler_names: Tuple[str, ...]
    source_verified_interfaces: Tuple[str, ...]
    source_verified_route_tokens: Tuple[str, ...]
    catalog_route_clues: Tuple[str, ...]
    catalog_candidate_ids: Tuple[str, ...]
    source_refs: Tuple[str, ...]
    candidate_analyzers: Tuple[str, ...]
    status: str = "open"

    def to_dict(self) -> dict:
        return {
            "vulnerability_identifier": self.vulnerability_identifier,
            "audit_category": self.audit_category,
            "action": self.action.value,
            "priority": self.priority,
            "evidence_state": self.evidence_state.value,
            "reason_codes": list(self.reason_codes),
            "observed_parameters": list(self.observed_parameters),
            "source_verified_parameters": list(self.source_verified_parameters),
            "suspicious_parameters": list(self.suspicious_parameters),
            "missing_compound_parameters": list(self.missing_compound_parameters),
            "configuration_keys": list(self.configuration_keys),
            "misclassified_parameters": list(self.misclassified_parameters),
            "handler_names": list(self.handler_names),
            "source_verified_interfaces": list(self.source_verified_interfaces),
            "source_verified_route_tokens": list(self.source_verified_route_tokens),
            "catalog_route_clues": list(self.catalog_route_clues),
            "catalog_candidate_ids": list(self.catalog_candidate_ids),
            "source_refs": list(self.source_refs),
            "candidate_analyzers": list(self.candidate_analyzers),
            "status": self.status,
        }


@dataclass(frozen=True)
class HistoricalCoverageQueue:
    audit_id: str
    catalog_id: Optional[str]
    entries: Tuple[HistoricalCoverageQueueEntry, ...]
    summary: Dict[str, int]
    schema_version: str = HISTORICAL_COVERAGE_QUEUE_SCHEMA_VERSION

    @property
    def queue_id(self) -> str:
        encoded = json.dumps(
            self.to_dict(include_id=False), separators=(",", ":"), sort_keys=True
        ).encode()
        return "historical-coverage-queue:" + hashlib.sha256(encoded).hexdigest()

    def to_dict(self, include_id: bool = True) -> dict:
        value = {
            "schema_version": self.schema_version,
            "audit_id": self.audit_id,
            "catalog_id": self.catalog_id,
            "summary": dict(sorted(self.summary.items())),
            "entries": [item.to_dict() for item in self.entries],
        }
        if include_id:
            value["queue_id"] = self.queue_id
        return value


_SUSPICIOUS_PARAMETER_WORDS = {
    "appear", "appears", "contain", "contains", "exist", "exists", "occur",
    "occurs", "provide", "provides", "result", "results", "trigger",
    "triggers", "use", "uses",
}
_COMPOUND = re.compile(
    r"(?<![A-Za-z0-9_.:-])([A-Za-z_][A-Za-z0-9_.:-]*"
    r"(?:/[A-Za-z_][A-Za-z0-9_.:-]*)+)"
)


def _compound_parameter_members(description: str) -> Tuple[str, ...]:
    values = []
    for match in _COMPOUND.finditer(description):
        members = tuple(item.rstrip(".") for item in match.group(1).split("/"))
        # A path is not a slash-delimited parameter list.  Compound state keys
        # in the source corpus are qualified names on both sides of the slash.
        if all("." in item for item in members):
            values.extend(members)
    return tuple(sorted(set(values)))


def _catalog_routes(
    catalog: Optional[DiscoveryCatalog], handler_names: Tuple[str, ...]
) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    if catalog is None or not handler_names:
        return (), ()
    routes = []
    candidate_ids = []
    handlers = set(handler_names)
    for candidate in catalog.candidates:
        attributes = dict(candidate.attributes)
        if candidate.candidate_kind != DiscoveryCandidateKind.NATIVE_ROUTE_BINDING:
            continue
        if attributes.get("handler_symbol") not in handlers:
            continue
        routes.append(candidate.canonical_identity)
        candidate_ids.append(candidate.candidate_id)
    return tuple(sorted(set(routes))), tuple(sorted(set(candidate_ids)))


def _category_by_identifier(audit: HistoricalVulnerabilityAudit) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for category, identifiers in (
        ("compared_interface", audit.compared_interface_identifiers),
        ("parameter_only", audit.parameter_only_identifiers),
        ("no_structured_communication", audit.no_structured_communication_identifiers),
        ("not_analyzed", audit.not_analyzed_identifiers),
    ):
        for identifier in identifiers:
            if identifier in result:
                raise ValueError("duplicate vulnerability in historical audit categories")
            result[identifier] = category
    if len(result) != audit.total_vulnerability_count:
        raise ValueError("historical audit categories do not cover denominator")
    return result


def _make_entry(
    identifier: str,
    category: str,
    clue: Optional[HistoricalSemanticClue],
    catalog: Optional[DiscoveryCatalog],
) -> HistoricalCoverageQueueEntry:
    parameters = tuple(sorted(set(clue.parameters))) if clue else ()
    handlers = tuple(sorted(set(clue.handler_names))) if clue else ()
    interfaces = tuple(sorted(set(clue.source_verified_interfaces))) if clue else ()
    source_refs = tuple(sorted(set(clue.source_refs))) if clue else ()
    source_route_tokens = tuple(
        sorted(set(clue.source_verified_route_tokens))
    ) if clue else ()
    source_parameters = tuple(
        sorted(set(clue.source_verified_parameters))
    ) if clue else ()
    classifications = dict(clue.parameter_classifications) if clue else {}
    configuration_keys = tuple(sorted(
        name for name, role in classifications.items()
        if role == "configuration_key"
    ))
    misclassified = tuple(
        name for name in configuration_keys if name in set(parameters)
    )
    suspicious = tuple(sorted(
        item for item in parameters if item.casefold() in _SUSPICIOUS_PARAMETER_WORDS
    ))
    compound = _compound_parameter_members(clue.description) if clue else ()
    missing_compound = tuple(item for item in compound if item not in set(parameters))
    route_clues, candidate_ids = _catalog_routes(catalog, handlers)
    reasons = []

    if category == "not_analyzed":
        action = HistoricalCoverageAction.ANALYZE_SEMANTICS
        priority = 30
        evidence_state = HistoricalEvidenceState.SEMANTIC_ANALYSIS_MISSING
        analyzers = ("rule-semantic-analyzer", "model-semantic-analyzer")
        reasons.append("semantic_analysis_missing")
    elif category == "no_structured_communication":
        action = HistoricalCoverageAction.EXTRACT_STRUCTURED_COMMUNICATION
        priority = 50
        evidence_state = HistoricalEvidenceState.NEEDS_PRIMARY_SOURCE
        analyzers = ("primary-source-semantic-extractor", "model-semantic-analyzer")
        reasons.append("structured_communication_missing")
    elif suspicious or missing_compound or misclassified:
        action = HistoricalCoverageAction.REPAIR_PARAMETER_EXTRACTION
        priority = 100 if suspicious else 95
        if interfaces:
            evidence_state = HistoricalEvidenceState.SOURCE_VERIFIED
        elif source_route_tokens or configuration_keys or source_parameters:
            evidence_state = HistoricalEvidenceState.SOURCE_PARTIAL
        else:
            evidence_state = HistoricalEvidenceState.NEEDS_PRIMARY_SOURCE
        analyzers = ("rule-semantic-analyzer", "primary-source-semantic-extractor")
        if suspicious:
            reasons.append("suspicious_parameter_token")
        if missing_compound:
            reasons.append("compound_parameter_member_missing")
        if misclassified:
            reasons.append("configuration_key_misclassified_as_request_parameter")
        reasons.append("interface_observation_missing")
    elif interfaces:
        action = HistoricalCoverageAction.VERIFY_SOURCE_EXPECTATION
        priority = 90
        evidence_state = HistoricalEvidenceState.SOURCE_VERIFIED
        analyzers = ("historical-expectation-replay",)
        reasons.append("primary_source_interface_ready")
    elif handlers:
        action = HistoricalCoverageAction.RESOLVE_HANDLER_TO_ROUTE
        priority = 85
        evidence_state = (
            HistoricalEvidenceState.CATALOG_CLUE_ONLY
            if route_clues else HistoricalEvidenceState.NEEDS_PRIMARY_SOURCE
        )
        analyzers = ("native-route-binding", "primary-source-semantic-extractor")
        reasons.append("handler_without_source_interface")
        if route_clues:
            reasons.append("catalog_clue_not_historical_fact")
    else:
        action = HistoricalCoverageAction.RECOVER_INTERFACE
        priority = 80
        evidence_state = HistoricalEvidenceState.NEEDS_PRIMARY_SOURCE
        analyzers = ("primary-source-semantic-extractor", "model-semantic-analyzer")
        reasons.append("parameter_without_interface")

    if source_route_tokens and not interfaces:
        reasons.append("source_route_token_without_http_interface")

    return HistoricalCoverageQueueEntry(
        vulnerability_identifier=identifier,
        audit_category=category,
        action=action,
        priority=priority,
        evidence_state=evidence_state,
        reason_codes=tuple(reasons),
        observed_parameters=parameters,
        source_verified_parameters=source_parameters,
        suspicious_parameters=suspicious,
        missing_compound_parameters=missing_compound,
        configuration_keys=configuration_keys,
        misclassified_parameters=misclassified,
        handler_names=handlers,
        source_verified_interfaces=interfaces,
        source_verified_route_tokens=source_route_tokens,
        catalog_route_clues=route_clues,
        catalog_candidate_ids=candidate_ids,
        source_refs=source_refs,
        candidate_analyzers=analyzers,
    )


def build_historical_coverage_queue(
    audit: HistoricalVulnerabilityAudit,
    semantic_clues: Tuple[HistoricalSemanticClue, ...] = (),
    catalog: Optional[DiscoveryCatalog] = None,
) -> HistoricalCoverageQueue:
    """Build a stable priority queue for every historical gap in an audit."""

    categories = _category_by_identifier(audit)
    clues: Dict[str, HistoricalSemanticClue] = {}
    for clue in semantic_clues:
        if clue.vulnerability_identifier not in categories:
            raise ValueError("historical semantic clue is outside audit scope")
        if clue.vulnerability_identifier in clues:
            raise ValueError("duplicate historical semantic clue")
        clues[clue.vulnerability_identifier] = clue
    entries = tuple(sorted(
        (
            _make_entry(identifier, category, clues.get(identifier), catalog)
            for identifier, category in categories.items()
            if category != "compared_interface"
        ),
        key=lambda item: (-item.priority, item.vulnerability_identifier),
    ))
    action_counts: Dict[str, int] = {}
    for item in entries:
        action_counts[item.action.value] = action_counts.get(item.action.value, 0) + 1
    return HistoricalCoverageQueue(
        audit_id=audit.audit_id,
        catalog_id=catalog.catalog_id if catalog else None,
        entries=entries,
        summary={"open": len(entries), **action_counts},
    )


def load_historical_semantic_clues(
    document: dict,
) -> Tuple[HistoricalSemanticClue, ...]:
    if document.get("schema_version") != (
        "firmatlas.mapping.historical-semantic-clues/v1alpha1"
    ):
        raise ValueError("unsupported historical semantic clues schema_version")
    clues = tuple(
        HistoricalSemanticClue.from_dict(item)
        for item in document.get("clues", ())
    )
    if len({item.vulnerability_identifier for item in clues}) != len(clues):
        raise ValueError("duplicate historical semantic clue")
    return clues
