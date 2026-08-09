"""Coverage-aware structural comparison for immutable mapping catalogs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple

from .hidden_interface import project_potential_hidden_interface_document


MAPPING_SNAPSHOT_DIFF_SCHEMA_VERSION = (
    "firmatlas.mapping.snapshot-diff/v1alpha1"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class SnapshotComparisonStatus(str, Enum):
    COVERAGE_EQUIVALENT = "coverage_equivalent"
    COVERAGE_EQUIVALENT_PARTIAL = "coverage_equivalent_partial"
    COVERAGE_CONFOUNDED = "coverage_confounded"


class SnapshotChangeKind(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


class SnapshotChangeConfidence(str, Enum):
    FIRMWARE_CHANGE_SUPPORTED = "firmware_change_supported"
    OBSERVED_SCOPE_ONLY = "observed_scope_only"
    COVERAGE_CONFOUNDED = "coverage_confounded"


@dataclass(frozen=True)
class MappingReleaseContext:
    vendor: str
    product: str
    device_model: str
    firmware_version: str
    source_ref: str
    evidence: str

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str) and value.strip()
            for value in (
                self.vendor, self.product, self.device_model,
                self.firmware_version, self.source_ref, self.evidence,
            )
        ):
            raise ValueError("mapping release context fields are required")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class MappingSnapshotChange:
    change_id: str
    category: str
    stable_identity: str
    display_identity: str
    change_kind: SnapshotChangeKind
    confidence: SnapshotChangeConfidence
    changed_fields: Tuple[str, ...]
    base: Optional[dict]
    target: Optional[dict]
    interpretation: str


@dataclass(frozen=True)
class MappingSnapshotDiffDiagnostic:
    code: str
    message: str


@dataclass(frozen=True)
class MappingSnapshotDiff:
    comparison_id: str
    base_catalog_id: str
    target_catalog_id: str
    base_firmware_artifact_sha256: str
    target_firmware_artifact_sha256: str
    comparison_status: SnapshotComparisonStatus
    same_firmware_family_verified: bool
    base_release_context: Optional[MappingReleaseContext]
    target_release_context: Optional[MappingReleaseContext]
    changes: Tuple[MappingSnapshotChange, ...]
    diagnostics: Tuple[MappingSnapshotDiffDiagnostic, ...]
    schema_version: str = MAPPING_SNAPSHOT_DIFF_SCHEMA_VERSION

    def to_dict(self) -> dict:
        changes = [
            {
                **asdict(item),
                "change_kind": item.change_kind.value,
                "confidence": item.confidence.value,
            }
            for item in self.changes
        ]
        return {
            "schema_version": self.schema_version,
            "comparison_id": self.comparison_id,
            "base": {
                "catalog_id": self.base_catalog_id,
                "firmware_artifact_sha256": self.base_firmware_artifact_sha256,
                "release_context": (
                    self.base_release_context.to_dict()
                    if self.base_release_context else None
                ),
            },
            "target": {
                "catalog_id": self.target_catalog_id,
                "firmware_artifact_sha256": self.target_firmware_artifact_sha256,
                "release_context": (
                    self.target_release_context.to_dict()
                    if self.target_release_context else None
                ),
            },
            "comparison_status": self.comparison_status.value,
            "same_firmware_family_verified": self.same_firmware_family_verified,
            "summary": _summary(changes),
            "changes": changes,
            "diagnostics": [asdict(item) for item in self.diagnostics],
        }


def compare_mapping_catalog_documents(
    base: dict,
    target: dict,
    base_release_context: Optional[MappingReleaseContext] = None,
    target_release_context: Optional[MappingReleaseContext] = None,
) -> MappingSnapshotDiff:
    """Compare two catalog documents without treating analysis drift as firmware drift."""

    _validate_catalog_identity(base, "base")
    _validate_catalog_identity(target, "target")
    base_coverage = _coverage_entities(base)
    target_coverage = _coverage_entities(target)
    profiles_equal = _coverage_profile(base_coverage) == _coverage_profile(
        target_coverage
    )
    if not profiles_equal:
        status = SnapshotComparisonStatus.COVERAGE_CONFOUNDED
        confidence = SnapshotChangeConfidence.COVERAGE_CONFOUNDED
    elif _coverage_complete(base_coverage) and _coverage_complete(target_coverage):
        status = SnapshotComparisonStatus.COVERAGE_EQUIVALENT
        confidence = SnapshotChangeConfidence.FIRMWARE_CHANGE_SUPPORTED
    else:
        status = SnapshotComparisonStatus.COVERAGE_EQUIVALENT_PARTIAL
        confidence = SnapshotChangeConfidence.OBSERVED_SCOPE_ONLY
    changes = []
    changes.extend(_compare_entities(
        "coverage", base_coverage, target_coverage,
        SnapshotChangeConfidence.COVERAGE_CONFOUNDED,
    ))
    changes.extend(_compare_entities(
        "candidate", _candidate_entities(base), _candidate_entities(target), confidence,
    ))
    changes.extend(_compare_entities(
        "parameter", _parameter_entities(base), _parameter_entities(target), confidence,
    ))
    same_family = _same_release_family(
        base_release_context, target_release_context
    )
    diagnostics = []
    if not same_family:
        diagnostics.append(MappingSnapshotDiffDiagnostic(
            (
                "release_family_mismatch"
                if base_release_context and target_release_context
                else "firmware_family_unverified"
            ),
            "both catalogs require evidence-backed matching vendor, product, and "
            "device model before structural differences can assert version lineage",
        ))
    base_hidden = project_potential_hidden_interface_document(base)
    target_hidden = project_potential_hidden_interface_document(target)
    if (
        base_hidden.coverage_status.value == "completed"
        and target_hidden.coverage_status.value == "completed"
    ):
        changes.extend(_compare_entities(
            "potential_hidden_interface",
            _hidden_entities(base_hidden.items),
            _hidden_entities(target_hidden.items),
            confidence,
        ))
    else:
        diagnostics.append(MappingSnapshotDiffDiagnostic(
            "hidden_interface_comparison_unavailable",
            "both catalogs require completed source inventory, frontend, and "
            "set-difference coverage before absence-state transitions can be compared",
        ))
    changes = tuple(sorted(
        changes,
        key=lambda item: (item.category, item.stable_identity, item.change_kind.value),
    ))
    comparison_id = _stable_id(
        "mapping-snapshot-diff",
        base["catalog_id"],
        target["catalog_id"],
        MAPPING_SNAPSHOT_DIFF_SCHEMA_VERSION,
        json.dumps(
            base_release_context.to_dict() if base_release_context else None,
            sort_keys=True,
        ),
        json.dumps(
            target_release_context.to_dict() if target_release_context else None,
            sort_keys=True,
        ),
    )
    return MappingSnapshotDiff(
        comparison_id,
        base["catalog_id"],
        target["catalog_id"],
        base["firmware_artifact_sha256"],
        target["firmware_artifact_sha256"],
        status,
        same_family,
        base_release_context,
        target_release_context,
        changes,
        tuple(diagnostics),
    )


def _same_release_family(
    base: Optional[MappingReleaseContext],
    target: Optional[MappingReleaseContext],
) -> bool:
    if base is None or target is None:
        return False
    return tuple(
        _normalized_identity(value)
        for value in (base.vendor, base.product, base.device_model)
    ) == tuple(
        _normalized_identity(value)
        for value in (target.vendor, target.product, target.device_model)
    )


def _normalized_identity(value: str) -> str:
    return " ".join(re.findall(r"[a-z0-9]+", value.casefold()))


def _validate_catalog_identity(document: dict, label: str) -> None:
    catalog_id = document.get("catalog_id")
    firmware = document.get("firmware_artifact_sha256")
    if not isinstance(catalog_id, str) or not catalog_id:
        raise ValueError("{} catalog_id is required".format(label))
    if not isinstance(firmware, str) or not _SHA256.fullmatch(firmware):
        raise ValueError("{} firmware artifact identity is invalid".format(label))


def _stable_id(prefix: str, *values: str) -> str:
    payload = json.dumps(values, separators=(",", ":")).encode("utf-8")
    return "{}:{}".format(prefix, hashlib.sha256(payload).hexdigest())


def _attributes(item: Mapping[str, Any]) -> Dict[str, str]:
    return {str(key): str(value) for key, value in item.get("attributes", [])}


def _candidate_alignment(item: Mapping[str, Any]) -> str:
    kind = str(item.get("candidate_kind", "unknown"))
    canonical = str(item.get("canonical_identity", ""))
    attributes = _attributes(item)
    if kind == "native_handler" and attributes.get("route_token"):
        canonical = attributes["route_token"]
    elif kind == "native_nested_dispatch" and attributes.get("normalized_operation"):
        canonical = attributes["normalized_operation"]
    elif kind == "native_request_protection":
        canonical = canonical.rsplit(" -> ", 1)[0]
    elif kind == "set_difference_attribution":
        canonical = "{}|{}|{}".format(
            canonical,
            attributes.get("difference_side", ""),
            attributes.get("attribution_kind", ""),
        )
    return "{}|{}".format(kind, canonical)


def _candidate_entities(document: dict) -> Dict[str, dict]:
    grouped: Dict[str, list] = {}
    for item in document.get("candidates", []):
        grouped.setdefault(_candidate_alignment(item), []).append(item)
    entities = {}
    for identity, members in grouped.items():
        first = members[0]
        entities[identity] = {
            "candidate_kind": first.get("candidate_kind"),
            "canonical_identities": sorted({
                str(item.get("canonical_identity", "")) for item in members
            }),
            "member_count": len(members),
            "claim_statuses": sorted({
                str(item.get("claim_status", "")) for item in members
            }),
            "source_paths": sorted({
                str(item.get("source_path", "")) for item in members
            }),
            "source_constructs": sorted({
                str(item.get("source_construct", "")) for item in members
            }),
            "attributes": sorted({
                (str(key), str(value))
                for item in members for key, value in item.get("attributes", [])
            }),
        }
    return entities


def _parameter_entities(document: dict) -> Dict[str, dict]:
    candidate_keys = {
        str(item.get("candidate_id")): _candidate_alignment(item)
        for item in document.get("candidates", [])
    }
    grouped: Dict[str, list] = {}
    for item in document.get("parameters", []):
        owner = candidate_keys.get(
            str(item.get("owner_ref")),
            "unresolved-owner|{}".format(item.get("owner_ref", "")),
        )
        identity = "{}|{}|{}".format(
            owner, item.get("namespace", ""), item.get("name", "")
        )
        grouped.setdefault(identity, []).append(item)
    entities = {}
    for identity, members in grouped.items():
        entities[identity] = {
            "member_count": len(members),
            "literal_values": sorted({
                str(item["literal_value"]) for item in members
                if item.get("literal_value") is not None
            }),
            "selector_values": sorted({
                str(value) for item in members
                for value in item.get("selector_values", [])
            }),
            "operation_selector": any(
                bool(item.get("is_operation_selector")) for item in members
            ),
            "source_constructs": sorted({
                str(item.get("source_construct", "")) for item in members
            }),
        }
    return entities


def _coverage_entities(document: dict) -> Dict[str, dict]:
    entities = {
        "source_inventory|catalog": {
            "producer_kind": "source_inventory",
            "scope": "catalog",
            "status": document.get("source_inventory_coverage_status"),
            "required": True,
        }
    }
    for item in document.get("coverage", []):
        identity = "{}|{}".format(
            item.get("producer_kind", ""), item.get("scope", "")
        )
        entities[identity] = {
            "producer_kind": item.get("producer_kind"),
            "scope": item.get("scope"),
            "producer": item.get("producer"),
            "producer_version": item.get("producer_version"),
            "status": item.get("status"),
            "required": bool(item.get("required")),
            "processed_result_count": int(item.get("processed_result_count", 0)),
            "diagnostic": item.get("diagnostic"),
        }
    return entities


def _coverage_profile(entities: Mapping[str, dict]) -> tuple:
    relevant = (
        "producer_kind", "scope", "producer", "producer_version", "status", "required"
    )
    return tuple(sorted(
        (identity, tuple((key, value.get(key)) for key in relevant))
        for identity, value in entities.items()
    ))


def _coverage_complete(entities: Mapping[str, dict]) -> bool:
    return all(
        not value.get("required") or value.get("status") == "completed"
        for value in entities.values()
    )


def _hidden_entities(items: Iterable[Any]) -> Dict[str, dict]:
    entities = {}
    for item in items:
        identity = "{}|{}".format(
            item.operation_token, item.registration_artifact_path
        )
        entities[identity] = {
            "operation_token": item.operation_token,
            "registration_artifact_path": item.registration_artifact_path,
            "handler_identities": list(item.handler_identities),
            "frontend_coverage_scopes": list(item.frontend_coverage_scopes),
            "runtime_reachability_verified": item.runtime_reachability_verified,
        }
    return entities


def _compare_entities(
    category: str,
    base: Mapping[str, dict],
    target: Mapping[str, dict],
    confidence: SnapshotChangeConfidence,
) -> Tuple[MappingSnapshotChange, ...]:
    changes = []
    for identity in sorted(set(base) | set(target)):
        before, after = base.get(identity), target.get(identity)
        if before == after:
            continue
        if before is None:
            kind = SnapshotChangeKind.ADDED
            fields = tuple(sorted(after or ()))
        elif after is None:
            kind = SnapshotChangeKind.REMOVED
            fields = tuple(sorted(before))
        else:
            kind = SnapshotChangeKind.CHANGED
            fields = tuple(sorted(
                key for key in set(before) | set(after)
                if before.get(key) != after.get(key)
            ))
        display = _display_identity(category, identity, before, after)
        changes.append(MappingSnapshotChange(
            _stable_id("mapping-snapshot-change", category, identity, kind.value),
            category,
            identity,
            display,
            kind,
            confidence,
            fields,
            before,
            after,
            _interpretation(category, kind, confidence),
        ))
    return tuple(changes)


def _display_identity(
    category: str, identity: str,
    before: Optional[dict], after: Optional[dict],
) -> str:
    value = after or before or {}
    if category == "candidate":
        canonical = value.get("canonical_identities", [])
        return str(canonical[0] if canonical else identity)
    if category == "potential_hidden_interface":
        return str(value.get("operation_token", identity))
    if category == "coverage":
        return "{} · {}".format(value.get("producer_kind", ""), value.get("scope", ""))
    return identity.rsplit("|", 1)[-1]


def _interpretation(
    category: str,
    kind: SnapshotChangeKind,
    confidence: SnapshotChangeConfidence,
) -> str:
    if category == "coverage":
        return "analysis coverage changed; inspect this before interpreting structure"
    if confidence is SnapshotChangeConfidence.COVERAGE_CONFOUNDED:
        return "observed structural difference may be caused by analysis coverage drift"
    if confidence is SnapshotChangeConfidence.OBSERVED_SCOPE_ONLY:
        return "structural difference is supported only inside equal incomplete scopes"
    if category == "potential_hidden_interface":
        return (
            "absence-state {} under equivalent completed coverage; runtime cause remains open"
        ).format(kind.value)
    return "structural {} under equivalent analysis coverage".format(kind.value)


def _summary(changes: Iterable[dict]) -> dict:
    values = list(changes)
    def count(category: str, kind: str) -> int:
        return sum(
            item["category"] == category and item["change_kind"] == kind
            for item in values
        )
    return {
        "added_candidate_count": count("candidate", "added"),
        "removed_candidate_count": count("candidate", "removed"),
        "changed_candidate_count": count("candidate", "changed"),
        "added_parameter_count": count("parameter", "added"),
        "removed_parameter_count": count("parameter", "removed"),
        "changed_parameter_count": count("parameter", "changed"),
        "discovered_hidden_interface_count": count(
            "potential_hidden_interface", "added"
        ),
        "resolved_hidden_interface_count": count(
            "potential_hidden_interface", "removed"
        ),
        "changed_hidden_interface_count": count(
            "potential_hidden_interface", "changed"
        ),
        "coverage_change_count": sum(
            item["category"] == "coverage" for item in values
        ),
        "total_change_count": len(values),
    }
