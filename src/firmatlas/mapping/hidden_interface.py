"""Conservative projection of native registrations without observed frontend use."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Tuple

from .discovery_catalog import (
    DiscoveryCatalog,
)
from .domain import CoverageStatus
from .set_difference import DifferenceAttributionKind, DifferenceSide


POTENTIAL_HIDDEN_INTERFACE_INDEX_SCHEMA_VERSION = (
    "firmatlas.mapping.potential-hidden-interface-index/v1alpha1"
)


@dataclass(frozen=True)
class PotentialHiddenInterface:
    interface_id: str
    catalog_id: str
    firmware_artifact_sha256: str
    operation_token: str
    attribution_id: str
    registration_artifact_path: str
    binding_ids: Tuple[str, ...]
    handler_identities: Tuple[str, ...]
    frontend_coverage_scopes: Tuple[str, ...]
    frontend_coverage_complete: bool
    runtime_reachability_verified: bool
    interpretation: str
    open_obligation: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class PotentialHiddenInterfaceDiagnostic:
    code: str
    message: str


@dataclass(frozen=True)
class PotentialHiddenInterfaceIndex:
    catalog_id: str
    firmware_artifact_sha256: str
    coverage_status: CoverageStatus
    items: Tuple[PotentialHiddenInterface, ...]
    diagnostics: Tuple[PotentialHiddenInterfaceDiagnostic, ...] = ()
    schema_version: str = POTENTIAL_HIDDEN_INTERFACE_INDEX_SCHEMA_VERSION

    def __post_init__(self) -> None:
        _validate_index(self)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "catalog_id": self.catalog_id,
            "firmware_artifact_sha256": self.firmware_artifact_sha256,
            "coverage_status": self.coverage_status.value,
            "items": [asdict(item) for item in self.items],
            "diagnostics": [asdict(item) for item in self.diagnostics],
        }


def _validate_index(index: PotentialHiddenInterfaceIndex) -> None:
    if index.schema_version != POTENTIAL_HIDDEN_INTERFACE_INDEX_SCHEMA_VERSION:
        raise ValueError("unsupported potential hidden interface index schema")
    identities = set()
    for item in index.items:
        if item.interface_id in identities:
            raise ValueError("duplicate potential hidden interface identity")
        identities.add(item.interface_id)
        if (
            item.catalog_id != index.catalog_id
            or item.firmware_artifact_sha256 != index.firmware_artifact_sha256
            or not item.operation_token
            or not item.binding_ids
            or not item.handler_identities
            or not item.evidence_ids
            or not item.frontend_coverage_complete
        ):
            raise ValueError("potential hidden interface proof is incomplete")
        if item.runtime_reachability_verified:
            raise ValueError(
                "potential hidden interface cannot verify runtime reachability"
            )
        if (
            tuple(sorted(set(item.binding_ids))) != item.binding_ids
            or tuple(sorted(set(item.handler_identities)))
            != item.handler_identities
            or tuple(sorted(set(item.frontend_coverage_scopes)))
            != item.frontend_coverage_scopes
            or tuple(sorted(set(item.evidence_ids))) != item.evidence_ids
        ):
            raise ValueError("potential hidden interface values must be stable")
    if index.items and index.coverage_status is not CoverageStatus.COMPLETED:
        raise ValueError("incomplete coverage cannot publish hidden interface items")


def _identity(
    catalog_id: str, firmware_artifact_sha256: str, attribution_id: str
) -> str:
    payload = json.dumps(
        (catalog_id, firmware_artifact_sha256, attribution_id),
        separators=(",", ":"),
    ).encode("utf-8")
    return "potential-hidden-interface:" + hashlib.sha256(payload).hexdigest()


def build_potential_hidden_interface_index(
    catalog: DiscoveryCatalog,
) -> PotentialHiddenInterfaceIndex:
    """Project only completed native-registration/frontend-absence proofs."""

    return project_potential_hidden_interface_document(catalog.to_dict())


def project_potential_hidden_interface_document(
    document: dict,
) -> PotentialHiddenInterfaceIndex:
    """Project a validated catalog document for repository backfill and publish."""

    catalog_id = str(document.get("catalog_id", ""))
    firmware_sha256 = str(document.get("firmware_artifact_sha256", ""))
    if not catalog_id or len(firmware_sha256) != 64:
        raise ValueError("potential hidden interface catalog identity is invalid")
    required = {"frontend", "set_difference"}
    by_kind = {
        kind: tuple(
            item for item in document.get("coverage", [])
            if item.get("producer_kind") == kind
        )
        for kind in required
    }
    diagnostics = []
    if document.get("source_inventory_coverage_status") != "completed":
        diagnostics.append(PotentialHiddenInterfaceDiagnostic(
            "source_inventory_coverage_incomplete",
            "source inventory must be completed before frontend absence is meaningful",
        ))
    for kind in ("frontend", "set_difference"):
        entries = by_kind[kind]
        if not entries or any(
            item.get("status") != "completed" for item in entries
        ):
            diagnostics.append(PotentialHiddenInterfaceDiagnostic(
                "{}_coverage_incomplete".format(kind),
                "{} coverage must be completed".format(kind),
            ))
    if diagnostics:
        return PotentialHiddenInterfaceIndex(
            catalog_id,
            firmware_sha256,
            CoverageStatus.PARTIAL,
            (),
            tuple(diagnostics),
        )

    evidence = {
        item["evidence_id"]: item for item in document.get("evidence_atoms", [])
    }
    frontend_scopes = tuple(sorted(
        str(item["scope"]) for item in by_kind["frontend"]
    ))
    items = []
    for candidate in document.get("candidates", []):
        if candidate.get("candidate_kind") != "set_difference_attribution":
            continue
        attributes = dict(candidate.get("attributes", []))
        if (
            attributes.get("difference_side") != DifferenceSide.NATIVE_ONLY.value
            or attributes.get("attribution_kind")
            != DifferenceAttributionKind.NATIVE_REGISTRATION_NO_FRONTEND_REFERENCE.value
        ):
            continue
        proof_ids = tuple(sorted(candidate.get("evidence_ids", [])))
        if not set(proof_ids) <= set(evidence):
            raise ValueError("potential hidden interface references unknown evidence")
        proof = tuple(evidence[evidence_id] for evidence_id in proof_ids)
        route_bindings = {
            item["subject_ref"] for item in proof
            if item.get("capability") == "registers_route"
            and item.get("object_value") == candidate.get("canonical_identity")
        }
        handler_bindings = {
            item["subject_ref"] for item in proof
            if item.get("capability") == "binds_handler"
        }
        binding_ids = tuple(sorted(route_bindings & handler_bindings))
        handlers = tuple(sorted({
            item["object_value"] for item in proof
            if item.get("capability") == "binds_handler"
            and item.get("subject_ref") in binding_ids
        }))
        if not binding_ids or not handlers:
            raise ValueError(
                "potential hidden interface attribution lacks native binding"
            )
        paths = tuple(sorted({
            item["source_span"]["artifact_path"] for item in proof
        }))
        if len(paths) != 1:
            raise ValueError(
                "potential hidden interface registrations span multiple artifacts"
            )
        items.append(PotentialHiddenInterface(
            _identity(catalog_id, firmware_sha256, candidate["candidate_id"]),
            catalog_id,
            firmware_sha256,
            candidate["canonical_identity"],
            candidate["candidate_id"],
            paths[0],
            binding_ids,
            handlers,
            frontend_scopes,
            True,
            False,
            attributes.get("interpretation", ""),
            attributes.get("open_obligation", ""),
            proof_ids,
        ))
    return PotentialHiddenInterfaceIndex(
        catalog_id,
        firmware_sha256,
        CoverageStatus.COMPLETED,
        tuple(sorted(items, key=lambda item: item.operation_token)),
    )
