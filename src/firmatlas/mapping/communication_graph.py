"""Deterministic communication-architecture graph projection."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from enum import Enum
import hashlib
import json
from typing import Tuple

from .discovery_catalog import (
    DiscoveryCandidateKind,
    DiscoveryClaimStatus,
    DiscoveryCatalog,
)
from .domain import CoverageStatus


COMMUNICATION_GRAPH_SCHEMA_VERSION = (
    "firmatlas.mapping.communication-architecture-graph/v1alpha1"
)


class CommunicationGraphNodeKind(str, Enum):
    ARTIFACT = "artifact"
    INTERFACE = "interface"
    PARAMETER = "parameter"
    INVOCATION = "invocation"
    FEATURE_GATE = "feature_gate"
    ROUTE_BINDING = "route_binding"
    HANDLER = "handler"
    COMMUNICATION_RELATION = "communication_relation"
    COMPONENT = "component"
    OBLIGATION = "obligation"
    RUNTIME_PRINCIPAL = "runtime_principal"
    BACKEND_BINDING = "backend_binding"
    ACCESS_GRANT = "access_grant"
    RESPONSE_CONTRACT = "response_contract"
    DISPATCH = "dispatch"
    PROTECTION = "protection"
    SERVICE_ASSEMBLY = "service_assembly"
    LITERAL_XREF = "literal_xref"
    FEATURE_PIVOT = "feature_pivot"
    PARAMETER_CLUE = "parameter_clue"
    ASSOCIATION = "association"
    STATE = "state"
    EVIDENCE_CANDIDATE = "evidence_candidate"


class CommunicationGraphEdgeKind(str, Enum):
    DECLARED_IN_ARTIFACT = "declared_in_artifact"
    ACCEPTS_PARAMETER = "accepts_parameter"
    HAS_INVOCATION_STATE = "has_invocation_state"
    GATES = "gates"
    HAS_ROUTE_BINDING = "has_route_binding"
    BINDS_HANDLER = "binds_handler"
    INITIATES_RELATIONSHIP = "initiates_relationship"
    TARGETS_COMPONENT = "targets_component"
    REQUIRES_EVIDENCE = "requires_evidence"
    HAS_BACKEND_BINDING = "has_backend_binding"
    EXECUTED_BY = "executed_by"
    HAS_ACCESS_GRANT = "has_access_grant"
    HAS_RESPONSE_CONTRACT = "has_response_contract"
    DISPATCHED_BY = "dispatched_by"
    PROTECTED_BY = "protected_by"
    ASSEMBLED_BY = "assembled_by"
    HAS_LITERAL_XREF = "has_literal_xref"
    HAS_FEATURE_PIVOT = "has_feature_pivot"
    PIVOTS_TO_ROUTE_BINDING = "pivots_to_route_binding"
    HAS_PARAMETER_CLUE = "has_parameter_clue"
    HAS_NATIVE_ASSOCIATION = "has_native_association"
    ASSOCIATED_WITH = "associated_with"
    SATISFIES_OBLIGATION = "satisfies_obligation"
    CALLS = "calls"
    WRITES_STATE = "writes_state"
    IMPORTS_STATE = "imports_state"


@dataclass(frozen=True)
class CommunicationGraphPolicy:
    max_nodes: int = 100_000
    max_edges: int = 300_000
    focus_canonical_identities: Tuple[str, ...] = ()
    max_hops: int = 2

    def __post_init__(self) -> None:
        if self.max_nodes <= 0 or self.max_edges <= 0 or self.max_hops < 0:
            raise ValueError("communication graph budgets must be positive")
        if len(self.focus_canonical_identities) != len(
            set(self.focus_canonical_identities)
        ):
            raise ValueError("communication graph focus identities must be unique")
        if any(not item.strip() for item in self.focus_canonical_identities):
            raise ValueError("communication graph focus identity must not be blank")


@dataclass(frozen=True)
class CommunicationGraphNode:
    node_id: str
    node_kind: CommunicationGraphNodeKind
    label: str
    status: str
    source_path: str
    evidence_ids: Tuple[str, ...]
    attributes: Tuple[Tuple[str, str], ...] = ()


@dataclass(frozen=True)
class CommunicationGraphEdge:
    edge_id: str
    edge_kind: CommunicationGraphEdgeKind
    source_ref: str
    target_ref: str
    status: str
    origin_ref: str
    evidence_ids: Tuple[str, ...]
    attributes: Tuple[Tuple[str, str], ...] = ()


@dataclass(frozen=True)
class CommunicationGraphCoverage:
    scope: str
    producer_kind: str
    producer: str
    producer_version: str
    status: CoverageStatus
    required: bool
    processed_result_count: int
    diagnostic: str = ""


@dataclass(frozen=True)
class CommunicationGraphViewPreset:
    preset_id: str
    title: str
    node_kinds: Tuple[str, ...]
    edge_kinds: Tuple[str, ...]
    description: str


_VIEW_PRESETS = (
    CommunicationGraphViewPreset(
        "interface_structure",
        "Interface structure",
        (
            "artifact", "interface", "parameter", "invocation",
            "feature_gate", "route_binding", "handler", "obligation",
            "response_contract", "dispatch", "protection",
            "service_assembly", "backend_binding", "runtime_principal",
            "access_grant",
        ),
        (
            "accepts_parameter", "has_invocation_state", "gates",
            "has_route_binding", "binds_handler", "requires_evidence",
            "satisfies_obligation",
            "has_response_contract", "dispatched_by", "protected_by",
            "assembled_by", "has_backend_binding", "executed_by",
            "has_access_grant",
        ),
        "Interfaces, parameters, frontend invocation state, feature gates, "
        "verified route ownership, and remaining evidence obligations.",
    ),
    CommunicationGraphViewPreset(
        "communication_components",
        "Communication components",
        (
            "artifact", "interface", "invocation", "component",
            "communication_relation", "dispatch",
            "route_binding", "handler", "evidence_candidate",
            "service_assembly", "runtime_principal", "backend_binding",
            "feature_pivot", "literal_xref", "association",
        ),
        (
            "has_invocation_state", "dispatched_by",
            "initiates_relationship", "targets_component",
            "has_route_binding", "binds_handler", "assembled_by",
            "has_backend_binding", "executed_by", "has_literal_xref",
            "has_feature_pivot", "pivots_to_route_binding",
            "has_native_association", "associated_with",
            "calls",
        ),
        "Cross-artifact and cross-process communication relationships.",
    ),
    CommunicationGraphViewPreset(
        "parameter_state",
        "Parameter and state",
        (
            "interface", "parameter", "handler", "communication_relation",
            "evidence_candidate", "parameter_clue", "association", "state",
        ),
        (
            "accepts_parameter", "has_parameter_clue",
            "has_native_association", "associated_with",
            "writes_state",
        ),
        "Interface parameters and evidence-backed state or clue candidates.",
    ),
    CommunicationGraphViewPreset(
        "completeness",
        "Completeness and uncertainty",
        tuple(item.value for item in CommunicationGraphNodeKind),
        tuple(
            item.value for item in CommunicationGraphEdgeKind
            if item not in {
                CommunicationGraphEdgeKind.DECLARED_IN_ARTIFACT,
                CommunicationGraphEdgeKind.IMPORTS_STATE,
            }
        ),
        "Observed structure overlaid with coverage and unresolved obligations.",
    ),
)


def _view_presets(catalog: DiscoveryCatalog) -> Tuple[CommunicationGraphViewPreset, ...]:
    has_configuration_import = any(
        item.candidate_kind
        is DiscoveryCandidateKind.NATIVE_CONFIGURATION_TEXT_IMPORT_FLOW
        or item.candidate_kind
        is DiscoveryCandidateKind.NATIVE_CONFIGURATION_URL_DOCUMENT_FLOW
        for item in catalog.candidates
    )
    if not has_configuration_import:
        return _VIEW_PRESETS
    return tuple(
        replace(
            item,
            edge_kinds=(*item.edge_kinds, CommunicationGraphEdgeKind.IMPORTS_STATE.value),
        )
        if item.preset_id in {"parameter_state", "completeness"}
        else item
        for item in _VIEW_PRESETS
    )


@dataclass(frozen=True)
class CommunicationArchitectureGraph:
    graph_id: str
    source_catalog_id: str
    firmware_artifact_sha256: str
    source_catalog_coverage_status: CoverageStatus
    projection_status: CoverageStatus
    nodes: Tuple[CommunicationGraphNode, ...]
    edges: Tuple[CommunicationGraphEdge, ...]
    coverage: Tuple[CommunicationGraphCoverage, ...]
    view_presets: Tuple[CommunicationGraphViewPreset, ...]
    diagnostics: Tuple[str, ...] = ()
    schema_version: str = COMMUNICATION_GRAPH_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != COMMUNICATION_GRAPH_SCHEMA_VERSION:
            raise ValueError("unsupported communication graph schema_version")
        graph_digest = self.graph_id.removeprefix("communication-graph:")
        if (
            not self.graph_id.startswith("communication-graph:")
            or len(graph_digest) != 64
            or any(character not in "0123456789abcdef" for character in graph_digest)
        ):
            raise ValueError("communication graph requires stable graph_id")
        if not self.source_catalog_id.strip():
            raise ValueError("communication graph requires source_catalog_id")
        if (
            len(self.firmware_artifact_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.firmware_artifact_sha256
            )
        ):
            raise ValueError("communication graph requires firmware SHA-256")
        node_ids = {item.node_id for item in self.nodes}
        edge_ids = {item.edge_id for item in self.edges}
        if len(node_ids) != len(self.nodes):
            raise ValueError("duplicate communication graph node identity")
        if len(edge_ids) != len(self.edges):
            raise ValueError("duplicate communication graph edge identity")
        for edge in self.edges:
            if edge.source_ref not in node_ids or edge.target_ref not in node_ids:
                raise ValueError("communication graph edge references unknown graph node")
            if edge.edge_id != _stable_id(
                "communication-edge",
                edge.edge_kind.value,
                edge.source_ref,
                edge.target_ref,
                edge.origin_ref,
            ):
                raise ValueError("communication graph requires stable edge identity")
        for item in (*self.nodes, *self.edges):
            if not item.evidence_ids or len(item.evidence_ids) == len(
                set(item.evidence_ids)
            ):
                continue
            raise ValueError("communication graph evidence references must be unique")
        preset_ids = {item.preset_id for item in self.view_presets}
        if len(preset_ids) != len(self.view_presets):
            raise ValueError("duplicate communication graph view preset")
        known_node_kinds = {item.value for item in CommunicationGraphNodeKind}
        known_edge_kinds = {item.value for item in CommunicationGraphEdgeKind}
        if any(
            not set(preset.node_kinds).issubset(known_node_kinds)
            or not set(preset.edge_kinds).issubset(known_edge_kinds)
            for preset in self.view_presets
        ):
            raise ValueError("communication graph view preset has unknown kind")

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "graph_id": self.graph_id,
            "source_catalog_id": self.source_catalog_id,
            "firmware_artifact_sha256": self.firmware_artifact_sha256,
            "source_catalog_coverage_status": (
                self.source_catalog_coverage_status.value
            ),
            "projection_status": self.projection_status.value,
            "nodes": [
                {**asdict(item), "node_kind": item.node_kind.value}
                for item in self.nodes
            ],
            "edges": [
                {**asdict(item), "edge_kind": item.edge_kind.value}
                for item in self.edges
            ],
            "coverage": [
                {**asdict(item), "status": item.status.value}
                for item in self.coverage
            ],
            "view_presets": [asdict(item) for item in self.view_presets],
            "diagnostics": list(self.diagnostics),
        }

    @classmethod
    def from_dict(cls, value: dict) -> "CommunicationArchitectureGraph":
        try:
            return cls(
                graph_id=str(value["graph_id"]),
                source_catalog_id=str(value["source_catalog_id"]),
                firmware_artifact_sha256=str(
                    value["firmware_artifact_sha256"]
                ),
                source_catalog_coverage_status=CoverageStatus(
                    value["source_catalog_coverage_status"]
                ),
                projection_status=CoverageStatus(value["projection_status"]),
                nodes=tuple(
                    CommunicationGraphNode(
                        node_id=str(item["node_id"]),
                        node_kind=CommunicationGraphNodeKind(
                            item["node_kind"]
                        ),
                        label=str(item["label"]),
                        status=str(item["status"]),
                        source_path=str(item["source_path"]),
                        evidence_ids=tuple(item.get("evidence_ids", ())),
                        attributes=tuple(
                            tuple(pair) for pair in item.get("attributes", ())
                        ),
                    )
                    for item in value["nodes"]
                ),
                edges=tuple(
                    CommunicationGraphEdge(
                        edge_id=str(item["edge_id"]),
                        edge_kind=CommunicationGraphEdgeKind(
                            item["edge_kind"]
                        ),
                        source_ref=str(item["source_ref"]),
                        target_ref=str(item["target_ref"]),
                        status=str(item["status"]),
                        origin_ref=str(item["origin_ref"]),
                        evidence_ids=tuple(item.get("evidence_ids", ())),
                        attributes=tuple(
                            tuple(pair) for pair in item.get("attributes", ())
                        ),
                    )
                    for item in value["edges"]
                ),
                coverage=tuple(
                    CommunicationGraphCoverage(
                        scope=str(item["scope"]),
                        producer_kind=str(item["producer_kind"]),
                        producer=str(item["producer"]),
                        producer_version=str(item["producer_version"]),
                        status=CoverageStatus(item["status"]),
                        required=bool(item["required"]),
                        processed_result_count=int(
                            item["processed_result_count"]
                        ),
                        diagnostic=str(item.get("diagnostic", "")),
                    )
                    for item in value["coverage"]
                ),
                view_presets=tuple(
                    CommunicationGraphViewPreset(
                        preset_id=str(item["preset_id"]),
                        title=str(item["title"]),
                        node_kinds=tuple(item["node_kinds"]),
                        edge_kinds=tuple(item["edge_kinds"]),
                        description=str(item["description"]),
                    )
                    for item in value["view_presets"]
                ),
                diagnostics=tuple(value.get("diagnostics", ())),
                schema_version=str(value["schema_version"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, ValueError):
                raise
            raise ValueError("invalid communication graph document") from exc


def _stable_id(prefix: str, *values: str) -> str:
    encoded = json.dumps(values, separators=(",", ":")).encode("utf-8")
    return "{}:{}".format(prefix, hashlib.sha256(encoded).hexdigest())


def _artifact_id(path: str) -> str:
    return _stable_id("communication-artifact", path)


def _edge(
    kind: CommunicationGraphEdgeKind,
    source_ref: str,
    target_ref: str,
    status: str,
    origin_ref: str,
    evidence_ids: tuple,
    basis: str,
) -> CommunicationGraphEdge:
    return CommunicationGraphEdge(
        _stable_id(
            "communication-edge",
            kind.value,
            source_ref,
            target_ref,
            origin_ref,
        ),
        kind,
        source_ref,
        target_ref,
        status,
        origin_ref,
        tuple(dict.fromkeys(evidence_ids)),
        (("projection_basis", basis),),
    )


def _candidate_node_kind(kind: DiscoveryCandidateKind) -> CommunicationGraphNodeKind:
    return {
        DiscoveryCandidateKind.REQUEST_INTERFACE:
            CommunicationGraphNodeKind.INTERFACE,
        DiscoveryCandidateKind.FRONTEND_INVOCATION:
            CommunicationGraphNodeKind.INVOCATION,
        DiscoveryCandidateKind.FRONTEND_FEATURE_GATE:
            CommunicationGraphNodeKind.FEATURE_GATE,
        DiscoveryCandidateKind.NATIVE_ROUTE_BINDING:
            CommunicationGraphNodeKind.ROUTE_BINDING,
        DiscoveryCandidateKind.NATIVE_HANDLER:
            CommunicationGraphNodeKind.HANDLER,
        DiscoveryCandidateKind.NATIVE_RELATIONSHIP:
            CommunicationGraphNodeKind.COMMUNICATION_RELATION,
        DiscoveryCandidateKind.RUNTIME_PRINCIPAL:
            CommunicationGraphNodeKind.RUNTIME_PRINCIPAL,
        DiscoveryCandidateKind.UBUS_BACKEND_BINDING:
            CommunicationGraphNodeKind.BACKEND_BINDING,
        DiscoveryCandidateKind.UBUS_ACCESS_GRANT:
            CommunicationGraphNodeKind.ACCESS_GRANT,
        DiscoveryCandidateKind.RESPONSE_FIXTURE_CONTRACT:
            CommunicationGraphNodeKind.RESPONSE_CONTRACT,
        DiscoveryCandidateKind.NATIVE_NESTED_DISPATCH:
            CommunicationGraphNodeKind.DISPATCH,
        DiscoveryCandidateKind.NATIVE_CGI_DISPATCH:
            CommunicationGraphNodeKind.DISPATCH,
        DiscoveryCandidateKind.NATIVE_CROSS_ELF_CALL:
            CommunicationGraphNodeKind.COMMUNICATION_RELATION,
        DiscoveryCandidateKind.NATIVE_CONFIGURATION_BLOB_FLOW:
            CommunicationGraphNodeKind.COMMUNICATION_RELATION,
        DiscoveryCandidateKind.NATIVE_CONFIGURATION_TEXT_IMPORT_FLOW:
            CommunicationGraphNodeKind.COMMUNICATION_RELATION,
        DiscoveryCandidateKind.NATIVE_CONFIGURATION_URL_DOCUMENT_FLOW:
            CommunicationGraphNodeKind.COMMUNICATION_RELATION,
        DiscoveryCandidateKind.NATIVE_REQUEST_PROTECTION:
            CommunicationGraphNodeKind.PROTECTION,
        DiscoveryCandidateKind.NATIVE_SERVICE_ASSEMBLY:
            CommunicationGraphNodeKind.SERVICE_ASSEMBLY,
        DiscoveryCandidateKind.ARM_LITERAL_XREF:
            CommunicationGraphNodeKind.LITERAL_XREF,
        DiscoveryCandidateKind.ARM_FEATURE_PIVOT:
            CommunicationGraphNodeKind.FEATURE_PIVOT,
        DiscoveryCandidateKind.PARAMETER_CLUE_ASSESSMENT:
            CommunicationGraphNodeKind.PARAMETER_CLUE,
        DiscoveryCandidateKind.CANDIDATE_ASSOCIATION:
            CommunicationGraphNodeKind.ASSOCIATION,
    }.get(kind, CommunicationGraphNodeKind.EVIDENCE_CANDIDATE)


def project_communication_architecture_graph(
    catalog: DiscoveryCatalog,
    policy: CommunicationGraphPolicy = CommunicationGraphPolicy(),
) -> CommunicationArchitectureGraph:
    """Project one immutable Discovery Catalog into a graph read model."""

    evidence = {item.evidence_id: item for item in catalog.evidence_atoms}
    nodes = []
    edges = []
    artifact_paths = {item.source_path for item in catalog.candidates}
    for candidate in catalog.candidates:
        if candidate.candidate_kind is DiscoveryCandidateKind.NATIVE_RELATIONSHIP:
            artifact_paths.update(json.loads(
                dict(candidate.attributes).get("target_artifact_paths", "[]")
            ))
    parameter_source_paths = {}
    for parameter in catalog.parameters:
        source_paths = {
            evidence[evidence_id].source_span.artifact_path
            for evidence_id in parameter.evidence_ids
            if evidence_id in evidence
        }
        if len(source_paths) == 1:
            parameter_source_paths[parameter.parameter_id] = next(iter(source_paths))
            artifact_paths.update(source_paths)
    for path in sorted(artifact_paths):
        nodes.append(CommunicationGraphNode(
            _artifact_id(path),
            CommunicationGraphNodeKind.ARTIFACT,
            path.rsplit("/", 1)[-1],
            "observed",
            path,
            (),
            (("artifact_path", path),),
        ))
    for candidate in catalog.candidates:
        attributes = tuple(sorted((
            *candidate.attributes,
            ("candidate_kind", candidate.candidate_kind.value),
            ("canonical_identity", candidate.canonical_identity),
        )))
        nodes.append(CommunicationGraphNode(
            candidate.candidate_id,
            _candidate_node_kind(candidate.candidate_kind),
            candidate.canonical_identity,
            candidate.claim_status.value,
            candidate.source_path,
            candidate.evidence_ids,
            attributes,
        ))
        edges.append(_edge(
            CommunicationGraphEdgeKind.DECLARED_IN_ARTIFACT,
            _artifact_id(candidate.source_path),
            candidate.candidate_id,
            candidate.claim_status.value,
            candidate.candidate_id,
            candidate.evidence_ids,
            "candidate.source_path",
        ))
    for parameter in catalog.parameters:
        source_path = parameter_source_paths.get(parameter.parameter_id, "")
        nodes.append(CommunicationGraphNode(
            parameter.parameter_id,
            CommunicationGraphNodeKind.PARAMETER,
            parameter.name,
            "observed",
            source_path,
            parameter.evidence_ids,
            tuple(sorted((
                ("namespace", parameter.namespace),
                ("owner_ref", parameter.owner_ref),
                ("is_operation_selector", str(
                    parameter.is_operation_selector
                ).lower()),
            ))),
        ))
        edges.append(_edge(
            CommunicationGraphEdgeKind.ACCEPTS_PARAMETER,
            parameter.owner_ref,
            parameter.parameter_id,
            "observed",
            parameter.parameter_id,
            parameter.evidence_ids,
            "parameter.owner_ref",
        ))
        if source_path:
            edges.append(_edge(
                CommunicationGraphEdgeKind.DECLARED_IN_ARTIFACT,
                _artifact_id(source_path),
                parameter.parameter_id,
                "observed",
                parameter.parameter_id,
                parameter.evidence_ids,
                "parameter.evidence.source_span.artifact_path",
            ))
    for candidate in catalog.candidates:
        if candidate.candidate_kind is not DiscoveryCandidateKind.FRONTEND_INVOCATION:
            continue
        attributes = dict(candidate.attributes)
        edges.append(_edge(
            CommunicationGraphEdgeKind.HAS_INVOCATION_STATE,
            attributes["request_candidate_ref"],
            candidate.candidate_id,
            candidate.claim_status.value,
            candidate.candidate_id,
            candidate.evidence_ids,
            "frontend_invocation.request_candidate_ref",
        ))
    route_bindings = {}
    candidate_by_id = {
        item.candidate_id: item for item in catalog.candidates
    }
    requests_by_operation = {}
    for candidate in catalog.candidates:
        if candidate.candidate_kind is DiscoveryCandidateKind.REQUEST_INTERFACE:
            operation = (
                candidate.canonical_identity.split("?", 1)[0]
                .rstrip("/").rsplit("/", 1)[-1]
            )
            requests_by_operation.setdefault(operation, []).append(
                candidate.candidate_id
            )
    route_binding_request_refs = {}
    for candidate in catalog.candidates:
        attributes = dict(candidate.attributes)
        if candidate.candidate_kind is DiscoveryCandidateKind.FRONTEND_FEATURE_GATE:
            for request_ref in json.loads(
                attributes.get("request_candidate_refs", "[]")
            ):
                edges.append(_edge(
                    CommunicationGraphEdgeKind.GATES,
                    candidate.candidate_id,
                    request_ref,
                    candidate.claim_status.value,
                    candidate.candidate_id,
                    candidate.evidence_ids,
                    "frontend_feature_gate.request_candidate_refs",
                ))
        elif candidate.candidate_kind is DiscoveryCandidateKind.NATIVE_ROUTE_BINDING:
            request_refs = set(json.loads(
                attributes.get("request_candidate_refs", "[]")
            ))
            if attributes.get("target_ref", "").startswith("native-registrar:"):
                request_refs.update(requests_by_operation.get(
                    candidate.canonical_identity, ()
                ))
            route_binding_request_refs[candidate.candidate_id] = tuple(
                sorted(request_refs)
            )
            for request_ref in sorted(request_refs):
                request_evidence_ids = candidate_by_id[request_ref].evidence_ids
                edges.append(_edge(
                    CommunicationGraphEdgeKind.HAS_ROUTE_BINDING,
                    request_ref,
                    candidate.candidate_id,
                    candidate.claim_status.value,
                    candidate.candidate_id,
                    tuple(dict.fromkeys((
                        *request_evidence_ids, *candidate.evidence_ids,
                    ))),
                    (
                        "native_route_binding.request_candidate_refs"
                        if "request_candidate_refs" in attributes
                        else "projection.exact_endpoint_operation"
                    ),
                ))
            target_ref = attributes.get("target_ref")
            if target_ref:
                edges.append(_edge(
                    CommunicationGraphEdgeKind.HAS_ROUTE_BINDING,
                    target_ref,
                    candidate.candidate_id,
                    candidate.claim_status.value,
                    candidate.candidate_id,
                    candidate.evidence_ids,
                    "native_route_binding.target_ref",
                ))
            key = (
                candidate.source_path,
                target_ref,
                attributes.get("registration_address"),
                candidate.canonical_identity,
                attributes.get("handler_identity"),
            )
            route_bindings.setdefault(key, []).append(candidate)
    for candidate in catalog.candidates:
        if candidate.candidate_kind is not DiscoveryCandidateKind.NATIVE_HANDLER:
            continue
        attributes = dict(candidate.attributes)
        key = (
            candidate.source_path,
            attributes.get("target_ref"),
            attributes.get("registration_address"),
            attributes.get("route_token"),
            candidate.canonical_identity,
        )
        matching = route_bindings.get(key, ())
        if len(matching) == 1:
            binding = matching[0]
            edges.append(_edge(
                CommunicationGraphEdgeKind.BINDS_HANDLER,
                binding.candidate_id,
                candidate.candidate_id,
                candidate.claim_status.value,
                candidate.candidate_id,
                (*binding.evidence_ids, *candidate.evidence_ids),
                "exact source+target+registration+route+handler identity",
            ))
    for candidate in catalog.candidates:
        attributes = dict(candidate.attributes)
        if candidate.candidate_kind is DiscoveryCandidateKind.UBUS_BACKEND_BINDING:
            edges.append(_edge(
                CommunicationGraphEdgeKind.HAS_BACKEND_BINDING,
                attributes["target_ref"],
                candidate.candidate_id,
                candidate.claim_status.value,
                candidate.candidate_id,
                candidate.evidence_ids,
                "ubus_backend_binding.target_ref",
            ))
            edges.append(_edge(
                CommunicationGraphEdgeKind.EXECUTED_BY,
                candidate.candidate_id,
                attributes["principal_id"],
                candidate.claim_status.value,
                candidate.candidate_id,
                candidate.evidence_ids,
                "ubus_backend_binding.principal_id",
            ))
        elif candidate.candidate_kind is DiscoveryCandidateKind.UBUS_ACCESS_GRANT:
            edges.append(_edge(
                CommunicationGraphEdgeKind.HAS_ACCESS_GRANT,
                attributes["target_ref"],
                candidate.candidate_id,
                candidate.claim_status.value,
                candidate.candidate_id,
                candidate.evidence_ids,
                "ubus_access_grant.target_ref",
            ))
        elif (
            candidate.candidate_kind
            is DiscoveryCandidateKind.RESPONSE_FIXTURE_CONTRACT
        ):
            for request_ref in json.loads(
                attributes.get("frontend_request_refs", "[]")
            ):
                edges.append(_edge(
                    CommunicationGraphEdgeKind.HAS_RESPONSE_CONTRACT,
                    request_ref,
                    candidate.candidate_id,
                    candidate.claim_status.value,
                    candidate.candidate_id,
                    candidate.evidence_ids,
                    "response_fixture.frontend_request_refs",
                ))
        elif candidate.candidate_kind is DiscoveryCandidateKind.NATIVE_CGI_DISPATCH:
            edges.append(_edge(
                CommunicationGraphEdgeKind.BINDS_HANDLER,
                candidate.candidate_id,
                attributes["handler_ref"],
                candidate.claim_status.value,
                candidate.candidate_id,
                candidate.evidence_ids,
                "native_cgi_dispatch.handler_ref",
            ))
    target_ref_edges = {
        DiscoveryCandidateKind.NATIVE_NESTED_DISPATCH: (
            CommunicationGraphEdgeKind.DISPATCHED_BY,
            "native_nested_dispatch.target_ref",
        ),
        DiscoveryCandidateKind.NATIVE_CGI_DISPATCH: (
            CommunicationGraphEdgeKind.DISPATCHED_BY,
            "native_cgi_dispatch.target_ref",
        ),
        DiscoveryCandidateKind.NATIVE_REQUEST_PROTECTION: (
            CommunicationGraphEdgeKind.PROTECTED_BY,
            "native_request_protection.target_ref",
        ),
        DiscoveryCandidateKind.NATIVE_SERVICE_ASSEMBLY: (
            CommunicationGraphEdgeKind.ASSEMBLED_BY,
            "native_service_assembly.target_ref",
        ),
        DiscoveryCandidateKind.ARM_LITERAL_XREF: (
            CommunicationGraphEdgeKind.HAS_LITERAL_XREF,
            "arm_literal_xref.target_ref",
        ),
        DiscoveryCandidateKind.ARM_FEATURE_PIVOT: (
            CommunicationGraphEdgeKind.HAS_FEATURE_PIVOT,
            "arm_feature_pivot.target_ref",
        ),
    }
    for candidate in catalog.candidates:
        relation = target_ref_edges.get(candidate.candidate_kind)
        if relation is None:
            continue
        edge_kind, basis = relation
        attributes = dict(candidate.attributes)
        edges.append(_edge(
            edge_kind,
            attributes["target_ref"],
            candidate.candidate_id,
            candidate.claim_status.value,
            candidate.candidate_id,
            candidate.evidence_ids,
            basis,
        ))
        if candidate.candidate_kind is DiscoveryCandidateKind.ARM_FEATURE_PIVOT:
            edges.append(_edge(
                CommunicationGraphEdgeKind.PIVOTS_TO_ROUTE_BINDING,
                candidate.candidate_id,
                attributes["route_binding_ref"],
                candidate.claim_status.value,
                candidate.candidate_id,
                candidate.evidence_ids,
                "arm_feature_pivot.route_binding_ref",
            ))
    for candidate in catalog.candidates:
        if (
            candidate.candidate_kind
            is DiscoveryCandidateKind.PARAMETER_CLUE_ASSESSMENT
        ):
            edges.append(_edge(
                CommunicationGraphEdgeKind.HAS_PARAMETER_CLUE,
                dict(candidate.attributes)["target_ref"],
                candidate.candidate_id,
                candidate.claim_status.value,
                candidate.candidate_id,
                candidate.evidence_ids,
                "parameter_clue_assessment.target_ref",
            ))
    for candidate in catalog.candidates:
        if candidate.candidate_kind is not DiscoveryCandidateKind.NATIVE_CROSS_ELF_CALL:
            continue
        attributes = dict(candidate.attributes)
        source_function_identity = attributes["source_function_identity"]
        parent_calls = tuple(
            item for item in catalog.candidates
            if (
                item.candidate_kind is DiscoveryCandidateKind.NATIVE_CROSS_ELF_CALL
                and dict(item.attributes)["target_function_identity"]
                == source_function_identity
            )
        )
        for parent in parent_calls:
            edges.append(_edge(
                CommunicationGraphEdgeKind.CALLS,
                parent.candidate_id,
                candidate.candidate_id,
                candidate.claim_status.value,
                candidate.candidate_id,
                tuple(dict.fromkeys((*parent.evidence_ids, *candidate.evidence_ids))),
                "native_cross_elf_call.function_chain",
            ))
        for origin_ref in json.loads(attributes["origin_refs"]):
            if origin_ref not in candidate_by_id:
                continue
            origin_attributes = dict(candidate_by_id[origin_ref].attributes)
            if (
                origin_attributes.get("handler_identity")
                != source_function_identity
            ):
                continue
            edges.append(_edge(
                CommunicationGraphEdgeKind.CALLS,
                origin_ref,
                candidate.candidate_id,
                candidate.claim_status.value,
                candidate.candidate_id,
                candidate.evidence_ids,
                "native_cross_elf_call.origin_refs",
            ))
        argument_literals = set(json.loads(attributes["argument_literals"]))
        for binding in catalog.candidates:
            if binding.candidate_kind is not DiscoveryCandidateKind.NATIVE_COMMAND_BINDING:
                continue
            command = dict(binding.attributes).get("command", "")
            if command and any(
                literal.split()[-1:] == [command]
                for literal in argument_literals
            ):
                edges.append(_edge(
                    CommunicationGraphEdgeKind.CALLS,
                    candidate.candidate_id,
                    binding.candidate_id,
                    "supported",
                    candidate.candidate_id,
                    tuple(dict.fromkeys((
                        *candidate.evidence_ids, *binding.evidence_ids,
                    ))),
                    "native_cross_elf_call.argument_to_command_binding",
                ))
    state_specs = {}
    for candidate in catalog.candidates:
        if (
            candidate.candidate_kind
            is not DiscoveryCandidateKind.NATIVE_CONFIGURATION_BLOB_FLOW
        ):
            continue
        attributes = dict(candidate.attributes)
        state_scope = attributes["state_scope"]
        state_ref = _stable_id("configuration-state", state_scope)
        state_specs[state_ref] = (
            state_scope,
            attributes.get("write_granularity", ""),
            candidate.evidence_ids,
        )
        edges.append(_edge(
            CommunicationGraphEdgeKind.WRITES_STATE,
            candidate.candidate_id,
            state_ref,
            candidate.claim_status.value,
            candidate.candidate_id,
            candidate.evidence_ids,
            "native_configuration_blob_flow.state_scope",
        ))
    for candidate in catalog.candidates:
        if (
            candidate.candidate_kind
            is not DiscoveryCandidateKind.NATIVE_CONFIGURATION_TEXT_IMPORT_FLOW
        ):
            continue
        attributes = dict(candidate.attributes)
        declared_keys = json.loads(attributes["declared_keys"])
        key_evidence_pairs = json.loads(attributes["key_evidence"])
        evidence_by_key = {}
        for key, evidence_id in key_evidence_pairs:
            evidence_by_key.setdefault(key, []).append(evidence_id)
        for key in sorted(set(declared_keys)):
            state_ref = _stable_id("configuration-state", key)
            evidence_ids = tuple(evidence_by_key.get(key, ()))
            state_specs[state_ref] = (
                key,
                "key_value_entry",
                evidence_ids,
            )
            edges.append(_edge(
                CommunicationGraphEdgeKind.IMPORTS_STATE,
                candidate.candidate_id,
                state_ref,
                candidate.claim_status.value,
                candidate.candidate_id,
                tuple(dict.fromkeys((*candidate.evidence_ids, *evidence_ids))),
                "native_configuration_text_import_flow.declared_keys",
            ))
    for candidate in catalog.candidates:
        if (
            candidate.candidate_kind
            is not DiscoveryCandidateKind.NATIVE_CONFIGURATION_URL_DOCUMENT_FLOW
        ):
            continue
        attributes = dict(candidate.attributes)
        state_scope = attributes["state_scope"]
        state_ref = _stable_id("configuration-state", state_scope)
        state_specs[state_ref] = (
            state_scope,
            attributes.get("write_granularity", ""),
            candidate.evidence_ids,
        )
        edges.append(_edge(
            CommunicationGraphEdgeKind.IMPORTS_STATE,
            candidate.candidate_id,
            state_ref,
            candidate.claim_status.value,
            candidate.candidate_id,
            candidate.evidence_ids,
            "native_configuration_url_document_flow.state_scope",
        ))
    nodes.extend(
        CommunicationGraphNode(
            state_ref,
            CommunicationGraphNodeKind.STATE,
            state_scope,
            "supported",
            "",
            evidence_ids,
            (("write_granularity", granularity),),
        )
        for state_ref, (state_scope, granularity, evidence_ids)
        in sorted(state_specs.items())
    )
    for association in catalog.associations:
        edges.append(_edge(
            CommunicationGraphEdgeKind.HAS_NATIVE_ASSOCIATION,
            association.frontend_candidate_id,
            association.association_id,
            "candidate",
            association.association_id,
            association.evidence_ids,
            "catalog.association.frontend_candidate_id",
        ))
        edges.append(_edge(
            CommunicationGraphEdgeKind.ASSOCIATED_WITH,
            association.association_id,
            association.native_hint_id,
            "candidate",
            association.association_id,
            association.evidence_ids,
            "catalog.association.native_hint_id",
        ))
    component_specs = {}
    for candidate in catalog.candidates:
        if candidate.candidate_kind is not DiscoveryCandidateKind.NATIVE_RELATIONSHIP:
            continue
        attributes = dict(candidate.attributes)
        edges.append(_edge(
            CommunicationGraphEdgeKind.INITIATES_RELATIONSHIP,
            _artifact_id(candidate.source_path),
            candidate.candidate_id,
            candidate.claim_status.value,
            candidate.candidate_id,
            candidate.evidence_ids,
            "native_relationship.source_component",
        ))
        target_paths = json.loads(attributes.get("target_artifact_paths", "[]"))
        if target_paths:
            target_refs = tuple(_artifact_id(path) for path in target_paths)
        else:
            target_component = attributes["target_component"]
            target_ref = _stable_id(
                "communication-component", target_component
            )
            resolution_status = attributes.get(
                "target_resolution_status", "unresolved"
            )
            existing = component_specs.get(target_ref)
            if existing is None:
                component_specs[target_ref] = (
                    target_component,
                    resolution_status,
                    list(candidate.evidence_ids),
                )
            else:
                if existing[:2] != (target_component, resolution_status):
                    raise ValueError(
                        "conflicting communication component projection"
                    )
                existing[2].extend(candidate.evidence_ids)
            target_refs = (target_ref,)
        for target_ref in target_refs:
            edges.append(_edge(
                CommunicationGraphEdgeKind.TARGETS_COMPONENT,
                candidate.candidate_id,
                target_ref,
                candidate.claim_status.value,
                candidate.candidate_id,
                candidate.evidence_ids,
                "native_relationship.target_artifact_paths",
            ))
    nodes.extend(
        CommunicationGraphNode(
            target_ref,
            CommunicationGraphNodeKind.COMPONENT,
            label,
            "unresolved",
            "",
            tuple(dict.fromkeys(evidence_ids)),
            (("resolution_status", resolution_status),),
        )
        for target_ref, (label, resolution_status, evidence_ids)
        in sorted(component_specs.items())
    )
    node_source_paths = {item.node_id: item.source_path for item in nodes}
    satisfied_by_target = {}
    for binding_ref, request_refs in route_binding_request_refs.items():
        if (
            candidate_by_id[binding_ref].claim_status
            is not DiscoveryClaimStatus.SUPPORTED
        ):
            continue
        for request_ref in request_refs:
            satisfied_by_target.setdefault(request_ref, set()).add(binding_ref)
            for association in catalog.associations:
                if association.frontend_candidate_id == request_ref:
                    satisfied_by_target.setdefault(
                        association.association_id, set()
                    ).add(binding_ref)
    for obligation in catalog.open_obligations:
        satisfying_bindings = tuple(sorted(
            satisfied_by_target.get(obligation.target_ref, ())
            if obligation.required_capability
            in {"registers_route", "binds_handler"}
            else ()
        ))
        projection_status = (
            "satisfied_in_projection" if satisfying_bindings
            else obligation.status.value
        )
        nodes.append(CommunicationGraphNode(
            obligation.obligation_id,
            CommunicationGraphNodeKind.OBLIGATION,
            obligation.required_capability,
            projection_status,
            node_source_paths.get(obligation.target_ref, ""),
            (),
            tuple(sorted((
                ("target_ref", obligation.target_ref),
                ("reason", obligation.reason),
                ("priority", str(obligation.priority)),
                ("candidate_analyzers", json.dumps(
                    obligation.candidate_analyzers, separators=(",", ":")
                )),
                ("catalog_status", obligation.status.value),
                ("projection_status", projection_status),
            ))),
        ))
        if satisfying_bindings:
            for binding_ref in satisfying_bindings:
                binding = candidate_by_id[binding_ref]
                edges.append(_edge(
                    CommunicationGraphEdgeKind.SATISFIES_OBLIGATION,
                    binding_ref,
                    obligation.obligation_id,
                    "supported",
                    binding_ref,
                    binding.evidence_ids,
                    "projection.exact_supported_route_binding",
                ))
        else:
            edges.append(_edge(
                CommunicationGraphEdgeKind.REQUIRES_EVIDENCE,
                obligation.target_ref,
                obligation.obligation_id,
                obligation.status.value,
                obligation.obligation_id,
                (),
                "scheduler_obligation.target_ref",
            ))
    node_ids = {item.node_id for item in nodes}
    catalog_evidence_ids = set(evidence)
    if len(node_ids) != len(nodes):
        raise ValueError("communication graph contains duplicate node identity")
    diagnostics = []
    unresolved_references = []
    resolved_edges = []
    for edge in edges:
        missing_refs = tuple(
            ref for ref in (edge.source_ref, edge.target_ref)
            if ref not in node_ids
        )
        if missing_refs:
            unresolved_references.extend(
                (edge.origin_ref, ref, edge.source_ref, edge.target_ref)
                for ref in missing_refs
            )
        else:
            resolved_edges.append(edge)
    edges = resolved_edges
    if any(
        evidence_id not in catalog_evidence_ids
        for item in (*nodes, *edges)
        for evidence_id in item.evidence_ids
    ):
        raise ValueError("communication graph references unknown evidence")
    distances = {}
    if policy.focus_canonical_identities:
        candidates_by_identity = {}
        for candidate in catalog.candidates:
            candidates_by_identity.setdefault(
                candidate.canonical_identity, []
            ).append(candidate.candidate_id)
        seeds = set()
        for identity in policy.focus_canonical_identities:
            matching = candidates_by_identity.get(identity, ())
            if not matching:
                diagnostics.append(
                    "communication_graph.focus_identity_not_found:{}".format(
                        identity
                    )
                )
            seeds.update(matching)
        distances.update((node_id, 0) for node_id in seeds)
        semantic_edges = tuple(
            item for item in edges
            if item.edge_kind is not CommunicationGraphEdgeKind.DECLARED_IN_ARTIFACT
        )
        frontier = set(seeds)
        for distance in range(1, policy.max_hops + 1):
            reached = set()
            for edge in semantic_edges:
                if edge.source_ref in frontier and edge.target_ref not in distances:
                    reached.add(edge.target_ref)
                if edge.target_ref in frontier and edge.source_ref not in distances:
                    reached.add(edge.source_ref)
            if not reached:
                break
            distances.update((node_id, distance) for node_id in reached)
            frontier = reached
        semantic_node_ids = set(distances)
        declared_edges = tuple(
            item for item in edges
            if (
                item.edge_kind is CommunicationGraphEdgeKind.DECLARED_IN_ARTIFACT
                and item.target_ref in semantic_node_ids
            )
        )
        selected_ids = semantic_node_ids | {
            item.source_ref for item in declared_edges
        }
        for artifact_id in selected_ids - semantic_node_ids:
            distances[artifact_id] = policy.max_hops + 1
    else:
        selected_ids = node_ids
        distances.update((node_id, 0) for node_id in node_ids)
    ordered_nodes = tuple(sorted(
        (item for item in nodes if item.node_id in selected_ids),
        key=lambda item: (distances[item.node_id], item.node_id),
    ))
    selected_nodes = ordered_nodes[:policy.max_nodes]
    selected_node_ids = {item.node_id for item in selected_nodes}
    eligible_edges = tuple(sorted(
        (
            item for item in edges
            if item.source_ref in selected_node_ids
            and item.target_ref in selected_node_ids
        ),
        key=lambda item: item.edge_id,
    ))
    selected_edges = eligible_edges[:policy.max_edges]
    diagnostics.extend(
        "communication_graph.unresolved_reference:{}:{}".format(origin, ref)
        for origin, ref, source_ref, target_ref in unresolved_references
        if (
            not policy.focus_canonical_identities
            or origin in selected_node_ids
            or source_ref in selected_node_ids
            or target_ref in selected_node_ids
        )
    )
    projection_status = CoverageStatus.COMPLETED
    if diagnostics:
        projection_status = CoverageStatus.PARTIAL
    if (
        len(ordered_nodes) > policy.max_nodes
        or len(eligible_edges) > policy.max_edges
    ):
        projection_status = CoverageStatus.PARTIAL
        diagnostics.append("communication_graph.projection_budget_exceeded")
    diagnostics = sorted(dict.fromkeys(diagnostics))
    graph_coverage = tuple(
        CommunicationGraphCoverage(
            item.scope,
            item.producer_kind.value,
            item.producer,
            item.producer_version,
            item.status,
            item.required,
            item.processed_result_count,
            item.diagnostic or "",
        )
        for item in catalog.coverage
    )
    view_presets = _view_presets(catalog)
    identity = {
        "schema_version": COMMUNICATION_GRAPH_SCHEMA_VERSION,
        "source_catalog_id": catalog.catalog_id,
        "policy": asdict(policy),
        "projection_status": projection_status.value,
        "nodes": [asdict(item) for item in selected_nodes],
        "edges": [asdict(item) for item in selected_edges],
        "coverage": [asdict(item) for item in graph_coverage],
        "view_presets": [asdict(item) for item in view_presets],
        "diagnostics": diagnostics,
    }
    graph_id = "communication-graph:{}".format(hashlib.sha256(
        json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
            default=lambda item: item.value,
        ).encode("utf-8")
    ).hexdigest())
    return CommunicationArchitectureGraph(
        graph_id,
        catalog.catalog_id,
        catalog.firmware_artifact_sha256,
        catalog.coverage_status,
        projection_status,
        selected_nodes,
        selected_edges,
        graph_coverage,
        view_presets,
        tuple(diagnostics),
    )
