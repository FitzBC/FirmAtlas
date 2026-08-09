"""Publish a stable, evidence-backed cold-start discovery catalog."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Optional, Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom
from .frontend import FrontendProducerResult
from .parameter_clue import FrontendParameterClueIndex
from .response_fixture import ResponseFixtureResult
from .web_config import WebConfigProducerResult
from .script_backend import ScriptBackendProducerResult
from .native import NativeProducerResult
from .native_deep import NativeDeepResult
from .native_value_flow import MipsHandlerValueFlowResult
from .native_nested_dispatch import MipsNestedDispatchResult
from .native_request_protection import MipsRequestProtectionResult
from .native_service_assembly import MipsServiceAssemblyResult
from .ubus_backend import UbusBackendBindingStatus, UbusBackendGraphResult
from .set_difference import SetDifferenceAttributionResult
from .correlation import FrontendNativeCorrelationResult
from .scheduler import (
    ObligationSchedulerResult,
    SchedulerObligation,
    SchedulerTermination,
    normalize_scheduler_obligations,
)


DISCOVERY_CATALOG_SCHEMA_VERSION = "firmatlas.mapping.discovery-catalog/v1alpha1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class DiscoveryProducerKind(str, Enum):
    FRONTEND = "frontend"
    WEB_CONFIGURATION = "web_configuration"
    SCRIPT_BACKEND = "script_backend"
    NATIVE = "native"
    NATIVE_DEEP = "native_deep"
    NATIVE_VALUE_FLOW = "native_value_flow"
    NATIVE_NESTED_DISPATCH = "native_nested_dispatch"
    NATIVE_REQUEST_PROTECTION = "native_request_protection"
    NATIVE_SERVICE_ASSEMBLY = "native_service_assembly"
    SET_DIFFERENCE = "set_difference"
    CORRELATION = "correlation"
    SCHEDULER = "scheduler"
    UBUS_BACKEND = "ubus_backend"
    PARAMETER_CLUE = "parameter_clue"
    RESPONSE_FIXTURE = "response_fixture"


class DiscoveryCandidateKind(str, Enum):
    REQUEST_INTERFACE = "request_interface"
    WEB_CONFIGURATION = "web_configuration"
    SCRIPT_SOURCE = "script_source"
    SCRIPT_ROUTE = "script_route"
    CGI_PROGRAM = "cgi_program"
    STATE_ACCESS = "state_access"
    TEMPLATE_READ = "template_read"
    NATIVE_HINT = "native_hint"
    NATIVE_ROUTE_BINDING = "native_route_binding"
    NATIVE_REGISTRAR = "native_registrar"
    NATIVE_HANDLER = "native_handler"
    NATIVE_PARAMETER_STATE_FLOW = "native_parameter_state_flow"
    NATIVE_NESTED_DISPATCH = "native_nested_dispatch"
    NATIVE_REQUEST_PROTECTION = "native_request_protection"
    NATIVE_SERVICE_ASSEMBLY = "native_service_assembly"
    SET_DIFFERENCE_ATTRIBUTION = "set_difference_attribution"
    CANDIDATE_ASSOCIATION = "candidate_association"
    RUNTIME_PRINCIPAL = "runtime_principal"
    UBUS_BACKEND_BINDING = "ubus_backend_binding"
    UBUS_ACCESS_GRANT = "ubus_access_grant"
    PARAMETER_CLUE_ASSESSMENT = "parameter_clue_assessment"
    RESPONSE_FIXTURE_CONTRACT = "response_fixture_contract"


class DiscoveryClaimStatus(str, Enum):
    CANDIDATE = "candidate"
    SUPPORTED = "supported"


@dataclass(frozen=True)
class DiscoveryProducerBatch:
    producer_kind: DiscoveryProducerKind
    producer: AnalyzerIdentity
    scope: str
    results: tuple
    required: bool = True

    @classmethod
    def frontend(
        cls, results: Tuple[FrontendProducerResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("frontend-request-producer", "0.1.0")
        )
        return cls(DiscoveryProducerKind.FRONTEND, producer, scope, results)

    @classmethod
    def parameter_clue(
        cls, results: Tuple[FrontendParameterClueIndex, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("frontend-parameter-clue", "0.2.0")
        )
        return cls(DiscoveryProducerKind.PARAMETER_CLUE, producer, scope, results)

    @classmethod
    def response_fixture(
        cls, results: Tuple[ResponseFixtureResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("response-fixture-producer", "0.1.0")
        )
        return cls(DiscoveryProducerKind.RESPONSE_FIXTURE, producer, scope, results)

    @classmethod
    def web_configuration(
        cls, results: Tuple[WebConfigProducerResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("web-configuration-producer", "0.1.0")
        )
        return cls(DiscoveryProducerKind.WEB_CONFIGURATION, producer, scope, results)

    @classmethod
    def script_backend(
        cls, results: Tuple[ScriptBackendProducerResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("script-backend-producer", "0.1.0")
        )
        return cls(DiscoveryProducerKind.SCRIPT_BACKEND, producer, scope, results)

    @classmethod
    def native(
        cls, results: Tuple[NativeProducerResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("native-shallow-producer", "0.1.0")
        )
        return cls(DiscoveryProducerKind.NATIVE, producer, scope, results)

    @classmethod
    def native_deep(
        cls, results: Tuple[NativeDeepResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("native-deep-route-table", "0.1.0")
        )
        return cls(DiscoveryProducerKind.NATIVE_DEEP, producer, scope, results)

    @classmethod
    def native_value_flow(
        cls, results: Tuple[MipsHandlerValueFlowResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("native-mips-handler-value-flow", "0.1.0")
        )
        return cls(DiscoveryProducerKind.NATIVE_VALUE_FLOW, producer, scope, results)

    @classmethod
    def native_nested_dispatch(
        cls, results: Tuple[MipsNestedDispatchResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("native-mips-cgi-nested-dispatch", "0.1.0")
        )
        return cls(
            DiscoveryProducerKind.NATIVE_NESTED_DISPATCH,
            producer,
            scope,
            results,
        )

    @classmethod
    def native_request_protection(
        cls, results: Tuple[MipsRequestProtectionResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("native-mips-request-protection", "0.1.0")
        )
        return cls(
            DiscoveryProducerKind.NATIVE_REQUEST_PROTECTION,
            producer,
            scope,
            results,
        )

    @classmethod
    def native_service_assembly(
        cls, results: Tuple[MipsServiceAssemblyResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("native-mips-service-assembly", "0.1.0")
        )
        return cls(
            DiscoveryProducerKind.NATIVE_SERVICE_ASSEMBLY,
            producer,
            scope,
            results,
        )

    @classmethod
    def ubus_backend(
        cls, results: Tuple[UbusBackendGraphResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("ubus-backend-producer", "0.1.0")
        )
        return cls(DiscoveryProducerKind.UBUS_BACKEND, producer, scope, results)

    def __post_init__(self) -> None:
        if not self.scope.strip() or not self.producer.name.strip():
            raise ValueError("producer batch requires scope and producer identity")


@dataclass(frozen=True)
class DiscoveryCatalogInput:
    firmware_artifact_sha256: str
    source_inventory_sha256: str
    batches: Tuple[DiscoveryProducerBatch, ...]
    correlation: Optional[FrontendNativeCorrelationResult] = None
    scheduler: Optional[ObligationSchedulerResult] = None
    set_difference: Optional[SetDifferenceAttributionResult] = None
    source_inventory_coverage_status: CoverageStatus = CoverageStatus.COMPLETED

    def __post_init__(self) -> None:
        if not _SHA256.fullmatch(self.firmware_artifact_sha256):
            raise ValueError("firmware_artifact_sha256 must be a lowercase SHA-256")
        if not _SHA256.fullmatch(self.source_inventory_sha256):
            raise ValueError("source_inventory_sha256 must be a lowercase SHA-256")
        if not isinstance(self.source_inventory_coverage_status, CoverageStatus):
            raise ValueError("source_inventory_coverage_status must be a CoverageStatus")
        identities = tuple((x.producer_kind, x.scope) for x in self.batches)
        if len(identities) != len(set(identities)):
            raise ValueError("duplicate discovery producer batch")


@dataclass(frozen=True)
class DiscoveryCandidate:
    candidate_id: str
    candidate_kind: DiscoveryCandidateKind
    canonical_identity: str
    claim_status: DiscoveryClaimStatus
    source_path: str
    source_construct: str
    evidence_ids: Tuple[str, ...]
    attributes: Tuple[Tuple[str, str], ...] = ()


@dataclass(frozen=True)
class DiscoveryParameter:
    parameter_id: str
    owner_ref: str
    name: str
    namespace: str
    literal_value: Optional[str]
    selector_values: Tuple[str, ...]
    is_operation_selector: bool
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class DiscoveryCoverage:
    scope: str
    producer_kind: DiscoveryProducerKind
    producer: str
    producer_version: str
    status: CoverageStatus
    required: bool
    processed_result_count: int
    diagnostic: Optional[str] = None


@dataclass(frozen=True)
class DiscoveryAssociation:
    association_id: str
    frontend_candidate_id: str
    native_hint_id: str
    match_basis: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class DiscoveryCatalog:
    catalog_id: str
    firmware_artifact_sha256: str
    source_inventory_sha256: str
    coverage_status: CoverageStatus
    source_inventory_coverage_status: CoverageStatus
    candidates: Tuple[DiscoveryCandidate, ...]
    parameters: Tuple[DiscoveryParameter, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    coverage: Tuple[DiscoveryCoverage, ...]
    associations: Tuple[DiscoveryAssociation, ...] = ()
    open_obligations: Tuple[SchedulerObligation, ...] = ()
    scheduler_termination: Optional[SchedulerTermination] = None
    seed_input_count: int = 0
    schema_version: str = DISCOVERY_CATALOG_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "catalog_id": self.catalog_id,
            "firmware_artifact_sha256": self.firmware_artifact_sha256,
            "source_inventory_sha256": self.source_inventory_sha256,
            "coverage_status": self.coverage_status.value,
            "source_inventory_coverage_status": (
                self.source_inventory_coverage_status.value
            ),
            "seed_input_count": self.seed_input_count,
            "candidates": [
                {**asdict(x), "candidate_kind": x.candidate_kind.value,
                 "claim_status": x.claim_status.value}
                for x in self.candidates
            ],
            "parameters": [asdict(x) for x in self.parameters],
            "evidence_atoms": [x.to_dict() for x in self.evidence_atoms],
            "coverage": [
                {**asdict(x), "producer_kind": x.producer_kind.value,
                 "status": x.status.value}
                for x in self.coverage
            ],
            "associations": [asdict(x) for x in self.associations],
            "open_obligations": [
                {**asdict(x), "status": x.status.value}
                for x in self.open_obligations
            ],
            "scheduler_termination": (
                self.scheduler_termination.value if self.scheduler_termination else None
            ),
        }


def _catalog_id(
    value: DiscoveryCatalogInput, candidates: tuple, parameters: tuple,
    evidence_atoms: tuple, coverage: tuple, associations: tuple,
    obligations: tuple, termination: Optional[SchedulerTermination],
) -> str:
    payload = {
        "schema_version": DISCOVERY_CATALOG_SCHEMA_VERSION,
        "firmware": value.firmware_artifact_sha256,
        "inventory": value.source_inventory_sha256,
        "inventory_coverage": value.source_inventory_coverage_status.value,
        "candidates": [asdict(x) for x in candidates],
        "parameters": [asdict(x) for x in parameters],
        "evidence_ids": [x.evidence_id for x in evidence_atoms],
        "coverage": [asdict(x) for x in coverage],
        "associations": [asdict(x) for x in associations],
        "obligations": [asdict(x) for x in obligations],
        "scheduler_termination": termination.value if termination else None,
    }
    encoded = json.dumps(
        payload, separators=(",", ":"), sort_keys=True,
        default=lambda item: item.value,
    ).encode()
    return "discovery-catalog:{}".format(hashlib.sha256(encoded).hexdigest())


def _stable_id(prefix: str, *values: str) -> str:
    encoded = json.dumps(values, separators=(",", ":")).encode()
    return "{}:{}".format(prefix, hashlib.sha256(encoded).hexdigest())


def assemble_discovery_catalog(value: DiscoveryCatalogInput) -> DiscoveryCatalog:
    """Project versioned producer batches into one deterministic no-seed catalog."""

    candidates = []
    parameters = []
    evidence = {}
    coverage = []
    associations = []
    native_deep_target_refs = set()
    native_registrar_target_refs = set()
    native_nested_target_refs = set()
    native_protection_target_refs = set()
    native_service_target_refs = set()
    ubus_backend_target_refs = set()
    producer_obligations = []
    for batch in sorted(value.batches, key=lambda x: (x.producer_kind.value, x.scope)):
        statuses = []
        for result in batch.results:
            if result.producer != batch.producer:
                raise ValueError("producer result identity does not match its batch")
            statuses.append(result.coverage_status)
            for atom in result.evidence_atoms:
                existing = evidence.get(atom.evidence_id)
                if existing is not None and existing != atom:
                    raise ValueError("conflicting evidence identity")
                evidence[atom.evidence_id] = atom
            if batch.producer_kind is DiscoveryProducerKind.FRONTEND:
                for item in result.candidates:
                    candidates.append(DiscoveryCandidate(
                        item.candidate_id,
                        DiscoveryCandidateKind.REQUEST_INTERFACE,
                        item.endpoint,
                        DiscoveryClaimStatus.CANDIDATE,
                        result.source_path,
                        item.source_construct,
                        item.evidence_ids,
                        tuple(
                            (key, str(raw)) for key, raw in (
                                ("endpoint_shape", item.endpoint_shape.value),
                                ("request_role", item.request_role.value),
                                ("method", item.method),
                                ("representation", item.representation),
                            ) if raw is not None
                        ),
                    ))
                for item in result.parameters:
                    parameters.append(DiscoveryParameter(
                        item.parameter_id, item.request_candidate_id, item.name,
                        item.namespace.value, item.literal_value,
                        (item.literal_value,) if item.literal_value is not None else (),
                        item.is_operation_selector, item.source_construct,
                        item.evidence_ids,
                    ))
            elif batch.producer_kind is DiscoveryProducerKind.PARAMETER_CLUE:
                request_identities = {
                    item.candidate_id: item.canonical_identity
                    for item in candidates
                    if item.candidate_kind is DiscoveryCandidateKind.REQUEST_INTERFACE
                }
                for item in result.assessments:
                    endpoint = request_identities.get(
                        item.request_candidate_id, item.request_candidate_id
                    )
                    proof_ids = tuple(dict.fromkeys((
                        *item.frontend_evidence_ids,
                        *(hit.evidence_id for hit in item.occurrences),
                    )))
                    source_path = (
                        item.occurrences[0].artifact_path
                        if item.occurrences
                        else evidence[proof_ids[0]].source_span.artifact_path
                    )
                    candidates.append(DiscoveryCandidate(
                        _stable_id(
                            "parameter-clue-assessment",
                            item.parameter_id,
                            item.assessment_status,
                            *(hit.evidence_id for hit in item.occurrences),
                        ),
                        DiscoveryCandidateKind.PARAMETER_CLUE_ASSESSMENT,
                        "{}|{}".format(endpoint, item.parameter_name),
                        DiscoveryClaimStatus.CANDIDATE,
                        source_path,
                        result.schema_version,
                        proof_ids,
                        (
                            ("target_ref", item.parameter_id),
                            ("assessment_status", item.assessment_status),
                            ("occurrence_count", str(len(item.occurrences))),
                            ("artifact_paths", json.dumps(
                                sorted({hit.artifact_path for hit in item.occurrences}),
                                separators=(",", ":"),
                            )),
                        ),
                    ))
            elif batch.producer_kind is DiscoveryProducerKind.RESPONSE_FIXTURE:
                if result.endpoint_clue is None or result.binding_status is None:
                    continue
                candidate_id = _stable_id(
                    "response-fixture-contract",
                    result.source_path,
                    result.endpoint_clue,
                )
                normalized_endpoint = result.endpoint_clue.split("?", 1)[0].lstrip("/")
                matched_requests = tuple(
                    item
                    for item in candidates
                    if (
                        item.candidate_kind is DiscoveryCandidateKind.REQUEST_INTERFACE
                        and item.canonical_identity.split("?", 1)[0].lstrip("/")
                        == normalized_endpoint
                    )
                )
                proof_ids = tuple(dict.fromkeys((
                    *(atom.evidence_id for atom in result.evidence_atoms),
                    *(
                        evidence_id
                        for request in matched_requests
                        for evidence_id in request.evidence_ids
                    ),
                )))
                candidates.append(DiscoveryCandidate(
                    candidate_id,
                    DiscoveryCandidateKind.RESPONSE_FIXTURE_CONTRACT,
                    result.endpoint_clue,
                    DiscoveryClaimStatus.CANDIDATE,
                    result.source_path,
                    result.schema_version,
                    proof_ids,
                    (
                        ("binding_status", result.binding_status.value),
                        ("open_obligation", result.open_obligation),
                        ("frontend_request_refs", json.dumps(
                            [item.candidate_id for item in matched_requests],
                            separators=(",", ":"),
                        )),
                    ),
                ))
                for item in result.fields:
                    parameters.append(DiscoveryParameter(
                        item.field_id,
                        candidate_id,
                        item.json_pointer,
                        "response_json_pointer",
                        None,
                        (),
                        False,
                        result.schema_version,
                        item.evidence_ids,
                    ))
            elif batch.producer_kind is DiscoveryProducerKind.WEB_CONFIGURATION:
                for item in result.findings:
                    candidates.append(DiscoveryCandidate(
                        item.finding_id,
                        DiscoveryCandidateKind.WEB_CONFIGURATION,
                        item.value,
                        DiscoveryClaimStatus.SUPPORTED,
                        result.source_path,
                        item.source_construct,
                        item.evidence_ids,
                        tuple(
                            (key, str(raw)) for key, raw in (
                                ("finding_kind", item.kind.value),
                                ("namespace", item.namespace),
                                ("qualifier", item.qualifier),
                                ("related_value", item.related_value),
                            ) if raw is not None
                        ),
                    ))
            elif batch.producer_kind is DiscoveryProducerKind.SCRIPT_BACKEND:
                has_facts = any((
                    result.entries, result.routes, result.parameters,
                    result.state_accesses, result.template_reads,
                ))
                source_id = _stable_id("script-source", result.source_path)
                if has_facts:
                    source_evidence = tuple(dict.fromkeys(
                        evidence_id
                        for collection in (
                            result.entries, result.routes, result.parameters,
                            result.state_accesses, result.template_reads,
                        )
                        for fact in collection
                        for evidence_id in fact.evidence_ids
                    ))
                    candidates.append(DiscoveryCandidate(
                        source_id, DiscoveryCandidateKind.SCRIPT_SOURCE,
                        result.source_path, DiscoveryClaimStatus.SUPPORTED,
                        result.source_path,
                        result.language.value if result.language else "unknown",
                        source_evidence,
                        (("language", result.language.value),) if result.language else (),
                    ))
                for item in result.routes:
                    candidates.append(DiscoveryCandidate(
                        item.route_id, DiscoveryCandidateKind.SCRIPT_ROUTE,
                        item.route, DiscoveryClaimStatus.SUPPORTED,
                        result.source_path, item.source_construct, item.evidence_ids,
                        tuple((key, str(raw)) for key, raw in (
                            ("method", item.method), ("handler", item.handler),
                        ) if raw is not None),
                    ))
                for item in result.entries:
                    candidates.append(DiscoveryCandidate(
                        item.entry_id, DiscoveryCandidateKind.CGI_PROGRAM,
                        result.source_path, DiscoveryClaimStatus.SUPPORTED,
                        result.source_path, item.source_construct, item.evidence_ids,
                        (("entry_kind", item.kind.value),),
                    ))
                for item in result.parameters:
                    parameters.append(DiscoveryParameter(
                        item.parameter_id, source_id, item.name,
                        item.namespace.value, None, item.selector_values,
                        bool(item.selector_values), item.source_construct,
                        item.evidence_ids,
                    ))
                for item in result.state_accesses:
                    identity = "|".join(
                        value or "" for value in (
                            item.operation, item.object_name, item.field_name,
                            item.parameter_name,
                        )
                    )
                    candidates.append(DiscoveryCandidate(
                        item.access_id, DiscoveryCandidateKind.STATE_ACCESS,
                        identity, DiscoveryClaimStatus.SUPPORTED,
                        result.source_path, item.source_construct, item.evidence_ids,
                        tuple((key, str(raw)) for key, raw in (
                            ("operation", item.operation),
                            ("object_name", item.object_name),
                            ("field_name", item.field_name),
                            ("parameter_name", item.parameter_name),
                        ) if raw is not None),
                    ))
                for item in result.template_reads:
                    candidates.append(DiscoveryCandidate(
                        item.read_id, DiscoveryCandidateKind.TEMPLATE_READ,
                        "{}|{}".format(item.object_name, item.field_name),
                        DiscoveryClaimStatus.SUPPORTED, result.source_path,
                        item.source_construct, item.evidence_ids,
                        (("object_name", item.object_name), ("field_name", item.field_name)),
                    ))
            elif batch.producer_kind is DiscoveryProducerKind.NATIVE:
                for item in result.hints:
                    candidates.append(DiscoveryCandidate(
                        item.hint_id, DiscoveryCandidateKind.NATIVE_HINT,
                        item.value, DiscoveryClaimStatus.CANDIDATE,
                        result.source_path, item.source_construct, item.evidence_ids,
                        tuple((key, str(raw)) for key, raw in (
                            ("hint_kind", item.kind.value),
                            ("detected_format", result.detected_format),
                            ("bitness", result.bitness),
                            ("endianness", result.endianness),
                            ("machine", result.machine),
                        ) if raw is not None),
                    ))
            elif batch.producer_kind is DiscoveryProducerKind.NATIVE_DEEP:
                for item in result.bindings:
                    native_deep_target_refs.add(item.target_ref)
                    common_attributes = [
                        ("target_ref", item.target_ref),
                        ("profile", result.profile),
                        ("registration_address", "0x{:x}".format(item.registration_address)),
                        ("handler_address", "0x{:x}".format(item.handler_address)),
                    ]
                    if item.handler_symbol is not None:
                        common_attributes.append(("handler_symbol", item.handler_symbol))
                    if item.registrar_address is not None:
                        common_attributes.append((
                            "registrar_address", "0x{:x}".format(item.registrar_address)
                        ))
                    if item.registrar_pair_count is not None:
                        common_attributes.append((
                            "registrar_pair_count", str(item.registrar_pair_count)
                        ))
                    common_attributes = tuple(common_attributes)
                    if (
                        item.target_ref.startswith("native-registrar:")
                        and item.target_ref not in native_registrar_target_refs
                    ):
                        native_registrar_target_refs.add(item.target_ref)
                        candidates.append(DiscoveryCandidate(
                            item.target_ref,
                            DiscoveryCandidateKind.NATIVE_REGISTRAR,
                            "registrar@0x{:08x}|{}".format(
                                item.registrar_address or 0, item.route_token
                            ),
                            DiscoveryClaimStatus.SUPPORTED,
                            result.source_path,
                            item.source_construct,
                            tuple(
                                evidence_id for evidence_id in item.evidence_ids
                                if evidence[evidence_id].capability in {
                                    "establishes_pic_base", "registers_route",
                                }
                            ),
                            common_attributes,
                        ))
                    candidates.append(DiscoveryCandidate(
                        item.binding_id,
                        DiscoveryCandidateKind.NATIVE_ROUTE_BINDING,
                        item.route_token,
                        DiscoveryClaimStatus.SUPPORTED,
                        result.source_path,
                        item.source_construct,
                        item.evidence_ids,
                        (*common_attributes, ("handler_identity", item.handler_identity)),
                    ))
                    handler_id = _stable_id(
                        "native-handler",
                        result.source_path,
                        item.handler_identity,
                        item.binding_id,
                    )
                    handler_evidence = tuple(
                        evidence_id for evidence_id in item.evidence_ids
                        if evidence[evidence_id].capability in {
                            "resolves_handler_symbol", "binds_handler",
                        }
                    )
                    candidates.append(DiscoveryCandidate(
                        handler_id,
                        DiscoveryCandidateKind.NATIVE_HANDLER,
                        item.handler_identity,
                        DiscoveryClaimStatus.SUPPORTED,
                        result.source_path,
                        item.source_construct,
                        handler_evidence,
                        (*common_attributes, ("route_token", item.route_token)),
                    ))
            elif batch.producer_kind is DiscoveryProducerKind.NATIVE_VALUE_FLOW:
                for item in result.flows:
                    candidates.append(DiscoveryCandidate(
                        item.flow_id,
                        DiscoveryCandidateKind.NATIVE_PARAMETER_STATE_FLOW,
                        "{}->{}".format(item.parameter_name, item.state_key),
                        DiscoveryClaimStatus.SUPPORTED,
                        result.source_path,
                        result.profile,
                        item.evidence_ids,
                        (
                            ("handler_identity", item.handler_identity),
                            ("parameter_name", item.parameter_name),
                            ("state_key", item.state_key),
                            ("getter_symbol", item.getter_symbol),
                            ("setter_symbol", item.setter_symbol),
                            ("getter_callsite", "0x{:x}".format(item.getter_callsite)),
                            ("setter_callsite", "0x{:x}".format(item.setter_callsite)),
                        ),
                    ))
            elif batch.producer_kind is DiscoveryProducerKind.NATIVE_NESTED_DISPATCH:
                for item in result.paths:
                    native_nested_target_refs.add(item.target_ref)
                    candidates.append(DiscoveryCandidate(
                        item.path_id,
                        DiscoveryCandidateKind.NATIVE_NESTED_DISPATCH,
                        "{} -> {} -> {}".format(
                            item.transport_selector,
                            item.nested_selector,
                            item.dispatch_table_symbol,
                        ),
                        DiscoveryClaimStatus.SUPPORTED,
                        result.source_path,
                        item.source_construct,
                        item.evidence_ids,
                        (
                            ("target_ref", item.target_ref),
                            ("normalized_operation", item.normalized_operation),
                            ("dispatcher_identity", item.dispatcher_identity),
                            ("handler_identity", item.handler_identity),
                            ("registration_address", "0x{:x}".format(
                                item.registration_address
                            )),
                            ("transport_match_callsite", "0x{:x}".format(
                                item.transport_match_callsite
                            )),
                            ("selector_extract_callsite", "0x{:x}".format(
                                item.selector_extract_callsite
                            )),
                            ("upload_parse_callsite", "0x{:x}".format(
                                item.upload_parse_callsite
                            )),
                            ("suffix_normalization_address", "0x{:x}".format(
                                item.suffix_normalization_address
                            )),
                        ),
                    ))
            elif batch.producer_kind is DiscoveryProducerKind.NATIVE_REQUEST_PROTECTION:
                for item in result.assessments:
                    native_protection_target_refs.add(item.target_ref)
                    candidates.append(DiscoveryCandidate(
                        item.assessment_id,
                        DiscoveryCandidateKind.NATIVE_REQUEST_PROTECTION,
                        "{} -> {}".format(
                            item.request_path,
                            item.protection_status.value,
                        ),
                        DiscoveryClaimStatus.SUPPORTED,
                        result.source_path,
                        item.source_construct,
                        item.evidence_ids,
                        (
                            ("target_ref", item.target_ref),
                            ("protection_status", item.protection_status.value),
                            ("guard_patterns", "|".join(item.guard_patterns)),
                            ("response_hook_identity", item.response_hook_identity),
                            ("auth_hook_identity", item.auth_hook_identity),
                            (
                                "auth_hook_address",
                                "0x{:08x}".format(item.auth_hook_address),
                            ),
                            ("authenticator_identity", item.authenticator_identity),
                            (
                                "authenticator_address",
                                "0x{:08x}".format(item.authenticator_address),
                            ),
                            ("denial_status", str(item.denial_status)),
                            ("cookie_name", item.cookie_name),
                            ("auth_callsite", "0x{:x}".format(item.auth_callsite)),
                            ("enforcement_address", "0x{:x}".format(
                                item.enforcement_address
                            )),
                            ("cookie_callsite", "0x{:x}".format(
                                item.cookie_callsite
                            )),
                            ("session_lookup_callsite", "0x{:x}".format(
                                item.session_lookup_callsite
                            )),
                        ),
                    ))
            elif batch.producer_kind is DiscoveryProducerKind.NATIVE_SERVICE_ASSEMBLY:
                for item in result.assemblies:
                    native_service_target_refs.add(item.target_ref)
                    candidates.append(DiscoveryCandidate(
                        item.assembly_id,
                        DiscoveryCandidateKind.NATIVE_SERVICE_ASSEMBLY,
                        "{} -> {} -> {}".format(
                            item.launcher_identity.split("@", 1)[0],
                            item.server_artifact_path,
                            item.request_path,
                        ),
                        DiscoveryClaimStatus.SUPPORTED,
                        item.launcher_identity.split("@", 1)[0],
                        item.source_construct,
                        item.evidence_ids,
                        (
                            ("target_ref", item.target_ref),
                            ("assembly_status", item.assembly_status.value),
                            ("bootstrap_identity", item.bootstrap_identity),
                            (
                                "bootstrap_callsite",
                                "0x{:08x}".format(item.bootstrap_callsite),
                            ),
                            ("service_group_identity", item.service_group_identity),
                            (
                                "service_group_callsite",
                                "0x{:08x}".format(item.service_group_callsite),
                            ),
                            ("launcher_identity", item.launcher_identity),
                            ("launch_callsite", "0x{:08x}".format(item.launch_callsite)),
                            ("launch_arguments", "|".join(item.launch_arguments)),
                            ("server_artifact_path", item.server_artifact_path),
                            ("config_artifact_path", item.config_artifact_path),
                            ("listeners", "|".join(str(value) for value in item.listeners)),
                            ("document_root", item.document_root),
                            ("cgi_namespace", item.cgi_namespace),
                            ("target_artifact_path", item.target_artifact_path),
                            (
                                "runtime_reachability_verified",
                                str(item.runtime_reachability_verified).lower(),
                            ),
                        ),
                    ))
            elif batch.producer_kind is DiscoveryProducerKind.UBUS_BACKEND:
                principal_paths = {
                    item.principal_id: item.artifact_path
                    for item in result.principals
                }
                for item in result.principals:
                    candidates.append(DiscoveryCandidate(
                        item.principal_id,
                        DiscoveryCandidateKind.RUNTIME_PRINCIPAL,
                        item.artifact_path,
                        DiscoveryClaimStatus.SUPPORTED,
                        item.artifact_path,
                        item.principal_kind.value,
                        item.evidence_ids,
                        (
                            ("principal_kind", item.principal_kind.value),
                            ("object_names", "|".join(item.object_names)),
                        ),
                    ))
                for item in result.bindings:
                    ubus_backend_target_refs.add(item.operation_ref)
                    candidates.append(DiscoveryCandidate(
                        item.binding_id,
                        DiscoveryCandidateKind.UBUS_BACKEND_BINDING,
                        item.logical_operation,
                        (
                            DiscoveryClaimStatus.SUPPORTED
                            if item.status in {
                                UbusBackendBindingStatus.STATIC_PLUGIN_DISPATCH,
                                UbusBackendBindingStatus.VERIFIED_NATIVE_REGISTRATION,
                            }
                            else DiscoveryClaimStatus.CANDIDATE
                        ),
                        principal_paths[item.principal_id],
                        item.status.value,
                        item.evidence_ids,
                        (
                            ("target_ref", item.operation_ref),
                            ("principal_id", item.principal_id),
                            ("binding_status", item.status.value),
                            ("parameter_names", "|".join(item.parameter_names)),
                            ("handler_identity", item.handler_identity or ""),
                        ),
                    ))
                for item in result.access_grants:
                    ubus_backend_target_refs.add(item.operation_ref)
                    candidates.append(DiscoveryCandidate(
                        item.grant_id,
                        DiscoveryCandidateKind.UBUS_ACCESS_GRANT,
                        item.logical_operation,
                        DiscoveryClaimStatus.SUPPORTED,
                        item.source_path,
                        "rpcd_acl",
                        item.evidence_ids,
                        (
                            ("target_ref", item.operation_ref),
                            ("policy_group", item.policy_group),
                            ("access_mode", item.access_mode.value),
                            ("object_pattern", item.object_pattern),
                        ),
                    ))
                producer_obligations.extend(result.open_obligations)
        if not statuses:
            status = CoverageStatus.FAILED if batch.required else CoverageStatus.NOT_APPLICABLE
            diagnostic = "required_batch_has_no_results" if batch.required else None
        elif all(x is CoverageStatus.COMPLETED for x in statuses):
            status, diagnostic = CoverageStatus.COMPLETED, None
        else:
            status = CoverageStatus.PARTIAL
            diagnostic = "one or more producer results were incomplete"
        coverage.append(DiscoveryCoverage(
            batch.scope, batch.producer_kind, batch.producer.name,
            batch.producer.version, status, batch.required, len(batch.results), diagnostic,
        ))
    if value.set_difference is not None:
        result = value.set_difference
        for atom in (*result.upstream_evidence_atoms, *result.evidence_atoms):
            existing = evidence.get(atom.evidence_id)
            if existing is not None and existing != atom:
                raise ValueError("conflicting set-difference evidence identity")
            evidence[atom.evidence_id] = atom
        for item in result.attributions:
            proof_ids = tuple(dict.fromkeys(
                (*item.upstream_evidence_ids, *item.evidence_ids)
            ))
            source_path = evidence[proof_ids[-1]].source_span.artifact_path
            candidates.append(DiscoveryCandidate(
                item.attribution_id,
                DiscoveryCandidateKind.SET_DIFFERENCE_ATTRIBUTION,
                item.token,
                DiscoveryClaimStatus.SUPPORTED,
                source_path,
                result.schema_version,
                proof_ids,
                (
                    ("difference_side", item.side.value),
                    ("attribution_kind", item.kind.value),
                    ("matched_artifact_paths", json.dumps(
                        item.matched_artifact_paths, separators=(",", ":")
                    )),
                    ("interpretation", item.interpretation),
                    ("open_obligation", item.open_obligation),
                ),
            ))
        coverage.append(DiscoveryCoverage(
            "catalog/set-difference",
            DiscoveryProducerKind.SET_DIFFERENCE,
            result.producer.name,
            result.producer.version,
            result.coverage_status,
            True,
            1,
            "; ".join(item.message for item in result.diagnostics) or None,
        ))

    candidate_ids = {item.candidate_id for item in candidates}
    if value.correlation is not None:
        for item in value.correlation.associations:
            if item.frontend_candidate_id not in candidate_ids:
                raise ValueError("correlation references unknown frontend candidate")
            if item.native_hint_id not in candidate_ids:
                raise ValueError("correlation references unknown native hint")
            association = DiscoveryAssociation(
                item.association_id, item.frontend_candidate_id, item.native_hint_id,
                item.match_basis.value, item.evidence_ids,
            )
            associations.append(association)
            candidates.append(DiscoveryCandidate(
                item.association_id, DiscoveryCandidateKind.CANDIDATE_ASSOCIATION,
                "{}|{}".format(item.frontend_candidate_id, item.native_hint_id),
                DiscoveryClaimStatus.CANDIDATE, item.native_source_path,
                item.rule_version, item.evidence_ids,
                (("match_basis", item.match_basis.value),),
            ))
            candidate_ids.add(item.association_id)
        coverage.append(DiscoveryCoverage(
            "catalog/correlation", DiscoveryProducerKind.CORRELATION,
            "frontend-native-correlation", value.correlation.rule_version,
            value.correlation.coverage_status, True, 1,
            "; ".join(x.message for x in value.correlation.diagnostics) or None,
        ))
    if any(target not in candidate_ids for target in native_deep_target_refs):
        raise ValueError("native deep binding references unknown catalog candidate")
    if any(target not in candidate_ids for target in native_nested_target_refs):
        raise ValueError("native nested dispatch references unknown catalog candidate")
    if any(target not in candidate_ids for target in native_protection_target_refs):
        raise ValueError("native request protection references unknown catalog candidate")
    if any(target not in candidate_ids for target in native_service_target_refs):
        raise ValueError("native service assembly references unknown catalog candidate")
    if any(target not in candidate_ids for target in ubus_backend_target_refs):
        raise ValueError("ubus backend result references unknown catalog candidate")
    if value.scheduler is not None:
        obligations = normalize_scheduler_obligations((
            *value.scheduler.open_obligations,
            *producer_obligations,
        ))
        termination = value.scheduler.termination
        coverage.append(DiscoveryCoverage(
            "catalog/scheduler", DiscoveryProducerKind.SCHEDULER,
            "obligation-scheduler", value.scheduler.schema_version,
            value.scheduler.coverage_status, True, 1,
            "; ".join(x.message for x in value.scheduler.diagnostics) or None,
        ))
    elif value.correlation is not None:
        obligations = normalize_scheduler_obligations((
            *value.correlation.obligations,
            *producer_obligations,
        ))
        termination = None
    else:
        obligations = normalize_scheduler_obligations(tuple(producer_obligations))
        termination = None
    for item in obligations:
        if item.target_ref not in candidate_ids:
            raise ValueError("obligation references unknown catalog candidate")
    candidate_map = {}
    for item in candidates:
        existing = candidate_map.get(item.candidate_id)
        if existing is not None and existing != item:
            raise ValueError("conflicting candidate identity")
        candidate_map[item.candidate_id] = item
    candidates = tuple(sorted(candidate_map.values(), key=lambda x: x.candidate_id))
    parameter_map = {}
    for item in parameters:
        existing = parameter_map.get(item.parameter_id)
        if existing is not None and existing != item:
            raise ValueError("conflicting parameter identity")
        parameter_map[item.parameter_id] = item
    parameters = tuple(sorted(parameter_map.values(), key=lambda x: x.parameter_id))
    evidence_atoms = tuple(evidence[key] for key in sorted(evidence))
    evidence_ids = set(evidence)
    candidate_ids = {item.candidate_id for item in candidates}
    for item in candidates:
        if not item.evidence_ids:
            raise ValueError("catalog candidate requires evidence")
        if any(identity not in evidence_ids for identity in item.evidence_ids):
            raise ValueError("catalog candidate references unknown evidence")
    for item in parameters:
        if item.owner_ref not in candidate_ids:
            raise ValueError("catalog parameter references unknown owner")
        if not item.evidence_ids or any(
            identity not in evidence_ids for identity in item.evidence_ids
        ):
            raise ValueError("catalog parameter requires known evidence")
    coverage = tuple(coverage)
    incomplete = (
        value.source_inventory_coverage_status is not CoverageStatus.COMPLETED
        or any(
            x.required
            and x.status
            not in {CoverageStatus.COMPLETED, CoverageStatus.NOT_APPLICABLE}
            for x in coverage
        )
    )
    return DiscoveryCatalog(
        catalog_id=_catalog_id(
            value, candidates, parameters, evidence_atoms, coverage,
            tuple(associations), tuple(obligations), termination,
        ),
        firmware_artifact_sha256=value.firmware_artifact_sha256,
        source_inventory_sha256=value.source_inventory_sha256,
        coverage_status=(
            CoverageStatus.PARTIAL if incomplete else CoverageStatus.COMPLETED
        ),
        source_inventory_coverage_status=value.source_inventory_coverage_status,
        candidates=candidates,
        parameters=parameters,
        evidence_atoms=evidence_atoms,
        coverage=coverage,
        associations=tuple(sorted(associations, key=lambda x: x.association_id)),
        open_obligations=tuple(obligations),
        scheduler_termination=termination,
    )
