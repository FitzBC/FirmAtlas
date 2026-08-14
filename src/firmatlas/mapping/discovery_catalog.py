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
from .frontend_feature_gate import FrontendFeatureGateResult
from .frontend_reachability import FrontendReachabilityResult
from .parameter_clue import FrontendParameterClueIndex
from .response_fixture import ResponseFixtureResult
from .native_relationship import NativeRelationshipResult
from .native_arm_xref import ArmFeaturePivotResult, ArmLiteralXrefResult
from .native_command_binding import NativeCommandBindingResult
from .native_cgi_dispatch import ArmCgiDispatchResult
from .native_cross_elf_call import ArmCrossElfCallResult
from .native_arm_configuration_blob_flow import ArmConfigurationBlobFlowResult
from .native_arm_configuration_text_import_flow import (
    ArmConfigurationTextImportFlowResult,
)
from .native_arm_configuration_url_document_flow import (
    ArmConfigurationUrlDocumentFlowResult,
)
from .native_arm_configuration_url_ipc_flow import (
    ArmConfigurationUrlIpcFlowResult,
)
from .native_arm_cgi_selector_dispatch import ArmCgiSelectorDispatchResult
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
    FRONTEND_FEATURE_GATE = "frontend_feature_gate"
    FRONTEND_REACHABILITY = "frontend_reachability"
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
    NATIVE_RELATIONSHIP = "native_relationship"
    ARM_LITERAL_XREF = "arm_literal_xref"
    ARM_FEATURE_PIVOT = "arm_feature_pivot"
    NATIVE_COMMAND_BINDING = "native_command_binding"
    NATIVE_CGI_DISPATCH = "native_cgi_dispatch"
    NATIVE_CROSS_ELF_CALL = "native_cross_elf_call"
    NATIVE_CONFIGURATION_BLOB_FLOW = "native_configuration_blob_flow"
    NATIVE_CONFIGURATION_TEXT_IMPORT_FLOW = (
        "native_configuration_text_import_flow"
    )
    NATIVE_CONFIGURATION_URL_DOCUMENT_FLOW = (
        "native_configuration_url_document_flow"
    )
    NATIVE_CONFIGURATION_URL_IPC_FLOW = "native_configuration_url_ipc_flow"
    NATIVE_CGI_SELECTOR_DISPATCH = "native_cgi_selector_dispatch"


class DiscoveryCandidateKind(str, Enum):
    REQUEST_INTERFACE = "request_interface"
    FRONTEND_FEATURE_GATE = "frontend_feature_gate"
    FRONTEND_INVOCATION = "frontend_invocation"
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
    NATIVE_RELATIONSHIP = "native_relationship"
    ARM_LITERAL_XREF = "arm_literal_xref"
    ARM_FEATURE_PIVOT = "arm_feature_pivot"
    NATIVE_COMMAND_BINDING = "native_command_binding"
    NATIVE_CGI_DISPATCH = "native_cgi_dispatch"
    NATIVE_CROSS_ELF_CALL = "native_cross_elf_call"
    NATIVE_CONFIGURATION_BLOB_FLOW = "native_configuration_blob_flow"
    NATIVE_CONFIGURATION_TEXT_IMPORT_FLOW = (
        "native_configuration_text_import_flow"
    )
    NATIVE_CONFIGURATION_URL_DOCUMENT_FLOW = (
        "native_configuration_url_document_flow"
    )
    NATIVE_CONFIGURATION_URL_IPC_FLOW = "native_configuration_url_ipc_flow"
    NATIVE_CONFIGURATION_URL_CONSUMER = "native_configuration_url_consumer"
    NATIVE_CGI_SELECTOR = "native_cgi_selector"


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
    def frontend_feature_gate(
        cls, results: Tuple[FrontendFeatureGateResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("frontend-feature-gate", "0.1.0")
        )
        return cls(
            DiscoveryProducerKind.FRONTEND_FEATURE_GATE,
            producer,
            scope,
            results,
        )

    @classmethod
    def frontend_reachability(
        cls, results: Tuple[FrontendReachabilityResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("frontend-invocation-reachability", "0.1.0")
        )
        return cls(
            DiscoveryProducerKind.FRONTEND_REACHABILITY,
            producer,
            scope,
            results,
        )

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
    def native_relationship(
        cls, results: Tuple[NativeRelationshipResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("native-embedded-command-relationship", "0.1.0")
        )
        return cls(DiscoveryProducerKind.NATIVE_RELATIONSHIP, producer, scope, results)

    @classmethod
    def arm_literal_xref(
        cls, results: Tuple[ArmLiteralXrefResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results else AnalyzerIdentity("native-arm-literal-xref", "0.1.0")
        )
        return cls(DiscoveryProducerKind.ARM_LITERAL_XREF, producer, scope, results)

    @classmethod
    def arm_feature_pivot(
        cls, results: Tuple[ArmFeaturePivotResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("native-arm-feature-pivot", "0.1.0")
        )
        return cls(
            DiscoveryProducerKind.ARM_FEATURE_PIVOT,
            producer,
            scope,
            results,
        )

    @classmethod
    def native_command_binding(
        cls, results: Tuple[NativeCommandBindingResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results else AnalyzerIdentity("native-symbol-command-table", "0.1.0")
        )
        return cls(DiscoveryProducerKind.NATIVE_COMMAND_BINDING, producer, scope, results)

    @classmethod
    def native_cgi_dispatch(
        cls, results: Tuple[ArmCgiDispatchResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("native-arm-cgi-string-dispatch", "0.1.0")
        )
        return cls(
            DiscoveryProducerKind.NATIVE_CGI_DISPATCH,
            producer,
            scope,
            results,
        )

    @classmethod
    def native_cgi_selector_dispatch(
        cls, results: Tuple[ArmCgiSelectorDispatchResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("native-arm-cgi-selector-dispatch", "0.1.0")
        )
        return cls(
            DiscoveryProducerKind.NATIVE_CGI_SELECTOR_DISPATCH,
            producer,
            scope,
            results,
        )

    @classmethod
    def native_cross_elf_call(
        cls, results: Tuple[ArmCrossElfCallResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("native-arm-cross-elf-call", "0.1.0")
        )
        return cls(
            DiscoveryProducerKind.NATIVE_CROSS_ELF_CALL,
            producer,
            scope,
            results,
        )

    @classmethod
    def native_configuration_blob_flow(
        cls, results: Tuple[ArmConfigurationBlobFlowResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("native-arm-configuration-blob-flow", "0.1.0")
        )
        return cls(
            DiscoveryProducerKind.NATIVE_CONFIGURATION_BLOB_FLOW,
            producer,
            scope,
            results,
        )

    @classmethod
    def native_configuration_text_import_flow(
        cls, results: Tuple[ArmConfigurationTextImportFlowResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity(
                "native-arm-configuration-text-import-flow", "0.1.0"
            )
        )
        return cls(
            DiscoveryProducerKind.NATIVE_CONFIGURATION_TEXT_IMPORT_FLOW,
            producer,
            scope,
            results,
        )

    @classmethod
    def native_configuration_url_document_flow(
        cls, results: Tuple[ArmConfigurationUrlDocumentFlowResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity(
                "native-arm-configuration-url-document-flow", "0.1.0"
            )
        )
        return cls(
            DiscoveryProducerKind.NATIVE_CONFIGURATION_URL_DOCUMENT_FLOW,
            producer,
            scope,
            results,
        )

    @classmethod
    def native_configuration_url_ipc_flow(
        cls, results: Tuple[ArmConfigurationUrlIpcFlowResult, ...], scope: str
    ) -> "DiscoveryProducerBatch":
        producer = (
            results[0].producer
            if results
            else AnalyzerIdentity("native-arm-configuration-url-ipc-flow", "0.1.0")
        )
        return cls(
            DiscoveryProducerKind.NATIVE_CONFIGURATION_URL_IPC_FLOW,
            producer,
            scope,
            results,
        )

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

    known_source_paths = {
        result.source_path
        for batch in value.batches
        for result in batch.results
        if hasattr(result, "source_path")
    }
    source_paths_by_basename = {}
    for path in sorted(known_source_paths):
        source_paths_by_basename.setdefault(path.rsplit("/", 1)[-1], []).append(path)
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
    native_cgi_target_refs = set()
    ubus_backend_target_refs = set()
    arm_feature_pivot_binding_refs = set()
    frontend_invocation_request_refs = set()
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
            elif (
                batch.producer_kind
                is DiscoveryProducerKind.FRONTEND_FEATURE_GATE
            ):
                requests = {
                    item.candidate_id: item
                    for item in candidates
                    if item.candidate_kind
                    is DiscoveryCandidateKind.REQUEST_INTERFACE
                }
                for item in result.gates:
                    if any(
                        request_id not in requests
                        for request_id in item.request_candidate_ids
                    ):
                        raise ValueError(
                            "frontend feature gate references unknown request"
                        )
                    proof_ids = tuple(dict.fromkeys((
                        *item.evidence_ids,
                        *(
                            evidence_id
                            for request_id in item.request_candidate_ids
                            for evidence_id in requests[request_id].evidence_ids
                        ),
                    )))
                    candidates.append(DiscoveryCandidate(
                        item.gate_id,
                        DiscoveryCandidateKind.FRONTEND_FEATURE_GATE,
                        item.feature_symbol,
                        DiscoveryClaimStatus.SUPPORTED,
                        item.page_path,
                        item.source_construct,
                        proof_ids,
                        (
                            ("gate_status", item.status.value),
                            ("configured_value", item.configured_value),
                            ("enabled_value", item.enabled_value),
                            ("ui_target_id", item.ui_target_id),
                            ("page_path", item.page_path),
                            ("script_paths", json.dumps(
                                item.script_paths, separators=(",", ":")
                            )),
                            ("request_candidate_refs", json.dumps(
                                item.request_candidate_ids,
                                separators=(",", ":"),
                            )),
                            ("request_endpoints", json.dumps(
                                item.request_endpoints,
                                separators=(",", ":"),
                            )),
                        ),
                    ))
            elif (
                batch.producer_kind
                is DiscoveryProducerKind.FRONTEND_REACHABILITY
            ):
                for item in result.invocations:
                    frontend_invocation_request_refs.add(
                        item.request_candidate_id
                    )
                    candidates.append(DiscoveryCandidate(
                        item.invocation_id,
                        DiscoveryCandidateKind.FRONTEND_INVOCATION,
                        item.endpoint,
                        DiscoveryClaimStatus.SUPPORTED,
                        result.source_path,
                        item.source_construct,
                        item.evidence_ids,
                        (
                            (
                                "request_candidate_ref",
                                item.request_candidate_id,
                            ),
                            ("status", item.status.value),
                            ("function_name", item.function_name or ""),
                            ("root_kind", item.root_kind or ""),
                            (
                                "call_path",
                                json.dumps(
                                    item.call_path, separators=(",", ":")
                                ),
                            ),
                            (
                                "commented_reference_count",
                                str(item.commented_reference_count),
                            ),
                            (
                                "interpretation",
                                "Static executable-token coverage classifies "
                                "where the request is declared and whether a "
                                "bounded invocation path was observed; it does "
                                "not prove runtime execution or inaccessibility.",
                            ),
                        ),
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
            elif batch.producer_kind is DiscoveryProducerKind.NATIVE_RELATIONSHIP:
                for item in result.relationships:
                    target_artifact_paths = source_paths_by_basename.get(
                        item.target, ()
                    )
                    parts = [
                        result.source_path,
                        item.action,
                        item.target,
                    ]
                    if item.topic is not None:
                        parts.append("topic={}".format(item.topic))
                    if item.operation is not None:
                        parts.append("op={}".format(item.operation))
                    candidates.append(DiscoveryCandidate(
                        item.relationship_id,
                        DiscoveryCandidateKind.NATIVE_RELATIONSHIP,
                        "|".join(parts),
                        DiscoveryClaimStatus.CANDIDATE,
                        result.source_path,
                        result.schema_version,
                        item.evidence_ids,
                        tuple(
                            (key, raw) for key, raw in (
                                ("relationship_kind", item.kind.value),
                                ("binding_status", item.binding_status.value),
                                ("source_component", result.source_path),
                                ("action", item.action),
                                ("target_component", item.target),
                                ("command", item.command),
                                ("target_artifact_paths", json.dumps(
                                    target_artifact_paths,
                                    separators=(",", ":"),
                                )),
                                (
                                    "target_resolution_status",
                                    "resolved_same_firmware"
                                    if target_artifact_paths
                                    else "unresolved_in_analyzed_sources",
                                ),
                                ("topic", item.topic),
                                ("operation", item.operation),
                                ("arguments", json.dumps(
                                    list(item.arguments), separators=(",", ":")
                                )),
                                ("open_obligation", result.open_obligation),
                            ) if raw is not None
                        ),
                    ))
            elif batch.producer_kind is DiscoveryProducerKind.ARM_LITERAL_XREF:
                for item in result.xrefs:
                    candidates.append(DiscoveryCandidate(
                        item.xref_id,
                        DiscoveryCandidateKind.ARM_LITERAL_XREF,
                        "{}@0x{:08x}|{}".format(
                            result.source_path,
                            item.function_start_address,
                            item.literal_value,
                        ),
                        DiscoveryClaimStatus.CANDIDATE,
                        result.source_path,
                        item.source_construct,
                        item.evidence_ids,
                        (
                            ("target_ref", item.target_ref),
                            ("literal_value", item.literal_value),
                            ("literal_address", "0x{:08x}".format(item.literal_address)),
                            ("instruction_address", "0x{:08x}".format(
                                item.instruction_address
                            )),
                            ("function_identity", "{}@0x{:08x}".format(
                                result.source_path, item.function_start_address
                            )),
                            ("pic_base_address", "0x{:08x}".format(
                                item.pic_base_address
                            )),
                        ),
                    ))
            elif batch.producer_kind is DiscoveryProducerKind.ARM_FEATURE_PIVOT:
                for item in result.pivots:
                    arm_feature_pivot_binding_refs.add(item.route_binding_ref)
                    candidates.append(DiscoveryCandidate(
                        item.pivot_id,
                        DiscoveryCandidateKind.ARM_FEATURE_PIVOT,
                        "{}|{}|{}".format(
                            item.feature_token,
                            item.route_token,
                            item.literal_value,
                        ),
                        DiscoveryClaimStatus.CANDIDATE,
                        result.source_path,
                        item.source_construct,
                        item.evidence_ids,
                        (
                            ("target_ref", item.target_ref),
                            ("feature_token", item.feature_token),
                            ("literal_value", item.literal_value),
                            ("function_identity", "{}@0x{:08x}".format(
                                result.source_path,
                                item.function_start_address,
                            )),
                            ("instruction_address", "0x{:08x}".format(
                                item.instruction_address
                            )),
                            ("route_binding_ref", item.route_binding_ref),
                            ("route_token", item.route_token),
                            ("handler_identity", item.handler_identity),
                            ("handler_symbol", item.handler_symbol),
                            (
                                "interpretation",
                                "A verified route handler references an exact "
                                "allocated literal containing the feature token; "
                                "this is an adjacency clue, not operation ownership.",
                            ),
                        ),
                    ))
            elif batch.producer_kind is DiscoveryProducerKind.NATIVE_COMMAND_BINDING:
                for item in result.bindings:
                    candidates.append(DiscoveryCandidate(
                        item.binding_id,
                        DiscoveryCandidateKind.NATIVE_COMMAND_BINDING,
                        "{}|{}|handler=0x{:08x}".format(
                            result.source_path, item.process_name,
                            item.handler_address,
                        ),
                        DiscoveryClaimStatus.SUPPORTED,
                        result.source_path,
                        item.source_construct,
                        item.evidence_ids,
                        (
                            ("table_symbol", item.table_symbol),
                            ("registration_address", "0x{:08x}".format(
                                item.registration_address
                            )),
                            ("process_name", item.process_name),
                            ("command", item.command),
                            ("handler_identity", item.handler_identity),
                            ("handler_address", "0x{:08x}".format(
                                item.handler_address
                            )),
                            ("binding_status", item.binding_status.value),
                        ),
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
            elif (
                batch.producer_kind
                is DiscoveryProducerKind.NATIVE_CONFIGURATION_BLOB_FLOW
            ):
                for item in result.flows:
                    candidates.append(DiscoveryCandidate(
                        item.flow_id,
                        DiscoveryCandidateKind.NATIVE_CONFIGURATION_BLOB_FLOW,
                        "{}:opcode={}->{}".format(
                            item.client_symbol, item.request_opcode, item.state_scope
                        ),
                        DiscoveryClaimStatus.SUPPORTED,
                        item.dispatcher_path,
                        result.profile,
                        item.evidence_ids,
                        (
                            ("client_path", item.client_path),
                            ("client_identity", item.client_identity),
                            ("client_symbol", item.client_symbol),
                            ("dispatcher_path", item.dispatcher_path),
                            ("dispatcher_identity", item.dispatcher_identity),
                            ("request_opcode", str(item.request_opcode)),
                            ("response_opcode", str(item.response_opcode)),
                            ("message_size", str(item.message_size)),
                            ("payload_offset", str(item.payload_offset)),
                            ("payload_literal", item.payload_literal),
                            ("decoder_symbol", item.decoder_symbol),
                            ("state_writer_symbol", item.state_writer_symbol),
                            ("state_scope", item.state_scope),
                            ("write_granularity", item.write_granularity),
                        ),
                    ))
            elif (
                batch.producer_kind
                is DiscoveryProducerKind.NATIVE_CONFIGURATION_TEXT_IMPORT_FLOW
            ):
                for item in result.flows:
                    architecture_evidence = tuple(
                        evidence_id for evidence_id in item.evidence_ids
                        if evidence[evidence_id].capability
                        != "declares_configuration_state_key"
                    )
                    candidates.append(DiscoveryCandidate(
                        item.flow_id,
                        DiscoveryCandidateKind.NATIVE_CONFIGURATION_TEXT_IMPORT_FLOW,
                        "{}->{}".format(item.import_command, item.state_scope),
                        DiscoveryClaimStatus.SUPPORTED,
                        item.restore_path,
                        result.profile,
                        architecture_evidence,
                        (
                            ("upload_path", item.upload_path),
                            ("upload_identity", item.upload_identity),
                            ("restore_path", item.restore_path),
                            ("restore_identity", item.restore_identity),
                            ("ipc_client_identity", item.ipc_client_identity),
                            ("ipc_dispatcher_identity", item.ipc_dispatcher_identity),
                            ("request_opcode", str(item.request_opcode)),
                            ("payload_literal", item.payload_literal),
                            ("parser_identity", item.parser_identity),
                            ("primary_runtime_path", item.primary_runtime_path),
                            ("secondary_runtime_path", item.secondary_runtime_path),
                            ("source_document_path", item.source_document_path),
                            ("section_delimiter", item.section_delimiter),
                            ("import_command", item.import_command),
                            ("state_scope", item.state_scope),
                            ("write_granularity", item.write_granularity),
                            ("declared_key_count", str(len(item.declared_keys))),
                            ("unique_declared_key_count", str(len(set(item.declared_keys)))),
                            ("declared_keys", json.dumps(
                                item.declared_keys, ensure_ascii=False,
                                separators=(",", ":"),
                            )),
                            ("key_evidence", json.dumps(
                                item.key_evidence, ensure_ascii=False,
                                separators=(",", ":"),
                            )),
                        ),
                    ))
            elif (
                batch.producer_kind
                is DiscoveryProducerKind.NATIVE_CONFIGURATION_URL_DOCUMENT_FLOW
            ):
                for item in result.flows:
                    candidates.append(DiscoveryCandidate(
                        item.flow_id,
                        DiscoveryCandidateKind.NATIVE_CONFIGURATION_URL_DOCUMENT_FLOW,
                        "{}->{}".format(item.runtime_path, item.state_scope),
                        DiscoveryClaimStatus.CANDIDATE,
                        item.loader_path,
                        result.profile,
                        item.evidence_ids,
                        (
                            ("writer_path", item.writer_path),
                            ("writer_identity", item.writer_identity),
                            ("runtime_path", item.runtime_path),
                            ("loader_path", item.loader_path),
                            ("loader_identity", item.loader_identity),
                            ("parser_identity", item.parser_identity),
                            ("reload_identity", item.reload_identity),
                            ("state_scope", item.state_scope),
                            ("write_granularity", item.write_granularity),
                            ("activation_status", item.activation_status),
                        ),
                    ))
                producer_obligations.extend(result.open_obligations)
            elif (
                batch.producer_kind
                is DiscoveryProducerKind.NATIVE_CONFIGURATION_URL_IPC_FLOW
            ):
                call_counts_by_symbol = {}
                for path, symbol, count in result.client_call_counts:
                    call_counts_by_symbol.setdefault(symbol, []).append((path, count))
                for item in result.operations:
                    candidates.append(DiscoveryCandidate(
                        item.operation_id,
                        DiscoveryCandidateKind.NATIVE_CONFIGURATION_URL_IPC_FLOW,
                        "{}:opcode={}->{}".format(
                            item.client_symbol, item.request_opcode, item.state_scope
                        ),
                        DiscoveryClaimStatus.SUPPORTED,
                        item.dispatcher_path,
                        result.profile,
                        item.evidence_ids,
                        (
                            ("operation", item.operation),
                            ("client_path", item.client_path),
                            ("client_identity", item.client_identity),
                            ("client_symbol", item.client_symbol),
                            ("request_opcode", str(item.request_opcode)),
                            ("response_opcodes", json.dumps(item.response_opcodes)),
                            ("message_size", str(item.message_size)),
                            ("key_offset", "" if item.key_offset is None else str(item.key_offset)),
                            ("value_offset", "" if item.value_offset is None else str(item.value_offset)),
                            ("dispatcher_path", item.dispatcher_path),
                            ("dispatcher_identity", item.dispatcher_identity),
                            ("server_wrapper_symbol", item.server_wrapper_symbol),
                            ("store_primitive_symbol", item.store_primitive_symbol),
                            ("state_scope", item.state_scope),
                            ("access_mode", item.access_mode),
                            ("client_call_counts", json.dumps(
                                sorted(call_counts_by_symbol.get(item.client_symbol, ()))
                            )),
                        ),
                    ))
                for item in result.consumers:
                    candidates.append(DiscoveryCandidate(
                        item.consumer_id,
                        DiscoveryCandidateKind.NATIVE_CONFIGURATION_URL_CONSUMER,
                        "{}->{}".format(
                            item.function_identity,
                            ",".join(item.state_key_templates),
                        ),
                        DiscoveryClaimStatus.SUPPORTED,
                        item.source_path,
                        result.profile,
                        item.evidence_ids,
                        (
                            ("function_identity", item.function_identity),
                            ("client_symbols", json.dumps(item.client_symbols)),
                            ("state_key_templates", json.dumps(item.state_key_templates)),
                            ("state_accesses", json.dumps(item.state_accesses)),
                            ("access_modes", json.dumps(item.access_modes)),
                        ),
                    ))
            elif (
                batch.producer_kind
                is DiscoveryProducerKind.NATIVE_CGI_SELECTOR_DISPATCH
            ):
                for item in result.selectors:
                    candidates.append(DiscoveryCandidate(
                        item.selector_id,
                        DiscoveryCandidateKind.NATIVE_CGI_SELECTOR,
                        item.interface_path,
                        DiscoveryClaimStatus.SUPPORTED,
                        item.source_path,
                        result.profile,
                        item.evidence_ids,
                        (
                            ("transport_namespace", item.transport_namespace),
                            ("namespace_registration_address", "0x{:08x}".format(
                                item.namespace_registration_address
                            )),
                            ("namespace_registrar_address", "0x{:08x}".format(
                                item.namespace_registrar_address
                            )),
                            ("owner_identity", item.owner_identity),
                            ("dispatcher_identity", item.dispatcher_identity),
                            ("selector", item.selector),
                            ("comparison_width", str(item.comparison_width)),
                            ("comparison_address", "0x{:08x}".format(
                                item.comparison_address
                            )),
                            ("handler_address", "0x{:08x}".format(
                                item.handler_address
                            )),
                            ("handler_identity", item.handler_identity),
                            ("interface_path", item.interface_path),
                            ("interface_path_status", item.interface_path_status),
                            ("method", item.method),
                            ("method_status", item.method_status),
                            ("loader_activation_status", item.loader_activation_status),
                        ),
                    ))
                producer_obligations.extend(result.open_obligations)
            elif batch.producer_kind is DiscoveryProducerKind.NATIVE_CGI_DISPATCH:
                for item in result.bindings:
                    native_cgi_target_refs.add(item.target_ref)
                    handler_id = _stable_id(
                        "native-handler",
                        result.source_path,
                        item.handler_identity,
                        item.binding_id,
                    )
                    common_attributes = (
                        ("target_ref", item.target_ref),
                        ("interface_path", item.interface_path),
                        ("dispatch_token", item.dispatch_token),
                        ("dispatcher_identity", "{}@0x{:08x}".format(
                            result.source_path, item.dispatcher_address
                        )),
                        ("dispatcher_address", "0x{:08x}".format(
                            item.dispatcher_address
                        )),
                        ("dispatcher_entry_count", str(
                            item.dispatcher_entry_count
                        )),
                        ("comparison_address", "0x{:08x}".format(
                            item.comparison_address
                        )),
                        ("comparison_target_address", "0x{:08x}".format(
                            item.comparison_target_address
                        )),
                        ("handler_identity", item.handler_identity),
                        ("handler_address", "0x{:08x}".format(
                            item.handler_address
                        )),
                        ("handler_ref", handler_id),
                    )
                    candidates.append(DiscoveryCandidate(
                        item.binding_id,
                        DiscoveryCandidateKind.NATIVE_CGI_DISPATCH,
                        item.dispatch_token,
                        DiscoveryClaimStatus.SUPPORTED,
                        result.source_path,
                        item.source_construct,
                        item.evidence_ids,
                        common_attributes,
                    ))
                    handler_evidence = tuple(
                        evidence_id for evidence_id in item.evidence_ids
                        if evidence[evidence_id].capability == "binds_handler"
                    )
                    candidates.append(DiscoveryCandidate(
                        handler_id,
                        DiscoveryCandidateKind.NATIVE_HANDLER,
                        item.handler_identity,
                        DiscoveryClaimStatus.SUPPORTED,
                        result.source_path,
                        item.source_construct,
                        handler_evidence,
                        (
                            ("target_ref", item.target_ref),
                            ("route_token", item.dispatch_token),
                            ("handler_address", "0x{:08x}".format(
                                item.handler_address
                            )),
                            ("dispatch_ref", item.binding_id),
                        ),
                    ))
            elif batch.producer_kind is DiscoveryProducerKind.NATIVE_CROSS_ELF_CALL:
                for item in result.hops:
                    candidates.append(DiscoveryCandidate(
                        item.hop_id,
                        DiscoveryCandidateKind.NATIVE_CROSS_ELF_CALL,
                        "{}|{}|{}".format(
                            item.source_function_identity,
                            item.imported_symbol,
                            item.target_function_identity or "owner-unresolved",
                        ),
                        DiscoveryClaimStatus.SUPPORTED,
                        item.source_path,
                        result.schema_version,
                        item.evidence_ids,
                        (
                            ("origin_refs", json.dumps(
                                list(item.origin_refs), separators=(",", ":")
                            )),
                            ("source_function_identity", item.source_function_identity),
                            ("source_function_address", "0x{:08x}".format(
                                item.source_function_address
                            )),
                            ("callsite_address", "0x{:08x}".format(
                                item.callsite_address
                            )),
                            ("imported_symbol", item.imported_symbol),
                            ("target_path", item.target_path),
                            ("target_function_identity", item.target_function_identity),
                            ("target_function_address", "0x{:08x}".format(
                                item.target_function_address
                            )),
                            ("target_resolution_status", item.target_resolution_status),
                            ("argument_literals", json.dumps(
                                list(item.argument_literals), separators=(",", ":")
                            )),
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
    if any(target not in candidate_ids for target in native_cgi_target_refs):
        raise ValueError("native CGI dispatch references unknown catalog candidate")
    if any(target not in candidate_ids for target in ubus_backend_target_refs):
        raise ValueError("ubus backend result references unknown catalog candidate")
    if any(
        target not in candidate_ids
        for target in arm_feature_pivot_binding_refs
    ):
        raise ValueError("ARM feature pivot references unknown route binding")
    if any(
        target not in candidate_ids
        for target in frontend_invocation_request_refs
    ):
        raise ValueError(
            "frontend invocation references unknown request candidate"
        )
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
