"""Evidence-backed recovery of a distinct ARM URL-configuration document consumer."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import struct
from typing import Tuple

from .domain import AnalyzerIdentity, CoverageStatus, EvidenceAtom, ObservationKind, SpanKind
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .inventory import SourceArtifactEntry
from .native_arm_configuration_text_import_flow import (
    _calls,
    _pic_literals,
    _stable_id,
    _symbol,
)
from .native_cross_elf_call import ArmCrossElfArtifact, _function_end, _parse
from .scheduler import SchedulerObligation


ARM_CONFIGURATION_URL_DOCUMENT_FLOW_SCHEMA_VERSION = (
    "firmatlas.mapping.arm-configuration-url-document-flow/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("native-arm-configuration-url-document-flow", "0.1.0")


@dataclass(frozen=True)
class ArmConfigurationUrlDocumentArtifact:
    source: SourceArtifactEntry
    content: bytes


@dataclass(frozen=True)
class ArmConfigurationUrlDocumentProfile:
    name: str = "arm32-cfm-url-document-consumer/v1"
    writer_symbol: str = "tpi_sys_cfg_upload"
    loader_symbol: str = "load_url_mib"
    reload_symbol: str = "reload_url_mib"
    runtime_path: str = "/webroot/default_url.cfg"
    state_scope: str = "cfm/url_mib/*"
    maximum_function_bytes: int = 16 * 1024

    def __post_init__(self) -> None:
        values = (
            self.name, self.writer_symbol, self.loader_symbol,
            self.reload_symbol, self.runtime_path, self.state_scope,
        )
        if any(not item.strip() for item in values) or self.maximum_function_bytes <= 0:
            raise ValueError("configuration URL-document profile requires identity")


@dataclass(frozen=True)
class ArmConfigurationUrlDocumentFlowPolicy:
    max_artifacts: int = 256
    max_total_bytes: int = 256 * 1024 * 1024

    def __post_init__(self) -> None:
        if min(self.max_artifacts, self.max_total_bytes) <= 0:
            raise ValueError("configuration URL-document budgets must be positive")


@dataclass(frozen=True)
class ArmConfigurationUrlDocumentFlow:
    flow_id: str
    writer_path: str
    writer_identity: str
    runtime_path: str
    loader_path: str
    loader_identity: str
    parser_identity: str
    reload_identity: str
    state_scope: str
    write_granularity: str
    activation_status: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class ArmConfigurationUrlDocumentFlowResult:
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    profile: str
    flows: Tuple[ArmConfigurationUrlDocumentFlow, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    open_obligations: Tuple[SchedulerObligation, ...]
    diagnostics: Tuple[str, ...] = ()
    schema_version: str = ARM_CONFIGURATION_URL_DOCUMENT_FLOW_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "flows": [asdict(item) for item in self.flows],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
            "open_obligations": [asdict(item) for item in self.open_obligations],
        }


def _verify_source(artifact: ArmConfigurationUrlDocumentArtifact) -> None:
    source, content = artifact.source, artifact.content
    if (
        source.kind not in {"file", "hardlink", "archive_member"}
        or source.content_sha256 is None
        or source.size != len(content)
        or hashlib.sha256(content).hexdigest() != source.content_sha256
    ):
        raise ValueError("source_mismatch")


def _function_atom(parsed, flow_id: str, start: int, end: int,
                   predicate: str, value: str, capability: str) -> EvidenceAtom:
    offset = parsed.elf.address_offset(start, end - start)
    return capture_evidence(
        parsed.artifact.source,
        parsed.artifact.content,
        SpanSelection(SpanKind.BINARY, offset, offset + end - start),
        EvidenceClaim(
            flow_id, predicate, value, ObservationKind.DETERMINISTIC_DERIVED,
            capability, 1.0,
        ),
        _PRODUCER,
    )


def _literal_atom(parsed, flow_id: str, literal: str, span,
                  predicate: str, capability: str) -> EvidenceAtom:
    return capture_evidence(
        parsed.artifact.source,
        parsed.artifact.content,
        SpanSelection(SpanKind.BINARY, span[1], span[2]),
        EvidenceClaim(
            flow_id, predicate, literal, ObservationKind.DETERMINISTIC_DERIVED,
            capability, 1.0,
        ),
        _PRODUCER,
    )


def discover_arm_configuration_url_document_flows(
    artifacts: Tuple[ArmConfigurationUrlDocumentArtifact, ...],
    profile: ArmConfigurationUrlDocumentProfile = ArmConfigurationUrlDocumentProfile(),
    policy: ArmConfigurationUrlDocumentFlowPolicy = ArmConfigurationUrlDocumentFlowPolicy(),
) -> ArmConfigurationUrlDocumentFlowResult:
    """Recover the distinct URL-document consumer and keep activation unresolved."""
    total = sum(len(item.content) for item in artifacts)
    empty = ((), (), ())
    if len(artifacts) > policy.max_artifacts:
        return ArmConfigurationUrlDocumentFlowResult(
            CoverageStatus.SKIPPED_BY_POLICY, 0, _PRODUCER, profile.name,
            *empty, ("artifact_budget_exceeded",),
        )
    if total > policy.max_total_bytes:
        return ArmConfigurationUrlDocumentFlowResult(
            CoverageStatus.SKIPPED_BY_POLICY, 0, _PRODUCER, profile.name,
            *empty, ("byte_budget_exceeded",),
        )
    try:
        for item in artifacts:
            _verify_source(item)
    except ValueError:
        return ArmConfigurationUrlDocumentFlowResult(
            CoverageStatus.FAILED, total, _PRODUCER, profile.name,
            *empty, ("source_mismatch",),
        )

    parsed = []
    diagnostics = []
    for item in artifacts:
        if not item.content.startswith(b"\x7fELF"):
            continue
        try:
            parsed.append(_parse(ArmCrossElfArtifact(item.source, item.content)))
        except (KeyError, TypeError, ValueError, struct.error) as exc:
            diagnostics.append(
                "artifact_parse_failed:{}:{}".format(item.source.canonical_path, exc)
            )
    writer = next(((item, _symbol(item, profile.writer_symbol)) for item in parsed
                   if _symbol(item, profile.writer_symbol) is not None), None)
    owner = next((item for item in parsed
                  if _symbol(item, profile.loader_symbol) is not None
                  and _symbol(item, profile.reload_symbol) is not None), None)
    if writer is None:
        diagnostics.append("url_document_writer_missing")
    if owner is None:
        diagnostics.append("url_document_consumer_missing")
    if writer is None or owner is None:
        return ArmConfigurationUrlDocumentFlowResult(
            CoverageStatus.PARTIAL, total, _PRODUCER, profile.name,
            (), (), (), tuple(sorted(set(diagnostics))),
        )

    writer_parsed, writer_export = writer
    loader_export = _symbol(owner, profile.loader_symbol)
    reload_export = _symbol(owner, profile.reload_symbol)
    writer_end = _function_end(
        writer_parsed, writer_export.address, profile.maximum_function_bytes
    )
    writer_literals = _pic_literals(
        writer_parsed, writer_export.address, writer_end
    )
    loader_end = _function_end(owner, loader_export.address, profile.maximum_function_bytes)
    loader_literals = _pic_literals(owner, loader_export.address, loader_end)
    reload_end = _function_end(owner, reload_export.address, profile.maximum_function_bytes)
    reload_calls = _calls(owner, reload_export.address, reload_end)
    if profile.runtime_path not in writer_literals:
        diagnostics.append("url_document_writer_path_missing")
    if profile.runtime_path not in loader_literals:
        diagnostics.append("url_document_loader_path_missing")
    if not any(name == profile.loader_symbol for _, name, _ in reload_calls):
        diagnostics.append("reload_to_url_loader_call_missing")

    internal = [
        (callsite, target) for callsite, name, target
        in _calls(owner, loader_export.address, loader_end)
        if name is None and target < loader_export.address
    ]
    parser_choices = []
    for callsite, target in internal:
        end = _function_end(owner, target, profile.maximum_function_bytes)
        calls = _calls(owner, target, end)
        symbols = {name for _, name, _ in calls}
        if {"strtok", "strdup"}.issubset(symbols):
            parser_choices.append((callsite, target, end, calls))
    parser_span = None
    if len(parser_choices) == 1:
        _, parser_address, parser_end, parser_calls = parser_choices[0]
        helper_targets = {target for _, name, target in parser_calls if name is None}
        helper_calls = tuple(
            call
            for target in helper_targets
            for call in _calls(
                owner, target,
                _function_end(owner, target, profile.maximum_function_bytes),
            )
        )
        splitter = next((call for call in helper_calls if call[1] == "strchr"), None)
        inserter = next((call for call in helper_calls if call[1] == "hash_insert"), None)
        if splitter is None:
            diagnostics.append("url_key_value_splitter_missing")
        if inserter is None:
            diagnostics.append("url_hash_store_missing")
        parser_span = (parser_address, parser_end, splitter, inserter)
    else:
        diagnostics.append("url_key_value_parser_missing")
    if diagnostics:
        return ArmConfigurationUrlDocumentFlowResult(
            CoverageStatus.PARTIAL, total, _PRODUCER, profile.name,
            (), (), (), tuple(sorted(set(diagnostics))),
        )

    flow_id = _stable_id(
        "native-configuration-url-document-flow",
        writer_parsed.artifact.source.canonical_path, writer_export.address,
        owner.artifact.source.canonical_path, loader_export.address,
        profile.runtime_path, profile.state_scope,
    )
    atoms = [
        _function_atom(
            writer_parsed, flow_id, writer_export.address, writer_end,
            "writes_url_configuration_document", profile.writer_symbol,
            "writes_configuration_url_document",
        ),
        _literal_atom(
            writer_parsed, flow_id, profile.runtime_path,
            writer_literals[profile.runtime_path], "writes_url_document_path",
            "writes_configuration_url_document",
        ),
        _function_atom(
            owner, flow_id, loader_export.address, loader_end,
            "loads_url_configuration_document", profile.loader_symbol,
            "loads_configuration_url_document",
        ),
        _literal_atom(
            owner, flow_id, profile.runtime_path,
            loader_literals[profile.runtime_path], "loads_url_document_path",
            "loads_configuration_url_document",
        ),
        _function_atom(
            owner, flow_id, reload_export.address, reload_end,
            "reloads_url_configuration_document", profile.reload_symbol,
            "reloads_configuration_url_document",
        ),
    ]
    parser_address, parser_end, splitter, inserter = parser_span
    atoms.extend((
        _function_atom(
            owner, flow_id, parser_address, parser_end,
            "tokenizes_url_configuration_document", "strtok->strdup",
            "tokenizes_configuration_url_document",
        ),
        _function_atom(
            owner, flow_id, splitter[0], splitter[0] + 4,
            "splits_url_configuration_entry", "strchr('=')",
            "splits_configuration_url_entry",
        ),
        _function_atom(
            owner, flow_id, inserter[0], inserter[0] + 4,
            "imports_url_configuration_state", "hash_insert",
            "imports_configuration_url_state_scope",
        ),
    ))
    flow = ArmConfigurationUrlDocumentFlow(
        flow_id,
        writer_parsed.artifact.source.canonical_path,
        "{}@0x{:08x}".format(
            writer_parsed.artifact.source.canonical_path, writer_export.address
        ),
        profile.runtime_path,
        owner.artifact.source.canonical_path,
        "{}@0x{:08x}".format(owner.artifact.source.canonical_path, loader_export.address),
        "{}@0x{:08x}".format(owner.artifact.source.canonical_path, parser_address),
        "{}@0x{:08x}".format(owner.artifact.source.canonical_path, reload_export.address),
        profile.state_scope,
        "key_value_document",
        "unresolved",
        tuple(item.evidence_id for item in atoms),
    )
    obligation = SchedulerObligation(
        _stable_id(
            "configuration-url-document-obligation", flow_id,
            "binds_configuration_url_loader_activation",
        ),
        flow_id,
        "binds_configuration_url_loader_activation",
        "The writer and consumer are independently proven, but no static trigger "
        "from the upload/restore path to load_url_mib or reload_url_mib was recovered.",
        90,
        (),
    )
    return ArmConfigurationUrlDocumentFlowResult(
        CoverageStatus.PARTIAL, total, _PRODUCER, profile.name,
        (flow,), tuple(sorted(atoms, key=lambda item: item.evidence_id)),
        (obligation,), ("url_document_content_missing",),
    )
