"""Deterministic orchestration for an already extracted firmware root."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
import struct
from typing import Tuple

from .correlation import correlate_frontend_native
from .discovery_catalog import (
    DiscoveryCatalog,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    assemble_discovery_catalog,
)
from .domain import CoverageStatus
from .frontend import (
    FrontendAssetInput,
    discover_frontend_asset_graph,
    discover_frontend_requests,
)
from .inventory import InventoryPolicy, SourceArtifactEntry, build_inventory
from .native import discover_native_hints
from .native_deep import (
    ArmPicCallsiteProfile,
    NativeRouteAnchor,
    discover_arm_pic_callsite_bindings,
    native_deep_scheduler_analyzer,
)
from .native_ubus_registration import discover_native_ubus_registrations
from .script_backend import discover_script_backend
from .scheduler import (
    SchedulerAnalyzer,
    SchedulerDisposition,
    SchedulerOutcome,
    run_obligation_scheduler,
)
from .ubus_backend import (
    UbusArtifactInput,
    discover_ubus_backend_graph,
    ubus_operation_references_from_frontend,
)
from .web_config import discover_web_configuration


MAPPING_ANALYSIS_RUN_SCHEMA_VERSION = "firmatlas.mapping.analysis-run/v1alpha1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FRONTEND_SUFFIXES = frozenset({".js", ".html", ".htm", ".php", ".asp"})
_SCRIPT_SUFFIXES = frozenset({".php", ".asp", ".lua", ".cgi"})
_BASE_ANALYZERS = (
    "frontend", "web_configuration", "script_backend", "native",
)
_AUTO_V1_ANALYZERS = _BASE_ANALYZERS + (
    "arm_pic_callsite", "native_ubus_registration", "ubus_backend",
)
_AUTO_ANALYZERS = _AUTO_V1_ANALYZERS + ("frontend_asset_graph",)


@dataclass(frozen=True)
class MappingAnalysisProfile:
    profile_id: str
    enabled_analyzers: Tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.profile_id.strip() or not self.enabled_analyzers:
            raise ValueError("analysis profile requires identity and analyzers")
        if len(self.enabled_analyzers) != len(set(self.enabled_analyzers)):
            raise ValueError("analysis profile contains duplicate analyzers")

    @classmethod
    def base(cls) -> "MappingAnalysisProfile":
        return cls("firmatlas.mapping.profile/base-v1", _BASE_ANALYZERS)

    @classmethod
    def auto(cls) -> "MappingAnalysisProfile":
        return cls("firmatlas.mapping.profile/auto-v3", _AUTO_ANALYZERS)

    @classmethod
    def auto_v2(cls) -> "MappingAnalysisProfile":
        return cls("firmatlas.mapping.profile/auto-v2", _AUTO_ANALYZERS)

    @classmethod
    def auto_v1(cls) -> "MappingAnalysisProfile":
        return cls("firmatlas.mapping.profile/auto-v1", _AUTO_V1_ANALYZERS)


@dataclass(frozen=True)
class MappingAnalyzerRegistry:
    registry_id: str
    analyzer_names: Tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.registry_id.strip() or not self.analyzer_names:
            raise ValueError("analyzer registry requires identity and analyzers")
        if len(self.analyzer_names) != len(set(self.analyzer_names)):
            raise ValueError("analyzer registry contains duplicate analyzers")

    @classmethod
    def builtin(cls) -> "MappingAnalyzerRegistry":
        return cls("firmatlas.mapping.analyzer-registry/builtin-v3", _AUTO_ANALYZERS)

    @classmethod
    def builtin_v2(cls) -> "MappingAnalyzerRegistry":
        return cls("firmatlas.mapping.analyzer-registry/builtin-v2", _AUTO_ANALYZERS)

    @classmethod
    def builtin_v1(cls) -> "MappingAnalyzerRegistry":
        return cls(
            "firmatlas.mapping.analyzer-registry/builtin-v1", _AUTO_V1_ANALYZERS
        )

    def validate_profile(self, profile: MappingAnalysisProfile) -> None:
        missing = set(profile.enabled_analyzers) - set(self.analyzer_names)
        if missing:
            raise ValueError(
                "analysis profile requests unavailable analyzers: {}".format(
                    ", ".join(sorted(missing))
                )
            )

    def analyze_source(
        self, analyzer_name: str, source: SourceArtifactEntry, content: bytes,
    ):
        analyzers = {
            "frontend": discover_frontend_requests,
            "web_configuration": discover_web_configuration,
            "script_backend": discover_script_backend,
            "native": discover_native_hints,
            "native_ubus_registration": discover_native_ubus_registrations,
        }
        if analyzer_name not in self.analyzer_names or analyzer_name not in analyzers:
            raise ValueError("source analyzer is unavailable: {}".format(analyzer_name))
        return analyzers[analyzer_name](source, content)


BUILTIN_ANALYZER_REGISTRY = MappingAnalyzerRegistry.builtin()
BUILTIN_ANALYZER_REGISTRY_V2 = MappingAnalyzerRegistry.builtin_v2()
BUILTIN_ANALYZER_REGISTRY_V1 = MappingAnalyzerRegistry.builtin_v1()


@dataclass(frozen=True)
class MappingAnalysisRequest:
    root: Path
    firmware_artifact_sha256: str
    inventory_policy: InventoryPolicy = InventoryPolicy()
    profile: MappingAnalysisProfile = MappingAnalysisProfile.auto()

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root))
        if not _SHA256.fullmatch(self.firmware_artifact_sha256):
            raise ValueError("firmware_artifact_sha256 must be a lowercase SHA-256")


@dataclass(frozen=True)
class MappingSourcePlanEntry:
    source_path: str
    analyzer_kinds: Tuple[str, ...]
    content_sha256: str


@dataclass(frozen=True)
class MappingAnalysisStage:
    stage_name: str
    coverage_status: CoverageStatus
    input_count: int
    output_count: int
    diagnostics: Tuple[str, ...] = ()


@dataclass(frozen=True)
class MappingAnalysisRun:
    analysis_run_id: str
    firmware_artifact_sha256: str
    source_inventory_sha256: str
    inventory_coverage_status: CoverageStatus
    profile_id: str
    analyzer_registry_id: str
    source_plan: Tuple[MappingSourcePlanEntry, ...]
    stages: Tuple[MappingAnalysisStage, ...]
    catalog: DiscoveryCatalog
    schema_version: str = MAPPING_ANALYSIS_RUN_SCHEMA_VERSION

    @property
    def coverage_status(self) -> CoverageStatus:
        return self.catalog.coverage_status

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "analysis_run_id": self.analysis_run_id,
            "firmware_artifact_sha256": self.firmware_artifact_sha256,
            "source_inventory_sha256": self.source_inventory_sha256,
            "inventory_coverage_status": self.inventory_coverage_status.value,
            "profile_id": self.profile_id,
            "analyzer_registry_id": self.analyzer_registry_id,
            "coverage_status": self.coverage_status.value,
            "source_plan": [asdict(item) for item in self.source_plan],
            "stages": [
                {**asdict(item), "coverage_status": item.coverage_status.value}
                for item in self.stages
            ],
            "catalog": self.catalog.to_dict(),
        }


def _classify(
    path: str, content: bytes, profile: MappingAnalysisProfile,
) -> Tuple[str, ...]:
    enabled = set(profile.enabled_analyzers)
    if content.startswith(b"\x7fELF"):
        kinds = ["native"] if "native" in enabled else []
        if (
            "native_ubus_registration" in enabled
            and path.startswith("usr/lib/rpcd/")
            and content.find(b"rpc_plugin") >= 0
        ):
            kinds.append("native_ubus_registration")
        if "ubus_backend" in enabled and path.startswith("usr/lib/rpcd/"):
            kinds.append("ubus_backend")
        return tuple(kinds)
    pure = Path(path)
    suffix = pure.suffix.lower()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    kinds = []
    if "frontend" in enabled and suffix in _FRONTEND_SUFFIXES:
        kinds.append("frontend")
    if "script_backend" in enabled and suffix in _SCRIPT_SUFFIXES:
        kinds.append("script_backend")
    lowered = path.lower()
    if (
        "script_backend" in enabled and suffix == ".sh"
        and "/cgi-bin/" in "/{}".format(lowered)
    ):
        kinds.append("script_backend")
    basename = pure.name.lower()
    known_config = (
        basename in {"nginx.conf", "lighttpd.conf", "httpd.conf"}
        or lowered in {"etc/config/uhttpd", "etc/init.d/uhttpd"}
    )
    init_script = text is not None and "/etc/init.d/" in "/{}".format(lowered) and any(
        token in text.lower()
        for token in ("nginx", "lighttpd", "uhttpd", "httpd", "spawn-fcgi")
    )
    if "web_configuration" in enabled and (known_config or init_script):
        kinds.append("web_configuration")
    if "ubus_backend" in enabled and (
        lowered.startswith("usr/libexec/rpcd/")
        or lowered.startswith("usr/share/rpcd/acl.d/")
    ):
        kinds.append("ubus_backend")
    return tuple(kinds)


def _stage(name: str, results: tuple, output_count: int) -> MappingAnalysisStage:
    if not results:
        return MappingAnalysisStage(
            name, CoverageStatus.NOT_APPLICABLE, 0, 0, ("no selected sources",)
        )
    status = (
        CoverageStatus.COMPLETED
        if all(item.coverage_status is CoverageStatus.COMPLETED for item in results)
        else CoverageStatus.PARTIAL
    )
    diagnostics = tuple(sorted({
        diagnostic.code
        for result in results
        for diagnostic in result.diagnostics
    }))
    return MappingAnalysisStage(name, status, len(results), output_count, diagnostics)


def _batch(factory, results: tuple, scope: str) -> DiscoveryProducerBatch:
    batch = factory(results, scope)
    if results:
        return batch
    return DiscoveryProducerBatch(
        batch.producer_kind, batch.producer, batch.scope, (), required=False
    )


def _combined_native_deep_analyzer(results: tuple) -> Tuple[SchedulerAnalyzer, ...]:
    adapters = tuple(
        native_deep_scheduler_analyzer(item) for item in results if item.bindings
    )
    if not adapters:
        return ()

    def analyze(obligation):
        evidence_ids = []
        for adapter in adapters:
            outcome = adapter.analyze(obligation)
            if outcome.disposition is SchedulerDisposition.RESOLVED:
                evidence_ids.extend(outcome.evidence_ids)
        return SchedulerOutcome(
            SchedulerDisposition.RESOLVED
            if evidence_ids else SchedulerDisposition.UNCHANGED,
            evidence_ids=tuple(dict.fromkeys(evidence_ids)),
        )

    return (SchedulerAnalyzer("native-deep", analyze),)


def _arm_pic_callsite_applicable(content: bytes) -> bool:
    if len(content) < 52 or content[:7] != b"\x7fELF\x01\x01\x01":
        return False
    try:
        machine = struct.unpack_from("<H", content, 18)[0]
        section_offset = struct.unpack_from("<I", content, 32)[0]
        section_entry_size, section_count = struct.unpack_from("<HH", content, 46)
    except struct.error:
        return False
    return (
        machine == 40 and section_offset > 0 and section_entry_size >= 40
        and section_count > 0
        and section_offset + section_entry_size * section_count <= len(content)
    )


def analyze_extracted_root(
    request: MappingAnalysisRequest,
    registry: MappingAnalyzerRegistry = BUILTIN_ANALYZER_REGISTRY,
) -> MappingAnalysisRun:
    """Analyze one extracted root through the stable mapping orchestration seam."""

    registry.validate_profile(request.profile)
    inventory = build_inventory(request.root, request.inventory_policy)
    selected = []
    for source in inventory.entries:
        if source.kind not in {"file", "hardlink"} or source.content_sha256 is None:
            continue
        path = request.root.joinpath(*source.canonical_path.split("/"))
        content = path.read_bytes()
        kinds = _classify(source.canonical_path, content, request.profile)
        if kinds:
            selected.append((source, content, kinds))
    selected.sort(key=lambda item: item[0].canonical_path)
    plan = tuple(
        MappingSourcePlanEntry(source.canonical_path, kinds, source.content_sha256 or "")
        for source, _, kinds in selected
    )

    frontend_sources = tuple(
        (source, content)
        for source, content, kinds in selected if "frontend" in kinds
    )
    frontend_graph = None
    if (
        "frontend_asset_graph" in request.profile.enabled_analyzers
        and frontend_sources
    ):
        frontend_graph = discover_frontend_asset_graph(tuple(
            FrontendAssetInput(source, content)
            for source, content in frontend_sources
        ))
        frontend = frontend_graph.results
    else:
        frontend = tuple(
            registry.analyze_source("frontend", source, content)
            for source, content in frontend_sources
        )
    web = tuple(
        registry.analyze_source("web_configuration", source, content)
        for source, content, kinds in selected if "web_configuration" in kinds
    )
    scripts = tuple(
        registry.analyze_source("script_backend", source, content)
        for source, content, kinds in selected if "script_backend" in kinds
    )
    native = tuple(
        registry.analyze_source("native", source, content)
        for source, content, kinds in selected if "native" in kinds
    )
    correlation = correlate_frontend_native(frontend, native) if frontend and native else None
    selected_by_path = {
        source.canonical_path: (source, content)
        for source, content, _ in selected
    }
    native_by_path = {item.source_path: item for item in native}
    native_hints = {
        hint.hint_id: hint for item in native for hint in item.hints
    }
    anchors_by_path = {}
    if correlation is not None and "arm_pic_callsite" in request.profile.enabled_analyzers:
        for association in correlation.associations:
            hint = native_hints[association.native_hint_id]
            anchors_by_path.setdefault(association.native_source_path, []).append(
                NativeRouteAnchor(association.association_id, hint.value)
            )
    native_deep = tuple(
        discover_arm_pic_callsite_bindings(
            selected_by_path[path][0], selected_by_path[path][1], tuple(anchors),
            ArmPicCallsiteProfile.v1()
            if request.profile.profile_id in {
                "firmatlas.mapping.profile/auto-v1",
                "firmatlas.mapping.profile/auto-v2",
            }
            else ArmPicCallsiteProfile(),
        )
        for path, anchors in sorted(anchors_by_path.items())
        if (
            path in selected_by_path and native_by_path[path].machine == "ARM"
            and _arm_pic_callsite_applicable(selected_by_path[path][1])
        )
    )
    native_ubus = tuple(
        registry.analyze_source("native_ubus_registration", source, content)
        for source, content, kinds in selected
        if "native_ubus_registration" in kinds
    )
    ubus_artifacts = tuple(
        UbusArtifactInput(source, content)
        for source, content, kinds in selected if "ubus_backend" in kinds
    )
    ubus_backend = None
    if "ubus_backend" in request.profile.enabled_analyzers and ubus_artifacts:
        operations = ubus_operation_references_from_frontend(frontend)
        if operations:
            ubus_backend = discover_ubus_backend_graph(
                operations,
                ubus_artifacts,
                native_registrations=tuple(
                    item for item in native_ubus
                    if item.registration_coverage_complete
                ),
            )
    initial_obligations = (
        *((correlation.obligations) if correlation is not None else ()),
        *((ubus_backend.open_obligations) if ubus_backend is not None else ()),
    )
    scheduler = run_obligation_scheduler(
        initial_obligations, _combined_native_deep_analyzer(native_deep)
    )
    batches = [
        _batch(DiscoveryProducerBatch.frontend, frontend, "auto:frontend"),
        _batch(DiscoveryProducerBatch.web_configuration, web, "auto:web-configuration"),
        _batch(DiscoveryProducerBatch.script_backend, scripts, "auto:script-backend"),
        _batch(DiscoveryProducerBatch.native, native, "auto:native"),
    ]
    if "arm_pic_callsite" in request.profile.enabled_analyzers:
        batches.append(_batch(
            DiscoveryProducerBatch.native_deep,
            native_deep,
            "auto:arm-pic-callsite",
        ))
    if "ubus_backend" in request.profile.enabled_analyzers:
        batches.append(_batch(
            DiscoveryProducerBatch.ubus_backend,
            (ubus_backend,) if ubus_backend is not None else (),
            "auto:ubus-backend",
        ))
    catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
        firmware_artifact_sha256=request.firmware_artifact_sha256,
        source_inventory_sha256=inventory.inventory_sha256,
        source_inventory_coverage_status=inventory.coverage_status,
        batches=tuple(batches),
        correlation=correlation,
        scheduler=scheduler,
    ))
    stages = [
        MappingAnalysisStage(
            "inventory", inventory.coverage_status, inventory.observed_count,
            inventory.processed_count,
            tuple(sorted({item.code for item in inventory.diagnostics})),
        ),
        MappingAnalysisStage(
            "source_plan", CoverageStatus.COMPLETED, len(inventory.entries), len(plan)
        ),
        _stage("frontend", frontend, sum(len(item.candidates) for item in frontend)),
        _stage("web_configuration", web, sum(len(item.findings) for item in web)),
        _stage(
            "script_backend", scripts,
            sum(
                len(item.entries) + len(item.routes) + len(item.parameters)
                + len(item.state_accesses) + len(item.template_reads)
                for item in scripts
            ),
        ),
        _stage("native", native, sum(len(item.hints) for item in native)),
    ]
    if "frontend_asset_graph" in request.profile.enabled_analyzers:
        stages.insert(3, MappingAnalysisStage(
            "frontend_asset_graph",
            frontend_graph.coverage_status if frontend_graph is not None
            else CoverageStatus.NOT_APPLICABLE,
            len(frontend_sources),
            len(frontend_graph.bindings) if frontend_graph is not None else 0,
            tuple(item.code for item in frontend_graph.diagnostics)
            if frontend_graph is not None else ("no frontend sources",),
        ))
    if "native_ubus_registration" in request.profile.enabled_analyzers:
        stages.append(_stage(
            "native_ubus_registration", native_ubus,
            sum(len(item.objects) for item in native_ubus if item.registration_coverage_complete),
        ))
    if "arm_pic_callsite" in request.profile.enabled_analyzers:
        stages.append(_stage(
            "arm_pic_callsite", native_deep,
            sum(len(item.bindings) for item in native_deep),
        ))
    if "ubus_backend" in request.profile.enabled_analyzers:
        stages.append(MappingAnalysisStage(
            "ubus_backend",
            ubus_backend.coverage_status if ubus_backend is not None
            else CoverageStatus.NOT_APPLICABLE,
            len(ubus_artifacts),
            len(ubus_backend.bindings) if ubus_backend is not None else 0,
            tuple(item.code for item in ubus_backend.diagnostics)
            if ubus_backend is not None else ("no ubus operations",),
        ))
    stages.extend((
        MappingAnalysisStage(
            "scheduler", scheduler.coverage_status,
            len(initial_obligations),
            len(scheduler.open_obligations),
            tuple(item.code for item in scheduler.diagnostics),
        ),
        MappingAnalysisStage(
            "catalog", catalog.coverage_status, len(plan), len(catalog.candidates),
            tuple(item.diagnostic for item in catalog.coverage if item.diagnostic),
        ),
    ))
    stages = tuple(stages)
    identity_document = {
        "schema": MAPPING_ANALYSIS_RUN_SCHEMA_VERSION,
        "firmware": request.firmware_artifact_sha256,
        "inventory": inventory.inventory_sha256,
        "plan": [asdict(item) for item in plan],
        "catalog": catalog.catalog_id,
        "stages": [
            {**asdict(item), "coverage_status": item.coverage_status.value}
            for item in stages
        ],
    }
    # Preserve the R2-01 base-profile run identity while making every expanded
    # profile/registry choice part of subsequent content-addressed runs.
    if not (
        request.profile == MappingAnalysisProfile.base()
        and registry == BUILTIN_ANALYZER_REGISTRY
    ):
        identity_document["profile"] = request.profile.profile_id
        identity_document["registry"] = registry.registry_id
    identity_payload = json.dumps(
        identity_document, sort_keys=True, separators=(",", ":")
    ).encode()
    run_id = "mapping-analysis-run:{}".format(hashlib.sha256(identity_payload).hexdigest())
    return MappingAnalysisRun(
        run_id, request.firmware_artifact_sha256, inventory.inventory_sha256,
        inventory.coverage_status, request.profile.profile_id, registry.registry_id,
        plan, stages, catalog,
    )
