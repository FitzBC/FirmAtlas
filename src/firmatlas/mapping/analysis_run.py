"""Deterministic orchestration for an already extracted firmware root."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
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
    FrontendPolicy,
    discover_frontend_asset_graph,
    discover_frontend_requests,
)
from .frontend_feature_gate import (
    FrontendFeatureGatePolicy,
    discover_frontend_feature_gates,
)
from .frontend_reachability import (
    FrontendReachabilityPolicy,
    discover_frontend_invocation_reachability,
)
from .inventory import InventoryPolicy, SourceArtifactEntry, build_inventory
from .parameter_clue import (
    ParameterClueArtifact,
    ParameterClueArtifactRole,
    ParameterCluePolicy,
    trace_frontend_parameter_clues,
)
from .response_fixture import (
    ResponseFixturePolicy,
    discover_response_fixture,
)
from .native_relationship import (
    NativeRelationshipPolicy,
    discover_native_relationships,
)
from .native_command_binding import (
    NativeCommandBindingPolicy,
    discover_native_command_table_bindings,
)
from .native_arm_xref import (
    ArmFeaturePivotAnchor,
    ArmFunctionTarget,
    ArmLiteralXrefPolicy,
    discover_arm_feature_pivots,
    discover_arm_function_literal_xrefs,
)
from .native import discover_native_hints
from .native_deep import (
    ArmPicCallsiteProfile,
    NativeRouteAnchor,
    discover_arm_pic_callsite_bindings,
    discover_arm_pic_registrar_bindings,
    native_deep_scheduler_analyzer,
)
from .native_ubus_registration import discover_native_ubus_registrations
from .script_backend import discover_script_backend
from .set_difference import (
    AttributionArtifact,
    AttributionArtifactRole,
    SetDifferencePolicy,
    attribute_frontend_native_set_difference,
)
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
_AUTO_V2_ANALYZERS = _AUTO_V1_ANALYZERS + ("frontend_asset_graph",)
_AUTO_V5_ANALYZERS = _AUTO_V2_ANALYZERS + ("arm_pic_registrar", "set_difference")
_AUTO_V6_ANALYZERS = _AUTO_V5_ANALYZERS + ("parameter_clue",)
_AUTO_V7_ANALYZERS = _AUTO_V6_ANALYZERS + ("response_fixture",)
_AUTO_V8_ANALYZERS = _AUTO_V7_ANALYZERS + ("native_relationship",)
_AUTO_V9_ANALYZERS = _AUTO_V8_ANALYZERS + (
    "native_command_binding", "arm_literal_xref",
)
_AUTO_V10_ANALYZERS = _AUTO_V9_ANALYZERS
_AUTO_V11_ANALYZERS = _AUTO_V10_ANALYZERS + ("frontend_feature_gate",)
_AUTO_V12_ANALYZERS = _AUTO_V11_ANALYZERS + ("arm_feature_pivot",)
_AUTO_ANALYZERS = _AUTO_V12_ANALYZERS + ("frontend_reachability",)


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
        return cls("firmatlas.mapping.profile/auto-v13", _AUTO_ANALYZERS)

    @classmethod
    def auto_v12(cls) -> "MappingAnalysisProfile":
        return cls("firmatlas.mapping.profile/auto-v12", _AUTO_V12_ANALYZERS)

    @classmethod
    def auto_v11(cls) -> "MappingAnalysisProfile":
        return cls("firmatlas.mapping.profile/auto-v11", _AUTO_V11_ANALYZERS)

    @classmethod
    def auto_v10(cls) -> "MappingAnalysisProfile":
        return cls("firmatlas.mapping.profile/auto-v10", _AUTO_V10_ANALYZERS)

    @classmethod
    def auto_v9(cls) -> "MappingAnalysisProfile":
        return cls("firmatlas.mapping.profile/auto-v9", _AUTO_V9_ANALYZERS)

    @classmethod
    def auto_v8(cls) -> "MappingAnalysisProfile":
        return cls("firmatlas.mapping.profile/auto-v8", _AUTO_V8_ANALYZERS)

    @classmethod
    def auto_v7(cls) -> "MappingAnalysisProfile":
        return cls("firmatlas.mapping.profile/auto-v7", _AUTO_V7_ANALYZERS)

    @classmethod
    def auto_v6(cls) -> "MappingAnalysisProfile":
        return cls("firmatlas.mapping.profile/auto-v6", _AUTO_V6_ANALYZERS)

    @classmethod
    def auto_v5(cls) -> "MappingAnalysisProfile":
        return cls("firmatlas.mapping.profile/auto-v5", _AUTO_V5_ANALYZERS)

    @classmethod
    def auto_v4(cls) -> "MappingAnalysisProfile":
        return cls("firmatlas.mapping.profile/auto-v4", _AUTO_V5_ANALYZERS)

    @classmethod
    def auto_v3(cls) -> "MappingAnalysisProfile":
        return cls("firmatlas.mapping.profile/auto-v3", _AUTO_V2_ANALYZERS)

    @classmethod
    def auto_v2(cls) -> "MappingAnalysisProfile":
        return cls("firmatlas.mapping.profile/auto-v2", _AUTO_V2_ANALYZERS)

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
        return cls("firmatlas.mapping.analyzer-registry/builtin-v13", _AUTO_ANALYZERS)

    @classmethod
    def builtin_v12(cls) -> "MappingAnalyzerRegistry":
        return cls(
            "firmatlas.mapping.analyzer-registry/builtin-v12",
            _AUTO_V12_ANALYZERS,
        )

    @classmethod
    def builtin_v11(cls) -> "MappingAnalyzerRegistry":
        return cls(
            "firmatlas.mapping.analyzer-registry/builtin-v11",
            _AUTO_V11_ANALYZERS,
        )

    @classmethod
    def builtin_v10(cls) -> "MappingAnalyzerRegistry":
        return cls(
            "firmatlas.mapping.analyzer-registry/builtin-v10",
            _AUTO_V10_ANALYZERS,
        )

    @classmethod
    def builtin_v9(cls) -> "MappingAnalyzerRegistry":
        return cls(
            "firmatlas.mapping.analyzer-registry/builtin-v9", _AUTO_V9_ANALYZERS
        )

    @classmethod
    def builtin_v8(cls) -> "MappingAnalyzerRegistry":
        return cls("firmatlas.mapping.analyzer-registry/builtin-v8", _AUTO_V8_ANALYZERS)

    @classmethod
    def builtin_v7(cls) -> "MappingAnalyzerRegistry":
        return cls("firmatlas.mapping.analyzer-registry/builtin-v7", _AUTO_V7_ANALYZERS)

    @classmethod
    def builtin_v6(cls) -> "MappingAnalyzerRegistry":
        return cls("firmatlas.mapping.analyzer-registry/builtin-v6", _AUTO_V6_ANALYZERS)

    @classmethod
    def builtin_v5(cls) -> "MappingAnalyzerRegistry":
        return cls("firmatlas.mapping.analyzer-registry/builtin-v5", _AUTO_V5_ANALYZERS)

    @classmethod
    def builtin_v4(cls) -> "MappingAnalyzerRegistry":
        return cls("firmatlas.mapping.analyzer-registry/builtin-v4", _AUTO_V5_ANALYZERS)

    @classmethod
    def builtin_v3(cls) -> "MappingAnalyzerRegistry":
        return cls(
            "firmatlas.mapping.analyzer-registry/builtin-v3", _AUTO_V2_ANALYZERS
        )

    @classmethod
    def builtin_v2(cls) -> "MappingAnalyzerRegistry":
        return cls("firmatlas.mapping.analyzer-registry/builtin-v2", _AUTO_V2_ANALYZERS)

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
            "response_fixture": discover_response_fixture,
            "native_relationship": discover_native_relationships,
            "native_command_binding": discover_native_command_table_bindings,
        }
        if analyzer_name not in self.analyzer_names or analyzer_name not in analyzers:
            raise ValueError("source analyzer is unavailable: {}".format(analyzer_name))
        return analyzers[analyzer_name](source, content)


BUILTIN_ANALYZER_REGISTRY = MappingAnalyzerRegistry.builtin()
BUILTIN_ANALYZER_REGISTRY_V12 = MappingAnalyzerRegistry.builtin_v12()
BUILTIN_ANALYZER_REGISTRY_V11 = MappingAnalyzerRegistry.builtin_v11()
BUILTIN_ANALYZER_REGISTRY_V10 = MappingAnalyzerRegistry.builtin_v10()
BUILTIN_ANALYZER_REGISTRY_V9 = MappingAnalyzerRegistry.builtin_v9()
BUILTIN_ANALYZER_REGISTRY_V8 = MappingAnalyzerRegistry.builtin_v8()
BUILTIN_ANALYZER_REGISTRY_V7 = MappingAnalyzerRegistry.builtin_v7()
BUILTIN_ANALYZER_REGISTRY_V6 = MappingAnalyzerRegistry.builtin_v6()
BUILTIN_ANALYZER_REGISTRY_V5 = MappingAnalyzerRegistry.builtin_v5()
BUILTIN_ANALYZER_REGISTRY_V4 = MappingAnalyzerRegistry.builtin_v4()
BUILTIN_ANALYZER_REGISTRY_V3 = MappingAnalyzerRegistry.builtin_v3()
BUILTIN_ANALYZER_REGISTRY_V2 = MappingAnalyzerRegistry.builtin_v2()
BUILTIN_ANALYZER_REGISTRY_V1 = MappingAnalyzerRegistry.builtin_v1()


@dataclass(frozen=True)
class MappingAnalysisRequest:
    root: Path
    firmware_artifact_sha256: str
    inventory_policy: InventoryPolicy = InventoryPolicy()
    profile: MappingAnalysisProfile = MappingAnalysisProfile.auto()
    parameter_clue_policy: ParameterCluePolicy = ParameterCluePolicy()
    response_fixture_policy: ResponseFixturePolicy = ResponseFixturePolicy()
    native_relationship_policy: NativeRelationshipPolicy = NativeRelationshipPolicy()
    native_command_binding_policy: NativeCommandBindingPolicy = NativeCommandBindingPolicy()
    arm_literal_xref_policy: ArmLiteralXrefPolicy = ArmLiteralXrefPolicy()
    frontend_feature_gate_policy: FrontendFeatureGatePolicy = (
        FrontendFeatureGatePolicy()
    )
    frontend_reachability_policy: FrontendReachabilityPolicy = (
        FrontendReachabilityPolicy()
    )

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
        if "native_relationship" in enabled:
            kinds.append("native_relationship")
        if (
            "native_command_binding" in enabled
            and b"daemon_exe_info" in content
        ):
            kinds.append("native_command_binding")
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
    if (
        "response_fixture" in enabled
        and suffix == ".txt"
        and "goform" in pure.parts
        and content.lstrip().startswith((b"{", b"["))
    ):
        kinds.append("response_fixture")
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


_FEATURE_PIVOT_GENERIC_TOKENS = frozenset({
    "config", "feature", "menu", "module", "modules", "server", "status",
    "system", "target", "webroot",
})


def _feature_pivot_anchors(frontend_feature_gates) -> Tuple[ArmFeaturePivotAnchor, ...]:
    if frontend_feature_gates is None:
        return ()
    anchors = set()
    for gate in frontend_feature_gates.gates:
        for token in re.findall(r"[a-z0-9]+", gate.ui_target_id.lower()):
            if (
                len(token) >= 4
                and token not in _FEATURE_PIVOT_GENERIC_TOKENS
            ):
                anchors.add(ArmFeaturePivotAnchor(gate.gate_id, token))
    return tuple(sorted(anchors, key=lambda item: (
        item.feature_token, item.target_ref,
    )))


def _feature_pivot_binding_view(registrar_inventory, native_deep):
    anchored = {
        (
            result.source_path,
            binding.route_token,
            binding.handler_address,
        ): (result, binding)
        for result in native_deep
        for binding in result.bindings
    }
    views = []
    for result in registrar_inventory:
        evidence_by_id = {
            atom.evidence_id: atom for atom in result.evidence_atoms
        }
        bindings = []
        for binding in result.bindings:
            replacement = anchored.get((
                result.source_path,
                binding.route_token,
                binding.handler_address,
            ))
            if replacement is None:
                chosen = binding
            else:
                source_result, chosen = replacement
                if source_result.producer != result.producer:
                    raise ValueError(
                        "feature pivot binding views require one native producer"
                    )
                evidence_by_id.update(
                    (atom.evidence_id, atom)
                    for atom in source_result.evidence_atoms
                    if atom.evidence_id in chosen.evidence_ids
                )
            bindings.append(chosen)
        selected_ids = {
            evidence_id
            for binding in bindings
            for evidence_id in binding.evidence_ids
        }
        views.append(replace(
            result,
            bindings=tuple(bindings),
            evidence_atoms=tuple(sorted(
                (
                    atom for evidence_id, atom in evidence_by_id.items()
                    if evidence_id in selected_ids
                ),
                key=lambda atom: atom.evidence_id,
            )),
        ))
    return tuple(views)


def analyze_extracted_root(
    request: MappingAnalysisRequest,
    registry: MappingAnalyzerRegistry = BUILTIN_ANALYZER_REGISTRY,
) -> MappingAnalysisRun:
    """Analyze one extracted root through the stable mapping orchestration seam."""

    registry.validate_profile(request.profile)
    inventory = build_inventory(request.root, request.inventory_policy)
    selected = []
    inventory_contents = []
    for source in inventory.entries:
        if source.kind not in {"file", "hardlink"} or source.content_sha256 is None:
            continue
        path = request.root.joinpath(*source.canonical_path.split("/"))
        content = path.read_bytes()
        inventory_contents.append((source, content))
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
    frontend_policy = FrontendPolicy(
        enable_inline_form_literal=(
            request.profile.profile_id in {
                "firmatlas.mapping.profile/auto-v6",
                "firmatlas.mapping.profile/auto-v7",
                "firmatlas.mapping.profile/auto-v8",
                "firmatlas.mapping.profile/auto-v9",
                "firmatlas.mapping.profile/auto-v10",
                "firmatlas.mapping.profile/auto-v11",
                "firmatlas.mapping.profile/auto-v12",
                "firmatlas.mapping.profile/auto-v13",
            }
        ),
        enable_tenda_get_set_data=(
            request.profile.profile_id in {
                "firmatlas.mapping.profile/auto-v6",
                "firmatlas.mapping.profile/auto-v7",
                "firmatlas.mapping.profile/auto-v8",
                "firmatlas.mapping.profile/auto-v9",
                "firmatlas.mapping.profile/auto-v10",
                "firmatlas.mapping.profile/auto-v11",
                "firmatlas.mapping.profile/auto-v12",
                "firmatlas.mapping.profile/auto-v13",
            }
        ),
        enable_regex_literals=(
            request.profile.profile_id
            in {
                "firmatlas.mapping.profile/auto-v10",
                "firmatlas.mapping.profile/auto-v11",
                "firmatlas.mapping.profile/auto-v12",
                "firmatlas.mapping.profile/auto-v13",
            }
        ),
    )
    frontend_graph = None
    if (
        "frontend_asset_graph" in request.profile.enabled_analyzers
        and frontend_sources
    ):
        frontend_graph = discover_frontend_asset_graph(tuple(
            FrontendAssetInput(source, content)
            for source, content in frontend_sources
        ), frontend_policy)
        frontend = frontend_graph.results
    else:
        frontend = tuple(
            discover_frontend_requests(source, content, frontend_policy)
            for source, content in frontend_sources
        )
    frontend_feature_gates = (
        discover_frontend_feature_gates(
            tuple(
                FrontendAssetInput(source, content)
                for source, content in frontend_sources
            ),
            frontend_graph,
            request.frontend_feature_gate_policy,
        )
        if (
            "frontend_feature_gate" in request.profile.enabled_analyzers
            and frontend_graph is not None
        )
        else None
    )
    frontend_sources_by_path = {
        source.canonical_path: (source, content)
        for source, content in frontend_sources
    }
    frontend_reachability = tuple(
        discover_frontend_invocation_reachability(
            frontend_sources_by_path[result.source_path][0],
            frontend_sources_by_path[result.source_path][1],
            result,
            replace(
                request.frontend_reachability_policy,
                enable_regex_literals=frontend_policy.enable_regex_literals,
            ),
        )
        for result in frontend
        if (
            "frontend_reachability" in request.profile.enabled_analyzers
            and result.source_path in frontend_sources_by_path
        )
    )
    parameter_clues = None
    parameter_clue_artifacts = ()
    if (
        "parameter_clue" in request.profile.enabled_analyzers
        and frontend_graph is not None
    ):
        frontend_paths = {source.canonical_path for source, _ in frontend_sources}
        parameter_clue_artifacts = tuple(
            ParameterClueArtifact(
                source,
                content,
                ParameterClueArtifactRole.NATIVE
                if content.startswith(b"\x7fELF")
                else ParameterClueArtifactRole.CONFIGURATION
                if source.canonical_path.startswith("etc/")
                or Path(source.canonical_path).suffix.lower()
                in {".conf", ".cfg", ".ini", ".xml"}
                else ParameterClueArtifactRole.SCRIPT
                if Path(source.canonical_path).suffix.lower()
                in {".sh", ".lua", ".php", ".cgi"}
                else ParameterClueArtifactRole.OTHER,
            )
            for source, content in inventory_contents
            if (
                source.canonical_path not in frontend_paths
                and not source.canonical_path.split("/", 1)[0].lower().startswith(
                    ("www", "webroot")
                )
            )
        )
        parameter_clues = trace_frontend_parameter_clues(
            frontend_graph,
            parameter_clue_artifacts,
            request.parameter_clue_policy,
        )
    response_fixtures = tuple(
        discover_response_fixture(
            source, content, request.response_fixture_policy
        )
        for source, content, kinds in selected
        if "response_fixture" in kinds
    )
    native_relationships = tuple(
        discover_native_relationships(
            source, content, request.native_relationship_policy
        )
        for source, content, kinds in selected
        if "native_relationship" in kinds
    )
    native_command_bindings = tuple(
        discover_native_command_table_bindings(
            source, content, policy=request.native_command_binding_policy
        )
        for source, content, kinds in selected
        if "native_command_binding" in kinds
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
    command_handler_literal_xrefs = (
        tuple(
            discover_arm_function_literal_xrefs(
                selected_by_path[result.source_path][0],
                selected_by_path[result.source_path][1],
                tuple(
                    ArmFunctionTarget(binding.binding_id, binding.handler_address)
                    for binding in result.bindings
                ),
                policy=request.arm_literal_xref_policy,
            )
            for result in native_command_bindings
            if result.bindings
        )
        if "arm_literal_xref" in request.profile.enabled_analyzers
        else ()
    )
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
            (
                ArmPicCallsiteProfile.v1()
                if request.profile.profile_id in {
                    "firmatlas.mapping.profile/auto-v1",
                    "firmatlas.mapping.profile/auto-v2",
                }
                else ArmPicCallsiteProfile.v2()
                if request.profile.profile_id in {
                    "firmatlas.mapping.profile/auto-v3",
                    "firmatlas.mapping.profile/auto-v4",
                }
                else ArmPicCallsiteProfile.v3()
                if request.profile.profile_id in {
                    "firmatlas.mapping.profile/auto-v5",
                    "firmatlas.mapping.profile/auto-v6",
                    "firmatlas.mapping.profile/auto-v7",
                    "firmatlas.mapping.profile/auto-v8",
                    "firmatlas.mapping.profile/auto-v9",
                }
                else ArmPicCallsiteProfile()
            ),
        )
        for path, anchors in sorted(anchors_by_path.items())
        if (
            path in selected_by_path and native_by_path[path].machine == "ARM"
            and _arm_pic_callsite_applicable(selected_by_path[path][1])
        )
    )
    tail_handler_targets_by_path = {}
    if "arm_literal_xref" in request.profile.enabled_analyzers:
        for result in native_deep:
            for binding in result.bindings:
                if ":tail-merged:" not in binding.source_construct:
                    continue
                tail_handler_targets_by_path.setdefault(
                    result.source_path, []
                ).append(ArmFunctionTarget(
                    binding.binding_id, binding.handler_address
                ))
    route_handler_literal_xrefs = tuple(
        discover_arm_function_literal_xrefs(
            selected_by_path[path][0],
            selected_by_path[path][1],
            tuple(sorted(set(targets), key=lambda item: (
                item.function_address, item.target_ref,
            ))),
            policy=request.arm_literal_xref_policy,
        )
        for path, targets in sorted(tail_handler_targets_by_path.items())
    )
    arm_literal_xrefs = (
        *command_handler_literal_xrefs,
        *route_handler_literal_xrefs,
    )
    registrar_inventory = tuple(
        discover_arm_pic_registrar_bindings(
            source,
            content,
            ArmPicCallsiteProfile.v2()
            if request.profile.profile_id == "firmatlas.mapping.profile/auto-v4"
            else ArmPicCallsiteProfile.v3()
            if request.profile.profile_id in {
                "firmatlas.mapping.profile/auto-v5",
                "firmatlas.mapping.profile/auto-v6",
                "firmatlas.mapping.profile/auto-v7",
                "firmatlas.mapping.profile/auto-v8",
                "firmatlas.mapping.profile/auto-v9",
            }
            else ArmPicCallsiteProfile(),
        )
        for source, content, _ in selected
        if (
            "arm_pic_registrar" in request.profile.enabled_analyzers
            and source.canonical_path in native_by_path
            and native_by_path[source.canonical_path].machine == "ARM"
            and _arm_pic_callsite_applicable(content)
        )
    )
    anchored_routes = {
        (result.source_path, binding.route_token)
        for result in native_deep for binding in result.bindings
    }
    registrar_catalog = tuple(
        replace(
            result,
            bindings=tuple(
                item for item in result.bindings
                if (result.source_path, item.route_token) not in anchored_routes
            ),
            evidence_atoms=tuple(
                atom for atom in result.evidence_atoms
                if atom.subject_ref in {
                    item.binding_id for item in result.bindings
                    if (result.source_path, item.route_token) not in anchored_routes
                }
            ),
        )
        for result in registrar_inventory
    )
    feature_pivot_anchors = _feature_pivot_anchors(frontend_feature_gates)
    feature_pivot_binding_view = _feature_pivot_binding_view(
        registrar_inventory, native_deep
    )
    arm_feature_pivots = tuple(
        discover_arm_feature_pivots(
            selected_by_path[result.source_path][0],
            selected_by_path[result.source_path][1],
            feature_pivot_anchors,
            result,
            policy=request.arm_literal_xref_policy,
        )
        for result in feature_pivot_binding_view
        if (
            "arm_feature_pivot" in request.profile.enabled_analyzers
            and feature_pivot_anchors
            and result.bindings
            and result.source_path in selected_by_path
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
    set_difference = None
    set_difference_diagnostics = ()
    attribution_artifacts = ()
    if "set_difference" in request.profile.enabled_analyzers:
        if frontend_graph is None:
            set_difference_diagnostics = ("frontend asset graph unavailable",)
        elif not registrar_inventory:
            set_difference_diagnostics = (
                "set difference requires an ARM registrar inventory",
            )
        else:
            attribution_artifacts = (
                tuple(
                    AttributionArtifact(
                        source, content, AttributionArtifactRole.NATIVE_AUXILIARY
                    )
                    for source, content, kinds in selected if "native" in kinds
                )
                if request.profile.profile_id
                in {
                    "firmatlas.mapping.profile/auto-v5",
                    "firmatlas.mapping.profile/auto-v6",
                    "firmatlas.mapping.profile/auto-v7",
                    "firmatlas.mapping.profile/auto-v8",
                    "firmatlas.mapping.profile/auto-v9",
                    "firmatlas.mapping.profile/auto-v10",
                    "firmatlas.mapping.profile/auto-v11",
                    "firmatlas.mapping.profile/auto-v12",
                    "firmatlas.mapping.profile/auto-v13",
                }
                else ()
            )
            set_difference = attribute_frontend_native_set_difference(
                frontend_graph,
                registrar_inventory,
                attribution_artifacts,
                SetDifferencePolicy.route_aware(
                    frontend_auxiliary_only=request.profile.profile_id
                    in {
                        "firmatlas.mapping.profile/auto-v5",
                        "firmatlas.mapping.profile/auto-v6",
                        "firmatlas.mapping.profile/auto-v7",
                        "firmatlas.mapping.profile/auto-v8",
                        "firmatlas.mapping.profile/auto-v9",
                        "firmatlas.mapping.profile/auto-v10",
                        "firmatlas.mapping.profile/auto-v11",
                        "firmatlas.mapping.profile/auto-v12",
                        "firmatlas.mapping.profile/auto-v13",
                    },
                    include_fixed_action_dynamic_query=(
                        request.profile.profile_id
                        in {
                            "firmatlas.mapping.profile/auto-v10",
                            "firmatlas.mapping.profile/auto-v11",
                            "firmatlas.mapping.profile/auto-v12",
                            "firmatlas.mapping.profile/auto-v13",
                        }
                    ),
                ),
                feature_gates=frontend_feature_gates,
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
    if "frontend_feature_gate" in request.profile.enabled_analyzers:
        batches.append(_batch(
            DiscoveryProducerBatch.frontend_feature_gate,
            (frontend_feature_gates,) if frontend_feature_gates is not None else (),
            "auto:frontend-feature-gate",
        ))
    if "frontend_reachability" in request.profile.enabled_analyzers:
        batches.append(_batch(
            DiscoveryProducerBatch.frontend_reachability,
            frontend_reachability,
            "auto:frontend-reachability",
        ))
    if "parameter_clue" in request.profile.enabled_analyzers:
        batches.append(_batch(
            DiscoveryProducerBatch.parameter_clue,
            (parameter_clues,) if parameter_clues is not None else (),
            "auto:parameter-clue",
        ))
    if "response_fixture" in request.profile.enabled_analyzers:
        batches.append(_batch(
            DiscoveryProducerBatch.response_fixture,
            response_fixtures,
            "auto:response-fixture",
        ))
    if "native_relationship" in request.profile.enabled_analyzers:
        batches.append(_batch(
            DiscoveryProducerBatch.native_relationship,
            native_relationships,
            "auto:native-relationship",
        ))
    if "native_command_binding" in request.profile.enabled_analyzers:
        batches.append(_batch(
            DiscoveryProducerBatch.native_command_binding,
            native_command_bindings,
            "auto:native-command-binding",
        ))
    if "arm_literal_xref" in request.profile.enabled_analyzers:
        batches.append(_batch(
            DiscoveryProducerBatch.arm_literal_xref,
            arm_literal_xrefs,
            "auto:arm-literal-xref",
        ))
    if "arm_feature_pivot" in request.profile.enabled_analyzers:
        batches.append(_batch(
            DiscoveryProducerBatch.arm_feature_pivot,
            arm_feature_pivots,
            "auto:arm-feature-pivot",
        ))
    if "arm_pic_callsite" in request.profile.enabled_analyzers:
        batches.append(_batch(
            DiscoveryProducerBatch.native_deep,
            native_deep,
            "auto:arm-pic-callsite",
        ))
    if "arm_pic_registrar" in request.profile.enabled_analyzers:
        batches.append(_batch(
            DiscoveryProducerBatch.native_deep,
            registrar_catalog,
            "auto:arm-pic-registrar-unreferenced",
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
        set_difference=set_difference,
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
    if "parameter_clue" in request.profile.enabled_analyzers:
        stages.insert(4, MappingAnalysisStage(
            "parameter_clue",
            parameter_clues.coverage_status if parameter_clues is not None
            else CoverageStatus.NOT_APPLICABLE,
            len(parameter_clue_artifacts),
            len(parameter_clues.assessments) if parameter_clues is not None else 0,
            parameter_clues.diagnostics
            if parameter_clues is not None else ("frontend asset graph unavailable",),
        ))
    if "response_fixture" in request.profile.enabled_analyzers:
        stages.insert(5, _stage(
            "response_fixture",
            response_fixtures,
            sum(len(item.fields) for item in response_fixtures),
        ))
    if "native_relationship" in request.profile.enabled_analyzers:
        stages.insert(6, _stage(
            "native_relationship",
            native_relationships,
            sum(len(item.relationships) for item in native_relationships),
        ))
    if "native_command_binding" in request.profile.enabled_analyzers:
        stages.insert(7, _stage(
            "native_command_binding",
            native_command_bindings,
            sum(len(item.bindings) for item in native_command_bindings),
        ))
    if "arm_literal_xref" in request.profile.enabled_analyzers:
        stages.insert(8, _stage(
            "arm_literal_xref",
            arm_literal_xrefs,
            sum(len(item.xrefs) for item in arm_literal_xrefs),
        ))
    if "arm_feature_pivot" in request.profile.enabled_analyzers:
        stages.insert(9, MappingAnalysisStage(
            "arm_feature_pivot",
            (
                CoverageStatus.COMPLETED
                if arm_feature_pivots and all(
                    item.coverage_status is CoverageStatus.COMPLETED
                    for item in arm_feature_pivots
                )
                else CoverageStatus.PARTIAL
                if arm_feature_pivots
                else CoverageStatus.NOT_APPLICABLE
            ),
            len(arm_feature_pivots),
            sum(len(item.pivots) for item in arm_feature_pivots),
            tuple(sorted({
                diagnostic
                for item in arm_feature_pivots
                for diagnostic in item.diagnostics
            })) if arm_feature_pivots else (
                "no frontend feature anchors"
                if not feature_pivot_anchors
                else "no applicable ARM registrar bindings",
            ),
        ))
    if "frontend_feature_gate" in request.profile.enabled_analyzers:
        graph_stage_index = next(
            index for index, item in enumerate(stages)
            if item.stage_name == "frontend_asset_graph"
        )
        stages.insert(graph_stage_index + 1, MappingAnalysisStage(
            "frontend_feature_gate",
            frontend_feature_gates.coverage_status
            if frontend_feature_gates is not None
            else CoverageStatus.NOT_APPLICABLE,
            len(frontend_sources),
            len(frontend_feature_gates.gates)
            if frontend_feature_gates is not None else 0,
            frontend_feature_gates.diagnostics
            if frontend_feature_gates is not None
            else ("frontend asset graph unavailable",),
        ))
    if "frontend_reachability" in request.profile.enabled_analyzers:
        reachability_anchor_name = (
            "frontend_feature_gate"
            if any(
                item.stage_name == "frontend_feature_gate" for item in stages
            )
            else "frontend_asset_graph"
            if any(
                item.stage_name == "frontend_asset_graph" for item in stages
            )
            else "frontend"
        )
        reachability_anchor_index = next(
            index for index, item in enumerate(stages)
            if item.stage_name == reachability_anchor_name
        )
        stages.insert(reachability_anchor_index + 1, _stage(
            "frontend_reachability",
            frontend_reachability,
            sum(len(item.invocations) for item in frontend_reachability),
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
    if "arm_pic_registrar" in request.profile.enabled_analyzers:
        stages.append(_stage(
            "arm_pic_registrar", registrar_inventory,
            sum(len(item.bindings) for item in registrar_inventory),
        ))
    if "set_difference" in request.profile.enabled_analyzers:
        stages.append(MappingAnalysisStage(
            "set_difference",
            set_difference.coverage_status if set_difference is not None
            else CoverageStatus.NOT_APPLICABLE,
            len(attribution_artifacts) or sum(
                len(item.bindings) for item in registrar_inventory
            ),
            len(set_difference.attributions) if set_difference is not None else 0,
            tuple(item.code for item in set_difference.diagnostics)
            if set_difference is not None else set_difference_diagnostics,
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
