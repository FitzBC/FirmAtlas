"""Deterministic orchestration for an already extracted firmware root."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Tuple

from .correlation import correlate_frontend_native
from .discovery_catalog import (
    DiscoveryCatalog,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    assemble_discovery_catalog,
)
from .domain import CoverageStatus
from .frontend import discover_frontend_requests
from .inventory import InventoryPolicy, SourceArtifactEntry, build_inventory
from .native import discover_native_hints
from .script_backend import discover_script_backend
from .scheduler import run_obligation_scheduler
from .web_config import discover_web_configuration


MAPPING_ANALYSIS_RUN_SCHEMA_VERSION = "firmatlas.mapping.analysis-run/v1alpha1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FRONTEND_SUFFIXES = frozenset({".js", ".html", ".htm", ".php", ".asp"})
_SCRIPT_SUFFIXES = frozenset({".php", ".asp", ".lua", ".cgi"})


@dataclass(frozen=True)
class MappingAnalysisRequest:
    root: Path
    firmware_artifact_sha256: str
    inventory_policy: InventoryPolicy = InventoryPolicy()

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
            "coverage_status": self.coverage_status.value,
            "source_plan": [asdict(item) for item in self.source_plan],
            "stages": [
                {**asdict(item), "coverage_status": item.coverage_status.value}
                for item in self.stages
            ],
            "catalog": self.catalog.to_dict(),
        }


def _classify(path: str, content: bytes) -> Tuple[str, ...]:
    if content.startswith(b"\x7fELF"):
        return ("native",)
    pure = Path(path)
    suffix = pure.suffix.lower()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    kinds = []
    if suffix in _FRONTEND_SUFFIXES:
        kinds.append("frontend")
    if suffix in _SCRIPT_SUFFIXES:
        kinds.append("script_backend")
    lowered = path.lower()
    if suffix == ".sh" and "/cgi-bin/" in "/{}".format(lowered):
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
    if known_config or init_script:
        kinds.append("web_configuration")
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


def analyze_extracted_root(request: MappingAnalysisRequest) -> MappingAnalysisRun:
    """Analyze one extracted root through the stable mapping orchestration seam."""

    inventory = build_inventory(request.root, request.inventory_policy)
    selected = []
    for source in inventory.entries:
        if source.kind not in {"file", "hardlink"} or source.content_sha256 is None:
            continue
        path = request.root.joinpath(*source.canonical_path.split("/"))
        content = path.read_bytes()
        kinds = _classify(source.canonical_path, content)
        if kinds:
            selected.append((source, content, kinds))
    selected.sort(key=lambda item: item[0].canonical_path)
    plan = tuple(
        MappingSourcePlanEntry(source.canonical_path, kinds, source.content_sha256 or "")
        for source, _, kinds in selected
    )

    frontend = tuple(
        discover_frontend_requests(source, content)
        for source, content, kinds in selected if "frontend" in kinds
    )
    web = tuple(
        discover_web_configuration(source, content)
        for source, content, kinds in selected if "web_configuration" in kinds
    )
    scripts = tuple(
        discover_script_backend(source, content)
        for source, content, kinds in selected if "script_backend" in kinds
    )
    native = tuple(
        discover_native_hints(source, content)
        for source, content, kinds in selected if "native" in kinds
    )
    correlation = correlate_frontend_native(frontend, native) if frontend and native else None
    scheduler = run_obligation_scheduler(
        correlation.obligations if correlation is not None else (), ()
    )
    catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
        firmware_artifact_sha256=request.firmware_artifact_sha256,
        source_inventory_sha256=inventory.inventory_sha256,
        source_inventory_coverage_status=inventory.coverage_status,
        batches=(
            _batch(DiscoveryProducerBatch.frontend, frontend, "auto:frontend"),
            _batch(DiscoveryProducerBatch.web_configuration, web, "auto:web-configuration"),
            _batch(DiscoveryProducerBatch.script_backend, scripts, "auto:script-backend"),
            _batch(DiscoveryProducerBatch.native, native, "auto:native"),
        ),
        correlation=correlation,
        scheduler=scheduler,
    ))
    stages = (
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
        MappingAnalysisStage(
            "scheduler", scheduler.coverage_status,
            len(correlation.obligations) if correlation is not None else 0,
            len(scheduler.open_obligations),
            tuple(item.code for item in scheduler.diagnostics),
        ),
        MappingAnalysisStage(
            "catalog", catalog.coverage_status, len(plan), len(catalog.candidates),
            tuple(item.diagnostic for item in catalog.coverage if item.diagnostic),
        ),
    )
    identity_payload = json.dumps({
        "schema": MAPPING_ANALYSIS_RUN_SCHEMA_VERSION,
        "firmware": request.firmware_artifact_sha256,
        "inventory": inventory.inventory_sha256,
        "plan": [asdict(item) for item in plan],
        "catalog": catalog.catalog_id,
        "stages": [
            {**asdict(item), "coverage_status": item.coverage_status.value}
            for item in stages
        ],
    }, sort_keys=True, separators=(",", ":")).encode()
    run_id = "mapping-analysis-run:{}".format(hashlib.sha256(identity_payload).hexdigest())
    return MappingAnalysisRun(
        run_id, request.firmware_artifact_sha256, inventory.inventory_sha256,
        inventory.coverage_status, plan, stages, catalog,
    )
