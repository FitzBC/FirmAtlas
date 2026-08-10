"""Evidence-backed frontend feature visibility gates and gated requests."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import posixpath
import re
from pathlib import PurePosixPath
from typing import Optional, Tuple

from .domain import (
    AnalyzerIdentity,
    CoverageStatus,
    EvidenceAtom,
    ObservationKind,
    SpanKind,
)
from .evidence import EvidenceClaim, SpanSelection, capture_evidence
from .frontend import FrontendAssetGraphResult, FrontendAssetInput


FRONTEND_FEATURE_GATE_SCHEMA_VERSION = (
    "firmatlas.mapping.frontend-feature-gate/v1alpha1"
)
_PRODUCER = AnalyzerIdentity("frontend-feature-gate", "0.1.0")
_MACRO = re.compile(
    rb"\bvar\s+(?P<symbol>CONFIG_[A-Z0-9_]+)\s*=\s*"
    rb"(?P<quote>[\"'])(?P<value>[^\"']+)(?P=quote)\s*;?"
)
_FEATURE_MAP = re.compile(
    rb"(?P<quote>[\"'])(?P<target>[A-Za-z0-9_-]+)(?P=quote)\s*:\s*"
    rb"(?P<symbol>CONFIG_[A-Z0-9_]+)"
)
_MODULES_MAP = re.compile(
    rb"\bmodulesObj\s*=\s*\{(?P<body>.{0,8192}?)\}",
    re.DOTALL,
)
_REVEAL = re.compile(
    rb"if\s*\(\s*modulesObj\s*\[\s*prop\s*\]\s*={2,3}\s*"
    rb"(?P<quote>[\"'])(?P<enabled>[^\"']+)(?P=quote)\s*\)\s*\{"
    rb".{0,512}?removeClass\s*\(\s*[\"']none[\"']\s*\)",
    re.DOTALL,
)
_SCRIPT = re.compile(
    rb"<script\b[^>]{0,2048}?\bsrc\s*=\s*"
    rb"(?P<quote>[\"'])(?P<src>[^\"']+)(?P=quote)[^>]*>",
    re.IGNORECASE,
)


class FrontendFeatureGateStatus(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"


@dataclass(frozen=True)
class FrontendFeatureGatePolicy:
    max_assets: int = 10_000
    max_total_bytes: int = 256 * 1024 * 1024
    max_gates: int = 10_000

    def __post_init__(self) -> None:
        if (
            self.max_assets <= 0
            or self.max_total_bytes <= 0
            or self.max_gates <= 0
        ):
            raise ValueError("frontend feature gate budgets must be positive")


@dataclass(frozen=True)
class FrontendFeatureGate:
    gate_id: str
    status: FrontendFeatureGateStatus
    feature_symbol: str
    configured_value: str
    enabled_value: str
    ui_target_id: str
    page_path: str
    script_paths: Tuple[str, ...]
    request_candidate_ids: Tuple[str, ...]
    request_endpoints: Tuple[str, ...]
    source_construct: str
    evidence_ids: Tuple[str, ...]


@dataclass(frozen=True)
class FrontendFeatureGateResult:
    source_path: str
    coverage_status: CoverageStatus
    processed_bytes: int
    producer: AnalyzerIdentity
    gates: Tuple[FrontendFeatureGate, ...]
    evidence_atoms: Tuple[EvidenceAtom, ...]
    diagnostics: Tuple[str, ...] = ()
    schema_version: str = FRONTEND_FEATURE_GATE_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            **asdict(self),
            "coverage_status": self.coverage_status.value,
            "producer": asdict(self.producer),
            "gates": [
                {**asdict(item), "status": item.status.value}
                for item in self.gates
            ],
            "evidence_atoms": [item.to_dict() for item in self.evidence_atoms],
        }


def _identity(prefix: str, *values: object) -> str:
    encoded = json.dumps(
        values, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return "{}:{}".format(prefix, hashlib.sha256(encoded).hexdigest())


def _resolve_relative(base_path: str, reference: str) -> Optional[str]:
    reference = reference.split("?", 1)[0].split("#", 1)[0]
    if not reference or "://" in reference or reference.startswith("//"):
        return None
    if reference.startswith("/"):
        root = PurePosixPath(base_path).parts[0]
        resolved = posixpath.normpath("{}/{}".format(root, reference.lstrip("/")))
    else:
        resolved = posixpath.normpath(
            posixpath.join(posixpath.dirname(base_path), reference)
        )
    if resolved == ".." or resolved.startswith("../"):
        return None
    return resolved


def _route_pattern(target: bytes) -> re.Pattern[bytes]:
    return re.compile(
        rb"case\s*[\"']" + re.escape(target) + rb"[\"']\s*:"
        rb".{0,1024}?showIframe\s*\(.{0,1024}?"
        rb"(?P<quote>[\"'])(?P<page>[^\"']+\.html)(?P=quote)",
        re.DOTALL,
    )


def _resolve_page_path(
    script_path: str, reference: str, known_paths: set,
) -> Optional[str]:
    candidates = []
    relative = _resolve_relative(script_path, reference)
    if relative is not None:
        candidates.append(relative)
    parts = PurePosixPath(script_path).parts
    if parts:
        candidates.append(posixpath.normpath(
            "{}/{}".format(parts[0], reference.lstrip("/"))
        ))
    matches = tuple(dict.fromkeys(
        item for item in candidates if item in known_paths
    ))
    return matches[0] if len(matches) == 1 else None


def discover_frontend_feature_gates(
    assets: Tuple[FrontendAssetInput, ...],
    frontend: FrontendAssetGraphResult,
    policy: FrontendFeatureGatePolicy = FrontendFeatureGatePolicy(),
) -> FrontendFeatureGateResult:
    """Link literal product feature flags to gated pages and their requests."""

    if len(assets) > policy.max_assets:
        return FrontendFeatureGateResult(
            "frontend-assets",
            CoverageStatus.SKIPPED_BY_POLICY,
            0,
            _PRODUCER,
            (),
            (),
            ("frontend_feature_gate.asset_budget_exceeded",),
        )
    paths = tuple(item.source.canonical_path for item in assets)
    if len(paths) != len(set(paths)):
        raise ValueError("frontend feature gate requires unique source paths")
    total_bytes = sum(len(item.content) for item in assets)
    if total_bytes > policy.max_total_bytes:
        return FrontendFeatureGateResult(
            "frontend-assets",
            CoverageStatus.SKIPPED_BY_POLICY,
            0,
            _PRODUCER,
            (),
            (),
            ("frontend_feature_gate.byte_budget_exceeded",),
        )
    by_path = {item.source.canonical_path: item for item in assets}
    for asset in assets:
        if (
            asset.source.content_sha256 is None
            or asset.source.size != len(asset.content)
            or hashlib.sha256(asset.content).hexdigest()
            != asset.source.content_sha256
        ):
            raise ValueError("frontend feature gate content does not match inventory")

    requests_by_path = {
        result.source_path: result.candidates for result in frontend.results
    }
    macros = {}
    for asset in assets:
        for match in _MACRO.finditer(asset.content):
            symbol = match.group("symbol").decode("utf-8")
            macros.setdefault(symbol, []).append((asset, match))

    gates = []
    evidence = {}
    limited = False
    for main_asset in assets:
        for modules_map in _MODULES_MAP.finditer(main_asset.content):
            reveal = _REVEAL.search(
                main_asset.content,
                modules_map.end(),
                min(len(main_asset.content), modules_map.end() + 4096),
            )
            if reveal is None:
                continue
            enabled_value = reveal.group("enabled").decode("utf-8")
            feature_matches = _FEATURE_MAP.finditer(
                main_asset.content,
                modules_map.start("body"),
                modules_map.end("body"),
            )
            for feature_match in feature_matches:
                symbol = feature_match.group("symbol").decode("utf-8")
                definitions = macros.get(symbol, ())
                if len(definitions) != 1:
                    continue
                target_bytes = feature_match.group("target")
                route = _route_pattern(target_bytes).search(main_asset.content)
                if route is None:
                    continue
                page_reference = route.group("page").decode("utf-8")
                page_path = _resolve_page_path(
                    main_asset.source.canonical_path,
                    page_reference,
                    set(by_path),
                )
                page_asset = by_path.get(page_path or "")
                if page_asset is None:
                    continue
                scripts = []
                script_matches = []
                for script_match in _SCRIPT.finditer(page_asset.content):
                    script_path = _resolve_relative(
                        page_asset.source.canonical_path,
                        script_match.group("src").decode("utf-8"),
                    )
                    if script_path is None or script_path not in by_path:
                        continue
                    if (
                        PurePosixPath(script_path).stem
                        != PurePosixPath(page_path or "").stem
                    ):
                        continue
                    scripts.append(script_path)
                    script_matches.append(script_match)
                request_candidates = tuple(sorted(
                    (
                        candidate
                        for script_path in scripts
                        for candidate in requests_by_path.get(script_path, ())
                    ),
                    key=lambda item: (item.endpoint, item.candidate_id),
                ))
                if not request_candidates:
                    continue
                if len(gates) >= policy.max_gates:
                    limited = True
                    break
                definition_asset, macro_match = definitions[0]
                configured_value = macro_match.group("value").decode("utf-8")
                target = target_bytes.decode("utf-8")
                gate_id = _identity(
                    "frontend-feature-gate",
                    symbol,
                    configured_value,
                    enabled_value,
                    target,
                    page_path,
                    tuple(item.candidate_id for item in request_candidates),
                )
                claims = (
                (
                    definition_asset,
                    macro_match.start("value"),
                    macro_match.end("value"),
                    "declares_feature_value",
                    "{}={}".format(symbol, configured_value),
                ),
                (
                    main_asset,
                    feature_match.start(),
                    feature_match.end(),
                    "maps_feature_to_ui_target",
                    "{}->{}".format(symbol, target),
                ),
                (
                    main_asset,
                    reveal.start(),
                    reveal.end(),
                    "reveals_feature_target",
                    "{}={}".format(target, enabled_value),
                ),
                (
                    main_asset,
                    route.start("page"),
                    route.end("page"),
                    "routes_feature_target_to_page",
                    "{}->{}".format(target, page_path),
                ),
                *(
                    (
                        page_asset,
                        script_match.start("src"),
                        script_match.end("src"),
                        "loads_feature_script",
                        "{}->{}".format(page_path, script_path),
                    )
                    for script_path, script_match in zip(scripts, script_matches)
                ),
            )
                evidence_ids = []
                for source_asset, start, end, capability, object_value in claims:
                    atom = capture_evidence(
                    source_asset.source,
                    source_asset.content,
                    SpanSelection(SpanKind.TEXT_UTF8, start, end),
                    EvidenceClaim(
                        gate_id,
                        capability,
                        object_value,
                        ObservationKind.DETERMINISTIC_DERIVED,
                        capability,
                        1.0,
                    ),
                    _PRODUCER,
                )
                    evidence[atom.evidence_id] = atom
                    evidence_ids.append(atom.evidence_id)
                gates.append(FrontendFeatureGate(
                gate_id,
                (
                    FrontendFeatureGateStatus.ENABLED
                    if configured_value == enabled_value
                    else FrontendFeatureGateStatus.DISABLED
                ),
                symbol,
                configured_value,
                enabled_value,
                target,
                page_path or "",
                tuple(sorted(set(scripts))),
                tuple(item.candidate_id for item in request_candidates),
                tuple(item.endpoint for item in request_candidates),
                "javascript.feature-map+visibility-loop+switch-iframe+same-stem-html-script",
                tuple(evidence_ids),
                ))
            if limited:
                break
        if limited:
            break

    diagnostics = []
    if limited:
        diagnostics.append("frontend_feature_gate.gate_budget_exceeded")
    if frontend.coverage_status is not CoverageStatus.COMPLETED:
        diagnostics.append(
            "frontend_feature_gate.upstream_frontend_coverage={}".format(
                frontend.coverage_status.value
            )
        )
    return FrontendFeatureGateResult(
        "frontend-assets",
        (
            CoverageStatus.PARTIAL
            if limited or frontend.coverage_status is not CoverageStatus.COMPLETED
            else CoverageStatus.COMPLETED
        ),
        total_bytes,
        _PRODUCER,
        tuple(sorted(gates, key=lambda item: item.gate_id)),
        tuple(sorted(evidence.values(), key=lambda item: item.evidence_id)),
        tuple(diagnostics),
    )
