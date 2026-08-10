#!/usr/bin/env python3
"""Build the R2-15 AC9-primary / AC18-positive-control DLNA report."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from firmatlas.mapping import (
    BUILTIN_ANALYZER_REGISTRY_V12,
    DiscoveryCandidateKind,
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    analyze_extracted_root,
)
from build_vendor_tenda_ac9_registrar_inventory_report import (
    ARTIFACT_SHA256 as AC9_ARTIFACT_SHA256,
    ROOT as AC9_ROOT,
)


AC18_ARTIFACT_SHA256 = (
    "359d2feac6a7d28bd45a11e60a7062945152f516978deb7d54daea84d9211410"
)
_DLNA_ROUTES = {"GetDlnaCfg", "SetDlnaCfg", "expandDlnaFile"}
_FIXTURES = (
    "webroot_ro/goform/GetDlnaCfg.txt",
    "webroot_ro/goform/SetDlnaCfg.txt",
    "webroot_ro/goform/expandDlnaFile.txt",
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _normalized_asset_sha(path: Path) -> str:
    content = re.sub(rb"[0-9a-f]{32}", b"<ASSET_HASH>", path.read_bytes())
    return hashlib.sha256(content).hexdigest()


def _sample(root: Path, artifact_sha256: str) -> tuple[dict, object]:
    run = analyze_extracted_root(
        MappingAnalysisRequest(
            root,
            artifact_sha256,
            profile=MappingAnalysisProfile.auto_v12(),
        ),
        registry=BUILTIN_ANALYZER_REGISTRY_V12,
    )
    pivots = sorted(
        (
            {
                "candidate_id": item.candidate_id,
                "source_path": item.source_path,
                **dict(item.attributes),
                "evidence_ids": list(item.evidence_ids),
            }
            for item in run.catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.ARM_FEATURE_PIVOT
            and dict(item.attributes).get("feature_token") == "dlna"
        ),
        key=lambda item: (
            item["route_token"], item["literal_value"], item["candidate_id"]
        ),
    )
    bindings = sorted(
        (
            {
                "candidate_id": item.candidate_id,
                "route_token": item.canonical_identity,
                "source_path": item.source_path,
                **dict(item.attributes),
                "evidence_ids": list(item.evidence_ids),
            }
            for item in run.catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.NATIVE_ROUTE_BINDING
            and item.canonical_identity in _DLNA_ROUTES
        ),
        key=lambda item: item["route_token"],
    )
    gates = sorted(
        (
            {
                "feature_symbol": item.canonical_identity,
                **dict(item.attributes),
                "evidence_ids": list(item.evidence_ids),
            }
            for item in run.catalog.candidates
            if item.candidate_kind is DiscoveryCandidateKind.FRONTEND_FEATURE_GATE
        ),
        key=lambda item: item["feature_symbol"],
    )
    dlna_gate = next(
        item for item in gates if item["feature_symbol"] == "CONFIG_DLNA_SERVER"
    )
    refresh = sorted(
        (
            {
                "candidate_id": item.candidate_id,
                "claim_status": item.claim_status.value,
                **dict(item.attributes),
                "evidence_ids": list(item.evidence_ids),
            }
            for item in run.catalog.candidates
            if item.candidate_kind
            is DiscoveryCandidateKind.SET_DIFFERENCE_ATTRIBUTION
            and item.canonical_identity == "refreshDLNA"
        ),
        key=lambda item: item["candidate_id"],
    )
    return ({
        "firmware_artifact_sha256": artifact_sha256,
        "analysis_run_id": run.analysis_run_id,
        "catalog_id": run.catalog.catalog_id,
        "profile_id": run.profile_id,
        "analyzer_registry_id": run.analyzer_registry_id,
        "coverage_status": run.coverage_status.value,
        "mapping_summary": {
            "candidate_count": len(run.catalog.candidates),
            "evidence_count": len(run.catalog.evidence_atoms),
            "open_obligation_count": len(run.catalog.open_obligations),
            "dlna_feature_pivot_count": len(pivots),
            "dlna_route_binding_count": len(bindings),
        },
        "stages": [
            {
                "name": item.stage_name,
                "coverage_status": item.coverage_status.value,
                "input_count": item.input_count,
                "output_count": item.output_count,
                "diagnostics": list(item.diagnostics),
            }
            for item in run.stages
        ],
        "dlna_feature_gate": dlna_gate,
        "dlna_feature_pivots": pivots,
        "dlna_route_bindings": bindings,
        "refresh_dlna_set_difference": refresh,
    }, run)


def build(ac18_root: Path) -> dict:
    ac9, _ = _sample(AC9_ROOT, AC9_ARTIFACT_SHA256)
    ac18, _ = _sample(ac18_root, AC18_ARTIFACT_SHA256)
    if (
        ac9["dlna_feature_gate"]["configured_value"] != "n"
        or ac18["dlna_feature_gate"]["configured_value"] != "y"
    ):
        raise RuntimeError("AC9/AC18 DLNA feature-state expectation changed")
    if (
        ac9["mapping_summary"]["dlna_feature_pivot_count"] != 3
        or {item["route_token"] for item in ac9["dlna_feature_pivots"]}
        != {"GetUSBStatus"}
        or ac9["dlna_route_bindings"]
    ):
        raise RuntimeError("AC9 bounded DLNA pivot expectation changed")
    if {item["route_token"] for item in ac18["dlna_route_bindings"]} != _DLNA_ROUTES:
        raise RuntimeError("AC18 enabled DLNA binding positive control changed")
    if {
        item["route_token"]: item["handler_symbol"]
        for item in ac18["dlna_route_bindings"]
    } != {
        "GetDlnaCfg": "getDLNAserverCfg",
        "SetDlnaCfg": "formDLNAserver",
        "expandDlnaFile": "formExpandDlnaFile",
    }:
        raise RuntimeError("AC18 enabled DLNA handler positive control changed")
    if (
        len(ac18["dlna_feature_pivots"]) != 17
        or [
            item["attribution_kind"]
            for item in ac9["refresh_dlna_set_difference"]
        ] != ["frontend_feature_disabled"]
        or [
            item["attribution_kind"]
            for item in ac18["refresh_dlna_set_difference"]
        ] != ["frontend_operation_native_absent"]
    ):
        raise RuntimeError("AC9/AC18 DLNA pivot or refresh negative control changed")

    asset_shas = {
        "ac9": _normalized_asset_sha(AC9_ROOT / "webroot_ro/js/dlna.js"),
        "ac18": _normalized_asset_sha(ac18_root / "webroot_ro/js/dlna.js"),
    }
    fixture_shas = {
        path: {"ac9": _sha(AC9_ROOT / path), "ac18": _sha(ac18_root / path)}
        for path in _FIXTURES
    }
    if len(set(asset_shas.values())) != 1 or any(
        len(set(item.values())) != 1 for item in fixture_shas.values()
    ):
        raise RuntimeError("AC9/AC18 frontend-family equivalence changed")

    prior = Path(
        "docs/firmware-mapping/samples/"
        "r2-14-vendor-tenda-ac9-disabled-dlna-feature.json"
    )
    return {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-15/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-with-official-ac18-positive-control",
        "artifact_provenance": {
            "ac9_primary": {
                "artifact_kind": "benchmark-repacked-rootfs-zip",
                "artifact_sha256": AC9_ARTIFACT_SHA256,
                "embedded_version": "V15.03.05.19 / ac9_V2.0.0.0(6318)_cn",
                "source": "FirmEmuHub BM-2024-00012",
            },
            "ac18_positive_control": {
                "artifact_kind": "official-vendor-raw-firmware-zip",
                "release_version": "V15.03.05.19(6318)",
                "release_page": "https://www.tenda.com.cn/download/detail-2683.html",
                "download_url": (
                    "https://static.tenda.com.cn/tdcweb/download/uploadfile/AC18/"
                    "ac18_kf_V15.03.05.19%286318_%29_cn.zip"
                ),
                "zip_sha256": AC18_ARTIFACT_SHA256,
                "firmware_bin_sha256": (
                    "7f226515e19d9f8243068e880da74135da495df78821d6044a92f40af29811a5"
                ),
                "httpd_sha256": (
                    "addecb1e2d5e7befe200b75d925c52d84f3d60db5f18c1071136648e0f70d388"
                ),
            },
        },
        "evidence_boundary": (
            "Feature pivots are candidate investigation edges. AC18 bindings are "
            "facts about AC18 only and do not resolve the AC9 handler-owner obligation."
        ),
        "ac9_primary": ac9,
        "ac18_positive_control": ac18,
        "family_comparison": {
            "normalized_dlna_asset_sha256": asset_shas,
            "fixture_sha256": fixture_shas,
            "feature_transition": "CONFIG_DLNA_SERVER:n->y",
            "route_binding_transition": "three-routes:absent->registered",
            "interpretation": "family-template-plus-build-pruning-candidate",
        },
        "historical_vulnerability_context": {
            "source_report": prior.as_posix(),
            "source_report_sha256": _sha(prior),
            "scope_rule": (
                "Historical CVE route/parameter records seed expectations only; "
                "they do not transfer AC18 vulnerability status to AC9."
            ),
        },
        "open_obligations": [
            "obtain and partition-compare an official AC9 raw firmware image",
            "exclude alias/hash dispatch and omitted conditional components in AC9",
            "recover active frontend invocation reachability for refreshDLNA",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ac18-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = build(args.ac18_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
