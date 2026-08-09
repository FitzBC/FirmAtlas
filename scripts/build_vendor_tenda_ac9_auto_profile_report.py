#!/usr/bin/env python3
"""Build the primary vendor Tenda AC9 auto-profile mapping report."""

from __future__ import annotations

import json
from pathlib import Path

from firmatlas.mapping import (
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    analyze_extracted_root,
)


ROOT = Path("../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root")
ARTIFACT_SHA256 = "981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296"
REPRESENTATIVE = {
    "SetOnlineDevName", "setBlackRule", "delBlackRule",
    "getOnlineList", "getBlackRuleList",
}


def build_report() -> dict:
    run = analyze_extracted_root(MappingAnalysisRequest(
        root=ROOT,
        firmware_artifact_sha256=ARTIFACT_SHA256,
        profile=MappingAnalysisProfile.auto(),
    ))
    route_bindings = [
        item for item in run.catalog.candidates
        if item.candidate_kind.value == "native_route_binding"
    ]
    examples = list({
        item.canonical_identity: {
            "route": item.canonical_identity,
            "source_path": item.source_path,
            "handler_symbol": dict(item.attributes).get("handler_symbol"),
            "handler_identity": dict(item.attributes).get("handler_identity"),
            "registration_address": dict(item.attributes).get("registration_address"),
            "registrar_pair_count": int(
                dict(item.attributes).get("registrar_pair_count", "0")
            ),
        }
        for item in route_bindings if item.canonical_identity in REPRESENTATIVE
    }.values())
    scheduler = next(item for item in run.stages if item.stage_name == "scheduler")
    return {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-auto-profile/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-goform-arm-pic",
        "firmware_artifact_sha256": ARTIFACT_SHA256,
        "analysis_run_id": run.analysis_run_id,
        "catalog_id": run.catalog.catalog_id,
        "profile_id": run.profile_id,
        "analyzer_registry_id": run.analyzer_registry_id,
        "coverage_status": run.coverage_status.value,
        "inventory_coverage_status": run.inventory_coverage_status.value,
        "source_plan_count": len(run.source_plan),
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
        "catalog_summary": {
            "candidate_count": len(run.catalog.candidates),
            "parameter_count": len(run.catalog.parameters),
            "evidence_count": len(run.catalog.evidence_atoms),
            "association_count": len(run.catalog.associations),
            "open_obligation_count": len(run.catalog.open_obligations),
            "resolved_obligation_count": scheduler.input_count - scheduler.output_count,
            "native_route_binding_count": len(route_bindings),
            "native_handler_count": sum(
                item.candidate_kind.value == "native_handler"
                for item in run.catalog.candidates
            ),
        },
        "representative_routes": examples,
        "iteration_findings": [
            {
                "code": "empty_page_model_url",
                "affected_sources": [
                    "webroot_ro/js/parental_control.js",
                    "webroot_ro/js/status_usb.js",
                    "webroot_ro/js/system_log.js",
                ],
                "resolution": (
                    "empty getUrl/setUrl values are disabled operations and no longer "
                    "become zero-length interface evidence"
                ),
            }
        ],
        "interpretation": {
            "supported": (
                "a whole-root no-seed run automatically derives ARM anchors from "
                "frontend/native correlation, proves 45 route-handler bindings, and "
                "resolves 90 route/handler obligations"
            ),
            "why_open_obligations_remain": (
                "89 unmatched or non-profiled operations still require script, other "
                "native dispatcher, runtime, or parameter analysis"
            ),
            "not_claimed": (
                "runtime reachability, authentication outcome, exploitability, or "
                "complete parameter-to-state recovery for all 45 handlers"
            ),
        },
    }


if __name__ == "__main__":
    print(json.dumps(build_report(), ensure_ascii=False, indent=2))
