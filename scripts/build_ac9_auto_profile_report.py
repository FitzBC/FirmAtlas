#!/usr/bin/env python3
"""Build the R2-02 auto-profile report for OpenWrt Tenda AC9."""

from __future__ import annotations

from collections import Counter
import json

from build_ac9_analysis_run_report import ARTIFACT_SHA256, ROOT
from firmatlas.mapping import MappingAnalysisProfile, MappingAnalysisRequest, analyze_extracted_root


def build_report() -> dict:
    run = analyze_extracted_root(MappingAnalysisRequest(
        root=ROOT,
        firmware_artifact_sha256=ARTIFACT_SHA256,
        profile=MappingAnalysisProfile.auto(),
    ))
    bindings = [
        item for item in run.catalog.candidates
        if item.candidate_kind.value == "ubus_backend_binding"
    ]
    binding_status = Counter(
        dict(item.attributes).get("binding_status") for item in bindings
    )
    handler_examples = list({
        (
            item.canonical_identity,
            item.source_path,
            dict(item.attributes).get("handler_identity"),
        ): {
            "logical_operation": item.canonical_identity,
            "source_path": item.source_path,
            "handler_identity": dict(item.attributes).get("handler_identity"),
        }
        for item in bindings
        if dict(item.attributes).get("handler_identity")
        and item.canonical_identity in {"ubus://file/read", "ubus://luci-rpc/getBoardJSON"}
    }.values())
    return {
        "schema_version": "firmatlas.mapping.ac9-auto-profile-report/v1alpha1",
        "sample_role": "same-hardware-openwrt-control-plane-validation",
        "firmware_artifact_sha256": ARTIFACT_SHA256,
        "analysis_run_id": run.analysis_run_id,
        "catalog_id": run.catalog.catalog_id,
        "profile_id": run.profile_id,
        "analyzer_registry_id": run.analyzer_registry_id,
        "coverage_status": run.coverage_status.value,
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
            "verified_native_binding_count": binding_status[
                "verified_native_registration"
            ],
            "static_plugin_binding_count": binding_status[
                "static_plugin_dispatch"
            ],
            "native_registration_obligation_count": sum(
                item.required_capability == "resolve_ubus_registration_table"
                for item in run.catalog.open_obligations
            ),
            "runtime_owner_obligation_count": sum(
                item.required_capability == "resolve_ubus_runtime_owner"
                for item in run.catalog.open_obligations
            ),
        },
        "handler_examples": handler_examples,
        "comparison_to_base_profile": {
            "source_plan_count": {"base": 269, "auto": len(run.source_plan)},
            "candidate_count": {"base": 720, "auto": len(run.catalog.candidates)},
            "evidence_count": {"base": 1105, "auto": len(run.catalog.evidence_atoms)},
            "native_ubus_binding": {"base": 0, "auto": binding_status["verified_native_registration"]},
        },
        "interpretation": {
            "supported": (
                "the versioned auto profile and builtin registry select four rpcd "
                "registration validators and project verified native handlers into the "
                "same immutable catalog"
            ),
            "why_obligations_increase": (
                "the enriched graph removes all native registration-table obligations "
                "while exposing 17 real runtime-owner gaps that the base profile did not model"
            ),
            "not_claimed": (
                "runtime ubus object existence, authentication outcome, vulnerability, "
                "or resolution of the remaining generic frontend/native obligations"
            ),
        },
    }


if __name__ == "__main__":
    print(json.dumps(build_report(), ensure_ascii=False, indent=2))
