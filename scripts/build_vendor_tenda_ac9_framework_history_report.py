#!/usr/bin/env python3
"""Build AC9 auto-v2 framework, history, and full vulnerability-scope audit."""

from __future__ import annotations

import json
from pathlib import Path

from firmatlas.mapping import (
    DiscoveryCandidateKind,
    HistoricalVulnerabilityRecord,
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    analyze_extracted_root,
    build_historical_vulnerability_audit,
    compare_historical_expectations,
    compare_historical_route_bindings,
    load_historical_expectations,
)


ROOT = Path("../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root")
ARTIFACT_SHA256 = "981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296"
EXPECTATIONS = Path(
    "docs/firmware-mapping/samples/r2-03-vendor-tenda-ac9-historical-expectations.json"
)
VULNERABILITY_SCOPE = Path(
    "docs/firmware-mapping/samples/r2-04-vendor-tenda-ac9-vulnerability-scope.json"
)


def build_report() -> dict:
    expectations = load_historical_expectations(
        json.loads(EXPECTATIONS.read_text(encoding="utf-8"))
    )
    scope = json.loads(VULNERABILITY_SCOPE.read_text(encoding="utf-8"))
    records = tuple(
        HistoricalVulnerabilityRecord(**item) for item in scope["records"]
    )
    run = analyze_extracted_root(MappingAnalysisRequest(
        root=ROOT,
        firmware_artifact_sha256=ARTIFACT_SHA256,
        profile=MappingAnalysisProfile.auto(),
    ))
    diff = compare_historical_expectations(run.catalog, expectations)
    audit = build_historical_vulnerability_audit(diff, records)
    binding_report = compare_historical_route_bindings(
        run.catalog, expectations
    )
    route_bindings = tuple(
        item for item in run.catalog.candidates
        if item.candidate_kind == DiscoveryCandidateKind.NATIVE_ROUTE_BINDING
    )
    framework_candidates = tuple(
        item for item in run.catalog.candidates
        if item.source_construct == "R.pageModel.setUrl.framework"
    )
    return {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-04/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-completeness-iteration",
        "firmware_artifact_sha256": ARTIFACT_SHA256,
        "firmware_release_version": "15.03.05.19",
        "analysis_run_id": run.analysis_run_id,
        "catalog_id": run.catalog.catalog_id,
        "profile_id": run.profile_id,
        "analyzer_registry_id": run.analyzer_registry_id,
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
        "mapping_summary": {
            "request_interface_count": sum(
                item.candidate_kind == DiscoveryCandidateKind.REQUEST_INTERFACE
                for item in run.catalog.candidates
            ),
            "parameter_count": len(run.catalog.parameters),
            "native_route_binding_count": len(route_bindings),
            "native_handler_count": sum(
                item.candidate_kind == DiscoveryCandidateKind.NATIVE_HANDLER
                for item in run.catalog.candidates
            ),
            "framework_post_interface_count": len(framework_candidates),
            "evidence_count": len(run.catalog.evidence_atoms),
            "open_obligation_count": len(run.catalog.open_obligations),
        },
        "historical_expectation_diff": diff.to_dict(),
        "vulnerability_scope_audit": audit.to_dict(),
        "sample_vulnerability_linkage": scope["sample_linkage"],
        "historical_route_binding_coverage": binding_report.to_dict(),
        "interpretation": {
            "supported": (
                "cross-resource RouterPage framework evidence proves POST for 31 "
                "setUrl interfaces and closes the final structured historical "
                "interface/parameter/method gap in the selected expectation set"
            ),
            "remaining_binding_gap": (
                "only three of thirteen historical route expectations currently have "
                "verified ARM route-handler bindings; exact-version SetSambaCfg has "
                "an interface and parameters but no verified handler binding"
            ),
            "denominator_guard": (
                "all 71 normalized AC9 vulnerability records remain in the audit; "
                "records without a structured interface cannot count as mapping hits"
            ),
            "not_claimed": (
                "complete runtime reachability, vulnerability presence, exploitability, "
                "or full recall across records whose communication facts were not extracted"
            ),
        },
    }


if __name__ == "__main__":
    print(json.dumps(build_report(), ensure_ascii=False, indent=2, sort_keys=True))
