#!/usr/bin/env python3
"""Build AC9 auto-v4 full registrar inventory and hidden-interface audit."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from firmatlas.mapping import (
    DiscoveryCandidateKind,
    HistoricalVulnerabilityRecord,
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    analyze_extracted_root,
    build_historical_vulnerability_audit,
    build_potential_hidden_interface_index,
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
    expectations = load_historical_expectations(json.loads(
        EXPECTATIONS.read_text(encoding="utf-8")
    ))
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
    route_report = compare_historical_route_bindings(run.catalog, expectations)
    hidden = build_potential_hidden_interface_index(run.catalog)
    kinds = Counter(item.candidate_kind.value for item in run.catalog.candidates)
    difference_sides = Counter(
        dict(item.attributes).get("difference_side")
        for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.SET_DIFFERENCE_ATTRIBUTION
    )
    frontend_only = sorted(
        item.canonical_identity
        for item in run.catalog.candidates
        if (
            item.candidate_kind is DiscoveryCandidateKind.SET_DIFFERENCE_ATTRIBUTION
            and dict(item.attributes).get("difference_side") == "frontend_only"
        )
    )
    return {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-06/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-full-registrar-iteration",
        "firmware_artifact_sha256": ARTIFACT_SHA256,
        "firmware_release_version": "15.03.05.19",
        "analysis_run_id": run.analysis_run_id,
        "catalog_id": run.catalog.catalog_id,
        "profile_id": run.profile_id,
        "analyzer_registry_id": run.analyzer_registry_id,
        "coverage_status": run.coverage_status.value,
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
            "candidate_count": len(run.catalog.candidates),
            "parameter_count": len(run.catalog.parameters),
            "evidence_count": len(run.catalog.evidence_atoms),
            "open_obligation_count": len(run.catalog.open_obligations),
            "candidate_kinds": dict(sorted(kinds.items())),
        },
        "set_difference_summary": {
            "frontend_only": difference_sides["frontend_only"],
            "frontend_only_operations": frontend_only,
            "native_only": difference_sides["native_only"],
        },
        "potential_hidden_interface_index": hidden.to_dict(),
        "historical_expectation_diff": diff.to_dict(),
        "historical_route_binding_coverage": route_report.to_dict(),
        "vulnerability_scope_audit": audit.to_dict(),
        "sample_vulnerability_linkage": scope["sample_linkage"],
        "interpretation": {
            "supported": (
                "two ARM binaries expose 185 instruction-validated registrations; "
                "route-aware comparison publishes 110 native-only operations only "
                "because inventory, frontend, native, and set-difference coverage complete"
            ),
            "not_claimed": (
                "hidden client intent, runtime reachability, authentication state, "
                "vulnerability presence, exploitability, or dead-code status"
            ),
        },
    }


if __name__ == "__main__":
    print(json.dumps(build_report(), ensure_ascii=False, indent=2, sort_keys=True))
