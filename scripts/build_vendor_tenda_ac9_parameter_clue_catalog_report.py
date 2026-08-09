#!/usr/bin/env python3
"""Build the AC9 auto-v6 frontend-wrapper and parameter-clue catalog report."""

from __future__ import annotations

import argparse
from collections import Counter
import json

from firmatlas.mapping import (
    BUILTIN_ANALYZER_REGISTRY_V6,
    DiscoveryCandidateKind,
    MappingAnalysisProfile,
)
from build_vendor_tenda_ac9_registrar_inventory_report import (
    ARTIFACT_SHA256,
    EXPECTATIONS,
    ROOT,
    VULNERABILITY_SCOPE,
)


def build() -> dict:
    from firmatlas.mapping import (
        HistoricalVulnerabilityRecord,
        MappingAnalysisRequest,
        analyze_extracted_root,
        build_historical_vulnerability_audit,
        build_potential_hidden_interface_index,
        compare_historical_expectations,
        load_historical_expectations,
    )
    run = analyze_extracted_root(MappingAnalysisRequest(
        ROOT, ARTIFACT_SHA256, profile=MappingAnalysisProfile.auto_v6()
    ), registry=BUILTIN_ANALYZER_REGISTRY_V6)
    hidden = build_potential_hidden_interface_index(run.catalog)
    expectations = load_historical_expectations(json.loads(
        EXPECTATIONS.read_text(encoding="utf-8")
    ))
    scope = json.loads(VULNERABILITY_SCOPE.read_text(encoding="utf-8"))
    historical_diff = compare_historical_expectations(run.catalog, expectations)
    vulnerability_audit = build_historical_vulnerability_audit(
        historical_diff,
        tuple(HistoricalVulnerabilityRecord(**item) for item in scope["records"]),
    )
    assessments = [
        item for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.PARAMETER_CLUE_ASSESSMENT
    ]
    status_counts = Counter(
        dict(item.attributes)["assessment_status"] for item in assessments
    )
    selected_names = {"dlnaEn", "deviceName", "scanList", "folderGrade", "filePath"}
    report = {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-09/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-wrapper-and-parameter-clue-iteration",
        "firmware_artifact_sha256": ARTIFACT_SHA256,
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
        },
        "parameter_clue_summary": {
            "assessment_count": len(assessments),
            "status_counts": dict(sorted(status_counts.items())),
            "selected_dlna_assessments": [
                {
                    "canonical_identity": item.canonical_identity,
                    "source_path": item.source_path,
                    "evidence_ids": list(item.evidence_ids),
                    "attributes": dict(item.attributes),
                }
                for item in assessments
                if (
                    item.canonical_identity.rsplit("|", 1)[-1] in selected_names
                    or item.canonical_identity == "/goform/refreshDLNA|action"
                )
            ],
        },
        "frontend_wrapper_recovery": {
            "new_request_operations": [
                "goform/expandDlnaFile?", "goform/setNotUpgrade",
                "goform/setPptpUserList", "goform/setUsbUnload",
                "goform/setThundercfg",
            ],
            "new_dlna_parameters": ["folderGrade", "filePath", "action"],
            "hidden_interface_count_before": 110,
            "hidden_interface_count_after": len(hidden.items),
            "removed_from_hidden": [
                "setNotUpgrade", "setPptpUserList", "setUsbUnload"
            ],
        },
        "potential_hidden_interface_summary": {
            "coverage_status": hidden.coverage_status.value,
            "item_count": len(hidden.items),
        },
        "historical_expectation_diff": historical_diff.to_dict(),
        "vulnerability_scope_audit": vulnerability_audit.to_dict(),
        "interpretation": {
            "supported": (
                "auto-v6 recovers Tenda GetSetData requests and inline jQuery form "
                "parameters, publishes bounded parameter-clue assessments in the "
                "catalog, and reduces evidence-complete native-only candidates from "
                "110 to 107"
            ),
            "not_claimed": (
                "token clues are parameter-to-state flows, runtime reachability, "
                "authentication state, vulnerability presence, or exploitability"
            ),
        },
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output")
    args = parser.parse_args()
    from pathlib import Path
    Path(args.output).write_text(
        json.dumps(build(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
