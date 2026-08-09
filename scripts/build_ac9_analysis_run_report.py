#!/usr/bin/env python3
"""Build the compact R2 AnalyzeRun report for OpenWrt AC9 19.07.8."""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path

from firmatlas.mapping import (
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    analyze_extracted_root,
)


ROOT = Path(
    "var/mapping-work/ac9-version-diff/extractions/openwrt-19.07.8/"
    "extractions/firmware.bin.extracted/0/partition_1.bin.extracted/0/squashfs-root"
)
ARTIFACT_SHA256 = "d40b191c95c5b6e43358785d6c6e9d7915296e9a954d27fbc1936bdf48568ec9"


def build_report() -> dict:
    run = analyze_extracted_root(MappingAnalysisRequest(
        root=ROOT,
        firmware_artifact_sha256=ARTIFACT_SHA256,
        profile=MappingAnalysisProfile.base(),
    ))
    candidate_kinds = Counter(
        item.candidate_kind.value for item in run.catalog.candidates
    )
    analyzer_inputs = Counter(
        kind for item in run.source_plan for kind in item.analyzer_kinds
    )
    representative = []
    wanted = {
        "ubus://luci/getFeatures",
        "ubus://file/read",
        "ubus://hostapd.{dynamic}/del_client",
        "/admin/status/overview",
    }
    for item in run.catalog.candidates:
        if item.canonical_identity in wanted:
            representative.append({
                "identity": item.canonical_identity,
                "kind": item.candidate_kind.value,
                "status": item.claim_status.value,
                "source_path": item.source_path,
                "evidence_count": len(item.evidence_ids),
            })
    return {
        "schema_version": "firmatlas.mapping.ac9-analysis-run-report/v1alpha1",
        "sample_role": "real-extracted-root-one-command-analysis",
        "firmware_artifact_sha256": ARTIFACT_SHA256,
        "analysis_run_id": run.analysis_run_id,
        "catalog_id": run.catalog.catalog_id,
        "coverage_status": run.coverage_status.value,
        "inventory_coverage_status": run.inventory_coverage_status.value,
        "source_inventory_sha256": run.source_inventory_sha256,
        "source_plan_count": len(run.source_plan),
        "analyzer_input_distribution": dict(sorted(analyzer_inputs.items())),
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
            "scheduler_termination": run.catalog.scheduler_termination.value,
            "candidate_kind_distribution": dict(sorted(candidate_kinds.items())),
        },
        "representative_candidates": representative,
        "interpretation": {
            "supported": (
                "one public AnalyzeRun interface inventories the root, selects sources, "
                "runs four producer families, correlates candidates, reaches a scheduler "
                "fixed point, and publishes an immutable catalog"
            ),
            "partial_reason": (
                "a bounded dynamic LuCI ubus object template remains unresolved; the run "
                "preserves this as coverage and open obligations"
            ),
            "not_claimed": (
                "native deep handler recovery, runtime reachability, vulnerability, or "
                "complete non-HTTP protocol coverage"
            ),
        },
    }


if __name__ == "__main__":
    print(json.dumps(build_report(), ensure_ascii=False, indent=2))
