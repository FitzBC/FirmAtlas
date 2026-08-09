#!/usr/bin/env python3
"""Compare the primary vendor AC9 map with version-scoped vulnerability claims."""

from __future__ import annotations

import json
from pathlib import Path

from firmatlas.mapping import (
    BUILTIN_ANALYZER_REGISTRY_V1,
    HistoricalApplicability,
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    analyze_extracted_root,
    compare_historical_expectations,
    load_historical_expectations,
)


ROOT = Path("../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root")
ARTIFACT_SHA256 = "981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296"
EXPECTATIONS = Path(
    "docs/firmware-mapping/samples/r2-03-vendor-tenda-ac9-historical-expectations.json"
)


def build_report() -> dict:
    expectations = load_historical_expectations(
        json.loads(EXPECTATIONS.read_text(encoding="utf-8"))
    )
    run = analyze_extracted_root(MappingAnalysisRequest(
        root=ROOT,
        firmware_artifact_sha256=ARTIFACT_SHA256,
        profile=MappingAnalysisProfile.auto_v1(),
    ), registry=BUILTIN_ANALYZER_REGISTRY_V1)
    diff = compare_historical_expectations(run.catalog, expectations)
    exact_entries = tuple(
        item for item in diff.entries
        if item.applicability == HistoricalApplicability.EXACT_ARTIFACT
    )
    reference_entries = tuple(
        item for item in diff.entries
        if item.applicability != HistoricalApplicability.EXACT_ARTIFACT
    )
    return {
        **diff.to_dict(),
        "sample_role": "primary-vendor-tenda-ac9-v15.03.05.19",
        "firmware_artifact_sha256": ARTIFACT_SHA256,
        "firmware_release_version": "15.03.05.19",
        "analysis_run_id": run.analysis_run_id,
        "profile_id": run.profile_id,
        "analyzer_registry_id": run.analyzer_registry_id,
        "expectation_manifest": str(EXPECTATIONS),
        "scope_summary": {
            "exact_artifact_expectation_count": len(exact_entries),
            "cross_version_reference_count": len(reference_entries),
            "exact_artifact_observed_count": sum(
                item.status.value == "observed" for item in exact_entries
            ),
            "exact_artifact_gap_count": sum(
                item.status.value in ("partial", "missing") for item in exact_entries
            ),
        },
        "interpretation": {
            "supported": (
                "both historical interface expectations explicitly scoped to the "
                "selected V15.03.05.19 artifact are observed in the cold-start catalog"
            ),
            "cross_version_use": (
                "the remaining claims test architecture and clue coverage only; absence "
                "does not count as a miss for this artifact"
            ),
            "not_claimed": (
                "vulnerability presence, exploitability, runtime reachability, or recall "
                "for claims targeting other AC9 firmware versions"
            ),
        },
    }


if __name__ == "__main__":
    print(json.dumps(build_report(), ensure_ascii=False, indent=2, sort_keys=True))
