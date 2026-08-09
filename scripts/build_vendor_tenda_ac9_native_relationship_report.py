#!/usr/bin/env python3
"""Build the AC9 auto-v8 native embedded-command relationship report."""

from __future__ import annotations

import argparse
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
    load_historical_expectations,
)
from build_vendor_tenda_ac9_registrar_inventory_report import (
    ARTIFACT_SHA256,
    EXPECTATIONS,
    ROOT,
    VULNERABILITY_SCOPE,
)


def _attributes(candidate) -> dict:
    return dict(candidate.attributes)


def build() -> dict:
    run = analyze_extracted_root(MappingAnalysisRequest(
        ROOT, ARTIFACT_SHA256, profile=MappingAnalysisProfile.auto()
    ))
    relationships = [
        item for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.NATIVE_RELATIONSHIP
    ]
    relationship_rows = []
    for item in relationships:
        attributes = _attributes(item)
        relationship_rows.append({
            "relationship_id": item.candidate_id,
            "source_component": attributes["source_component"],
            "action": attributes["action"],
            "target_component": attributes["target_component"],
            "command": attributes["command"],
            "target_artifact_paths": json.loads(
                attributes["target_artifact_paths"]
            ),
            "target_resolution_status": attributes["target_resolution_status"],
            "relationship_kind": attributes["relationship_kind"],
            "binding_status": attributes["binding_status"],
            "topic": attributes.get("topic"),
            "operation": attributes.get("operation"),
            "arguments": json.loads(attributes["arguments"]),
            "open_obligation": attributes["open_obligation"],
            "evidence_ids": list(item.evidence_ids),
        })
    relationship_rows.sort(key=lambda item: item["relationship_id"])
    evidence_by_id = {
        item.evidence_id: item.to_dict() for item in run.catalog.evidence_atoms
    }
    dlna_rows = [
        item for item in relationship_rows
        if (
            item["source_component"] == "bin/httpd"
            and item["target_component"] == "minidlna"
        ) or (
            item["source_component"] == "bin/time_check"
            and item["target_component"] == "netctrl"
            and item["topic"] == "51"
            and item["operation"] == "6"
        )
    ]
    dlna_evidence_ids = {
        evidence_id for item in dlna_rows for evidence_id in item["evidence_ids"]
    }

    expectations = load_historical_expectations(json.loads(
        EXPECTATIONS.read_text(encoding="utf-8")
    ))
    historical_diff = compare_historical_expectations(run.catalog, expectations)
    scope = json.loads(VULNERABILITY_SCOPE.read_text(encoding="utf-8"))
    audit = build_historical_vulnerability_audit(
        historical_diff,
        tuple(HistoricalVulnerabilityRecord(**item) for item in scope["records"]),
    )
    hidden = build_potential_hidden_interface_index(run.catalog)
    kind_counts = Counter(item["relationship_kind"] for item in relationship_rows)
    status_counts = Counter(item["binding_status"] for item in relationship_rows)
    target_counts = Counter(item["target_component"] for item in relationship_rows)
    return {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-11/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-native-relationship-iteration",
        "firmware_artifact_sha256": ARTIFACT_SHA256,
        "analysis_run_id": run.analysis_run_id,
        "catalog_id": run.catalog.catalog_id,
        "profile_id": run.profile_id,
        "analyzer_registry_id": run.analyzer_registry_id,
        "coverage_status": run.coverage_status.value,
        "mapping_summary": {
            "candidate_count": len(run.catalog.candidates),
            "parameter_count": len(run.catalog.parameters),
            "evidence_count": len(run.catalog.evidence_atoms),
            "open_obligation_count": len(run.catalog.open_obligations),
            "potential_hidden_interface_count": len(hidden.items),
            "native_relationship_count": len(relationship_rows),
            "native_relationship_source_count": len({
                item["source_component"] for item in relationship_rows
            }),
            "resolved_target_count": sum(
                bool(item["target_artifact_paths"]) for item in relationship_rows
            ),
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
        "relationship_distribution": {
            "by_kind": dict(sorted(kind_counts.items())),
            "by_binding_status": dict(sorted(status_counts.items())),
            "top_targets": [
                {"target_component": target, "count": count}
                for target, count in sorted(
                    target_counts.items(), key=lambda item: (-item[1], item[0])
                )[:20]
            ],
        },
        "relationships": relationship_rows,
        "dlna_relationships": dlna_rows,
        "dlna_relationship_evidence": [
            evidence_by_id[evidence_id]
            for evidence_id in sorted(dlna_evidence_ids)
        ],
        "historical_expectation_summary": historical_diff.to_dict()["summary"],
        "historical_expectation_entries": [
            {
                "vulnerability_identifier": item.vulnerability_identifier,
                "interface_value": item.interface_value,
                "expected_parameters": list(item.expected_parameters),
                "status": item.status.value,
                "gap_reason": item.gap_reason.value,
                "applicability": item.applicability.value,
                "missing_parameters": list(item.missing_parameters),
            }
            for item in historical_diff.entries
        ],
        "vulnerability_scope_summary": {
            "total_vulnerability_count": audit.total_vulnerability_count,
            "category_counts": dict(audit.category_counts),
            "exact_artifact_expectation_count": audit.exact_artifact_expectation_count,
            "exact_artifact_observed_count": audit.exact_artifact_observed_count,
        },
        "interpretation": {
            "supported": (
                "complete embedded commands establish candidate sender-to-target "
                "process-control and CFM IPC relationships, with literal topic, "
                "operation, and argument fields preserved when present"
            ),
            "unresolved": (
                "the DLNA fixture/state clues are not yet connected by a proven "
                "code callsite to the exact time_check topic 51 operation 6 command"
            ),
            "not_claimed": (
                "embedded commands executed, targets were live, routes were reachable, "
                "or historical vulnerabilities are present"
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(
        json.dumps(build(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
