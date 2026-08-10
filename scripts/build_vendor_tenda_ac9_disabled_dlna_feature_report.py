#!/usr/bin/env python3
"""Build the AC9 auto-v11 disabled DLNA feature attribution report."""

from __future__ import annotations

import argparse
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


_DLNA_OPERATIONS = (
    "GetDlnaCfg",
    "SetDlnaCfg",
    "expandDlnaFile",
    "refreshDLNA",
)
_DLNA_ENDPOINTS = (
    "/goform/refreshDLNA",
    "goform/GetDlnaCfg",
    "goform/SetDlnaCfg",
    "goform/expandDlnaFile?",
)


def build() -> dict:
    run = analyze_extracted_root(MappingAnalysisRequest(
        ROOT,
        ARTIFACT_SHA256,
        profile=MappingAnalysisProfile.auto(),
    ))
    gates = [
        item for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.FRONTEND_FEATURE_GATE
    ]
    gates.sort(key=lambda item: item.canonical_identity)
    disabled = [
        item for item in gates
        if dict(item.attributes)["gate_status"] == "disabled"
    ]
    if len(gates) != 3 or len(disabled) != 1:
        raise RuntimeError(
            "AC9 frontend feature gate expectation changed: {}/{}".format(
                len(gates), len(disabled)
            )
        )
    dlna_gate = disabled[0]
    gate_attributes = dict(dlna_gate.attributes)
    request_endpoints = tuple(json.loads(gate_attributes["request_endpoints"]))
    request_refs = tuple(json.loads(gate_attributes["request_candidate_refs"]))
    if (
        dlna_gate.canonical_identity != "CONFIG_DLNA_SERVER"
        or gate_attributes["configured_value"] != "n"
        or gate_attributes["enabled_value"] != "y"
        or request_endpoints != _DLNA_ENDPOINTS
    ):
        raise RuntimeError("AC9 disabled DLNA feature evidence changed")

    attributions = [
        item for item in run.catalog.candidates
        if (
            item.candidate_kind
            is DiscoveryCandidateKind.SET_DIFFERENCE_ATTRIBUTION
            and item.canonical_identity in _DLNA_OPERATIONS
        )
    ]
    attributions.sort(key=lambda item: item.canonical_identity)
    if (
        tuple(item.canonical_identity for item in attributions)
        != _DLNA_OPERATIONS
        or any(
            dict(item.attributes)["attribution_kind"]
            != "frontend_feature_disabled"
            for item in attributions
        )
    ):
        raise RuntimeError("AC9 DLNA set-difference attribution changed")

    evidence_by_id = {
        item.evidence_id: item for item in run.catalog.evidence_atoms
    }
    gate_evidence = [
        evidence_by_id[evidence_id]
        for evidence_id in dlna_gate.evidence_ids
        if evidence_by_id[evidence_id].producer == "frontend-feature-gate"
    ]
    if {
        item.capability for item in gate_evidence
    } != {
        "declares_feature_value",
        "maps_feature_to_ui_target",
        "reveals_feature_target",
        "routes_feature_target_to_page",
        "loads_feature_script",
    }:
        raise RuntimeError("AC9 DLNA feature gate proof chain changed")

    request_candidates = {
        item.candidate_id: item
        for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.REQUEST_INTERFACE
    }
    request_evidence_ids = {
        evidence_id
        for request_id in request_refs
        for evidence_id in request_candidates[request_id].evidence_ids
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

    return {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-14/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-disabled-feature-attribution",
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
            "frontend_feature_gate_count": len(gates),
            "disabled_frontend_feature_gate_count": len(disabled),
            "feature_disabled_operation_count": len(attributions),
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
        "frontend_feature_gates": [
            {
                "candidate_id": item.candidate_id,
                "feature_symbol": item.canonical_identity,
                **dict(item.attributes),
                "request_endpoints": json.loads(
                    dict(item.attributes)["request_endpoints"]
                ),
                "request_candidate_refs": json.loads(
                    dict(item.attributes)["request_candidate_refs"]
                ),
                "script_paths": json.loads(
                    dict(item.attributes)["script_paths"]
                ),
                "evidence_ids": list(item.evidence_ids),
            }
            for item in gates
        ],
        "disabled_dlna_feature_chain": {
            "feature_gate_candidate_id": dlna_gate.candidate_id,
            "feature_symbol": dlna_gate.canonical_identity,
            "configured_value": gate_attributes["configured_value"],
            "enabled_value": gate_attributes["enabled_value"],
            "ui_target_id": gate_attributes["ui_target_id"],
            "page_path": gate_attributes["page_path"],
            "script_paths": json.loads(gate_attributes["script_paths"]),
            "request_endpoints": list(request_endpoints),
            "requests": [
                {
                    "request_candidate_id": request_id,
                    "endpoint": request_candidates[request_id].canonical_identity,
                    "source_path": request_candidates[request_id].source_path,
                    "evidence_ids": list(
                        request_candidates[request_id].evidence_ids
                    ),
                }
                for request_id in request_refs
            ],
            "gate_evidence": [
                item.to_dict() for item in sorted(
                    gate_evidence, key=lambda atom: atom.evidence_id
                )
            ],
            "request_evidence": [
                evidence_by_id[evidence_id].to_dict()
                for evidence_id in sorted(request_evidence_ids)
            ],
        },
        "dlna_set_difference_attributions": [
            {
                "candidate_id": item.candidate_id,
                "operation": item.canonical_identity,
                "difference_side": dict(item.attributes)["difference_side"],
                "attribution_kind": dict(item.attributes)["attribution_kind"],
                "interpretation": dict(item.attributes)["interpretation"],
                "open_obligation": dict(item.attributes)["open_obligation"],
                "matched_artifact_paths": json.loads(
                    dict(item.attributes)["matched_artifact_paths"]
                ),
                "evidence_ids": list(item.evidence_ids),
            }
            for item in attributions
        ],
        "historical_expectation_summary": historical_diff.to_dict()["summary"],
        "vulnerability_scope_summary": {
            "total_vulnerability_count": audit.total_vulnerability_count,
            "category_counts": dict(audit.category_counts),
            "exact_artifact_expectation_count": (
                audit.exact_artifact_expectation_count
            ),
            "exact_artifact_observed_count": audit.exact_artifact_observed_count,
        },
        "interpretation": {
            "supported": (
                "The product macro sets CONFIG_DLNA_SERVER=n while the UI reveals "
                "usb_dlna only for value y; that target opens dlna.html, whose "
                "same-stem dlna.js issues exactly four DLNA operations."
            ),
            "explains": (
                "The four bundled requests are residual in the declared UI path, "
                "which explains their frontend-only catalog shape in this artifact."
            ),
            "still_unresolved": (
                "A disabled UI feature does not prove backend implementation "
                "absence; direct requests, alternate clients, conditional "
                "components, and version-matched builds remain to test."
            ),
            "not_claimed": (
                "Runtime reachability, route ownership, vulnerability presence, "
                "or exploitability."
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
