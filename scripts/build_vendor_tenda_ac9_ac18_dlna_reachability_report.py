#!/usr/bin/env python3
"""Build the R2-16 AC9-primary / AC18-control DLNA reachability report."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from firmatlas.mapping import (
    DiscoveryCandidateKind,
    MappingAnalysisRequest,
    analyze_extracted_root,
)
from build_vendor_tenda_ac9_registrar_inventory_report import (
    ARTIFACT_SHA256 as AC9_ARTIFACT_SHA256,
    ROOT as AC9_ROOT,
)
from build_vendor_tenda_ac9_ac18_dlna_feature_pivot_report import (
    AC18_ARTIFACT_SHA256,
)


_ENDPOINT_OPERATIONS = {
    "goform/GetDlnaCfg": "GetDlnaCfg",
    "goform/SetDlnaCfg": "SetDlnaCfg",
    "goform/expandDlnaFile?": "expandDlnaFile",
    "/goform/refreshDLNA": "refreshDLNA",
}
_EXPECTED_REACHABILITY = {
    "GetDlnaCfg": "top_level_declaration",
    "SetDlnaCfg": "top_level_declaration",
    "expandDlnaFile": "active_call_path",
    "refreshDLNA": "declared_but_unreached",
}


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sample(root: Path, artifact_sha256: str) -> dict:
    run = analyze_extracted_root(MappingAnalysisRequest(root, artifact_sha256))
    evidence = {
        item.evidence_id: item for item in run.catalog.evidence_atoms
    }
    bindings = {
        item.canonical_identity: item
        for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.NATIVE_ROUTE_BINDING
        and item.canonical_identity in set(_ENDPOINT_OPERATIONS.values())
    }
    differences = {
        item.canonical_identity: item
        for item in run.catalog.candidates
        if item.candidate_kind
        is DiscoveryCandidateKind.SET_DIFFERENCE_ATTRIBUTION
        and item.canonical_identity in set(_ENDPOINT_OPERATIONS.values())
    }
    gate = next(
        item for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.FRONTEND_FEATURE_GATE
        and item.canonical_identity == "CONFIG_DLNA_SERVER"
    )
    all_invocations = [
        item for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.FRONTEND_INVOCATION
    ]
    invocation_by_endpoint = {
        item.canonical_identity: item
        for item in all_invocations
        if item.canonical_identity in _ENDPOINT_OPERATIONS
    }
    if set(invocation_by_endpoint) != set(_ENDPOINT_OPERATIONS):
        raise RuntimeError("DLNA frontend invocation set changed")
    operations = []
    selected_evidence_ids = set()
    for endpoint, operation in _ENDPOINT_OPERATIONS.items():
        invocation = invocation_by_endpoint[endpoint]
        attributes = dict(invocation.attributes)
        request_ref = attributes["request_candidate_ref"]
        parameters = sorted(
            item.name for item in run.catalog.parameters
            if item.owner_ref == request_ref
        )
        binding = bindings.get(operation)
        difference = differences.get(operation)
        selected_evidence_ids.update(invocation.evidence_ids)
        operations.append({
            "operation": operation,
            "endpoint": endpoint,
            "request_candidate_ref": request_ref,
            "invocation_candidate_id": invocation.candidate_id,
            "invocation_status": attributes["status"],
            "function_name": attributes["function_name"] or None,
            "root_kind": attributes["root_kind"] or None,
            "call_path": json.loads(attributes["call_path"]),
            "commented_reference_count": int(
                attributes["commented_reference_count"]
            ),
            "frontend_parameters": parameters,
            "feature_gate_status": dict(gate.attributes)["gate_status"],
            "native_binding": (
                {
                    "candidate_id": binding.candidate_id,
                    "handler_identity": dict(binding.attributes)[
                        "handler_identity"
                    ],
                    "handler_symbol": dict(binding.attributes).get(
                        "handler_symbol"
                    ),
                    "registration_address": dict(binding.attributes)[
                        "registration_address"
                    ],
                    "evidence_ids": list(binding.evidence_ids),
                }
                if binding is not None else None
            ),
            "set_difference": (
                {
                    "attribution_kind": dict(difference.attributes)[
                        "attribution_kind"
                    ],
                    "difference_side": dict(difference.attributes)[
                        "difference_side"
                    ],
                    "open_obligation": dict(difference.attributes)[
                        "open_obligation"
                    ],
                }
                if difference is not None else None
            ),
            "evidence_ids": list(invocation.evidence_ids),
        })
    operations.sort(key=lambda item: item["operation"])
    reachability_stage = next(
        item for item in run.stages
        if item.stage_name == "frontend_reachability"
    )
    return {
        "firmware_artifact_sha256": artifact_sha256,
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
            "frontend_invocation_count": len(all_invocations),
            "frontend_invocation_status_counts": dict(sorted(Counter(
                dict(item.attributes)["status"] for item in all_invocations
            ).items())),
            "dlna_native_binding_count": len(bindings),
        },
        "frontend_reachability_stage": {
            "coverage_status": reachability_stage.coverage_status.value,
            "input_count": reachability_stage.input_count,
            "output_count": reachability_stage.output_count,
            "diagnostics": list(reachability_stage.diagnostics),
        },
        "dlna_feature_gate": {
            "configured_value": dict(gate.attributes)["configured_value"],
            "enabled_value": dict(gate.attributes)["enabled_value"],
            "gate_status": dict(gate.attributes)["gate_status"],
            "candidate_id": gate.candidate_id,
        },
        "dlna_operations": operations,
        "dlna_invocation_evidence": [
            evidence[evidence_id].to_dict()
            for evidence_id in sorted(selected_evidence_ids)
        ],
    }


def build(ac18_root: Path) -> dict:
    ac9 = _sample(AC9_ROOT, AC9_ARTIFACT_SHA256)
    ac18 = _sample(ac18_root, AC18_ARTIFACT_SHA256)
    for sample in (ac9, ac18):
        observed = {
            item["operation"]: item["invocation_status"]
            for item in sample["dlna_operations"]
        }
        if observed != _EXPECTED_REACHABILITY:
            raise RuntimeError("DLNA invocation reachability changed")
    if (
        ac9["dlna_feature_gate"]["gate_status"] != "disabled"
        or ac18["dlna_feature_gate"]["gate_status"] != "enabled"
        or ac9["mapping_summary"]["dlna_native_binding_count"] != 0
        or ac18["mapping_summary"]["dlna_native_binding_count"] != 3
    ):
        raise RuntimeError("AC9/AC18 feature or binding control changed")

    by_sample = {
        "ac9": {item["operation"]: item for item in ac9["dlna_operations"]},
        "ac18": {item["operation"]: item for item in ac18["dlna_operations"]},
    }
    historical_leads = []
    for cve_id, operation, parameter in (
        ("CVE-2024-10661", "SetDlnaCfg", "scanList"),
        ("CVE-2022-38325", "expandDlnaFile", "filePath"),
    ):
        historical_leads.append({
            "cve_id": cve_id,
            "operation": operation,
            "parameter": parameter,
            "ac9_frontend_parameter_observed": (
                parameter in by_sample["ac9"][operation]["frontend_parameters"]
            ),
            "ac9_native_owner_observed": (
                by_sample["ac9"][operation]["native_binding"] is not None
            ),
            "ac18_frontend_parameter_observed": (
                parameter in by_sample["ac18"][operation]["frontend_parameters"]
            ),
            "ac18_native_owner_observed": (
                by_sample["ac18"][operation]["native_binding"] is not None
            ),
            "scope_rule": (
                "The CVE is a family/version investigation lead, not an AC9 "
                "vulnerability or reachability claim."
            ),
        })

    prior = Path(
        "docs/firmware-mapping/samples/"
        "r2-15-vendor-tenda-ac9-ac18-dlna-feature-pivot.json"
    )
    return {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-16/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-with-ac18-reachability-control",
        "evidence_boundary": (
            "Static invocation reachability distinguishes declarations, bounded "
            "call paths, and declared-but-unreached functions. It does not prove "
            "runtime execution, network reachability, or vulnerability."
        ),
        "ac9_primary": ac9,
        "ac18_positive_control": ac18,
        "historical_parameter_leads": historical_leads,
        "prior_round": {
            "report": prior.as_posix(),
            "report_sha256": _sha(prior),
        },
        "open_obligations": [
            "resolve cross-resource and dynamic frontend calls not covered by v1",
            "obtain and partition-compare an official AC9 raw firmware image",
            "separate page-load eligibility from runtime event execution",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ac18-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    payload = build(args.ac18_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
