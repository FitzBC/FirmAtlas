#!/usr/bin/env python3
"""Build the AC9 auto-v10 tail-merged USB/DLNA status chain report."""

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


_DLNA_LITERALS = frozenset({"dlna.en", "/var/etc/upan", "dlna"})


def _xref_row(item) -> dict:
    attributes = dict(item.attributes)
    return {
        "xref_id": item.candidate_id,
        "literal_value": attributes["literal_value"],
        "literal_address": attributes["literal_address"],
        "instruction_address": attributes["instruction_address"],
        "function_identity": attributes["function_identity"],
        "pic_base_address": attributes["pic_base_address"],
        "evidence_ids": list(item.evidence_ids),
    }


def build() -> dict:
    run = analyze_extracted_root(MappingAnalysisRequest(
        ROOT, ARTIFACT_SHA256, profile=MappingAnalysisProfile.auto()
    ))
    request_candidates = [
        item for item in run.catalog.candidates
        if (
            item.candidate_kind is DiscoveryCandidateKind.REQUEST_INTERFACE
            and item.source_path == "webroot_ro/js/main.js"
            and item.source_construct == "jQuery.getJSON"
        )
    ]
    request_candidates.sort(key=lambda item: item.canonical_identity)
    usb_request = next(
        item for item in request_candidates
        if item.canonical_identity == "goform/GetUSBStatus?"
    )
    bindings = [
        item for item in run.catalog.candidates
        if (
            item.candidate_kind is DiscoveryCandidateKind.NATIVE_ROUTE_BINDING
            and item.canonical_identity == "GetUSBStatus"
            and ":tail-merged:" in item.source_construct
        )
    ]
    if len(bindings) != 1:
        raise RuntimeError(
            "AC9 tail-merged GetUSBStatus binding expectation changed: {}".format(
                len(bindings)
            )
        )
    binding = bindings[0]
    binding_attributes = dict(binding.attributes)
    xrefs = [
        item for item in run.catalog.candidates
        if (
            item.candidate_kind is DiscoveryCandidateKind.ARM_LITERAL_XREF
            and dict(item.attributes)["target_ref"] == binding.candidate_id
        )
    ]
    xrefs.sort(key=lambda item: (
        dict(item.attributes)["instruction_address"],
        dict(item.attributes)["literal_value"],
    ))
    if len(xrefs) != 12:
        raise RuntimeError(
            "AC9 GetUSBStatus handler xref expectation changed: {}".format(
                len(xrefs)
            )
        )
    dlna_xrefs = [
        item for item in xrefs
        if dict(item.attributes)["literal_value"] in _DLNA_LITERALS
    ]
    if len(dlna_xrefs) != 4:
        raise RuntimeError(
            "AC9 GetUSBStatus DLNA xref expectation changed: {}".format(
                len(dlna_xrefs)
            )
        )
    chain_evidence_ids = {
        *usb_request.evidence_ids,
        *binding.evidence_ids,
        *(evidence_id for item in xrefs for evidence_id in item.evidence_ids),
    }
    evidence_by_id = {
        item.evidence_id: item.to_dict() for item in run.catalog.evidence_atoms
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
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-13/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-tail-merged-route-iteration",
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
            "main_js_getjson_request_count": len(request_candidates),
            "tail_merged_route_binding_count": sum(
                item.candidate_kind
                is DiscoveryCandidateKind.NATIVE_ROUTE_BINDING
                and ":tail-merged:" in item.source_construct
                for item in run.catalog.candidates
            ),
            "usb_status_handler_literal_xref_count": len(xrefs),
        },
        "main_js_getjson_requests": [
            {
                "request_id": item.candidate_id,
                "endpoint": item.canonical_identity,
                "source_path": item.source_path,
                "evidence_ids": list(item.evidence_ids),
            }
            for item in request_candidates
        ],
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
        "usb_status_route_handler_chain": {
            "frontend_request_id": usb_request.candidate_id,
            "frontend_endpoint": usb_request.canonical_identity,
            "binding_id": binding.candidate_id,
            "route_token": binding.canonical_identity,
            "source_construct": binding.source_construct,
            "registration_address": binding_attributes["registration_address"],
            "registrar_address": binding_attributes["registrar_address"],
            "registrar_pair_count": int(
                binding_attributes["registrar_pair_count"]
            ),
            "handler_identity": binding_attributes["handler_identity"],
            "handler_symbol": binding_attributes["handler_symbol"],
            "binding_evidence_ids": list(binding.evidence_ids),
            "handler_literal_xrefs": [_xref_row(item) for item in xrefs],
            "dlna_literal_xrefs": [_xref_row(item) for item in dlna_xrefs],
        },
        "usb_status_route_handler_evidence": [
            evidence_by_id[evidence_id]
            for evidence_id in sorted(chain_evidence_ids)
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
            "exact_artifact_expectation_count": (
                audit.exact_artifact_expectation_count
            ),
            "exact_artifact_observed_count": audit.exact_artifact_observed_count,
        },
        "interpretation": {
            "supported": (
                "main.js constructs GET goform/GetUSBStatus?; an ARM tail-merged "
                "registration binds GetUSBStatus to formGetUSBStatus@0xa62d0; "
                "that exact handler references DLNA state and media-mount literals"
            ),
            "still_unresolved": (
                "GetDlnaCfg, SetDlnaCfg, refreshDLNA, and expandDlnaFile still "
                "lack an exact Native route-handler binding"
            ),
            "not_claimed": (
                "GetUSBStatus aliases the separate DLNA operations, the route is "
                "runtime reachable, the returned fields have fixture values, or a "
                "vulnerability exists"
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
