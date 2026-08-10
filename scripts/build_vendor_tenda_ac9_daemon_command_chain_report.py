#!/usr/bin/env python3
"""Build AC9 auto-v9 daemon command-table and ARM literal-xref report."""

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


def build() -> dict:
    run = analyze_extracted_root(MappingAnalysisRequest(
        ROOT, ARTIFACT_SHA256, profile=MappingAnalysisProfile.auto()
    ))
    command_bindings = [
        item for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.NATIVE_COMMAND_BINDING
    ]
    xrefs = [
        item for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.ARM_LITERAL_XREF
    ]
    if len(command_bindings) != 1:
        raise RuntimeError(
            "AC9 command binding expectation changed: {}".format(
                len(command_bindings)
            )
        )
    binding = command_bindings[0]
    binding_attributes = dict(binding.attributes)
    related_xrefs = [
        item for item in xrefs
        if dict(item.attributes)["target_ref"] == binding.candidate_id
    ]
    if len(related_xrefs) != 2:
        raise RuntimeError(
            "AC9 bound handler literal-xref expectation changed: {}".format(
                len(related_xrefs)
            )
        )
    xref_rows = [
        {
            "xref_id": item.candidate_id,
            "literal_value": dict(item.attributes)["literal_value"],
            "literal_address": dict(item.attributes)["literal_address"],
            "instruction_address": dict(item.attributes)["instruction_address"],
            "function_identity": dict(item.attributes)["function_identity"],
            "pic_base_address": dict(item.attributes)["pic_base_address"],
            "evidence_ids": list(item.evidence_ids),
        }
        for item in related_xrefs
    ]
    xref_rows.sort(key=lambda item: item["literal_value"])
    chain_evidence_ids = {
        *binding.evidence_ids,
        *(evidence_id for item in related_xrefs for evidence_id in item.evidence_ids),
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
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-12/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-daemon-command-chain-iteration",
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
            "native_command_binding_count": len(command_bindings),
            "bound_handler_literal_xref_count": len(related_xrefs),
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
        "daemon_command_chain": {
            "binding_id": binding.candidate_id,
            "table_symbol": binding_attributes["table_symbol"],
            "registration_address": binding_attributes["registration_address"],
            "process_name": binding_attributes["process_name"],
            "command": binding_attributes["command"],
            "handler_identity": binding_attributes["handler_identity"],
            "handler_address": binding_attributes["handler_address"],
            "binding_status": binding_attributes["binding_status"],
            "evidence_ids": list(binding.evidence_ids),
            "handler_literal_xrefs": xref_rows,
        },
        "daemon_command_chain_evidence": [
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
            "exact_artifact_expectation_count": audit.exact_artifact_expectation_count,
            "exact_artifact_observed_count": audit.exact_artifact_observed_count,
        },
        "interpretation": {
            "supported": (
                "the daemon_exe_info dynamic-symbol record binds process minidlna "
                "and command cfm post netctrl 51?op=6 to executable handler 0x15868; "
                "that exact handler function references /var/etc/upan and "
                "time_check_daemon_minidlna through proven ARM PIC GOT xrefs"
            ),
            "still_unresolved": (
                "no exact goform route registration or handler binding connects "
                "the DLNA frontend/fixture contract to this supervision chain"
            ),
            "not_claimed": (
                "the command executed at runtime, minidlna was present, a DLNA "
                "goform operation reached the handler, or a vulnerability exists"
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
