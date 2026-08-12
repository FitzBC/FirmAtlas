#!/usr/bin/env python3
"""Build the AC9 R2-23 cross-ELF configuration persistence report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from firmatlas.mapping import (
    CommunicationGraphEdgeKind,
    DiscoveryCandidateKind,
    MappingAnalysisRequest,
    analyze_extracted_root,
    project_communication_architecture_graph,
)
from build_vendor_tenda_ac9_registrar_inventory_report import ARTIFACT_SHA256, ROOT


_SYMBOLS = {
    "tpi_upfile_handle", "tpi_sys_cfg_upload", "doSystemCmd",
    "UploadValue", "SendMsg", "RecvMsg",
}


def build() -> dict:
    run = analyze_extracted_root(MappingAnalysisRequest(ROOT, ARTIFACT_SHA256))
    graph = project_communication_architecture_graph(run.catalog)
    upload_dispatch = next(
        item for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.NATIVE_CGI_DISPATCH
        and item.canonical_identity == "UploadCfg"
    )
    upload_command = next(
        item for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.NATIVE_COMMAND_BINDING
        and dict(item.attributes).get("command") == "Upload"
        and dict(item.attributes).get("table_symbol") == "gCtlCmdArr"
    )
    origin_refs = {upload_dispatch.candidate_id, upload_command.candidate_id}
    calls = []
    for item in run.catalog.candidates:
        if item.candidate_kind is not DiscoveryCandidateKind.NATIVE_CROSS_ELF_CALL:
            continue
        attributes = dict(item.attributes)
        origins = set(json.loads(attributes["origin_refs"]))
        if origins & origin_refs and attributes["imported_symbol"] in _SYMBOLS:
            calls.append({
                "candidate_id": item.candidate_id,
                "source_function_identity": attributes["source_function_identity"],
                "callsite_address": attributes["callsite_address"],
                "imported_symbol": attributes["imported_symbol"],
                "target_function_identity": attributes["target_function_identity"],
                "target_resolution_status": attributes["target_resolution_status"],
                "argument_literals": json.loads(attributes["argument_literals"]),
                "origin_refs": sorted(origins & origin_refs),
                "evidence_ids": list(item.evidence_ids),
            })
    calls.sort(key=lambda item: (
        item["source_function_identity"], item["callsite_address"],
        item["imported_symbol"],
    ))
    required = {
        ("bin/httpd@0x0003b850", "0x0003ba38", "tpi_upfile_handle"),
        ("lib/libtpi.so@0x00009e80", "0x00009ef4", "tpi_sys_cfg_upload"),
        ("lib/libtpi.so@0x00009c5c", "0x00009d68", "doSystemCmd"),
        ("bin/cfm@0x00009e20", "0x00009e64", "UploadValue"),
        ("lib/libCfm.so@0x0000429c", "0x00004334", "SendMsg"),
        ("lib/libCfm.so@0x0000429c", "0x00004374", "RecvMsg"),
    }
    observed = {
        (item["source_function_identity"], item["callsite_address"],
         item["imported_symbol"])
        for item in calls
    }
    if not required <= observed:
        raise RuntimeError("AC9 cross-ELF persistence chain is incomplete")
    command_call = next(
        item for item in calls
        if item["source_function_identity"] == "lib/libtpi.so@0x00009c5c"
        and item["imported_symbol"] == "doSystemCmd"
    )
    if command_call["argument_literals"] != ["cfm Upload"]:
        raise RuntimeError("AC9 cfm Upload argument recovery drifted")
    if command_call["target_resolution_status"] != "unresolved_import_owner":
        raise RuntimeError("ambiguous doSystemCmd owner must remain unresolved")
    call_edges = [
        item for item in graph.edges
        if item.edge_kind is CommunicationGraphEdgeKind.CALLS
        and (item.source_ref in origin_refs or item.source_ref.startswith(
            "native-cross-elf-call:"
        ))
    ]
    return {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-23/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-cross-elf-persistence",
        "firmware_artifact_sha256": ARTIFACT_SHA256,
        "analysis_run_id": run.analysis_run_id,
        "catalog_id": run.catalog.catalog_id,
        "graph_id": graph.graph_id,
        "profile_id": run.profile_id,
        "analyzer_registry_id": run.analyzer_registry_id,
        "stages": [
            {
                "stage_name": item.stage_name,
                "coverage_status": item.coverage_status.value,
                "input_count": item.input_count,
                "output_count": item.output_count,
                "diagnostics": list(item.diagnostics),
            }
            for item in run.stages
            if item.stage_name in {
                "native_pointer_command_binding", "native_cross_elf_call"
            }
        ],
        "anchors": {
            "upload_dispatch_ref": upload_dispatch.candidate_id,
            "upload_command_ref": upload_command.candidate_id,
        },
        "selected_calls": calls,
        "call_edge_count": len(call_edges),
        "closed_obligation": "configuration-persistence-link",
        "remaining_obligations": [
            "prove command process launch/runtime reachability",
            "recover uploaded configuration key parser or retain wildcard state write",
            "link wildcard state write to historical configuration-key sinks",
        ],
        "not_claimed": [
            "doSystemCmd is owned by an arbitrary same-name export",
            "the static call chain executed at runtime",
            "every uploaded configuration key is parsed or persisted",
            "a vulnerability is present or exploitable",
        ],
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
