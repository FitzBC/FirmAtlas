#!/usr/bin/env python3
"""Build the AC9 R2-22 CGI configuration-ingress evidence report."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from firmatlas.mapping import (
    BUILTIN_ANALYZER_REGISTRY_V14,
    CommunicationGraphEdgeKind,
    DiscoveryCandidateKind,
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    analyze_extracted_root,
    project_communication_architecture_graph,
)
from firmatlas.mapping.native_deep import _file_offset_for_address, _parse_elf
from build_vendor_tenda_ac9_registrar_inventory_report import ARTIFACT_SHA256, ROOT


def _artifact(path: str) -> tuple[Path, bytes]:
    artifact = ROOT.joinpath(*path.split("/"))
    content = artifact.read_bytes()
    return artifact, content


def _instruction(path: str, address: int, claim: str) -> dict:
    _, content = _artifact(path)
    offset = _file_offset_for_address(_parse_elf(content), address)
    if offset is None:
        raise RuntimeError("address is not file-backed: {}@0x{:x}".format(path, address))
    return {
        "artifact_path": path,
        "artifact_sha256": hashlib.sha256(content).hexdigest(),
        "virtual_address": "0x{:08x}".format(address),
        "file_offset": offset,
        "instruction_bytes_hex": content[offset:offset + 4].hex(),
        "claim": claim,
    }


def _literal(path: str, value: str, claim: str) -> dict:
    _, content = _artifact(path)
    raw = value.encode("utf-8")
    offset = content.find(raw)
    if offset < 0 or content.find(raw, offset + 1) >= 0:
        raise RuntimeError("literal must occur exactly once: {} {!r}".format(path, value))
    return {
        "artifact_path": path,
        "artifact_sha256": hashlib.sha256(content).hexdigest(),
        "file_offset": offset,
        "length": len(raw),
        "literal": value,
        "claim": claim,
    }


def build() -> dict:
    run = analyze_extracted_root(
        MappingAnalysisRequest(
            ROOT,
            ARTIFACT_SHA256,
            profile=MappingAnalysisProfile.auto_v14(),
        ),
        registry=BUILTIN_ANALYZER_REGISTRY_V14,
    )
    requests = {
        item.candidate_id: item
        for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.REQUEST_INTERFACE
    }
    upload = next(
        item for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.NATIVE_CGI_DISPATCH
        and item.canonical_identity == "UploadCfg"
    )
    upload_attributes = dict(upload.attributes)
    request = requests[upload_attributes["target_ref"]]
    filename = next(
        item for item in run.catalog.parameters
        if item.owner_ref == request.candidate_id
        and item.name == "filename"
    )
    handler = next(
        item for item in run.catalog.candidates
        if item.candidate_id == upload_attributes["handler_ref"]
    )
    graph = project_communication_architecture_graph(run.catalog)
    path_edges = [
        item for item in graph.edges
        if (
            item.source_ref == request.candidate_id
            and item.target_ref == upload.candidate_id
            and item.edge_kind is CommunicationGraphEdgeKind.DISPATCHED_BY
        ) or (
            item.source_ref == upload.candidate_id
            and item.target_ref == handler.candidate_id
            and item.edge_kind is CommunicationGraphEdgeKind.BINDS_HANDLER
        )
    ]
    if len(path_edges) != 2:
        raise RuntimeError("AC9 upload graph path is incomplete")

    automated_evidence_ids = {
        *request.evidence_ids,
        *filename.evidence_ids,
        *upload.evidence_ids,
        *handler.evidence_ids,
    }
    evidence = {
        item.evidence_id: item.to_dict() for item in run.catalog.evidence_atoms
    }
    manual_chain = (
        _instruction(
            "bin/httpd", 0x3BA38,
            "UploadCfg handler calls libtpi tpi_upfile_handle with mode 1",
        ),
        _instruction(
            "lib/libtpi.so", 0x9EF4,
            "tpi_upfile_handle mode 1 calls tpi_sys_cfg_upload",
        ),
        _literal(
            "lib/libtpi.so", "/webroot/default.cfg",
            "public configuration upload target",
        ),
        _literal(
            "lib/libtpi.so", "/webroot/default_url.cfg",
            "URL configuration upload target",
        ),
        _literal(
            "lib/libtpi.so", "##the public configure end##",
            "uploaded blob split boundary",
        ),
        _literal(
            "lib/libtpi.so", "cfm Upload",
            "configuration service command",
        ),
        _instruction(
            "lib/libtpi.so", 0x9D68,
            "tpi_sys_cfg_upload invokes doSystemCmd for cfm Upload",
        ),
        _instruction(
            "bin/cfm", 0x9E64,
            "Upload command handler calls libCfm UploadValue",
        ),
        _instruction(
            "lib/libCfm.so", 0x4334,
            "UploadValue sends a framed configuration message over Cfm IPC",
        ),
        _instruction(
            "lib/libCfm.so", 0x4374,
            "UploadValue receives the Cfm IPC response",
        ),
    )
    cgi_stage = next(
        item for item in run.stages if item.stage_name == "native_cgi_dispatch"
    )
    return {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-22/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-configuration-ingress-iteration",
        "firmware_artifact_sha256": ARTIFACT_SHA256,
        "profile_id": run.profile_id,
        "analyzer_registry_id": run.analyzer_registry_id,
        "analysis_run_id": run.analysis_run_id,
        "catalog_id": run.catalog.catalog_id,
        "coverage_status": run.coverage_status.value,
        "automated_chain": {
            "request_ref": request.candidate_id,
            "interface_path": request.canonical_identity,
            "method": dict(request.attributes).get("method"),
            "multipart_parameter": filename.name,
            "parameter_namespace": filename.namespace,
            "dispatch_ref": upload.candidate_id,
            "dispatch_token": upload.canonical_identity,
            "dispatcher_identity": upload_attributes["dispatcher_identity"],
            "dispatcher_entry_count": int(
                upload_attributes["dispatcher_entry_count"]
            ),
            "comparison_target_address": upload_attributes[
                "comparison_target_address"
            ],
            "handler_ref": handler.candidate_id,
            "handler_identity": handler.canonical_identity,
            "graph_edges": [
                {**asdict(item), "edge_kind": item.edge_kind.value}
                for item in path_edges
            ],
            "evidence": [
                evidence[item] for item in sorted(automated_evidence_ids)
            ],
        },
        "native_cgi_dispatch_stage": {
            "coverage_status": cgi_stage.coverage_status.value,
            "input_count": cgi_stage.input_count,
            "output_count": cgi_stage.output_count,
            "diagnostics": list(cgi_stage.diagnostics),
        },
        "manual_cross_binary_continuation": list(manual_chain),
        "obligation_state": {
            "closed_by_auto_v14": [
                "frontend multipart upload ingress",
                "CGI string-switch dispatcher ownership",
                "direct native handler binding",
            ],
            "open_for_next_producer": [
                "automate handler-to-tpi-to-cfm cross-binary call chain",
                "model uploaded configuration as a wildcard state-write surface",
                "link historical configuration-key sinks without relabeling them as HTTP parameters",
            ],
        },
        "not_claimed": [
            "an uploaded file was accepted at runtime",
            "every uploaded key is valid or persisted",
            "security.ddos.map or sys.schedulereboot fields are HTTP parameters",
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
