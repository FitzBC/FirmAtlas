#!/usr/bin/env python3
"""Replay X5000R multipart upload mode into its native operation table."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from firmatlas.mapping import (
    MipsNestedDispatchAnchor,
    discover_mips_cgi_nested_dispatch,
)

if __package__:
    from scripts.build_x5000r_expanded_frontend_report import (
        X5000R_ROOT,
        build_analysis as build_expanded_analysis,
    )
else:
    from build_x5000r_expanded_frontend_report import (
        X5000R_ROOT,
        build_analysis as build_expanded_analysis,
    )


TARGET_OPERATION = "setUploadSetting"
TARGET_TRANSPORT = "upload"


def build_analysis(root: Path = X5000R_ROOT):
    assets, frontend, native_source, native, artifacts, difference = (
        build_expanded_analysis(root)
    )
    candidates = {
        item.candidate_id: item
        for result in frontend.results
        for item in result.candidates
    }
    parameters = [
        item
        for result in frontend.results
        for item in result.parameters
    ]
    operation = next(
        item for item in parameters
        if item.literal_value == TARGET_OPERATION
        and item.is_operation_selector
    )
    transport = next(
        item for item in parameters
        if item.request_candidate_id == operation.request_candidate_id
        and item.literal_value == TARGET_TRANSPORT
        and item.is_operation_selector
    )
    anchor = MipsNestedDispatchAnchor(
        operation.request_candidate_id,
        transport.name,
        transport.literal_value,
        operation.name,
        operation.literal_value,
    )
    native_content = (root / native_source.canonical_path).read_bytes()
    dispatch = discover_mips_cgi_nested_dispatch(
        native_source, native_content, (anchor,)
    )
    return (
        assets,
        frontend,
        native_source,
        native,
        artifacts,
        difference,
        candidates[operation.request_candidate_id],
        transport,
        operation,
        dispatch,
    )


def build_summary(root: Path = X5000R_ROOT) -> dict:
    (
        _assets,
        _frontend,
        native_source,
        _native,
        _artifacts,
        _difference,
        candidate,
        transport,
        operation,
        dispatch,
    ) = build_analysis(root)
    return {
        "schema_version": "firmatlas.mapping.x5000r-nested-dispatch/v1alpha1",
        "source": {
            "path": native_source.canonical_path,
            "content_sha256": native_source.content_sha256,
            "size": native_source.size,
        },
        "frontend_anchor": {
            "request_candidate_id": candidate.candidate_id,
            "endpoint": candidate.endpoint,
            "method": candidate.method,
            "representation": candidate.representation,
            "source_construct": candidate.source_construct,
            "request_evidence_ids": list(candidate.evidence_ids),
            "transport_selector": {
                "name": transport.name,
                "value": transport.literal_value,
                "namespace": transport.namespace.value,
                "evidence_ids": list(transport.evidence_ids),
            },
            "nested_operation_selector": {
                "name": operation.name,
                "value": operation.literal_value,
                "namespace": operation.namespace.value,
                "evidence_ids": list(operation.evidence_ids),
            },
        },
        "native_dispatch": dispatch.to_dict(),
        "architecture_path": [
            {
                "stage": "transport_mode",
                "value": path.transport_selector,
                "address": "0x{:08x}".format(path.transport_match_callsite),
            },
            {
                "stage": "query_segment_extraction",
                "value": path.nested_selector,
                "address": "0x{:08x}".format(path.selector_extract_callsite),
            },
            {
                "stage": "multipart_body_parse",
                "value": "cutUploadFile",
                "address": "0x{:08x}".format(path.upload_parse_callsite),
            },
            {
                "stage": "slash_suffix_normalization",
                "value": path.normalized_operation,
                "address": "0x{:08x}".format(
                    path.suffix_normalization_address
                ),
            },
            {
                "stage": "operation_table",
                "value": path.dispatch_table_symbol,
                "address": "0x{:08x}".format(path.registration_address),
            },
            {
                "stage": "handler",
                "value": path.handler_identity,
                "address": "0x{:08x}".format(path.handler_address),
            },
        ]
        if (path := next(iter(dispatch.paths), None)) is not None else [],
        "ghidra_trigger": {
            "triggered": False,
            "reason": (
                "main/cutUploadFile/table symbols and the bounded MIPS branch, "
                "query extraction, suffix normalization, table loop, and exact "
                "handler entry are replayable from original ELF bytes"
            ),
            "future_trigger": (
                "use the isolated Ghidra Candidate Worker when a variant hides "
                "these edges behind unsupported CFG, indirect factories, or "
                "cross-function P-code flow"
            ),
        },
        "obligation_transition": {
            "resolved": "obligation:x5000r-upload-mode-owner",
            "created": [
                "obligation:x5000r-upload-runtime-reachability",
                "obligation:x5000r-upload-auth-guard",
            ],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=X5000R_ROOT)
    args = parser.parse_args()
    print(json.dumps(build_summary(args.root), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
