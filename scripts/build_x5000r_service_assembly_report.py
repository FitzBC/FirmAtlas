#!/usr/bin/env python3
"""Replay X5000R's static init-to-CGI service assembly chain."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from firmatlas.mapping import (
    MipsServiceAssemblyAnchor,
    ServiceAssemblyArtifact,
    SourceArtifactEntry,
    discover_mips_service_assembly,
)

if __package__:
    from scripts.build_x5000r_nested_dispatch_report import (
        X5000R_ROOT,
        build_analysis as build_nested_analysis,
    )
else:
    from build_x5000r_nested_dispatch_report import (
        X5000R_ROOT,
        build_analysis as build_nested_analysis,
    )


ARTIFACT_PATHS = (
    "sbin/rc",
    "usr/sbin/lighttpd",
    "lighttp/lighttpd.conf",
    "www/cgi-bin/cstecgi.cgi",
)


def _artifact(path: str, content: bytes) -> ServiceAssemblyArtifact:
    return ServiceAssemblyArtifact(
        SourceArtifactEntry(
            path,
            path,
            "file",
            len(content),
            hashlib.sha256(content).hexdigest(),
        ),
        content,
    )


def build_analysis(root: Path = X5000R_ROOT):
    nested = build_nested_analysis(root)[-1]
    artifacts = tuple(
        _artifact(path, (root / path).read_bytes()) for path in ARTIFACT_PATHS
    )
    assembly = discover_mips_service_assembly(
        artifacts,
        (MipsServiceAssemblyAnchor(
            nested.paths[0].path_id,
            "/cgi-bin/cstecgi.cgi",
        ),),
    )
    return artifacts, nested, assembly


def build_summary(root: Path = X5000R_ROOT) -> dict:
    artifacts, nested, result = build_analysis(root)
    assembly = result.assemblies[0]
    dispatch = nested.paths[0]
    return {
        "schema_version": "firmatlas.mapping.x5000r-service-assembly/v1alpha1",
        "sources": [
            {
                "path": item.source.canonical_path,
                "content_sha256": item.source.content_sha256,
                "size": item.source.size,
            }
            for item in artifacts
        ],
        "service_assembly_analysis": result.to_dict(),
        "static_chain": [
            {
                "stage": "firmware_initialization",
                "identity": assembly.bootstrap_identity,
                "callsite": "0x{:08x}".format(assembly.bootstrap_callsite),
                "next": assembly.service_group_identity,
            },
            {
                "stage": "service_group",
                "identity": assembly.service_group_identity,
                "callsite": "0x{:08x}".format(assembly.service_group_callsite),
                "next": assembly.launcher_identity,
            },
            {
                "stage": "service_launch",
                "identity": assembly.launcher_identity,
                "callsite": "0x{:08x}".format(assembly.launch_callsite),
                "argument_table": "0x{:08x}".format(
                    assembly.argument_table_address
                ),
                "arguments": list(assembly.launch_arguments),
            },
            {
                "stage": "server_configuration",
                "server": assembly.server_artifact_path,
                "configuration": assembly.config_artifact_path,
                "listeners": list(assembly.listeners),
                "document_root": assembly.document_root,
                "cgi_namespace": assembly.cgi_namespace,
            },
            {
                "stage": "request_artifact",
                "request_path": assembly.request_path,
                "artifact": assembly.target_artifact_path,
                "nested_dispatch": dispatch.path_id,
                "handler": dispatch.handler_identity,
            },
        ],
        "interpretation_boundary": {
            "supported": (
                "the shipped init path schedules start_httpd, whose exact argv "
                "selects the shipped lighttpd and configuration; that configuration "
                "maps /cgi-bin/ under /www/ to the shipped cstecgi.cgi artifact"
            ),
            "not_claimed": (
                "a live process observation, boot success, network reachability, "
                "external mediation, authorization state, or exploitability"
            ),
        },
        "ghidra_trigger": {
            "triggered": False,
            "reason": (
                "bounded exported init/service/launcher symbols, direct/GOT calls, "
                "argv table pointers, and config spans replay from original bytes"
            ),
            "future_trigger": (
                "use the isolated Ghidra Candidate Worker for stripped init chains, "
                "computed argv vectors, or indirect service factories"
            ),
        },
        "obligation_transition": {
            "resolved": "obligation:x5000r-static-service-assembly",
            "retained": "obligation:x5000r-upload-runtime-reachability",
            "reason": (
                "static initialization and artifact resolution are now proved, "
                "while runtime observation remains a separate evidence class"
            ),
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
