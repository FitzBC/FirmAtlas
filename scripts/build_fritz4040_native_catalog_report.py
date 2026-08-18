#!/usr/bin/env python3
"""Build the R2-34 FRITZ!Box 4040 native UBUS holdout report."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from firmatlas.mapping import (
    CommunicationGraphEdgeKind,
    DiscoveryCandidateKind,
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    analyze_extracted_root,
    project_communication_architecture_graph,
)

if __package__:
    from scripts.build_mapping_corpus_report import (
        FRITZ4040_FIRMWARE_SHA256,
        FRITZ4040_ROOT,
        _fritz4040_native_catalog,
    )
else:
    from build_mapping_corpus_report import (
        FRITZ4040_FIRMWARE_SHA256,
        FRITZ4040_ROOT,
        _fritz4040_native_catalog,
    )


ARTIFACT = Path(
    "var/mapping-work/r2-34-fritz4040/"
    "openwrt-19.07.10-ipq40xx-generic-avm_fritzbox-4040-squashfs-sysupgrade.bin"
)
MISSING_FROM_FRONTEND_DRIVEN = (
    "ubus://iwinfo/devices",
    "ubus://iwinfo/info",
    "ubus://iwinfo/phyname",
    "ubus://iwinfo/survey",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(root: Path = FRITZ4040_ROOT, artifact: Path = ARTIFACT):
    if _sha256(artifact) != FRITZ4040_FIRMWARE_SHA256:
        raise ValueError("FRITZ!Box 4040 artifact identity mismatch")
    scoped_catalog = _fritz4040_native_catalog(root)
    if scoped_catalog is None:
        raise ValueError("FRITZ!Box 4040 rpcd plugins are unavailable")
    run = analyze_extracted_root(MappingAnalysisRequest(
        root=root,
        firmware_artifact_sha256=FRITZ4040_FIRMWARE_SHA256,
        profile=MappingAnalysisProfile.auto_v21(),
    ))
    graph = project_communication_architecture_graph(run.catalog)

    direct_operations = tuple(sorted((
        item for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.REQUEST_INTERFACE
        and dict(item.attributes).get("request_role") == "native_registration"
    ), key=lambda item: item.canonical_identity))
    direct_identities = {item.canonical_identity for item in direct_operations}
    frontend_bound_identities = {
        item.canonical_identity for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.UBUS_BACKEND_BINDING
        and dict(item.attributes).get("binding_status")
        == "verified_native_registration"
        and "handler_ref" not in dict(item.attributes)
    }
    direct_bindings = tuple(
        item for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.UBUS_BACKEND_BINDING
        and "handler_ref" in dict(item.attributes)
    )
    direct_handlers = {
        dict(item.attributes)["handler_ref"] for item in direct_bindings
    }
    binding_edges = tuple(
        item for item in graph.edges
        if item.edge_kind is CommunicationGraphEdgeKind.BINDS_HANDLER
        and item.source_ref in {candidate.candidate_id for candidate in direct_bindings}
        and item.target_ref in direct_handlers
    )
    stage = next(item for item in run.stages if item.stage_name == "native_ubus_catalog")

    report = {
        "schema_version": "firmatlas.mapping.fritz4040-native-catalog-report/v1alpha1",
        "sample_role": "independent-native-only-holdout",
        "firmware": {
            "product": "AVM FRITZ!Box 4040",
            "release": "OpenWrt 19.07.10",
            "artifact_sha256": FRITZ4040_FIRMWARE_SHA256,
            "inventory_sha256": run.source_inventory_sha256,
            "inventory_coverage_status": run.inventory_coverage_status.value,
        },
        "analysis_run": {
            "analysis_run_id": run.analysis_run_id,
            "profile_id": run.profile_id,
            "analyzer_registry_id": run.analyzer_registry_id,
            "coverage_status": run.coverage_status.value,
            "stage": {
                "coverage_status": stage.coverage_status.value,
                "input_count": stage.input_count,
                "output_count": stage.output_count,
                "diagnostics": list(stage.diagnostics),
            },
            "catalog_id": run.catalog.catalog_id,
            "candidate_count": len(run.catalog.candidates),
            "evidence_count": len(run.catalog.evidence_atoms),
            "open_obligation_count": len(run.catalog.open_obligations),
            "candidate_kind_distribution": dict(sorted(Counter(
                item.candidate_kind.value for item in run.catalog.candidates
            ).items())),
        },
        "direct_native_projection": {
            "scoped_catalog_id": scoped_catalog.catalog_id,
            "scoped_catalog_coverage_status": scoped_catalog.coverage_status.value,
            "scoped_candidate_count": len(scoped_catalog.candidates),
            "scoped_evidence_count": len(scoped_catalog.evidence_atoms),
            "object_count": len({
                dict(item.attributes)["object_name"] for item in direct_operations
            }),
            "operation_count": len(direct_operations),
            "binding_count": len(direct_bindings),
            "handler_count": len(direct_handlers),
            "binds_handler_edge_count": len(binding_edges),
            "operations": [item.canonical_identity for item in direct_operations],
        },
        "regression_delta": {
            "frontend_driven_operation_count": len(frontend_bound_identities),
            "direct_native_operation_count": len(direct_identities),
            "previously_missing_operations": list(MISSING_FROM_FRONTEND_DRIVEN),
            "previously_missing_now_present": sorted(
                set(MISSING_FROM_FRONTEND_DRIVEN) & direct_identities
            ),
        },
        "graph": {
            "graph_id": graph.graph_id,
            "projection_status": graph.projection_status.value,
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
        },
        "interpretation_boundary": [
            "direct native registration proves a statically registered UBUS operation and handler binding",
            "full auto-v21 coverage remains partial where unrelated analyzers preserve open obligations",
            "static registration does not prove runtime reachability, access control, vulnerability, or exploitability",
        ],
    }
    return report, run, graph


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--root", type=Path, default=FRITZ4040_ROOT)
    parser.add_argument("--artifact", type=Path, default=ARTIFACT)
    parser.add_argument("--analysis-output", type=Path)
    parser.add_argument("--graph-output", type=Path)
    args = parser.parse_args()
    report, run, graph = build(args.root, args.artifact)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if args.analysis_output is not None:
        args.analysis_output.write_text(
            json.dumps(run.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if args.graph_output is not None:
        args.graph_output.write_text(
            json.dumps(graph.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
