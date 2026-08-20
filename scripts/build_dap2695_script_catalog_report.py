#!/usr/bin/env python3
"""Build the R2-35 DAP-2695 independent script-backend holdout report."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from firmatlas.mapping import (
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    analyze_extracted_root,
    project_communication_architecture_graph,
)

if __package__:
    from scripts.build_mapping_corpus_report import (
        DAP2695_FIRMWARE_SHA256,
        DAP2695_ROOT,
        _dap2695_script_catalog,
    )
else:
    from build_mapping_corpus_report import (
        DAP2695_FIRMWARE_SHA256,
        DAP2695_ROOT,
        _dap2695_script_catalog,
    )


ARTIFACT = Path(
    "var/mapping-work/r2-35-dap2695/acquisition/"
    "DAP-2695_120B20RC101.bin"
)
FOCUS_SOURCE = "www/__action.php"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(root: Path = DAP2695_ROOT, artifact: Path = ARTIFACT):
    if _sha256(artifact) != DAP2695_FIRMWARE_SHA256:
        raise ValueError("DAP-2695 artifact identity mismatch")
    scoped_catalog = _dap2695_script_catalog(root)
    if scoped_catalog is None:
        raise ValueError("DAP-2695 PHP source scope is unavailable")
    run = analyze_extracted_root(MappingAnalysisRequest(
        root=root,
        firmware_artifact_sha256=DAP2695_FIRMWARE_SHA256,
        profile=MappingAnalysisProfile.auto_v21(),
    ))
    graph = project_communication_architecture_graph(run.catalog)
    stage = next(item for item in run.stages if item.stage_name == "script_backend")
    script_paths = tuple(sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*.php") if path.is_file()
    ))
    capabilities = tuple(sorted({
        item.capability for item in scoped_catalog.evidence_atoms
    }))
    focus_candidates = tuple(
        item for item in scoped_catalog.candidates
        if item.source_path == FOCUS_SOURCE
    )
    focus_evidence_ids = {
        evidence_id for item in focus_candidates for evidence_id in item.evidence_ids
    }
    focus_candidate_ids = {item.candidate_id for item in focus_candidates}
    focus_capabilities = tuple(sorted({
        item.capability for item in scoped_catalog.evidence_atoms
        if item.evidence_id in focus_evidence_ids
    }))

    report = {
        "schema_version": "firmatlas.mapping.dap2695-script-catalog-report/v1alpha1",
        "sample_role": "independent-script-backend-holdout",
        "firmware": {
            "vendor": "D-Link",
            "product": "DAP-2695 Rev.A",
            "release": "1.20B20 RC101",
            "artifact_sha256": DAP2695_FIRMWARE_SHA256,
            "inventory_sha256": run.source_inventory_sha256,
            "inventory_coverage_status": run.inventory_coverage_status.value,
        },
        "analysis_run": {
            "analysis_run_id": run.analysis_run_id,
            "profile_id": run.profile_id,
            "analyzer_registry_id": run.analyzer_registry_id,
            "coverage_status": run.coverage_status.value,
            "catalog_id": run.catalog.catalog_id,
            "candidate_count": len(run.catalog.candidates),
            "evidence_count": len(run.catalog.evidence_atoms),
            "open_obligation_count": len(run.catalog.open_obligations),
            "script_backend_stage": {
                "coverage_status": stage.coverage_status.value,
                "input_count": stage.input_count,
                "output_count": stage.output_count,
                "diagnostics": list(stage.diagnostics),
            },
        },
        "script_backend_projection": {
            "source_scope_schema": "firmatlas.mapping.selected-source-inventory/v1",
            "source_inventory_sha256": scoped_catalog.source_inventory_sha256,
            "source_glob": "**/*.php",
            "source_count": len(script_paths),
            "scoped_catalog_id": scoped_catalog.catalog_id,
            "scoped_catalog_coverage_status": scoped_catalog.coverage_status.value,
            "candidate_count": len(scoped_catalog.candidates),
            "evidence_count": len(scoped_catalog.evidence_atoms),
            "open_obligation_count": len(scoped_catalog.open_obligations),
            "candidate_kind_distribution": dict(sorted(Counter(
                item.candidate_kind.value for item in scoped_catalog.candidates
            ).items())),
            "capabilities": list(capabilities),
        },
        "focus_case": {
            "source_path": FOCUS_SOURCE,
            "source_sha256": _sha256(root / FOCUS_SOURCE),
            "candidate_count": len(focus_candidates),
            "evidence_count": len(focus_evidence_ids),
            "capabilities": list(focus_capabilities),
            "parameter_names": sorted({
                item.name for item in scoped_catalog.parameters
                if item.owner_ref in focus_candidate_ids
            }),
        },
        "graph": {
            "graph_id": graph.graph_id,
            "projection_status": graph.projection_status.value,
            "node_count": len(graph.nodes),
            "edge_count": len(graph.edges),
        },
        "interpretation_boundary": [
            "the selected-source catalog covers every readable PHP file in the explicit **/*.php rootfs scope",
            "the full auto-v21 run remains partial because a dangling symlink and non-UTF-8 frontend inputs are preserved as independent diagnostics",
            "static parameter and configuration access evidence does not prove runtime reachability, authentication state, vulnerability, or exploitability",
        ],
    }
    return report, run, graph


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--root", type=Path, default=DAP2695_ROOT)
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
