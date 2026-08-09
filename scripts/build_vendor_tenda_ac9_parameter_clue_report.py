#!/usr/bin/env python3
"""Build the replayable AC9 DLNA parameter-clue research report."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from firmatlas.mapping import (
    FrontendAssetInput,
    ParameterClueArtifact,
    ParameterClueArtifactRole,
    ParameterCluePolicy,
    SourceArtifactEntry,
    discover_frontend_asset_graph,
    trace_frontend_parameter_clues,
)


def source(root: Path, path: Path) -> tuple[SourceArtifactEntry, bytes]:
    content = path.read_bytes()
    relative = path.relative_to(root).as_posix()
    return SourceArtifactEntry(relative, relative, "file", len(content), hashlib.sha256(content).hexdigest()), content


def role(path: str, content: bytes) -> ParameterClueArtifactRole:
    if content.startswith(b"\x7fELF"):
        return ParameterClueArtifactRole.NATIVE
    if path.startswith("etc/") or Path(path).suffix.lower() in {".conf", ".cfg", ".ini", ".xml"}:
        return ParameterClueArtifactRole.CONFIGURATION
    if Path(path).suffix.lower() in {".sh", ".lua", ".php", ".cgi"}:
        return ParameterClueArtifactRole.SCRIPT
    return ParameterClueArtifactRole.OTHER


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    frontend_source, frontend_content = source(args.root, args.root / "webroot_ro/js/dlna.js")
    graph = discover_frontend_asset_graph((FrontendAssetInput(frontend_source, frontend_content),))
    artifacts = []
    for path in sorted(args.root.rglob("*")):
        if not path.is_file() or path.is_symlink() or "webroot" in path.relative_to(args.root).parts[0]:
            continue
        item_source, content = source(args.root, path)
        artifacts.append(ParameterClueArtifact(item_source, content, role(item_source.canonical_path, content)))
    result = trace_frontend_parameter_clues(graph, tuple(artifacts), ParameterCluePolicy())
    endpoints = {candidate.candidate_id: candidate.endpoint for item in graph.results for candidate in item.candidates}
    payload = {
        "schema_version": "firmatlas.mapping.research/ac9-parameter-clue-r2-08/v1",
        "scope": "Tenda AC9 V15.03.2.21_cn DLNA frontend request parameters versus non-webroot artifacts",
        "claim_boundary": "Exact token co-occurrence is a discovery clue, not parameter-to-state value flow.",
        "frontend_requests": sorted(endpoints.values()),
        "known_parser_gaps": [
            {"endpoint": "goform/expandDlnaFile", "parameters": ["folderGrade", "filePath"], "reason": "custom $.GetSetData.setData wrapper is not yet modeled"},
            {"endpoint": "/goform/refreshDLNA", "parameters": ["action"], "reason": "jQuery.post form-encoded string payload is not yet modeled"},
        ],
        "coverage_status": result.coverage_status.value,
        "processed_artifact_count": result.processed_artifact_count,
        "processed_bytes": result.processed_bytes,
        "assessments": [
            {
                **asdict(item),
                "endpoint": endpoints.get(item.request_candidate_id),
                "occurrences": [
                    {**asdict(hit), "artifact_role": hit.artifact_role.value}
                    for hit in item.occurrences
                ],
            }
            for item in result.assessments
        ],
        "diagnostics": list(result.diagnostics),
        "evidence_atoms": [atom.to_dict() for atom in result.evidence_atoms if atom.producer == "frontend-parameter-clue"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
