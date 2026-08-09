#!/usr/bin/env python3
"""Build AC9 auto-v7 response-fixture and DLNA architecture clue report."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from firmatlas.mapping import (
    BUILTIN_ANALYZER_REGISTRY_V7,
    DiscoveryCandidateKind,
    EvidenceClaim,
    HistoricalVulnerabilityRecord,
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    ObservationKind,
    SourceArtifactEntry,
    SpanKind,
    SpanSelection,
    analyze_extracted_root,
    build_historical_vulnerability_audit,
    build_potential_hidden_interface_index,
    capture_evidence,
    compare_historical_expectations,
    load_historical_expectations,
)
from firmatlas.mapping.domain import AnalyzerIdentity
from build_vendor_tenda_ac9_registrar_inventory_report import (
    ARTIFACT_SHA256,
    EXPECTATIONS,
    ROOT,
    VULNERABILITY_SCOPE,
)


_CLUE_PRODUCER = AnalyzerIdentity("ac9-dlna-architecture-clue-report", "0.1.0")


def _architecture_clues() -> list[dict]:
    specifications = (
        ("etc_ro/init.d/rcS", b"/var/etc/upan", "prepares_media_mount"),
        ("etc_ro/nginx/conf/nginx.conf", b"/var/etc/upan/", "aliases_media_download"),
        ("bin/netctrl", b"/var/etc/upan", "mounts_media_storage"),
        ("bin/httpd", b"dlna.en", "reads_dlna_state"),
        ("bin/httpd", b"deviceName", "mentions_dlna_device_field"),
        ("bin/httpd", b"minidlna", "stops_media_daemon_during_upgrade"),
        ("bin/time_check", b"minidlna", "monitors_media_daemon"),
        ("bin/time_check", b"/var/etc/upan", "checks_media_mount"),
    )
    output = []
    for relative, token, capability in specifications:
        content = (ROOT / relative).read_bytes()
        offset = content.find(token)
        if offset < 0:
            raise RuntimeError("missing AC9 architecture clue: {}:{}".format(relative, token))
        source = SourceArtifactEntry(
            relative, relative, "file", len(content), hashlib.sha256(content).hexdigest()
        )
        atom = capture_evidence(
            source,
            content,
            SpanSelection(
                SpanKind.BINARY if content.startswith(b"\x7fELF") else SpanKind.TEXT_UTF8,
                offset,
                offset + len(token),
            ),
            EvidenceClaim(
                "ac9-dlna-architecture",
                "has_architecture_clue",
                token.decode("utf-8"),
                ObservationKind.DIRECT_STATIC,
                capability,
                1.0,
            ),
            _CLUE_PRODUCER,
        )
        output.append(atom.to_dict())
    return output


def build() -> dict:
    run = analyze_extracted_root(MappingAnalysisRequest(
        ROOT, ARTIFACT_SHA256, profile=MappingAnalysisProfile.auto_v7()
    ), registry=BUILTIN_ANALYZER_REGISTRY_V7)
    fixture_candidates = [
        item for item in run.catalog.candidates
        if item.candidate_kind is DiscoveryCandidateKind.RESPONSE_FIXTURE_CONTRACT
    ]
    fixture_by_id = {item.candidate_id: item for item in fixture_candidates}
    dlna_fixture_ids = {
        item.candidate_id for item in fixture_candidates
        if "dlna" in item.canonical_identity.lower()
    }
    dlna_fixtures = [
        {
            "endpoint_clue": item.canonical_identity,
            "source_path": item.source_path,
            "attributes": dict(item.attributes),
            "evidence_ids": list(item.evidence_ids),
            "response_fields": [
                {
                    "json_pointer": field.name,
                    "evidence_ids": list(field.evidence_ids),
                }
                for field in run.catalog.parameters
                if field.owner_ref == item.candidate_id
            ],
        }
        for item in fixture_candidates
        if item.candidate_id in dlna_fixture_ids
    ]
    dlna_fixture_proof_ids = {
        evidence_id
        for item in fixture_candidates
        if item.candidate_id in dlna_fixture_ids
        for evidence_id in item.evidence_ids
    }
    expectations = load_historical_expectations(json.loads(
        EXPECTATIONS.read_text(encoding="utf-8")
    ))
    scope = json.loads(VULNERABILITY_SCOPE.read_text(encoding="utf-8"))
    historical_diff = compare_historical_expectations(run.catalog, expectations)
    audit = build_historical_vulnerability_audit(
        historical_diff,
        tuple(HistoricalVulnerabilityRecord(**item) for item in scope["records"]),
    )
    hidden = build_potential_hidden_interface_index(run.catalog)
    return {
        "schema_version": "firmatlas.mapping.vendor-tenda-ac9-r2-10/v1alpha1",
        "sample_role": "primary-vendor-tenda-ac9-response-fixture-iteration",
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
            "response_fixture_count": len(fixture_candidates),
            "response_fixture_field_count": sum(
                1 for item in run.catalog.parameters if item.owner_ref in fixture_by_id
            ),
            "potential_hidden_interface_count": len(hidden.items),
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
        "dlna_response_fixture_contracts": dlna_fixtures,
        "dlna_response_fixture_evidence": [
            atom.to_dict() for atom in run.catalog.evidence_atoms
            if atom.evidence_id in dlna_fixture_proof_ids
        ],
        "dlna_architecture_evidence": _architecture_clues(),
        "historical_expectation_diff": historical_diff.to_dict(),
        "vulnerability_scope_audit": audit.to_dict(),
        "interpretation": {
            "supported": (
                "firmware-bundled JSON fixtures declare response shapes for DLNA "
                "operations and are linked to matching frontend request candidates; "
                "separate direct clues establish media mount, nginx alias, httpd state "
                "strings, and minidlna monitoring roles"
            ),
            "unresolved": (
                "no exact Native route registration or handler binding was observed "
                "for GetDlnaCfg, SetDlnaCfg, refreshDLNA, or expandDlnaFile"
            ),
            "not_claimed": (
                "fixtures prove runtime reachability, handler ownership, current-version "
                "vulnerability presence, or exploitability"
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
