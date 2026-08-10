#!/usr/bin/env python3
"""Build the R2-17 AC9-primary focused communication graph report."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from firmatlas.mapping import (
    BUILTIN_ANALYZER_REGISTRY_V13,
    CommunicationGraphEdgeKind,
    CommunicationGraphNodeKind,
    CommunicationGraphPolicy,
    MappingAnalysisProfile,
    MappingAnalysisRequest,
    analyze_extracted_root,
    project_communication_architecture_graph,
)
from build_vendor_tenda_ac9_registrar_inventory_report import (
    ARTIFACT_SHA256 as AC9_ARTIFACT_SHA256,
    ROOT as AC9_ROOT,
)
from build_vendor_tenda_ac9_ac18_dlna_feature_pivot_report import (
    AC18_ARTIFACT_SHA256,
)


_ENDPOINT_OPERATIONS = {
    "goform/GetDlnaCfg": "GetDlnaCfg",
    "goform/SetDlnaCfg": "SetDlnaCfg",
    "goform/expandDlnaFile?": "expandDlnaFile",
    "/goform/refreshDLNA": "refreshDLNA",
}
_EXPECTED_REACHABILITY = {
    "GetDlnaCfg": "top_level_declaration",
    "SetDlnaCfg": "top_level_declaration",
    "expandDlnaFile": "active_call_path",
    "refreshDLNA": "declared_but_unreached",
}
_R2_16_REPORT = Path(
    "docs/firmware-mapping/samples/"
    "r2-16-vendor-tenda-ac9-ac18-dlna-reachability.json"
)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _neighbors(graph, request_id: str, edge_kind) -> tuple:
    node_by_id = {item.node_id: item for item in graph.nodes}
    return tuple(
        node_by_id[item.target_ref]
        for item in graph.edges
        if item.edge_kind is edge_kind and item.source_ref == request_id
    )


def _operation_view(graph, endpoint: str, operation: str) -> dict:
    node_by_id = {item.node_id: item for item in graph.nodes}
    requests = tuple(
        item for item in graph.nodes
        if item.node_kind is CommunicationGraphNodeKind.INTERFACE
        and item.label == endpoint
    )
    if len(requests) != 1:
        raise RuntimeError(
            "expected one focused request for {}, observed {}".format(
                endpoint, len(requests)
            )
        )
    request = requests[0]
    parameters = _neighbors(
        graph, request.node_id, CommunicationGraphEdgeKind.ACCEPTS_PARAMETER
    )
    invocations = _neighbors(
        graph, request.node_id,
        CommunicationGraphEdgeKind.HAS_INVOCATION_STATE,
    )
    if len(invocations) != 1:
        raise RuntimeError("focused request requires one invocation state")
    associations = _neighbors(
        graph, request.node_id,
        CommunicationGraphEdgeKind.HAS_NATIVE_ASSOCIATION,
    )
    route_bindings = list(_neighbors(
        graph, request.node_id,
        CommunicationGraphEdgeKind.HAS_ROUTE_BINDING,
    ))
    for association in associations:
        route_bindings.extend(_neighbors(
            graph, association.node_id,
            CommunicationGraphEdgeKind.HAS_ROUTE_BINDING,
        ))
    route_bindings = tuple({
        item.node_id: item for item in route_bindings
    }.values())
    handlers = []
    for binding in route_bindings:
        handlers.extend(_neighbors(
            graph, binding.node_id, CommunicationGraphEdgeKind.BINDS_HANDLER
        ))
    gate_nodes = tuple(
        node_by_id[item.source_ref]
        for item in graph.edges
        if item.edge_kind is CommunicationGraphEdgeKind.GATES
        and item.target_ref == request.node_id
    )
    response_contracts = _neighbors(
        graph, request.node_id,
        CommunicationGraphEdgeKind.HAS_RESPONSE_CONTRACT,
    )
    obligations = list(_neighbors(
        graph, request.node_id,
        CommunicationGraphEdgeKind.REQUIRES_EVIDENCE,
    ))
    for association in associations:
        obligations.extend(_neighbors(
            graph, association.node_id,
            CommunicationGraphEdgeKind.REQUIRES_EVIDENCE,
        ))
    obligations = tuple({
        item.node_id: item for item in obligations
    }.values())
    invocation = invocations[0]
    selected_node_ids = {
        request.node_id,
        *(item.node_id for item in parameters),
        invocation.node_id,
        *(item.node_id for item in route_bindings),
        *(item.node_id for item in handlers),
        *(item.node_id for item in gate_nodes),
        *(item.node_id for item in associations),
        *(item.node_id for item in response_contracts),
        *(item.node_id for item in obligations),
    }
    selected_edges = tuple(
        item for item in graph.edges
        if item.source_ref in selected_node_ids
        and item.target_ref in selected_node_ids
    )
    evidence_ids = tuple(sorted({
        evidence_id
        for item in (
            request, *parameters, invocation, *route_bindings, *handlers,
            *gate_nodes, *response_contracts,
            *associations,
        )
        for evidence_id in item.evidence_ids
    } | {
        evidence_id
        for edge in selected_edges
        for evidence_id in edge.evidence_ids
    }))
    return {
        "operation": operation,
        "endpoint": endpoint,
        "request_node_id": request.node_id,
        "parameter_nodes": [
            {
                "node_id": item.node_id,
                "name": item.label,
                "namespace": dict(item.attributes)["namespace"],
                "evidence_ids": list(item.evidence_ids),
            }
            for item in sorted(parameters, key=lambda value: value.label)
        ],
        "invocation": {
            "node_id": invocation.node_id,
            "status": dict(invocation.attributes)["status"],
            "function_name": dict(invocation.attributes)["function_name"] or None,
            "root_kind": dict(invocation.attributes)["root_kind"] or None,
            "call_path": json.loads(dict(invocation.attributes)["call_path"]),
        },
        "feature_gates": [
            {
                "node_id": item.node_id,
                "symbol": item.label,
                "status": dict(item.attributes)["gate_status"],
            }
            for item in sorted(gate_nodes, key=lambda value: value.label)
        ],
        "route_bindings": [
            {
                "node_id": item.node_id,
                "route_token": item.label,
                "source_path": item.source_path,
                "handler_identity": dict(item.attributes)["handler_identity"],
            }
            for item in route_bindings
        ],
        "handlers": [
            {
                "node_id": item.node_id,
                "handler_identity": item.label,
                "source_path": item.source_path,
            }
            for item in handlers
        ],
        "response_contract_nodes": [
            item.node_id for item in response_contracts
        ],
        "open_obligations": [
            {
                "node_id": item.node_id,
                "required_capability": item.label,
                "reason": dict(item.attributes)["reason"],
            }
            for item in obligations
        ],
        "evidence_ids": list(evidence_ids),
    }


def _sample(root: Path, artifact_sha256: str) -> dict:
    run = analyze_extracted_root(
        MappingAnalysisRequest(
            root,
            artifact_sha256,
            profile=MappingAnalysisProfile.auto_v13(),
        ),
        registry=BUILTIN_ANALYZER_REGISTRY_V13,
    )
    graph = project_communication_architecture_graph(
        run.catalog,
        CommunicationGraphPolicy(
            focus_canonical_identities=tuple(_ENDPOINT_OPERATIONS),
            max_hops=4,
            max_nodes=2_000,
            max_edges=5_000,
        ),
    )
    node_counts = Counter(item.node_kind.value for item in graph.nodes)
    edge_counts = Counter(item.edge_kind.value for item in graph.edges)
    operations = tuple(
        _operation_view(graph, endpoint, operation)
        for endpoint, operation in _ENDPOINT_OPERATIONS.items()
    )
    return {
        "firmware_artifact_sha256": artifact_sha256,
        "analysis_run_id": run.analysis_run_id,
        "catalog_id": run.catalog.catalog_id,
        "profile_id": run.profile_id,
        "analyzer_registry_id": run.analyzer_registry_id,
        "source_catalog_coverage_status": graph.source_catalog_coverage_status.value,
        "graph_id": graph.graph_id,
        "graph_projection_status": graph.projection_status.value,
        "graph_diagnostics": list(graph.diagnostics),
        "node_kind_counts": dict(sorted(node_counts.items())),
        "edge_kind_counts": dict(sorted(edge_counts.items())),
        "operations": list(operations),
        "focused_graph": graph.to_dict(),
    }


def build(ac18_root: Path) -> dict:
    ac9 = _sample(AC9_ROOT, AC9_ARTIFACT_SHA256)
    ac18 = _sample(ac18_root, AC18_ARTIFACT_SHA256)
    by_sample = {
        "ac9": {item["operation"]: item for item in ac9["operations"]},
        "ac18": {item["operation"]: item for item in ac18["operations"]},
    }
    for sample in by_sample.values():
        observed = {
            operation: item["invocation"]["status"]
            for operation, item in sample.items()
        }
        if observed != _EXPECTED_REACHABILITY:
            raise RuntimeError("DLNA reachability classification changed")
    if any(
        item["route_bindings"] for item in by_sample["ac9"].values()
    ):
        raise RuntimeError("AC9 unexpectedly gained a DLNA route owner")
    ac18_owner_operations = {
        operation for operation, item in by_sample["ac18"].items()
        if item["route_bindings"]
    }
    if ac18_owner_operations != {
        "GetDlnaCfg", "SetDlnaCfg", "expandDlnaFile",
    }:
        raise RuntimeError("AC18 DLNA owner control changed")
    prior = json.loads(_R2_16_REPORT.read_text(encoding="utf-8"))
    historical_leads = []
    for lead in prior["historical_parameter_leads"]:
        item = dict(lead)
        operation = item["operation"]
        parameter = item["parameter"]
        for sample_name in ("ac9", "ac18"):
            item["{}_graph_parameter_observed".format(sample_name)] = (
                parameter in {
                    node["name"]
                    for node in by_sample[sample_name][operation]["parameter_nodes"]
                }
            )
        historical_leads.append(item)
    return {
        "schema_version": (
            "firmatlas.mapping.vendor-tenda-ac9-r2-17/"
            "communication-graph-v1alpha1"
        ),
        "sample_role": "ac9-primary-with-official-ac18-positive-control",
        "evidence_boundary": (
            "The graph is a deterministic read model over one immutable Catalog. "
            "It preserves evidence, coverage, and obligations but creates no new "
            "firmware fact, runtime reachability, vulnerability, or family-owner "
            "claim."
        ),
        "graph_policy": {
            "focus_canonical_identities": list(_ENDPOINT_OPERATIONS),
            "max_hops": 4,
            "max_nodes": 2000,
            "max_edges": 5000,
            "artifact_edges_do_not_expand_focus": True,
        },
        "ac9_primary": ac9,
        "ac18_positive_control": ac18,
        "comparison": {
            "ac9_direct_dlna_owner_count": sum(
                bool(item["route_bindings"])
                for item in by_sample["ac9"].values()
            ),
            "ac18_direct_dlna_owner_count": sum(
                bool(item["route_bindings"])
                for item in by_sample["ac18"].values()
            ),
            "shared_reachability_classification": True,
            "owner_transfer_allowed": False,
        },
        "historical_parameter_leads": historical_leads,
        "prior_round": {
            "report": _R2_16_REPORT.as_posix(),
            "report_sha256": _sha(_R2_16_REPORT),
        },
        "ui_handoff": {
            "view_preset_ids": [
                "interface_structure", "communication_components",
                "parameter_state", "completeness",
            ],
            "required_interactions": [
                "filter by node/edge kind and evidence status",
                "focus an exact interface with bounded semantic hops",
                "open candidate and EvidenceAtom details by stable identity",
                "overlay Coverage Ledger and unresolved obligations",
            ],
        },
        "open_obligations": [
            "connect historical expectation records as a separate comparison overlay",
            "add persisted graph projection and HTTP query adapter before product UI",
            "extend parameter-state graph only from explicit Catalog references",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ac18-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    payload = build(args.ac18_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
