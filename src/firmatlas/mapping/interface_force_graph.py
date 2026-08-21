"""Evidence-preserving firmware -> component -> interface -> parameter read model."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


SCHEMA_VERSION = "firmatlas.mapping.interface-force-graph/v1alpha1"


def _identifier(prefix: str, *parts: str) -> str:
    payload = "\x00".join(parts).encode("utf-8")
    return "{}:{}".format(prefix, hashlib.sha256(payload).hexdigest())


def _attributes(item: Mapping[str, Any]) -> Dict[str, str]:
    return {str(key): str(value) for key, value in item.get("attributes", [])}


def _json_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    try:
        observed = json.loads(value)
    except (TypeError, ValueError):
        return []
    return [str(item) for item in observed] if isinstance(observed, list) else []


def _is_web_interface(candidate: Mapping[str, Any]) -> bool:
    identity = str(candidate.get("canonical_identity", ""))
    shape = _attributes(candidate).get("endpoint_shape", "")
    if identity.startswith(("ubus://", "ipc://")) or shape == "logical_operation":
        return False
    return identity.startswith(("/", "goform/", "http://", "https://")) or shape in {
        "url_path", "exact_literal", "literal_prefix", "deterministic_derived",
    }


def _display_path(identity: str) -> str:
    return "/" + identity if identity.startswith("goform/") else identity


def _parameter_type(parameter: Mapping[str, Any]) -> Tuple[str, str]:
    values = [str(item) for item in parameter.get("selector_values", [])]
    literal = parameter.get("literal_value")
    observed = values or ([] if literal is None else [str(literal)])
    basis = "selector_domain" if values else "observed_literal"
    if not observed:
        return "unknown", "not_recovered"
    lowered = {item.lower() for item in observed}
    if lowered and lowered.issubset({"true", "false"}):
        return "boolean", basis
    try:
        for item in observed:
            int(item, 10)
        return "integer", basis
    except ValueError:
        return "string", basis


def _evidence_locations(
    evidence_ids: Iterable[str], evidence_by_id: Mapping[str, Mapping[str, Any]],
) -> List[Dict[str, str]]:
    result = []
    for evidence_id in dict.fromkeys(evidence_ids):
        atom = evidence_by_id.get(evidence_id)
        if atom is None:
            continue
        span = atom.get("source_span", {})
        result.append({
            "evidence_id": evidence_id,
            "capability": str(atom.get("capability", "")),
            "predicate": str(atom.get("predicate", "")),
            "artifact_path": str(span.get("artifact_path", "")),
            "locator": str(span.get("locator", "")),
        })
    return result


def _bounded_evidence_locations(
    evidence_ids: Iterable[str], evidence_by_id: Mapping[str, Mapping[str, Any]],
    limit: int = 12,
) -> Tuple[List[Dict[str, str]], int]:
    locations = _evidence_locations(evidence_ids, evidence_by_id)
    return locations[:limit], max(0, len(locations) - limit)


def project_interface_force_graph(
    catalog: Mapping[str, Any],
    release_context: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    """Build a bounded UI read model without inventing runtime or type facts."""

    candidates = list(catalog.get("candidates", []))
    parameters = list(catalog.get("parameters", []))
    associations = {
        item["association_id"]: item for item in catalog.get("associations", [])
    }
    evidence_by_id = {
        item["evidence_id"]: item for item in catalog.get("evidence_atoms", [])
    }
    obligations_by_target: Dict[str, List[Mapping[str, Any]]] = {}
    for item in catalog.get("open_obligations", []):
        obligations_by_target.setdefault(str(item.get("target_ref", "")), []).append(item)

    requests = {
        item["candidate_id"]: item for item in candidates
        if item.get("candidate_kind") == "request_interface" and _is_web_interface(item)
    }
    request_by_identity = {
        _display_path(str(item.get("canonical_identity", ""))): item
        for item in requests.values()
    }
    clues_by_parameter: Dict[str, List[Mapping[str, Any]]] = {}
    for item in candidates:
        if item.get("candidate_kind") != "parameter_clue_assessment":
            continue
        clues_by_parameter.setdefault(_attributes(item).get("target_ref", ""), []).append(item)

    native_kinds = {"native_route_binding", "native_cgi_dispatch", "native_cgi_selector"}
    native_candidates = [item for item in candidates if item.get("candidate_kind") in native_kinds]
    native_owner: Dict[str, str] = {}
    native_request: Dict[str, Mapping[str, Any]] = {}
    for item in native_candidates:
        attrs = _attributes(item)
        target = attrs.get("target_ref", "")
        association = associations.get(target)
        request_id = str(association.get("frontend_candidate_id", "")) if association else target
        if request_id in requests:
            native_owner[item["candidate_id"]] = request_id
            native_request[request_id] = item
            continue
        if item.get("candidate_kind") in {"native_cgi_dispatch", "native_cgi_selector"}:
            path = attrs.get("interface_path", "")
            if path in request_by_identity:
                request_id = request_by_identity[path]["candidate_id"]
                native_owner[item["candidate_id"]] = request_id
                native_request[request_id] = item

    root_id = _identifier("force-root", str(catalog.get("catalog_id", "")))
    identity = dict(release_context or {})
    firmware_label = " ".join(filter(None, (
        identity.get("vendor", ""), identity.get("device_model", ""),
        identity.get("firmware_version", ""),
    ))) or "未识别固件"
    nodes: List[Dict[str, Any]] = [{
        "node_id": root_id,
        "node_kind": "firmware",
        "label": firmware_label,
        "parent_id": None,
        "child_ids": [],
        "expandable": True,
        "status": str(catalog.get("coverage_status", "unknown")),
        "details": {
            "vendor": identity.get("vendor", "未确认"),
            "product": identity.get("product", "未确认"),
            "device_model": identity.get("device_model", "未确认"),
            "firmware_version": identity.get("firmware_version", "未确认"),
            "firmware_artifact_sha256": catalog.get("firmware_artifact_sha256", ""),
            "claim_boundary": "Catalog 的确定性 UI 投影；不证明运行时可达或漏洞存在。",
        },
    }]
    edges: List[Dict[str, str]] = []
    node_by_id = {root_id: nodes[0]}

    def ensure_component(source_path: str, binary: bool) -> str:
        component_id = _identifier("force-component", str(catalog.get("catalog_id", "")), source_path)
        if component_id not in node_by_id:
            node = {
                "node_id": component_id,
                "node_kind": "component",
                "label": source_path,
                "parent_id": root_id,
                "child_ids": [],
                "expandable": True,
                "status": "observed",
                "details": {
                    "component_kind": "binary" if binary else "frontend_module",
                    "source_path": source_path,
                    "ownership_basis": "native registration source" if binary else "unbound request source",
                },
            }
            nodes.append(node)
            node_by_id[component_id] = node
            node_by_id[root_id]["child_ids"].append(component_id)
            edges.append({
                "edge_id": _identifier("force-edge", root_id, component_id, "contains"),
                "source_ref": root_id, "target_ref": component_id,
                "edge_kind": "contains", "label": "包含组件",
            })
        return component_id

    interface_by_request: Dict[str, str] = {}
    interface_by_native: Dict[str, str] = {}

    def add_interface(
        label: str, component_id: str, candidate: Mapping[str, Any],
        request: Optional[Mapping[str, Any]], exposure_status: str,
    ) -> str:
        interface_id = _identifier("force-interface", component_id, label)
        if interface_id in node_by_id:
            return interface_id
        attrs = _attributes(candidate)
        request_attrs = _attributes(request or {})
        evidence_ids = list(dict.fromkeys((request or {}).get("evidence_ids", []) + candidate.get("evidence_ids", [])))
        candidate_ids = [candidate.get("candidate_id", "")]
        if request and request.get("candidate_id") != candidate.get("candidate_id"):
            candidate_ids.insert(0, request.get("candidate_id", ""))
        evidence_locations, additional_evidence_count = _bounded_evidence_locations(
            evidence_ids, evidence_by_id
        )
        node = {
            "node_id": interface_id,
            "node_kind": "interface",
            "label": label,
            "parent_id": component_id,
            "child_ids": [],
            "expandable": True,
            "status": str(candidate.get("claim_status", "candidate")),
            "details": {
                "candidate_ids": candidate_ids,
                "method": request_attrs.get("method") or attrs.get("method") or "unresolved",
                "path_status": (
                    request_attrs.get("endpoint_shape")
                    or attrs.get("interface_path_status")
                    or ("unresolved" if exposure_status == "native_registration_only" else "observed")
                ),
                "exposure_status": exposure_status,
                "frontend_reference_observed": request is not None,
                "handler_symbol": attrs.get("handler_symbol", "unresolved"),
                "handler_identity": attrs.get("handler_identity", "unresolved"),
                "source_path": candidate.get("source_path", ""),
                "source_construct": candidate.get("source_construct", ""),
                "evidence_locations": evidence_locations,
                "additional_evidence_count": additional_evidence_count,
                "open_obligations": [
                    {"reason": item.get("reason", ""), "required_capability": item.get("required_capability", "")}
                    for candidate_id in candidate_ids for item in obligations_by_target.get(candidate_id, [])
                ],
            },
        }
        nodes.append(node)
        node_by_id[interface_id] = node
        node_by_id[component_id]["child_ids"].append(interface_id)
        edges.append({
            "edge_id": _identifier("force-edge", component_id, interface_id, "exposes"),
            "source_ref": component_id, "target_ref": interface_id,
            "edge_kind": "exposes", "label": "暴露接口",
        })
        return interface_id

    for native in sorted(native_candidates, key=lambda item: (str(item.get("source_path", "")), str(item.get("canonical_identity", "")))):
        source_path = str(native.get("source_path", "")) or "owner unresolved"
        component_id = ensure_component(source_path, True)
        request_id = native_owner.get(native["candidate_id"], "")
        request = requests.get(request_id)
        attrs = _attributes(native)
        label = (
            _display_path(str(request.get("canonical_identity", ""))) if request
            else attrs.get("interface_path") or str(native.get("canonical_identity", ""))
        )
        interface_id = add_interface(
            label, component_id, native, request,
            "frontend_and_native" if request else "native_registration_only",
        )
        interface_by_native[native["candidate_id"]] = interface_id
        if request_id:
            interface_by_request[request_id] = interface_id

    excluded_static_resource_interface_count = len([
        request_id for request_id in requests if request_id not in interface_by_request
    ])

    for parameter in sorted(parameters, key=lambda item: (str(item.get("owner_ref", "")), str(item.get("name", "")))):
        interface_id = interface_by_request.get(str(parameter.get("owner_ref", "")))
        if not interface_id:
            continue
        parameter_id = _identifier("force-parameter", interface_id, str(parameter.get("parameter_id", "")))
        clues = clues_by_parameter.get(str(parameter.get("parameter_id", "")), [])
        data_type, data_type_basis = _parameter_type(parameter)
        allowed_values = [str(item) for item in parameter.get("selector_values", [])]
        if parameter.get("literal_value") is not None and not allowed_values:
            allowed_values = [str(parameter.get("literal_value"))]
        clue_evidence = [evidence_id for clue in clues for evidence_id in clue.get("evidence_ids", [])]
        evidence_ids = list(parameter.get("evidence_ids", [])) + clue_evidence
        dependencies = []
        for clue in clues:
            attrs = _attributes(clue)
            paths = _json_list(attrs.get("artifact_paths"))
            dependencies.append({
                "kind": "code_reference_assessment",
                "status": attrs.get("assessment_status", "unknown"),
                "label": "{} · {} occurrence(s)".format(
                    attrs.get("assessment_status", "unknown"), attrs.get("occurrence_count", "0")
                ),
                "artifact_paths": paths[:8],
                "additional_artifact_count": max(0, len(paths) - 8),
            })
        constraints = []
        if allowed_values:
            constraints.append({
                "kind": "selector_domain" if parameter.get("selector_values") else "fixed_literal",
                "status": "observed",
                "values": allowed_values,
                "interpretation": "仅表示静态观察到的值域；不等同于后端校验已证明。",
            })
        else:
            constraints.append({
                "kind": "code_validation",
                "status": "not_recovered",
                "values": [],
                "interpretation": "当前证据未恢复整数范围、长度、格式或时间边界。",
            })
        evidence_locations, additional_evidence_count = _bounded_evidence_locations(
            evidence_ids, evidence_by_id
        )
        node = {
            "node_id": parameter_id,
            "node_kind": "parameter",
            "label": str(parameter.get("name", "")),
            "parent_id": interface_id,
            "child_ids": [],
            "expandable": False,
            "status": "observed",
            "details": {
                "parameter_id": parameter.get("parameter_id", ""),
                "namespace": parameter.get("namespace", "unknown"),
                "parameter_role": "operation_selector" if parameter.get("is_operation_selector") else "input",
                "data_type": data_type,
                "data_type_basis": data_type_basis,
                "allowed_values": allowed_values,
                "function_summary": (
                    "选择接口内部操作分支" if parameter.get("is_operation_selector")
                    else "接口输入参数；具体业务语义尚未由确定性证据恢复"
                ),
                "source_construct": parameter.get("source_construct", ""),
                "constraints": constraints,
                "dependencies": dependencies,
                "evidence_locations": evidence_locations,
                "additional_evidence_count": additional_evidence_count,
                "claim_boundary": "类型只由固定字面量或 selector 值域归纳；名称不用于猜测类型。",
            },
        }
        nodes.append(node)
        node_by_id[parameter_id] = node
        node_by_id[interface_id]["child_ids"].append(parameter_id)
        edges.append({
            "edge_id": _identifier("force-edge", interface_id, parameter_id, "accepts"),
            "source_ref": interface_id, "target_ref": parameter_id,
            "edge_kind": "accepts", "label": "接收参数",
        })

    binary_components = [
        item for item in nodes
        if item["node_kind"] == "component" and item["details"]["component_kind"] == "binary"
    ]
    interface_nodes = [item for item in nodes if item["node_kind"] == "interface"]
    parameter_nodes = [item for item in nodes if item["node_kind"] == "parameter"]
    for node in nodes:
        if node["node_kind"] != "parameter":
            node["expandable"] = bool(node["child_ids"])
    return {
        "schema_version": SCHEMA_VERSION,
        "catalog_id": catalog.get("catalog_id", ""),
        "firmware_artifact_sha256": catalog.get("firmware_artifact_sha256", ""),
        "root_node_id": root_id,
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "component_count": len([item for item in nodes if item["node_kind"] == "component"]),
            "binary_component_count": len(binary_components),
            "interface_count": len(interface_nodes),
            "parameter_count": len(parameter_nodes),
            "native_only_interface_count": len([
                item for item in interface_nodes
                if item["details"]["exposure_status"] == "native_registration_only"
            ]),
            "unknown_parameter_type_count": len([
                item for item in parameter_nodes if item["details"]["data_type"] == "unknown"
            ]),
            "excluded_static_resource_interface_count": excluded_static_resource_interface_count,
        },
        "claim_boundary": (
            "该力导图是 Catalog 的确定性界面投影。Native 注册不自动证明完整 URL、"
            "HTTP 方法、运行时可达或漏洞；参数名称不用于猜测数据类型与约束。"
        ),
    }
