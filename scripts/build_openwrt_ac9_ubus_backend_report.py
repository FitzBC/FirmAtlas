#!/usr/bin/env python3
"""Build the real OpenWrt 19.07.8 AC9 LuCI/ubus execution graph report."""

from __future__ import annotations

import argparse
import json
from typing import Optional

from firmatlas.mapping import DiscoveryCatalogRepository
from build_openwrt_ac9_version_diff import build_catalog, _release_context


def _attributes(candidate) -> dict:
    return dict(candidate.attributes)


def build_report(database: Optional[str] = None) -> dict:
    catalog, snapshot = build_catalog("19.07.8", include_ubus_backend=True)
    if database:
        repository = DiscoveryCatalogRepository(database)
        try:
            repository.publish(catalog)
            repository.register_release_context(
                catalog.catalog_id, _release_context("19.07.8")
            )
        finally:
            repository.close()

    candidates = catalog.candidates
    operation_by_id = {
        item.candidate_id: item
        for item in candidates
        if item.candidate_kind.value == "request_interface"
        and item.canonical_identity.startswith("ubus://")
    }
    principals = {
        item.candidate_id: item
        for item in candidates if item.candidate_kind.value == "runtime_principal"
    }
    bindings = [
        item for item in candidates
        if item.candidate_kind.value == "ubus_backend_binding"
    ]
    grants = [
        item for item in candidates
        if item.candidate_kind.value == "ubus_access_grant"
    ]
    chains = []
    representative = (
        "ubus://luci/getFeatures",
        "ubus://luci-rpc/getBoardJSON",
        "ubus://file/read",
        "ubus://hostapd.{dynamic}/del_client",
    )
    for identity in representative:
        operations = [
            item for item in operation_by_id.values()
            if item.canonical_identity == identity
        ]
        if not operations:
            continue
        operation = operations[0]
        related_bindings = [
            item for item in bindings
            if _attributes(item).get("target_ref") == operation.candidate_id
        ]
        related_grants = [
            item for item in grants
            if _attributes(item).get("target_ref") == operation.candidate_id
        ]
        chains.append({
            "logical_operation": identity,
            "frontend_source": operation.source_path,
            "endpoint_shape": _attributes(operation).get("endpoint_shape"),
            "backend_bindings": [{
                "status": _attributes(item).get("binding_status"),
                "principal_kind": _attributes(
                    principals[_attributes(item)["principal_id"]]
                ).get("principal_kind"),
                "artifact_path": principals[
                    _attributes(item)["principal_id"]
                ].source_path,
                "handler_identity": _attributes(item).get("handler_identity") or None,
            } for item in related_bindings],
            "access_grants": [{
                "policy_group": _attributes(item).get("policy_group"),
                "access_mode": _attributes(item).get("access_mode"),
                "object_pattern": _attributes(item).get("object_pattern"),
                "source_path": item.source_path,
            } for item in related_grants],
            "open_obligations": [
                item.required_capability for item in catalog.open_obligations
                if item.target_ref == operation.candidate_id
            ],
        })

    unique_operations = {
        item.canonical_identity for item in operation_by_id.values()
    }
    return {
        "schema_version": "firmatlas.mapping.openwrt-ac9-ubus-backend/v1alpha1",
        "sample_role": "real-luci-ubus-execution-and-access-graph",
        "catalog_id": catalog.catalog_id,
        "firmware_artifact_sha256": catalog.firmware_artifact_sha256,
        "release_context": _release_context("19.07.8").to_dict(),
        "source_snapshot": snapshot,
        "summary": {
            "frontend_ubus_candidate_count": len(operation_by_id),
            "unique_logical_operation_count": len(unique_operations),
            "dynamic_operation_template_count": sum(
                "{dynamic}" in identity for identity in unique_operations
            ),
            "runtime_principal_count": len(principals),
            "static_plugin_binding_count": sum(
                _attributes(item).get("binding_status") == "static_plugin_dispatch"
                for item in bindings
            ),
            "native_plugin_candidate_count": sum(
                _attributes(item).get("binding_status") == "native_plugin_candidate"
                for item in bindings
            ),
            "verified_native_binding_count": sum(
                _attributes(item).get("binding_status")
                == "verified_native_registration"
                for item in bindings
            ),
            "access_grant_count": len(grants),
            "runtime_owner_obligation_count": sum(
                item.required_capability == "resolve_ubus_runtime_owner"
                for item in catalog.open_obligations
            ),
            "native_registration_obligation_count": sum(
                item.required_capability == "resolve_ubus_registration_table"
                for item in catalog.open_obligations
            ),
        },
        "representative_chains": chains,
        "interpretation_boundary": {
            "supported": (
                "frontend LuCI declarations, statically enumerable rpcd exec-plugin "
                "dispatch, replayable native registration-table handler bindings, "
                "and rpcd ACL grants"
            ),
            "not_claimed": (
                "runtime reachability, authentication outcome, vulnerability, or a "
                "runtime owner for operations without registration-table evidence"
            ),
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database")
    arguments = parser.parse_args()
    print(json.dumps(build_report(arguments.database), ensure_ascii=False, indent=2))
