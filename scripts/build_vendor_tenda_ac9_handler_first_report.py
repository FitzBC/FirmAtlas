#!/usr/bin/env python3
"""Build AC9 auto-v5 handler-first registrar recovery report."""

from __future__ import annotations

import json

from firmatlas.mapping import BUILTIN_ANALYZER_REGISTRY_V5, MappingAnalysisProfile
from build_vendor_tenda_ac9_registrar_inventory_report import build_report


def build_handler_first_report() -> dict:
    report = build_report(
        profile=MappingAnalysisProfile.auto_v5(),
        registry=BUILTIN_ANALYZER_REGISTRY_V5,
        selected_routes=("GetUpnpCfg", "GetSySLogCfg"),
    )
    report["schema_version"] = "firmatlas.mapping.vendor-tenda-ac9-r2-07/v1alpha1"
    report["sample_role"] = "primary-vendor-tenda-ac9-handler-first-iteration"
    report["interpretation"] = {
        "supported": (
            "handler-first ARM registrar layout recovers GetUpnpCfg and GetSySLogCfg; "
            "both now have relocation, symbol, callsite, and shared-registrar proof"
        ),
        "remaining_frontend_gap": (
            "GetDlnaCfg, SetDlnaCfg, and refreshDLNA occur only in frontend sources "
            "after completed comparison against 287 native auxiliary artifacts"
        ),
        "not_claimed": (
            "DLNA removal, runtime reachability, firmware defect, vulnerability presence, "
            "or exploitability"
        ),
    }
    return report


if __name__ == "__main__":
    print(json.dumps(
        build_handler_first_report(), ensure_ascii=False, indent=2, sort_keys=True
    ))
