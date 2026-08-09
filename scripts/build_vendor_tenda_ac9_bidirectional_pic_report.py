#!/usr/bin/env python3
"""Build the AC9 auto-v3 bidirectional ARM literal-pool report."""

from __future__ import annotations

import json

from firmatlas.mapping import BUILTIN_ANALYZER_REGISTRY, MappingAnalysisProfile
from build_vendor_tenda_ac9_framework_history_report import build_report


def build_bidirectional_report() -> dict:
    report = build_report(
        profile=MappingAnalysisProfile.auto(),
        registry=BUILTIN_ANALYZER_REGISTRY,
    )
    report["schema_version"] = "firmatlas.mapping.vendor-tenda-ac9-r2-05/v1alpha1"
    report["sample_role"] = "primary-vendor-tenda-ac9-bidirectional-pic-iteration"
    report["interpretation"] = {
        "supported": (
            "ARM32 PIC callsite analysis validates both positive and negative PC-relative "
            "literal pools; SetSambaCfg is bound to formSetSambaConf with instruction, "
            "relocation, symbol, and shared-registrar evidence"
        ),
        "remaining_binding_gap": (
            "historical route expectations without a current exact route identity or "
            "current-version applicability remain unbound"
        ),
        "denominator_guard": report["interpretation"]["denominator_guard"],
        "not_claimed": report["interpretation"]["not_claimed"],
    }
    return report


if __name__ == "__main__":
    print(json.dumps(
        build_bidirectional_report(), ensure_ascii=False, indent=2, sort_keys=True
    ))
