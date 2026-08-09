#!/usr/bin/env python3
"""Build the M1 representative communication-architecture corpus report."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from firmatlas.mapping import (
    CorpusEvidenceTier,
    CorpusReportInput,
    CorpusSampleInput,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    FrontendAssetInput,
    InventoryPolicy,
    NativeRouteAnchor,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    build_inventory,
    build_corpus_report,
    correlate_frontend_native,
    discover_arm_pic_callsite_bindings,
    discover_frontend_requests,
    discover_frontend_asset_graph,
    discover_mips_inline_route_bindings,
    discover_mips_handler_value_flows,
    discover_native_hints,
    discover_script_backend,
    discover_web_configuration,
    native_deep_scheduler_analyzer,
    run_obligation_scheduler,
)


AC9_FIRMWARE_SHA256 = "981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296"
AC9_INVENTORY_SHA256 = "a6b3a57b7262de8692ebf9f9fac2aa249bbbdb69272a45c8c0a651089a6ddcf4"
DAP3520_FIRMWARE_SHA256 = "0de4c72f3d7ba1dc6419328be355b51e39d1dae0a8ad14918f0e4eb4699499f9"
X5000R_FIRMWARE_SHA256 = "2acd661c22b0ca4467af24931864946b8b6ded772ec24a8601d30aea2436ade9"
X5000R_ROOT = Path(
    "var/mapping-work/x5000r-v9.1.0u.6118/extractions/firmware.bin.extracted/"
    "1004C/C8343R-6118.bin.extracted/184C70/squashfs-root"
)
DAP3520_ROOT = Path(
    "../iot_seedintelligentanalysis/binwalk_result/类型6/BM-2024-00027/"
    "_DAP-3520_REVA_FIRMWARE_PATCH_1.17.RC047.ZIP.extracted/"
    "_DAP-3520_FW_v117-rc047.bin.extracted/squashfs-root"
)


def _source(path: str, content: bytes) -> SourceArtifactEntry:
    return SourceArtifactEntry(
        canonical_path=path,
        original_path=path,
        kind="file",
        size=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
    )


def _frontend_catalog(label: str, content: bytes, discriminator: str):
    frontend = discover_frontend_requests(_source(label, content), content)
    return assemble_discovery_catalog(DiscoveryCatalogInput(
        firmware_artifact_sha256=hashlib.sha256(
            ("contract:" + discriminator).encode()
        ).hexdigest(),
        source_inventory_sha256=hashlib.sha256(
            ("contract-inventory:" + discriminator).encode()
        ).hexdigest(),
        batches=(DiscoveryProducerBatch.frontend((frontend,), label),),
    ))


def _ac9_catalog(root: Path):
    frontend_path = root / "webroot_ro/js/online_list.js"
    native_path = root / "bin/httpd"
    frontend_content = frontend_path.read_bytes()
    native_content = native_path.read_bytes()
    frontend = discover_frontend_requests(
        _source("webroot_ro/js/online_list.js", frontend_content), frontend_content
    )
    native_source = _source("bin/httpd", native_content)
    native = discover_native_hints(native_source, native_content)
    correlation = correlate_frontend_native((frontend,), (native,))
    native_by_id = {item.hint_id: item for item in native.hints}
    deep = discover_arm_pic_callsite_bindings(
        native_source,
        native_content,
        tuple(
            NativeRouteAnchor(
                association.association_id,
                native_by_id[association.native_hint_id].value,
            )
            for association in correlation.associations
        ),
    )
    scheduler = run_obligation_scheduler(
        correlation.obligations, (native_deep_scheduler_analyzer(deep),)
    )
    return assemble_discovery_catalog(DiscoveryCatalogInput(
        AC9_FIRMWARE_SHA256,
        AC9_INVENTORY_SHA256,
        (
            DiscoveryProducerBatch.frontend(
                (frontend,), "webroot_ro/js/online_list.js"
            ),
            DiscoveryProducerBatch.native((native,), "bin/httpd"),
            DiscoveryProducerBatch.native_deep((deep,), "bin/httpd:callsite"),
        ),
        correlation,
        scheduler,
    ))


def _dap3520_catalog(root: Path):
    inputs = (
        ("etc/templates/httpd/httpd.php", discover_web_configuration),
        ("www/home_sys.php", discover_script_backend),
        ("www/__action.php", discover_script_backend),
    )
    if not all((root / path).exists() for path, _ in inputs):
        return None
    results = []
    for path, producer in inputs:
        content = (root / path).read_bytes()
        results.append((producer, producer(_source(path, content), content)))
    web = tuple(
        result
        for producer, result in results
        if producer is discover_web_configuration
    )
    scripts = tuple(
        result
        for producer, result in results
        if producer is discover_script_backend
    )
    inventory = build_inventory(root, InventoryPolicy())
    return assemble_discovery_catalog(DiscoveryCatalogInput(
        DAP3520_FIRMWARE_SHA256,
        inventory.inventory_sha256,
        (
            DiscoveryProducerBatch.web_configuration(
                web, "etc/templates/httpd/httpd.php"
            ),
            DiscoveryProducerBatch.script_backend(
                scripts, "www/{home_sys.php,__action.php}"
            ),
        ),
        source_inventory_coverage_status=inventory.coverage_status,
    ))


def _x5000r_catalog(root: Path):
    paths = {
        "config": "www/static/js/config.js",
        "frontend": "www/static/js/config_ie.js",
        "wrapper": "www/static/js/topicurl.js",
        "web": "lighttp/lighttpd.conf",
        "native": "www/cgi-bin/cstecgi.cgi",
    }
    if not all((root / path).is_file() for path in paths.values()):
        return None
    frontend_assets = []
    for key in ("config", "frontend", "wrapper"):
        path = paths[key]
        content = (root / path).read_bytes()
        frontend_assets.append(
            FrontendAssetInput(_source(path, content), content)
        )
    frontend_graph = discover_frontend_asset_graph(tuple(frontend_assets))
    native_content = (root / paths["native"]).read_bytes()
    native_source = _source(paths["native"], native_content)
    deep = discover_mips_inline_route_bindings(
        native_source,
        native_content,
        tuple(
            NativeRouteAnchor(
                parameter.request_candidate_id, parameter.literal_value
            )
            for result in frontend_graph.results
            for parameter in result.parameters
            if parameter.is_operation_selector
            and parameter.source_construct == "shared-cgi.topicurl"
        ),
    )
    value_flow = discover_mips_handler_value_flows(
        native_source, native_content, 0x004209B8
    )
    web_content = (root / paths["web"]).read_bytes()
    web = discover_web_configuration(
        _source(paths["web"], web_content), web_content
    )
    native = discover_native_hints(native_source, native_content)
    inventory = build_inventory(root, InventoryPolicy())
    return assemble_discovery_catalog(DiscoveryCatalogInput(
        X5000R_FIRMWARE_SHA256,
        inventory.inventory_sha256,
        (
            DiscoveryProducerBatch.frontend(
                frontend_graph.results,
                "www/static/js/{config,config_ie,topicurl}.js",
            ),
            DiscoveryProducerBatch.web_configuration(
                (web,), paths["web"]
            ),
            DiscoveryProducerBatch.native((native,), paths["native"]),
            DiscoveryProducerBatch.native_deep(
                (deep,), paths["native"] + ":inline-route-tables"
            ),
            DiscoveryProducerBatch.native_value_flow(
                (value_flow,), paths["native"] + ":setLanCfg"
            ),
        ),
        source_inventory_coverage_status=inventory.coverage_status,
    ))


def build_m1_report(
    ac9_root: Path,
    dap3520_root: Path = DAP3520_ROOT,
    x5000r_root: Path = X5000R_ROOT,
):
    """Replay available evidence without promoting fixtures or leads to firmware truth."""

    ac9 = _ac9_catalog(ac9_root)
    hnap = _frontend_catalog(
        "fixtures/hnap.js",
        b'''$.ajax({
          url: "/HNAP1", type: "POST", dataType: "xml",
          headers: {"SOAPAction": "http://purenetworks.com/HNAP1/GetDeviceSettings"}
        });''',
        "hnap-soapaction",
    )
    shared_cgi = _frontend_catalog(
        "fixtures/shared-cgi.js",
        b'''$.ajax({
          url: "/cgi-bin/cstecgi.cgi", type: "POST", contentType: "application/json",
          data: JSON.stringify({topicurl: "setting/setLanCfg", lanIp: value})
        });''',
        "shared-cgi-selector",
    )
    dap3520 = _dap3520_catalog(dap3520_root)
    x5000r = _x5000r_catalog(x5000r_root)
    return build_corpus_report(CorpusReportInput(
        corpus_version="firmatlas.mapping.corpus/m1.2",
        required_categories=(
            "form_handler", "hnap_soap", "cgi_gateway",
            "script_backend", "native_only",
        ),
        samples=(
            CorpusSampleInput(
                "tenda-ac9-goform-dev", "form_handler",
                "goform_camel_registry", "development",
                CorpusEvidenceTier.REAL_FIRMWARE,
                ("constructs_request", "binds_handler"),
                expected_firmware_sha256=AC9_FIRMWARE_SHA256,
                catalog=ac9,
            ),
            CorpusSampleInput(
                "hnap-soapaction-contract", "hnap_soap",
                "hnap_envelope_dispatcher", "contract",
                CorpusEvidenceTier.CONTRACT_FIXTURE,
                ("constructs_request", "selects_operation"), catalog=hnap,
            ),
            CorpusSampleInput(
                "dlink-dap3520-hnap-xgi-validation", "hnap_soap",
                "hybrid_hnap_xgi_dispatcher", "cross-architecture-validation",
                CorpusEvidenceTier.REAL_FIRMWARE,
                (
                    "maps_namespace", "binds_handler", "selects_operation",
                    "reads_configuration", "writes_configuration",
                ),
                expected_firmware_sha256=DAP3520_FIRMWARE_SHA256,
                catalog=dap3520,
            ),
            CorpusSampleInput(
                "shared-cgi-selector-contract", "cgi_gateway",
                "shared_cgi_dispatcher", "contract",
                CorpusEvidenceTier.CONTRACT_FIXTURE,
                ("constructs_request", "selects_operation"), catalog=shared_cgi,
            ),
            CorpusSampleInput(
                "totolink-x5000r-shared-cgi", "cgi_gateway",
                "shared_cgi_dispatcher", "cross-architecture-validation",
                CorpusEvidenceTier.REAL_FIRMWARE,
                (
                    "constructs_request", "selects_operation",
                    "maps_namespace", "binds_handler", "mentions_endpoint",
                ),
                expected_firmware_sha256=X5000R_FIRMWARE_SHA256,
                catalog=x5000r,
            ),
            CorpusSampleInput(
                "dlink-dsl2877-derived", "script_backend",
                "vendor_asp_controller", "cross-architecture-validation",
                CorpusEvidenceTier.DERIVED_FIRMWARE,
                ("reads_parameter", "writes_configuration"),
            ),
            CorpusSampleInput(
                "native-only-acquisition-gap", "native_only",
                "native_route_registry", "acquisition-gap",
                CorpusEvidenceTier.EXTERNAL_LEAD,
                ("mentions_endpoint", "binds_handler"),
            ),
        ),
    ))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ac9-root",
        type=Path,
        default=Path(
            "../iot_seedintelligentanalysis/_tenda_ac9.zip.extracted/squashfs-root"
        ),
    )
    parser.add_argument("--dap3520-root", type=Path, default=DAP3520_ROOT)
    parser.add_argument("--x5000r-root", type=Path, default=X5000R_ROOT)
    args = parser.parse_args()
    print(json.dumps(
        build_m1_report(
            args.ac9_root, args.dap3520_root, args.x5000r_root
        ).to_dict(),
        ensure_ascii=False,
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
