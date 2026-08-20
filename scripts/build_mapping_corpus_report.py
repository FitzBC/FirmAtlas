#!/usr/bin/env python3
"""Build the M1 representative communication-architecture corpus report."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from firmatlas.mapping import (
    ArmPicCallsiteProfile,
    CorpusEvidenceTier,
    CorpusReportInput,
    CorpusSampleInput,
    CoverageStatus,
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    InventoryPolicy,
    MipsNestedDispatchAnchor,
    MipsRequestProtectionAnchor,
    MipsServiceAssemblyAnchor,
    NativeRouteAnchor,
    ServiceAssemblyArtifact,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    build_inventory,
    build_corpus_report,
    correlate_frontend_native,
    discover_arm_pic_callsite_bindings,
    discover_frontend_requests,
    discover_mips_inline_route_bindings,
    discover_mips_handler_value_flows,
    discover_mips_cgi_nested_dispatch,
    discover_mips_request_protection,
    discover_mips_service_assembly,
    discover_native_hints,
    discover_native_ubus_registrations,
    discover_script_backend,
    discover_web_configuration,
    native_deep_scheduler_analyzer,
    run_obligation_scheduler,
)

if __package__:
    from scripts.build_x5000r_expanded_frontend_report import (
        EXPANDED_FRONTEND_PATHS,
        build_analysis as _x5000r_expanded_analysis,
    )
else:
    from build_x5000r_expanded_frontend_report import (
        EXPANDED_FRONTEND_PATHS,
        build_analysis as _x5000r_expanded_analysis,
    )


AC9_FIRMWARE_SHA256 = "981ae43f0114432425f211783a4051a81f861b6f8208a9d80cb1528daf3bf296"
AC9_INVENTORY_SHA256 = "a6b3a57b7262de8692ebf9f9fac2aa249bbbdb69272a45c8c0a651089a6ddcf4"
DAP3520_FIRMWARE_SHA256 = "0de4c72f3d7ba1dc6419328be355b51e39d1dae0a8ad14918f0e4eb4699499f9"
X5000R_FIRMWARE_SHA256 = "2acd661c22b0ca4467af24931864946b8b6ded772ec24a8601d30aea2436ade9"
FRITZ4040_FIRMWARE_SHA256 = "cc34c5449138fd2f247cbd448922df01093b754ed0b9ca02150f302e044c0f00"
DAP2695_FIRMWARE_SHA256 = "11479c2dcce46af141954a067a0c0355d76bd49ed1793894b1d5960ac5300609"
X5000R_ROOT = Path(
    "var/mapping-work/x5000r-v9.1.0u.6118/extractions/firmware.bin.extracted/"
    "1004C/C8343R-6118.bin.extracted/184C70/squashfs-root"
)
DAP3520_ROOT = Path(
    "../iot_seedintelligentanalysis/binwalk_result/类型6/BM-2024-00027/"
    "_DAP-3520_REVA_FIRMWARE_PATCH_1.17.RC047.ZIP.extracted/"
    "_DAP-3520_FW_v117-rc047.bin.extracted/squashfs-root"
)
FRITZ4040_ROOT = Path(
    "var/mapping-work/r2-34-fritz4040/extracted/"
    "_firmware.bin.extracted/squashfs-root"
)
DAP2695_ROOT = Path(
    "var/mapping-work/r2-35-dap2695/extraction-v2/"
    "_firmware.bin.extracted/squashfs-root"
)
FRITZ4040_RPCD_SHA256 = {
    "usr/lib/rpcd/file.so": "91163cbcc4ae596288f29e3b513db2f57989784094c17e9ce126967e030c3379",
    "usr/lib/rpcd/iwinfo.so": "82afa783fc8e2f485742bb52823bea7833618be5f04198bd7f72da50bca91695",
    "usr/lib/rpcd/luci.so": "1fa7d49d50408365cfd175206f811d4ffdf36d6fd6b9d3a5c7834ff45b23fc60",
    "usr/lib/rpcd/rrdns.so": "3d726800cd7f2d0a204101eaac962cbafb05ff6c1a7682d139a758b456575a3b",
}


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
        ArmPicCallsiteProfile.v1(),
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
        "web": "lighttp/lighttpd.conf",
        "native": "www/cgi-bin/cstecgi.cgi",
        "server": "usr/sbin/lighttpd",
        "launcher": "sbin/rc",
    }
    if not all(
        (root / path).is_file()
        for path in (*paths.values(), *EXPANDED_FRONTEND_PATHS)
    ):
        return None
    (
        _frontend_assets,
        frontend_graph,
        native_source,
        table_inventory,
        _artifacts,
        set_difference,
    ) = _x5000r_expanded_analysis(root)
    native_content = (root / paths["native"]).read_bytes()
    candidates = {
        item.candidate_id: item
        for result in frontend_graph.results
        for item in result.candidates
    }
    anchor_pairs = {
        (parameter.request_candidate_id, parameter.literal_value)
        for result in frontend_graph.results
        for parameter in result.parameters
        if parameter.is_operation_selector
        and parameter.literal_value is not None
        and candidates[parameter.request_candidate_id].endpoint
        == "/cgi-bin/cstecgi.cgi"
    }
    deep = discover_mips_inline_route_bindings(
        native_source,
        native_content,
        tuple(
            NativeRouteAnchor(candidate_id, operation)
            for candidate_id, operation in sorted(anchor_pairs)
        ),
    )
    value_flow = discover_mips_handler_value_flows(
        native_source, native_content, 0x004209B8
    )
    upload_operation = next(
        parameter
        for result in frontend_graph.results
        for parameter in result.parameters
        if parameter.is_operation_selector
        and parameter.literal_value == "setUploadSetting"
    )
    upload_transport = next(
        parameter
        for result in frontend_graph.results
        for parameter in result.parameters
        if parameter.is_operation_selector
        and parameter.request_candidate_id == upload_operation.request_candidate_id
        and parameter.literal_value == "upload"
    )
    nested_dispatch = discover_mips_cgi_nested_dispatch(
        native_source,
        native_content,
        (MipsNestedDispatchAnchor(
            upload_operation.request_candidate_id,
            upload_transport.name,
            upload_transport.literal_value,
            upload_operation.name,
            upload_operation.literal_value,
        ),),
    )
    server_content = (root / paths["server"]).read_bytes()
    protection = discover_mips_request_protection(
        _source(paths["server"], server_content),
        server_content,
        (MipsRequestProtectionAnchor(
            nested_dispatch.paths[0].path_id,
            "/cgi-bin/cstecgi.cgi",
        ),),
    )
    assembly_artifacts = []
    for path in (
        paths["launcher"], paths["server"], paths["web"], paths["native"]
    ):
        content = (root / path).read_bytes()
        assembly_artifacts.append(
            ServiceAssemblyArtifact(_source(path, content), content)
        )
    service_assembly = discover_mips_service_assembly(
        tuple(assembly_artifacts),
        (MipsServiceAssemblyAnchor(
            nested_dispatch.paths[0].path_id,
            "/cgi-bin/cstecgi.cgi",
        ),),
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
                "X5000R:expanded-frontend-scope/v1",
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
            DiscoveryProducerBatch.native_nested_dispatch(
                (nested_dispatch,), paths["native"] + ":main:upload"
            ),
            DiscoveryProducerBatch.native_request_protection(
                (protection,), paths["server"] + ":custom-auth"
            ),
            DiscoveryProducerBatch.native_service_assembly(
                (service_assembly,), paths["launcher"] + ":static-init"
            ),
        ),
        set_difference=set_difference,
        source_inventory_coverage_status=inventory.coverage_status,
    ))


def _fritz4040_native_catalog(root: Path):
    if not all((root / path).is_file() for path in FRITZ4040_RPCD_SHA256):
        return None
    registrations = []
    for path, expected_sha256 in FRITZ4040_RPCD_SHA256.items():
        content = (root / path).read_bytes()
        source = _source(path, content)
        if source.content_sha256 != expected_sha256:
            raise ValueError("FRITZ rpcd plugin identity mismatch: {}".format(path))
        result = discover_native_ubus_registrations(source, content)
        if not result.registration_coverage_complete:
            raise ValueError("FRITZ rpcd registration is incomplete: {}".format(path))
        registrations.append(result)
    inventory = build_inventory(root, InventoryPolicy())
    return assemble_discovery_catalog(DiscoveryCatalogInput(
        FRITZ4040_FIRMWARE_SHA256,
        inventory.inventory_sha256,
        (DiscoveryProducerBatch.native_ubus_registration(
            tuple(registrations), "usr/lib/rpcd/{file,iwinfo,luci,rrdns}.so"
        ),),
        source_inventory_coverage_status=inventory.coverage_status,
    ))


def _selected_source_inventory_sha256(sources) -> str:
    """Identify an explicit, fully-read producer source scope."""

    payload = {
        "schema_version": "firmatlas.mapping.selected-source-inventory/v1",
        "sources": [
            {
                "canonical_path": item.canonical_path,
                "content_sha256": item.content_sha256,
                "size": item.size,
            }
            for item in sorted(sources, key=lambda value: value.canonical_path)
        ],
    }
    return hashlib.sha256(json.dumps(
        payload, separators=(",", ":"), sort_keys=True,
    ).encode()).hexdigest()


def _dap2695_script_catalog(root: Path):
    if not root.is_dir():
        return None
    sources = []
    results = []
    for path in sorted(root.rglob("*.php")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        content = path.read_bytes()
        source = _source(relative, content)
        result = discover_script_backend(source, content)
        if result.coverage_status is not CoverageStatus.COMPLETED:
            raise ValueError(
                "DAP-2695 script analysis is incomplete: {}".format(relative)
            )
        sources.append(source)
        results.append(result)
    if not results:
        return None
    return assemble_discovery_catalog(DiscoveryCatalogInput(
        DAP2695_FIRMWARE_SHA256,
        _selected_source_inventory_sha256(tuple(sources)),
        (DiscoveryProducerBatch.script_backend(
            tuple(results), "selected-source-inventory:**/*.php"
        ),),
    ))


def build_m1_report(
    ac9_root: Path,
    dap3520_root: Path = DAP3520_ROOT,
    x5000r_root: Path = X5000R_ROOT,
    fritz4040_root: Path = FRITZ4040_ROOT,
    dap2695_root: Path = DAP2695_ROOT,
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
    fritz4040 = _fritz4040_native_catalog(fritz4040_root)
    dap2695 = _dap2695_script_catalog(dap2695_root)
    dap3520_script_scope = tuple(
        item.candidate_id for item in dap3520.candidates
        if item.source_path in {"www/home_sys.php", "www/__action.php"}
    ) if dap3520 is not None else ()
    x5000r_native_only_scope = tuple(
        item.candidate_id for item in x5000r.candidates
        if dict(item.attributes).get("difference_side") == "native_only"
        and dict(item.attributes).get("attribution_kind")
        == "native_registration_no_frontend_reference"
    ) if x5000r is not None else ()
    fritz4040_native_scope = tuple(
        item.candidate_id for item in fritz4040.candidates
        if item.candidate_kind.value == "request_interface"
        and dict(item.attributes).get("request_role") == "native_registration"
    ) if fritz4040 is not None else ()
    return build_corpus_report(CorpusReportInput(
        corpus_version="firmatlas.mapping.corpus/m1.5",
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
                "dlink-dap3520-script-backend", "script_backend",
                "php_xgi_controller", "cross-architecture-validation",
                CorpusEvidenceTier.REAL_FIRMWARE,
                ("reads_parameter", "writes_configuration"),
                ("constructs_request",),
                expected_firmware_sha256=DAP3520_FIRMWARE_SHA256,
                catalog=dap3520,
                scope_candidate_ids=dap3520_script_scope,
            ),
            CorpusSampleInput(
                "dlink-dap2695-script-backend-holdout", "script_backend",
                "php_xgi_controller", "independent-holdout",
                CorpusEvidenceTier.REAL_FIRMWARE,
                ("reads_parameter", "writes_configuration"),
                ("constructs_request",),
                expected_firmware_sha256=DAP2695_FIRMWARE_SHA256,
                catalog=dap2695,
            ),
            CorpusSampleInput(
                "dlink-dsl2877-derived", "script_backend",
                "vendor_asp_controller", "cross-architecture-validation",
                CorpusEvidenceTier.DERIVED_FIRMWARE,
                ("reads_parameter", "writes_configuration"),
            ),
            CorpusSampleInput(
                "totolink-x5000r-native-only", "native_only",
                "native_route_registry_without_frontend_reference",
                "cross-architecture-validation",
                CorpusEvidenceTier.REAL_FIRMWARE,
                ("mentions_endpoint", "binds_handler"),
                ("constructs_request",),
                expected_firmware_sha256=X5000R_FIRMWARE_SHA256,
                catalog=x5000r,
                scope_candidate_ids=x5000r_native_only_scope,
            ),
            CorpusSampleInput(
                "openwrt-fritz4040-native-only-holdout", "native_only",
                "arm_rpcd_native_registration", "independent-holdout",
                CorpusEvidenceTier.REAL_FIRMWARE,
                ("mentions_endpoint", "binds_handler"),
                ("constructs_request",),
                expected_firmware_sha256=FRITZ4040_FIRMWARE_SHA256,
                catalog=fritz4040,
                scope_candidate_ids=fritz4040_native_scope,
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
    parser.add_argument("--fritz4040-root", type=Path, default=FRITZ4040_ROOT)
    parser.add_argument("--dap2695-root", type=Path, default=DAP2695_ROOT)
    args = parser.parse_args()
    print(json.dumps(
        build_m1_report(
            args.ac9_root, args.dap3520_root, args.x5000r_root,
            args.fritz4040_root,
            args.dap2695_root,
        ).to_dict(),
        ensure_ascii=False,
        indent=2,
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
