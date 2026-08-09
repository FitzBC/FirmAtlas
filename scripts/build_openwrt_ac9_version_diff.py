#!/usr/bin/env python3
"""Build the real OpenWrt/Tenda AC9 18.06.7 → 19.07.8 mapping diff."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Optional

from firmatlas.mapping import (
    DiscoveryCatalogInput,
    DiscoveryProducerBatch,
    InventoryPolicy,
    MappingReleaseContext,
    DiscoveryCatalogRepository,
    SourceArtifactEntry,
    assemble_discovery_catalog,
    build_inventory,
    compare_mapping_catalog_documents,
    correlate_frontend_native,
    discover_frontend_requests,
    discover_native_hints,
    discover_script_backend,
    discover_web_configuration,
)


WORK_ROOT = Path("var/mapping-work/ac9-version-diff")
VERSIONS = {
    "18.06.7": {
        "artifact": WORK_ROOT / "downloads/openwrt-18.06.7-bcm53xx-tenda-ac9-squashfs.trx",
        "root": WORK_ROOT / (
            "extractions/openwrt-18.06.7/extractions/firmware.bin.extracted/0/"
            "partition_1.bin.extracted/0/squashfs-root"
        ),
        "source_ref": "openwrt-downloads:18.06.7:bcm53xx:tenda-ac9",
        "source_url": (
            "https://downloads.openwrt.org/releases/18.06.7/targets/bcm53xx/"
            "generic/openwrt-18.06.7-bcm53xx-tenda-ac9-squashfs.trx"
        ),
        "execution_fingerprint": (
            "8fc6bbf0f2a350297f8fea13a84bb5c0442da4a32daf1c21924cbb4d7998bb74"
        ),
    },
    "19.07.8": {
        "artifact": WORK_ROOT / "downloads/openwrt-19.07.8-bcm53xx-tenda-ac9-squashfs.trx",
        "root": WORK_ROOT / (
            "extractions/openwrt-19.07.8/extractions/firmware.bin.extracted/0/"
            "partition_1.bin.extracted/0/squashfs-root"
        ),
        "source_ref": "openwrt-downloads:19.07.8:bcm53xx:tenda-ac9",
        "source_url": (
            "https://downloads.openwrt.org/releases/19.07.8/targets/bcm53xx/"
            "generic/openwrt-19.07.8-bcm53xx-tenda-ac9-squashfs.trx"
        ),
        "execution_fingerprint": (
            "44467c7444e6f3428b47a251fb94694a72f54399b2624081526f39290260bf7a"
        ),
    },
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source(root: Path, path: Path) -> tuple[SourceArtifactEntry, bytes]:
    content = path.read_bytes()
    relative = path.relative_to(root).as_posix()
    return SourceArtifactEntry(
        canonical_path=relative,
        original_path=relative,
        kind="file",
        size=len(content),
        content_sha256=hashlib.sha256(content).hexdigest(),
    ), content


def _release_context(version: str) -> MappingReleaseContext:
    metadata = VERSIONS[version]
    return MappingReleaseContext(
        vendor="OpenWrt",
        product="OpenWrt",
        device_model="Tenda AC9",
        firmware_version=version,
        source_ref=metadata["source_ref"],
        evidence=(
            "official OpenWrt release target path and filename identify "
            "bcm53xx/generic/tenda-ac9"
        ),
    )


def build_catalog(version: str):
    metadata = VERSIONS[version]
    artifact, root = metadata["artifact"], metadata["root"]
    if not artifact.is_file() or not root.is_dir():
        raise ValueError("download and extract both OpenWrt AC9 artifacts first")
    inventory = build_inventory(root, InventoryPolicy())
    frontend_paths = sorted(
        path for path in (root / "www").rglob("*")
        if path.is_file() and path.suffix.lower() in {".js", ".html"}
    )
    script_paths = sorted(
        path for path in (root / "usr/lib/lua/luci/controller").rglob("*.lua")
        if path.is_file()
    )
    web_paths = tuple(
        root / relative for relative in ("etc/config/uhttpd", "etc/init.d/uhttpd")
    )
    native_paths = tuple(
        root / relative for relative in ("usr/sbin/uhttpd", "sbin/rpcd")
    )
    frontends = tuple(
        discover_frontend_requests(*_source(root, path))
        for path in frontend_paths
    )
    scripts = tuple(
        discover_script_backend(*_source(root, path))
        for path in script_paths
    )
    web = tuple(
        discover_web_configuration(*_source(root, path))
        for path in web_paths
    )
    native = tuple(
        discover_native_hints(*_source(root, path))
        for path in native_paths
    )
    correlation = correlate_frontend_native(frontends, native)
    catalog = assemble_discovery_catalog(DiscoveryCatalogInput(
        firmware_artifact_sha256=_sha256(artifact),
        source_inventory_sha256=inventory.inventory_sha256,
        batches=(
            DiscoveryProducerBatch.frontend(
                frontends, "www/**/*.{js,html}"
            ),
            DiscoveryProducerBatch.script_backend(
                scripts, "usr/lib/lua/luci/controller/**/*.lua"
            ),
            DiscoveryProducerBatch.web_configuration(
                web, "etc/{config,init.d}/uhttpd"
            ),
            DiscoveryProducerBatch.native(
                native, "{usr/sbin/uhttpd,sbin/rpcd}"
            ),
        ),
        correlation=correlation,
        source_inventory_coverage_status=inventory.coverage_status,
    ))
    return catalog, {
        "version": version,
        "source_url": metadata["source_url"],
        "artifact_sha256": _sha256(artifact),
        "extraction_execution_fingerprint": metadata["execution_fingerprint"],
        "inventory_sha256": inventory.inventory_sha256,
        "inventory_coverage_status": inventory.coverage_status.value,
        "inventory_entry_count": len(inventory.entries),
        "frontend_asset_count": len(frontend_paths),
        "lua_controller_count": len(script_paths),
        "candidate_count": len(catalog.candidates),
        "parameter_count": len(catalog.parameters),
        "association_count": len(catalog.associations),
        "open_obligation_count": len(catalog.open_obligations),
        "catalog_coverage_status": catalog.coverage_status.value,
        "candidate_kind_distribution": {
            kind: sum(
                item.candidate_kind.value == kind for item in catalog.candidates
            )
            for kind in sorted({item.candidate_kind.value for item in catalog.candidates})
        },
    }


def build_report(database: Optional[str] = None) -> dict:
    base, base_summary = build_catalog("18.06.7")
    target, target_summary = build_catalog("19.07.8")
    if database:
        repository = DiscoveryCatalogRepository(database)
        try:
            for version, catalog in (("18.06.7", base), ("19.07.8", target)):
                repository.publish(catalog)
                repository.register_release_context(
                    catalog.catalog_id, _release_context(version)
                )
        finally:
            repository.close()
    difference = compare_mapping_catalog_documents(
        base.to_dict(), target.to_dict(),
        _release_context("18.06.7"), _release_context("19.07.8"),
    ).to_dict()
    return {
        "schema_version": "firmatlas.mapping.openwrt-ac9-version-diff/v1alpha1",
        "sample_role": "same-device-family-real-version-comparison",
        "device_family": {
            "vendor": "OpenWrt", "product": "OpenWrt", "device_model": "Tenda AC9"
        },
        "extraction_tool": {
            "name": "binwalk", "version": "3.1.0",
            "image_digest": (
                "sha256:a22e83ed3465eea9a009a33b01a68233253dc420bcad2b791a48c80444f0880a"
            ),
            "network": "none",
        },
        "snapshots": [base_summary, target_summary],
        "comparison": difference,
        "interpretation_boundary": {
            "supported": (
                "two official OpenWrt builds for the same Tenda AC9 target were "
                "compared under equal declared producer scopes"
            ),
            "not_claimed": (
                "vendor Tenda firmware lineage, runtime reachability, patch causality, "
                "vulnerability remediation, or complete LuCI/RPC semantics"
            ),
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--database",
        help="optionally publish both immutable catalogs and release contexts",
    )
    args = parser.parse_args()
    print(json.dumps(build_report(args.database), ensure_ascii=False, indent=2))
