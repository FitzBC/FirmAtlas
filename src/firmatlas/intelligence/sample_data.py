"""Deterministic demo records for local UI development."""

from __future__ import annotations

from typing import Tuple

from .models import VulnerabilityRecord


def demo_records() -> Tuple[VulnerabilityRecord, ...]:
    return (
        _record(
            "CVE-2026-31840",
            "TP-Link Archer Firmware Command Injection",
            "A command injection issue in TP-Link Archer router firmware allows an unauthenticated network attacker to execute commands through the management interface.",
            "TP-Link",
            "Archer AX55",
            "CRITICAL",
            9.8,
            True,
            "2026-08-04T08:20:00Z",
            "CWE-78",
        ),
        _record(
            "CVE-2026-29417",
            "Hikvision Camera Firmware Authentication Bypass",
            "Selected Hikvision network camera firmware contains an authentication bypass in its web management endpoint.",
            "Hikvision",
            "DS-2CD Series",
            "CRITICAL",
            9.1,
            False,
            "2026-08-03T12:05:00Z",
            "CWE-288",
        ),
        _record(
            "CVE-2026-28102",
            "NETGEAR Nighthawk Buffer Overflow",
            "NETGEAR Nighthawk router firmware processes a crafted configuration value with insufficient bounds checking.",
            "NETGEAR",
            "Nighthawk RAX50",
            "HIGH",
            8.6,
            False,
            "2026-08-02T17:40:00Z",
            "CWE-120",
        ),
        _record(
            "CVE-2026-26091",
            "QNAP QTS Improper Authorization",
            "QNAP NAS device firmware permits a low-privileged user to access an administrative RPC method.",
            "QNAP",
            "QTS",
            "HIGH",
            8.1,
            True,
            "2026-07-31T09:18:00Z",
            "CWE-285",
        ),
        _record(
            "CVE-2026-23988",
            "Siemens Industrial Gateway Path Traversal",
            "A Siemens industrial gateway exposes a path traversal flaw in the embedded device update service.",
            "Siemens",
            "SCALANCE M-800",
            "HIGH",
            7.5,
            False,
            "2026-07-29T05:15:00Z",
            "CWE-22",
        ),
        _record(
            "CVE-2026-22063",
            "UEFI Secure Boot Verification Weakness",
            "UEFI firmware on affected embedded devices accepts an incorrectly signed update under a specific recovery path.",
            "Multiple Vendors",
            "UEFI Firmware",
            "MEDIUM",
            6.7,
            False,
            "2026-07-27T21:00:00Z",
            "CWE-347",
        ),
    )


def _record(
    identifier: str,
    title: str,
    summary: str,
    vendor: str,
    product: str,
    severity: str,
    score: float,
    kev: bool,
    modified: str,
    cwe: str,
) -> VulnerabilityRecord:
    vendor_cpe = vendor.lower().replace(" ", "_").replace("-", "_")
    product_cpe = product.lower().replace(" ", "_").replace("-", "_")
    return VulnerabilityRecord(
        identifier=identifier,
        source="demo",
        source_identifier=identifier,
        title=title,
        summary=summary,
        published_at=modified,
        modified_at=modified,
        vendor=vendor,
        product=product,
        severity=severity,
        cvss_score=score,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cwes=(cwe,),
        cpes=(
            "cpe:2.3:h:{}:{}:*:*:*:*:*:*:*:*".format(vendor_cpe, product_cpe),
        ),
        references=("https://example.invalid/advisories/{}".format(identifier),),
        kev=kev,
        kev_date_added=modified[:10] if kev else None,
        raw={"demo": True},
    )
