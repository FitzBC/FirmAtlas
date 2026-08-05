"""Explainable firmware-relevance classification."""

from __future__ import annotations

import re
from typing import Iterable, List, Optional, Sequence
from urllib.parse import unquote

from .models import (
    RelevanceDecision,
    RelevanceLevel,
    RelevancePolicy,
    RelevanceSignal,
    VulnerabilityRecord,
)


_NEGATIVE_CONTEXT = (
    "cloud service",
    "software as a service",
    "saas platform",
    "desktop application",
    "mobile application",
)


def _normalized(value: Optional[str]) -> str:
    return re.sub(
        r"\s+", " ", unquote(value or "").replace("_", " ").lower()
    ).strip()


def _first_match(haystack: str, needles: Iterable[str]) -> Optional[str]:
    for needle in needles:
        normalized = _normalized(needle)
        if normalized and re.search(
            r"(?<![\w]){}(?![\w])".format(re.escape(normalized)), haystack
        ):
            return needle
    return None


class FirmwareRelevanceClassifier:
    """Classify records with additive, bounded, human-readable evidence."""

    def classify(
        self, record: VulnerabilityRecord, policy: RelevancePolicy
    ) -> RelevanceDecision:
        text = _normalized(
            " ".join(
                filter(
                    None,
                    (record.title, record.summary, record.vendor, record.product),
                )
            )
        )
        signals: List[RelevanceSignal] = []

        firmware_term = _first_match(text, policy.firmware_keywords)
        if firmware_term:
            signals.append(
                RelevanceSignal(
                    "firmware-term",
                    "固件术语",
                    55,
                    '正文或标题包含“{}”'.format(firmware_term),
                )
            )

        device_term = _first_match(text, policy.device_keywords)
        if device_term:
            signals.append(
                RelevanceSignal(
                    "device-term",
                    "设备类型",
                    25,
                    '描述指向“{}”设备'.format(device_term),
                )
            )

        firmware_vendor = self._match_vendor(record, policy.firmware_only_vendors)
        if firmware_vendor:
            signals.append(
                RelevanceSignal(
                    "firmware-vendor",
                    "固件专属厂商",
                    55,
                    '厂商匹配“{}”'.format(firmware_vendor),
                )
            )
        else:
            vendor = self._match_vendor(record, policy.vendor_keywords)
            if vendor:
                signals.append(
                    RelevanceSignal(
                        "watched-vendor",
                        "关注厂商",
                        25,
                        '厂商匹配“{}”，需要设备或固件证据共同确认'.format(vendor),
                    )
                )

        signals.extend(self._cpe_signals(record.cpes))

        firmware_ref = _first_match(
            " ".join(record.references).lower(), ("firmware", "download")
        )
        if firmware_ref:
            signals.append(
                RelevanceSignal(
                    "firmware-reference",
                    "固件引用",
                    10,
                    "参考链接包含固件或下载路径",
                )
            )

        negative = _first_match(text, _NEGATIVE_CONTEXT)
        if negative and not any(signal.weight >= 55 for signal in signals):
            signals.append(
                RelevanceSignal(
                    "non-firmware-context",
                    "非固件语境",
                    -25,
                    '描述主要指向“{}”'.format(negative),
                )
            )

        score = max(0, min(100, sum(signal.weight for signal in signals)))
        if score >= policy.strong_threshold:
            level = RelevanceLevel.STRONG
        elif score >= policy.likely_threshold:
            level = RelevanceLevel.LIKELY
        elif score >= policy.review_threshold:
            level = RelevanceLevel.REVIEW
        else:
            level = RelevanceLevel.UNRELATED
        return RelevanceDecision(score, level, tuple(signals), policy.version)

    @staticmethod
    def _match_vendor(
        record: VulnerabilityRecord, configured_vendors: Sequence[str]
    ) -> Optional[str]:
        vendor_text = _normalized(
            " ".join(filter(None, (record.vendor, record.product, record.title)))
        )
        return _first_match(vendor_text, configured_vendors)

    @staticmethod
    def _cpe_signals(cpes: Sequence[str]) -> List[RelevanceSignal]:
        found_hardware = False
        found_firmware_target = False
        for cpe in cpes:
            parts = cpe.lower().split(":")
            is_hardware = (len(parts) >= 4 and parts[2] == "h") or (
                len(parts) >= 2 and parts[1].lstrip("/") == "h"
            )
            if is_hardware:
                found_hardware = True
            if len(parts) >= 11 and parts[10] in ("firmware", "embedded"):
                found_firmware_target = True

        signals: List[RelevanceSignal] = []
        if found_hardware:
            signals.append(
                RelevanceSignal(
                    "hardware-cpe",
                    "硬件 CPE",
                    30,
                    "受影响配置包含 CPE 硬件类型",
                )
            )
        if found_firmware_target:
            signals.append(
                RelevanceSignal(
                    "firmware-target-cpe",
                    "固件目标 CPE",
                    65,
                    "CPE target_sw 指向 firmware/embedded",
                )
            )
        return signals
