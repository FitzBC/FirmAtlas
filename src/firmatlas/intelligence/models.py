"""Domain models for normalized vulnerability intelligence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Tuple


class RelevanceLevel(str, Enum):
    STRONG = "strong"
    LIKELY = "likely"
    REVIEW = "review"
    UNRELATED = "unrelated"


@dataclass(frozen=True)
class RelevanceSignal:
    code: str
    label: str
    weight: int
    evidence: str


@dataclass(frozen=True)
class RelevanceDecision:
    score: int
    level: RelevanceLevel
    signals: Tuple[RelevanceSignal, ...]
    policy_version: str

    @property
    def is_firmware_related(self) -> bool:
        return self.level in (RelevanceLevel.STRONG, RelevanceLevel.LIKELY)

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["level"] = self.level.value
        result["is_firmware_related"] = self.is_firmware_related
        return result


@dataclass(frozen=True)
class RelevancePolicy:
    version: str = "2026.08.2"
    firmware_keywords: Tuple[str, ...] = (
        "firmware",
        "embedded firmware",
        "firmware update",
        "bootloader",
        "u-boot",
        "uefi",
        "bios",
        "baseboard management controller",
        "bmc firmware",
        "flash memory",
        "system image",
        "device software",
        "embedded software",
        "secure boot",
        "trusted execution environment",
    )
    device_keywords: Tuple[str, ...] = (
        "router",
        "gateway",
        "network camera",
        "ip camera",
        "nas device",
        "network attached storage",
        "access point",
        "modem",
        "network switch",
        "printer",
        "iot device",
        "embedded device",
        "industrial control system",
        "programmable logic controller",
        "smart device",
        "firewall",
        "vpn appliance",
        "dvr",
        "nvr",
        "video recorder",
        "ip phone",
        "voip phone",
        "cable modem",
        "ont",
        "optical network terminal",
        "wireless controller",
        "storage appliance",
        "management controller",
        "medical device",
        "vehicle ecu",
        "smart tv",
        "set-top box",
    )
    vendor_keywords: Tuple[str, ...] = (
        "cisco",
        "huawei",
        "siemens",
        "schneider electric",
        "rockwell automation",
        "abb",
        "honeywell",
        "dell",
        "hewlett packard enterprise",
        "lenovo",
        "supermicro",
        "canon",
        "brother",
        "xerox",
    )
    firmware_only_vendors: Tuple[str, ...] = (
        "tp-link",
        "d-link",
        "netgear",
        "hikvision",
        "dahua",
        "ubiquiti",
        "openwrt",
        "qnap",
        "synology",
        "tenda",
        "mikrotik",
        "zyxel",
        "draytek",
        "ruijie",
        "mercusys",
        "totolink",
        "linksys",
        "belkin",
        "buffalo",
        "asus",
        "foscam",
        "reolink",
        "uniview",
        "axis communications",
        "hanwha",
        "asustor",
        "western digital",
        "moxa",
        "advantech",
        "phoenix contact",
        "omron",
        "mitsubishi electric",
        "american megatrends",
        "insyde",
        "openwrt",
    )
    strong_threshold: int = 70
    likely_threshold: int = 50
    review_threshold: int = 35

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: Dict[str, Any]) -> "RelevancePolicy":
        allowed = {
            "version",
            "firmware_keywords",
            "device_keywords",
            "vendor_keywords",
            "firmware_only_vendors",
            "strong_threshold",
            "likely_threshold",
            "review_threshold",
        }
        data = {key: item for key, item in value.items() if key in allowed}
        for key in (
            "firmware_keywords",
            "device_keywords",
            "vendor_keywords",
            "firmware_only_vendors",
        ):
            if key in data:
                data[key] = tuple(
                    str(item).strip() for item in data[key] if str(item).strip()
                )
        return cls(**data)


@dataclass(frozen=True)
class VulnerabilityRecord:
    identifier: str
    source: str
    source_identifier: str
    title: str
    summary: str
    published_at: Optional[str]
    modified_at: Optional[str]
    vendor: Optional[str] = None
    product: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_version: Optional[str] = None
    impact_score: Optional[float] = None
    exploitability_score: Optional[float] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    cvss_metrics: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
    aliases: Tuple[str, ...] = field(default_factory=tuple)
    cwes: Tuple[str, ...] = field(default_factory=tuple)
    cpes: Tuple[str, ...] = field(default_factory=tuple)
    references: Tuple[str, ...] = field(default_factory=tuple)
    reference_details: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
    exploit_references: Tuple[str, ...] = field(default_factory=tuple)
    cwe_details: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
    affected_products: Tuple[Dict[str, Any], ...] = field(default_factory=tuple)
    kev: bool = False
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None
    ransomware_use: Optional[str] = None
    required_action: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result["has_exploit"] = bool(self.exploit_references)
        return result
