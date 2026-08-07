"""Metadata-only firmware sample discovery from evidence-backed public sources."""

from __future__ import annotations

import csv
import hashlib
from io import TextIOWrapper
import re
from typing import Any, Callable, Dict, Iterable, Iterator, List, TextIO, Tuple
from urllib.parse import quote, unquote, urlsplit
from urllib.request import Request, urlopen


FIRMEMUHUB_DEVICES_URL = (
    "https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/main/DEVICES.md"
)
IOTVULBENCH_LIST_URL = (
    "https://raw.githubusercontent.com/a101e-lab/IoTVulBench/main/"
    "vulnerabilities_list.md"
)
IOTVULBENCH_DETAIL_URL = (
    "https://raw.githubusercontent.com/a101e-lab/IoTVulBench/main/"
    "Vulnerabilities/{identifier}/detail.yml"
)
WUSTL_FIRMWARE_LIST_URL = (
    "https://raw.githubusercontent.com/WUSTL-CSPL/Firmware-Dataset/main/"
    "dat/firmware_download_list.csv"
)
WUSTL_FIRMWARE_LIST_PAGE = (
    "https://github.com/WUSTL-CSPL/Firmware-Dataset/blob/main/"
    "dat/firmware_download_list.csv"
)


DEFAULT_FIRMWARE_SOURCES: Tuple[Dict[str, Any], ...] = (
    {
        "source_id": "firmemuhub",
        "name": "FirmEmuHub",
        "source_type": "benchmark",
        "base_url": "https://github.com/a101e-lab/FirmEmuHub",
        "vendor": None,
        "trust_level": "high",
        "access_notes": "GitHub 公开仓库；固件文件可通过 raw.githubusercontent.com 获取。",
        "evidence_url": "https://github.com/a101e-lab/FirmEmuHub/blob/main/DEVICES.md",
    },
    {
        "source_id": "iotvulbench",
        "name": "IoTVulBench",
        "source_type": "benchmark",
        "base_url": "https://github.com/a101e-lab/IoTVulBench",
        "vendor": None,
        "trust_level": "high",
        "access_notes": "公开漏洞验证环境；detail.yml 精确关联 CVE 与 FirmEmuHub benchmark。",
        "evidence_url": "https://github.com/a101e-lab/IoTVulBench/blob/main/vulnerabilities_list.md",
    },
    {
        "source_id": "tplink-download-center",
        "name": "TP-Link Download Center",
        "source_type": "official",
        "base_url": "https://www.tp-link.com/en/support/download/",
        "vendor": "TP-Link",
        "trust_level": "primary",
        "access_notes": "按产品型号和硬件版本选择固件；存在地区版本差异。",
        "evidence_url": "https://www.tp-link.com/en/support/download/",
    },
    {
        "source_id": "dlink-support",
        "name": "D-Link Support",
        "source_type": "official",
        "base_url": "https://support.dlink.com/",
        "vendor": "D-Link",
        "trust_level": "primary",
        "access_notes": "按产品与硬件修订版本检索；旧型号可能位于 legacy 站点。",
        "evidence_url": "https://support.dlink.com/",
    },
    {
        "source_id": "dlink-legacy-support",
        "name": "D-Link Legacy Support",
        "source_type": "official",
        "base_url": "https://legacy.us.dlink.com/",
        "vendor": "D-Link",
        "trust_level": "primary",
        "access_notes": "官方旧型号入口；必须保留产品硬件 revision 与地区信息。",
        "evidence_url": "https://legacy.us.dlink.com/",
    },
    {
        "source_id": "tenda-download",
        "name": "Tenda Download",
        "source_type": "official",
        "base_url": "https://www.tendacn.com/download/default.html",
        "vendor": "Tenda",
        "trust_level": "primary",
        "access_notes": "厂商下载中心；产品和地区版本需要人工核对。",
        "evidence_url": "https://www.tendacn.com/download/default.html",
    },
    {
        "source_id": "netgear-download-center",
        "name": "NETGEAR Download Center",
        "source_type": "official",
        "base_url": "https://www.netgear.com/support/download/",
        "vendor": "NETGEAR",
        "trust_level": "primary",
        "access_notes": "支持按型号检索固件和历史版本。",
        "evidence_url": "https://www.netgear.com/support/download/",
    },
    {
        "source_id": "linksys-support",
        "name": "Linksys Support Downloads",
        "source_type": "official",
        "base_url": "https://support.linksys.com/",
        "vendor": "Linksys",
        "trust_level": "primary",
        "access_notes": "下载文章通常按硬件版本和地区拆分，最终文件位于官方 CDN。",
        "evidence_url": "https://support.linksys.com/kb/article/1184-en/",
    },
    {
        "source_id": "asus-download-center",
        "name": "ASUS Download Center",
        "source_type": "official",
        "base_url": "https://www.asus.com/support/download-center/",
        "vendor": "ASUS",
        "trust_level": "primary",
        "access_notes": "按产品型号进入 BIOS 与固件下载。",
        "evidence_url": "https://www.asus.com/support/download-center/",
    },
    {
        "source_id": "ubiquiti-downloads",
        "name": "Ubiquiti Downloads",
        "source_type": "official",
        "base_url": "https://ui.com/download",
        "vendor": "Ubiquiti",
        "trust_level": "primary",
        "access_notes": "官方产品固件与软件发布入口。",
        "evidence_url": "https://ui.com/download",
    },
    {
        "source_id": "qnap-download-center",
        "name": "QNAP Download Center",
        "source_type": "official",
        "base_url": "https://www.qnap.com/en/download",
        "vendor": "QNAP",
        "trust_level": "primary",
        "access_notes": "按 NAS 型号和操作系统版本筛选。",
        "evidence_url": "https://www.qnap.com/en/download",
    },
    {
        "source_id": "synology-download-center",
        "name": "Synology Download Center",
        "source_type": "official",
        "base_url": "https://www.synology.com/en-global/support/download",
        "vendor": "Synology",
        "trust_level": "primary",
        "access_notes": "按产品型号获取 DSM、SRM 与固件资源。",
        "evidence_url": "https://www.synology.com/en-global/support/download",
    },
    {
        "source_id": "cisco-software-download",
        "name": "Cisco Software Download",
        "source_type": "official",
        "base_url": "https://software.cisco.com/download/home",
        "vendor": "Cisco",
        "trust_level": "primary",
        "access_notes": "部分下载需要 Cisco 账户和有效授权。",
        "evidence_url": "https://software.cisco.com/download/home",
    },
    {
        "source_id": "zyxel-download-library",
        "name": "Zyxel Download Library",
        "source_type": "official",
        "base_url": "https://www.zyxel.com/global/en/support/download",
        "vendor": "Zyxel",
        "trust_level": "primary",
        "access_notes": "官方型号、固件和文档下载目录。",
        "evidence_url": "https://www.zyxel.com/global/en/support/download",
    },
    {
        "source_id": "draytek-firmware",
        "name": "DrayTek Latest Firmwares",
        "source_type": "official",
        "base_url": "https://www.draytek.com/support/latest-firmwares",
        "vendor": "DrayTek",
        "trust_level": "primary",
        "access_notes": "官方最新固件入口；历史版本需进一步定位。",
        "evidence_url": "https://www.draytek.com/support/latest-firmwares",
    },
    {
        "source_id": "openwrt-firmware-selector",
        "name": "OpenWrt Firmware Selector",
        "source_type": "community",
        "base_url": "https://firmware-selector.openwrt.org/",
        "vendor": "OpenWrt",
        "trust_level": "high",
        "access_notes": "开源社区构建，不等同于设备厂商原厂固件。",
        "evidence_url": "https://firmware-selector.openwrt.org/",
    },
    {
        "source_id": "wustl-firmware-dataset",
        "name": "WUSTL Firmware Dataset",
        "source_type": "archive",
        "base_url": "https://github.com/WUSTL-CSPL/Firmware-Dataset",
        "vendor": None,
        "trust_level": "medium",
        "access_notes": "大规模 URL 候选队列；需按官方域名、跳转与可用性二次核验，不自动下载。",
        "evidence_url": "https://github.com/WUSTL-CSPL/Firmware-Dataset/blob/main/dat/firmware_download_list.csv",
    },
    {
        "source_id": "firmware-center",
        "name": "firmware.center Community Archive",
        "source_type": "archive",
        "base_url": "https://firmware.center/firmware/",
        "vendor": None,
        "trust_level": "low",
        "access_notes": "社区归档，仅用于发现与失效链接回补，必须与官方来源或哈希交叉验证。",
        "evidence_url": "https://firmware.center/firmware/",
    },
)


def fetch_text(url: str, timeout: int = 20) -> str:
    request = Request(url, headers={"User-Agent": "FirmAtlas/0.1 metadata-catalog"})
    with urlopen(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def parse_firmemuhub_devices(markdown: str) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    row_pattern = re.compile(
        r"^\|\s*\[(BM-\d{4}-\d+)\]\([^)]+\)\s*"
        r"\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|?\s*$"
    )
    for line in markdown.splitlines():
        match = row_pattern.match(line)
        if not match:
            continue
        benchmark_id, vendor_raw, model, filename = (
            value.strip() for value in match.groups()
        )
        vendor = "TP-Link" if vendor_raw.lower() == "tp-link" else vendor_raw
        encoded_filename = quote(filename, safe="._-()")
        benchmark_url = (
            "https://github.com/a101e-lab/FirmEmuHub/tree/main/Benchmark/{}"
        ).format(benchmark_id)
        candidates.append(
            {
                "candidate_id": "firmemuhub:{}".format(benchmark_id),
                "source_id": "firmemuhub",
                "external_id": benchmark_id,
                "vendor": vendor,
                "product": model,
                "model": model,
                "firmware_version": filename,
                "filename": filename,
                "download_url": (
                    "https://raw.githubusercontent.com/a101e-lab/FirmEmuHub/"
                    "main/Benchmark/{}/emulation/firmware/{}"
                ).format(benchmark_id, encoded_filename),
                "download_host": "raw.githubusercontent.com",
                "source_page_url": benchmark_url,
                "evidence_url": FIRMEMUHUB_DEVICES_URL,
                "url_status": "listed",
                "download_kind": "direct",
                "notes": (
                    "FirmEmuHub benchmark 固件；尚未由 FirmAtlas 下载或校验哈希。"
                    + (" 原始厂商值：{}。".format(vendor_raw) if vendor_raw != vendor else "")
                    + (" 型号、版本与文件名语义存在冲突，需人工复核。" if benchmark_id == "BM-2024-00062" else "")
                ),
            }
        )
    return candidates


def vulnerability_identifiers(markdown: str) -> List[str]:
    seen = set()
    identifiers = []
    for identifier in re.findall(r"\b(?:CVE-\d{4}-\d+|CNVD-\d{4}-\d+)\b", markdown):
        if identifier not in seen:
            seen.add(identifier)
            identifiers.append(identifier)
    return identifiers


_VENDOR_NAMES = {
    "asus": "ASUS",
    "cisco": "Cisco",
    "d-link": "D-Link",
    "dlink": "D-Link",
    "linksys": "Linksys",
    "netgear": "NETGEAR",
    "qnap": "QNAP",
    "synology": "Synology",
    "tenda": "Tenda",
    "tp-link": "TP-Link",
    "tplink": "TP-Link",
    "ubiquiti": "Ubiquiti",
    "zyxel": "Zyxel",
}


def parse_wustl_candidates(stream: TextIO) -> Iterator[Dict[str, Any]]:
    """Parse the large WUSTL URL catalog without loading it into memory."""
    for row in csv.DictReader(stream):
        download_url = (row.get("url") or "").strip()
        parsed = urlsplit(download_url)
        if parsed.scheme.lower() not in ("http", "https", "ftp") or not parsed.netloc:
            continue
        vendor_raw = (row.get("vendor") or "unknown").strip() or "unknown"
        vendor = _VENDOR_NAMES.get(vendor_raw.lower(), vendor_raw)
        product = (row.get("product") or "unknown").strip() or "unknown"
        version = (row.get("version") or "unknown").strip() or "unknown"
        release_date = (row.get("date") or "unknown").strip() or "unknown"
        filename = unquote(parsed.path.rstrip("/").rsplit("/", 1)[-1]) or product
        digest = hashlib.sha256(download_url.encode("utf-8")).hexdigest()
        yield {
            "candidate_id": "wustl:{}".format(digest),
            "source_id": "wustl-firmware-dataset",
            "external_id": digest[:16],
            "vendor": vendor,
            "product": product,
            "model": product,
            "firmware_version": None if version.lower() == "unknown" else version,
            "filename": filename,
            "download_url": download_url,
            "download_host": parsed.hostname.lower() if parsed.hostname else "",
            "source_page_url": WUSTL_FIRMWARE_LIST_PAGE,
            "evidence_url": WUSTL_FIRMWARE_LIST_URL,
            "url_status": "unverified",
            "download_kind": "direct",
            "notes": (
                "WUSTL 固件 URL 数据集候选；发布日期 {}。"
                "尚未由 FirmAtlas 请求文件、跟随跳转或校验内容。"
            ).format(release_date),
        }


def iter_wustl_candidates(timeout: int = 60) -> Iterator[Dict[str, Any]]:
    request = Request(
        WUSTL_FIRMWARE_LIST_URL,
        headers={"User-Agent": "FirmAtlas/0.1 metadata-catalog"},
    )
    with urlopen(request, timeout=timeout) as response:
        with TextIOWrapper(response, encoding="utf-8", errors="replace", newline="") as stream:
            yield from parse_wustl_candidates(stream)


def parse_iotvulbench_detail(identifier: str, detail: str) -> List[Dict[str, Any]]:
    leads = []
    for benchmark_id in dict.fromkeys(re.findall(r"\bBM-\d{4}-\d+\b", detail)):
        leads.append(
            {
                "candidate_id": "firmemuhub:{}".format(benchmark_id),
                "vulnerability_identifier": identifier,
                "relationship": "reproduced_on",
                "confidence": "high",
                "evidence_url": (
                    "https://github.com/a101e-lab/IoTVulBench/blob/main/"
                    "Vulnerabilities/{}/detail.yml"
                ).format(identifier),
                "notes": "IoTVulBench 将该漏洞验证环境明确指向此 benchmark。",
            }
        )
    return leads


def collect_public_catalog(
    loader: Callable[[str], str] = fetch_text,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    candidates = parse_firmemuhub_devices(loader(FIRMEMUHUB_DEVICES_URL))
    candidate_ids = {item["candidate_id"] for item in candidates}
    identifiers = vulnerability_identifiers(loader(IOTVULBENCH_LIST_URL))
    leads: List[Dict[str, Any]] = []
    failures: List[str] = []
    for identifier in identifiers:
        try:
            detail = loader(IOTVULBENCH_DETAIL_URL.format(identifier=identifier))
        except (OSError, ValueError):
            failures.append(identifier)
            continue
        leads.extend(
            item for item in parse_iotvulbench_detail(identifier, detail)
            if item["candidate_id"] in candidate_ids
        )
    return list(DEFAULT_FIRMWARE_SOURCES), candidates, leads, failures


def bootstrap_public_catalog(repository: Any) -> Dict[str, Any]:
    sources, candidates, leads, failures = collect_public_catalog()
    repository.upsert_firmware_sources(sources)
    repository.upsert_firmware_candidates(candidates)
    repository.upsert_firmware_vulnerability_leads(leads)
    wustl_processed = 0
    wustl_error = ""
    batch: List[Dict[str, Any]] = []
    try:
        for candidate in iter_wustl_candidates():
            batch.append(candidate)
            if len(batch) < 2000:
                continue
            repository.upsert_firmware_candidates(batch)
            wustl_processed += len(batch)
            batch = []
        if batch:
            repository.upsert_firmware_candidates(batch)
            wustl_processed += len(batch)
    except (OSError, csv.Error) as error:
        if batch:
            repository.upsert_firmware_candidates(batch)
            wustl_processed += len(batch)
        wustl_error = str(error)
    source_counts = {
        item["source_id"]: item["candidate_count"]
        for item in repository.list_firmware_sources()
    }
    total_candidates = repository.firmware_catalog_overview()["counts"][
        "candidate_count"
    ]
    return {
        "sources": len(sources),
        "benchmark_candidates": len(candidates),
        "wustl_rows_processed": wustl_processed,
        "wustl_candidates": source_counts.get("wustl-firmware-dataset", 0),
        "candidates": total_candidates,
        "vulnerability_leads": len(leads),
        "detail_failures": failures,
        "large_source_failures": (
            [{"source": "wustl-firmware-dataset", "error": wustl_error}]
            if wustl_error else []
        ),
    }
