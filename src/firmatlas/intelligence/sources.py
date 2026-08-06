"""Adapters for official vulnerability intelligence sources."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
import time
from typing import Any, Dict, Iterable, Iterator, List, Optional, Protocol, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .models import VulnerabilityRecord


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
CPE_VENDOR_LABELS = {
    "d-link": "D-Link",
    "dlink": "D-Link",
    "tp-link": "TP-Link",
    "tplink": "TP-Link",
    "netgear": "NETGEAR",
    "totolink": "TOTOLINK",
}


class SourceError(RuntimeError):
    pass


class JsonTransport(Protocol):
    def get_json(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        ...


class UrllibJsonTransport:
    def __init__(self, timeout: float = 60.0, attempts: int = 3) -> None:
        self.timeout = timeout
        self.attempts = attempts

    def get_json(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        target = url
        if params:
            target = "{}?{}".format(url, urlencode(params))
        request_headers = {
            "Accept": "application/json",
            "User-Agent": "FirmAtlas/0.1 (+https://github.com/FitzBC/FirmAtlas)",
        }
        request_headers.update(headers or {})
        last_error: Optional[BaseException] = None
        for attempt in range(self.attempts):
            try:
                with urlopen(
                    Request(target, headers=request_headers), timeout=self.timeout
                ) as response:
                    return json.loads(response.read().decode("utf-8"))
            except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
                last_error = error
                if isinstance(error, HTTPError) and error.code not in (
                    429,
                    500,
                    502,
                    503,
                    504,
                ):
                    break
                if attempt + 1 < self.attempts:
                    retry_after = 0.0
                    if isinstance(error, HTTPError):
                        retry_after = float(error.headers.get("Retry-After", "0") or 0)
                    time.sleep(max(retry_after, float(2 ** attempt)))
        raise SourceError("failed to fetch {}: {}".format(target, last_error))


class NvdSource:
    name = "nvd"

    def __init__(
        self,
        transport: Optional[JsonTransport] = None,
        api_key: Optional[str] = None,
        page_size: int = 200,
        window_hours: int = 3,
        min_interval: Optional[float] = None,
    ) -> None:
        self.transport = transport or UrllibJsonTransport()
        self.api_key = api_key if api_key is not None else os.getenv("NVD_API_KEY")
        self.page_size = max(1, min(page_size, 2000))
        self.window_hours = max(1, min(window_hours, 24 * 120))
        self.min_interval = (
            min_interval
            if min_interval is not None
            else (0.7 if self.api_key else 6.2)
        )
        self._last_request_at = 0.0

    def fetch_modified(
        self, start: datetime, end: datetime
    ) -> Iterator[VulnerabilityRecord]:
        if start.tzinfo is None or end.tzinfo is None:
            raise ValueError("NVD sync range must be timezone-aware")
        if end <= start:
            return
        window_start = start
        while window_start < end:
            window_end = min(
                window_start + timedelta(hours=self.window_hours), end
            )
            yield from self._fetch_window(window_start, window_end)
            window_start = window_end

    def _fetch_window(
        self, start: datetime, end: datetime
    ) -> Iterator[VulnerabilityRecord]:
        start_index = 0
        headers = {"apiKey": self.api_key} if self.api_key else {}
        while True:
            self._throttle()
            payload = self.transport.get_json(
                NVD_API_URL,
                params={
                    "lastModStartDate": _nvd_time(start),
                    "lastModEndDate": _nvd_time(end),
                    "resultsPerPage": str(self.page_size),
                    "startIndex": str(start_index),
                },
                headers=headers,
            )
            vulnerabilities = payload.get("vulnerabilities", [])
            for item in vulnerabilities:
                cve = item.get("cve", item)
                yield normalize_nvd(cve)
            received = len(vulnerabilities)
            total = int(payload.get("totalResults", received))
            start_index += received
            if received == 0 or start_index >= total:
                break

    def _throttle(self) -> None:
        elapsed = time.monotonic() - self._last_request_at
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_request_at = time.monotonic()


class CisaKevSource:
    name = "cisa-kev"

    def __init__(self, transport: Optional[JsonTransport] = None) -> None:
        self.transport = transport or UrllibJsonTransport()

    def fetch_all(self) -> Iterator[VulnerabilityRecord]:
        payload = self.transport.get_json(CISA_KEV_URL)
        for item in payload.get("vulnerabilities", []):
            yield normalize_cisa_kev(item, payload.get("dateReleased"))


def normalize_nvd(cve: Dict[str, Any]) -> VulnerabilityRecord:
    identifier = str(cve.get("id", "")).strip()
    description = _english_description(cve.get("descriptions", []))
    affected = cve.get("affected", [])
    cpes = tuple(
        dict.fromkeys(
            tuple(_walk_cpes(cve.get("configurations", [])))
            + tuple(_walk_field_values(affected, "cpes"))
        )
    )
    cpe_vendors, cpe_products = vendors_and_products_from_cpes(cpes)
    vendors = _meaningful_identity_values(
        tuple(_walk_field_values(affected, "vendor")) + tuple(cpe_vendors)
    )
    products = _meaningful_identity_values(
        tuple(_walk_field_values(affected, "product")) + tuple(cpe_products)
    )
    cvss_metrics = _cvss_metrics(cve.get("metrics", {}))
    best_cvss = cvss_metrics[0] if cvss_metrics else {}
    score = best_cvss.get("base_score")
    severity = best_cvss.get("base_severity")
    vector = best_cvss.get("vector")
    cwes = tuple(
        sorted(
            {
                description_item.get("value", "")
                for weakness in cve.get("weaknesses", [])
                for description_item in weakness.get("description", [])
                if description_item.get("value")
            }
        )
    )
    cwe_details = tuple(
        {
            "id": description_item.get("value", ""),
            "source": weakness.get("source"),
            "type": weakness.get("type"),
        }
        for weakness in cve.get("weaknesses", [])
        for description_item in weakness.get("description", [])
        if description_item.get("value")
    )
    reference_details = tuple(
        {
            "url": reference.get("url", ""),
            "source": reference.get("source"),
            "tags": tuple(reference.get("tags") or ()),
        }
        for reference in cve.get("references", [])
        if reference.get("url")
    )
    references = tuple(item["url"] for item in reference_details)
    exploit_references = tuple(
        item["url"]
        for item in reference_details
        if any(str(tag).lower() == "exploit" for tag in item["tags"])
    )
    vendor = vendors[0] if vendors else None
    product = products[0] if products else None
    title = cve.get("cisaVulnerabilityName") or _summary_title(
        identifier, description, vendor, product
    )
    return VulnerabilityRecord(
        identifier=identifier,
        source="nvd",
        source_identifier=identifier,
        title=title,
        summary=description,
        published_at=cve.get("published"),
        modified_at=cve.get("lastModified"),
        vendor=vendor,
        product=product,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        cvss_version=best_cvss.get("version"),
        impact_score=best_cvss.get("impact_score"),
        exploitability_score=best_cvss.get("exploitability_score"),
        attack_vector=best_cvss.get("attack_vector"),
        attack_complexity=best_cvss.get("attack_complexity"),
        privileges_required=best_cvss.get("privileges_required"),
        user_interaction=best_cvss.get("user_interaction"),
        scope=best_cvss.get("scope"),
        cvss_metrics=cvss_metrics,
        cwes=cwes,
        cpes=cpes,
        references=references,
        reference_details=reference_details,
        exploit_references=exploit_references,
        cwe_details=cwe_details,
        affected_products=_affected_products(cve.get("configurations", [])),
        kev=bool(cve.get("cisaExploitAdd")),
        kev_date_added=cve.get("cisaExploitAdd"),
        kev_due_date=cve.get("cisaActionDue"),
        required_action=cve.get("cisaRequiredAction"),
        raw=cve,
    )


def normalize_cisa_kev(
    item: Dict[str, Any], catalog_date: Optional[str]
) -> VulnerabilityRecord:
    identifier = str(item.get("cveID", "")).strip()
    cwes_value = item.get("cwes") or []
    if isinstance(cwes_value, str):
        cwes_value = [cwes_value]
    return VulnerabilityRecord(
        identifier=identifier,
        source="cisa-kev",
        source_identifier=identifier,
        title=item.get("vulnerabilityName") or identifier,
        summary=item.get("shortDescription") or "",
        published_at=item.get("dateAdded"),
        modified_at=catalog_date or item.get("dateAdded"),
        vendor=item.get("vendorProject"),
        product=item.get("product"),
        cwes=tuple(str(value) for value in cwes_value),
        references=tuple(
            value.strip()
            for value in str(item.get("notes") or "").split(";")
            if value.strip().startswith("http")
        ),
        kev=True,
        kev_date_added=item.get("dateAdded"),
        kev_due_date=item.get("dueDate"),
        ransomware_use=item.get("knownRansomwareCampaignUse"),
        required_action=item.get("requiredAction"),
        raw=item,
    )


def _nvd_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _english_description(values: Iterable[Dict[str, Any]]) -> str:
    values = list(values)
    for item in values:
        if item.get("lang") == "en":
            return str(item.get("value", ""))
    return str(values[0].get("value", "")) if values else ""


def _walk_cpes(value: Any) -> Iterator[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "criteria" and isinstance(child, str):
                yield child
            else:
                yield from _walk_cpes(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_cpes(child)


def _walk_field_values(value: Any, field: str) -> Iterator[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == field:
                if isinstance(child, str) and child:
                    yield child
                elif isinstance(child, list):
                    for item in child:
                        if isinstance(item, str) and item:
                            yield item
            else:
                yield from _walk_field_values(child, field)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_field_values(child, field)


def vendors_and_products_from_cpes(
    cpes: Iterable[str],
) -> Tuple[List[str], List[str]]:
    vendors: List[str] = []
    products: List[str] = []
    for cpe in cpes:
        parts = cpe.split(":")
        if cpe.startswith("cpe:/") and len(parts) >= 4:
            vendor = parts[2].replace("_", " ")
            product = parts[3].replace("_", " ")
        elif len(parts) >= 5:
            vendor = parts[3].replace("_", " ")
            product = parts[4].replace("_", " ")
        else:
            continue
        vendor = CPE_VENDOR_LABELS.get(vendor.lower(), vendor)
        if is_meaningful_identity(vendor) and vendor not in vendors:
            vendors.append(vendor)
        if is_meaningful_identity(product) and product not in products:
            products.append(product)
    return vendors, products


def is_meaningful_identity(value: Any) -> bool:
    return str(value or "").strip().lower() not in {
        "", "*", "-", "n/a", "na", "unknown", "unspecified", "not applicable",
    }


def _meaningful_identity_values(values: Iterable[Any]) -> List[str]:
    result: List[str] = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        key = text.lower()
        if is_meaningful_identity(text) and key not in seen:
            result.append(text)
            seen.add(key)
    return result


def _cvss_metrics(metrics: Dict[str, Any]) -> Tuple[Dict[str, Any], ...]:
    result: List[Dict[str, Any]] = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = metrics.get(key) or []
        candidates = sorted(candidates, key=lambda item: item.get("type") != "Primary")
        for candidate in candidates:
            data = candidate.get("cvssData", {})
            score = data.get("baseScore")
            version = str(data.get("version") or _version_from_key(key))
            severity = data.get("baseSeverity") or candidate.get("baseSeverity")
            if not severity and score is not None:
                severity = _severity(float(score), version)
            result.append(
                {
                    "version": version,
                    "type": candidate.get("type"),
                    "source": candidate.get("source"),
                    "base_score": float(score) if score is not None else None,
                    "base_severity": str(severity).upper() if severity else None,
                    "vector": data.get("vectorString"),
                    "impact_score": candidate.get("impactScore"),
                    "exploitability_score": candidate.get("exploitabilityScore"),
                    "attack_vector": data.get("attackVector") or data.get("accessVector"),
                    "attack_complexity": data.get("attackComplexity") or data.get("accessComplexity"),
                    "privileges_required": data.get("privilegesRequired") or data.get("authentication"),
                    "user_interaction": data.get("userInteraction") or candidate.get("userInteractionRequired"),
                    "scope": data.get("scope"),
                }
            )
    return tuple(result)


def _version_from_key(key: str) -> str:
    return {"cvssMetricV40": "4.0", "cvssMetricV31": "3.1", "cvssMetricV30": "3.0", "cvssMetricV2": "2.0"}[key]


def _severity(score: float, version: str) -> str:
    if score == 0:
        return "NONE" if not version.startswith("2") else "LOW"
    if version.startswith("2"):
        return "LOW" if score < 4 else "MEDIUM" if score < 7 else "HIGH"
    return "LOW" if score < 4 else "MEDIUM" if score < 7 else "HIGH" if score < 9 else "CRITICAL"


def _affected_products(configurations: Any) -> Tuple[Dict[str, Any], ...]:
    result: List[Dict[str, Any]] = []

    def walk(value: Any, vulnerable: Optional[bool] = None) -> None:
        if isinstance(value, dict):
            current_vulnerable = value.get("vulnerable", vulnerable)
            if isinstance(value.get("criteria"), str):
                result.append(
                    {
                        "criteria": value["criteria"],
                        "match_criteria_id": value.get("matchCriteriaId"),
                        "vulnerable": bool(current_vulnerable),
                        "version_start_including": value.get("versionStartIncluding"),
                        "version_start_excluding": value.get("versionStartExcluding"),
                        "version_end_including": value.get("versionEndIncluding"),
                        "version_end_excluding": value.get("versionEndExcluding"),
                    }
                )
            for child in value.values():
                walk(child, current_vulnerable)
        elif isinstance(value, list):
            for child in value:
                walk(child, vulnerable)

    walk(configurations)
    return tuple(result)


def _summary_title(
    identifier: str, summary: str, vendor: Optional[str], product: Optional[str]
) -> str:
    if vendor or product:
        return "{} · {} {}".format(identifier, vendor or "", product or "").strip()
    sentence = summary.split(". ", 1)[0].strip()
    return sentence[:120] if sentence else identifier
