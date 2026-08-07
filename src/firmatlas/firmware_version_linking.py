"""Derive explainable firmware candidate to vulnerability version leads."""

from __future__ import annotations

from collections import defaultdict
import json
import re
from typing import Any, DefaultDict, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import unquote


_UNKNOWN = {"", "*", "-", "n/a", "na", "none", "null", "unknown", "unspecified"}
_VERSION_PATTERN = re.compile(
    r"(?<![a-z0-9])([a-z]?\d+(?:[._-]\d+){1,6}(?:[a-z]+\d*)?)",
    re.IGNORECASE,
)
_SINGLE_VERSION_PATTERN = re.compile(
    r"(?:^|[_-])(?:fw|firmware|ver|version|bios|v)[_-]?(\d{3,8}[a-z]?)(?=[_.-]|$)",
    re.IGNORECASE,
)
_PRODUCT_NOISE = re.compile(
    r"\b(?:firmware|software|router|gateway|device|series|version)\b",
    re.IGNORECASE,
)


def normalize_version(value: str) -> str:
    value = unquote(str(value or "")).replace("\\", "").strip().lower()
    value = re.sub(r"\.(?:zip|bin|img|trx|chk|tar|gz|rar|exe)$", "", value)
    value = re.sub(r"^(?:firmware|version|ver)[-_ ]*", "", value)
    value = re.sub(r"^v(?=\d)", "", value)
    return value.strip(" _-")


def _meaningful_version(value: Optional[str]) -> bool:
    return normalize_version(value or "") not in _UNKNOWN


def _version_key(value: str) -> Tuple[Tuple[int, Any], ...]:
    normalized = normalize_version(value).replace("_", ".").replace("-", ".")
    return tuple(
        (0, int(token)) if token.isdigit() else (1, token)
        for token in re.findall(r"\d+|[a-z]+", normalized)
    )


def _version_scheme(value: str) -> Tuple[str, int]:
    normalized = normalize_version(value)
    prefix_match = re.match(r"([a-z]+)(?=\d)", normalized)
    prefix = prefix_match.group(1) if prefix_match else ""
    return prefix, len(re.findall(r"\d+", normalized))


def _comparable_versions(left: str, right: str) -> bool:
    left_prefix, left_parts = _version_scheme(left)
    right_prefix, right_parts = _version_scheme(right)
    if left_prefix != right_prefix:
        return False
    # A single integer is commonly a build date or vendor build ID, not a
    # semantic release comparable with a dotted multi-component version.
    if (left_parts == 1) != (right_parts == 1):
        return False
    return bool(left_parts and right_parts)


def _same_version(left: str, right: str) -> bool:
    return bool(_version_key(left)) and _version_key(left) == _version_key(right)


def extract_candidate_versions(
    filename: str, declared_version: Optional[str]
) -> List[Dict[str, str]]:
    """Return ordered version identities with extraction provenance."""
    result: List[Dict[str, str]] = []
    seen = set()

    def append(raw: str, source: str, confidence: str) -> None:
        normalized = normalize_version(raw)
        key = _version_key(normalized)
        if not normalized or normalized in _UNKNOWN or not key or key in seen:
            return
        seen.add(key)
        result.append({
            "raw": raw,
            "normalized": normalized,
            "source": source,
            "confidence": confidence,
        })

    declared = str(declared_version or "").strip()
    if _meaningful_version(declared) and not re.search(
        r"\.(?:zip|bin|img|trx|chk|tar|gz|rar|exe)$", declared, re.IGNORECASE
    ):
        append(declared, "declared", "high")
    for match in _VERSION_PATTERN.finditer(filename or declared):
        append(match.group(1), "filename", "medium")
    for match in _SINGLE_VERSION_PATTERN.finditer(filename or declared):
        append(match.group(1), "filename", "low")
    return result


def _identity(value: str) -> str:
    value = unquote(str(value or "")).replace("\\", " ").replace("_", " ")
    value = _PRODUCT_NOISE.sub(" ", value)
    return "".join(re.findall(r"[a-z0-9]+", value.lower()))


def _vendor_identity(value: str) -> str:
    normalized = _identity(value)
    aliases = {
        "tplink": "tplink", "dlink": "dlink", "netgearinc": "netgear",
        "axiscommunications": "axis", "hewlettpackardenterprise": "hpe",
    }
    return aliases.get(normalized, normalized)


def _parse_cpe(criteria: str) -> Optional[Tuple[str, str, str]]:
    parts = str(criteria or "").split(":")
    if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
        return parts[3], parts[4], parts[5]
    if str(criteria or "").startswith("cpe:/") and len(parts) >= 5:
        return parts[2], parts[3], parts[4]
    return None


def _constraint(claim: Dict[str, Any]) -> str:
    start_in = claim.get("version_start_including")
    start_ex = claim.get("version_start_excluding")
    end_in = claim.get("version_end_including")
    end_ex = claim.get("version_end_excluding")
    if any((start_in, start_ex, end_in, end_ex)):
        left = "[" if start_in else "("
        right = "]" if end_in else ")"
        return "{}{}, {}{}".format(
            left, start_in or start_ex or "-∞", end_in or end_ex or "+∞", right
        )
    parsed = _parse_cpe(str(claim.get("criteria") or ""))
    version = parsed[2] if parsed else "*"
    return version if _meaningful_version(version) else "all versions"


def _in_range(version: str, claim: Dict[str, Any]) -> bool:
    value = _version_key(version)
    if not value:
        return False
    boundaries = (
        ("version_start_including", lambda item: value >= item),
        ("version_start_excluding", lambda item: value > item),
        ("version_end_including", lambda item: value <= item),
        ("version_end_excluding", lambda item: value < item),
    )
    for name, predicate in boundaries:
        boundary = claim.get(name)
        if boundary:
            if not _comparable_versions(version, str(boundary)):
                return False
            if not predicate(_version_key(str(boundary))):
                return False
    return True


class FirmwareVersionLinker:
    """Build derived leads from NVD affected claims and candidate version identity."""

    def __init__(self, repository: Any) -> None:
        self.repository = repository

    def rebuild(self, batch_size: int = 5000) -> Dict[str, int]:
        with self.repository.read_connection() as connection:
            candidates = [dict(row) for row in connection.execute(
                "SELECT candidate_id,vendor,product,model,firmware_version,filename "
                "FROM firmware_sample_candidates"
            )]

        index: DefaultDict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
        version_updates = []
        versioned = 0
        for candidate in candidates:
            identities = extract_candidate_versions(
                candidate["filename"], candidate.get("firmware_version")
            )
            candidate["version_identities"] = identities
            if identities:
                versioned += 1
            version_updates.append((json.dumps(identities, ensure_ascii=False), candidate["candidate_id"]))
            vendor = _vendor_identity(candidate["vendor"])
            for product in {candidate["product"], candidate["model"]}:
                product_key = _identity(product)
                if vendor and product_key:
                    index[(vendor, product_key)].append(candidate)

        with self.repository.transaction() as connection:
            connection.executemany(
                "UPDATE firmware_sample_candidates SET version_identities_json=? WHERE candidate_id=?",
                version_updates,
            )
            connection.execute(
                "DELETE FROM firmware_sample_vulnerabilities WHERE association_origin='derived'"
            )
            curated = {
                (row[0], row[1]) for row in connection.execute(
                    "SELECT candidate_id,vulnerability_identifier "
                    "FROM firmware_sample_vulnerabilities"
                )
            }

        counts = {"exact_version": 0, "version_range": 0, "product_scope": 0}
        best: Dict[Tuple[str, str], Dict[str, Any]] = {}
        with self.repository.read_connection() as connection:
            rows = connection.execute(
                "SELECT identifier,affected_products_json FROM vulnerabilities "
                "WHERE affected_products_json!='[]'"
            )
            for row in rows:
                identifier = row["identifier"]
                for claim in json.loads(row["affected_products_json"] or "[]"):
                    if claim.get("vulnerable") is False:
                        continue
                    parsed = _parse_cpe(str(claim.get("criteria") or ""))
                    if not parsed:
                        continue
                    vendor, product, affected_version = parsed
                    matches = index.get((_vendor_identity(vendor), _identity(product)), ())
                    for candidate in matches:
                        key = (candidate["candidate_id"], identifier)
                        if key in curated:
                            continue
                        lead = self._match(candidate, claim, affected_version, identifier)
                        if not lead:
                            continue
                        previous = best.get(key)
                        if previous is None or lead["match_score"] > previous["match_score"]:
                            best[key] = lead

        leads = list(best.values())
        for start in range(0, len(leads), max(1, batch_size)):
            self.repository.upsert_firmware_vulnerability_leads(
                leads[start:start + batch_size]
            )
        for lead in leads:
            counts[lead["match_method"]] += 1
        return {
            "candidate_count": len(candidates),
            "version_identified_candidates": versioned,
            "derived_links": len(leads),
            **counts,
        }

    @staticmethod
    def _match(
        candidate: Dict[str, Any], claim: Dict[str, Any], affected_version: str,
        identifier: str,
    ) -> Optional[Dict[str, Any]]:
        identities: Sequence[Dict[str, str]] = candidate["version_identities"]
        matched: Optional[Dict[str, str]] = None
        method = ""
        score = 0
        confidence = "low"
        has_range = any(claim.get(name) for name in (
            "version_start_including", "version_start_excluding",
            "version_end_including", "version_end_excluding",
        ))
        if _meaningful_version(affected_version):
            matched = next((item for item in identities if _same_version(
                item["normalized"], affected_version
            )), None)
            if not matched:
                return None
            method, score, confidence = "exact_version", 98, "high"
        elif has_range:
            matched = next((item for item in identities if _in_range(
                item["normalized"], claim
            )), None)
            if not matched:
                return None
            method, score, confidence = "version_range", 90, "high"
        else:
            matched = identities[0] if identities else None
            method, score, confidence = "product_scope", 58, "low"

        criteria = str(claim.get("criteria") or "")
        candidate_version = matched["raw"] if matched else None
        return {
            "candidate_id": candidate["candidate_id"],
            "vulnerability_identifier": identifier,
            "relationship": "affected_release_candidate",
            "confidence": confidence,
            "evidence_url": "https://nvd.nist.gov/vuln/detail/{}".format(identifier),
            "notes": "由 NVD 受影响 CPE 与固件候选的厂商、产品及版本约束自动推导。",
            "association_origin": "derived",
            "match_method": method,
            "match_score": score,
            "candidate_version": candidate_version,
            "affected_constraint": _constraint(claim),
            "matched_criteria": criteria,
        }
