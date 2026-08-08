"""Evaluate representative communication-architecture coverage from catalogs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Optional, Tuple

from .discovery_catalog import DiscoveryCatalog
from .domain import CoverageStatus


CORPUS_REPORT_SCHEMA_VERSION = "firmatlas.mapping.corpus-report/v1alpha1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CorpusEvidenceTier(str, Enum):
    REAL_FIRMWARE = "real_firmware"
    DERIVED_FIRMWARE = "derived_firmware"
    CONTRACT_FIXTURE = "contract_fixture"
    EXTERNAL_LEAD = "external_lead"


class CorpusSampleStatus(str, Enum):
    VERIFIED = "verified"
    DERIVED_ONLY = "derived_only"
    CONTRACT_ONLY = "contract_only"
    COVERAGE_GAP = "coverage_gap"
    ACQUISITION_GAP = "acquisition_gap"


class CorpusGateStatus(str, Enum):
    PASSED = "passed"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass(frozen=True)
class CorpusSampleInput:
    sample_id: str
    architecture_category: str
    architecture_subtype: str
    role: str
    evidence_tier: CorpusEvidenceTier
    required_capabilities: Tuple[str, ...] = ()
    forbidden_capabilities: Tuple[str, ...] = ()
    expected_firmware_sha256: Optional[str] = None
    catalog: Optional[DiscoveryCatalog] = None

    def __post_init__(self) -> None:
        required_text = (
            self.sample_id, self.architecture_category,
            self.architecture_subtype, self.role,
        )
        if any(not value.strip() for value in required_text):
            raise ValueError("corpus sample identity fields cannot be empty")
        if not isinstance(self.evidence_tier, CorpusEvidenceTier):
            raise ValueError("corpus sample requires a valid evidence tier")
        if not self.required_capabilities and not self.forbidden_capabilities:
            raise ValueError("corpus sample requires an evidence capability expectation")
        if self.expected_firmware_sha256 is not None and not _SHA256.fullmatch(
            self.expected_firmware_sha256
        ):
            raise ValueError("expected_firmware_sha256 must be a lowercase SHA-256")
        if (
            self.evidence_tier is CorpusEvidenceTier.REAL_FIRMWARE
            and self.expected_firmware_sha256 is None
        ):
            raise ValueError("real firmware evidence requires an expected artifact identity")
        if set(self.required_capabilities) & set(self.forbidden_capabilities):
            raise ValueError("a capability cannot be both required and forbidden")


@dataclass(frozen=True)
class CorpusReportInput:
    corpus_version: str
    samples: Tuple[CorpusSampleInput, ...]
    required_categories: Tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.corpus_version.strip() or not self.samples:
            raise ValueError("corpus report requires a version and samples")
        if not self.required_categories or any(
            not value.strip() for value in self.required_categories
        ):
            raise ValueError("corpus report requires a required architecture category")
        sample_ids = tuple(item.sample_id for item in self.samples)
        if len(sample_ids) != len(set(sample_ids)):
            raise ValueError("duplicate corpus sample_id")
        if len(self.required_categories) != len(set(self.required_categories)):
            raise ValueError("duplicate required architecture category")


@dataclass(frozen=True)
class CorpusSampleResult:
    sample_id: str
    architecture_category: str
    architecture_subtype: str
    role: str
    evidence_tier: CorpusEvidenceTier
    status: CorpusSampleStatus
    catalog_id: Optional[str]
    required_capabilities: Tuple[str, ...]
    forbidden_capabilities: Tuple[str, ...]
    observed_capabilities: Tuple[str, ...]
    missing_capabilities: Tuple[str, ...]
    unexpected_capabilities: Tuple[str, ...]
    candidate_kinds: Tuple[str, ...]
    candidate_count: int
    evidence_count: int
    open_obligation_count: int


@dataclass(frozen=True)
class CorpusCategoryResult:
    architecture_category: str
    status: CorpusSampleStatus
    sample_count: int
    real_firmware_verified_count: int
    derived_firmware_verified_count: int
    contract_verified_count: int
    coverage_gap_count: int
    acquisition_gap_count: int
    observed_capabilities: Tuple[str, ...]
    candidate_kinds: Tuple[str, ...]
    open_obligation_count: int


@dataclass(frozen=True)
class CorpusReport:
    report_id: str
    corpus_version: str
    gate_status: CorpusGateStatus
    required_categories: Tuple[str, ...]
    samples: Tuple[CorpusSampleResult, ...]
    categories: Tuple[CorpusCategoryResult, ...]
    schema_version: str = CORPUS_REPORT_SCHEMA_VERSION

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "report_id": self.report_id,
            "corpus_version": self.corpus_version,
            "gate_status": self.gate_status.value,
            "required_categories": list(self.required_categories),
            "samples": [
                {
                    **asdict(item),
                    "evidence_tier": item.evidence_tier.value,
                    "status": item.status.value,
                }
                for item in self.samples
            ],
            "categories": [
                {**asdict(item), "status": item.status.value}
                for item in self.categories
            ],
        }


def _sample_result(sample: CorpusSampleInput) -> CorpusSampleResult:
    if sample.evidence_tier is CorpusEvidenceTier.EXTERNAL_LEAD:
        if sample.catalog is not None:
            raise ValueError("external leads cannot carry a firmware discovery catalog")
        return CorpusSampleResult(
            sample.sample_id, sample.architecture_category,
            sample.architecture_subtype, sample.role, sample.evidence_tier,
            CorpusSampleStatus.ACQUISITION_GAP, None,
            tuple(sorted(set(sample.required_capabilities))),
            tuple(sorted(set(sample.forbidden_capabilities))), (),
            tuple(sorted(set(sample.required_capabilities))), (), (), 0, 0, 0,
        )
    if sample.catalog is None:
        return CorpusSampleResult(
            sample.sample_id, sample.architecture_category,
            sample.architecture_subtype, sample.role, sample.evidence_tier,
            CorpusSampleStatus.COVERAGE_GAP, None,
            tuple(sorted(set(sample.required_capabilities))),
            tuple(sorted(set(sample.forbidden_capabilities))), (),
            tuple(sorted(set(sample.required_capabilities))), (), (), 0, 0, 0,
        )
    if (
        sample.expected_firmware_sha256 is not None
        and sample.catalog.firmware_artifact_sha256 != sample.expected_firmware_sha256
    ):
        raise ValueError("corpus catalog firmware identity does not match its sample")

    observed = tuple(sorted({atom.capability for atom in sample.catalog.evidence_atoms}))
    missing = tuple(sorted(set(sample.required_capabilities) - set(observed)))
    unexpected = tuple(sorted(set(sample.forbidden_capabilities) & set(observed)))
    candidate_kinds = tuple(sorted({
        item.candidate_kind.value for item in sample.catalog.candidates
    }))
    if (
        missing or unexpected or sample.catalog.open_obligations
        or sample.catalog.coverage_status is not CoverageStatus.COMPLETED
    ):
        status = CorpusSampleStatus.COVERAGE_GAP
    elif sample.evidence_tier is CorpusEvidenceTier.REAL_FIRMWARE:
        status = CorpusSampleStatus.VERIFIED
    elif sample.evidence_tier is CorpusEvidenceTier.DERIVED_FIRMWARE:
        status = CorpusSampleStatus.DERIVED_ONLY
    else:
        status = CorpusSampleStatus.CONTRACT_ONLY
    return CorpusSampleResult(
        sample.sample_id, sample.architecture_category,
        sample.architecture_subtype, sample.role, sample.evidence_tier,
        status, sample.catalog.catalog_id,
        tuple(sorted(set(sample.required_capabilities))),
        tuple(sorted(set(sample.forbidden_capabilities))),
        observed, missing, unexpected,
        candidate_kinds, len(sample.catalog.candidates),
        len(sample.catalog.evidence_atoms), len(sample.catalog.open_obligations),
    )


def _category_result(category: str, samples: tuple) -> CorpusCategoryResult:
    real_count = sum(item.status is CorpusSampleStatus.VERIFIED for item in samples)
    derived_count = sum(
        item.status is CorpusSampleStatus.DERIVED_ONLY for item in samples
    )
    contract_count = sum(item.status is CorpusSampleStatus.CONTRACT_ONLY for item in samples)
    coverage_gap_count = sum(
        item.status is CorpusSampleStatus.COVERAGE_GAP for item in samples
    )
    acquisition_gap_count = sum(
        item.status is CorpusSampleStatus.ACQUISITION_GAP for item in samples
    )
    if real_count:
        status = CorpusSampleStatus.VERIFIED
    elif derived_count:
        status = CorpusSampleStatus.DERIVED_ONLY
    elif contract_count:
        status = CorpusSampleStatus.CONTRACT_ONLY
    elif coverage_gap_count:
        status = CorpusSampleStatus.COVERAGE_GAP
    else:
        status = CorpusSampleStatus.ACQUISITION_GAP
    return CorpusCategoryResult(
        category, status, len(samples), real_count, derived_count, contract_count,
        coverage_gap_count, acquisition_gap_count,
        tuple(sorted({value for item in samples for value in item.observed_capabilities})),
        tuple(sorted({value for item in samples for value in item.candidate_kinds})),
        sum(item.open_obligation_count for item in samples),
    )


def build_corpus_report(value: CorpusReportInput) -> CorpusReport:
    """Build one deterministic, evidence-tier-aware representative corpus report."""

    samples = tuple(sorted(
        (_sample_result(item) for item in value.samples), key=lambda item: item.sample_id
    ))
    categories = tuple(
        _category_result(category, tuple(
            item for item in samples if item.architecture_category == category
        ))
        for category in sorted(
            {item.architecture_category for item in samples} | set(value.required_categories)
        )
    )
    category_by_name = {item.architecture_category: item for item in categories}
    required_statuses = tuple(
        category_by_name.get(category).status
        if category in category_by_name else CorpusSampleStatus.ACQUISITION_GAP
        for category in value.required_categories
    )
    if required_statuses and all(
        status is CorpusSampleStatus.VERIFIED for status in required_statuses
    ):
        gate_status = CorpusGateStatus.PASSED
    elif any(status in {
        CorpusSampleStatus.VERIFIED, CorpusSampleStatus.DERIVED_ONLY,
        CorpusSampleStatus.CONTRACT_ONLY,
    } for status in required_statuses):
        gate_status = CorpusGateStatus.PARTIAL
    else:
        gate_status = CorpusGateStatus.FAILED

    payload = {
        "schema_version": CORPUS_REPORT_SCHEMA_VERSION,
        "corpus_version": value.corpus_version,
        "gate_status": gate_status.value,
        "required_categories": sorted(value.required_categories),
        "samples": [
            {
                **asdict(item),
                "evidence_tier": item.evidence_tier.value,
                "status": item.status.value,
            }
            for item in samples
        ],
        "categories": [
            {**asdict(item), "status": item.status.value} for item in categories
        ],
    }
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return CorpusReport(
        "corpus-report:" + hashlib.sha256(encoded).hexdigest(),
        value.corpus_version, gate_status,
        tuple(sorted(value.required_categories)), samples, categories,
    )
