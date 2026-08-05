"""Firmware vulnerability intelligence acquisition and classification."""

from .models import (
    RelevanceDecision,
    RelevanceLevel,
    RelevancePolicy,
    VulnerabilityRecord,
)
from .relevance import FirmwareRelevanceClassifier

__all__ = [
    "FirmwareRelevanceClassifier",
    "RelevanceDecision",
    "RelevanceLevel",
    "RelevancePolicy",
    "VulnerabilityRecord",
]
