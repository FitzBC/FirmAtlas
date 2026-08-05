import unittest

from firmatlas.intelligence.models import RelevanceLevel, RelevancePolicy, VulnerabilityRecord
from firmatlas.intelligence.relevance import FirmwareRelevanceClassifier


def record(**overrides):
    values = {
        "identifier": "CVE-2026-0001",
        "source": "test",
        "source_identifier": "CVE-2026-0001",
        "title": "Example vulnerability",
        "summary": "A general-purpose server application has an issue.",
        "published_at": "2026-08-01T00:00:00Z",
        "modified_at": "2026-08-01T00:00:00Z",
    }
    values.update(overrides)
    return VulnerabilityRecord(**values)


class FirmwareRelevanceClassifierTests(unittest.TestCase):
    def test_tenda_is_explicitly_classified_as_firmware_vendor(self) -> None:
        record = VulnerabilityRecord(
            identifier="CVE-2026-9999", source="nvd", source_identifier="CVE-2026-9999",
            title="Tenda AC8 issue", summary="An issue affects the AC8 device.",
            published_at=None, modified_at=None, vendor="Tenda", product="AC8",
        )
        decision = FirmwareRelevanceClassifier().classify(record, RelevancePolicy())
        self.assertEqual(RelevanceLevel.LIKELY, decision.level)
        self.assertIn("firmware-vendor", [signal.code for signal in decision.signals])

    def setUp(self) -> None:
        self.classifier = FirmwareRelevanceClassifier()
        self.policy = RelevancePolicy()

    def test_explicit_firmware_and_device_term_is_strong(self) -> None:
        decision = self.classifier.classify(
            record(summary="The router firmware permits command injection."), self.policy
        )

        self.assertEqual(RelevanceLevel.STRONG, decision.level)
        self.assertIn("firmware-term", {signal.code for signal in decision.signals})

    def test_firmware_only_vendor_is_sufficient_but_explainable(self) -> None:
        decision = self.classifier.classify(
            record(vendor="TP-Link", product="Archer AX55"), self.policy
        )

        self.assertEqual(RelevanceLevel.LIKELY, decision.level)
        self.assertEqual(55, decision.score)

    def test_generic_watched_vendor_alone_goes_to_review_not_firmware_feed(self) -> None:
        decision = self.classifier.classify(record(vendor="Cisco"), self.policy)

        self.assertEqual(RelevanceLevel.UNRELATED, decision.level)
        self.assertFalse(decision.is_firmware_related)

    def test_hardware_cpe_plus_device_context_is_likely(self) -> None:
        decision = self.classifier.classify(
            record(
                summary="A network camera accepts a crafted request.",
                cpes=("cpe:2.3:h:acme:camera:*:*:*:*:*:*:*:*",),
            ),
            self.policy,
        )

        self.assertEqual(RelevanceLevel.LIKELY, decision.level)

    def test_cloud_context_reduces_weak_vendor_match(self) -> None:
        decision = self.classifier.classify(
            record(vendor="Cisco", summary="A Cisco cloud service has an issue."),
            self.policy,
        )

        self.assertEqual(0, decision.score)


if __name__ == "__main__":
    unittest.main()
