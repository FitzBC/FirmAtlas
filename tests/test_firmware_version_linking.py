import unittest
from dataclasses import replace
from typing import Optional

from firmatlas.firmware_version_linking import (
    FirmwareVersionLinker,
    extract_candidate_versions,
)
from firmatlas.intelligence.relevance import FirmwareRelevanceClassifier
from firmatlas.intelligence.repository import IntelligenceRepository
from firmatlas.intelligence.sample_data import demo_records


class FirmwareVersionLinkingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = IntelligenceRepository(":memory:")
        self.repository.upsert_firmware_sources(({
            "source_id": "fixture", "name": "Fixture",
            "source_type": "official", "base_url": "https://example.test",
            "vendor": None, "trust_level": "primary", "access_notes": "",
            "evidence_url": "https://example.test/catalog",
        },))
        self.classifier = FirmwareRelevanceClassifier()
        self.policy = self.repository.get_policy()

    def tearDown(self) -> None:
        self.repository.close()

    def add_candidate(self, candidate_id: str, model: str, version: Optional[str]) -> None:
        filename = "{}_{}.bin".format(model, version or "unknown")
        self.repository.upsert_firmware_candidates(({
            "candidate_id": candidate_id, "source_id": "fixture",
            "vendor": "TP-Link", "product": model, "model": model,
            "firmware_version": version, "filename": filename,
            "download_url": "https://example.test/{}".format(filename),
            "source_page_url": "https://example.test/catalog",
            "evidence_url": "https://example.test/catalog",
        },))

    def add_vulnerability(self, identifier: str, claim: dict) -> None:
        base = demo_records()[0]
        record = replace(
            base, identifier=identifier, source_identifier=identifier,
            vendor="TP-Link", product="TL-WR1043ND firmware",
            affected_products=(claim,), cpes=(claim["criteria"],),
        )
        self.repository.upsert(
            record, self.classifier.classify(record, self.policy)
        )

    def test_extracts_declared_and_filename_versions_with_evidence(self) -> None:
        versions = extract_candidate_versions(
            "DIR850LA1_FW106KRb02.bin", "1.06KRb02"
        )

        self.assertEqual("1.06krb02", versions[0]["normalized"])
        self.assertEqual("declared", versions[0]["source"])
        self.assertIn(
            "1.06krb02",
            {item["normalized"] for item in versions},
        )

    def test_links_exact_version_and_exposes_match_basis(self) -> None:
        self.add_candidate("fixture:exact", "TL-WR1043ND", "3.00")
        self.add_candidate("fixture:other", "TL-WR1043ND", "4.00")
        self.add_vulnerability("CVE-2026-10001", {
            "criteria": "cpe:2.3:o:tp-link:tl-wr1043nd_firmware:3.00:*:*:*:*:*:*:*",
            "vulnerable": True,
        })

        result = FirmwareVersionLinker(self.repository).rebuild()
        linked = self.repository.firmware_candidates_for_vulnerability(
            "CVE-2026-10001"
        )

        self.assertEqual(1, result["exact_version"])
        self.assertEqual(["fixture:exact"], [item["candidate_id"] for item in linked["items"]])
        self.assertEqual("exact_version", linked["items"][0]["match_method"])
        self.assertEqual("3.00", linked["items"][0]["candidate_version"])
        self.assertEqual(98, linked["items"][0]["match_score"])

    def test_links_only_versions_inside_affected_range(self) -> None:
        self.add_candidate("fixture:inside", "TL-WR1043ND", "1.9.5")
        self.add_candidate("fixture:fixed", "TL-WR1043ND", "2.0.0")
        self.add_vulnerability("CVE-2026-10002", {
            "criteria": "cpe:2.3:o:tp-link:tl-wr1043nd_firmware:*:*:*:*:*:*:*:*",
            "vulnerable": True,
            "version_start_including": "1.5.0",
            "version_end_excluding": "2.0.0",
        })

        result = FirmwareVersionLinker(self.repository).rebuild()
        linked = self.repository.firmware_candidates_for_vulnerability(
            "CVE-2026-10002"
        )

        self.assertEqual(1, result["version_range"])
        self.assertEqual(["fixture:inside"], [item["candidate_id"] for item in linked["items"]])
        self.assertEqual("[1.5.0, 2.0.0)", linked["items"][0]["affected_constraint"])

    def test_marks_unbounded_claim_as_product_scope_not_version_match(self) -> None:
        self.add_candidate("fixture:scope", "TL-WR1043ND", "3.00")
        self.add_vulnerability("CVE-2026-10003", {
            "criteria": "cpe:2.3:o:tp-link:tl-wr1043nd_firmware:*:*:*:*:*:*:*:*",
            "vulnerable": True,
        })

        result = FirmwareVersionLinker(self.repository).rebuild()
        linked = self.repository.firmware_candidates_for_vulnerability(
            "CVE-2026-10003"
        )

        self.assertEqual(1, result["product_scope"])
        self.assertEqual("product_scope", linked["items"][0]["match_method"])
        self.assertEqual("low", linked["items"][0]["confidence"])

    def test_does_not_compare_date_boundary_with_dotted_release_version(self) -> None:
        self.add_candidate("fixture:dated", "TL-WR1043ND", "3.13.9")
        self.add_vulnerability("CVE-2026-10004", {
            "criteria": "cpe:2.3:o:tp-link:tl-wr1043nd_firmware:*:*:*:*:*:*:*:*",
            "vulnerable": True,
            "version_end_including": "250908",
        })

        result = FirmwareVersionLinker(self.repository).rebuild()

        self.assertEqual(0, result["version_range"])
        self.assertEqual(
            0,
            self.repository.firmware_candidates_for_vulnerability(
                "CVE-2026-10004"
            )["total"],
        )

    def test_preserves_named_version_scheme_for_range_comparison(self) -> None:
        self.add_candidate("fixture:quts", "TL-WR1043ND", "h4.5.1.1592")
        self.add_vulnerability("CVE-2026-10005", {
            "criteria": "cpe:2.3:o:tp-link:tl-wr1043nd_firmware:*:*:*:*:*:*:*:*",
            "vulnerable": True,
            "version_end_including": "h4.5.1.1592",
        })

        result = FirmwareVersionLinker(self.repository).rebuild()
        linked = self.repository.firmware_candidates_for_vulnerability(
            "CVE-2026-10005"
        )

        self.assertEqual(1, result["version_range"])
        self.assertEqual("h4.5.1.1592", linked["items"][0]["candidate_version"])


if __name__ == "__main__":
    unittest.main()
