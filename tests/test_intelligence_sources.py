import unittest
from datetime import datetime, timezone

from firmatlas.intelligence.sources import NvdSource, normalize_cisa_kev, normalize_nvd


class RecordingTransport:
    def __init__(self):
        self.calls = []

    def get_json(self, url, params=None, headers=None):
        self.calls.append((url, params, headers))
        return {"vulnerabilities": [], "totalResults": 0}


class SourceNormalizationTests(unittest.TestCase):
    def test_nvd_splits_large_increment_into_bounded_windows(self) -> None:
        transport = RecordingTransport()
        source = NvdSource(
            transport=transport, api_key="test", window_hours=12, min_interval=0
        )

        records = list(
            source.fetch_modified(
                datetime(2026, 8, 4, tzinfo=timezone.utc),
                datetime(2026, 8, 5, tzinfo=timezone.utc),
            )
        )

        self.assertEqual([], records)
        self.assertEqual(2, len(transport.calls))
        self.assertIn("T12:00:00.000Z", transport.calls[0][1]["lastModEndDate"])

    def test_normalizes_nvd_record_and_nested_cpe(self) -> None:
        item = {
            "id": "CVE-2026-1000",
            "published": "2026-08-01T00:00:00Z",
            "lastModified": "2026-08-02T00:00:00Z",
            "descriptions": [
                {"lang": "en", "value": "Router firmware command injection."}
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "type": "Primary",
                        "cvssData": {
                            "version": "3.1",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N",
                        },
                    }
                ]
            },
            "weaknesses": [
                {"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-78"}]}
            ],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "criteria": "cpe:2.3:h:acme:router_x:*:*:*:*:*:*:*:*",
                                    "vulnerable": True,
                                    "versionEndExcluding": "2.0"
                                }
                            ]
                        }
                    ]
                }
            ],
            "references": [
                {"url": "https://vendor.example/firmware/advisory", "source": "nvd", "tags": ["Vendor Advisory"]},
                {"url": "https://example.org/poc", "source": "researcher", "tags": ["Exploit"]},
            ],
        }

        normalized = normalize_nvd(item)

        self.assertEqual("acme", normalized.vendor)
        self.assertEqual("router x", normalized.product)
        self.assertEqual(9.8, normalized.cvss_score)
        self.assertEqual(("CWE-78",), normalized.cwes)
        self.assertEqual("3.1", normalized.cvss_version)
        self.assertEqual(("https://example.org/poc",), normalized.exploit_references)
        self.assertEqual("2.0", normalized.affected_products[0]["version_end_excluding"])
        self.assertEqual("nvd@nist.gov", normalized.cwe_details[0]["source"])

    def test_normalizes_new_nvd_affected_vendor_shape(self) -> None:
        normalized = normalize_nvd(
            {
                "id": "CVE-2026-1001",
                "descriptions": [{"lang": "en", "value": "Device issue."}],
                "affected": [
                    {
                        "source": "vendor.example",
                        "affectedData": [
                            {
                                "vendor": "Acme Devices",
                                "product": "Edge Gateway",
                                "cpes": ["cpe:/h:acme:edge_gateway"],
                            }
                        ],
                    }
                ],
            }
        )

        self.assertEqual("Acme Devices", normalized.vendor)
        self.assertEqual("Edge Gateway", normalized.product)
        self.assertEqual(("cpe:/h:acme:edge_gateway",), normalized.cpes)

    def test_nvd_placeholder_identity_falls_back_to_cpe_identity(self) -> None:
        normalized = normalize_nvd(
            {
                "id": "CVE-2018-16119",
                "descriptions": [{
                    "lang": "en",
                    "value": "Stack overflow in TP-Link WR1043nd firmware version 3.",
                }],
                "affected": [{
                    "affectedData": [{"vendor": "n/a", "product": "n/a"}],
                }],
                "configurations": [{
                    "nodes": [{
                        "cpeMatch": [{
                            "criteria": "cpe:2.3:o:tp-link:tl-wr1043nd_firmware:3.00:*:*:*:*:*:*:*",
                            "vulnerable": True,
                        }],
                    }],
                }],
            }
        )

        self.assertEqual("TP-Link", normalized.vendor)
        self.assertEqual("tl-wr1043nd firmware", normalized.product)
        self.assertNotIn("n/a", normalized.title.lower())

    def test_normalizes_cisa_kev_enrichment(self) -> None:
        normalized = normalize_cisa_kev(
            {
                "cveID": "CVE-2026-1000",
                "vendorProject": "Acme",
                "product": "Router X",
                "vulnerabilityName": "Acme Router Flaw",
                "shortDescription": "Router firmware is affected.",
                "dateAdded": "2026-08-03",
                "dueDate": "2026-08-24",
                "knownRansomwareCampaignUse": "Known",
                "requiredAction": "Apply updates.",
                "cwes": ["CWE-78"],
            },
            "2026-08-04T00:00:00Z",
        )

        self.assertTrue(normalized.kev)
        self.assertEqual("Known", normalized.ransomware_use)
        self.assertEqual("2026-08-24", normalized.kev_due_date)


if __name__ == "__main__":
    unittest.main()
