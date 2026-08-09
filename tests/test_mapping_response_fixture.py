import hashlib
import unittest

from firmatlas.mapping import (
    CoverageStatus,
    ResponseFixtureBindingStatus,
    SourceArtifactEntry,
    discover_response_fixture,
)


class ResponseFixtureProducerContractTests(unittest.TestCase):
    def test_goform_json_fixture_publishes_response_field_paths_without_handler_claim(self):
        content = b'''{
  "dlnaEn": "1",
  "deviceName": "Tenda",
  "deviceList": [{
    "deviceName": "disk",
    "diskList": [{"fileName": "usb", "hasChildFile": "true"}]
  }],
  "scanList": ["usb/media"]
}'''
        source = SourceArtifactEntry(
            "webroot_ro/goform/GetDlnaCfg.txt",
            "webroot_ro/goform/GetDlnaCfg.txt",
            "file",
            len(content),
            hashlib.sha256(content).hexdigest(),
        )

        result = discover_response_fixture(source, content)

        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual("goform/GetDlnaCfg", result.endpoint_clue)
        self.assertEqual(
            ResponseFixtureBindingStatus.FIXTURE_DECLARED,
            result.binding_status,
        )
        self.assertEqual(
            [
                "/deviceList",
                "/deviceList/*/deviceName",
                "/deviceList/*/diskList",
                "/deviceList/*/diskList/*/fileName",
                "/deviceList/*/diskList/*/hasChildFile",
                "/deviceName",
                "/dlnaEn",
                "/scanList",
            ],
            [item.json_pointer for item in result.fields],
        )
        self.assertEqual(
            {"observes_fixture_endpoint", "observes_response_field"},
            {item.capability for item in result.evidence_atoms},
        )
        self.assertTrue(all(item.confidence < 1.0 for item in result.evidence_atoms))
        self.assertIn(
            "response fixture does not prove runtime route registration",
            result.open_obligation,
        )

    def test_non_goform_file_is_not_applicable(self):
        content = b'{"name":"value"}'
        source = SourceArtifactEntry(
            "etc/example.txt", "etc/example.txt", "file", len(content),
            hashlib.sha256(content).hexdigest(),
        )

        result = discover_response_fixture(source, content)

        self.assertEqual(CoverageStatus.NOT_APPLICABLE, result.coverage_status)
        self.assertEqual((), result.fields)


if __name__ == "__main__":
    unittest.main()
