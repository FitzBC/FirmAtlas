import json
import unittest
from datetime import datetime, timezone

from firmatlas.cli import demo_report
from firmatlas.domain import (
    AnalysisReport,
    AnalysisStatus,
    AnalyzerIdentity,
    ArtifactRef,
)


class ArtifactRefTests(unittest.TestCase):
    def test_rejects_non_canonical_digest(self) -> None:
        with self.assertRaisesRegex(ValueError, "sha256"):
            ArtifactRef(sha256="ABC", size=1)

    def test_rejects_negative_size(self) -> None:
        with self.assertRaisesRegex(ValueError, "size"):
            ArtifactRef(sha256="a" * 64, size=-1)


class AnalysisReportTests(unittest.TestCase):
    def test_demo_report_is_json_serializable_and_evidence_backed(self) -> None:
        report = demo_report()
        encoded = json.dumps(report.to_dict())

        self.assertIn("software-component", encoded)
        self.assertEqual(1, len(report.observations[0].evidence))

    def test_failed_report_requires_diagnostics(self) -> None:
        when = datetime.now(timezone.utc)
        with self.assertRaisesRegex(ValueError, "diagnostics"):
            AnalysisReport(
                run_id="run-1",
                artifact=ArtifactRef(sha256="b" * 64, size=0),
                analyzer=AnalyzerIdentity("unpack", "1", "1"),
                status=AnalysisStatus.FAILED,
                started_at=when,
                finished_at=when,
            )


if __name__ == "__main__":
    unittest.main()
