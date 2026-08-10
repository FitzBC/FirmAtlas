from dataclasses import replace
import unittest

from firmatlas.mapping.discovery_catalog import (
    DiscoveryCandidate,
    DiscoveryCandidateKind,
    DiscoveryClaimStatus,
)
from firmatlas.mapping.historical_coverage_queue import (
    HistoricalCoverageAction,
    HistoricalSemanticClue,
    build_historical_coverage_queue,
)
from firmatlas.mapping.historical_expectation import HistoricalVulnerabilityAudit

from tests.test_mapping_historical_expectation_diff import (
    catalog_with_native_route_only,
)


class HistoricalCoverageQueueTests(unittest.TestCase):
    def audit(self) -> HistoricalVulnerabilityAudit:
        return HistoricalVulnerabilityAudit(
            expectation_diff_id="historical-expectation-diff:" + "1" * 64,
            total_vulnerability_count=5,
            category_counts={
                "compared_interface": 0,
                "parameter_only": 3,
                "no_structured_communication": 1,
                "not_analyzed": 1,
            },
            compared_interface_identifiers=(),
            parameter_only_identifiers=(
                "CVE-2021-42659",
                "CVE-2026-2191",
                "CVE-2026-2192",
            ),
            no_structured_communication_identifiers=("CVE-2025-5900",),
            not_analyzed_identifiers=("CVE-2017-16923",),
            exact_artifact_expectation_count=0,
            exact_artifact_observed_count=0,
        )

    def test_prioritizes_parameter_repair_and_never_promotes_catalog_clue(self):
        base = catalog_with_native_route_only()
        route = replace(
            base.candidates[0],
            candidate_id="native-route:get-ddos",
            canonical_identity="GetDdosDefenceList",
            attributes=(("handler_symbol", "formGetDdosDefenceList"),),
        )
        catalog = replace(base, candidates=(route,))
        clues = (
            HistoricalSemanticClue(
                "CVE-2021-42659",
                "When setting the virtual service, the server exits when the "
                "super-long list parameter occurs.",
                parameters=("occurs",),
                source_refs=("primary:stack4",),
                source_verified_parameters=("list",),
            ),
            HistoricalSemanticClue(
                "CVE-2026-2191",
                "The formGetDdosDefenceList handler reads parameter security.ddos.map.",
                parameters=("security.ddos.map",),
                handler_names=("formGetDdosDefenceList",),
                source_refs=("primary:tenda3",),
            ),
            HistoricalSemanticClue(
                "CVE-2026-2192",
                "formGetRebootTimer reads sys.schedulereboot.start_time/"
                "sys.schedulereboot.end_time.",
                parameters=("sys.schedulereboot.start_time",),
                handler_names=("formGetRebootTimer",),
                source_refs=("primary:tenda4",),
            ),
        )

        queue = build_historical_coverage_queue(self.audit(), clues, catalog)
        entries = {item.vulnerability_identifier: item for item in queue.entries}

        self.assertEqual(
            HistoricalCoverageAction.REPAIR_PARAMETER_EXTRACTION,
            entries["CVE-2021-42659"].action,
        )
        self.assertIn("occurs", entries["CVE-2021-42659"].suspicious_parameters)
        self.assertEqual(
            "source_partial", entries["CVE-2021-42659"].evidence_state.value
        )
        self.assertEqual(
            ("list",), entries["CVE-2021-42659"].source_verified_parameters
        )
        self.assertEqual(
            ("sys.schedulereboot.end_time",),
            entries["CVE-2026-2192"].missing_compound_parameters,
        )
        ddos = entries["CVE-2026-2191"]
        self.assertEqual(
            HistoricalCoverageAction.RESOLVE_HANDLER_TO_ROUTE, ddos.action
        )
        self.assertEqual(("GetDdosDefenceList",), ddos.catalog_route_clues)
        self.assertEqual((), ddos.source_verified_interfaces)
        self.assertIn("catalog_clue_not_historical_fact", ddos.reason_codes)
        self.assertGreater(
            entries["CVE-2021-42659"].priority,
            entries["CVE-2025-5900"].priority,
        )
        self.assertEqual(5, queue.summary["open"])

    def test_primary_source_interface_resolves_route_task_deterministically(self):
        clue = HistoricalSemanticClue(
            "CVE-2026-2191",
            "Handler formGetDdosDefenceList is reached through /goform/GetDdosDefenceList.",
            parameters=("security.ddos.map",),
            handler_names=("formGetDdosDefenceList",),
            source_refs=("primary:tenda3",),
            source_verified_interfaces=("/goform/GetDdosDefenceList",),
        )

        first = build_historical_coverage_queue(self.audit(), (clue,))
        second = build_historical_coverage_queue(self.audit(), (clue,))

        item = next(
            entry for entry in first.entries
            if entry.vulnerability_identifier == "CVE-2026-2191"
        )
        self.assertEqual(HistoricalCoverageAction.VERIFY_SOURCE_EXPECTATION, item.action)
        self.assertEqual("source_verified", item.evidence_state.value)
        self.assertEqual(first.queue_id, second.queue_id)
        self.assertEqual(first.to_dict(), second.to_dict())

    def test_rejects_clues_outside_audit_scope(self):
        with self.assertRaisesRegex(ValueError, "outside audit scope"):
            build_historical_coverage_queue(
                self.audit(),
                (HistoricalSemanticClue("CVE-OTHER", "description"),),
            )

    def test_separates_configuration_keys_from_http_parameters(self):
        clue = HistoricalSemanticClue(
            "CVE-2026-2192",
            "formGetRebootTimer reads sys.schedulereboot.start_time/"
            "sys.schedulereboot.end_time.",
            parameters=("sys.schedulereboot.start_time",),
            handler_names=("formGetRebootTimer",),
            source_refs=("primary:tenda4",),
            parameter_classifications=((
                "sys.schedulereboot.start_time", "configuration_key",
            ),),
            source_verified_route_tokens=("GetSysAutoRebbotCfg",),
        )

        queue = build_historical_coverage_queue(self.audit(), (clue,))
        item = next(
            entry for entry in queue.entries
            if entry.vulnerability_identifier == "CVE-2026-2192"
        )

        self.assertEqual(
            ("sys.schedulereboot.start_time",), item.configuration_keys
        )
        self.assertEqual(item.configuration_keys, item.misclassified_parameters)
        self.assertIn(
            "configuration_key_misclassified_as_request_parameter",
            item.reason_codes,
        )
        self.assertEqual(("GetSysAutoRebbotCfg",), item.source_verified_route_tokens)
        self.assertEqual((), item.source_verified_interfaces)


if __name__ == "__main__":
    unittest.main()
