import json
from pathlib import Path
import unittest

from firmatlas.mapping import (
    CorrelationObligation,
    CoverageStatus,
    ObligationStatus,
    SchedulerAnalyzer,
    SchedulerDisposition,
    SchedulerObligation,
    SchedulerOutcome,
    SchedulerPolicy,
    SchedulerTermination,
    normalize_scheduler_obligations,
    run_obligation_scheduler,
)


def obligation(identity="o1", priority=50, analyzers=("a",), capability="binds_handler"):
    return SchedulerObligation(
        obligation_id=identity,
        target_ref="target:" + identity,
        required_capability=capability,
        reason="missing " + capability,
        priority=priority,
        candidate_analyzers=analyzers,
        status=ObligationStatus.OPEN,
    )


class ObligationSchedulerContractTests(unittest.TestCase):
    def test_correlation_obligations_normalize_without_losing_identity(self):
        item = CorrelationObligation(
            obligation_id="corr:1", target_ref="assoc:1",
            target_kind="candidate_association",
            required_capability="registers_route", reason="candidate only",
            candidate_analyzers=("native-deep", "runtime"), priority=90,
        )
        result = normalize_scheduler_obligations((item,))
        self.assertEqual(1, len(result))
        self.assertEqual("corr:1", result[0].obligation_id)
        self.assertEqual(ObligationStatus.OPEN, result[0].status)

    def test_priority_then_identity_controls_deterministic_attempt_order(self):
        seen = []
        def analyze(item):
            seen.append(item.obligation_id)
            return SchedulerOutcome(SchedulerDisposition.RESOLVED)

        result = run_obligation_scheduler(
            (obligation("low", 10), obligation("z", 90), obligation("a", 90)),
            (SchedulerAnalyzer("a", analyze),),
        )
        self.assertEqual(["a", "z", "low"], seen)
        self.assertEqual(SchedulerTermination.FIXED_POINT, result.termination)
        self.assertEqual(3, len(result.resolved_obligations))

    def test_no_available_analyzer_is_a_fixed_point_with_open_work(self):
        items = tuple(obligation("o" + str(i), analyzers=("native-deep",)) for i in range(14))
        result = run_obligation_scheduler(items, ())

        self.assertEqual(SchedulerTermination.FIXED_POINT, result.termination)
        self.assertEqual(CoverageStatus.COMPLETED, result.coverage_status)
        self.assertEqual(0, len(result.attempts))
        self.assertEqual(14, len(result.open_obligations))
        self.assertEqual("no_eligible_analyzer", result.diagnostics[0].code)

    def test_resolved_outcome_can_add_a_followup_obligation(self):
        def first(item):
            return SchedulerOutcome(
                SchedulerDisposition.RESOLVED,
                generated_obligations=(obligation("follow", 80, ("second",), "flows_to"),),
                evidence_ids=("evidence:1",),
            )
        def second(item):
            return SchedulerOutcome(SchedulerDisposition.RESOLVED)

        result = run_obligation_scheduler(
            (obligation("start", 90, ("first",), "registers_route"),),
            (SchedulerAnalyzer("second", second), SchedulerAnalyzer("first", first)),
        )
        self.assertEqual(["start", "follow"], [x.obligation_id for x in result.resolved_obligations])
        self.assertEqual(["first", "second"], [x.analyzer for x in result.attempts])
        self.assertEqual(("evidence:1",), result.attempts[0].evidence_ids)

    def test_unchanged_or_failed_analyzer_falls_through_once(self):
        calls = []
        def broken(item):
            calls.append("broken")
            raise RuntimeError("worker unavailable")
        def unchanged(item):
            calls.append("unchanged")
            return SchedulerOutcome(SchedulerDisposition.UNCHANGED)
        def final(item):
            calls.append("final")
            return SchedulerOutcome(SchedulerDisposition.RESOLVED)

        result = run_obligation_scheduler(
            (obligation(analyzers=("broken", "unchanged", "final")),),
            tuple(SchedulerAnalyzer(name, fn) for name, fn in
                  (("final", final), ("broken", broken), ("unchanged", unchanged))),
        )
        self.assertEqual(["broken", "unchanged", "final"], calls)
        self.assertEqual(["failed", "unchanged", "resolved"], [x.status.value for x in result.attempts])
        self.assertEqual("analyzer_failed", result.diagnostics[0].code)

    def test_duplicate_inputs_dedupe_but_conflicting_identity_is_rejected(self):
        item = obligation()
        result = run_obligation_scheduler((item, item), ())
        self.assertEqual(1, len(result.open_obligations))
        conflict = SchedulerObligation(**{**item.__dict__, "reason": "different"})
        with self.assertRaisesRegex(ValueError, "conflicting obligation"):
            run_obligation_scheduler((item, conflict), ())

    def test_step_budget_returns_exact_partial_prefix(self):
        def analyze(item):
            return SchedulerOutcome(SchedulerDisposition.RESOLVED)
        result = run_obligation_scheduler(
            (obligation("a", 90), obligation("b", 80)),
            (SchedulerAnalyzer("a", analyze),), SchedulerPolicy(max_steps=1),
        )
        self.assertEqual(SchedulerTermination.BUDGET_EXHAUSTED, result.termination)
        self.assertEqual(CoverageStatus.PARTIAL, result.coverage_status)
        self.assertEqual(["a"], [x.obligation_id for x in result.resolved_obligations])
        self.assertEqual(["b"], [x.obligation_id for x in result.open_obligations])

    def test_generated_obligation_budget_is_bounded(self):
        def fanout(item):
            return SchedulerOutcome(
                SchedulerDisposition.RESOLVED,
                generated_obligations=(obligation("b"), obligation("c")),
            )
        result = run_obligation_scheduler(
            (obligation("a"),), (SchedulerAnalyzer("a", fanout),),
            SchedulerPolicy(max_obligations=2),
        )
        self.assertEqual(SchedulerTermination.BUDGET_EXHAUSTED, result.termination)
        self.assertEqual(["a", "b"], [x.obligation_id for x in (*result.resolved_obligations, *result.open_obligations)])
        self.assertEqual("obligation_budget_exceeded", result.diagnostics[-1].code)

    def test_initial_obligation_budget_keeps_highest_priority_prefix(self):
        result = run_obligation_scheduler(
            (obligation("low", 1), obligation("high", 99)), (),
            SchedulerPolicy(max_obligations=1),
        )
        self.assertEqual(["high"], [x.obligation_id for x in result.open_obligations])
        self.assertEqual(SchedulerTermination.BUDGET_EXHAUSTED, result.termination)

    def test_conflicting_generated_identity_is_contained_and_falls_through(self):
        original = obligation("same", analyzers=("bad", "good"))
        conflict = SchedulerObligation(**{**original.__dict__, "reason": "conflict"})
        def bad(item):
            return SchedulerOutcome(
                SchedulerDisposition.UNCHANGED, generated_obligations=(conflict,)
            )
        def good(item):
            return SchedulerOutcome(SchedulerDisposition.RESOLVED)
        result = run_obligation_scheduler(
            (original,), (SchedulerAnalyzer("bad", bad), SchedulerAnalyzer("good", good))
        )
        self.assertEqual(["failed", "resolved"], [x.status.value for x in result.attempts])
        self.assertEqual(1, len(result.resolved_obligations))

    def test_resolved_input_is_never_reexecuted(self):
        item = SchedulerObligation(**{**obligation().__dict__, "status": ObligationStatus.RESOLVED})
        result = run_obligation_scheduler(
            (item,), (SchedulerAnalyzer("a", lambda _: (_ for _ in ()).throw(AssertionError())),)
        )
        self.assertEqual((), result.attempts)
        self.assertEqual((item,), result.resolved_obligations)

    def test_output_is_stable_across_input_and_registry_order(self):
        def unchanged(item):
            return SchedulerOutcome(SchedulerDisposition.UNCHANGED)
        items = (obligation("b", analyzers=("x", "y")), obligation("a", analyzers=("x", "y")))
        first = run_obligation_scheduler(items, (SchedulerAnalyzer("x", unchanged), SchedulerAnalyzer("y", unchanged)))
        second = run_obligation_scheduler(tuple(reversed(items)), (SchedulerAnalyzer("y", unchanged), SchedulerAnalyzer("x", unchanged)))
        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertIsInstance(json.dumps(first.to_dict()), str)

    def test_documented_ac9_discover_fixed_point_keeps_all_open_work(self):
        payload = json.loads(Path(
            "docs/firmware-mapping/samples/m1-07-obligation-scheduler-summary.json"
        ).read_text())
        self.assertEqual(14, payload["input"]["obligations"])
        self.assertEqual("fixed_point", payload["result"]["termination"])
        self.assertEqual(0, payload["result"]["resolved_obligations"])
        self.assertEqual(14, payload["result"]["open_obligations"])
        self.assertEqual("no_eligible_analyzer", payload["result"]["diagnostic"])


if __name__ == "__main__":
    unittest.main()
