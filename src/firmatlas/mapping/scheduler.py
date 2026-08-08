"""Deterministic, bounded scheduling of unresolved mapping obligations."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from enum import Enum
from typing import Callable, Optional, Tuple

from .correlation import CorrelationObligation
from .domain import CoverageStatus, ObligationStatus, UnresolvedObligation


SCHEDULER_RESULT_SCHEMA_VERSION = "firmatlas.mapping.scheduler-result/v1alpha1"


class SchedulerDisposition(str, Enum):
    RESOLVED = "resolved"
    UNCHANGED = "unchanged"


class SchedulerAttemptStatus(str, Enum):
    RESOLVED = "resolved"
    UNCHANGED = "unchanged"
    FAILED = "failed"


class SchedulerTermination(str, Enum):
    FIXED_POINT = "fixed_point"
    BUDGET_EXHAUSTED = "budget_exhausted"


@dataclass(frozen=True)
class SchedulerPolicy:
    max_steps: int = 100_000
    max_obligations: int = 100_000

    def __post_init__(self) -> None:
        if self.max_steps <= 0 or self.max_obligations <= 0:
            raise ValueError("scheduler budgets must be positive")


@dataclass(frozen=True)
class SchedulerObligation:
    obligation_id: str
    target_ref: str
    required_capability: str
    reason: str
    priority: int
    candidate_analyzers: Tuple[str, ...]
    status: ObligationStatus = ObligationStatus.OPEN

    def __post_init__(self) -> None:
        for label, value in (
            ("obligation_id", self.obligation_id),
            ("target_ref", self.target_ref),
            ("required_capability", self.required_capability),
            ("reason", self.reason),
        ):
            if not value.strip():
                raise ValueError("{} must not be empty".format(label))
        if not 0 <= self.priority <= 100:
            raise ValueError("scheduler obligation priority must be 0..100")
        if len(self.candidate_analyzers) != len(set(self.candidate_analyzers)):
            raise ValueError("duplicate candidate analyzer")
        if any(not value.strip() for value in self.candidate_analyzers):
            raise ValueError("candidate analyzer must not be empty")


@dataclass(frozen=True)
class SchedulerOutcome:
    disposition: SchedulerDisposition
    generated_obligations: Tuple[SchedulerObligation, ...] = ()
    evidence_ids: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.disposition, SchedulerDisposition):
            raise ValueError("scheduler outcome requires a valid disposition")


@dataclass(frozen=True)
class SchedulerAnalyzer:
    name: str
    analyze: Callable[[SchedulerObligation], SchedulerOutcome]

    def __post_init__(self) -> None:
        if not self.name.strip() or not callable(self.analyze):
            raise ValueError("scheduler analyzer requires a name and callable")


@dataclass(frozen=True)
class SchedulerAttempt:
    step: int
    obligation_id: str
    analyzer: str
    status: SchedulerAttemptStatus
    generated_obligation_ids: Tuple[str, ...]
    evidence_ids: Tuple[str, ...]
    diagnostic: Optional[str] = None


@dataclass(frozen=True)
class SchedulerDiagnostic:
    code: str
    message: str
    obligation_id: Optional[str] = None
    analyzer: Optional[str] = None


@dataclass(frozen=True)
class ObligationSchedulerResult:
    termination: SchedulerTermination
    coverage_status: CoverageStatus
    attempts: Tuple[SchedulerAttempt, ...]
    resolved_obligations: Tuple[SchedulerObligation, ...]
    open_obligations: Tuple[SchedulerObligation, ...]
    diagnostics: Tuple[SchedulerDiagnostic, ...] = ()
    schema_version: str = SCHEDULER_RESULT_SCHEMA_VERSION

    def to_dict(self) -> dict:
        def obligation(value: SchedulerObligation) -> dict:
            return {**asdict(value), "status": value.status.value}

        return {
            "schema_version": self.schema_version,
            "termination": self.termination.value,
            "coverage_status": self.coverage_status.value,
            "attempts": [
                {**asdict(value), "status": value.status.value}
                for value in self.attempts
            ],
            "resolved_obligations": [obligation(x) for x in self.resolved_obligations],
            "open_obligations": [obligation(x) for x in self.open_obligations],
            "diagnostics": [asdict(x) for x in self.diagnostics],
        }


def normalize_scheduler_obligations(values: tuple) -> Tuple[SchedulerObligation, ...]:
    """Normalize public obligation contracts and reject identity collisions."""

    normalized = {}
    for value in values:
        if isinstance(value, SchedulerObligation):
            item = value
        elif isinstance(value, UnresolvedObligation):
            item = SchedulerObligation(
                value.obligation_id, value.target_ref, value.required_capability,
                value.reason, value.priority, value.candidate_analyzers, value.status,
            )
        elif isinstance(value, CorrelationObligation):
            item = SchedulerObligation(
                value.obligation_id, value.target_ref, value.required_capability,
                value.reason, value.priority, value.candidate_analyzers,
                ObligationStatus.OPEN,
            )
        else:
            raise TypeError("unsupported obligation contract")
        existing = normalized.get(item.obligation_id)
        if existing is not None and existing != item:
            raise ValueError("conflicting obligation identity: {}".format(item.obligation_id))
        normalized[item.obligation_id] = item
    return tuple(sorted(normalized.values(), key=lambda x: x.obligation_id))


def _queue_key(value: SchedulerObligation) -> tuple:
    return (-value.priority, value.obligation_id)


def _next_attempt(obligations: dict, analyzers: dict, attempted: set):
    for item in sorted(
        (value for value in obligations.values() if value.status is ObligationStatus.OPEN),
        key=_queue_key,
    ):
        for analyzer_name in item.candidate_analyzers:
            if analyzer_name in analyzers and (item.obligation_id, analyzer_name) not in attempted:
                return item, analyzers[analyzer_name]
    return None


def run_obligation_scheduler(
    initial_obligations: tuple,
    analyzers: Tuple[SchedulerAnalyzer, ...],
    policy: SchedulerPolicy = SchedulerPolicy(),
) -> ObligationSchedulerResult:
    """Run each eligible obligation/analyzer pair at most once to a bounded fixed point."""

    registry = {}
    for analyzer in analyzers:
        existing = registry.get(analyzer.name)
        if existing is not None and existing != analyzer:
            raise ValueError("conflicting analyzer identity: {}".format(analyzer.name))
        registry[analyzer.name] = analyzer
    initial = normalize_scheduler_obligations(initial_obligations)
    if len(initial) > policy.max_obligations:
        initial = tuple(sorted(initial, key=_queue_key)[:policy.max_obligations])
        obligation_budget_exceeded = True
    else:
        obligation_budget_exceeded = False
    obligations = {item.obligation_id: item for item in initial}
    resolved_order = [
        item.obligation_id for item in initial if item.status is ObligationStatus.RESOLVED
    ]
    attempted = set()
    attempts = []
    diagnostics = []
    budget_exhausted = obligation_budget_exceeded
    if obligation_budget_exceeded:
        diagnostics.append(SchedulerDiagnostic(
            "obligation_budget_exceeded",
            "initial obligations were truncated at max_obligations",
        ))

    while not budget_exhausted and len(attempts) < policy.max_steps:
        selected = _next_attempt(obligations, registry, attempted)
        if selected is None:
            break
        item, analyzer = selected
        attempted.add((item.obligation_id, analyzer.name))
        step = len(attempts) + 1
        try:
            outcome = analyzer.analyze(item)
            if not isinstance(outcome, SchedulerOutcome):
                raise TypeError("analyzer returned an unsupported outcome")
            generated = normalize_scheduler_obligations(outcome.generated_obligations)
            for generated_item in generated:
                existing = obligations.get(generated_item.obligation_id)
                if existing is not None and existing != generated_item:
                    raise ValueError("conflicting obligation identity: {}".format(
                        generated_item.obligation_id
                    ))
        except Exception as exc:  # analyzer seam: contain worker/provider failures
            message = "{}: {}".format(type(exc).__name__, str(exc))
            attempts.append(SchedulerAttempt(
                step, item.obligation_id, analyzer.name, SchedulerAttemptStatus.FAILED,
                (), (), message,
            ))
            diagnostics.append(SchedulerDiagnostic(
                "analyzer_failed", message, item.obligation_id, analyzer.name,
            ))
            continue

        accepted = []
        for generated_item in generated:
            existing = obligations.get(generated_item.obligation_id)
            if existing is not None:
                continue
            if len(obligations) >= policy.max_obligations:
                budget_exhausted = True
                diagnostics.append(SchedulerDiagnostic(
                    "obligation_budget_exceeded",
                    "generated obligations were truncated at max_obligations",
                    item.obligation_id, analyzer.name,
                ))
                break
            obligations[generated_item.obligation_id] = generated_item
            accepted.append(generated_item.obligation_id)
        if outcome.disposition is SchedulerDisposition.RESOLVED:
            obligations[item.obligation_id] = replace(item, status=ObligationStatus.RESOLVED)
            resolved_order.append(item.obligation_id)
            attempt_status = SchedulerAttemptStatus.RESOLVED
        else:
            attempt_status = SchedulerAttemptStatus.UNCHANGED
        attempts.append(SchedulerAttempt(
            step, item.obligation_id, analyzer.name, attempt_status,
            tuple(accepted), tuple(dict.fromkeys(outcome.evidence_ids)),
        ))

    if not budget_exhausted and len(attempts) >= policy.max_steps:
        if _next_attempt(obligations, registry, attempted) is not None:
            budget_exhausted = True
            diagnostics.append(SchedulerDiagnostic(
                "step_budget_exceeded", "scheduler stopped at max_steps"
            ))
    open_values = tuple(sorted(
        (x for x in obligations.values() if x.status is ObligationStatus.OPEN),
        key=_queue_key,
    ))
    if not budget_exhausted and open_values and _next_attempt(obligations, registry, attempted) is None:
        diagnostics.append(SchedulerDiagnostic(
            "no_eligible_analyzer",
            "open obligations remain but no unattempted eligible analyzer is available",
        ))
    resolved_values = tuple(obligations[identity] for identity in dict.fromkeys(resolved_order))
    return ObligationSchedulerResult(
        SchedulerTermination.BUDGET_EXHAUSTED if budget_exhausted else SchedulerTermination.FIXED_POINT,
        CoverageStatus.PARTIAL if budget_exhausted else CoverageStatus.COMPLETED,
        tuple(attempts), resolved_values, open_values, tuple(diagnostics),
    )
