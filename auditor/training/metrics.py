"""Scoring: what the diffs add up to.

Three views, because they answer different questions:

* **Per-field metrics** — where is the candidate parser weak? Precision is
  measured over *claims* (what it actually asserted), not over all fields, so a
  parser cannot inflate its score by escalating everything.
* **Calibration** — when it says 0.8, is it right 80% of the time? An
  uncalibrated confidence is worse than no confidence, because every threshold
  downstream is set against it.
* **Verdict impact** — the only view that matters to an auditor. A field error
  that never changes a control's verdict is cheap; one that turns a FAIL into a
  PASS hands someone a clean bill of health for a vulnerable device. Those are
  counted separately and never averaged away.
"""

from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..models.result import ControlResult, Status
from .comparison import BaselineComparison, FieldComparison, FieldOutcome


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


class FieldMetrics(BaseModel):
    """How one baseline field performed across the corpus."""

    model_config = ConfigDict(frozen=True)

    field: str
    correct: int = 0
    wrong: int = 0
    overreach: int = 0
    missed: int = 0
    both_unknown: int = 0

    @property
    def claims(self) -> int:
        """Times the candidate asserted a value."""
        return self.correct + self.wrong + self.overreach

    @property
    def truth_decided(self) -> int:
        return self.correct + self.wrong + self.missed

    @property
    def precision(self) -> float:
        """Of what it claimed, how much was right. Overreach counts against it."""
        return _ratio(self.correct, self.claims)

    @property
    def coverage(self) -> float:
        """Of what ground truth could establish, how much did it also establish."""
        return _ratio(self.correct + self.wrong, self.truth_decided)

    @property
    def wrong_rate(self) -> float:
        return _ratio(self.wrong, self.claims)

    def to_row(self) -> Dict[str, object]:
        return {
            "field": self.field,
            "claims": self.claims,
            "correct": self.correct,
            "wrong": self.wrong,
            "overreach": self.overreach,
            "missed": self.missed,
            "precision": self.precision,
            "coverage": self.coverage,
        }

    @classmethod
    def from_comparisons(cls, field: str, comparisons: List[FieldComparison]) -> "FieldMetrics":
        counts = {outcome: 0 for outcome in FieldOutcome}
        for comparison in comparisons:
            counts[comparison.outcome] += 1
        return cls(
            field=field,
            correct=counts[FieldOutcome.CORRECT],
            wrong=counts[FieldOutcome.WRONG],
            overreach=counts[FieldOutcome.OVERREACH],
            missed=counts[FieldOutcome.MISSED],
            both_unknown=counts[FieldOutcome.BOTH_UNKNOWN],
        )


class CalibrationBin(BaseModel):
    model_config = ConfigDict(frozen=True)

    lower: float
    upper: float
    claims: int
    correct: int

    @property
    def observed_accuracy(self) -> float:
        return _ratio(self.correct, self.claims)

    @property
    def midpoint(self) -> float:
        return round((self.lower + self.upper) / 2, 3)

    @property
    def gap(self) -> float:
        """Positive means over-confident: it promised more than it delivered."""
        return round(self.midpoint - self.observed_accuracy, 4) if self.claims else 0.0


class Calibration(BaseModel):
    bins: List[CalibrationBin] = Field(default_factory=list)
    expected_calibration_error: float = 0.0
    overconfident: bool = False

    @classmethod
    def from_claims(cls, claims: List[FieldComparison], bin_count: int = 5) -> "Calibration":
        """Bucket claims by stated confidence and compare against observed accuracy."""
        graded = [c for c in claims if c.outcome.is_claim]
        edges = [i / bin_count for i in range(bin_count + 1)]
        bins: List[CalibrationBin] = []
        total = len(graded)
        error = 0.0

        for lower, upper in zip(edges, edges[1:]):
            in_bin = [
                c
                for c in graded
                if lower <= c.candidate_confidence < upper
                or (upper == 1.0 and c.candidate_confidence == 1.0)
            ]
            if not in_bin:
                continue
            correct = sum(1 for c in in_bin if c.outcome is FieldOutcome.CORRECT)
            calibration_bin = CalibrationBin(lower=lower, upper=upper, claims=len(in_bin), correct=correct)
            bins.append(calibration_bin)
            error += (len(in_bin) / total) * abs(calibration_bin.gap)

        return cls(
            bins=bins,
            expected_calibration_error=round(error, 4),
            overconfident=any(b.gap > 0.1 for b in bins),
        )


class VerdictImpact(BaseModel):
    """What the field errors did to actual control verdicts.

    ``dangerous_flips`` is the number the loop exists to drive to zero: a
    control that ground truth failed or escalated, which the candidate passed.
    """

    total: int = 0
    agreements: int = 0
    dangerous_flips: int = 0
    false_alarms: int = 0
    lost_coverage: int = 0
    transitions: Dict[str, int] = Field(default_factory=dict)
    dangerous_examples: List[str] = Field(default_factory=list)

    @property
    def agreement_rate(self) -> float:
        return _ratio(self.agreements, self.total)

    @classmethod
    def from_results(
        cls,
        truth: List[ControlResult],
        candidate: List[ControlResult],
        source_file: Optional[str] = None,
    ) -> "VerdictImpact":
        candidate_by_id = {result.rule_id: result for result in candidate}
        impact = cls()
        transitions: Dict[str, int] = {}
        examples: List[str] = []

        for truth_result in truth:
            other = candidate_by_id.get(truth_result.rule_id)
            if other is None:
                continue
            impact.total += 1
            key = f"{truth_result.status.value}->{other.status.value}"
            transitions[key] = transitions.get(key, 0) + 1

            if truth_result.status is other.status:
                impact.agreements += 1
                continue
            if other.status is Status.PASS:
                impact.dangerous_flips += 1
                examples.append(f"{source_file or '?'}: {truth_result.rule_id} {key}")
            elif truth_result.status is Status.PASS and other.status is Status.FAIL:
                impact.false_alarms += 1
            elif other.status is Status.NEEDS_REVIEW:
                impact.lost_coverage += 1

        return impact.model_copy(update={"transitions": transitions, "dangerous_examples": examples})

    def merged_with(self, other: "VerdictImpact") -> "VerdictImpact":
        transitions = dict(self.transitions)
        for key, count in other.transitions.items():
            transitions[key] = transitions.get(key, 0) + count
        return VerdictImpact(
            total=self.total + other.total,
            agreements=self.agreements + other.agreements,
            dangerous_flips=self.dangerous_flips + other.dangerous_flips,
            false_alarms=self.false_alarms + other.false_alarms,
            lost_coverage=self.lost_coverage + other.lost_coverage,
            transitions=transitions,
            dangerous_examples=(self.dangerous_examples + other.dangerous_examples)[:20],
        )


class RunMetrics(BaseModel):
    """Everything one loop run measured."""

    configs_scored: int = 0
    fields_compared: int = 0
    per_field: List[FieldMetrics] = Field(default_factory=list)
    calibration: Calibration = Field(default_factory=Calibration)
    verdict_impact: VerdictImpact = Field(default_factory=VerdictImpact)
    ungrounded_claims_rejected: int = 0

    @property
    def overall_precision(self) -> float:
        claims = sum(m.claims for m in self.per_field)
        correct = sum(m.correct for m in self.per_field)
        return _ratio(correct, claims)

    @property
    def overall_coverage(self) -> float:
        decided = sum(m.truth_decided for m in self.per_field)
        established = sum(m.correct + m.wrong for m in self.per_field)
        return _ratio(established, decided)

    @property
    def weakest_fields(self) -> List[FieldMetrics]:
        """Fields with at least one error, worst precision first."""
        offenders = [m for m in self.per_field if m.wrong or m.overreach]
        return sorted(offenders, key=lambda m: (m.precision, -m.wrong))

    @classmethod
    def from_comparisons(
        cls,
        comparisons: List[BaselineComparison],
        verdict_impact: Optional[VerdictImpact] = None,
    ) -> "RunMetrics":
        by_field: Dict[str, List[FieldComparison]] = {}
        all_fields: List[FieldComparison] = []
        for comparison in comparisons:
            for field_comparison in comparison.fields:
                by_field.setdefault(field_comparison.field, []).append(field_comparison)
                all_fields.append(field_comparison)

        rejected = sum(
            1
            for comparison in comparisons
            for warning in comparison.candidate_warnings
            if "ungrounded" in warning.lower()
        )
        return cls(
            configs_scored=len(comparisons),
            fields_compared=len(all_fields),
            per_field=[FieldMetrics.from_comparisons(name, items) for name, items in sorted(by_field.items())],
            calibration=Calibration.from_claims(all_fields),
            verdict_impact=verdict_impact or VerdictImpact(),
            ungrounded_claims_rejected=rejected,
        )
