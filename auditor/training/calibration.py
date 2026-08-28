"""Turning measurements into a policy the parser actually uses.

This is the "feed back" half of the loop. Measurement alone changes nothing;
what changes behaviour is a per-field confidence threshold, fitted to the
evidence and written to a file the LLM parser loads on its next run.

The fit is deliberately one-sided. For each field we take the *lowest*
threshold whose surviving claims still hit the precision target — lowest,
because every point of threshold costs coverage, and coverage is the whole
reason to run a model parser at all. But precision is a hard floor, never
traded: a field that cannot reach the target at any threshold is pinned to
``ALWAYS_ESCALATE`` rather than allowed to answer badly. Escalating a field to
a human is a known cost; a wrong verdict is not.

Small samples are the obvious way to fool this, so a threshold is only fitted
when a field has at least ``min_samples`` claims behind it. Below that the
field keeps the global default and the policy records why.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .comparison import BaselineComparison, FieldComparison, FieldOutcome

#: A threshold no confidence can satisfy: the field always escalates to review.
ALWAYS_ESCALATE = 1.01

_GRID = [round(0.05 * step, 2) for step in range(0, 21)]


class FieldThreshold(BaseModel):
    model_config = ConfigDict(frozen=True)

    field: str
    threshold: float
    precision_at_threshold: float
    claims_kept: int
    claims_total: int
    fitted: bool = Field(description="False when the default was kept for lack of evidence.")
    reason: str

    @property
    def escalates_always(self) -> bool:
        return self.threshold >= ALWAYS_ESCALATE


class ThresholdPolicy(BaseModel):
    """The fitted policy. Serialised to JSON; loaded by LLMParser."""

    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target_precision: float = 0.95
    min_samples: int = 10
    default_threshold: float = 0.6
    corpus_size: int = 0
    fields: List[FieldThreshold] = Field(default_factory=list)

    def as_mapping(self) -> Dict[str, float]:
        """The form the parser consumes: field -> minimum acceptable confidence."""
        return {entry.field: entry.threshold for entry in self.fields if entry.fitted}

    def threshold_for(self, field: str) -> float:
        for entry in self.fields:
            if entry.field == field and entry.fitted:
                return entry.threshold
        return self.default_threshold

    @property
    def escalated_fields(self) -> List[str]:
        return [entry.field for entry in self.fields if entry.escalates_always]


def fit_field_threshold(
    field: str,
    claims: List[FieldComparison],
    *,
    target_precision: float,
    min_samples: int,
    default_threshold: float,
) -> FieldThreshold:
    """Lowest threshold meeting the precision target; escalate if none does."""
    graded = [c for c in claims if c.outcome.is_claim]
    total = len(graded)

    if total < min_samples:
        return FieldThreshold(
            field=field,
            threshold=default_threshold,
            precision_at_threshold=_precision(graded),
            claims_kept=total,
            claims_total=total,
            fitted=False,
            reason=f"only {total} claim(s) observed; need {min_samples} before fitting a threshold",
        )

    for threshold in _GRID:
        kept = [c for c in graded if c.candidate_confidence >= threshold]
        if not kept:
            break
        precision = _precision(kept)
        if precision >= target_precision:
            return FieldThreshold(
                field=field,
                threshold=threshold,
                precision_at_threshold=precision,
                claims_kept=len(kept),
                claims_total=total,
                fitted=True,
                reason=(
                    f"lowest threshold reaching {target_precision:.0%} precision "
                    f"({precision:.0%} on {len(kept)} of {total} claims)"
                ),
            )

    return FieldThreshold(
        field=field,
        threshold=ALWAYS_ESCALATE,
        precision_at_threshold=_precision(graded),
        claims_kept=0,
        claims_total=total,
        fitted=True,
        reason=(
            f"no threshold reached {target_precision:.0%} precision "
            f"(best observed {_precision(graded):.0%}); field always escalates to review"
        ),
    )


def _precision(claims: List[FieldComparison]) -> float:
    if not claims:
        return 0.0
    correct = sum(1 for c in claims if c.outcome is FieldOutcome.CORRECT)
    return round(correct / len(claims), 4)


def fit_policy(
    comparisons: List[BaselineComparison],
    *,
    target_precision: float = 0.95,
    min_samples: int = 10,
    default_threshold: float = 0.6,
    previous: Optional[ThresholdPolicy] = None,
) -> ThresholdPolicy:
    """Fit a per-field threshold policy from a corpus of comparisons."""
    by_field: Dict[str, List[FieldComparison]] = {}
    for comparison in comparisons:
        for field_comparison in comparison.fields:
            by_field.setdefault(field_comparison.field, []).append(field_comparison)

    fitted = [
        fit_field_threshold(
            field,
            claims,
            target_precision=target_precision,
            min_samples=min_samples,
            default_threshold=_carry_forward(previous, field, default_threshold),
        )
        for field, claims in sorted(by_field.items())
    ]
    return ThresholdPolicy(
        target_precision=target_precision,
        min_samples=min_samples,
        default_threshold=default_threshold,
        corpus_size=len(comparisons),
        fields=fitted,
    )


def _carry_forward(previous: Optional[ThresholdPolicy], field: str, fallback: float) -> float:
    """A field with too little new evidence keeps whatever the last run decided.

    Without this, adding one config to the corpus could silently relax a
    threshold that an earlier, larger run had tightened for good reason.
    """
    if previous is None:
        return fallback
    for entry in previous.fields:
        if entry.field == field and entry.fitted:
            return entry.threshold
    return fallback
