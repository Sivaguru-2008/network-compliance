"""Field-by-field comparison of a candidate baseline against ground truth.

The whole loop rests on one observation: for any configuration the
deterministic parser can read, its output *is* ground truth. That makes labels
free and exact — no annotation, no sampling error — for every Cisco IOS config
we have. Run the LLM parser over the same file, diff the two baselines, and
every disagreement is a labelled error.

The outcomes below are deliberately not a single "correct / incorrect" bit,
because the ways a parser can disagree are not equally bad:

    WRONG        both parsers decided, and they disagree. The worst outcome:
                 the candidate produced a confident, verifiable-looking answer
                 that is simply false.
    OVERREACH    the candidate decided where ground truth would not. Not always
                 an error — but it claims more than the evidence supports,
                 which is exactly the failure this tool is built to avoid.
    MISSED       the candidate escalated where ground truth decided. Safe, and
                 the designed failure mode; costs coverage, not correctness.
    CORRECT      both decided and agree.
    BOTH_UNKNOWN neither could decide. No signal either way.

Grading these separately is what lets calibration trade coverage for safety
knowingly, instead of optimising one blended accuracy number that hides which
kind of mistake is being made.
"""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..models.baseline import SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation, Origin


class FieldOutcome(str, Enum):
    CORRECT = "correct"
    WRONG = "wrong"
    OVERREACH = "overreach"
    MISSED = "missed"
    BOTH_UNKNOWN = "both_unknown"

    @property
    def is_claim(self) -> bool:
        """Did the candidate assert something? Claims are what precision is measured over."""
        return self in (FieldOutcome.CORRECT, FieldOutcome.WRONG, FieldOutcome.OVERREACH)

    @property
    def is_error(self) -> bool:
        return self in (FieldOutcome.WRONG, FieldOutcome.OVERREACH)


def normalize_value(value: Any) -> Any:
    """Reduce a baseline value to something order- and type-insensitively comparable."""
    if isinstance(value, (list, tuple)):
        items = list(value)
        if items and isinstance(items[0], SnmpCommunity):
            return sorted((c.name.casefold(), (c.access or "").casefold()) for c in items)
        return sorted(str(item).casefold() for item in items)
    if isinstance(value, str):
        return value.casefold()
    return value


def values_agree(truth: Any, candidate: Any) -> bool:
    return normalize_value(truth) == normalize_value(candidate)


class FieldComparison(BaseModel):
    """One field, judged against ground truth."""

    model_config = ConfigDict(frozen=True)

    field: str
    outcome: FieldOutcome
    truth_value: Any = None
    candidate_value: Any = None
    truth_detected: bool
    candidate_detected: bool
    candidate_confidence: float = 0.0
    candidate_origin: Origin = Origin.DETERMINISTIC
    candidate_source_line: Optional[str] = None
    truth_source_line: Optional[str] = None

    @classmethod
    def build(cls, field: str, truth: Observation, candidate: Observation) -> "FieldComparison":
        if truth.detected and candidate.detected:
            outcome = FieldOutcome.CORRECT if values_agree(truth.value, candidate.value) else FieldOutcome.WRONG
        elif candidate.detected:
            outcome = FieldOutcome.OVERREACH
        elif truth.detected:
            outcome = FieldOutcome.MISSED
        else:
            outcome = FieldOutcome.BOTH_UNKNOWN
        return cls(
            field=field,
            outcome=outcome,
            truth_value=_display(truth.value),
            candidate_value=_display(candidate.value),
            truth_detected=truth.detected,
            candidate_detected=candidate.detected,
            candidate_confidence=candidate.confidence if candidate.detected else 0.0,
            candidate_origin=candidate.origin,
            candidate_source_line=candidate.source_line,
            truth_source_line=truth.source_line,
        )


def _display(value: Any) -> Any:
    """JSON-safe rendering of a value for the metrics artifact."""
    if isinstance(value, (list, tuple)):
        items = list(value)
        if items and isinstance(items[0], SnmpCommunity):
            return [f"{c.name}:{c.access or '-'}" for c in items]
        return [str(item) for item in items]
    return value


class BaselineComparison(BaseModel):
    """Every field of one config, candidate versus ground truth."""

    source_file: Optional[str] = None
    source_sha256: Optional[str] = None
    truth_parser: str
    candidate_parser: str
    fields: List[FieldComparison] = Field(default_factory=list)
    candidate_warnings: List[str] = Field(default_factory=list)

    @property
    def errors(self) -> List[FieldComparison]:
        return [f for f in self.fields if f.outcome.is_error]

    def by_outcome(self, outcome: FieldOutcome) -> List[FieldComparison]:
        return [f for f in self.fields if f.outcome is outcome]

    def counts(self) -> Dict[str, int]:
        counts = {outcome.value: 0 for outcome in FieldOutcome}
        for comparison in self.fields:
            counts[comparison.outcome.value] += 1
        return counts


def compare_baselines(
    truth: SecurityBaselineModel,
    candidate: SecurityBaselineModel,
) -> BaselineComparison:
    """Diff two baselines produced from the same configuration."""
    if truth.source_sha256 and candidate.source_sha256 and truth.source_sha256 != candidate.source_sha256:
        raise ValueError(
            "Refusing to compare baselines from different configurations "
            f"({truth.source_sha256[:12]} vs {candidate.source_sha256[:12]})."
        )
    return BaselineComparison(
        source_file=truth.source_file or candidate.source_file,
        source_sha256=truth.source_sha256,
        truth_parser=truth.provenance.parser_name,
        candidate_parser=candidate.provenance.parser_name,
        fields=[
            FieldComparison.build(field, getattr(truth, field), getattr(candidate, field))
            for field in SecurityBaselineModel.observable_fields()
        ],
        candidate_warnings=list(candidate.provenance.warnings),
    )
