"""Condition operators and the three-valued logic the engine runs on.

Ordinary boolean logic cannot express this tool's central requirement: a
control can be satisfied, violated, or *undecidable from the evidence*.  So
conditions evaluate to Kleene three-valued logic instead of ``bool``:

    TRUE    -- the config proves the control is met      -> PASS
    FALSE   -- the config proves the control is violated -> FAIL
    UNKNOWN -- the config proves neither                 -> NEEDS_REVIEW

The combination rules follow from that reading.  For ``all_of``, one proven
violation condemns the control even if other operands are unknown; unknown only
wins when nothing is proven false.  ``any_of`` is the mirror image.  This is
what stops missing evidence from ever being rounded up to PASS.
"""

import re
from dataclasses import dataclass, field as dataclass_field
from enum import Enum
from typing import Any, List, Optional, Sequence

from ..models.observation import Observation
from ..models.rule import (
    AllOfCondition,
    AnyOfCondition,
    LeafCondition,
    NotCondition,
    Operator,
)


class Ternary(Enum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


class RuleEvaluationError(Exception):
    """A rule is malformed or refers to something the baseline does not provide."""


@dataclass
class LeafOutcome:
    """One leaf assertion's result, with the evidence that produced it."""

    ternary: Ternary
    field: str
    observation: Observation
    detail: str


@dataclass
class ConditionOutcome:
    ternary: Ternary
    leaves: List[LeafOutcome] = dataclass_field(default_factory=list)


# ---------------------------------------------------------------------------
# operators
# ---------------------------------------------------------------------------

_NO_OPERAND_REQUIRED = {
    Operator.IS_TRUE,
    Operator.IS_FALSE,
    Operator.IS_EMPTY,
    Operator.IS_NOT_EMPTY,
}


def _fold_case(value: Any) -> Any:
    if isinstance(value, str):
        return value.casefold()
    if isinstance(value, (list, tuple, set)):
        return [_fold_case(item) for item in value]
    return value


def _as_sequence(value: Any, operator: Operator) -> Sequence:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    raise RuleEvaluationError(f"Operator {operator.value!r} requires a list value, got {type(value).__name__}.")


def _as_number(value: Any, operator: Operator) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuleEvaluationError(f"Operator {operator.value!r} requires a numeric value, got {value!r}.")
    return float(value)


def apply_operator(operator: Operator, actual: Any, expected: Any, ignore_case: bool = False) -> bool:
    """Apply one operator to an already-detected value. Pure and total."""
    if operator not in _NO_OPERAND_REQUIRED and expected is None:
        raise RuleEvaluationError(f"Operator {operator.value!r} requires a 'value' operand.")

    if ignore_case:
        actual, expected = _fold_case(actual), _fold_case(expected)

    if operator is Operator.EQUALS:
        return actual == expected
    if operator is Operator.NOT_EQUALS:
        return actual != expected
    if operator is Operator.IS_TRUE:
        return bool(actual)
    if operator is Operator.IS_FALSE:
        return not bool(actual)
    if operator is Operator.GREATER_THAN:
        return _as_number(actual, operator) > _as_number(expected, operator)
    if operator is Operator.GREATER_OR_EQUAL:
        return _as_number(actual, operator) >= _as_number(expected, operator)
    if operator is Operator.LESS_THAN:
        return _as_number(actual, operator) < _as_number(expected, operator)
    if operator is Operator.LESS_OR_EQUAL:
        return _as_number(actual, operator) <= _as_number(expected, operator)
    if operator is Operator.IN_SET:
        return actual in _as_sequence(expected, operator)
    if operator is Operator.NOT_IN_SET:
        return actual not in _as_sequence(expected, operator)
    if operator is Operator.SUBSET_OF:
        return set(_as_sequence(actual, operator)).issubset(set(_as_sequence(expected, operator)))
    if operator is Operator.CONTAINS_ANY:
        return bool(set(_as_sequence(actual, operator)) & set(_as_sequence(expected, operator)))
    if operator is Operator.CONTAINS_NONE:
        return not (set(_as_sequence(actual, operator)) & set(_as_sequence(expected, operator)))
    if operator is Operator.IS_EMPTY:
        return len(_as_sequence(actual, operator)) == 0
    if operator is Operator.IS_NOT_EMPTY:
        return len(_as_sequence(actual, operator)) > 0
    if operator is Operator.MATCHES_REGEX:
        flags = re.IGNORECASE if ignore_case else 0
        return bool(re.search(str(expected), str(actual), flags))
    raise RuleEvaluationError(f"Unhandled operator {operator!r}.")


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------


def resolve_observation(baseline: Any, path: str) -> Observation:
    """Look up a baseline field by (optionally dotted) path."""
    target: Any = baseline
    for part in path.split("."):
        if not hasattr(target, part):
            raise RuleEvaluationError(
                f"Baseline has no field {path!r}. Available: {', '.join(baseline.observable_fields())}"
            )
        target = getattr(target, part)
    if not isinstance(target, Observation):
        raise RuleEvaluationError(f"Baseline field {path!r} is not an Observation (got {type(target).__name__}).")
    return target


def _select(value: Any, attribute: Optional[str], field_name: str) -> Any:
    """Pluck ``attribute`` from each item of a list value (e.g. community names)."""
    if attribute is None:
        return value
    items = value or []
    if not isinstance(items, (list, tuple)):
        raise RuleEvaluationError(f"'select' on field {field_name!r} requires a list value.")
    plucked = []
    for item in items:
        if not hasattr(item, attribute):
            raise RuleEvaluationError(f"Items of {field_name!r} have no attribute {attribute!r}.")
        plucked.append(getattr(item, attribute))
    return plucked


def _describe(field: str, select: Optional[str], value: Any, operator: Operator, expected: Any) -> str:
    label = f"{field}.{select}" if select else field
    if operator in _NO_OPERAND_REQUIRED:
        return f"{label}={value!r} (required: {operator.value})"
    return f"{label}={value!r} (required: {operator.value} {expected!r})"


def evaluate_leaf(leaf: LeafCondition, baseline: Any) -> LeafOutcome:
    observation = resolve_observation(baseline, leaf.field)

    if not observation.detected:
        return LeafOutcome(
            ternary=Ternary.UNKNOWN,
            field=leaf.field,
            observation=observation,
            detail=f"{leaf.field}: no conclusive evidence in configuration",
        )

    value = _select(observation.value, leaf.select, leaf.field)
    holds = apply_operator(leaf.operator, value, leaf.value, leaf.ignore_case)
    return LeafOutcome(
        ternary=Ternary.TRUE if holds else Ternary.FALSE,
        field=leaf.field,
        observation=observation,
        detail=_describe(leaf.field, leaf.select, value, leaf.operator, leaf.value),
    )


def evaluate_condition(condition: Any, baseline: Any) -> ConditionOutcome:
    """Evaluate a (possibly nested) condition against a baseline, in Kleene logic."""
    if isinstance(condition, LeafCondition):
        outcome = evaluate_leaf(condition, baseline)
        return ConditionOutcome(ternary=outcome.ternary, leaves=[outcome])

    if isinstance(condition, AllOfCondition):
        results = [evaluate_condition(child, baseline) for child in condition.all_of]
        leaves = [leaf for result in results for leaf in result.leaves]
        states = {result.ternary for result in results}
        if Ternary.FALSE in states:
            return ConditionOutcome(Ternary.FALSE, leaves)
        if Ternary.UNKNOWN in states:
            return ConditionOutcome(Ternary.UNKNOWN, leaves)
        return ConditionOutcome(Ternary.TRUE, leaves)

    if isinstance(condition, AnyOfCondition):
        results = [evaluate_condition(child, baseline) for child in condition.any_of]
        leaves = [leaf for result in results for leaf in result.leaves]
        states = {result.ternary for result in results}
        if Ternary.TRUE in states:
            return ConditionOutcome(Ternary.TRUE, leaves)
        if Ternary.UNKNOWN in states:
            return ConditionOutcome(Ternary.UNKNOWN, leaves)
        return ConditionOutcome(Ternary.FALSE, leaves)

    if isinstance(condition, NotCondition):
        inner = evaluate_condition(condition.negate, baseline)
        flipped = {
            Ternary.TRUE: Ternary.FALSE,
            Ternary.FALSE: Ternary.TRUE,
            Ternary.UNKNOWN: Ternary.UNKNOWN,
        }[inner.ternary]
        return ConditionOutcome(flipped, inner.leaves)

    raise RuleEvaluationError(f"Unsupported condition node: {type(condition).__name__}")
