"""Compliance rule schema.

Rules are *data*, not code: they are loaded from JSON so a framework can be
swapped (CIS -> NIST 800-53, DISA STIG, an internal policy) without touching
the engine.  A rule never mentions Cisco syntax -- it only refers to fields of
the vendor-neutral ``SecurityBaselineModel`` -- which is what makes the same
rule pack reusable across vendors once their parsers exist.
"""

from enum import Enum
from typing import Annotated, Any, List, Optional, Set, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]


class Operator(str, Enum):
    """The closed vocabulary a rule may use to express a required condition.

    Kept deliberately small and total: every operator must be decidable from a
    single normalized value, so evaluation stays pure and testable.
    """

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    IS_TRUE = "is_true"
    IS_FALSE = "is_false"
    GREATER_THAN = "greater_than"
    GREATER_OR_EQUAL = "greater_or_equal"
    LESS_THAN = "less_than"
    LESS_OR_EQUAL = "less_or_equal"
    IN_SET = "in_set"
    NOT_IN_SET = "not_in_set"
    SUBSET_OF = "subset_of"
    CONTAINS_ANY = "contains_any"
    CONTAINS_NONE = "contains_none"
    IS_EMPTY = "is_empty"
    IS_NOT_EMPTY = "is_not_empty"
    MATCHES_REGEX = "matches_regex"


class LeafCondition(BaseModel):
    """A single assertion about one baseline field."""

    model_config = ConfigDict(extra="forbid")

    field: str = Field(description="Name of a SecurityBaselineModel observable field.")
    select: Optional[str] = Field(
        default=None,
        description="For list-of-object fields, pluck this attribute from each item before comparing.",
    )
    operator: Operator
    value: Any = Field(default=None, description="Right-hand operand; unused by is_true/is_false/is_empty.")
    ignore_case: bool = False


class AllOfCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    all_of: List["Condition"] = Field(min_length=1)


class AnyOfCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    any_of: List["Condition"] = Field(min_length=1)


class NotCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    negate: "Condition" = Field(alias="not")


Condition = Annotated[
    Union[AllOfCondition, AnyOfCondition, NotCondition, LeafCondition],
    Field(union_mode="left_to_right"),
]

AllOfCondition.model_rebuild()
AnyOfCondition.model_rebuild()
NotCondition.model_rebuild()


def referenced_fields(condition: Any) -> Set[str]:
    """Every baseline field a (possibly nested) condition depends on."""
    if isinstance(condition, LeafCondition):
        return {condition.field}
    if isinstance(condition, AllOfCondition):
        return set().union(*(referenced_fields(c) for c in condition.all_of))
    if isinstance(condition, AnyOfCondition):
        return set().union(*(referenced_fields(c) for c in condition.any_of))
    if isinstance(condition, NotCondition):
        return referenced_fields(condition.negate)
    raise TypeError(f"Unsupported condition node: {type(condition)!r}")


class Remediation(BaseModel):
    """What an operator must actually type to fix the finding."""

    model_config = ConfigDict(extra="forbid")

    summary: str
    cli: List[str] = Field(default_factory=list, description="Vendor CLI lines, in order, as given by the benchmark.")


class ComplianceRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    control_ref: Optional[str] = Field(default=None, description="Clause number within the framework, e.g. '1.2.2'.")
    title: str
    description: str
    framework: str = "CIS"
    severity: Severity
    baseline_fields: List[str] = Field(
        default_factory=list,
        description="Baseline fields this rule reads. Auto-derived if omitted; validated if supplied.",
    )
    condition: Condition = Field(description="The condition that must hold for the control to PASS.")
    rationale: Optional[str] = None
    remediation: Remediation
    references: List[str] = Field(default_factory=list)
    notes: Optional[str] = None

    @model_validator(mode="after")
    def _sync_declared_fields(self) -> "ComplianceRule":
        """Keep the human-readable field list honest against the machine-read condition."""
        derived = referenced_fields(self.condition)
        if not self.baseline_fields:
            object.__setattr__(self, "baseline_fields", sorted(derived))
        elif set(self.baseline_fields) != derived:
            raise ValueError(
                f"Rule {self.id}: declared baseline_fields {sorted(self.baseline_fields)} "
                f"do not match fields used in condition {sorted(derived)}"
            )
        return self


class Platform(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vendor: str
    os_family: str


class RuleSet(BaseModel):
    """A loaded rule pack: one framework, one platform family, N rules."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str
    framework: str
    framework_version: str
    platform: Platform
    source_note: Optional[str] = None
    rules: List[ComplianceRule] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_ids(self) -> "RuleSet":
        seen = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"Duplicate rule id in rule pack: {rule.id}")
            seen.add(rule.id)
        return self

    def by_id(self, rule_id: str) -> ComplianceRule:
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        raise KeyError(rule_id)
