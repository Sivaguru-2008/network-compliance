"""Evaluation output: one result per control, plus the assembled report."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .baseline import SecurityBaselineModel
from .observation import Observation, Origin
from .rule import ComplianceRule, Remediation, Severity

REPORT_SCHEMA_VERSION = "1.0"


class SourceClassification(str, Enum):
    """How a framework control reference was sourced for this vendor."""

    VERIFIED_FROM_PDF = "VERIFIED_FROM_PDF"
    CONTROL_INTENT = "CONTROL_INTENT"
    GENERIC_MAPPING = "GENERIC_MAPPING"
    UNVERIFIED = "UNVERIFIED"


class Status(str, Enum):
    """Verdicts this tool is allowed to reach.

    ``PASS``: Evidence proves the requirement is satisfied.
    ``FAIL``: Evidence proves the requirement is violated.
    ``NEEDS_REVIEW``: Configuration carried no conclusive evidence either way.
    ``NOT_APPLICABLE``: Control does not apply to this device/scenario.
    ``UNSUPPORTED``: Parser/framework does not evaluate this property.
    ``ERROR``: Auditing pipeline itself failed.
    ``MANUAL_REVIEW``: Control requires human judgment.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNSUPPORTED = "UNSUPPORTED"
    ERROR = "ERROR"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class Evidence(BaseModel):
    """The exact configuration facts a verdict was based on."""

    model_config = ConfigDict(frozen=True)

    field: str
    value: Any = None
    detected: bool
    source_line: Optional[str] = None
    line_number: Optional[int] = None
    origin: Origin = Origin.DETERMINISTIC
    confidence: float = 1.0
    note: Optional[str] = None
    mapping_id: Optional[str] = None
    original_line_number: Optional[int] = None
    original_line: Optional[str] = None
    normalized_value: Any = None

    @classmethod
    def from_observation(cls, field: str, obs: Observation) -> "Evidence":
        return cls(
            field=field,
            value=obs.value,
            detected=obs.detected,
            source_line=obs.source_line,
            line_number=obs.line_number,
            origin=obs.origin,
            confidence=obs.confidence,
            note=obs.note,
            mapping_id=getattr(obs, "mapping_id", None),
            original_line_number=getattr(obs, "original_line_number", None),
            original_line=getattr(obs, "original_line", None),
            normalized_value=getattr(obs, "value", None),
        )

    @property
    def display(self) -> str:
        if self.origin == Origin.LEARNED or self.mapping_id:
            source = f"Administrator-trained mapping #{self.mapping_id or 'unknown'}"
            evidence = f"line {self.original_line_number or self.line_number or '?'}: {self.original_line or self.source_line or ''}"
            return f"{source} (Evidence: {evidence})"
        if self.source_line:
            return f"L{self.line_number}: {self.source_line}" if self.line_number else self.source_line
        if self.detected:
            return f"<absent> {self.note or 'not present in configuration'}"
        return f"<no evidence> {self.note or 'not found in configuration'}"


class ControlResult(BaseModel):
    """The verdict for a single control against a single device."""

    rule_id: str
    control_id: Optional[str] = None
    control_ref: Optional[str] = None
    internal_control_id: Optional[str] = None
    verified_ref: bool = True
    title: str
    description: str
    framework: str
    severity: Severity
    status: Status
    message: str = Field(description="Why this verdict was reached, in one line.")
    evidence: List[Evidence] = Field(default_factory=list)
    remediation: Optional[Remediation] = None
    references: List[str] = Field(default_factory=list)
    device: Optional[str] = None
    vendor: Optional[str] = None
    parser: Optional[str] = None
    knowledge_version: Optional[str] = None
    source_classification: Optional[SourceClassification] = None
    source_reference: Optional[str] = None
    evaluation_result: Optional[str] = None
    reason: Optional[str] = None

    @classmethod
    def build(
        cls,
        rule: ComplianceRule,
        status: Status,
        message: str,
        evidence: List[Evidence],
        *,
        device: Optional[str] = None,
        vendor: Optional[str] = None,
        parser: Optional[str] = None,
    ) -> "ControlResult":
        return cls(
            rule_id=rule.id,
            control_id=rule.id,
            control_ref=rule.control_ref,
            internal_control_id=rule.internal_control_id,
            verified_ref=rule.verified_ref,
            title=rule.title,
            description=rule.description,
            framework=rule.framework,
            severity=rule.severity,
            status=status,
            message=message,
            evidence=evidence,
            remediation=None if status is Status.PASS else rule.remediation,
            references=rule.references,
            device=device,
            vendor=vendor,
            parser=parser,
            source_classification=(
                SourceClassification.VERIFIED_FROM_PDF
                if rule.verified_ref and rule.control_ref
                else SourceClassification.CONTROL_INTENT
                if rule.control_ref
                else SourceClassification.GENERIC_MAPPING
            ),
            knowledge_version=rule.knowledge_version,
            source_reference=rule.control_ref,
            evaluation_result=status.value,
            reason=message,
        )

    @property
    def primary_evidence(self) -> Optional[Evidence]:
        if not self.evidence:
            return None
        wanted = self.status is Status.PASS
        return next((item for item in self.evidence if item.detected is wanted), self.evidence[0])


class ReportSummary(BaseModel):
    total: int = 0
    passed: int = 0
    failed: int = 0
    needs_review: int = 0
    not_applicable: int = 0
    unsupported: int = 0
    error: int = 0
    manual_review: int = 0
    applicable_controls: int = 0
    decidable_controls: int = 0
    undecidable_controls: int = 0
    unsupported_controls: int = 0
    error_controls: int = 0
    decision_coverage: float = Field(
        default=0.0,
        description="decidable_controls / applicable_controls. Percentage of applicable controls with a decided result.",
    )
    failed_by_severity: Dict[str, int] = Field(default_factory=dict)
    needs_review_by_severity: Dict[str, int] = Field(default_factory=dict)
    compliance_score: float = Field(
        default=0.0,
        description="passed / applicable_controls. Raw compliance score over all applicable controls.",
    )
    adjudicated_score: float = Field(
        default=0.0,
        description="passed / decidable_controls. Score calculated strictly from decided (PASS + FAIL) controls.",
    )

    @classmethod
    def from_results(cls, results: List[ControlResult]) -> "ReportSummary":
        passed = [r for r in results if r.status is Status.PASS]
        failed = [r for r in results if r.status is Status.FAIL]
        review = [r for r in results if r.status is Status.NEEDS_REVIEW]
        na = [r for r in results if r.status is Status.NOT_APPLICABLE]
        unsupported = [r for r in results if r.status is Status.UNSUPPORTED]
        error = [r for r in results if r.status is Status.ERROR]
        manual = [r for r in results if r.status is Status.MANUAL_REVIEW]
        total = len(results)
        applicable = total - len(na)
        decidable = len(passed) + len(failed)
        return cls(
            total=total,
            passed=len(passed),
            failed=len(failed),
            needs_review=len(review),
            not_applicable=len(na),
            unsupported=len(unsupported),
            error=len(error),
            manual_review=len(manual),
            applicable_controls=applicable,
            decidable_controls=decidable,
            undecidable_controls=len(review) + len(manual),
            unsupported_controls=len(unsupported),
            error_controls=len(error),
            decision_coverage=round(100.0 * decidable / applicable, 1) if applicable else 0.0,
            failed_by_severity=_count_by_severity(failed),
            needs_review_by_severity=_count_by_severity(review),
            compliance_score=round(100.0 * len(passed) / applicable, 1) if applicable else 0.0,
            adjudicated_score=round(100.0 * len(passed) / decidable, 1) if decidable else 0.0,
        )


def _count_by_severity(results: List[ControlResult]) -> Dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for result in results:
        counts[result.severity.value] += 1
    return {k: v for k, v in counts.items() if v}


class TargetInfo(BaseModel):
    """What was audited, and how it was read."""

    source_file: Optional[str] = None
    source_sha256: Optional[str] = None
    hostname: Optional[str] = None
    vendor: str
    os_family: str
    parser: str
    parser_version: str
    detection_confidence: float = 1.0
    config_line_count: int = 0
    parser_warnings: List[str] = Field(default_factory=list)
    completeness: Optional[Dict[str, Any]] = None
    capabilities: Optional[Dict[str, str]] = None


class FrameworkInfo(BaseModel):
    name: str
    version: str
    rules_evaluated: int
    source_note: Optional[str] = None
    platform_note: Optional[str] = Field(
        default=None,
        description="Set when the rule pack targets a different platform than the audited device.",
    )


class AuditReport(BaseModel):
    """The structured deliverable. The CLI table is a rendering of exactly this."""

    schema_version: str = REPORT_SCHEMA_VERSION
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tool: Dict[str, str] = Field(default_factory=dict)
    target: TargetInfo
    framework: FrameworkInfo
    frameworks: List[FrameworkInfo] = Field(default_factory=list)
    framework_summaries: Dict[str, ReportSummary] = Field(default_factory=dict)
    summary: ReportSummary
    results: List[ControlResult] = Field(default_factory=list)
    baseline: Optional[SecurityBaselineModel] = Field(
        default=None,
        description="Full normalized model, emitted for transparency and for downstream (LLM/training) consumers.",
    )

    def results_by_status(self, status: Status) -> List[ControlResult]:
        return [r for r in self.results if r.status is status]

    def validate_consistency(self) -> None:
        """Enforces that counts, scores, and integrity match perfectly."""
        if self.summary.total != len(self.results):
            raise ValueError(
                f"Summary total ({self.summary.total}) != results count ({len(self.results)})"
            )
        status_sum = (
            self.summary.passed
            + self.summary.failed
            + self.summary.needs_review
            + self.summary.not_applicable
            + self.summary.unsupported
            + self.summary.error
            + self.summary.manual_review
        )
        if status_sum != self.summary.total:
            raise ValueError(
                f"Sum of status counts ({status_sum}) != summary.total ({self.summary.total})"
            )
        expected_applicable = self.summary.total - self.summary.not_applicable
        if self.summary.applicable_controls != expected_applicable:
            raise ValueError(
                f"Applicable controls ({self.summary.applicable_controls}) != expected ({expected_applicable})"
            )
        expected_decidable = self.summary.passed + self.summary.failed
        if self.summary.decidable_controls != expected_decidable:
            raise ValueError(
                f"Decidable controls ({self.summary.decidable_controls}) != expected ({expected_decidable})"
            )
        for name, fw_summary in self.framework_summaries.items():
            fw_res = [r for r in self.results if r.framework == name]
            if fw_summary.total != len(fw_res):
                raise ValueError(
                    f"Framework {name} summary total ({fw_summary.total}) != matching results ({len(fw_res)})"
                )
