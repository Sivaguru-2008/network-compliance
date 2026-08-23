"""Evaluation output: one result per control, plus the assembled report."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .baseline import SecurityBaselineModel
from .observation import Observation, Origin
from .rule import ComplianceRule, Remediation, Severity

REPORT_SCHEMA_VERSION = "1.0"


class Status(str, Enum):
    """The three verdicts this tool is allowed to reach.

    ``NEEDS_REVIEW`` is a designed outcome, not a failure mode: it means the
    configuration carried no conclusive evidence either way, so the tool
    escalates to a human instead of guessing.  Missing evidence is never
    silently upgraded to PASS.
    """

    PASS = "PASS"
    FAIL = "FAIL"
    NEEDS_REVIEW = "NEEDS_REVIEW"


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
    control_ref: Optional[str] = None
    title: str
    description: str
    framework: str
    severity: Severity
    status: Status
    message: str = Field(description="Why this verdict was reached, in one line.")
    evidence: List[Evidence] = Field(default_factory=list)
    remediation: Optional[Remediation] = None
    references: List[str] = Field(default_factory=list)

    @classmethod
    def build(
        cls,
        rule: ComplianceRule,
        status: Status,
        message: str,
        evidence: List[Evidence],
    ) -> "ControlResult":
        return cls(
            rule_id=rule.id,
            control_ref=rule.control_ref,
            title=rule.title,
            description=rule.description,
            framework=rule.framework,
            severity=rule.severity,
            status=status,
            message=message,
            evidence=evidence,
            # Remediation is carried on non-PASS results only: a passing control
            # has nothing to remediate, and shipping it anyway invites operators
            # to paste commands they do not need.
            remediation=None if status is Status.PASS else rule.remediation,
            references=rule.references,
        )

    @property
    def primary_evidence(self) -> Optional[Evidence]:
        """The evidence line that best explains this verdict.

        Which one that is depends on the verdict. A control that passed is
        explained by a field that was actually established -- citing an
        undetected field next to PASS reads as "passed on no evidence", which
        is precisely the impression this tool must never give. A FAIL or
        NEEDS_REVIEW is explained by the field that fell short, so there the
        undetected field is the interesting one.
        """
        if not self.evidence:
            return None
        wanted = self.status is Status.PASS
        return next((item for item in self.evidence if item.detected is wanted), self.evidence[0])


class ReportSummary(BaseModel):
    total: int = 0
    passed: int = 0
    failed: int = 0
    needs_review: int = 0
    failed_by_severity: Dict[str, int] = Field(default_factory=dict)
    needs_review_by_severity: Dict[str, int] = Field(default_factory=dict)
    compliance_score: float = Field(
        default=0.0,
        description="passed / total, as a percentage. NEEDS_REVIEW counts against the score.",
    )
    adjudicated_score: float = Field(
        default=0.0,
        description="passed / (passed + failed), as a percentage. Excludes NEEDS_REVIEW from the denominator.",
    )

    @classmethod
    def from_results(cls, results: List[ControlResult]) -> "ReportSummary":
        passed = [r for r in results if r.status is Status.PASS]
        failed = [r for r in results if r.status is Status.FAIL]
        review = [r for r in results if r.status is Status.NEEDS_REVIEW]
        total = len(results)
        adjudicated = len(passed) + len(failed)
        return cls(
            total=total,
            passed=len(passed),
            failed=len(failed),
            needs_review=len(review),
            failed_by_severity=_count_by_severity(failed),
            needs_review_by_severity=_count_by_severity(review),
            compliance_score=round(100.0 * len(passed) / total, 1) if total else 0.0,
            adjudicated_score=round(100.0 * len(passed) / adjudicated, 1) if adjudicated else 0.0,
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
    summary: ReportSummary
    results: List[ControlResult] = Field(default_factory=list)
    baseline: Optional[SecurityBaselineModel] = Field(
        default=None,
        description="Full normalized model, emitted for transparency and for downstream (LLM/training) consumers.",
    )

    def results_by_status(self, status: Status) -> List[ControlResult]:
        return [r for r in self.results if r.status is status]
