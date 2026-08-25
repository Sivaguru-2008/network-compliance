"""The compliance engine: baseline + rule pack -> audit report.

The engine knows nothing about Cisco, about ciscoconfparse2, or about CIS.  It
knows only the ``SecurityBaselineModel`` field vocabulary and the condition
grammar.  That is what makes both sides swappable: a new vendor is a new
parser, a new framework is a new JSON file, and neither touches this module.
"""

from typing import Dict, List, Optional

from ..models.baseline import SecurityBaselineModel
from ..models.result import (
    AuditReport,
    ControlResult,
    Evidence,
    FrameworkInfo,
    ReportSummary,
    Status,
    TargetInfo,
)
from ..models.rule import ComplianceRule, RuleSet
from .conditions import ConditionOutcome, RuleEvaluationError, Ternary, evaluate_condition

_TERNARY_TO_STATUS = {
    Ternary.TRUE: Status.PASS,
    Ternary.FALSE: Status.FAIL,
    Ternary.UNKNOWN: Status.NEEDS_REVIEW,
}

# Report order: worst first, so an operator reads the urgent rows without scrolling.
_STATUS_ORDER = {
    Status.FAIL: 0,
    Status.NEEDS_REVIEW: 1,
    Status.UNSUPPORTED: 2,
    Status.MANUAL_REVIEW: 3,
    Status.PASS: 4,
    Status.NOT_APPLICABLE: 5,
}


class ComplianceEngine:
    """Evaluates one rule pack against one normalized baseline."""

    def __init__(self, ruleset: RuleSet, *, validate_fields: bool = True) -> None:
        self.ruleset = ruleset
        if validate_fields:
            self._validate_against_baseline()

    def _validate_against_baseline(self) -> None:
        """Fail fast if a rule references a field no parser can ever produce.

        Rule packs are external, hand-edited data. Catching a typo here -- at
        load time, naming the rule -- beats discovering it as a mysterious
        NEEDS_REVIEW during an audit.
        """
        known = set(SecurityBaselineModel.observable_fields())
        problems = []
        for rule in self.ruleset.rules:
            unknown = [f for f in rule.baseline_fields if f.split(".")[0] not in known]
            if unknown:
                problems.append(f"  {rule.id}: unknown baseline field(s) {', '.join(sorted(unknown))}")
        if problems:
            raise RuleEvaluationError(
                "Rule pack references fields that do not exist on SecurityBaselineModel:\n"
                + "\n".join(problems)
                + "\nKnown fields: "
                + ", ".join(sorted(known))
            )

    # -- evaluation --------------------------------------------------------

    def evaluate_rule(self, rule: ComplianceRule, baseline: SecurityBaselineModel) -> ControlResult:
        outcome = evaluate_condition(rule.condition, baseline)
        status = _TERNARY_TO_STATUS[outcome.ternary]
        device = baseline.hostname.value or baseline.source_file
        vendor = baseline.provenance.vendor
        parser = baseline.provenance.parser_name
        return ControlResult.build(
            rule=rule,
            status=status,
            message=self._message(status, outcome),
            evidence=self._evidence(outcome),
            device=device,
            vendor=vendor,
            parser=parser,
        )

    def evaluate(self, baseline: SecurityBaselineModel) -> List[ControlResult]:
        results = [self.evaluate_rule(rule, baseline) for rule in self.ruleset.rules]
        return sorted(
            results,
            key=lambda r: (_STATUS_ORDER[r.status], -r.severity.rank, r.control_ref or "", r.rule_id),
        )

    @staticmethod
    def _evidence(outcome: ConditionOutcome) -> List[Evidence]:
        """One evidence entry per distinct field, in the order the rule read them."""
        seen: Dict[str, Evidence] = {}
        for leaf in outcome.leaves:
            if leaf.field not in seen:
                seen[leaf.field] = Evidence.from_observation(leaf.field, leaf.observation)
        return list(seen.values())

    @staticmethod
    def _message(status: Status, outcome: ConditionOutcome) -> str:
        if status is Status.NEEDS_REVIEW:
            unknown = [leaf for leaf in outcome.leaves if leaf.ternary is Ternary.UNKNOWN]
            fields = ", ".join(sorted({leaf.field for leaf in unknown}))
            note = next((leaf.observation.note for leaf in unknown if leaf.observation.note), None)
            base = f"No conclusive evidence for {fields}"
            return f"{base}. {note}" if note else f"{base}."
        if status is Status.FAIL:
            violated = [leaf.detail for leaf in outcome.leaves if leaf.ternary is Ternary.FALSE]
            return "; ".join(violated) if violated else "Required condition not met."
        satisfied = [leaf.detail for leaf in outcome.leaves if leaf.ternary is Ternary.TRUE]
        return "; ".join(satisfied) if satisfied else "Required condition met."

    # -- report assembly ---------------------------------------------------

    def build_report(
        self,
        baseline: SecurityBaselineModel,
        *,
        tool_name: str,
        tool_version: str,
        include_baseline: bool = True,
        platform_note: Optional[str] = None,
    ) -> AuditReport:
        results = self.evaluate(baseline)
        return AuditReport(
            tool={"name": tool_name, "version": tool_version},
            target=TargetInfo(
                source_file=baseline.source_file,
                source_sha256=baseline.source_sha256,
                hostname=baseline.hostname.value,
                vendor=baseline.provenance.vendor,
                os_family=baseline.provenance.os_family,
                parser=baseline.provenance.parser_name,
                parser_version=baseline.provenance.parser_version,
                detection_confidence=baseline.provenance.detection_confidence,
                config_line_count=baseline.config_line_count,
                parser_warnings=baseline.provenance.warnings,
            ),
            framework=FrameworkInfo(
                name=self.ruleset.framework,
                version=self.ruleset.framework_version,
                rules_evaluated=len(results),
                source_note=self.ruleset.source_note,
                platform_note=platform_note,
            ),
            summary=ReportSummary.from_results(results),
            results=results,
            baseline=baseline if include_baseline else None,
        )


__all__ = ["ComplianceEngine", "RuleEvaluationError"]
