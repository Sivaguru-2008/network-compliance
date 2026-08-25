"""
Load CIS rules from the knowledge base into ComplianceRule/RuleSet objects.

This module bridges the knowledge base (SQLite with full CIS provenance) and
the evaluation engine (which needs RuleSet objects).  It produces two outputs:

1. A RuleSet of DETERMINISTIC rules the engine can evaluate automatically.
2. A list of pre-built ControlResult entries for MANUAL/UNSUPPORTED/PARSER_REQUIRED
   rules, with the correct status set so they appear in the report without
   being silently dropped or converted to PASS.
"""

import json
from typing import Any, Dict, List, Optional, Tuple

from auditor.cis.fortigate_map import FORTIGATE_RULE_MAP, RuleMapping
from auditor.cis.schema import EvaluationType
from auditor.knowledge.db import init_db
from auditor.knowledge.repository import get_controls_for_framework
from auditor.models.result import ControlResult, Evidence, Status
from auditor.models.rule import (
    ComplianceRule,
    Condition,
    LeafCondition,
    Platform,
    Remediation,
    RuleSet,
    Severity,
)


def _parse_condition(cond_dict: dict) -> Condition:
    """Parse a condition dict into the Condition union type."""
    if "all_of" in cond_dict:
        from auditor.models.rule import AllOfCondition
        return AllOfCondition(all_of=[_parse_condition(c) for c in cond_dict["all_of"]])
    if "any_of" in cond_dict:
        from auditor.models.rule import AnyOfCondition
        return AnyOfCondition(any_of=[_parse_condition(c) for c in cond_dict["any_of"]])
    if "not" in cond_dict:
        from auditor.models.rule import NotCondition
        return NotCondition(**{"not": _parse_condition(cond_dict["not"])})
    return LeafCondition(**cond_dict)


def load_fortigate_cis_rules(
    *,
    version: Optional[str] = None,
    include_unapproved: bool = False,
) -> Tuple[Optional[RuleSet], List[ControlResult]]:
    """
    Load CIS FortiGate rules from the knowledge base.

    Returns:
        (ruleset, non_evaluable_results):
          - ruleset: RuleSet of deterministic rules, or None if none found
          - non_evaluable_results: pre-built ControlResult for MANUAL/UNSUPPORTED rules
    """
    init_db()

    controls = get_controls_for_framework(
        "CIS", "fortios", version=version, include_unapproved=True,
    )

    if not controls:
        return None, []

    evaluable_rules: List[ComplianceRule] = []
    non_evaluable: List[ControlResult] = []
    framework_version = version or "1.4.0"

    for ctrl in controls:
        control_id = ctrl["control_id"]
        mapping = FORTIGATE_RULE_MAP.get(control_id)

        if not mapping:
            non_evaluable.append(_build_manual_result(ctrl, "No mapping defined for this CIS recommendation."))
            continue

        if mapping.evaluation_type == EvaluationType.DETERMINISTIC and ctrl.get("pass_condition"):
            condition_dict = ctrl["pass_condition"]
            if not condition_dict:
                non_evaluable.append(_build_manual_result(ctrl, "Deterministic rule has empty condition."))
                continue

            if ctrl["validation_status"] != "APPROVED" and not include_unapproved:
                non_evaluable.append(_build_unsupported_result(
                    ctrl, "Rule not yet approved in knowledge base."
                ))
                continue

            try:
                condition = _parse_condition(condition_dict)
            except Exception as e:
                non_evaluable.append(_build_manual_result(ctrl, f"Failed to parse condition: {e}"))
                continue

            rule = ComplianceRule(
                id=f"CIS-FORTIOS-{control_id}",
                control_ref=control_id,
                internal_control_id=mapping.internal_control,
                verified_ref=True,
                title=ctrl["title"],
                description=ctrl.get("requirement") or ctrl.get("description") or "",
                framework="CIS",
                severity=Severity(ctrl["severity"]),
                condition=condition,
                remediation=Remediation(
                    summary=ctrl.get("remediation_summary", ""),
                    cli=ctrl.get("remediation_cli", []),
                    provenance="CIS_PDF",
                ),
                references=ctrl.get("references", []),
                knowledge_version=framework_version,
            )
            evaluable_rules.append(rule)

        elif mapping.evaluation_type == EvaluationType.PARSER_REQUIRED:
            non_evaluable.append(_build_unsupported_result(
                ctrl,
                f"Parser extension required. {mapping.gap_note}",
            ))

        elif mapping.evaluation_type in (EvaluationType.MANUAL, EvaluationType.SEMANTIC):
            non_evaluable.append(_build_manual_result(
                ctrl,
                f"Manual review required. {mapping.gap_note}",
            ))

        elif mapping.evaluation_type == EvaluationType.NOT_APPLICABLE:
            non_evaluable.append(_build_na_result(ctrl))

        else:
            non_evaluable.append(_build_manual_result(ctrl, mapping.gap_note or "Unclassified rule."))

    ruleset = None
    if evaluable_rules:
        ruleset = RuleSet(
            schema_version="1.0",
            framework="CIS",
            framework_version=framework_version,
            platform=Platform(vendor="fortinet", os_family="fortios"),
            source_note=(
                "CIS Fortinet FortiGate 7.0.x Benchmark v1.4.0. "
                "Rules extracted from authoritative PDF with full provenance. "
                f"{len(evaluable_rules)} deterministic rules loaded."
            ),
            rules=evaluable_rules,
        )

    return ruleset, non_evaluable


def _build_manual_result(ctrl: Dict[str, Any], message: str) -> ControlResult:
    return ControlResult(
        rule_id=f"CIS-FORTIOS-{ctrl['control_id']}",
        control_ref=ctrl["control_id"],
        title=ctrl["title"],
        description=ctrl.get("requirement") or ctrl.get("description") or "",
        framework="CIS",
        severity=Severity(ctrl["severity"]),
        status=Status.MANUAL_REVIEW,
        message=message,
        evidence=[],
        source_reference=ctrl.get("source_location"),
        knowledge_version=ctrl.get("framework_version"),
    )


def _build_unsupported_result(ctrl: Dict[str, Any], message: str) -> ControlResult:
    return ControlResult(
        rule_id=f"CIS-FORTIOS-{ctrl['control_id']}",
        control_ref=ctrl["control_id"],
        title=ctrl["title"],
        description=ctrl.get("requirement") or ctrl.get("description") or "",
        framework="CIS",
        severity=Severity(ctrl["severity"]),
        status=Status.UNSUPPORTED,
        message=message,
        evidence=[],
        source_reference=ctrl.get("source_location"),
        knowledge_version=ctrl.get("framework_version"),
    )


def _build_na_result(ctrl: Dict[str, Any]) -> ControlResult:
    return ControlResult(
        rule_id=f"CIS-FORTIOS-{ctrl['control_id']}",
        control_ref=ctrl["control_id"],
        title=ctrl["title"],
        description=ctrl.get("requirement") or ctrl.get("description") or "",
        framework="CIS",
        severity=Severity(ctrl["severity"]),
        status=Status.NOT_APPLICABLE,
        message="This control is not applicable to this device configuration.",
        evidence=[],
        source_reference=ctrl.get("source_location"),
        knowledge_version=ctrl.get("framework_version"),
    )


def load_paloalto_cis_rules(
    *,
    version: Optional[str] = None,
    include_unapproved: bool = False,
) -> Tuple[Optional[RuleSet], List[ControlResult]]:
    """
    Load CIS Palo Alto rules from the knowledge base.

    Returns:
        (ruleset, non_evaluable_results):
          - ruleset: RuleSet of deterministic rules, or None if none found
          - non_evaluable_results: pre-built ControlResult for MANUAL/PARSER_REQUIRED rules
    """
    from auditor.cis.paloalto_map import PALOALTO_RULE_MAP
    init_db()

    controls = get_controls_for_framework(
        "CIS", "paloalto", version=version, include_unapproved=True,
    )

    if not controls:
        return None, []

    evaluable_rules: List[ComplianceRule] = []
    non_evaluable: List[ControlResult] = []
    framework_version = version or "1.2.0"

    for ctrl in controls:
        control_id = ctrl["control_id"]
        mapping = PALOALTO_RULE_MAP.get(control_id)

        if not mapping:
            non_evaluable.append(_build_paloalto_manual_result(ctrl, "No mapping defined for this CIS recommendation."))
            continue

        rule_id_str = f"CIS-PALOALTO-{control_id}"

        if mapping.evaluation_type == EvaluationType.DETERMINISTIC and ctrl.get("pass_condition"):
            condition_dict = ctrl["pass_condition"]
            if not condition_dict:
                non_evaluable.append(_build_paloalto_manual_result(ctrl, "Deterministic rule has empty condition."))
                continue

            if ctrl["validation_status"] != "APPROVED" and not include_unapproved:
                non_evaluable.append(_build_paloalto_unsupported_result(
                    ctrl, "Rule not yet approved in knowledge base."
                ))
                continue

            try:
                condition = _parse_condition(condition_dict)
            except Exception as e:
                non_evaluable.append(_build_paloalto_manual_result(ctrl, f"Failed to parse condition: {e}"))
                continue

            rule = ComplianceRule(
                id=rule_id_str,
                control_ref=control_id,
                internal_control_id=mapping.internal_control,
                verified_ref=True,
                title=ctrl["title"],
                description=ctrl.get("requirement") or ctrl.get("description") or "",
                framework="CIS",
                severity=Severity(ctrl["severity"]),
                condition=condition,
                remediation=Remediation(
                    summary=ctrl.get("remediation_summary", ""),
                    cli=ctrl.get("remediation_cli", []),
                    provenance="CIS_PDF",
                ),
                references=ctrl.get("references", []),
                knowledge_version=framework_version,
            )
            evaluable_rules.append(rule)

        elif mapping.evaluation_type == EvaluationType.PARSER_REQUIRED:
            non_evaluable.append(_build_paloalto_unsupported_result(
                ctrl,
                f"Parser extension required. {mapping.gap_note}",
            ))

        elif mapping.evaluation_type in (EvaluationType.MANUAL, EvaluationType.SEMANTIC):
            non_evaluable.append(_build_paloalto_manual_result(
                ctrl,
                f"Manual review required. {mapping.gap_note}",
            ))

        elif mapping.evaluation_type == EvaluationType.NOT_APPLICABLE:
            non_evaluable.append(_build_paloalto_na_result(ctrl))

        else:
            non_evaluable.append(_build_paloalto_manual_result(ctrl, mapping.gap_note or "Unclassified rule."))

    ruleset = None
    if evaluable_rules:
        ruleset = RuleSet(
            schema_version="1.0",
            framework="CIS",
            framework_version=framework_version,
            platform=Platform(vendor="paloalto", os_family="panos"),
            source_note=(
                "CIS Palo Alto Firewall 11 Benchmark v1.2.0. "
                "Rules extracted from authoritative PDF with full provenance. "
                f"{len(evaluable_rules)} deterministic rules loaded."
            ),
            rules=evaluable_rules,
        )

    return ruleset, non_evaluable


def _build_paloalto_manual_result(ctrl: Dict[str, Any], message: str) -> ControlResult:
    return ControlResult(
        rule_id=f"CIS-PALOALTO-{ctrl['control_id']}",
        control_ref=ctrl["control_id"],
        title=ctrl["title"],
        description=ctrl.get("requirement") or ctrl.get("description") or "",
        framework="CIS",
        severity=Severity(ctrl["severity"]),
        status=Status.MANUAL_REVIEW,
        message=message,
        evidence=[],
        source_reference=ctrl.get("source_location"),
        knowledge_version=ctrl.get("framework_version"),
    )


def _build_paloalto_unsupported_result(ctrl: Dict[str, Any], message: str) -> ControlResult:
    return ControlResult(
        rule_id=f"CIS-PALOALTO-{ctrl['control_id']}",
        control_ref=ctrl["control_id"],
        title=ctrl["title"],
        description=ctrl.get("requirement") or ctrl.get("description") or "",
        framework="CIS",
        severity=Severity(ctrl["severity"]),
        status=Status.UNSUPPORTED,
        message=message,
        evidence=[],
        source_reference=ctrl.get("source_location"),
        knowledge_version=ctrl.get("framework_version"),
    )


def _build_paloalto_na_result(ctrl: Dict[str, Any]) -> ControlResult:
    return ControlResult(
        rule_id=f"CIS-PALOALTO-{ctrl['control_id']}",
        control_ref=ctrl["control_id"],
        title=ctrl["title"],
        description=ctrl.get("requirement") or ctrl.get("description") or "",
        framework="CIS",
        severity=Severity(ctrl["severity"]),
        status=Status.NOT_APPLICABLE,
        message="This control is not applicable to this device configuration.",
        evidence=[],
        source_reference=ctrl.get("source_location"),
        knowledge_version=ctrl.get("framework_version"),
    )
