"""
Populate the SQLite knowledge base from extracted CIS benchmark JSON.

This module reads the normalized CIS recommendation JSON (produced by
extractor.py) and the rule classification map, then writes each recommendation
into the knowledge base with full provenance and evaluation classification.

All data originates from the PDF — the knowledge base stores what was in the
document, not what the LLM knows about CIS.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from auditor.cis.fortigate_map import FORTIGATE_RULE_MAP
from auditor.cis.schema import CISBenchmark, CISRecommendation, EvaluationType
from auditor.knowledge.db import init_db
from auditor.knowledge.repository import save_control, save_source


def _severity_from_profile(rec: CISRecommendation) -> str:
    """Map CIS profile level to severity."""
    from auditor.cis.schema import Profile

    if Profile.LEVEL_1 in rec.profile and Profile.LEVEL_2 not in rec.profile:
        return "high"
    if Profile.LEVEL_2 in rec.profile and Profile.LEVEL_1 not in rec.profile:
        return "medium"
    return "high"


def _extract_cli_commands(remediation_text: str) -> List[str]:
    """Extract CLI command lines from remediation text."""
    lines = remediation_text.split("\n")
    commands = []
    in_cli = False
    for line in lines:
        stripped = line.strip()
        if stripped.lower().startswith("cli:") or stripped.lower() == "in cli:":
            in_cli = True
            continue
        if stripped.lower().startswith("in the gui:") or stripped.lower().startswith("gui:"):
            in_cli = False
            continue
        if in_cli and stripped:
            if stripped.startswith("FGT") or stripped.startswith("config ") or stripped.startswith("set ") or stripped.startswith("end") or stripped.startswith("edit ") or stripped.startswith("next"):
                commands.append(stripped)
    return commands


def populate_fortigate_kb(
    benchmark_json_path: str | Path,
    *,
    approve_deterministic: bool = True,
) -> Dict[str, Any]:
    """
    Populate the knowledge base from a CIS FortiGate benchmark JSON.

    Args:
        benchmark_json_path: Path to CIS_Fortigate_7.0.x_rules.json
        approve_deterministic: Auto-approve rules that have deterministic conditions

    Returns:
        Summary dict with counts by evaluation type and validation status.
    """
    benchmark_json_path = Path(benchmark_json_path)
    data = json.loads(benchmark_json_path.read_text(encoding="utf-8"))
    benchmark = CISBenchmark(**data)

    init_db()

    source_id = save_source(
        source_name=f"CIS {benchmark.vendor} {benchmark.product} Benchmark v{benchmark.benchmark_version}",
        source_type="CIS_BENCHMARK_PDF",
        source_url_or_path=benchmark.source_file,
        source_version=benchmark.benchmark_version,
        source_date=benchmark.publication_date,
        content_hash=benchmark.source_hash,
        validation_status="APPROVED",
    )

    stats = {
        "total": 0,
        "by_eval_type": {},
        "by_validation": {},
        "approved": 0,
        "pending": 0,
    }

    for rec in benchmark.recommendations:
        mapping = FORTIGATE_RULE_MAP.get(rec.rule_id)

        eval_type = mapping.evaluation_type if mapping else EvaluationType.MANUAL
        condition = mapping.condition_json if mapping and mapping.condition_json else {}
        internal_control = mapping.internal_control if mapping else None
        gap_note = mapping.gap_note if mapping else "No mapping defined."

        if eval_type == EvaluationType.DETERMINISTIC and condition and approve_deterministic:
            validation_status = "APPROVED"
        elif eval_type in (EvaluationType.MANUAL, EvaluationType.NOT_APPLICABLE):
            validation_status = "MANUAL_REVIEW"
        else:
            validation_status = "VALIDATION_PENDING"

        evidence_fields = []
        if condition:
            evidence_fields = _extract_evidence_fields(condition)

        cli_commands = _extract_cli_commands(rec.remediation)

        source_note = (
            f"AUTHORITATIVE CIS RULE from {rec.source.file} page {rec.source.page}. "
            f"Evaluation: {eval_type.value}."
        )
        if gap_note:
            source_note += f" Gap: {gap_note}"

        save_control(
            framework="CIS",
            framework_version=benchmark.benchmark_version,
            framework_display_name=f"CIS {benchmark.product} {benchmark.product_version} Benchmark",
            control_id=rec.rule_id,
            internal_control_id=internal_control,
            verified_ref=1,
            title=rec.title,
            requirement=rec.description,
            description=rec.rationale,
            severity=_severity_from_profile(rec),
            vendor=benchmark.vendor.lower(),
            platform="fortios",
            platform_version=benchmark.product_version,
            evidence_requirements=evidence_fields,
            pass_condition=condition,
            remediation_summary=rec.remediation[:500] if rec.remediation else "",
            remediation_cli=cli_commands,
            remediation_provenance="CIS_PDF",
            references=rec.references,
            source_id=source_id,
            source_location=f"page {rec.source.page}",
            source_note=source_note,
            validation_status=validation_status,
        )

        stats["total"] += 1
        stats["by_eval_type"][eval_type.value] = stats["by_eval_type"].get(eval_type.value, 0) + 1
        stats["by_validation"][validation_status] = stats["by_validation"].get(validation_status, 0) + 1
        if validation_status == "APPROVED":
            stats["approved"] += 1
        else:
            stats["pending"] += 1

    return stats


def _extract_evidence_fields(condition: dict) -> List[str]:
    """Recursively extract baseline field names from a condition tree."""
    fields = []
    if "field" in condition:
        fields.append(condition["field"])
    for key in ("all_of", "any_of"):
        if key in condition:
            for sub in condition[key]:
                fields.extend(_extract_evidence_fields(sub))
    if "not" in condition:
        fields.extend(_extract_evidence_fields(condition["not"]))
    return list(dict.fromkeys(fields))


def populate_paloalto_kb(
    benchmark_json_path: str | Path,
    *,
    approve_deterministic: bool = True,
) -> Dict[str, Any]:
    """
    Populate the knowledge base from a CIS Palo Alto benchmark JSON.

    Args:
        benchmark_json_path: Path to CIS_Palo_Alto_Firewall_11_rules.json
        approve_deterministic: Auto-approve rules that have deterministic conditions

    Returns:
        Summary dict with counts by evaluation type and validation status.
    """
    from auditor.cis.paloalto_map import PALOALTO_RULE_MAP
    benchmark_json_path = Path(benchmark_json_path)
    data = json.loads(benchmark_json_path.read_text(encoding="utf-8"))
    benchmark = CISBenchmark(**data)

    init_db()

    source_id = save_source(
        source_name=f"CIS {benchmark.vendor} {benchmark.product} Benchmark v{benchmark.benchmark_version}",
        source_type="CIS_BENCHMARK_PDF",
        source_url_or_path=benchmark.source_file,
        source_version=benchmark.benchmark_version,
        source_date=benchmark.publication_date,
        content_hash=benchmark.source_hash,
        validation_status="APPROVED",
    )

    stats = {
        "total": 0,
        "by_eval_type": {},
        "by_validation": {},
        "approved": 0,
        "pending": 0,
    }

    for rec in benchmark.recommendations:
        mapping = PALOALTO_RULE_MAP.get(rec.rule_id)

        eval_type = mapping.evaluation_type if mapping else EvaluationType.MANUAL
        condition = mapping.condition_json if mapping and mapping.condition_json else {}
        internal_control = mapping.internal_control if mapping else None
        gap_note = mapping.gap_note if mapping else "No mapping defined."

        if eval_type == EvaluationType.DETERMINISTIC and condition and approve_deterministic:
            validation_status = "APPROVED"
        elif eval_type in (EvaluationType.MANUAL, EvaluationType.NOT_APPLICABLE):
            validation_status = "MANUAL_REVIEW"
        else:
            validation_status = "VALIDATION_PENDING"

        evidence_fields = []
        if condition:
            evidence_fields = _extract_evidence_fields(condition)

        cli_commands = _extract_cli_commands(rec.remediation)

        source_note = (
            f"AUTHORITATIVE CIS RULE from {rec.source.file} page {rec.source.page}. "
            f"Evaluation: {eval_type.value}."
        )
        if gap_note:
            source_note += f" Gap: {gap_note}"

        save_control(
            framework="CIS",
            framework_version=benchmark.benchmark_version,
            framework_display_name="CIS",
            control_id=rec.rule_id,
            internal_control_id=internal_control,
            verified_ref=1,
            title=rec.title,
            requirement=rec.description,
            description=rec.rationale,
            severity=_severity_from_profile(rec),
            vendor=benchmark.vendor.lower(),
            platform="paloalto",
            platform_version=benchmark.product_version,
            evidence_requirements=evidence_fields,
            pass_condition=condition,
            remediation_summary=rec.remediation[:500] if rec.remediation else "",
            remediation_cli=cli_commands,
            remediation_provenance="CIS_PDF",
            references=rec.references,
            source_id=source_id,
            source_location=f"page {rec.source.page}",
            source_note=source_note,
            validation_status=validation_status,
        )

        stats["total"] += 1
        stats["by_eval_type"][eval_type.value] = stats["by_eval_type"].get(eval_type.value, 0) + 1
        stats["by_validation"][validation_status] = stats["by_validation"].get(validation_status, 0) + 1
        if validation_status == "APPROVED":
            stats["approved"] += 1
        else:
            stats["pending"] += 1

    return stats
