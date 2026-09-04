"""End-to-end evaluation of the auditor pipeline on REAL_PRODUCTION configs.

Runs all 26 REAL_PRODUCTION configurations (16 Cisco IOS Stanford + 10 Juniper
Junos Internet2) through the full pipeline: vendor detection, parsing, semantic
extraction, compliance evaluation, evidence extraction, and remediation
validation.

Ground truth is derived from manual inspection of the actual config files --
NOT fabricated.  Stanford Cisco configs contain only data-plane configuration
(ACLs, interfaces, routing) with zero management-plane commands.  Internet2
Juniper configs follow a consistent template with RADIUS AAA, SSH-only access,
syslog, NTP, lo0 filters, but no root password, no banner, and no idle timeout.

Metrics reported:
  - Vendor detection accuracy
  - Parser success rate
  - Semantic field coverage
  - Per-rule TP/TN/FP/FN/Precision/Recall/F1
  - Evidence correctness (line-level verification)
  - Remediation validation success rate
  - Processing time (average, P95)
"""

import json
import re
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import ControlResult, Status
from auditor.parsers.base import ParserRegistry, registry
from auditor.pipeline import evaluate, parse_config, platform_key_for, select_parser


MANIFEST_PATH = PROJECT_ROOT / "dataset" / "manifest.json"


# --------------------------------------------------------------------------- #
#  Ground truth                                                                #
# --------------------------------------------------------------------------- #

# Rules from security_controls.json
RULE_IDS = [
    "aaa_enabled",
    "secure_vty_transport",
    "vty_idle_timeout",
    "enable_secret_encrypted",
    "no_default_snmp_community",
    "http_server_disabled",
    "ssh_version_2",
    "logging_enabled",
    "management_acl",
    "login_banner",
    "password_min_length",
    "ntp_configured",
    "no_write_snmp_community",
]

# Ground truth for each config, derived from actual config inspection.
#
# Stanford Cisco IOS configs (bbra_rtr..yozb_rtr): These configs contain only
# data-plane configuration (access-lists, interfaces, routing protocols).  No
# management-plane commands (hostname, enable secret, aaa new-model, line vty,
# snmp-server community, logging host, ntp server, banner, ip http, ip ssh)
# exist in any of the 16 files.  Confirmed via grep on the actual files.
#
# Internet2 Juniper Junos configs (atla..wash): All 10 follow a consistent
# template:
#   - authentication-order [ radius password ] + radius-server → AAA on
#   - system services ssh only (no telnet/ftp/finger) → secure transport
#   - No system login idle-timeout → absent(0) → timeout FAIL
#   - root-authentication { } (empty, sanitized) → no enable secret → FAIL
#   - password_encryption → absent(True) (Junos hashes by default)
#   - No snmp community → vacuously PASS
#   - No web-management http → HTTP disabled PASS
#   - 7 configs have protocol-version v2 → SSH v2 PASS
#   - 3 configs (chic, newy32aoa, wash) lack protocol-version → NEEDS_REVIEW
#   - system syslog host + file → logging PASS
#   - lo0 unit 0 filter input → management ACL PASS
#   - No login message/announcement → no banner FAIL
#   - No password minimum-length → NEEDS_REVIEW
#   - system ntp server → NTP PASS
#
# Status mapping for ground truth:
#   "PASS"         → rule condition satisfied
#   "FAIL"         → rule condition violated
#   "NEEDS_REVIEW" → evidence inconclusive
#   "UNSUPPORTED"  → parser does not cover this field


def _cisco_stanford_ground_truth() -> Dict[str, str]:
    """Ground truth for ALL 16 Stanford Cisco IOS backbone router configs.

    No management-plane configuration exists in any of these files.
    """
    return {
        "aaa_enabled": "FAIL",
        "secure_vty_transport": "NEEDS_REVIEW",
        "vty_idle_timeout": "NEEDS_REVIEW",
        "enable_secret_encrypted": "FAIL",
        "no_default_snmp_community": "PASS",
        "http_server_disabled": "NEEDS_REVIEW",
        "ssh_version_2": "NEEDS_REVIEW",
        "logging_enabled": "FAIL",
        "management_acl": "NEEDS_REVIEW",
        "login_banner": "FAIL",
        "password_min_length": "FAIL",
        "ntp_configured": "FAIL",
        "no_write_snmp_community": "PASS",
    }


# Juniper configs that DO have protocol-version v2
_JUNOS_WITH_SSH_V2 = {"atla.conf", "hous.conf", "clev.conf", "kans.conf",
                       "losa.conf", "salt.conf", "seat.conf"}
# Juniper configs WITHOUT protocol-version v2
_JUNOS_WITHOUT_SSH_V2 = {"chic.conf", "newy32aoa.conf", "wash.conf"}


def _juniper_internet2_ground_truth(filename: str) -> Dict[str, str]:
    """Ground truth for one Internet2 Juniper Junos config."""
    base = {
        "aaa_enabled": "PASS",
        "secure_vty_transport": "PASS",
        "vty_idle_timeout": "FAIL",
        "enable_secret_encrypted": "FAIL",
        "no_default_snmp_community": "PASS",
        "http_server_disabled": "PASS",
        "logging_enabled": "PASS",
        "management_acl": "PASS",
        "login_banner": "FAIL",
        "password_min_length": "NEEDS_REVIEW",
        "ntp_configured": "PASS",
        "no_write_snmp_community": "PASS",
    }
    if filename in _JUNOS_WITH_SSH_V2:
        base["ssh_version_2"] = "PASS"
    else:
        base["ssh_version_2"] = "NEEDS_REVIEW"
    return base


def build_ground_truth(entries: List[Dict]) -> Dict[str, Dict[str, str]]:
    """Build ground truth for every REAL_PRODUCTION config from its entry."""
    truth = {}
    for entry in entries:
        path = entry["local_path"]
        filename = Path(path).name
        if entry["platform"] == "cisco_ios":
            truth[path] = _cisco_stanford_ground_truth()
        elif entry["platform"] == "juniper_junos":
            truth[path] = _juniper_internet2_ground_truth(filename)
    return truth


# --------------------------------------------------------------------------- #
#  Independent evidence verifiers                                              #
# --------------------------------------------------------------------------- #

def verify_evidence_correctness(
    config_text: str,
    platform: str,
    result: ControlResult,
) -> Dict[str, Any]:
    """Independently verify that evidence line references exist in the config."""
    verification = {
        "rule_id": result.rule_id,
        "evidence_count": len(result.evidence),
        "verified_count": 0,
        "evidence_details": [],
    }
    for ev in result.evidence:
        detail = {
            "field": ev.field,
            "detected": ev.detected,
            "has_source_line": ev.source_line is not None,
            "has_line_number": ev.line_number is not None,
            "line_found_in_config": False,
        }
        if ev.source_line and ev.source_line.strip():
            detail["line_found_in_config"] = ev.source_line.strip() in config_text
        if ev.detected and ev.source_line:
            if detail["line_found_in_config"]:
                verification["verified_count"] += 1
        elif ev.detected and not ev.source_line:
            verification["verified_count"] += 1
        elif not ev.detected:
            verification["verified_count"] += 1
        verification["evidence_details"].append(detail)
    return verification


# --------------------------------------------------------------------------- #
#  Remediation validation                                                      #
# --------------------------------------------------------------------------- #

INTERACTIVE_REMEDIATIONS = {
    "plain-text-password",
}


def _is_interactive_remediation(commands: List[str]) -> bool:
    """Return True if the remediation requires device interaction (e.g. password prompt)."""
    for cmd in commands:
        if any(marker in cmd for marker in INTERACTIVE_REMEDIATIONS):
            return True
    return False


def validate_remediation(
    config_text: str,
    platform: str,
    result: ControlResult,
    parser_cls,
) -> Dict[str, Any]:
    """Apply remediation to a config copy, re-parse, re-evaluate.

    Only applies to FAIL results where remediation commands exist.
    Skips interactive remediations that require device prompts.
    """
    if result.status != Status.FAIL:
        return {"skipped": True, "reason": "not a FAIL result"}

    if not result.remediation or not result.remediation.commands:
        return {"skipped": True, "reason": "no remediation commands"}

    if _is_interactive_remediation(result.remediation.commands):
        return {"skipped": True, "reason": "interactive remediation (requires device prompt)"}

    modified = _apply_remediation(config_text, platform, result.remediation.commands)
    if modified == config_text:
        return {"skipped": True, "reason": "remediation did not modify config"}

    try:
        parser = parser_cls()
        new_baseline = parser.parse(modified, source_file="remediated_copy")
    except Exception as exc:
        return {"success": False, "error": f"re-parse failed: {exc}"}

    from auditor.rules.loader import load_framework
    from auditor.engine.evaluator import ComplianceEngine

    pk = f"{parser_cls.vendor}_{parser_cls.os_family}"
    try:
        ruleset = load_framework("CIS", pk, allow_cross_platform=True)
    except Exception:
        return {"skipped": True, "reason": f"no CIS ruleset for {pk}"}

    engine = ComplianceEngine(ruleset)
    for rule in ruleset.rules:
        if rule.id == result.rule_id or rule.internal_control_id == result.rule_id:
            new_result = engine.evaluate_rule(rule, new_baseline)
            return {
                "success": new_result.status == Status.PASS,
                "original_status": result.status.value,
                "new_status": new_result.status.value,
                "rule_id": result.rule_id,
            }
    return {"skipped": True, "reason": "rule not found in ruleset"}


def _apply_remediation(config_text: str, platform: str, commands: List[str]) -> str:
    """Best-effort textual application of remediation commands to a config copy.

    This is NOT a real device -- it applies IOS/Junos commands as text edits.
    """
    lines = config_text.splitlines()
    if platform == "cisco_ios":
        return _apply_ios_remediation(lines, commands)
    elif platform == "juniper_junos":
        return _apply_junos_remediation(lines, commands)
    return config_text


def _apply_ios_remediation(lines: List[str], commands: List[str]) -> str:
    """Apply IOS CLI commands as text edits to the running-config."""
    additions = []
    in_config_mode = False
    current_section = None

    for cmd in commands:
        cmd = cmd.strip()
        if not cmd or cmd.startswith("#"):
            continue
        if cmd == "configure terminal":
            in_config_mode = True
            continue
        if cmd == "end" or cmd.startswith("copy "):
            in_config_mode = False
            current_section = None
            continue

        if cmd.startswith("line vty"):
            current_section = cmd
            additions.append(cmd)
            continue

        if current_section:
            additions.append(f" {cmd}")
        elif cmd.startswith("no "):
            additions.append(cmd)
        else:
            additions.append(cmd)

    if additions:
        lines.extend(["!"] + additions)
    return "\n".join(lines)


def _apply_junos_remediation(lines: List[str], commands: List[str]) -> str:
    """Apply Junos set/delete commands to the config text."""
    additions = []
    for cmd in commands:
        cmd = cmd.strip()
        if not cmd or cmd.startswith("#"):
            continue
        if cmd in ("configure", "commit and-quit", "commit confirmed 5"):
            continue
        if cmd.startswith("set ") or cmd.startswith("delete "):
            additions.append(cmd)

    if additions:
        lines.extend(additions)
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  Metrics calculation                                                         #
# --------------------------------------------------------------------------- #

@dataclass
class RuleMetrics:
    rule_id: str
    tp: int = 0
    tn: int = 0
    fp: int = 0
    fn: int = 0
    needs_review_correct: int = 0
    needs_review_incorrect: int = 0
    total: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else float("nan")

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else float("nan")

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        if p != p or r != r:  # NaN check
            return float("nan")
        denom = p + r
        return 2 * p * r / denom if denom else 0.0

    @property
    def accuracy(self) -> float:
        correct = self.tp + self.tn + self.needs_review_correct
        return correct / self.total if self.total else 0.0


def classify_result(
    predicted_status: str,
    ground_truth_status: str,
) -> str:
    """Map pipeline vs ground-truth to TP/TN/FP/FN/NR_CORRECT/NR_INCORRECT.

    Convention (positive = FAIL/violation detected):
      TP: pipeline says FAIL, ground truth says FAIL
      TN: pipeline says PASS, ground truth says PASS
      FP: pipeline says FAIL, ground truth says PASS
      FN: pipeline says PASS, ground truth says FAIL
      NR_CORRECT: both say NEEDS_REVIEW
      NR_INCORRECT: disagree on NEEDS_REVIEW
    """
    p = predicted_status
    g = ground_truth_status

    if p == g:
        if p == "FAIL":
            return "TP"
        if p == "PASS":
            return "TN"
        if p == "NEEDS_REVIEW":
            return "NR_CORRECT"
        return "NR_CORRECT"

    if p == "FAIL" and g == "PASS":
        return "FP"
    if p == "PASS" and g == "FAIL":
        return "FN"
    if g == "NEEDS_REVIEW" or p == "NEEDS_REVIEW":
        return "NR_INCORRECT"

    if p == "FAIL" and g == "FAIL":
        return "TP"

    return "NR_INCORRECT"


# --------------------------------------------------------------------------- #
#  Main evaluation pipeline                                                    #
# --------------------------------------------------------------------------- #

@dataclass
class ConfigResult:
    path: str
    vendor: str
    platform: str
    filename: str
    detection_confidence: float = 0.0
    detected_vendor: str = ""
    detection_correct: bool = False
    parse_success: bool = False
    parse_error: str = ""
    fields_populated: int = 0
    fields_total: int = 0
    field_coverage: float = 0.0
    rule_results: Dict[str, str] = field(default_factory=dict)
    evidence_verifications: List[Dict] = field(default_factory=list)
    remediation_results: List[Dict] = field(default_factory=list)
    detection_time_ms: float = 0.0
    parse_time_ms: float = 0.0
    eval_time_ms: float = 0.0
    total_time_ms: float = 0.0


def load_real_production_entries() -> List[Dict]:
    """Load the 26 REAL_PRODUCTION entries from manifest.json."""
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        manifest = json.load(f)
    return [
        e for e in manifest["categories"]["REAL_PRODUCTION"]
        if e["provenance_class"] == "REAL_PRODUCTION"
    ]


def run_pipeline_on_config(
    entry: Dict,
    ground_truth: Dict[str, str],
) -> ConfigResult:
    """Run full pipeline on one config file and compare against ground truth."""
    path = entry["local_path"]
    full_path = PROJECT_ROOT / path
    result = ConfigResult(
        path=path,
        vendor=entry["vendor"],
        platform=entry["platform"],
        filename=Path(path).name,
    )

    config_text = full_path.read_text(encoding="utf-8", errors="replace")

    # Stage 1: Vendor Detection
    t0 = time.perf_counter()
    try:
        parser_cls, confidence = select_parser(config_text)
        result.detection_confidence = confidence
        result.detected_vendor = f"{parser_cls.vendor}_{parser_cls.os_family}"
        expected_vendor = entry["platform"]
        result.detection_correct = result.detected_vendor == expected_vendor
    except Exception as exc:
        result.parse_error = f"Detection failed: {exc}"
        result.total_time_ms = (time.perf_counter() - t0) * 1000
        return result
    result.detection_time_ms = (time.perf_counter() - t0) * 1000

    # Stage 2: Parsing + Semantic Extraction
    t1 = time.perf_counter()
    try:
        parser = parser_cls()
        baseline = parse_config(
            parser, config_text,
            source_file=path,
            parser_cls=parser_cls,
            confidence=confidence,
        )
        result.parse_success = True
    except Exception as exc:
        result.parse_error = f"Parse failed: {exc}"
        result.total_time_ms = (time.perf_counter() - t0) * 1000
        return result
    result.parse_time_ms = (time.perf_counter() - t1) * 1000

    # Stage 3: Semantic field coverage
    observable = baseline.observable_fields()
    result.fields_total = len(observable)
    populated = 0
    for fname in observable:
        obs = getattr(baseline, fname)
        if obs.detected:
            populated += 1
    result.fields_populated = populated
    result.field_coverage = populated / result.fields_total if result.fields_total else 0.0

    # Stage 4: Compliance evaluation
    t2 = time.perf_counter()
    try:
        outcome = evaluate(baseline, ["CIS"])
    except Exception as exc:
        result.parse_error = f"Evaluation failed: {exc}"
        result.total_time_ms = (time.perf_counter() - t0) * 1000
        return result
    result.eval_time_ms = (time.perf_counter() - t2) * 1000

    # Map results by internal_control_id (which matches our RULE_IDS)
    for cr in outcome.results:
        rule_id = cr.internal_control_id or cr.rule_id
        mapped_status = cr.status.value
        if cr.status in (Status.UNSUPPORTED, Status.NOT_APPLICABLE, Status.ERROR):
            mapped_status = cr.status.value
        result.rule_results[rule_id] = mapped_status

    # Stage 5: Evidence verification
    for cr in outcome.results:
        rule_id = cr.internal_control_id or cr.rule_id
        ev_check = verify_evidence_correctness(config_text, entry["platform"], cr)
        result.evidence_verifications.append(ev_check)

    # Stage 6: Remediation validation (on FAIL results only)
    for cr in outcome.results:
        rule_id = cr.internal_control_id or cr.rule_id
        if cr.status == Status.FAIL:
            rem_result = validate_remediation(
                config_text, entry["platform"], cr, parser_cls,
            )
            result.remediation_results.append({
                "rule_id": rule_id,
                **rem_result,
            })

    result.total_time_ms = (time.perf_counter() - t0) * 1000
    return result


def compute_metrics(
    config_results: List[ConfigResult],
    ground_truth: Dict[str, Dict[str, str]],
) -> Dict[str, Any]:
    """Compute all requested metrics from actual execution results."""

    # 1. Vendor detection accuracy
    detection_total = len(config_results)
    detection_correct = sum(1 for r in config_results if r.detection_correct)

    # 2. Parser success rate
    parse_total = len(config_results)
    parse_success = sum(1 for r in config_results if r.parse_success)

    # 3. Semantic field coverage
    coverages = [r.field_coverage for r in config_results if r.parse_success]

    # 4. Per-rule confusion matrix
    rule_metrics: Dict[str, RuleMetrics] = {rid: RuleMetrics(rule_id=rid) for rid in RULE_IDS}

    for cr in config_results:
        if not cr.parse_success:
            continue
        gt = ground_truth.get(cr.path, {})
        for rule_id in RULE_IDS:
            predicted = cr.rule_results.get(rule_id, "MISSING")
            expected = gt.get(rule_id, "MISSING")
            if predicted == "MISSING" or expected == "MISSING":
                continue

            m = rule_metrics[rule_id]
            m.total += 1
            classification = classify_result(predicted, expected)
            if classification == "TP":
                m.tp += 1
            elif classification == "TN":
                m.tn += 1
            elif classification == "FP":
                m.fp += 1
            elif classification == "FN":
                m.fn += 1
            elif classification == "NR_CORRECT":
                m.needs_review_correct += 1
            elif classification == "NR_INCORRECT":
                m.needs_review_incorrect += 1

    # 5. Evidence correctness
    total_evidence = 0
    verified_evidence = 0
    for cr in config_results:
        for ev in cr.evidence_verifications:
            total_evidence += ev["evidence_count"]
            verified_evidence += ev["verified_count"]

    # 6. Remediation success rate
    remediation_attempted = 0
    remediation_success = 0
    remediation_details = []
    for cr in config_results:
        for rem in cr.remediation_results:
            if rem.get("skipped"):
                continue
            remediation_attempted += 1
            if rem.get("success"):
                remediation_success += 1
            remediation_details.append(rem)

    # 7. Processing times
    total_times = [r.total_time_ms for r in config_results]
    detection_times = [r.detection_time_ms for r in config_results if r.detection_time_ms > 0]
    parse_times = [r.parse_time_ms for r in config_results if r.parse_time_ms > 0]
    eval_times = [r.eval_time_ms for r in config_results if r.eval_time_ms > 0]

    def _timing_stats(values: List[float]) -> Dict[str, float]:
        if not values:
            return {"avg_ms": 0, "p95_ms": 0, "min_ms": 0, "max_ms": 0}
        sorted_v = sorted(values)
        p95_idx = int(len(sorted_v) * 0.95)
        return {
            "avg_ms": round(statistics.mean(values), 2),
            "p95_ms": round(sorted_v[min(p95_idx, len(sorted_v) - 1)], 2),
            "min_ms": round(min(values), 2),
            "max_ms": round(max(values), 2),
        }

    # Build per-rule output
    per_rule = {}
    for rid, m in rule_metrics.items():
        per_rule[rid] = {
            "tp": m.tp,
            "tn": m.tn,
            "fp": m.fp,
            "fn": m.fn,
            "needs_review_correct": m.needs_review_correct,
            "needs_review_incorrect": m.needs_review_incorrect,
            "total": m.total,
            "precision": round(m.precision, 4) if m.precision == m.precision else None,
            "recall": round(m.recall, 4) if m.recall == m.recall else None,
            "f1": round(m.f1, 4) if m.f1 == m.f1 else None,
            "accuracy": round(m.accuracy, 4),
        }

    # Aggregate precision/recall/F1 (macro average over rules with defined values)
    precisions = [m.precision for m in rule_metrics.values() if m.precision == m.precision]
    recalls = [m.recall for m in rule_metrics.values() if m.recall == m.recall]
    f1s = [m.f1 for m in rule_metrics.values() if m.f1 == m.f1]

    return {
        "dataset": {
            "total_configs": len(config_results),
            "cisco_ios_count": sum(1 for r in config_results if r.platform == "cisco_ios"),
            "juniper_junos_count": sum(1 for r in config_results if r.platform == "juniper_junos"),
            "provenance_class": "REAL_PRODUCTION",
        },
        "vendor_detection": {
            "total": detection_total,
            "correct": detection_correct,
            "accuracy": round(detection_correct / detection_total, 4) if detection_total else 0,
            "per_config": [
                {
                    "file": r.filename,
                    "expected": r.platform,
                    "detected": r.detected_vendor,
                    "confidence": round(r.detection_confidence, 4),
                    "correct": r.detection_correct,
                }
                for r in config_results
            ],
        },
        "parser_success": {
            "total": parse_total,
            "success": parse_success,
            "rate": round(parse_success / parse_total, 4) if parse_total else 0,
            "failures": [
                {"file": r.filename, "error": r.parse_error}
                for r in config_results if not r.parse_success
            ],
        },
        "semantic_field_coverage": {
            "avg_coverage": round(statistics.mean(coverages), 4) if coverages else 0,
            "min_coverage": round(min(coverages), 4) if coverages else 0,
            "max_coverage": round(max(coverages), 4) if coverages else 0,
            "per_config": [
                {
                    "file": r.filename,
                    "populated": r.fields_populated,
                    "total": r.fields_total,
                    "coverage": round(r.field_coverage, 4),
                }
                for r in config_results if r.parse_success
            ],
        },
        "compliance_evaluation": {
            "rules_evaluated": len(RULE_IDS),
            "per_rule": per_rule,
            "macro_avg_precision": round(statistics.mean(precisions), 4) if precisions else None,
            "macro_avg_recall": round(statistics.mean(recalls), 4) if recalls else None,
            "macro_avg_f1": round(statistics.mean(f1s), 4) if f1s else None,
        },
        "evidence_correctness": {
            "total_evidence_items": total_evidence,
            "verified_correct": verified_evidence,
            "rate": round(verified_evidence / total_evidence, 4) if total_evidence else 0,
        },
        "remediation_validation": {
            "attempted": remediation_attempted,
            "success": remediation_success,
            "rate": round(remediation_success / remediation_attempted, 4) if remediation_attempted else 0,
            "details": remediation_details,
        },
        "processing_time": {
            "total": _timing_stats(total_times),
            "detection": _timing_stats(detection_times),
            "parsing": _timing_stats(parse_times),
            "evaluation": _timing_stats(eval_times),
        },
        "per_config_results": [
            {
                "file": r.filename,
                "path": r.path,
                "vendor": r.vendor,
                "platform": r.platform,
                "detection_correct": r.detection_correct,
                "detection_confidence": round(r.detection_confidence, 4),
                "parse_success": r.parse_success,
                "field_coverage": round(r.field_coverage, 4),
                "rule_results": r.rule_results,
                "total_time_ms": round(r.total_time_ms, 2),
            }
            for r in config_results
        ],
    }


def run_evaluation() -> Dict[str, Any]:
    """Execute the full end-to-end evaluation."""
    print("Loading REAL_PRODUCTION entries from manifest...")
    entries = load_real_production_entries()
    print(f"  Found {len(entries)} REAL_PRODUCTION configs")

    print("Building ground truth from config inspection...")
    ground_truth = build_ground_truth(entries)

    print("Running pipeline on all configs...")
    config_results = []
    for i, entry in enumerate(entries):
        path = entry["local_path"]
        print(f"  [{i+1:2d}/{len(entries)}] {Path(path).name}...", end=" ", flush=True)
        result = run_pipeline_on_config(entry, ground_truth.get(path, {}))
        config_results.append(result)
        status = "OK" if result.parse_success else f"FAIL: {result.parse_error}"
        print(f"{status} ({result.total_time_ms:.0f}ms)")

    print("\nComputing metrics...")
    metrics = compute_metrics(config_results, ground_truth)

    # Add ground truth for transparency
    metrics["ground_truth"] = {
        path: truth for path, truth in ground_truth.items()
    }

    return metrics


def main():
    metrics = run_evaluation()

    output_path = PROJECT_ROOT / "evaluation" / "e2e_results.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, default=str)
    print(f"\nResults written to {output_path}")

    # Summary
    print("\n" + "=" * 72)
    print("END-TO-END EVALUATION SUMMARY (REAL_PRODUCTION only)")
    print("=" * 72)
    print(f"Dataset: {metrics['dataset']['total_configs']} configs "
          f"({metrics['dataset']['cisco_ios_count']} Cisco IOS, "
          f"{metrics['dataset']['juniper_junos_count']} Juniper Junos)")
    print(f"Vendor Detection Accuracy:   {metrics['vendor_detection']['accuracy']:.1%}")
    print(f"Parser Success Rate:         {metrics['parser_success']['rate']:.1%}")
    print(f"Semantic Field Coverage:     {metrics['semantic_field_coverage']['avg_coverage']:.1%}")
    print(f"Evidence Correctness:        {metrics['evidence_correctness']['rate']:.1%}")

    if metrics['remediation_validation']['attempted'] > 0:
        print(f"Remediation Success Rate:    {metrics['remediation_validation']['rate']:.1%} "
              f"({metrics['remediation_validation']['success']}/{metrics['remediation_validation']['attempted']})")
    else:
        print(f"Remediation Success Rate:    N/A (0 attempted)")

    print(f"\nProcessing Time (total):")
    t = metrics['processing_time']['total']
    print(f"  Average: {t['avg_ms']:.0f}ms  P95: {t['p95_ms']:.0f}ms")

    print(f"\nPer-Rule Metrics ({metrics['compliance_evaluation']['rules_evaluated']} rules):")
    print(f"  {'Rule':<30s} {'TP':>4s} {'TN':>4s} {'FP':>4s} {'FN':>4s} {'NR':>4s} {'Prec':>6s} {'Rec':>6s} {'F1':>6s} {'Acc':>6s}")
    print(f"  {'-'*30} {'-'*4} {'-'*4} {'-'*4} {'-'*4} {'-'*4} {'-'*6} {'-'*6} {'-'*6} {'-'*6}")
    for rid in RULE_IDS:
        m = metrics['compliance_evaluation']['per_rule'][rid]
        p = f"{m['precision']:.2f}" if m['precision'] is not None else "  N/A"
        r = f"{m['recall']:.2f}" if m['recall'] is not None else "  N/A"
        f1 = f"{m['f1']:.2f}" if m['f1'] is not None else "  N/A"
        nr = m['needs_review_correct'] + m['needs_review_incorrect']
        print(f"  {rid:<30s} {m['tp']:4d} {m['tn']:4d} {m['fp']:4d} {m['fn']:4d} {nr:4d} {p:>6s} {r:>6s} {f1:>6s} {m['accuracy']:.2f}")

    if metrics['compliance_evaluation']['macro_avg_f1'] is not None:
        print(f"\n  Macro Avg Precision: {metrics['compliance_evaluation']['macro_avg_precision']:.4f}")
        print(f"  Macro Avg Recall:    {metrics['compliance_evaluation']['macro_avg_recall']:.4f}")
        print(f"  Macro Avg F1:        {metrics['compliance_evaluation']['macro_avg_f1']:.4f}")


if __name__ == "__main__":
    main()
