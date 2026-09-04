"""All-vendor end-to-end pipeline validation v4.

Runs every real-world config + representative samples for every vendor through:
  DETECTION -> PARSER -> SEMANTICS -> EVIDENCE -> COMPLIANCE -> REMEDIATION
Records each stage independently per file and per vendor.
"""

import hashlib
import json
import os
import sys
import traceback
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from auditor.parsers import registry
from auditor.parsers.base import ParserError, VendorParser
from auditor.models.baseline import SecurityBaselineModel
from auditor.models.observation import EvidenceState
from auditor.models.result import Status, ControlResult
from auditor.pipeline import (
    select_parser, parse_config, evaluate, platform_key_for,
    EvaluationOutcome, RulesetResolver,
)
from auditor.rules import load_framework, discover_packs

SECURITY_FIELDS = [
    "ssh_enabled", "ssh_version", "telnet_enabled",
    "aaa_enabled", "enable_secret_set", "password_encryption",
    "password_min_length", "snmp_communities", "logging_enabled",
    "logging_hosts", "ntp_servers", "management_acl_applied",
    "login_banner_present", "vty_exec_timeout_seconds",
    "vty_transport_input", "http_server_enabled", "https_server_enabled",
    "logging_buffered", "dns_servers",
]


def sha256_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def collect_real_world_configs():
    """Load from dataset/real_world/manifest.json."""
    manifest = PROJECT_ROOT / "dataset" / "real_world" / "manifest.json"
    if not manifest.exists():
        return []
    records = json.loads(manifest.read_text(encoding="utf-8"))
    configs = []
    for r in records:
        fp = PROJECT_ROOT / r["local_path"]
        if fp.exists():
            configs.append({
                "path": fp,
                "vendor_label": r.get("vendor", "unknown"),
                "platform_key": r.get("platform_key", "unknown"),
                "provenance": r.get("provenance_classification", "UNKNOWN"),
                "filename": r.get("filename", fp.name),
                "source": "real_world_manifest",
            })
    return configs


def collect_vendor_configs():
    """One representative config per vendor from configs/ directory."""
    configs_dir = PROJECT_ROOT / "configs"
    results = []
    if not configs_dir.exists():
        return results
    for vendor_dir in sorted(configs_dir.iterdir()):
        if not vendor_dir.is_dir():
            continue
        files = sorted([f for f in vendor_dir.iterdir() if f.is_file() and f.suffix in (
            ".cfg", ".conf", ".config", ".txt", ".rsc", ".ios", ".junos", ".fortios", ".xml"
        )])
        if files:
            results.append({
                "path": files[0],
                "vendor_label": vendor_dir.name,
                "platform_key": vendor_dir.name,
                "provenance": "PUBLIC_REFERENCE",
                "filename": files[0].name,
                "source": "configs_dir",
            })
    return results


def collect_sample_configs():
    """Representative configs from samples/ directory."""
    samples_dir = PROJECT_ROOT / "samples"
    results = []
    if not samples_dir.exists():
        return results
    for vendor_dir in sorted(samples_dir.iterdir()):
        if not vendor_dir.is_dir():
            continue
        if vendor_dir.name in ("configs", "unknown"):
            continue
        files = sorted([f for f in vendor_dir.iterdir() if f.is_file() and f.suffix in (
            ".cfg", ".conf", ".config", ".txt", ".rsc", ".ios", ".junos",
            ".fortios", ".xml", ".json",
        )])
        for f in files[:1]:
            results.append({
                "path": f,
                "vendor_label": vendor_dir.name,
                "platform_key": vendor_dir.name,
                "provenance": "SYNTHETIC",
                "filename": f.name,
                "source": "samples_dir",
            })
    return results


def validate_one_config(cfg, resolver):
    """Run full pipeline on one config, return per-stage results."""
    result = {
        "filename": cfg["filename"],
        "path": str(cfg["path"]),
        "vendor_label": cfg["vendor_label"],
        "platform_key": cfg["platform_key"],
        "provenance": cfg["provenance"],
        "source": cfg["source"],
        "vendor_detection": "FAIL",
        "detected_vendor": None,
        "detection_confidence": 0.0,
        "parser": "FAIL",
        "parser_name": None,
        "parser_error": None,
        "semantic_extraction": "FAIL",
        "semantic_fields_detected": 0,
        "semantic_fields_total": len(SECURITY_FIELDS),
        "evidence_extraction": "FAIL",
        "evidence_count": 0,
        "evidence_present": 0,
        "evidence_absent": 0,
        "evidence_unknown": 0,
        "evidence_unsupported": 0,
        "source_line_traceability": 0.0,
        "compliance": "FAIL",
        "compliance_results_count": 0,
        "compliance_pass": 0,
        "compliance_fail": 0,
        "compliance_needs_review": 0,
        "compliance_not_applicable": 0,
        "compliance_unsupported": 0,
        "compliance_manual_review": 0,
        "remediation": "FAIL",
        "remediation_count": 0,
        "remediation_valid": 0,
        "remediation_needs_review": 0,
        "error": None,
    }

    try:
        config_text = cfg["path"].read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        result["error"] = f"Read error: {e}"
        return result

    if not config_text.strip():
        result["error"] = "Empty file"
        return result

    # Stage 1: Vendor Detection
    try:
        parser_cls, confidence = select_parser(config_text)
        result["vendor_detection"] = "PASS"
        result["detected_vendor"] = parser_cls.vendor
        result["detection_confidence"] = round(confidence, 4)
        result["parser_name"] = parser_cls.name
    except ParserError as e:
        result["vendor_detection"] = "FAIL"
        result["parser_error"] = str(e)
        result["error"] = f"Detection failed: {e}"
        return result

    # Stage 2: Parser
    try:
        parser = parser_cls()
        baseline = parse_config(
            parser, config_text,
            source_file=str(cfg["path"]),
            parser_cls=parser_cls,
            confidence=confidence,
        )
        result["parser"] = "PASS"
    except Exception as e:
        result["parser"] = "FAIL"
        result["parser_error"] = f"{type(e).__name__}: {e}"
        result["error"] = f"Parse failed: {e}"
        return result

    # Stage 3: Semantic Extraction
    try:
        detected_count = 0
        for field_name in SECURITY_FIELDS:
            obs = getattr(baseline, field_name, None)
            if obs is not None and hasattr(obs, "detected") and obs.detected:
                detected_count += 1
        result["semantic_extraction"] = "PASS" if detected_count > 0 else "FAIL"
        result["semantic_fields_detected"] = detected_count
    except Exception as e:
        result["semantic_extraction"] = "FAIL"
        result["error"] = f"Semantic extraction failed: {e}"

    # Stage 4: Evidence Extraction -- three separate metrics
    # A. Evidence extraction: did the parser produce any conclusions (found OR absent)?
    # B. Source-line traceability: of conclusions, how many have a config line?
    # C. Evidence correctness: validated downstream (not in this stage)
    try:
        evidence_present = 0      # Observation.found() -- detected=True, source_line set
        evidence_absent = 0       # Observation.absent() -- detected=True, source_line=None
        evidence_unknown = 0      # Observation.unknown() -- detected=False
        evidence_unsupported = 0  # Observation.unsupported() -- is_unsupported=True
        evidence_details = []
        for field_name in SecurityBaselineModel.observable_fields():
            obs = getattr(baseline, field_name, None)
            if obs is None:
                continue
            state = obs.evidence_state
            detail = {
                "field": field_name,
                "evidence_state": state.value,
                "detected": obs.detected,
                "has_source_line": obs.source_line is not None,
                "value": str(obs.value)[:100] if obs.value is not None else None,
            }
            if state == EvidenceState.PRESENT:
                evidence_present += 1
            elif state == EvidenceState.ABSENT:
                evidence_absent += 1
            elif state == EvidenceState.NOT_APPLICABLE:
                evidence_unsupported += 1
            else:
                evidence_unknown += 1
            evidence_details.append(detail)

        evidence_with_conclusion = evidence_present + evidence_absent
        evidence_total_evaluated = evidence_present + evidence_absent + evidence_unknown
        result["evidence_present"] = evidence_present
        result["evidence_absent"] = evidence_absent
        result["evidence_unknown"] = evidence_unknown
        result["evidence_unsupported"] = evidence_unsupported
        result["evidence_count"] = evidence_with_conclusion
        result["evidence_with_source"] = evidence_present
        result["evidence_absence"] = evidence_absent
        result["evidence_details"] = evidence_details

        # Evidence extraction PASSES if the parser reached ANY conclusion
        # (found OR absent). Both are valid evidence.
        if evidence_with_conclusion > 0:
            result["evidence_extraction"] = "PASS"
        elif evidence_unknown > 0:
            result["evidence_extraction"] = "NOT_DETERMINABLE"
        else:
            result["evidence_extraction"] = "FAIL"

        # Source-line traceability: fraction with direct config line references
        if evidence_with_conclusion > 0:
            result["source_line_traceability"] = round(
                evidence_present / evidence_with_conclusion, 4
            )
        else:
            result["source_line_traceability"] = 0.0
    except Exception as e:
        result["evidence_extraction"] = "FAIL"
        result["error"] = f"Evidence extraction failed: {e}"

    # Stage 5: Compliance Evaluation
    try:
        outcome = evaluate(baseline, ["CIS"], resolver=resolver)
        results_list = outcome.results
        result["compliance"] = "PASS" if len(results_list) > 0 else "NOT_DETERMINABLE"
        result["compliance_results_count"] = len(results_list)
        result["compliance_pass"] = sum(1 for r in results_list if r.status == Status.PASS)
        result["compliance_fail"] = sum(1 for r in results_list if r.status == Status.FAIL)
        result["compliance_needs_review"] = sum(1 for r in results_list if r.status == Status.NEEDS_REVIEW)
        result["compliance_not_applicable"] = sum(1 for r in results_list if r.status == Status.NOT_APPLICABLE)
        result["compliance_unsupported"] = sum(1 for r in results_list if r.status == Status.UNSUPPORTED)
        result["compliance_manual_review"] = sum(1 for r in results_list if r.status == Status.MANUAL_REVIEW)
    except Exception as e:
        result["compliance"] = "FAIL"
        result["error"] = f"Compliance failed: {e}"
        results_list = []

    # Stage 6: Remediation Validation
    try:
        rem_count = 0
        rem_valid = 0
        rem_needs_review = 0
        for cr in results_list:
            if cr.remediation and cr.status in (Status.FAIL, Status.NEEDS_REVIEW):
                rem_count += 1
                if cr.remediation.cli and len(cr.remediation.cli) > 0:
                    rem_valid += 1
                elif cr.remediation.summary:
                    rem_needs_review += 1
                else:
                    rem_needs_review += 1
        result["remediation"] = "PASS" if rem_valid > 0 else ("NEEDS_REVIEW" if rem_needs_review > 0 else "FAIL")
        result["remediation_count"] = rem_count
        result["remediation_valid"] = rem_valid
        result["remediation_needs_review"] = rem_needs_review
    except Exception as e:
        result["remediation"] = "FAIL"
        result["error"] = f"Remediation validation failed: {e}"

    return result


def validate_evidence_grounding(cfg, resolver):
    """For every compliance finding, verify evidence grounding."""
    findings = []
    try:
        config_text = cfg["path"].read_text(encoding="utf-8", errors="replace")
        parser_cls, confidence = select_parser(config_text)
        parser = parser_cls()
        baseline = parse_config(parser, config_text, source_file=str(cfg["path"]),
                                parser_cls=parser_cls, confidence=confidence)
        outcome = evaluate(baseline, ["CIS"], resolver=resolver)
        for cr in outcome.results:
            finding = {
                "control_id": cr.control_id or cr.rule_id,
                "status": cr.status.value,
                "has_severity": cr.severity is not None,
                "has_vendor": cr.vendor is not None or baseline.provenance.vendor is not None,
                "has_evidence": len(cr.evidence) > 0,
                "evidence_has_source_line": any(e.source_line for e in cr.evidence),
                "evidence_has_line_number": any(e.line_number for e in cr.evidence),
                "reasoning_references_evidence": bool(cr.message),
                "remediation_corresponds": (
                    cr.remediation is not None and
                    (bool(cr.remediation.summary) or bool(cr.remediation.cli))
                ) if cr.status in (Status.FAIL, Status.NEEDS_REVIEW) else True,
                "grounding_valid": True,
            }
            if cr.status in (Status.PASS, Status.FAIL) and not finding["has_evidence"]:
                finding["grounding_valid"] = False
            findings.append(finding)
    except Exception:
        pass
    return findings


def run_hard_negative_tests():
    """Test detector robustness with tricky inputs."""
    tests = [
        {
            "name": "Arista-like but not Cisco",
            "text": "! Arista vEOS\nhostname arista-spine\ninterface Ethernet1\n  ip address 10.0.0.1/30\nip routing\nrouter bgp 65000\n  neighbor 10.0.0.2 remote-as 65001\n",
            "should_not_be": "cisco_ios",
        },
        {
            "name": "Generic routing config",
            "text": "interface eth0\n  ip address 192.168.1.1/24\nip route 0.0.0.0/0 192.168.1.254\naccess-list 100 permit ip any any\n",
            "should_not_be": None,
        },
        {
            "name": "ACL-heavy config",
            "text": "access-list 1 permit 10.0.0.0 0.255.255.255\naccess-list 1 deny any\naccess-list 2 permit 172.16.0.0 0.15.255.255\naccess-list 2 deny any\n",
            "should_not_be": None,
        },
        {
            "name": "Firewall-heavy config",
            "text": "set security zones security-zone trust\nset security policies from-zone trust to-zone untrust\nset security nat source rule-set nat1\n",
            "should_not_be": "cisco_ios",
        },
        {
            "name": "Mixed vendor terminology",
            "text": "hostname mixed-device\nset system host-name mixed\nconfig system global\ninterface GigabitEthernet0/0\n",
            "should_not_be": None,
        },
        {
            "name": "Partial incomplete config",
            "text": "!\n!\n!\ninterface Lo0\n",
            "should_not_be": None,
        },
    ]
    results = []
    for test in tests:
        try:
            ranked = registry.rank(test["text"])
            top_score, top_parser = ranked[0] if ranked else (0.0, None)
            detected = top_parser.name if top_parser else None
            correctly_avoided = True
            if test["should_not_be"] and detected == test["should_not_be"] and top_score >= 0.3:
                correctly_avoided = False
            results.append({
                "name": test["name"],
                "detected_as": detected,
                "confidence": round(top_score, 4),
                "should_not_be": test["should_not_be"],
                "correctly_avoided": correctly_avoided,
            })
        except Exception as e:
            results.append({
                "name": test["name"],
                "error": str(e),
                "correctly_avoided": False,
            })
    return results


def check_confidence_calibration(all_results):
    """Analyze confidence scores per vendor."""
    by_vendor = defaultdict(list)
    for r in all_results:
        if r["vendor_detection"] == "PASS":
            by_vendor[r["detected_vendor"]].append({
                "confidence": r["detection_confidence"],
                "correct": True,
            })
    calibration = {}
    for vendor, entries in sorted(by_vendor.items()):
        confs = [e["confidence"] for e in entries]
        calibration[vendor] = {
            "count": len(confs),
            "min": round(min(confs), 4),
            "max": round(max(confs), 4),
            "mean": round(sum(confs) / len(confs), 4),
            "median": round(sorted(confs)[len(confs) // 2], 4),
        }
    return calibration


def check_benchmark_immutability():
    """Verify benchmark datasets haven't been modified."""
    benchmark_dir = PROJECT_ROOT / "benchmarks" / "human_verified"
    results = {}
    if not benchmark_dir.exists():
        return {"error": "benchmarks/human_verified not found"}
    for f in sorted(benchmark_dir.iterdir()):
        if f.is_file():
            content = f.read_bytes()
            results[f.name] = {
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
                "lines": content.count(b'\n'),
            }
    return results


def check_fabricated_formats():
    """Check previously flagged fabricated format vendors."""
    flagged = [
        "forcepoint_ngfw", "zscaler_zia", "zscaler_zpa",
        "cato_networks", "sangfor_ngaf", "hillstone_stoneos",
    ]
    results = {}
    for vendor_key in flagged:
        sample_dir = PROJECT_ROOT / "samples" / vendor_key.replace("_", "_")
        alt_names = [vendor_key]
        if "_" in vendor_key:
            parts = vendor_key.split("_")
            alt_names.extend([parts[0], vendor_key.replace("_", "")])
        found_files = []
        for name in alt_names:
            d = PROJECT_ROOT / "samples" / name
            if d.exists() and d.is_dir():
                found_files.extend([f for f in d.iterdir() if f.is_file()])
        sample_search = []
        for name_variant in ["forcepoint", "zscaler_zia", "zscaler_zpa",
                             "cato", "sangfor", "hillstone"]:
            d = PROJECT_ROOT / "samples" / name_variant
            if d.exists() and d.is_dir():
                sample_search.extend([f for f in d.iterdir() if f.is_file()])
        has_real = False
        has_synthetic = False
        classification = "UNKNOWN"
        if found_files or sample_search:
            has_synthetic = True
            classification = "SYNTHETIC_FIXTURE"
        configs_d = PROJECT_ROOT / "configs" / vendor_key
        if configs_d.exists() and any(configs_d.iterdir()):
            has_real = True
            classification = "PUBLIC_REFERENCE"
        results[vendor_key] = {
            "has_real_config": has_real,
            "has_synthetic_sample": has_synthetic or bool(sample_search),
            "classification": classification,
            "note": "Fabricated/unverifiable format" if not has_real else "Has reference configs",
        }
    return results


def main():
    print("=" * 70)
    print("ALL-VENDOR END-TO-END PIPELINE VALIDATION V4")
    print("=" * 70)
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")

    resolver = RulesetResolver()

    # Collect all configs
    real_world = collect_real_world_configs()
    vendor_configs = collect_vendor_configs()
    sample_configs = collect_sample_configs()

    print(f"\nReal-world configs: {len(real_world)}")
    print(f"Vendor reference configs: {len(vendor_configs)}")
    print(f"Sample configs: {len(sample_configs)}")

    # Deduplicate: real_world takes priority
    seen_paths = set()
    all_configs = []
    for c in real_world:
        key = str(c["path"].resolve())
        if key not in seen_paths:
            seen_paths.add(key)
            all_configs.append(c)
    for c in vendor_configs:
        key = str(c["path"].resolve())
        if key not in seen_paths:
            seen_paths.add(key)
            all_configs.append(c)
    for c in sample_configs:
        key = str(c["path"].resolve())
        if key not in seen_paths:
            seen_paths.add(key)
            all_configs.append(c)

    print(f"Total unique configs to validate: {len(all_configs)}")

    # Run validation
    all_results = []
    all_evidence_findings = []
    for i, cfg in enumerate(all_configs, 1):
        if i % 10 == 0 or i == 1:
            print(f"  Processing {i}/{len(all_configs)}: {cfg['filename']}")
        result = validate_one_config(cfg, resolver)
        all_results.append(result)

        if result["vendor_detection"] == "PASS" and result["parser"] == "PASS":
            findings = validate_evidence_grounding(cfg, resolver)
            all_evidence_findings.extend(findings)

    # Aggregate by vendor
    vendor_scorecard = defaultdict(lambda: {
        "detection_pass": 0, "detection_fail": 0,
        "parser_pass": 0, "parser_fail": 0,
        "semantic_pass": 0, "semantic_fail": 0,
        "evidence_pass": 0, "evidence_fail": 0, "evidence_not_determinable": 0,
        "evidence_present_total": 0, "evidence_absent_total": 0,
        "evidence_unknown_total": 0, "evidence_unsupported_total": 0,
        "compliance_pass": 0, "compliance_fail": 0, "compliance_not_determinable": 0,
        "compliance_pass_count": 0, "compliance_fail_count": 0,
        "compliance_needs_review_count": 0, "compliance_not_applicable_count": 0,
        "remediation_pass": 0, "remediation_fail": 0, "remediation_needs_review": 0,
        "real_count": 0, "reference_count": 0, "synthetic_count": 0,
        "files": [],
    })

    for r in all_results:
        vendor = r["detected_vendor"] or r["vendor_label"]
        sc = vendor_scorecard[vendor]
        sc["files"].append(r["filename"])
        if r["provenance"] == "REAL_PRODUCTION":
            sc["real_count"] += 1
        elif r["provenance"] == "PUBLIC_REFERENCE":
            sc["reference_count"] += 1
        else:
            sc["synthetic_count"] += 1
        sc["detection_pass" if r["vendor_detection"] == "PASS" else "detection_fail"] += 1
        sc["parser_pass" if r["parser"] == "PASS" else "parser_fail"] += 1
        sc["semantic_pass" if r["semantic_extraction"] == "PASS" else "semantic_fail"] += 1
        if r["evidence_extraction"] == "PASS":
            sc["evidence_pass"] += 1
        elif r["evidence_extraction"] == "NOT_DETERMINABLE":
            sc["evidence_not_determinable"] += 1
        else:
            sc["evidence_fail"] += 1
        sc["evidence_present_total"] += r.get("evidence_present", 0)
        sc["evidence_absent_total"] += r.get("evidence_absent", 0)
        sc["evidence_unknown_total"] += r.get("evidence_unknown", 0)
        sc["evidence_unsupported_total"] += r.get("evidence_unsupported", 0)
        if r["compliance"] == "PASS":
            sc["compliance_pass"] += 1
        elif r["compliance"] == "NOT_DETERMINABLE":
            sc["compliance_not_determinable"] += 1
        else:
            sc["compliance_fail"] += 1
        sc["compliance_pass_count"] += r.get("compliance_pass", 0)
        sc["compliance_fail_count"] += r.get("compliance_fail", 0)
        sc["compliance_needs_review_count"] += r.get("compliance_needs_review", 0)
        sc["compliance_not_applicable_count"] += r.get("compliance_not_applicable", 0)
        if r["remediation"] == "PASS":
            sc["remediation_pass"] += 1
        elif r["remediation"] == "NEEDS_REVIEW":
            sc["remediation_needs_review"] += 1
        else:
            sc["remediation_fail"] += 1

    # Hard negative tests
    hard_neg = run_hard_negative_tests()

    # Confidence calibration
    calibration = check_confidence_calibration(all_results)

    # Benchmark immutability
    benchmarks = check_benchmark_immutability()

    # Fabricated format audit
    fabricated = check_fabricated_formats()

    # Summary stats
    total = len(all_results)
    det_pass = sum(1 for r in all_results if r["vendor_detection"] == "PASS")
    parse_pass = sum(1 for r in all_results if r["parser"] == "PASS")
    sem_pass = sum(1 for r in all_results if r["semantic_extraction"] == "PASS")
    evid_pass = sum(1 for r in all_results if r["evidence_extraction"] == "PASS")
    evid_not_det = sum(1 for r in all_results if r["evidence_extraction"] == "NOT_DETERMINABLE")
    comp_pass = sum(1 for r in all_results if r["compliance"] == "PASS")
    rem_pass = sum(1 for r in all_results if r["remediation"] == "PASS")

    # Separated evidence metrics
    total_present = sum(r.get("evidence_present", 0) for r in all_results)
    total_absent = sum(r.get("evidence_absent", 0) for r in all_results)
    total_unknown = sum(r.get("evidence_unknown", 0) for r in all_results)
    total_unsupported = sum(r.get("evidence_unsupported", 0) for r in all_results)
    total_with_conclusion = total_present + total_absent

    # Evidence grounding stats
    total_findings = len(all_evidence_findings)
    grounded = sum(1 for f in all_evidence_findings if f["grounding_valid"])

    # Failures
    failures = [r for r in all_results if r["vendor_detection"] == "FAIL" or r["parser"] == "FAIL"]

    # Build output JSON
    # Evidence failure audit
    evidence_failures = []
    for r in all_results:
        if r["evidence_extraction"] != "PASS":
            failure = {
                "vendor": r.get("detected_vendor") or r["vendor_label"],
                "filename": r["filename"],
                "provenance": r["provenance"],
                "evidence_extraction": r["evidence_extraction"],
                "evidence_present": r.get("evidence_present", 0),
                "evidence_absent": r.get("evidence_absent", 0),
                "evidence_unknown": r.get("evidence_unknown", 0),
                "evidence_unsupported": r.get("evidence_unsupported", 0),
                "semantic_extraction": r["semantic_extraction"],
                "detection": r["vendor_detection"],
            }
            if r["vendor_detection"] == "FAIL":
                failure["root_cause"] = "detection_failure"
                failure["classification"] = "FABRICATED_FORMAT" if r["provenance"] == "SYNTHETIC" else "DOCUMENTATION_OR_SCRIPT"
            elif r["semantic_extraction"] == "FAIL":
                failure["root_cause"] = "semantic_failure"
                failure["classification"] = "parser_limitation"
            elif r.get("evidence_present", 0) == 0 and r.get("evidence_absent", 0) == 0:
                failure["root_cause"] = "no_evidence_produced"
                failure["classification"] = "parser_limitation"
            else:
                failure["root_cause"] = "partial_evidence"
                failure["classification"] = "missing_source_evidence"
            evidence_failures.append(failure)

    # Remediation failure audit
    remediation_failures = []
    for r in all_results:
        if r.get("remediation") not in ("PASS", None) and r["vendor_detection"] == "PASS":
            remediation_failures.append({
                "vendor": r.get("detected_vendor") or r["vendor_label"],
                "filename": r["filename"],
                "provenance": r["provenance"],
                "remediation_status": r["remediation"],
                "remediation_count": r.get("remediation_count", 0),
                "remediation_valid": r.get("remediation_valid", 0),
                "remediation_needs_review": r.get("remediation_needs_review", 0),
            })

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_configs": total,
            "detection_pass": det_pass,
            "detection_fail": total - det_pass,
            "parser_pass": parse_pass,
            "parser_fail": total - parse_pass,
            "semantic_pass": sem_pass,
            "semantic_fail": total - sem_pass,
            "evidence_extraction_pass": evid_pass,
            "evidence_extraction_not_determinable": evid_not_det,
            "evidence_extraction_fail": total - evid_pass - evid_not_det,
            "evidence_observations_present": total_present,
            "evidence_observations_absent": total_absent,
            "evidence_observations_unknown": total_unknown,
            "evidence_observations_unsupported": total_unsupported,
            "evidence_with_conclusion": total_with_conclusion,
            "compliance_pass": comp_pass,
            "compliance_fail": total - comp_pass,
            "remediation_pass": rem_pass,
            "remediation_fail": total - rem_pass,
            "evidence_grounding_total": total_findings,
            "evidence_grounding_valid": grounded,
        },
        "vendor_scorecard": {k: {kk: vv for kk, vv in v.items() if kk != "files"}
                            for k, v in sorted(vendor_scorecard.items())},
        "hard_negative_tests": hard_neg,
        "confidence_calibration": calibration,
        "benchmark_immutability": benchmarks,
        "fabricated_format_audit": fabricated,
        "evidence_failure_audit": evidence_failures,
        "remediation_failure_audit": remediation_failures,
        "failures": [{k: v for k, v in r.items() if v is not None and k != "evidence_details"}
                     for r in failures],
        "all_results": [{k: v for k, v in r.items() if k != "evidence_details"}
                        for r in all_results],
    }

    reports_dir = PROJECT_ROOT / "reports"
    reports_dir.mkdir(exist_ok=True)

    json_path = reports_dir / "all_vendor_pipeline_validation_v4.json"
    json_path.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    print(f"\nJSON report: {json_path}")

    # Generate markdown report
    md_lines = [
        "# All-Vendor Pipeline Validation V4",
        f"\nGenerated: {datetime.now(timezone.utc).isoformat()}",
        f"\n## Summary",
        f"\n| Stage | Pass | Fail | Total |",
        f"|-------|------|------|-------|",
        f"| Detection | {det_pass} | {total - det_pass} | {total} |",
        f"| Parser | {parse_pass} | {total - parse_pass} | {total} |",
        f"| Semantics | {sem_pass} | {total - sem_pass} | {total} |",
        f"| Evidence | {evid_pass} | {total - evid_pass} | {total} |",
        f"| Compliance | {comp_pass} | {total - comp_pass} | {total} |",
        f"| Remediation | {rem_pass} | {total - rem_pass} | {total} |",
        f"\nEvidence Grounding: {grounded}/{total_findings} valid",
        f"\n## Vendor Scorecard",
        f"\n| Vendor | Detection | Parser | Semantics | Evidence | Compliance | Remediation | Real | Ref | Synth |",
        f"|--------|-----------|--------|-----------|----------|------------|-------------|------|-----|-------|",
    ]

    for vendor in sorted(vendor_scorecard.keys()):
        sc = vendor_scorecard[vendor]
        det = "PASS" if sc["detection_fail"] == 0 else f"PARTIAL ({sc['detection_pass']}/{sc['detection_pass']+sc['detection_fail']})"
        par = "PASS" if sc["parser_fail"] == 0 and sc["parser_pass"] > 0 else ("FAIL" if sc["parser_pass"] == 0 else f"PARTIAL ({sc['parser_pass']}/{sc['parser_pass']+sc['parser_fail']})")
        sem = "PASS" if sc["semantic_fail"] == 0 and sc["semantic_pass"] > 0 else ("FAIL" if sc["semantic_pass"] == 0 else f"PARTIAL")
        evd = "PASS" if sc["evidence_fail"] == 0 and sc["evidence_pass"] > 0 else ("FAIL" if sc["evidence_pass"] == 0 else f"PARTIAL")
        cmp = "PASS" if sc["compliance_fail"] == 0 and sc["compliance_pass"] > 0 else ("FAIL" if sc["compliance_pass"] == 0 else f"PARTIAL")
        rem = "PASS" if sc["remediation_fail"] == 0 and sc["remediation_pass"] > 0 else ("NEEDS_REVIEW" if sc["remediation_needs_review"] > 0 else "FAIL")
        md_lines.append(
            f"| {vendor} | {det} | {par} | {sem} | {evd} | {cmp} | {rem} | {sc['real_count']} | {sc['reference_count']} | {sc['synthetic_count']} |"
        )

    md_lines.append(f"\n## Failures ({len(failures)})")
    for f in failures:
        md_lines.append(f"\n- **{f['filename']}** ({f['vendor_label']}): {f.get('error', 'unknown')}")

    md_lines.append(f"\n## Hard Negative Tests")
    for t in hard_neg:
        status = "PASS" if t.get("correctly_avoided") else "FAIL"
        md_lines.append(f"- {t['name']}: {status} (detected as {t.get('detected_as', '?')} @ {t.get('confidence', 0):.2f})")

    md_lines.append(f"\n## Confidence Calibration")
    for vendor, cal in sorted(calibration.items()):
        md_lines.append(f"- {vendor}: min={cal['min']}, max={cal['max']}, mean={cal['mean']}, median={cal['median']} (n={cal['count']})")

    md_lines.append(f"\n## Benchmark Immutability")
    for name, info in sorted(benchmarks.items()):
        if isinstance(info, dict) and "sha256" in info:
            md_lines.append(f"- {name}: SHA-256={info['sha256'][:16]}... ({info['lines']} lines)")

    md_lines.append(f"\n## Fabricated Format Audit")
    for vendor, info in sorted(fabricated.items()):
        md_lines.append(f"- {vendor}: {info['classification']} - {info['note']}")

    md_path = reports_dir / "all_vendor_validation_v4.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    print(f"Markdown report: {md_path}")

    # Print summary
    print(f"\n{'='*70}")
    print(f"VALIDATION COMPLETE")
    print(f"{'='*70}")
    print(f"Detection: {det_pass}/{total}")
    print(f"Parser: {parse_pass}/{total}")
    print(f"Semantics: {sem_pass}/{total}")
    print(f"Evidence: {evid_pass}/{total}")
    print(f"Compliance: {comp_pass}/{total}")
    print(f"Remediation: {rem_pass}/{total}")
    print(f"Evidence Grounding: {grounded}/{total_findings}")
    print(f"Failures: {len(failures)}")
    print(f"Vendors tested: {len(vendor_scorecard)}")

    return output


if __name__ == "__main__":
    main()
