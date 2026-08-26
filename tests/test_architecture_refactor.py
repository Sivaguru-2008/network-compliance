"""Tests for the Pre-Palo-Alto Architecture Refactoring.

This test suite covers:
1. Mapping equivalence (old semantics == new semantics)
2. Field normalization (fortiOS parser populates both admin_tls13_only and management_min_tls_version)
3. Evidence preservation (normalized observations retain source line & line number)
4. Rule loading (rules load correctly from database and mapping)
5. Invalid mapping rejection (malformed mappings raise ValueError)
6. Unknown field rejection (mappings with unknown baseline fields raise ValueError)
7. Duplicate rule detection (mappings with duplicate keys raise ValueError)
8. FortiGate regression (running evaluators yields expected results)
"""

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from auditor.cis.fortigate_map import (
    FORTIGATE_RULE_MAP,
    RuleMapping,
    load_and_validate_mappings,
)
from auditor.cis.loader import load_fortigate_cis_rules
from auditor.cis.schema import EvaluationType
from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers.fortios import FortiosParser
from auditor.pipeline import evaluate_cis_fortigate


SAMPLE_CONFIG = Path(__file__).parents[1] / "samples" / "fortios_fgt.conf"


# ── Test 1: Mapping equivalence ─────────────────────────────────────────────

def test_mapping_equivalence():
    """Verify that all 56 original rules are mapped with the expected types and conditions."""
    assert len(FORTIGATE_RULE_MAP) == 56

    # Verify key deterministic controls are present and mapped as expected
    assert "2.1.10" in FORTIGATE_RULE_MAP
    tls13_map = FORTIGATE_RULE_MAP["2.1.10"]
    assert tls13_map.cis_id == "2.1.10"
    assert tls13_map.baseline_field == "admin_tls13_only"
    assert tls13_map.evaluation_type == EvaluationType.DETERMINISTIC
    assert tls13_map.condition_json == {"field": "admin_tls13_only", "operator": "is_true"}

    assert "2.2.1" in FORTIGATE_RULE_MAP
    pwd_map = FORTIGATE_RULE_MAP["2.2.1"]
    assert pwd_map.cis_id == "2.2.1"
    assert pwd_map.baseline_field == "password_min_length"
    assert pwd_map.evaluation_type == EvaluationType.DETERMINISTIC
    assert pwd_map.condition_json == {"field": "password_min_length", "operator": "greater_or_equal", "value": 8}


# ── Test 2: Field normalization ─────────────────────────────────────────────

def test_field_normalization():
    """Verify that the parser populates both admin_tls13_only and management_min_tls_version."""
    config_text = """
config system global
    set hostname "TEST-FGT-01"
    set admin-https-ssl-versions tlsv1-3
end
"""
    parser = FortiosParser()
    baseline = parser.parse(config_text)

    # Verify both fields are set correctly
    assert baseline.admin_tls13_only.detected is True
    assert baseline.admin_tls13_only.value is True

    assert baseline.management_min_tls_version.detected is True
    assert baseline.management_min_tls_version.value == "1.3"

    # Test with multiple versions allowed
    config_multiple = """
config system global
    set hostname "TEST-FGT-02"
    set admin-https-ssl-versions tlsv1-2 tlsv1-3
end
"""
    baseline_mult = parser.parse(config_multiple)
    assert baseline_mult.admin_tls13_only.detected is True
    assert baseline_mult.admin_tls13_only.value is False

    assert baseline_mult.management_min_tls_version.detected is True
    assert baseline_mult.management_min_tls_version.value == "1.2"


# ── Test 3: Evidence preservation ───────────────────────────────────────────

def test_evidence_preservation():
    """Verify that the source line and line number are correctly attached to normalized observations."""
    config_text = """config system global
    set hostname "TEST-FGT-01"
    set admin-https-ssl-versions tlsv1-3
end
"""
    parser = FortiosParser()
    baseline = parser.parse(config_text)

    # Assert TLS version observations contain exact source line and line number
    obs_tls13 = baseline.admin_tls13_only
    assert obs_tls13.source_line == 'set admin-https-ssl-versions tlsv1-3'
    assert obs_tls13.line_number == 3

    obs_min_tls = baseline.management_min_tls_version
    assert obs_min_tls.source_line == 'set admin-https-ssl-versions tlsv1-3'
    assert obs_min_tls.line_number == 3


# ── Test 4: Rule loading ────────────────────────────────────────────────────

def test_rule_loading():
    """Verify that compliance rules load correctly from the database and declarative mapping."""
    ruleset, non_evaluable = load_fortigate_cis_rules(include_unapproved=True)
    assert ruleset is not None
    assert len(ruleset.rules) == 27
    assert len(non_evaluable) == 29

    # Verify specific rules in the loaded ruleset
    rule_ids = {r.control_ref for r in ruleset.rules}
    assert "2.1.10" in rule_ids
    assert "2.2.1" in rule_ids


# ── Test 5: Invalid mapping rejection ───────────────────────────────────────

def test_invalid_mapping_rejection():
    """Verify that malformed mappings (missing required fields) fail to load."""
    invalid_data = {
        "1.1": {
            "cis_id": "1.1",
            "evaluation_type": "DETERMINISTIC",
            # Missing baseline_field, internal_control, condition_json
        }
    }
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(invalid_data, f)
        temp_path = Path(f.name)

    try:
        with pytest.raises(ValueError, match="missing required keys"):
            load_and_validate_mappings(temp_path)
    finally:
        temp_path.unlink()


# ── Test 6: Unknown field rejection ─────────────────────────────────────────

def test_unknown_field_rejection():
    """Verify that referencing a nonexistent field in SecurityBaselineModel throws ValueError."""
    invalid_field_data = {
        "1.1": {
            "cis_id": "1.1",
            "baseline_field": "nonexistent_field_xyz",
            "internal_control": "dns_configured",
            "evaluation_type": "DETERMINISTIC",
            "condition_json": {
                "field": "nonexistent_field_xyz",
                "operator": "is_not_empty"
            },
            "gap_note": ""
        }
    }
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        json.dump(invalid_field_data, f)
        temp_path = Path(f.name)

    try:
        with pytest.raises(ValueError, match="Unknown baseline field 'nonexistent_field_xyz'"):
            load_and_validate_mappings(temp_path)
    finally:
        temp_path.unlink()


# ── Test 7: Duplicate rule detection ────────────────────────────────────────

def test_duplicate_rule_detection():
    """Verify that defining duplicate rule IDs in mapping JSON raises ValueError."""
    # JSON standard allows duplicate keys, but our custom hook rejects them
    duplicate_json_str = """
{
  "1.1": {
    "cis_id": "1.1",
    "baseline_field": "dns_servers",
    "internal_control": "dns_configured",
    "evaluation_type": "DETERMINISTIC",
    "condition_json": {"field": "dns_servers", "operator": "is_not_empty"}
  },
  "1.1": {
    "cis_id": "1.1",
    "baseline_field": "dns_servers",
    "internal_control": "dns_configured",
    "evaluation_type": "DETERMINISTIC",
    "condition_json": {"field": "dns_servers", "operator": "is_not_empty"}
  }
}
"""
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        f.write(duplicate_json_str)
        temp_path = Path(f.name)

    try:
        with pytest.raises(ValueError, match="Duplicate rule ID found in mapping: 1.1"):
            load_and_validate_mappings(temp_path)
    finally:
        temp_path.unlink()


# ── Test 8: FortiGate regression ────────────────────────────────────────────

def test_fortigate_regression():
    """Verify that evaluate_cis_fortigate behaves identically to the pre-refactor state."""
    config_text = SAMPLE_CONFIG.read_text(encoding="utf-8")
    parser = FortiosParser()
    baseline = parser.parse(config_text, source_file=str(SAMPLE_CONFIG))
    report = evaluate_cis_fortigate(baseline)

    # Check totals
    assert report.summary.total == 56
    assert report.summary.passed == 3
    assert report.summary.failed == 16
    assert report.summary.needs_review == 8
    assert report.summary.unsupported == 5
    assert report.summary.manual_review == 24
    assert report.summary.not_applicable == 0

    results_by_ref = {r.control_ref: r for r in report.results}
    # Spot-check a few rules
    assert results_by_ref["2.1.5"].status == Status.PASS  # hostname
    assert results_by_ref["2.4.5"].status == Status.FAIL  # telnet/HTTP
    assert results_by_ref["2.1.10"].status == Status.NEEDS_REVIEW  # admin_tls13_only not found
