"""Tests for multi-framework compliance evaluation."""

import pytest
from pathlib import Path
from pydantic import ValidationError
from auditor.models.baseline import SecurityBaselineModel, ParserProvenance
from auditor.models.observation import Observation, Origin
from auditor.models.result import Status, Severity
from auditor.rules import load_framework, RuleLoadError
from auditor.engine import ComplianceEngine
from auditor.training.mappings import LearnedMapping, LearnedMappingStore, resolve_learned_mappings
from auditor.parsers import CiscoIOSParser

@pytest.fixture
def clean_baseline():
    """Returns a completely passing normalized baseline for Cisco IOS."""
    # We can parse the hardened config directly
    from tests.conftest import SAMPLES
    hardened_text = (SAMPLES / "hardened_ios.conf").read_text(encoding="utf-8")
    return CiscoIOSParser().parse(hardened_text, source_file="samples/hardened_ios.conf")

# 1. CIS evaluation
def test_cis_evaluation(clean_baseline):
    ruleset = load_framework("CIS", "cisco_ios")
    engine = ComplianceEngine(ruleset)
    results = engine.evaluate(clean_baseline)
    
    assert len(results) == 13
    for r in results:
        assert r.framework == "CIS"
        assert r.status == Status.PASS

# 2. NIST SP 800-53 evaluation
def test_nist_evaluation(clean_baseline):
    ruleset = load_framework("NIST_800_53", "cisco_ios")
    engine = ComplianceEngine(ruleset)
    results = engine.evaluate(clean_baseline)
    
    assert len(results) == 13
    for r in results:
        assert r.framework == "NIST SP 800-53"
        assert r.status == Status.PASS
        # Mapped to verified NIST controls
        if r.rule_id == "NIST-AC-2":
            assert r.control_ref == "AC-2"
            assert r.verified_ref is True

# 3. STIG evaluation
def test_stig_evaluation(clean_baseline):
    ruleset = load_framework("STIG", "cisco_ios")
    engine = ComplianceEngine(ruleset)
    results = engine.evaluate(clean_baseline)
    
    assert len(results) == 13
    for r in results:
        assert r.framework == "DISA STIG"
        assert r.status == Status.PASS
        # CCI controls
        if r.rule_id == "STIG-CCI-000015":
            assert r.control_ref == "CCI-000015"
            assert r.verified_ref is True

# 4. ISO evaluation
def test_iso_evaluation(clean_baseline):
    ruleset = load_framework("ISO_27001", "cisco_ios")
    engine = ComplianceEngine(ruleset)
    results = engine.evaluate(clean_baseline)
    
    assert len(results) == 13
    for r in results:
        assert r.framework == "ISO/IEC 27001"
        assert r.status == Status.PASS
        # ISO controls
        if r.rule_id == "ISO-A.8.2":
            assert r.control_ref == "A.8.2"
            assert r.verified_ref is True

# 5. multiple frameworks in one audit
def test_multiple_frameworks_in_one_audit(clean_baseline):
    from auditor import cli
    from auditor.models.result import AuditReport
    
    # We can evaluate multiple frameworks and construct a merged report
    # simulating CLI call using mock arguments
    platform_key = "cisco_ios"
    frameworks = ["CIS", "NIST_800_53", "STIG", "ISO_27001"]
    
    all_results = []
    framework_summaries = {}
    
    for fw in frameworks:
        ruleset = load_framework(fw, platform_key)
        engine = ComplianceEngine(ruleset)
        results = engine.evaluate(clean_baseline)
        all_results.extend(results)
        framework_summaries[ruleset.framework] = r_sum = results
        
    assert len(all_results) == 13 * 4
    # All should pass
    assert all(r.status == Status.PASS for r in all_results)

# 6. PASS propagation
def test_pass_propagation(clean_baseline):
    # Proves that a passing value (aaa_enabled = True) propagates to PASS on all 4 frameworks
    clean_baseline.aaa_enabled = Observation[bool].found(True, source_line="aaa new-model", line_number=10)
    
    for fw in ["CIS", "NIST_800_53", "STIG", "ISO_27001"]:
        ruleset = load_framework(fw, "cisco_ios")
        engine = ComplianceEngine(ruleset)
        results = {r.internal_control_id: r for r in engine.evaluate(clean_baseline)}
        assert results["aaa_enabled"].status == Status.PASS

# 7. FAIL propagation
def test_fail_propagation(clean_baseline):
    # Modify a field to FAIL and verify it propagates to FAIL on all 4 frameworks
    clean_baseline.aaa_enabled = Observation[bool].found(False, source_line="no aaa new-model", line_number=10)
    
    for fw in ["CIS", "NIST_800_53", "STIG", "ISO_27001"]:
        ruleset = load_framework(fw, "cisco_ios")
        engine = ComplianceEngine(ruleset)
        results = {r.internal_control_id: r for r in engine.evaluate(clean_baseline)}
        assert results["aaa_enabled"].status == Status.FAIL

# 8. NEEDS_REVIEW propagation
def test_needs_review_propagation(clean_baseline):
    # Modify a field to be undetected (NEEDS_REVIEW) and verify it propagates to NEEDS_REVIEW on all 4 frameworks
    clean_baseline.aaa_enabled = Observation[bool].unknown("AAA status not configured")
    
    for fw in ["CIS", "NIST_800_53", "STIG", "ISO_27001"]:
        ruleset = load_framework(fw, "cisco_ios")
        engine = ComplianceEngine(ruleset)
        results = {r.internal_control_id: r for r in engine.evaluate(clean_baseline)}
        assert results["aaa_enabled"].status == Status.NEEDS_REVIEW

# 9. framework isolation
def test_framework_isolation(clean_baseline):
    # Check that changing the evaluation result/rules of one framework doesn't touch another
    # We will load CIS and NIST rulesets separately. They must not share rule instances or states.
    cis_ruleset = load_framework("CIS", "cisco_ios")
    nist_ruleset = load_framework("NIST_800_53", "cisco_ios")
    
    assert cis_ruleset is not nist_ruleset
    assert cis_ruleset.rules[0] is not nist_ruleset.rules[0]
    
    # Asserting condition changes don't leak
    cis_ruleset.rules[0].condition = None
    assert nist_ruleset.rules[0].condition is not None

# 10. unknown framework rejection
def test_unknown_framework_rejection():
    with pytest.raises(RuleLoadError, match="No rule pack for framework"):
        load_framework("XYZ_FRAMEWORK", "cisco_ios")

# 11. duplicate mapping detection
def test_duplicate_mapping_detection(tmp_path):
    # If a mapping file contains duplicate IDs, it should raise an error at validation/load time
    from auditor.models.rule import RuleSet
    bad_fw_json = tmp_path / "bad_fw.json"
    bad_fw_json.write_text("""{
        "schema_version": "1.0",
        "framework": "BAD",
        "framework_version": "1.0",
        "platform": { "vendor": "cisco", "os_family": "ios" },
        "rules": [
            {
                "id": "DUP-1",
                "title": "title1",
                "description": "desc1",
                "severity": "medium",
                "condition": { "field": "aaa_enabled", "operator": "is_true" },
                "remediation": { "summary": "remedy", "cli": [] },
                "references": ["ref1"]
            },
            {
                "id": "DUP-1",
                "title": "title2",
                "description": "desc2",
                "severity": "medium",
                "condition": { "field": "telnet_enabled", "operator": "is_false" },
                "remediation": { "summary": "remedy", "cli": [] },
                "references": ["ref2"]
            }
        ]
    }""", encoding="utf-8")
    
    with pytest.raises(ValidationError, match="Duplicate rule id"):
        RuleSet.model_validate_json(bad_fw_json.read_text(encoding="utf-8"))

# 12. missing framework reference handling
def test_missing_framework_reference_handling(clean_baseline):
    # Some STIG controls have no verified CCI reference (control_ref = null).
    # Verify that control_ref is None in the result.
    ruleset = load_framework("STIG", "cisco_ios")
    engine = ComplianceEngine(ruleset)
    results = {r.internal_control_id: r for r in engine.evaluate(clean_baseline)}
    
    assert "management_acl" in results
    assert results["management_acl"].control_ref is None
    assert results["management_acl"].verified_ref is False

# 13. verified vs unverified reference metadata
def test_verified_vs_unverified_reference_metadata(clean_baseline):
    # CIS Cisco rules are verified, so verified_ref is True
    cis_rules = load_framework("CIS", "cisco_ios")
    cis_engine = ComplianceEngine(cis_rules)
    cis_results = {r.internal_control_id: r for r in cis_engine.evaluate(clean_baseline)}
    assert cis_results["aaa_enabled"].verified_ref is True
    
    # CIS Junos rules have control_ref = null and verified = false in our mapping
    junos_rules = load_framework("CIS", "juniper_junos")
    junos_engine = ComplianceEngine(junos_rules)
    
    # Create a clean Junos baseline to evaluate
    from auditor.parsers import JunosParser
    junos_config = "set system login password minimum-length 8\nset system services ssh protocol-version v2\nset system login message \"Welcome\""
    junos_baseline = JunosParser().parse(junos_config)
    junos_results = {r.internal_control_id: r for r in junos_engine.evaluate(junos_baseline)}
    assert junos_results["aaa_enabled"].verified_ref is False

# 14. training compatibility
def test_training_compatibility_neutrality(tmp_path):
    # 1. Create a learned mapping in a temporary store
    store_file = tmp_path / "learned_mappings.jsonl"
    store = LearnedMappingStore(store_file)
    
    # The administrator teaches a normalized field, NOT a framework-specific one
    mapping = LearnedMapping(
        mapping_id="LM-MIN-LEN",
        vendor="cisco",
        pattern="security passwords min-length",
        field="password_min_length",
        extraction_strategy="token",
    )
    store.create_mapping(mapping)
    store.approve_mapping("LM-MIN-LEN")
    
    # 2. Parse a config that has the taught command but was undetected by parser
    # Cisco parser without 'security passwords min-length' line defaults to undetected (0) if line absent.
    # If line is present but let's say parser didn't match it deterministically:
    config_text = "security passwords min-length 12"
    
    # Setup an empty baseline
    baseline = SecurityBaselineModel(
        provenance=ParserProvenance(parser_name="test", parser_version="1.0", vendor="cisco", os_family="ios"),
        config_line_count=1
    )
    
    # 3. Resolve using learned mappings
    resolved_baseline = resolve_learned_mappings(config_text, baseline, store)
    
    # Assert it was resolved as password_min_length = 12
    assert resolved_baseline.password_min_length.value == 12
    assert resolved_baseline.password_min_length.detected is True
    assert resolved_baseline.password_min_length.origin == Origin.LEARNED
    
    # 4. Evaluate against all four frameworks (proving framework-neutrality)
    for fw in ["CIS", "NIST_800_53", "STIG", "ISO_27001"]:
        ruleset = load_framework(fw, "cisco_ios")
        engine = ComplianceEngine(ruleset)
        results = {r.internal_control_id: r for r in engine.evaluate(resolved_baseline)}
        
        # All frameworks should correctly consume this resolved field
        # password_min_length control is mapped to a check (>= 8), which 12 satisfies
        assert results["password_min_length"].status == Status.PASS
        assert results["password_min_length"].evidence[0].value == 12
        assert results["password_min_length"].evidence[0].origin == Origin.LEARNED

# 15. hybrid and LLM compatibility
def test_hybrid_and_llm_compatibility(clean_baseline):
    # Verify that hybrid and LLM observations are consumed by all frameworks exactly the same way as deterministic ones
    clean_baseline.ssh_version = Observation[int].found(
        value=2,
        source_line="ip ssh version 2",
        line_number=20,
        origin=Origin.HYBRID,
        confidence=0.9
    )
    clean_baseline.telnet_enabled = Observation[bool].found(
        value=False,
        source_line="transport input ssh",
        line_number=21,
        origin=Origin.LLM,
        confidence=0.85
    )
    
    for fw in ["CIS", "NIST_800_53", "STIG", "ISO_27001"]:
        ruleset = load_framework(fw, "cisco_ios")
        engine = ComplianceEngine(ruleset)
        results = {r.internal_control_id: r for r in engine.evaluate(clean_baseline)}
        
        # Verify that they pass, and the evidence origin / confidence is preserved
        ssh_res = results["ssh_version_2"]
        assert ssh_res.status == Status.PASS
        assert ssh_res.evidence[0].origin == Origin.HYBRID
        assert ssh_res.evidence[0].confidence == 0.9
        
        vty_res = results["secure_vty_transport"]
        assert vty_res.status == Status.PASS
        
        # Find the telnet evidence
        telnet_ev = next(e for e in vty_res.evidence if e.field == "telnet_enabled")
        assert telnet_ev.origin == Origin.LLM
        assert telnet_ev.confidence == 0.85
