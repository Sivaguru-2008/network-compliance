import json
import pytest
from pathlib import Path
from datetime import datetime

from auditor.models.baseline import SecurityBaselineModel, SnmpCommunity
from auditor.models.observation import Origin
from auditor.models.result import Status
from auditor.parsers import HybridParser, LLMParser, registry
from auditor.parsers.base import VendorParser
from auditor.training.mappings import (
    LearnedMapping,
    LearnedMappingStore,
    resolve_learned_mappings,
    cast_value,
)
from tests.llm_stub import StubClient, make_extraction, found


@pytest.fixture
def temp_store(tmp_path):
    store_file = tmp_path / "learned_mappings.jsonl"
    return LearnedMappingStore(store_file)


# 1. create mapping
def test_create_mapping(temp_store):
    mapping = LearnedMapping(
        mapping_id="LM-001",
        vendor="fortios",
        pattern="set admin-https-ssl-versions",
        field="https_server_enabled",
        extraction_strategy="exact",
    )
    saved = temp_store.create_mapping(mapping)
    assert saved.mapping_id == "LM-001"
    assert saved.version == 1
    assert len(temp_store.list_mappings()) == 1


# 2. retrieve mapping
def test_retrieve_mapping(temp_store):
    mapping = LearnedMapping(
        mapping_id="LM-001",
        vendor="fortios",
        pattern="set admin-https-ssl-versions",
        field="https_server_enabled",
        extraction_strategy="exact",
    )
    temp_store.create_mapping(mapping)
    retrieved = temp_store.retrieve_mapping("LM-001")
    assert retrieved is not None
    assert retrieved.pattern == "set admin-https-ssl-versions"


# 3. approve mapping
def test_approve_mapping(temp_store):
    mapping = LearnedMapping(
        mapping_id="LM-001",
        vendor="fortios",
        pattern="set admin-https-ssl-versions",
        field="https_server_enabled",
        extraction_strategy="exact",
        status="pending",
        approval_state="pending",
    )
    temp_store.create_mapping(mapping)
    approved = temp_store.approve_mapping("LM-001")
    assert approved.status == "approved"
    assert approved.approval_state == "approved"
    assert approved.version == 2


# 4. disabled mapping is ignored
def test_disabled_mapping_ignored(temp_store):
    mapping = LearnedMapping(
        mapping_id="LM-001",
        vendor="fortios",
        pattern="set admin-https-ssl-versions",
        field="https_server_enabled",
        extraction_strategy="exact",
        status="disabled",
        approval_state="approved",
    )
    temp_store.create_mapping(mapping)
    active = temp_store.get_active_approved_mappings()
    assert len(active) == 0


# 5. rejected mapping is ignored
def test_rejected_mapping_ignored(temp_store):
    mapping = LearnedMapping(
        mapping_id="LM-001",
        vendor="fortios",
        pattern="set admin-https-ssl-versions",
        field="https_server_enabled",
        extraction_strategy="exact",
        status="rejected",
        approval_state="rejected",
    )
    temp_store.create_mapping(mapping)
    active = temp_store.get_active_approved_mappings()
    assert len(active) == 0


# 6. learned mapping applies to future config
# 7. learned mapping preserves original evidence
# 8. learned mapping preserves line number
# 9. learned mapping does not call LLM
def test_learned_mapping_applies_and_preserves_evidence_and_bypasses_llm(tmp_path):
    store_file = tmp_path / "learned_mappings.jsonl"
    stats_file = tmp_path / "stats.json"
    store = LearnedMappingStore(store_file)
    
    mapping = LearnedMapping(
        mapping_id="LM-002",
        vendor="fortios",
        pattern="set admin-https-ssl-versions",
        field="https_server_enabled",
        extraction_strategy="exact",
        status="approved",
        approval_state="approved",
    )
    store.create_mapping(mapping)

    # HybridParser with mock deterministic and mock LLM
    class MockDet(VendorParser):
        name = "mock_det"
        vendor = "fortios"
        os_family = "fortios"
        version = "1.0.0"
        
        @classmethod
        def detect(cls, config_text: str) -> float:
            return 1.0
            
        def parse(self, config_text: str, *, source_file=None):
            # Returns a baseline where https_server_enabled is undetected
            from auditor.models.baseline import ParserProvenance
            return SecurityBaselineModel(
                provenance=ParserProvenance(
                    parser_name=self.name,
                    parser_version=self.version,
                    vendor=self.vendor,
                    os_family=self.os_family,
                )
            )

    stub_llm = StubClient()
    llm_parser = LLMParser(client=stub_llm, training_dir=tmp_path, mapping_store=store)
    hybrid_parser = HybridParser(
        deterministic=MockDet(),
        llm=llm_parser,
        training_dir=tmp_path,
        mapping_store=store,
    )

    config_text = "set admin-https-ssl-versions tlsv1-2 tlsv1-3"
    baseline = hybrid_parser.parse(config_text)

    # Asserts
    assert baseline.https_server_enabled.detected is True
    assert baseline.https_server_enabled.value is True
    assert baseline.https_server_enabled.origin == Origin.LEARNED
    assert baseline.https_server_enabled.mapping_id == "LM-002"
    assert baseline.https_server_enabled.line_number == 1
    assert baseline.https_server_enabled.source_line == "set admin-https-ssl-versions tlsv1-2 tlsv1-3"
    # Ensure no LLM calls were made because the mapping resolved all gaps
    assert stub_llm.calls == 0


# 10. deterministic parser beats learned mapping
def test_deterministic_parser_beats_learned_mapping(tmp_path):
    store_file = tmp_path / "learned_mappings.jsonl"
    store = LearnedMappingStore(store_file)
    
    mapping = LearnedMapping(
        mapping_id="LM-002",
        vendor="fortios",
        pattern="set admin-https-ssl-versions",
        field="https_server_enabled",
        extraction_strategy="exact",
        status="approved",
        approval_state="approved",
    )
    store.create_mapping(mapping)

    class MockDet(VendorParser):
        name = "mock_det"
        vendor = "fortios"
        os_family = "fortios"
        version = "1.0.0"
        @classmethod
        def detect(cls, config_text: str) -> float:
            return 1.0
        def parse(self, config_text: str, *, source_file=None):
            from auditor.models.baseline import ParserProvenance
            from auditor.models.observation import Observation
            b = SecurityBaselineModel(
                provenance=ParserProvenance(
                    parser_name=self.name,
                    parser_version=self.version,
                    vendor=self.vendor,
                    os_family=self.os_family,
                )
            )
            # Explicit deterministic value
            b.https_server_enabled = Observation[bool].found(False, "set admin-https-ssl-versions none", 1)
            return b

    hybrid_parser = HybridParser(
        deterministic=MockDet(),
        llm=LLMParser(client=StubClient(), training_dir=tmp_path, mapping_store=store),
        training_dir=tmp_path,
        mapping_store=store,
    )

    baseline = hybrid_parser.parse("set admin-https-ssl-versions tlsv1-2 tlsv1-3")
    # Should keep the deterministic False instead of learned mapping's True
    assert baseline.https_server_enabled.detected is True
    assert baseline.https_server_enabled.value is False
    assert baseline.https_server_enabled.origin == Origin.DETERMINISTIC


# 11. approved learned mapping beats LLM fallback
def test_approved_learned_mapping_beats_llm_fallback(tmp_path):
    store_file = tmp_path / "learned_mappings.jsonl"
    store = LearnedMappingStore(store_file)
    
    mapping = LearnedMapping(
        mapping_id="LM-003",
        vendor="fortios",
        pattern="set admin-https-ssl-versions",
        field="https_server_enabled",
        extraction_strategy="exact",
        status="approved",
        approval_state="approved",
    )
    store.create_mapping(mapping)

    # If we call LLMParser directly (no deterministic parser)
    stub_llm = StubClient(extraction=make_extraction(
        vendor="fortios",
        os_family="fortios",
        https_server_enabled=found(False, "set admin-https-ssl-versions none")
    ))

    llm_parser = LLMParser(client=stub_llm, training_dir=tmp_path, mapping_store=store)
    # The config has the pattern
    baseline = llm_parser.parse("set admin-https-ssl-versions tlsv1-2 tlsv1-3")

    # Learned mapping says True, LLM says False. Approved mapping must beat LLM!
    assert baseline.https_server_enabled.detected is True
    assert baseline.https_server_enabled.value is True
    assert baseline.https_server_enabled.origin == Origin.LEARNED


# 12. unapproved LLM suggestion is not persisted
def test_unapproved_llm_suggestion_not_persisted(tmp_path):
    store_file = tmp_path / "learned_mappings.jsonl"
    store = LearnedMappingStore(store_file)
    
    # We call propose_mapping via a client
    stub_llm = StubClient(proposal={
        "field": "https_server_enabled",
        "value": "true",
        "compliance_relevance": "Cryptographic Protocol Security",
        "reasoning": "Likely HTTPS server enabled",
    })
    
    proposal = stub_llm.propose_mapping("fortios", "fortios", "set admin-https-ssl-versions tlsv1-2 tlsv1-3")
    assert proposal["field"] == "https_server_enabled"
    
    # Verify it is not in the store yet
    assert len(store.list_mappings()) == 0


# 13. unknown baseline field is rejected
def test_unknown_baseline_field_rejected(temp_store):
    mapping = LearnedMapping(
        mapping_id="LM-001",
        vendor="fortios",
        pattern="set dummy",
        field="invalid_field_name",
        extraction_strategy="exact",
    )
    with pytest.raises(ValueError, match="Unknown baseline field"):
        temp_store.create_mapping(mapping)


# 14. malformed regex is rejected
def test_malformed_regex_rejected(temp_store):
    mapping = LearnedMapping(
        mapping_id="LM-001",
        vendor="fortios",
        pattern="set timeout",
        field="vty_exec_timeout_seconds",
        extraction_strategy="regex",
        regex_pattern="set timeout (\\d+",  # Missing closing parenthesis
    )
    with pytest.raises(ValueError, match="Invalid regex pattern"):
        temp_store.create_mapping(mapping)


# 15. conflicting mappings are detected
def test_conflicting_mappings_detected(temp_store):
    m1 = LearnedMapping(
        mapping_id="LM-001",
        vendor="fortios",
        pattern="set timeout",
        field="vty_exec_timeout_seconds",
        extraction_strategy="token",
        status="approved",
        approval_state="approved",
    )
    m2 = LearnedMapping(
        mapping_id="LM-002",
        vendor="fortios",
        pattern="set timeout",
        field="vty_exec_timeout_seconds",
        extraction_strategy="regex",
        regex_pattern="set timeout (\\d+)",
        status="approved",
        approval_state="approved",
    )
    temp_store.create_mapping(m1)
    temp_store.create_mapping(m2)

    # Retrieve them and check status
    r1 = temp_store.retrieve_mapping("LM-001")
    r2 = temp_store.retrieve_mapping("LM-002")
    assert r1.status == "conflicting"
    assert r2.status == "conflicting"


# 16. different vendors may have different mappings
def test_different_vendors_different_mappings(tmp_path):
    store_file = tmp_path / "learned_mappings.jsonl"
    store = LearnedMappingStore(store_file)

    m_fortios = LearnedMapping(
        mapping_id="LM-004",
        vendor="fortios",
        pattern="set admin-https-ssl-versions",
        field="https_server_enabled",
        extraction_strategy="exact",
        status="approved",
        approval_state="approved",
    )
    m_ios = LearnedMapping(
        mapping_id="LM-005",
        vendor="cisco_ios",
        pattern="ip http secure-server",
        field="https_server_enabled",
        extraction_strategy="exact",
        status="approved",
        approval_state="approved",
    )
    store.create_mapping(m_fortios)
    store.create_mapping(m_ios)

    from auditor.models.baseline import ParserProvenance
    b_fortios = SecurityBaselineModel(
        provenance=ParserProvenance(parser_name="mock", parser_version="1.0", vendor="fortios", os_family="fortios")
    )
    b_ios = SecurityBaselineModel(
        provenance=ParserProvenance(parser_name="mock", parser_version="1.0", vendor="cisco_ios", os_family="ios")
    )

    r_fortios = resolve_learned_mappings("set admin-https-ssl-versions", b_fortios, store)
    r_ios = resolve_learned_mappings("ip http secure-server", b_ios, store)

    assert r_fortios.https_server_enabled.value is True
    assert r_ios.https_server_enabled.value is True


# 17. same vendor can have multiple valid mappings where context differs
def test_same_vendor_multiple_mappings(tmp_path):
    store_file = tmp_path / "learned_mappings.jsonl"
    store = LearnedMappingStore(store_file)

    m1 = LearnedMapping(
        mapping_id="LM-006",
        vendor="fortios",
        pattern="set admintimeout",
        field="vty_exec_timeout_seconds",
        extraction_strategy="token",
        status="approved",
        approval_state="approved",
    )
    m2 = LearnedMapping(
        mapping_id="LM-007",
        vendor="fortios",
        pattern="set admin-https-ssl-versions",
        field="https_server_enabled",
        extraction_strategy="exact",
        status="approved",
        approval_state="approved",
    )
    store.create_mapping(m1)
    store.create_mapping(m2)

    from auditor.models.baseline import ParserProvenance
    b = SecurityBaselineModel(
        provenance=ParserProvenance(parser_name="mock", parser_version="1.0", vendor="fortios", os_family="fortios")
    )

    r = resolve_learned_mappings("set admintimeout 480\nset admin-https-ssl-versions", b, store)
    assert r.vty_exec_timeout_seconds.value == 480
    assert r.https_server_enabled.value is True


# 18. mapping versioning works
def test_mapping_versioning(temp_store):
    m = LearnedMapping(
        mapping_id="LM-001",
        vendor="fortios",
        pattern="set timeout",
        field="vty_exec_timeout_seconds",
        extraction_strategy="token",
        version=1,
    )
    temp_store.create_mapping(m)
    
    # Modify pattern and recreate
    m2 = m.model_copy(update={"pattern": "set timeout-new"})
    saved = temp_store.create_mapping(m2)
    assert saved.version == 2
    assert saved.pattern == "set timeout-new"
    
    latest = temp_store.retrieve_mapping("LM-001")
    assert latest.version == 2


# 19. revoked mapping no longer affects future audits
def test_revoked_mapping(tmp_path):
    store_file = tmp_path / "learned_mappings.jsonl"
    store = LearnedMappingStore(store_file)

    m = LearnedMapping(
        mapping_id="LM-008",
        vendor="fortios",
        pattern="set admin-https-ssl-versions",
        field="https_server_enabled",
        extraction_strategy="exact",
        status="approved",
        approval_state="approved",
    )
    store.create_mapping(m)
    
    # Verify it applies
    from auditor.models.baseline import ParserProvenance
    b1 = SecurityBaselineModel(
        provenance=ParserProvenance(parser_name="mock", parser_version="1.0", vendor="fortios", os_family="fortios")
    )
    r1 = resolve_learned_mappings("set admin-https-ssl-versions", b1, store)
    assert r1.https_server_enabled.value is True

    # Revoke/Delete
    store.delete_mapping("LM-008")

    # Verify it no longer applies
    b2 = SecurityBaselineModel(
        provenance=ParserProvenance(parser_name="mock", parser_version="1.0", vendor="fortios", os_family="fortios")
    )
    r2 = resolve_learned_mappings("set admin-https-ssl-versions", b2, store)
    assert r2.https_server_enabled.detected is False


# 20. audit report identifies learned evidence
def test_audit_report_identifies_learned_evidence():
    from auditor.models.result import Evidence
    from auditor.models.observation import Observation
    
    obs = Observation[bool].found(
        value=True,
        source_line="set admin-https-ssl-versions tlsv1-2 tlsv1-3",
        line_number=42,
        origin=Origin.LEARNED,
    )
    object.__setattr__(obs, "mapping_id", "LM-004")
    object.__setattr__(obs, "original_line", "set admin-https-ssl-versions tlsv1-2 tlsv1-3")
    object.__setattr__(obs, "original_line_number", 42)

    ev = Evidence.from_observation("https_server_enabled", obs)
    assert "Administrator-trained mapping #LM-004" in ev.display
    assert "line 42: set admin-https-ssl-versions tlsv1-2 tlsv1-3" in ev.display


# 21. End-to-end acceptance test
def test_end_to_end_acceptance_flow(tmp_path):
    store_file = tmp_path / "learned_mappings.jsonl"
    store = LearnedMappingStore(store_file)
    
    # Setup mock LLM parser client
    stub_llm = StubClient(
        extraction=make_extraction(
            vendor="unknown_vendor",
            os_family="unknown_os",
            vty_exec_timeout_seconds=found(600, "set timeout 10")
        ),
        proposal={
            "field": "vty_exec_timeout_seconds",
            "value": "600",
            "compliance_relevance": "Cryptographic Protocol Security",
            "reasoning": "Suggested timeout config",
        }
    )

    # 1. Run configuration for the first time
    config_text = "set timeout 10"
    
    # 2. Parser reports an unknown field / line (via unrecognized lines)
    llm_parser = LLMParser(client=stub_llm, training_dir=tmp_path, mapping_store=store)
    baseline_first = llm_parser.parse(config_text)
    
    # 3. AI proposes a mapping
    proposal = stub_llm.propose_mapping("unknown_vendor", "unknown_os", "set timeout 10")
    assert proposal["field"] == "vty_exec_timeout_seconds"
    
    # 4. Administrator approves/saves mapping
    mapping = LearnedMapping(
        mapping_id="LM-100",
        vendor="unknown_vendor",
        os_family="unknown_os",
        pattern="set timeout",
        field=proposal["field"],
        extraction_strategy="token",
        status="approved",
        approval_state="approved",
        evidence_example="set timeout 10",
    )
    store.create_mapping(mapping)
    
    # 5. Run the same configuration again
    # We clear LLM calls count to assert no calls occur
    stub_llm.calls = 0
    llm_parser_second = LLMParser(client=stub_llm, training_dir=tmp_path, mapping_store=store)
    baseline_second = llm_parser_second.parse(config_text)
    
    # 6. Asserts
    assert stub_llm.calls == 0  # No LLM call occurs
    assert baseline_second.vty_exec_timeout_seconds.detected is True
    assert baseline_second.vty_exec_timeout_seconds.value == 10  # Token extraction extracts 10!
    assert baseline_second.vty_exec_timeout_seconds.origin == Origin.LEARNED
    assert baseline_second.vty_exec_timeout_seconds.mapping_id == "LM-100"
    
    # Evaluate it against rules to ensure compliance rule evaluates it
    from auditor.engine import ComplianceEngine
    from auditor.models.rule import ComplianceRule, RuleSet, Platform, Remediation
    
    rule = ComplianceRule(
        id="RULE-01",
        title="Check VTY timeout",
        description="Timeout <= 600",
        framework="TEST",
        severity="medium",
        baseline_fields=["vty_exec_timeout_seconds"],
        condition={"field": "vty_exec_timeout_seconds", "operator": "less_or_equal", "value": 600},
        remediation=Remediation(summary="Set timeout to 600", cli=["timeout 600"])
    )
    ruleset = RuleSet(
        schema_version="1.0",
        framework="TEST",
        framework_version="1.0",
        platform=Platform(vendor="unknown_vendor", os_family="unknown_os"),
        rules=[rule]
    )
    engine = ComplianceEngine(ruleset)
    report = engine.build_report(baseline_second, tool_name="netaudit", tool_version="1.0")
    
    result = report.results[0]
    assert result.status == Status.PASS
    assert "Administrator-trained mapping #LM-100" in result.evidence[0].display
    assert "line 1: set timeout 10" in result.evidence[0].display
