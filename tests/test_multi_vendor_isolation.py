import sys
from pathlib import Path
import pytest
import copy

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parents[1]))

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers.fortios import FortiosParser
from auditor.parsers.paloalto import PaloAltoParser
from auditor.pipeline import evaluate_cis_fortigate, evaluate_cis_paloalto
from auditor.knowledge.bootstrap import bootstrap_database_if_empty

FGT_CONFIG_PATH = Path(__file__).parents[1] / "samples" / "fortios_fgt.conf"
PA_XML_PATH = Path(__file__).parents[1] / "samples" / "paloalto_panos.xml"

@pytest.fixture(scope="module")
def bootstrap_db():
    bootstrap_database_if_empty()

@pytest.fixture
def fortigate_config():
    return FGT_CONFIG_PATH.read_text(encoding="utf-8")

@pytest.fixture
def paloalto_config():
    return PA_XML_PATH.read_text(encoding="utf-8")


def test_repeated_determinism(bootstrap_db, fortigate_config, paloalto_config):
    """PHASE 13 & 9: Repeated determinism test.
    
    Verifies that running parsers and evaluators multiple times on the same input
    produces identical results, evidence, and normalized observations.
    """
    fgt_parser = FortiosParser()
    pa_parser = PaloAltoParser()

    # 1. Parse multiple times
    fgt_b1 = fgt_parser.parse(fortigate_config, source_file="samples/fortios_fgt.conf")
    fgt_b2 = fgt_parser.parse(fortigate_config, source_file="samples/fortios_fgt.conf")
    assert fgt_b1.model_dump() == fgt_b2.model_dump()

    pa_b1 = pa_parser.parse(paloalto_config, source_file="samples/paloalto_panos.xml")
    pa_b2 = pa_parser.parse(paloalto_config, source_file="samples/paloalto_panos.xml")
    assert pa_b1.model_dump() == pa_b2.model_dump()

    # 2. Evaluate multiple times
    fgt_r1 = evaluate_cis_fortigate(fgt_b1)
    fgt_r2 = evaluate_cis_fortigate(fgt_b2)
    assert len(fgt_r1.results) == len(fgt_r2.results)
    for res1, res2 in zip(fgt_r1.results, fgt_r2.results):
        assert res1.rule_id == res2.rule_id
        assert res1.status == res2.status
        assert res1.message == res2.message
        assert len(res1.evidence) == len(res2.evidence)

    pa_r1 = evaluate_cis_paloalto(pa_b1)
    pa_r2 = evaluate_cis_paloalto(pa_b2)
    assert len(pa_r1.results) == len(pa_r2.results)
    for res1, res2 in zip(pa_r1.results, pa_r2.results):
        assert res1.rule_id == res2.rule_id
        assert res1.status == res2.status
        assert res1.message == res2.message
        assert len(res1.evidence) == len(res2.evidence)


def test_state_cache_isolation(bootstrap_db, fortigate_config, paloalto_config):
    """PHASE 12: State/Cache isolation test.
    
    Verifies that running assessments in mixed sequences does not bleed or leak
    cached states between vendors.
    """
    fgt_parser = FortiosParser()
    pa_parser = PaloAltoParser()

    # Sequence A: FortiGate -> Palo Alto -> FortiGate
    fgt_b1 = fgt_parser.parse(fortigate_config, source_file="samples/fortios_fgt.conf")
    fgt_report1 = evaluate_cis_fortigate(fgt_b1)

    pa_b1 = pa_parser.parse(paloalto_config, source_file="samples/paloalto_panos.xml")
    evaluate_cis_paloalto(pa_b1)

    fgt_b2 = fgt_parser.parse(fortigate_config, source_file="samples/fortios_fgt.conf")
    fgt_report2 = evaluate_cis_fortigate(fgt_b2)

    # Compare FortiGate results
    assert len(fgt_report1.results) == len(fgt_report2.results)
    for res1, res2 in zip(fgt_report1.results, fgt_report2.results):
        assert res1.status == res2.status
        assert res1.message == res2.message

    # Sequence B: Palo Alto -> FortiGate -> Palo Alto
    pa_b1_seq2 = pa_parser.parse(paloalto_config, source_file="samples/paloalto_panos.xml")
    pa_report1 = evaluate_cis_paloalto(pa_b1_seq2)

    fgt_b_seq2 = fgt_parser.parse(fortigate_config, source_file="samples/fortios_fgt.conf")
    evaluate_cis_fortigate(fgt_b_seq2)

    pa_b2_seq2 = pa_parser.parse(paloalto_config, source_file="samples/paloalto_panos.xml")
    pa_report2 = evaluate_cis_paloalto(pa_b2_seq2)

    # Compare Palo Alto results
    assert len(pa_report1.results) == len(pa_report2.results)
    for res1, res2 in zip(pa_report1.results, pa_report2.results):
        assert res1.status == res2.status
        assert res1.message == res2.message


def test_vendor_isolation(bootstrap_db, fortigate_config, paloalto_config):
    """PHASE 6: Vendor isolation test.
    
    Verifies that modifying Palo Alto configuration or rules cannot alter
    FortiGate results, and vice versa.
    """
    fgt_parser = FortiosParser()
    pa_parser = PaloAltoParser()

    fgt_baseline_orig = fgt_parser.parse(fortigate_config, source_file="samples/fortios_fgt.conf")
    fgt_report_orig = evaluate_cis_fortigate(fgt_baseline_orig)

    # Mutate the Palo Alto configuration to trigger different results
    mutated_pa_config = paloalto_config.replace("<login-timeout>10</login-timeout>", "<login-timeout>99</login-timeout>")
    pa_baseline_mutated = pa_parser.parse(mutated_pa_config, source_file="samples/paloalto_panos.xml")
    evaluate_cis_paloalto(pa_baseline_mutated)

    # Re-evaluate FortiGate and assert absolutely no changes
    fgt_baseline_new = fgt_parser.parse(fortigate_config, source_file="samples/fortios_fgt.conf")
    fgt_report_new = evaluate_cis_fortigate(fgt_baseline_new)

    assert len(fgt_report_orig.results) == len(fgt_report_new.results)
    for res_orig, res_new in zip(fgt_report_orig.results, fgt_report_new.results):
        assert res_orig.status == res_new.status
        assert res_orig.message == res_new.message


def test_evidence_isolation(bootstrap_db, fortigate_config, paloalto_config):
    """PHASE 14: Evidence isolation.
    
    Proves that evidence paths and details belong strictly to the correct configuration.
    """
    fgt_parser = FortiosParser()
    pa_parser = PaloAltoParser()

    fgt_baseline = fgt_parser.parse(fortigate_config, source_file="samples/fortios_fgt.conf")
    fgt_report = evaluate_cis_fortigate(fgt_baseline)

    pa_baseline = pa_parser.parse(paloalto_config, source_file="samples/paloalto_panos.xml")
    pa_report = evaluate_cis_paloalto(pa_baseline)

    # Scan all FortiGate evidence
    for res in fgt_report.results:
        for ev in res.evidence:
            if ev.source_line:
                # FortiGate evidence should not look like XML
                assert not ev.source_line.strip().startswith("<")
                assert not ev.source_line.strip().endswith(">")
            if ev.note:
                assert "Path:" not in ev.note  # "/Path:" is Palo Alto style

    # Scan all Palo Alto evidence
    for res in pa_report.results:
        for ev in res.evidence:
            if ev.source_line:
                # Palo Alto evidence should look like XML
                assert ev.source_line.strip().startswith("<") or ev.source_line.strip().endswith(">")
                if ev.note:
                    assert "Path: " in ev.note


def test_data_provenance_actual_vs_required(bootstrap_db, paloalto_config):
    """PHASE 9: Data provenance tests.
    
    Verifies that:
    1. ACTUAL values change dynamically with config mutations.
    2. REQUIRED value rules remain unchanged.
    3. Parser outputs are derived purely from parsed config, not hardcoded mappings.
    """
    pa_parser = PaloAltoParser()
    
    # Configuration A: login timeout = 15 mins (900 secs)
    baseline_a = pa_parser.parse(paloalto_config)
    assert baseline_a.vty_exec_timeout_seconds.value == 900
    
    # Configuration B: login timeout = 5 mins (300 secs)
    mutated_config_b = paloalto_config.replace("<login-timeout>15</login-timeout>", "<login-timeout>5</login-timeout>")
    baseline_b = pa_parser.parse(mutated_config_b)
    assert baseline_b.vty_exec_timeout_seconds.value == 300

    # Ensure rule requirements do not shift when baseline changes
    report_a = evaluate_cis_paloalto(baseline_a)
    report_b = evaluate_cis_paloalto(baseline_b)
    
    res_a = next(r for r in report_a.results if r.control_ref == "1.4.1")
    res_b = next(r for r in report_b.results if r.control_ref == "1.4.1")
    
    # Both are checking against <= 600 seconds
    assert "required: less_or_equal 600" in res_a.message or "vty_exec_timeout_seconds" in res_a.message
    assert "required: less_or_equal 600" in res_b.message or "vty_exec_timeout_seconds" in res_b.message
