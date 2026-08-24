import os
import json
import sqlite3
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from auditor.cli import run, EXIT_OK, EXIT_FINDINGS
from auditor.knowledge.db import init_db, DB_PATH
from auditor.knowledge.repository import (
    get_controls_for_framework,
    approve_control,
    reject_control,
    list_controls,
    get_latest_framework_version,
    export_db,
    import_db
)
from auditor.knowledge.bootstrap import bootstrap_database_if_empty
from auditor.knowledge.ingest import ingest_from_json, ingest_from_text_with_llm, CandidateControl

@pytest.fixture(autouse=True)
def setup_clean_db(tmp_path, monkeypatch):
    """Fixture to isolate the database file during testing."""
    test_db_dir = tmp_path / "rules"
    test_db_dir.mkdir(parents=True, exist_ok=True)
    test_db_path = test_db_dir / "knowledge.db"
    
    # Patch the DB_PATH in both db and repository modules
    monkeypatch.setattr("auditor.knowledge.db.DB_PATH", test_db_path)
    monkeypatch.setattr("auditor.knowledge.repository.DB_PATH", test_db_path)
    
    # Initialize the test database
    init_db()
    yield test_db_path

def test_db_bootstrapping(setup_clean_db):
    """Verify that empty database successfully bootstraps from local JSON files."""
    assert bootstrap_database_if_empty() is True
    
    # Second bootstrap call should return False (already bootstrapped)
    assert bootstrap_database_if_empty() is False
    
    # Verify CIS controls are loaded
    cis_controls = get_controls_for_framework("CIS", "cisco_ios")
    assert len(cis_controls) > 0
    assert any(c["control_id"] == "CIS-IOS-1.2.2" for c in cis_controls)

def test_offline_audit(setup_clean_db, tmp_path):
    """Test 1: Run audit in offline mode without internet, API, or LLM."""
    bootstrap_database_if_empty()
    
    # Create mock configuration file
    config_file = tmp_path / "mock_ios.conf"
    config_file.write_text("""
    hostname router01
    !
    username admin privilege 15 secret 5 $1$mERr$hx5RL
    !
    line vty 0 4
     transport input ssh
     exec-timeout 5 0
    """, encoding="utf-8")
    
    # Run audit in offline mode (should return 0 or 1 depending on rules)
    argv = [str(config_file), "--framework", "CIS", "--offline", "--no-json"]
    
    # Make sure ANTHROPIC_API_KEY is not set to verify it doesn't depend on it
    with patch.dict(os.environ, {}, clear=True):
        code = run(argv)
        # Verify it ran without errors (either EXIT_OK or EXIT_FINDINGS)
        assert code in (EXIT_OK, EXIT_FINDINGS)

def test_knowledge_persistence_and_approval(setup_clean_db, tmp_path):
    """Test 2: Ingest candidate control once, verify it requires approval, and runs offline once approved."""
    bootstrap_database_if_empty()
    
    candidate_json = tmp_path / "candidate.json"
    candidate_json.write_text(json_content(), encoding="utf-8")
    
    # Ingest candidate control
    ingest_from_json(candidate_json)
    
    # Verify candidate control is VALIDATION_PENDING and NOT in production evaluations
    pending = list_controls(framework="TEST-FW", status="VALIDATION_PENDING")
    assert len(pending) == 1
    assert pending[0]["control_id"] == "TEST-FW-1.0.0"
    
    approved_rules = get_controls_for_framework("TEST-FW", "cisco_ios")
    assert len(approved_rules) == 0  # not yet approved!
    
    # Now approve it
    approve_control("TEST-FW-1.0.0", framework="TEST-FW", platform="cisco_ios")
    
    # Check it is now available for production evaluation
    approved_rules = get_controls_for_framework("TEST-FW", "cisco_ios")
    assert len(approved_rules) == 1
    assert approved_rules[0]["control_id"] == "TEST-FW-1.0.0"

def test_provenance_traceability(setup_clean_db, tmp_path):
    """Test 3: Verify that findings contain compliance source and knowledge version."""
    bootstrap_database_if_empty()
    
    config_file = tmp_path / "mock_ios.conf"
    config_file.write_text("hostname router01\nline vty 0 4\n transport input telnet\n", encoding="utf-8")
    
    # Run audit and export JSON report to check fields
    report_json = tmp_path / "report.json"
    argv = [str(config_file), "--framework", "CIS", "--offline", "--json", str(report_json)]
    
    run(argv)
    
    assert report_json.is_file()
    import json
    report_data = json.loads(report_json.read_text(encoding="utf-8"))
    
    # Verify results contain provenance fields
    results = report_data.get("results", [])
    assert len(results) > 0
    for r in results:
        assert "control_id" in r
        assert "device" in r
        assert "vendor" in r
        assert "parser" in r
        assert "knowledge_version" in r
        assert "source_reference" in r
        assert "evaluation_result" in r
        assert "reason" in r

def test_determinism(setup_clean_db, tmp_path):
    """Test 4: Verify same configuration + same knowledge snapshot produces the same results."""
    bootstrap_database_if_empty()
    
    config_file = tmp_path / "mock_ios.conf"
    config_file.write_text("hostname router01\nline vty 0 4\n transport input telnet\n", encoding="utf-8")
    
    report1 = tmp_path / "report1.json"
    report2 = tmp_path / "report2.json"
    
    run([str(config_file), "--framework", "CIS", "--offline", "--json", str(report1)])
    run([str(config_file), "--framework", "CIS", "--offline", "--json", str(report2)])
    
    import json
    data1 = json.loads(report1.read_text(encoding="utf-8"))
    data2 = json.loads(report2.read_text(encoding="utf-8"))
    
    # Strip generation timestamps which vary
    data1.pop("generated_at", None)
    data2.pop("generated_at", None)
    
    assert data1 == data2

def test_llm_isolation(setup_clean_db, tmp_path):
    """Test 5: Verify core compliance evaluation runs offline and isolates LLM when disabled."""
    bootstrap_database_if_empty()
    
    config_file = tmp_path / "mock_ios.conf"
    config_file.write_text("hostname router01\n", encoding="utf-8")
    
    # Offline run with LLM disallowed (standard mode)
    with patch("auditor.parsers.llm.client.AnthropicClient") as mock_client:
        code = run([str(config_file), "--framework", "CIS", "--offline", "--vendor", "cisco_ios"])
        assert code in (EXIT_OK, EXIT_FINDINGS)
        # AnthropicClient should never have been constructed
        mock_client.assert_not_called()

def test_knowledge_versioning(setup_clean_db, tmp_path):
    """Test 6: Verify old and new framework versions remain distinguishable."""
    bootstrap_database_if_empty()
    
    # Ingest version 1.0
    c1 = json_content()
    c1_data = json.loads(c1)
    c1_data["framework_version"] = "1.0"
    c1_data["title"] = "Version One Control"
    
    # Ingest version 1.1
    c2 = json_content()
    c2_data = json.loads(c2)
    c2_data["framework_version"] = "1.1"
    c2_data["title"] = "Version Two Control"
    
    v1_file = tmp_path / "v1.json"
    v1_file.write_text(json.dumps(c1_data), encoding="utf-8")
    v2_file = tmp_path / "v2.json"
    v2_file.write_text(json.dumps(c2_data), encoding="utf-8")
    
    ingest_from_json(v1_file)
    ingest_from_json(v2_file)
    
    approve_control("TEST-FW-1.0.0", "TEST-FW", "cisco_ios")
    
    v1_rules = get_controls_for_framework("TEST-FW", "cisco_ios", "1.0")
    v1_1_rules = get_controls_for_framework("TEST-FW", "cisco_ios", "1.1")
    
    assert len(v1_rules) == 1
    assert v1_rules[0]["title"] == "Version One Control"
    assert len(v1_1_rules) == 1
    assert v1_1_rules[0]["title"] == "Version Two Control"

def json_content():
    return """
    {
      "control_id": "TEST-FW-1.0.0",
      "framework": "TEST-FW",
      "framework_version": "1.0",
      "title": "Secure VTY Transport",
      "requirement": "Remote access must use secure transport.",
      "description": "Ensure VTY transport allows secure transport only.",
      "severity": "HIGH",
      "vendor": "Cisco",
      "platform": "cisco_ios",
      "evidence_requirements": [
        "vty_transport_input"
      ],
      "pass_condition": {
        "field": "vty_transport_input",
        "operator": "subset_of",
        "value": ["ssh"]
      },
      "remediation_summary": "Configure transport input ssh",
      "remediation_cli": ["line vty 0 4", "transport input ssh"],
      "references": ["Section 1.2.2"],
      "source_document": "TEST-FW Guide",
      "source_version": "1.0",
      "source_location": "Section 1.2.2"
    }
    """
