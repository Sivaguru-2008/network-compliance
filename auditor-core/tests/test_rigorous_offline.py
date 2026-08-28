import os
import json
import sqlite3
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from auditor.cli import run, EXIT_OK, EXIT_FINDINGS, EXIT_REVIEW
from auditor.knowledge.db import init_db, DB_PATH
from auditor.knowledge.repository import (
    get_controls_for_framework,
    approve_control,
    save_control,
    save_source
)
from auditor.knowledge.bootstrap import bootstrap_database_if_empty
from auditor.knowledge.ingest import ingest_from_json, CandidateControl, validate_candidate_control
from auditor.pipeline import RulesetResolver, audit_baseline, audit_unknown_vendor_offline
from auditor.parsers import CiscoIOSParser
from auditor.models.result import Status

@pytest.fixture(autouse=True)
def setup_clean_db(tmp_path, monkeypatch):
    """Fixture to isolate the database file during testing."""
    test_db_dir = tmp_path / "rules"
    test_db_dir.mkdir(parents=True, exist_ok=True)
    test_db_path = test_db_dir / "knowledge.db"
    
    # Patch the DB_PATH in both db and repository modules
    monkeypatch.setattr("auditor.knowledge.db.DB_PATH", test_db_path)
    monkeypatch.setattr("auditor.knowledge.repository.DB_PATH", test_db_path)
    
    # Initialize the database
    init_db()
    yield test_db_path

def test_no_api_key_required(setup_clean_db):
    """Verify that a normal audit runs successfully when all API credentials are absent from the environment."""
    bootstrap_database_if_empty()
    config_file = Path("samples/new_router.conf")
    
    # Run with empty environment (no API keys)
    with patch.dict(os.environ, {}, clear=True):
        argv = [str(config_file), "--framework", "CIS", "--offline", "--no-json"]
        code = run(argv)
        assert code in (EXIT_OK, EXIT_FINDINGS)

def test_network_blocked_guard(setup_clean_db):
    """Verify that any network connection attempted under --offline mode raises a RuntimeError."""
    bootstrap_database_if_empty()
    config_file = Path("samples/new_router.conf")
    
    # Run with --offline, and verify that attempting to create a socket raises RuntimeError
    argv = [str(config_file), "--framework", "CIS", "--offline", "--no-json"]
    
    # We patch inside the network guard context. Let's verify that a socket connection attempt throws RuntimeError.
    import socket
    
    # Test that socket creation is blocked inside the run command
    # We can mock select_parser to make a dummy socket connection to simulate a callout
    def mock_select(*args, **kwargs):
        s = socket.socket() # This should raise RuntimeError
        return CiscoIOSParser, 1.0
        
    with patch("auditor.cli._select_parser", mock_select):
        with pytest.raises(RuntimeError, match="Network connection attempted"):
            run(argv)

def test_llm_package_unneeded_offline(setup_clean_db):
    """Verify that the LLM client package is not required / imported during a deterministic offline audit."""
    bootstrap_database_if_empty()
    config_file = Path("samples/new_router.conf")
    
    # Force import error for anthropic
    with patch("sys.modules") as mock_modules:
        if "anthropic" in mock_modules:
            del mock_modules["anthropic"]
            
        argv = [str(config_file), "--framework", "CIS", "--offline", "--no-json"]
        code = run(argv)
        assert code in (EXIT_OK, EXIT_FINDINGS)

def test_unsupported_vendor_offline_behavior(setup_clean_db, tmp_path):
    """Verify that when offline, an unknown vendor config results in NEEDS_REVIEW findings instead of crashing."""
    bootstrap_database_if_empty()
    config_file = tmp_path / "unknown.conf"
    config_file.write_text("random configuration line here\n", encoding="utf-8")
    
    report_json = tmp_path / "report.json"
    argv = [str(config_file), "--framework", "CIS", "--offline", "--json", str(report_json), "--strict"]
    
    code = run(argv)
    assert code == EXIT_REVIEW # Exit code for needs review under strict
    
    # Verify report results have NEEDS_REVIEW status
    with open(report_json, "r", encoding="utf-8") as f:
        report_data = json.load(f)
        
    results = report_data.get("results", [])
    assert len(results) > 0
    for r in results:
        assert r["status"] == "NEEDS_REVIEW"
        assert "Unsupported vendor configuration offline" in r["message"]

def test_new_real_world_config(setup_clean_db):
    """Verify that auditing our new configuration successfully detects cisco_ios, parses, and produces correct results."""
    bootstrap_database_if_empty()
    config_file = Path("samples/new_router.conf")
    
    argv = [str(config_file), "--framework", "CIS", "--offline", "--no-json", "--strict"]
    code = run(argv)
    assert code == EXIT_FINDINGS # Should have findings since new_router.conf is insecure

def test_knowledge_persistence(setup_clean_db, tmp_path, monkeypatch):
    """Verify that the evaluator runs successfully off SQLite when local JSON rule files are absent."""
    bootstrap_database_if_empty()
    config_file = Path("samples/new_router.conf")
    
    # Temporarily remove/move the rules files from disk to prove database is the sole source of truth
    # We patch FRAMEWORKS_DIR and CONTROLS_PATH to point to empty locations
    empty_dir = tmp_path / "empty_frameworks"
    empty_dir.mkdir(exist_ok=True)
    empty_controls = tmp_path / "empty_controls.json"
    empty_controls.write_text("{}", encoding="utf-8")
    
    monkeypatch.setattr("auditor.rules.loader.FRAMEWORKS_DIR", empty_dir)
    monkeypatch.setattr("auditor.rules.loader.CONTROLS_PATH", empty_controls)
    
    argv = [str(config_file), "--framework", "CIS", "--offline", "--no-json", "--strict"]
    code = run(argv)
    # If the audit runs and finds findings, it successfully loaded the rules from SQLite!
    assert code == EXIT_FINDINGS

def test_knowledge_versioning(setup_clean_db, tmp_path):
    """Verify that two snapshots (e.g. V1 and V2) of a framework remain separate and can be run independently."""
    # Bootstrap empty DB first
    init_db()
    
    # Insert Control version 1.0
    source_id_1 = save_source("V1 Source", "file")
    save_control(
        framework="VERS-FW",
        framework_version="1.0",
        control_id="VERS-CTL-01",
        title="Version One Control",
        requirement="Check hostname",
        description="Verify V1",
        severity="medium",
        vendor="Cisco",
        platform="cisco_ios",
        evidence_requirements=["hostname"],
        pass_condition={"field": "hostname", "operator": "is_true"},
        remediation_summary="Verify hostname",
        remediation_cli=[],
        references=[],
        source_id=source_id_1,
        validation_status="APPROVED",
        source_note="V1 rule"
    )
    
    # Insert Control version 2.0 with a different title/requirement
    source_id_2 = save_source("V2 Source", "file")
    save_control(
        framework="VERS-FW",
        framework_version="2.0",
        control_id="VERS-CTL-01",
        title="Version Two Control",
        requirement="Check hostname v2",
        description="Verify V2",
        severity="high", # Severity changed to high
        vendor="Cisco",
        platform="cisco_ios",
        evidence_requirements=["hostname"],
        pass_condition={"field": "hostname", "operator": "is_true"},
        remediation_summary="Verify hostname v2",
        remediation_cli=[],
        references=[],
        source_id=source_id_2,
        validation_status="APPROVED",
        source_note="V2 rule"
    )
    
    config_file = Path("samples/new_router.conf")
    
    # Run version 1.0 audit
    report_v1 = tmp_path / "report_v1.json"
    run([str(config_file), "--framework", "VERS-FW:1.0", "--offline", "--json", str(report_v1)])
    with open(report_v1, "r", encoding="utf-8") as f:
        data_v1 = json.load(f)
        
    # Run version 2.0 audit
    report_v2 = tmp_path / "report_v2.json"
    run([str(config_file), "--framework", "VERS-FW:2.0", "--offline", "--json", str(report_v2)])
    with open(report_v2, "r", encoding="utf-8") as f:
        data_v2 = json.load(f)
        
    r1 = data_v1["results"][0]
    r2 = data_v2["results"][0]
    
    # Check that V1 rules were loaded for V1 audit
    assert r1["title"] == "Version One Control"
    assert r1["knowledge_version"] == "1.0"
    assert r1["severity"] == "medium"
    
    # Check that V2 rules were loaded for V2 audit
    assert r2["title"] == "Version Two Control"
    assert r2["knowledge_version"] == "2.0"
    assert r2["severity"] == "high"

def test_determinism(setup_clean_db, tmp_path):
    """Verify that executing repeated offline audits on the same config produces identical findings."""
    bootstrap_database_if_empty()
    config_file = Path("samples/new_router.conf")
    
    report1 = tmp_path / "r1.json"
    report2 = tmp_path / "r2.json"
    
    run([str(config_file), "--framework", "CIS", "--offline", "--json", str(report1)])
    run([str(config_file), "--framework", "CIS", "--offline", "--json", str(report2)])
    
    with open(report1, "r", encoding="utf-8") as f:
        data1 = json.load(f)
    with open(report2, "r", encoding="utf-8") as f:
        data2 = json.load(f)
        
    data1.pop("generated_at", None)
    data2.pop("generated_at", None)
    
    assert data1 == data2

def test_remediation_provenance_marking(setup_clean_db, tmp_path):
    """Verify that LLM-ingested controls have remediation marked as AI_SUGGESTED and prepend '[AI_SUGGESTED]'."""
    init_db()
    
    # Simulate LLM ingestion mapping by setting remediation_provenance to "AI_SUGGESTED"
    # Change pass_condition operator to is_false so it fails on new_router.conf (which has hostname 'new_router'), thus returning remediation
    source_id = save_source("LLM Extracted Document", "file")
    save_control(
        framework="AI-FW",
        framework_version="1.0",
        control_id="AI-CTL-01",
        title="AI Control",
        requirement="Ensure secure banners",
        description="Ensure secure banners description",
        severity="low",
        vendor="Cisco",
        platform="cisco_ios",
        evidence_requirements=["hostname"],
        pass_condition={"field": "hostname", "operator": "is_false"},
        remediation_summary="Configure security login banner.",
        remediation_cli=["banner login ^CAccess denied^C"],
        references=[],
        source_id=source_id,
        validation_status="APPROVED", # Approved so loader will fetch it
        remediation_provenance="AI_SUGGESTED"
    )
    
    config_file = Path("samples/new_router.conf")
    report = tmp_path / "ai_report.json"
    
    run([str(config_file), "--framework", "AI-FW", "--offline", "--json", str(report)])
    
    with open(report, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    results = data["results"]
    assert len(results) == 1
    rem = results[0]["remediation"]
    assert rem is not None
    assert rem["provenance"] == "AI_SUGGESTED"
    assert rem["summary"].startswith("[AI_SUGGESTED]")

def test_provenance_traceability_end_to_end(setup_clean_db, tmp_path):
    """Verify end-to-end provenance trace from evaluation findings back to database authoritative source."""
    bootstrap_database_if_empty()
    config_file = Path("samples/new_router.conf")
    
    report_json = tmp_path / "trace_report.json"
    run([str(config_file), "--framework", "CIS", "--offline", "--json", str(report_json)])
    
    with open(report_json, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    # Get VTY access control result
    vty_result = next(r for r in data["results"] if r["control_id"] == "CIS-IOS-1.2-VTY-ACCESS-CLASS")
    
    # Query database to match this rule
    conn = sqlite3.connect(setup_clean_db)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT c.*, s.source_name, s.source_version, s.source_url_or_path
        FROM controls c
        JOIN sources s ON c.source_id = s.id
        WHERE c.control_id = 'CIS-IOS-1.2-VTY-ACCESS-CLASS' AND c.platform = 'cisco_ios'
    """)
    db_row = cursor.fetchone()
    conn.close()
    
    assert db_row is not None
    # Verify report matches DB trace exactly
    assert vty_result["knowledge_version"] == db_row["framework_version"]
    assert vty_result["control_ref"] == db_row["source_location"]
