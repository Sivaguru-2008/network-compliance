import io
import re
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from auditor.web.app import create_app
from auditor.training.mappings import LearnedMapping, LearnedMappingStore
from auditor.models.result import Status
from auditor.models.observation import Origin
from auditor.parsers import HybridParser, registry

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAMPLES = PROJECT_ROOT / "samples"

def _sample_bytes(name: str) -> bytes:
    return (SAMPLES / name).read_bytes()

def _upload(client, files, frameworks=None):
    parts = [("files", (name, io.BytesIO(data), "text/plain")) for name, data in files]
    data = {"frameworks": frameworks} if frameworks else {}
    return client.post("/api/upload", files=parts, data=data)

@pytest.fixture
def test_client(tmp_path):
    app = create_app(store_root=tmp_path / "jobs")
    return TestClient(app)

# 1. API Queue and Item retrieval
def test_queue_and_item_endpoints(test_client):
    # Upload config to create a job and device record using a real config with an unrecognized line appended
    config_data = _sample_bytes("insecure_ios.conf") + b"\nexec-timeout-custom 15\n"
    response = _upload(test_client, [("cisco.conf", config_data)])
    assert response.status_code == 200
    
    # Get queue
    queue_res = test_client.get("/training/queue")
    assert queue_res.status_code == 200
    queue = queue_res.json()
    assert len(queue) > 0
    
    # Check item in queue
    item = next(x for x in queue if "exec-timeout-custom" in x["source_line"])
    assert item["vendor"] == "cisco_ios"
    assert item["device_identity"] == "BRANCH-SW-07"
    assert item["status"] == "NEEDS_REVIEW"
    assert "Line 45: exec-timeout-custom 15" in item["context"]
    
    # Retrieve detail by ID
    detail_res = test_client.get(f"/training/{item['id']}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == item["id"]
    assert detail["source_line"] == "exec-timeout-custom 15"

# 2. Mapping editor preview endpoint
def test_preview_endpoint(test_client):
    # Test Exact strategy preview
    preview_data = {
        "vendor": "cisco_ios",
        "pattern": "aaa custom-model",
        "field": "aaa_enabled",
        "extraction_strategy": "exact",
        "original_line": "aaa custom-model"
    }
    res = test_client.post("/training/preview", json=preview_data)
    assert res.status_code == 200
    assert res.json()["result"] == "FOUND"
    assert res.json()["extracted_value"] is True

    # Test Token strategy preview
    preview_data = {
        "vendor": "cisco_ios",
        "pattern": "exec-timeout-custom",
        "field": "vty_exec_timeout_seconds",
        "extraction_strategy": "token",
        "original_line": "exec-timeout-custom 300"
    }
    res = test_client.post("/training/preview", json=preview_data)
    assert res.status_code == 200
    assert res.json()["result"] == "FOUND"
    assert res.json()["extracted_value"] == 300

    # Test Regex strategy preview
    preview_data = {
        "vendor": "cisco_ios",
        "pattern": "exec-timeout-custom",
        "field": "vty_exec_timeout_seconds",
        "extraction_strategy": "regex",
        "regex_pattern": r"exec-timeout-custom (\d+)",
        "original_line": "exec-timeout-custom 450"
    }
    res = test_client.post("/training/preview", json=preview_data)
    assert res.status_code == 200
    assert res.json()["result"] == "FOUND"
    assert res.json()["extracted_value"] == 450

# 3. Create, Approve, Reject, Disable, Delete lifecycles
def test_mappings_lifecycle(test_client):
    # Create mapping as pending
    mapping = {
        "mapping_id": "LM-TEST-01",
        "vendor": "cisco_ios",
        "pattern": "aaa custom-model",
        "field": "aaa_enabled",
        "extraction_strategy": "exact",
        "status": "pending",
        "approval_state": "pending",
        "evidence_example": "aaa custom-model"
    }
    res = test_client.post("/training", json=mapping)
    assert res.status_code == 200
    
    # Verify in history as pending
    history_res = test_client.get("/training/history")
    history = history_res.json()
    assert any(x["mapping_id"] == "LM-TEST-01" and x["status"] == "pending" for x in history)
    
    # Approve it
    approve_res = test_client.post("/training/LM-TEST-01/approve")
    assert approve_res.status_code == 200
    assert approve_res.json()["status"] == "approved"
    assert approve_res.json()["approval_state"] == "approved"
    
    # Reject a mapping
    mapping2 = mapping.copy()
    mapping2["mapping_id"] = "LM-TEST-02"
    test_client.post("/training", json=mapping2)
    reject_res = test_client.post("/training/LM-TEST-02/reject")
    assert reject_res.status_code == 200
    assert reject_res.json()["status"] == "rejected"
    assert reject_res.json()["approval_state"] == "rejected"
    
    # Disable approved mapping
    disable_res = test_client.post("/training/LM-TEST-01/disable")
    assert disable_res.status_code == 200
    assert disable_res.json()["status"] == "disabled"
    
    # Delete mapping
    delete_res = test_client.post("/training/LM-TEST-01/delete")
    assert delete_res.status_code == 200
    assert delete_res.json()["status"] == "deleted"

# 4. E2E Parser Integration, Grounding, and Framework Neutrality
def test_e2e_parser_integration_and_framework_neutrality(test_client):
    # A config where vty_exec_timeout_seconds is undetected (NEEDS_REVIEW)
    config_text = _sample_bytes("insecure_ios.conf").decode("utf-8").replace("exec-timeout 0 0", "")
    config_data = (config_text + "\nexec-timeout-custom 15\n").encode("utf-8")
    
    # First upload: should be NEEDS_REVIEW on VTY idle timeout
    response_first = _upload(test_client, [("cisco.conf", config_data)])
    assert response_first.status_code == 200
    inventory_first = response_first.json()["inventory"]
    device_first = inventory_first["devices"][0]
    
    # Verify vty_exec_timeout_seconds is undetected and the rule NEEDS_REVIEW
    vty_findings_first = [x for x in device_first["findings"] if "idle timeout" in x["title"].lower() or "vty_idle_timeout" in x["rule_id"]]
    assert len(vty_findings_first) > 0
    assert any(x["status"] == "NEEDS_REVIEW" for x in vty_findings_first)

    # Propose/Create and Approve a mapping for vty_exec_timeout_seconds
    mapping = {
        "mapping_id": "LM-VTY-E2E",
        "vendor": "cisco_ios",
        "pattern": "exec-timeout-custom",
        "field": "vty_exec_timeout_seconds",
        "extraction_strategy": "token",
        "status": "pending",
        "approval_state": "pending",
        "evidence_example": "exec-timeout-custom 15"
    }
    create_res = test_client.post("/training", json=mapping)
    assert create_res.status_code == 200
    approve_res = test_client.post("/training/LM-VTY-E2E/approve")
    assert approve_res.status_code == 200
    
    # Second upload of the same configuration
    response_second = _upload(test_client, [("cisco.conf", config_data)])
    assert response_second.status_code == 200
    inventory_second = response_second.json()["inventory"]
    device_second = inventory_second["devices"][0]
    
    # The previously unknown field is now FOUND (15) with origin LEARNED and the correct evidence
    vty_findings_second = [x for x in device_second["findings"] if "idle timeout" in x["title"].lower() or "vty_idle_timeout" in x["rule_id"]]
    assert len(vty_findings_second) > 0
    
    # Now it passes since vty_exec_timeout_seconds resolved to 15 (which is <= 600)
    assert all(x["status"] == "PASS" for x in vty_findings_second)
    
    # Verify that the evidence points to the administrator-trained mapping and preserves original line
    evidence = vty_findings_second[0]["evidence"][0]
    assert evidence["origin"] == Origin.LEARNED.value
    assert evidence["mapping_id"] == "LM-VTY-E2E"
    assert evidence["original_line_number"] == 45
    assert "exec-timeout-custom 15" in evidence["source_line"]

# 5. Security & Input validations
def test_invalid_operations_rejected(test_client):
    # Unknown baseline field rejected
    mapping_bad_field = {
        "mapping_id": "LM-BAD-01",
        "vendor": "cisco_ios",
        "pattern": "test",
        "field": "nonexistent_field_xyz",
        "extraction_strategy": "exact",
        "status": "approved",
        "approval_state": "approved"
    }
    res = test_client.post("/training", json=mapping_bad_field)
    assert res.status_code == 400
    assert "Unknown baseline field" in res.json()["detail"]

    # Malformed regex rejected
    mapping_bad_regex = {
        "mapping_id": "LM-BAD-02",
        "vendor": "cisco_ios",
        "pattern": "test",
        "field": "vty_exec_timeout_seconds",
        "extraction_strategy": "regex",
        "regex_pattern": "timeout (\\d+", # missing closing parenthesis
        "status": "approved",
        "approval_state": "approved"
    }
    res = test_client.post("/training", json=mapping_bad_regex)
    assert res.status_code == 400
    assert "Invalid regex pattern" in res.json()["detail"]

    # Unapproved mapping does not affect parsing
    mapping_unapproved = {
        "mapping_id": "LM-UNAPPROVED",
        "vendor": "cisco_ios",
        "pattern": "exec-timeout-custom",
        "field": "vty_exec_timeout_seconds",
        "extraction_strategy": "token",
        "status": "pending",
        "approval_state": "pending",
        "evidence_example": "exec-timeout-custom 15"
    }
    create_res = test_client.post("/training", json=mapping_unapproved)
    assert create_res.status_code == 200
    
    # Upload: should still be NEEDS_REVIEW (not PASS) because the mapping is unapproved
    config_text = _sample_bytes("insecure_ios.conf").decode("utf-8").replace("exec-timeout 0 0", "")
    config_data = (config_text + "\nexec-timeout-custom 15\n").encode("utf-8")
    response = _upload(test_client, [("cisco.conf", config_data)])
    inventory = response.json()["inventory"]
    device = inventory["devices"][0]
    vty_findings = [x for x in device["findings"] if "idle timeout" in x["title"].lower() or "vty_idle_timeout" in x["rule_id"]]
    assert any(x["status"] == "NEEDS_REVIEW" for x in vty_findings)
