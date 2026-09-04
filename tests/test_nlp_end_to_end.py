"""End-to-end integration tests for Multi-Vendor Network Security NLP Pipeline."""

import pytest
from pathlib import Path
from nlp_pipeline.extractor import SecuritySemanticExtractor
from nlp_pipeline.dataset_builder import NLPDatasetBuilder
from nlp_pipeline.trainer import NLPTrainingPipeline, SecurityNLPModel

def test_semantic_extractor_cisco_multi_feature():
    lines = [
        "hostname core-rtr-01",
        "interface GigabitEthernet0/1",
        " ip address 10.0.1.1 255.255.255.0",
        " no shutdown",
        "!",
        "router ospf 1",
        " area 0",
        "!",
        "line vty 0 4",
        " transport input telnet",
        "!",
        "snmp-server community public RO",
    ]
    raw_cfg = "\n".join(lines)
    extractor = SecuritySemanticExtractor()
    cfg = extractor.extract(raw_cfg, file_id="test_cisco_01", vendor_slug="cisco_ios")
    assert cfg.device.hostname == "core-rtr-01"
    assert len(cfg.interfaces) == 1
    assert cfg.interfaces[0].ip_address == "10.0.1.1"
    assert "OSPF" in cfg.routing.protocols
    assert cfg.security_features["TELNET_ENABLED"] is True
    assert cfg.security_features["DEFAULT_CREDENTIAL"] is True
    assert any(f["finding"] == "TELNET_ENABLED" for f in cfg.findings)

def test_security_nlp_model_fit_evaluate():
    texts = [
        "line vty 0 4\n transport input telnet",
        "line vty 0 4\n transport input ssh",
        "snmp-server community public RO",
        "snmp-server community SECURE-COMM RO 99",
    ]
    labels = ["TELNET_ENABLED", "SECURE_BASELINE", "DEFAULT_CREDENTIAL", "SECURE_BASELINE"]

    model = SecurityNLPModel(task_name="test_detection")
    model.fit(texts, labels)
    metrics = model.evaluate(texts, labels)

    assert metrics["accuracy"] >= 0.75
    assert "macro_f1" in metrics
    assert "critical_finding_recall" in metrics
