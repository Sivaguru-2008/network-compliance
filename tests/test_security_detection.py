"""Unit tests for Grounded Security Finding Detection."""

import pytest
from nlp_pipeline.dataset_builder import NLPDatasetBuilder
from nlp_pipeline.extractor import SecuritySemanticExtractor

def test_security_detection_positive_finding():
    cfg_text = (
        "hostname Border-GW\n"
        "snmp-server community public RO\n"
        "line vty 0 4\n"
        " transport input telnet\n"
        "!"
    )
    extractor = SecuritySemanticExtractor()
    cfg = extractor.extract(cfg_text, file_id="test_sec_01", vendor_slug="cisco_ios")
    raw_texts = {"test_sec_01": cfg_text}

    builder = NLPDatasetBuilder()
    examples = builder._generate_task_b_security_detection([cfg], raw_texts)

    findings = [e["output"] for e in examples]
    assert "TELNET_ENABLED" in findings or "DEFAULT_CREDENTIAL" in findings

    for ex in examples:
        assert "<absent>" not in ex["input"]
        assert len(ex["input"].strip()) > 5

def test_security_detection_benign_baseline():
    cfg_text = (
        "hostname Secure-Core\n"
        "line vty 0 4\n"
        " transport input ssh\n"
        "!\n"
        "ntp server 10.1.1.100\n"
        "logging host 10.1.1.50\n"
        "!"
    )
    extractor = SecuritySemanticExtractor()
    cfg = extractor.extract(cfg_text, file_id="test_sec_02", vendor_slug="cisco_ios")
    raw_texts = {"test_sec_02": cfg_text}

    builder = NLPDatasetBuilder()
    examples = builder._generate_task_b_security_detection([cfg], raw_texts)

    labels = [e["output"] for e in examples]
    assert "SECURE_BASELINE" in labels
