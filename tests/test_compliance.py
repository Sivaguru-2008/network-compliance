"""Unit tests for Grounded Compliance Status Classification."""

import pytest
from nlp_pipeline.dataset_builder import NLPDatasetBuilder
from nlp_pipeline.extractor import SecuritySemanticExtractor

def test_compliance_non_compliant_detection():
    cfg_text = "hostname R1\nline vty 0 4\n transport input telnet\n!"
    extractor = SecuritySemanticExtractor()
    cfg = extractor.extract(cfg_text, file_id="test_comp_fail", vendor_slug="cisco_ios")
    raw_texts = {"test_comp_fail": cfg_text}

    builder = NLPDatasetBuilder()
    examples = builder._generate_task_c_compliance([cfg], raw_texts)

    telnet_comp = next((e for e in examples if "CIS-2.1.1" in e["input"]), None)
    assert telnet_comp is not None
    assert telnet_comp["output"] == "NON_COMPLIANT"
    assert "NON_COMPLIANT" not in telnet_comp["input"]

def test_compliance_compliant_detection():
    cfg_text = "hostname R1\nline vty 0 4\n transport input ssh\n!"
    extractor = SecuritySemanticExtractor()
    cfg = extractor.extract(cfg_text, file_id="test_comp_pass", vendor_slug="cisco_ios")
    raw_texts = {"test_comp_pass": cfg_text}

    builder = NLPDatasetBuilder()
    examples = builder._generate_task_c_compliance([cfg], raw_texts)

    telnet_comp = next((e for e in examples if "CIS-2.1.1" in e["input"]), None)
    assert telnet_comp is not None
    assert telnet_comp["output"] == "COMPLIANT"
    assert "compliant posture verified" not in telnet_comp["input"].lower()
