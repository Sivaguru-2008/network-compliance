"""Unit tests asserting Zero Target Label and Synthetic Evidence Leakage."""

import json
from pathlib import Path
import pytest
from nlp_pipeline.dataset_builder import NLPDatasetBuilder
from nlp_pipeline.extractor import SecuritySemanticExtractor

def test_no_synthetic_evidence_in_security_detection_input():
    extractor = SecuritySemanticExtractor()
    cfg = extractor.extract(
        "hostname R1\nline vty 0 4\n transport input telnet\n login\n!",
        file_id="test_leak_01",
        vendor_slug="cisco_ios"
    )
    raw_texts = {"test_leak_01": "hostname R1\nline vty 0 4\n transport input telnet\n login\n!"}
    builder = NLPDatasetBuilder()
    examples = builder._generate_task_b_security_detection([cfg], raw_texts)

    for ex in examples:
        inp = ex["input"].lower()
        # Input should not contain synthetic "<absent>" or finding labels
        assert "<absent>" not in inp, f"Synthetic token found in input: {ex['input']}"
        assert "evidence: " not in inp

def test_no_label_in_compliance_input():
    extractor = SecuritySemanticExtractor()
    cfg = extractor.extract(
        "hostname R1\nline vty 0 4\n transport input ssh\n!",
        file_id="test_comp_01",
        vendor_slug="cisco_ios"
    )
    raw_texts = {"test_comp_01": "hostname R1\nline vty 0 4\n transport input ssh\n!"}
    builder = NLPDatasetBuilder()
    examples = builder._generate_task_c_compliance([cfg], raw_texts)

    for ex in examples:
        inp = ex["input"]
        # Input must not leak the compliance verdict
        assert "compliant posture verified" not in inp.lower()
        assert "NON_COMPLIANT" not in inp
        assert "Evidence: <absent>" not in inp

def test_evidence_metadata_isolation():
    extractor = SecuritySemanticExtractor()
    cfg = extractor.extract(
        "snmp-server community public RO\n!",
        file_id="test_snmp_01",
        vendor_slug="cisco_ios"
    )
    raw_texts = {"test_snmp_01": "snmp-server community public RO\n!"}
    builder = NLPDatasetBuilder()
    examples = builder._generate_task_c_compliance([cfg], raw_texts)

    for ex in examples:
        assert "evidence" in ex
        assert isinstance(ex["evidence"], list)
        assert "input" in ex
        assert "output" in ex
