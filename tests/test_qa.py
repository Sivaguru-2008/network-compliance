"""Unit tests for Grounded Security Question Answering (QA)."""

import pytest
from nlp_pipeline.dataset_builder import NLPDatasetBuilder
from nlp_pipeline.extractor import SecuritySemanticExtractor

def test_qa_contains_configuration_context():
    cfg_text = (
        "hostname Edge-Router\n"
        "line vty 0 4\n"
        " transport input telnet\n"
        " login\n"
        "!\n"
        "snmp-server community public RO\n"
        "!"
    )
    extractor = SecuritySemanticExtractor()
    cfg = extractor.extract(cfg_text, file_id="test_qa_01", vendor_slug="cisco_ios")
    raw_texts = {"test_qa_01": cfg_text}

    builder = NLPDatasetBuilder()
    examples = builder._generate_task_d_qa([cfg], raw_texts)

    assert len(examples) > 0
    for ex in examples:
        inp = ex["input"]
        assert "Question:" in inp
        assert "Context:" in inp
        assert len(inp.splitlines()) >= 2
        assert ex["output"] in ("yes", "no")

def test_qa_answer_correctness():
    cfg_text_ssh = "hostname Secure-Rtr\nline vty 0 4\n transport input ssh\n!"
    extractor = SecuritySemanticExtractor()
    cfg = extractor.extract(cfg_text_ssh, file_id="test_qa_02", vendor_slug="cisco_ios")
    raw_texts = {"test_qa_02": cfg_text_ssh}

    builder = NLPDatasetBuilder()
    examples = builder._generate_task_d_qa([cfg], raw_texts)

    ssh_ex = next((e for e in examples if "Is SSH enabled?" in e["input"]), None)
    if ssh_ex:
        assert ssh_ex["output"] == "yes"

    telnet_ex = next((e for e in examples if "Is Telnet enabled?" in e["input"]), None)
    if telnet_ex:
        assert telnet_ex["output"] == "no"
