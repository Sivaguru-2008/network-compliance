"""Unit tests for Token-Level NER Exact Span Alignment & Entity Span Metrics."""

import json
from pathlib import Path
import pytest
from nlp_pipeline.dataset_builder import _tokenize_with_spans
from nlp_pipeline.trainer import TokenLevelNERModel, _extract_entity_spans

def test_token_span_offsets():
    """Verify that _tokenize_with_spans produces valid character slice offsets."""
    text = "interface GigabitEthernet0/1\n ip address 10.0.1.1 255.255.255.0"
    toks = _tokenize_with_spans(text)
    for tok, start, end in toks:
        assert text[start:end] == tok

def test_extract_entity_spans_function():
    """Verify conversion of BIO tags to entity spans."""
    tags = ["O", "B-INTERFACE", "O", "O", "B-IP_ADDRESS", "B-SUBNET"]
    spans = _extract_entity_spans(tags)
    assert ("INTERFACE", 1, 1) in spans
    assert ("IP_ADDRESS", 4, 4) in spans
    assert ("SUBNET", 5, 5) in spans

def test_ner_model_entity_f1_metrics():
    """Verify that TokenLevelNERModel reports Entity Precision, Recall, and Entity Macro-F1."""
    sentences = [
        ["interface", "GigabitEthernet0/1", "ip", "address", "10.0.1.1", "255.255.255.0"],
        ["access-list", "101", "permit", "tcp", "10.0.0.0", "any", "eq", "22"],
        ["crypto", "ipsec", "transform-set", "SECURE", "esp-aes", "256"],
    ]
    tags = [
        ["O", "B-INTERFACE", "O", "O", "B-IP_ADDRESS", "B-SUBNET"],
        ["O", "B-ACL", "O", "B-PROTOCOL", "B-IP_ADDRESS", "O", "O", "B-PORT"],
        ["O", "O", "O", "B-SERVICE", "B-CRYPTO_ALGORITHM", "O"],
    ]

    model = TokenLevelNERModel()
    model.fit(sentences, tags)
    metrics = model.evaluate(sentences, tags)

    assert "entity_precision" in metrics
    assert "entity_recall" in metrics
    assert "entity_f1" in metrics
    assert "entity_macro_f1" in metrics
    assert metrics["entity_f1"] >= 0.70
