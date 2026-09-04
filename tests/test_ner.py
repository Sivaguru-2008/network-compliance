"""Unit tests for Token-Level BIO Named Entity Recognition (NER)."""

import pytest
from nlp_pipeline.dataset_builder import NLPDatasetBuilder, _tokenize_with_spans
from nlp_pipeline.extractor import SecuritySemanticExtractor
from nlp_pipeline.trainer import TokenLevelNERModel

def test_tokenize_with_spans():
    text = "interface GigabitEthernet0/1 ip address 10.0.1.1 255.255.255.0"
    tokens_with_spans = _tokenize_with_spans(text)
    toks = [t[0] for t in tokens_with_spans]
    assert "GigabitEthernet0/1" in toks
    assert "10.0.1.1" in toks
    assert "255.255.255.0" in toks

def test_ner_bio_generation_from_real_config():
    extractor = SecuritySemanticExtractor()
    cfg_text = "interface GigabitEthernet0/1\n ip address 192.168.1.1 255.255.255.0\n!"
    cfg = extractor.extract(cfg_text, file_id="test_ner_01", vendor_slug="cisco_ios")
    raw_texts = {"test_ner_01": cfg_text}

    builder = NLPDatasetBuilder()
    examples = builder._generate_task_g_ner([cfg], raw_texts)

    assert len(examples) > 0
    ex = examples[0]
    assert "tokens" in ex
    assert "tags" in ex
    assert len(ex["tokens"]) == len(ex["tags"])
    assert "B-INTERFACE" in ex["tags"]
    assert any("B-IP_ADDRESS" in t for t in ex["tags"])

def test_token_level_ner_model_train_and_predict():
    sentences = [
        ["interface", "GigabitEthernet0/1", "ip", "address", "10.0.1.1", "255.255.255.0"],
        ["access-list", "101", "permit", "tcp", "10.0.0.0", "any", "eq", "22"],
        ["set", "interfaces", "ge-0/0/0", "unit", "0", "family", "inet", "address", "172.16.1.1/24"],
    ]
    tags = [
        ["O", "B-INTERFACE", "O", "O", "B-IP_ADDRESS", "B-SUBNET"],
        ["O", "B-ACL", "O", "B-PROTOCOL", "B-IP_ADDRESS", "O", "O", "B-PORT"],
        ["O", "O", "B-INTERFACE", "O", "O", "O", "O", "O", "B-IP_ADDRESS"],
    ]

    model = TokenLevelNERModel()
    model.fit(sentences, tags)

    preds = model.predict_sentence(["interface", "GigabitEthernet0/2", "ip", "address", "10.0.2.1"])
    assert len(preds) == 5
    assert preds[1] == "B-INTERFACE" or "INTERFACE" in preds[1]

    metrics = model.evaluate(sentences, tags)
    assert metrics["token_accuracy"] > 0.80
    assert "entity_f1" in metrics
