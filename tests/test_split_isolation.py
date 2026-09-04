"""Unit tests for Configuration-Level Grouping and Split Isolation."""

import pytest
from nlp_pipeline.dataset_builder import NLPDatasetBuilder
from nlp_pipeline.extractor import SecuritySemanticExtractor

def test_split_configuration_isolation():
    extractor = SecuritySemanticExtractor()
    configs = []
    for i in range(10):
        c = extractor.extract(
            f"hostname router-{i}\ninterface GigabitEthernet0/{i}\n ip address 10.0.{i}.1 255.255.255.0\n!",
            file_id=f"cfg_{i:03d}",
            vendor_slug="cisco_ios" if i < 5 else "juniper_junos"
        )
        configs.append(c)

    builder = NLPDatasetBuilder()
    train_cfgs, val_cfgs, test_cfgs = builder._split_configurations(configs)

    train_ids = set(c.file_id for c in train_cfgs)
    val_ids = set(c.file_id for c in val_cfgs)
    test_ids = set(c.file_id for c in test_cfgs)

    assert len(train_ids & val_ids) == 0, "Train and Val configuration overlap detected!"
    assert len(train_ids & test_ids) == 0, "Train and Test configuration overlap detected!"
    assert len(val_ids & test_ids) == 0, "Val and Test configuration overlap detected!"
    assert len(train_ids | val_ids | test_ids) == len(configs)

def test_verify_leakage_helper():
    builder = NLPDatasetBuilder()
    clean_splits = {
        "train": {"b": [{"source_file_id": "c1", "input": "line vty 0 4\n transport input telnet"}]},
        "validation": {"b": [{"source_file_id": "c2", "input": "line vty 0 4\n transport input ssh"}]},
        "test": {"b": [{"source_file_id": "c3", "input": "snmp-server community public"}]},
    }
    leak_pass, msg = builder._verify_leakage(clean_splits)
    assert leak_pass is True

    leaky_splits = {
        "train": {"b": [{"source_file_id": "c1", "input": "line vty 0 4\n transport input telnet"}]},
        "validation": {"b": [{"source_file_id": "c2", "input": "line vty 0 4\n transport input ssh"}]},
        "test": {"b": [{"source_file_id": "c1", "input": "snmp-server community public"}]},
    }
    leak_pass, msg = builder._verify_leakage(leaky_splits)
    assert leak_pass is False
    assert "CONFIG LEAKAGE" in msg
