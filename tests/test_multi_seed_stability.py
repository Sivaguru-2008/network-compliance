"""Unit tests for Multi-Seed Evaluation Stability."""

import pytest
import numpy as np
from nlp_pipeline.trainer import SecurityNLPModel

def test_multi_seed_deterministic_variance():
    """Verify evaluation consistency across seeds 42, 123, 456."""
    train_texts = [
        "interface GigabitEthernet0/1\n ip address 10.0.1.1 255.255.255.0",
        "router bgp 65001\n neighbor 10.0.0.2 remote-as 65002",
        "ip access-list extended ACL-1\n permit ip any any",
        "line vty 0 4\n transport input ssh",
    ]
    train_labels = ["INTERFACE", "ROUTING", "FIREWALL", "MANAGEMENT"]

    f1_scores = []
    for seed in [42, 123, 456]:
        model = SecurityNLPModel(task_name="classification", random_seed=seed)
        model.fit(train_texts, train_labels)
        m = model.evaluate(train_texts, train_labels)
        f1_scores.append(m["macro_f1"])

    assert len(f1_scores) == 3
    assert np.std(f1_scores) < 0.15
