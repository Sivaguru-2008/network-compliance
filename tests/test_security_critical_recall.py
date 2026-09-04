"""Unit tests for Security Detection Critical Recall & Optimization."""

import json
from pathlib import Path
import pytest
from nlp_pipeline.trainer import SecurityNLPModel

REPO_ROOT = Path(__file__).resolve().parent.parent

def test_security_detection_model_critical_recall():
    """Verify that Security Detection model measures critical finding recall and precision."""
    train_texts = [
        "line vty 0 4\n transport input telnet",
        "snmp-server community public RO",
        "crypto ipsec transform-set TS esp-des esp-md5-hmac",
        "ip access-list extended OPEN\n permit ip any any",
        "line vty 0 4\n transport input ssh\n access-class 10 in",
        "logging host 10.1.1.1\nlogging buffered 64000",
        "ntp server 10.1.1.1\nntp authenticate",
    ]
    train_labels = [
        "TELNET_ENABLED",
        "DEFAULT_CREDENTIAL",
        "WEAK_CRYPTO",
        "ANY_TO_ANY_RULE",
        "SECURE_BASELINE",
        "SECURE_BASELINE",
        "SECURE_BASELINE",
    ]

    model = SecurityNLPModel(task_name="security_detection", random_seed=42)
    model.fit(train_texts, train_labels)

    metrics = model.evaluate(train_texts, train_labels, split_name="train_eval")
    assert "critical_finding_recall" in metrics
    assert "critical_finding_precision" in metrics
    assert metrics["critical_finding_recall"] >= 0.70
    assert metrics["accuracy"] >= 0.70
