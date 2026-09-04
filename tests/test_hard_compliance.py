"""Unit tests for Hard Compliance Benchmark Suite."""

import json
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
HARD_COMP_PATH = REPO_ROOT / "benchmarks" / "human_verified" / "compliance_hard.jsonl"

def test_hard_compliance_suite_structure():
    """Verify hard compliance benchmark contains subtle, absence, and vendor controls with zero verdict leakage."""
    assert HARD_COMP_PATH.exists()
    items = [json.loads(l) for l in open(HARD_COMP_PATH, encoding="utf-8") if l.strip()]
    assert len(items) >= 15

    labels = set(it["gold_label"] for it in items)
    assert "COMPLIANT" in labels
    assert "NON_COMPLIANT" in labels

    for it in items:
        inp = it["input"]
        # Zero target leakage in input
        assert "Status: COMPLIANT" not in inp
        assert "Status: NON_COMPLIANT" not in inp
        assert "verdict" not in inp.lower()
        assert "Control:" in inp
        assert "Config Snippet:" in inp

def test_hard_compliance_vendor_diversity():
    """Verify coverage of Cisco, Juniper, Fortinet, Huawei, Nokia, MikroTik in hard compliance."""
    items = [json.loads(l) for l in open(HARD_COMP_PATH, encoding="utf-8") if l.strip()]
    vendors = set(it["vendor"] for it in items)
    assert len(vendors) >= 4
