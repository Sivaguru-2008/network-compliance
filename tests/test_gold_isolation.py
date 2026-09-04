"""Unit tests for Gold Benchmark Isolation & Zero Contamination."""

import json
from pathlib import Path
import pytest
from nlp_pipeline.trainer import preprocess_config_text

REPO_ROOT = Path(__file__).resolve().parent.parent
BENCHMARKS_DIR = REPO_ROOT / "benchmarks" / "human_verified"
DATASET_DIR = REPO_ROOT / "nlp_dataset"

def test_gold_benchmarks_exist_and_non_empty():
    """Verify all gold benchmark suites exist and have human-verified examples."""
    expected = ["security_detection.jsonl", "compliance.jsonl", "compliance_hard.jsonl", "qa.jsonl", "ner.jsonl"]
    for b in expected:
        p = BENCHMARKS_DIR / b
        assert p.exists(), f"Missing gold benchmark {b}"
        lines = [l for l in open(p, encoding="utf-8") if l.strip()]
        assert len(lines) >= 10, f"Gold benchmark {b} has too few examples: {len(lines)}"

def test_zero_gold_contamination_in_training():
    """Verify that NO gold benchmark text occurs in the training partition."""
    train_texts = set()
    train_dir = DATASET_DIR / "train"
    if not train_dir.exists():
        pytest.skip("Dataset not yet built")

    for tf in train_dir.glob("*.jsonl"):
        for l in open(tf, encoding="utf-8"):
            if l.strip():
                ex = json.loads(l)
                train_texts.add(preprocess_config_text(ex["input"]))

    for gf in BENCHMARKS_DIR.glob("*.jsonl"):
        for l in open(gf, encoding="utf-8"):
            if l.strip():
                g = json.loads(l)
                ginp = preprocess_config_text(g["input"])
                assert ginp not in train_texts, f"Contamination detected in {gf.name}: {g['input'][:50]}"
