"""Evaluation of V2.3 Model Candidates on Frozen Benchmarks."""

import json
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from nlp_pipeline.v23_compliance import GroundedComplianceEngine
from nlp_pipeline.v23_cross_vendor import (
    CrossVendorGeneralizationModel,
    extract_rich_canonical_semantics,
)
from nlp_pipeline.v23_ner import HybridNEREngine, tokenize_with_spans
from nlp_pipeline.v23_qa import GroundedQAEngine


def evaluate_v23_compliance():
    print("\n--- Evaluating V2.3 Compliance Engine ---")
    engine = GroundedComplianceEngine()
    benchmarks_dir = REPO_ROOT / "benchmarks" / "human_verified"

    # 1. Gold Benchmark
    gold_items = [json.loads(l) for l in open(benchmarks_dir / "compliance.jsonl", encoding="utf-8") if l.strip()]
    gold_true = [it["gold_label"] for it in gold_items]
    gold_preds = [engine.evaluate_snippet(it["input"])["status"] for it in gold_items]

    acc_gold = accuracy_score(gold_true, gold_preds)
    f1_gold = f1_score(gold_true, gold_preds, average="macro", zero_division=0)
    print(f"  Compliance Gold Benchmark (24 items): Accuracy = {acc_gold:.4f}, Macro-F1 = {f1_gold:.4f}")

    # 2. Hard Benchmark
    hard_items = [json.loads(l) for l in open(benchmarks_dir / "compliance_hard.jsonl", encoding="utf-8") if l.strip()]
    hard_true = [it["gold_label"] for it in hard_items]
    hard_preds = [engine.evaluate_snippet(it["input"])["status"] for it in hard_items]

    acc_hard = accuracy_score(hard_true, hard_preds)
    f1_hard = f1_score(hard_true, hard_preds, average="macro", zero_division=0)
    print(f"  Compliance Hard Benchmark (16 items): Accuracy = {acc_hard:.4f}, Macro-F1 = {f1_hard:.4f}")

    return {
        "gold_macro_f1": f1_gold,
        "gold_accuracy": acc_gold,
        "hard_macro_f1": f1_hard,
        "hard_accuracy": acc_hard,
    }


def evaluate_v23_qa():
    print("\n--- Evaluating V2.3 QA Engine ---")
    engine = GroundedQAEngine()
    benchmarks_dir = REPO_ROOT / "benchmarks" / "human_verified"

    gold_items = [json.loads(l) for l in open(benchmarks_dir / "qa.jsonl", encoding="utf-8") if l.strip()]
    gold_true = [it["gold_label"] for it in gold_items]
    gold_preds = [engine.answer_question(it["input"])["answer"] for it in gold_items]

    acc_gold = accuracy_score(gold_true, gold_preds)
    f1_gold = f1_score(gold_true, gold_preds, average="macro", zero_division=0)
    print(f"  QA Gold Benchmark (16 items): Accuracy = {acc_gold:.4f}, Macro-F1 = {f1_gold:.4f}")

    return {
        "gold_macro_f1": f1_gold,
        "gold_accuracy": acc_gold,
    }


def evaluate_v23_ner():
    print("\n--- Evaluating V2.3 NER Engine ---")
    dataset_dir = REPO_ROOT / "nlp_dataset"
    benchmarks_dir = REPO_ROOT / "benchmarks" / "human_verified"

    train_items = [json.loads(l) for l in open(dataset_dir / "ner" / "train.jsonl", encoding="utf-8") if l.strip()]
    train_toks = [ex.get("tokens", ex["input"].split()) for ex in train_items]
    train_tags = [ex.get("tags", ["O"] * len(ex["input"].split())) for ex in train_items]

    engine = HybridNEREngine()
    engine.fit(train_toks, train_tags)

    # Gold evaluation
    gold_items = [json.loads(l) for l in open(benchmarks_dir / "ner.jsonl", encoding="utf-8") if l.strip()]
    gold_tok_sentences = []
    gold_tag_sentences = []
    gold_texts = []

    for item in gold_items:
        text = item["input"]
        gold_texts.append(text)
        tok_spans = tokenize_with_spans(text)
        toks = [t[0] for t in tok_spans]
        tags = ["O"] * len(toks)
        ents = item.get("entities", [])
        for e in ents:
            e_text = e["text"]
            e_type = e["type"]
            for idx, (tok, s, end_s) in enumerate(tok_spans):
                if tok == e_text or tok in e_text.split():
                    tags[idx] = f"B-{e_type}"
        gold_tok_sentences.append(toks)
        gold_tag_sentences.append(tags)

    metrics = engine.evaluate(gold_tok_sentences, gold_tag_sentences, full_texts=gold_texts)
    print(f"  NER Gold Benchmark: Entity Precision = {metrics['entity_precision']:.4f}, Recall = {metrics['entity_recall']:.4f}, Entity Macro-F1 = {metrics['entity_macro_f1']:.4f}, Token Acc = {metrics['token_accuracy']:.4f}")
    return metrics


def evaluate_v23_cross_vendor():
    print("\n--- Evaluating V2.3 Cross-Vendor Models ---")
    dataset_dir = REPO_ROOT / "nlp_dataset"
    train_vendors = {"cisco_ios", "cisco_asa", "cisco", "juniper_junos", "juniper", "arista_eos", "arista", "fortinet_fortios", "fortinet"}
    test_vendors = {"huawei_vrp", "huawei", "paloalto_panos", "paloalto", "mikrotik_routeros", "mikrotik", "nokia_sros", "nokia", "f5_bigip_tmos", "f5", "sonic", "netgate_pfsense", "netgate"}

    raw_items = [json.loads(l) for l in open(dataset_dir / "raw" / "security_detection.jsonl", encoding="utf-8") if l.strip()]

    train_subset = [ex for ex in raw_items if any(v in ex["vendor"].lower() for v in train_vendors)]
    test_subset = [ex for ex in raw_items if any(v in ex["vendor"].lower() for v in test_vendors)]

    train_x = [e["input"] for e in train_subset]
    train_y = [e["output"] if isinstance(e["output"], str) else e["output"]["finding"] for e in train_subset]
    test_x = [e["input"] for e in test_subset]
    test_y = [e["output"] if isinstance(e["output"], str) else e["output"]["finding"] for e in test_subset]

    modes = ["raw_only", "canonical_only", "raw_canonical", "raw_canonical_char"]
    results = {}
    for mode in modes:
        model = CrossVendorGeneralizationModel(feature_mode=mode, random_seed=42)
        model.fit(train_x, train_y)
        m = model.evaluate(test_x, test_y, split_name=f"held_out_{mode}")
        results[mode] = m
        print(f"  Mode [{mode}]: Accuracy = {m['accuracy']:.4f}, Macro-F1 = {m['macro_f1']:.4f}, Weighted-F1 = {m['weighted_f1']:.4f}, Critical Recall = {m['critical_recall']:.4f}")

    return results


if __name__ == "__main__":
    comp_res = evaluate_v23_compliance()
    qa_res = evaluate_v23_qa()
    ner_res = evaluate_v23_ner()
    cv_res = evaluate_v23_cross_vendor()
