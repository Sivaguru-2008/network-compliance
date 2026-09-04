"""V2.3 Master Improvement and Verification Engine.

Executes Phase 1 (Freeze V2.2) and Phase 2 (Error Analysis).
"""

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import joblib
import numpy as np

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from nlp_pipeline.extractor import SecuritySemanticExtractor
from nlp_pipeline.trainer import (
    NLPTrainingPipeline,
    SecurityNLPModel,
    TokenLevelNERModel,
    _tokenize_with_spans,
    preprocess_config_text,
)


def hash_file(p: Path) -> str:
    if not p.exists():
        return "MISSING"
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def compute_directory_hashes(d: Path) -> Dict[str, str]:
    res = {}
    if not d.exists():
        return res
    for root, _, files in os.walk(d):
        for f in sorted(files):
            p = Path(root) / f
            rel = str(p.relative_to(d)).replace("\\", "/")
            res[rel] = hash_file(p)
    return res


def phase1_freeze_v22() -> Dict[str, Any]:
    print("\n" + "=" * 60)
    print("PHASE 1 — FREEZING V2.2 STATE")
    print("=" * 60)

    dataset_dir = REPO_ROOT / "nlp_dataset"
    benchmarks_dir = REPO_ROOT / "benchmarks" / "human_verified"
    models_dir = REPO_ROOT / "models"

    gold_hashes = {
        "compliance.jsonl": hash_file(benchmarks_dir / "compliance.jsonl"),
        "compliance_hard.jsonl": hash_file(benchmarks_dir / "compliance_hard.jsonl"),
        "qa.jsonl": hash_file(benchmarks_dir / "qa.jsonl"),
        "ner.jsonl": hash_file(benchmarks_dir / "ner.jsonl"),
        "security_detection.jsonl": hash_file(benchmarks_dir / "security_detection.jsonl"),
    }

    train_hashes = compute_directory_hashes(dataset_dir / "train")
    test_hashes = compute_directory_hashes(dataset_dir / "test")
    val_hashes = compute_directory_hashes(dataset_dir / "validation")

    vendor_split = {
        "training_vendors": ["cisco_ios", "cisco_asa", "cisco", "juniper_junos", "juniper", "arista_eos", "arista", "fortinet_fortios", "fortinet"],
        "held_out_vendors": ["huawei_vrp", "huawei", "paloalto_panos", "paloalto", "mikrotik_routeros", "mikrotik", "nokia_sros", "nokia", "f5_bigip_tmos", "f5", "sonic", "netgate_pfsense", "netgate"]
    }

    v22_baseline = {
        "security_critical_recall": 0.9744,
        "security_macro_f1": 0.5150,
        "compliance_gold_macro_f1": 0.4667,
        "compliance_hard_macro_f1": 0.4353,
        "qa_gold_macro_f1": 0.5608,
        "ner_gold_entity_f1": 0.2755,
        "section_macro_f1": 0.6904,
        "cross_vendor_macro_f1": 0.4087,
        "cross_vendor_weighted_f1": 0.7897,
        "integrity": {
            "target_leakage": 0,
            "synthetic_leakage": 0,
            "config_overlap": 0,
            "duplicate_overlap": 0,
            "gold_contamination": 0,
            "secrets_remaining": 0
        }
    }

    freeze_record = {
        "version": "2.3.0",
        "phase": "FREEZE_V2.2",
        "timestamp": "2026-09-02T22:45:00Z",
        "v22_baseline": v22_baseline,
        "gold_benchmark_hashes": gold_hashes,
        "training_split_hashes": train_hashes,
        "test_split_hashes": test_hashes,
        "validation_split_hashes": val_hashes,
        "vendor_split": vendor_split,
        "evaluation_configuration": {
            "eval_seeds": [42, 123, 456, 789, 2026],
            "solver": "lbfgs",
            "max_iter": 1000,
            "class_weight": "balanced"
        }
    }

    reports_dir = REPO_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_file = reports_dir / "model_improvement_v23.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(freeze_record, f, indent=2)

    print(f"Recorded freeze state to {report_file}")
    for k, v in gold_hashes.items():
        print(f"  Gold Hash [{k}]: {v[:16]}...")
    return freeze_record


def phase2_error_analysis():
    print("\n" + "=" * 60)
    print("PHASE 2 — AUTOMATED ERROR ANALYSIS (V2.2 MODELS)")
    print("=" * 60)

    dataset_dir = REPO_ROOT / "nlp_dataset"
    benchmarks_dir = REPO_ROOT / "benchmarks" / "human_verified"
    models_dir = REPO_ROOT / "models"

    errors_by_task = {}

    # 1. Compliance Error Analysis
    print("\n--- Analyzing Compliance Errors ---")
    comp_errors = []
    comp_model_path = models_dir / "compliance" / "model.joblib"
    if comp_model_path.exists():
        comp_pipe = joblib.load(comp_model_path)
        comp_le = joblib.load(models_dir / "compliance" / "label_encoder.joblib")

        # Evaluate against gold and hard
        for benchmark_name in ["compliance.jsonl", "compliance_hard.jsonl"]:
            bpath = benchmarks_dir / benchmark_name
            if bpath.exists():
                for line in open(bpath, encoding="utf-8"):
                    if not line.strip():
                        continue
                    item = json.loads(line)
                    inp = item["input"]
                    true_lbl = item.get("gold_label") or item.get("output")
                    prob = comp_pipe.predict_proba([inp])[0]
                    top_idx = int(np.argmax(prob))
                    pred_lbl = str(comp_le.classes_[top_idx])
                    conf = float(prob[top_idx])

                    if pred_lbl != true_lbl:
                        category = "unknown"
                        if "telnet" in inp.lower() and "CIS-2.1.1" in inp:
                            category = "multi-line dependency / partial compliance"
                        elif "http" in inp.lower() and "CIS-2.2.1" in inp:
                            category = "vendor syntax / absence-based control"
                        elif "snmp" in inp.lower() and "CIS-1.3.1" in inp:
                            category = "string substring / regex confusion"
                        elif "crypto" in inp.lower() and "CIS-4.1.2" in inp:
                            category = "multi-line crypto algorithm check"
                        elif "any" in inp.lower() and "CIS-3.1.4" in inp:
                            category = "acl shadowing / multi-line rule evaluation"
                        elif "logging" in inp.lower() or "info-center" in inp.lower():
                            category = "vendor syntax / absence reasoning"
                        elif "ntp" in inp.lower():
                            category = "vendor syntax / enabled=no flag"

                        comp_errors.append({
                            "benchmark": benchmark_name,
                            "config_id": item.get("config_id", "unknown"),
                            "vendor": item.get("vendor", "unknown"),
                            "true_label": true_lbl,
                            "predicted_label": pred_lbl,
                            "confidence": round(conf, 4),
                            "category": category,
                            "snippet": inp[:120].replace("\n", " ")
                        })

    errors_by_task["compliance"] = {
        "error_count": len(comp_errors),
        "errors": comp_errors
    }
    print(f"  Total Compliance Errors Captured: {len(comp_errors)}")
    for e in comp_errors:
        print(f"    [{e['benchmark']}] ({e['vendor']}) True={e['true_label']} Pred={e['predicted_label']} (Conf={e['confidence']}) Cat: {e['category']}")

    # 2. QA Error Analysis
    print("\n--- Analyzing QA Errors ---")
    qa_errors = []
    qa_model_path = models_dir / "qa" / "model.joblib"
    if qa_model_path.exists():
        qa_pipe = joblib.load(qa_model_path)
        qa_le = joblib.load(models_dir / "qa" / "label_encoder.joblib")
        qpath = benchmarks_dir / "qa.jsonl"
        if qpath.exists():
            for line in open(qpath, encoding="utf-8"):
                if not line.strip():
                    continue
                item = json.loads(line)
                inp = item["input"]
                true_lbl = item.get("gold_label") or item.get("output")
                prob = qa_pipe.predict_proba([inp])[0]
                top_idx = int(np.argmax(prob))
                pred_lbl = str(qa_le.classes_[top_idx])
                conf = float(prob[top_idx])

                if pred_lbl != true_lbl:
                    category = "wrong intent / bag-of-words confusion"
                    if "weak" in inp.lower() or "crypto" in inp.lower():
                        category = "crypto concept extraction failure"
                    elif "ssh" in inp.lower() or "telnet" in inp.lower():
                        category = "negation / delete command misinterpretation"
                    elif "acl" in inp.lower() or "rules" in inp.lower():
                        category = "unrestricted rule reasoning failure"

                    qa_errors.append({
                        "config_id": item.get("config_id", "unknown"),
                        "vendor": item.get("vendor", "unknown"),
                        "true_label": true_lbl,
                        "predicted_label": pred_lbl,
                        "confidence": round(conf, 4),
                        "category": category,
                        "snippet": inp[:120].replace("\n", " ")
                    })

    errors_by_task["qa"] = {
        "error_count": len(qa_errors),
        "errors": qa_errors
    }
    print(f"  Total QA Errors Captured: {len(qa_errors)}")
    for e in qa_errors:
        print(f"    ({e['vendor']}) True={e['true_label']} Pred={e['predicted_label']} (Conf={e['confidence']}) Cat: {e['category']}")

    # 3. NER Error Analysis
    print("\n--- Analyzing NER Errors ---")
    ner_model_path = models_dir / "ner" / "model.joblib"
    ner_errors = []
    if ner_model_path.exists():
        ner_clf = joblib.load(ner_model_path)
        ner_vec = joblib.load(models_dir / "ner" / "vectorizer.joblib")
        ner_le = joblib.load(models_dir / "ner" / "label_encoder.joblib")

        npath = benchmarks_dir / "ner.jsonl"
        if npath.exists():
            for line in open(npath, encoding="utf-8"):
                if not line.strip():
                    continue
                item = json.loads(line)
                tok_spans = _tokenize_with_spans(item["input"])
                toks = [t[0] for t in tok_spans]
                gold_ents = item.get("entities", [])
                
                # Predict
                feats = [TokenLevelNERModel()._extract_token_features(toks, i) for i in range(len(toks))]
                X = ner_vec.transform(feats)
                preds = [str(ner_le.classes_[idx]) for idx in ner_clf.predict(X)]

                for g in gold_ents:
                    g_text = g["text"]
                    g_type = g["type"]
                    # check if captured
                    found = False
                    for idx, (t, s, e) in enumerate(tok_spans):
                        if (t == g_text or t in g_text.split()) and preds[idx] == f"B-{g_type}":
                            found = True
                            break
                    if not found:
                        ner_errors.append({
                            "config_id": item.get("config_id", "unknown"),
                            "vendor": item.get("vendor", "unknown"),
                            "entity_text": g_text,
                            "entity_type": g_type,
                            "category": "missed entity / boundary / vendor token"
                        })

    errors_by_task["ner"] = {
        "error_count": len(ner_errors),
        "errors": ner_errors[:15]
    }
    print(f"  Total Missed NER Gold Spans: {len(ner_errors)}")
    for e in ner_errors[:8]:
        print(f"    ({e['vendor']}) Entity='{e['entity_text']}' Type={e['entity_type']} Cat: {e['category']}")

    return errors_by_task


if __name__ == "__main__":
    freeze_rec = phase1_freeze_v22()
    err_rec = phase2_error_analysis()
