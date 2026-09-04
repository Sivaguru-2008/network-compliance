# Trainer generator
import os
import sys
from pathlib import Path

def write_trainer():
    code = '''"""Multi-Task NLP Training & Evaluation Pipeline for Network Security Compliance."""

import argparse
import collections
import json
import logging
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

logger = logging.getLogger(__name__)

# Preprocessor for configuration text
def preprocess_config_text(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r'\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b', '<IP>', text)
    text = re.sub(r'\\b[0-9a-fA-F]{4}:[0-9a-fA-F:]+\\b', '<IPV6>', text)
    text = re.sub(r'\\b\\d{5,}\\b', '<NUM>', text)
    return text

def build_feature_union() -> FeatureUnion:
    word_vec = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        max_features=4000,
        sublinear_tf=True,
        strip_accents="unicode",
        preprocessor=preprocess_config_text,
    )
    char_vec = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=6000,
        sublinear_tf=True,
        strip_accents="unicode",
        preprocessor=preprocess_config_text,
    )
    return FeatureUnion([
        ("word", word_vec),
        ("char", char_vec),
    ])


class SecurityNLPModel:
    """Standardized Security NLP Model with persistence & evaluation."""

    def __init__(self, task_name: str, random_seed: int = 42):
        self.task_name = task_name
        self.random_seed = random_seed
        self.label_encoder = LabelEncoder()
        self.pipeline: Optional[Pipeline] = None
        self.classes_: Optional[np.ndarray] = None
        self.metrics: Dict[str, Any] = {}
        self.training_metadata: Dict[str, Any] = {}

    def fit(self, texts: List[str], labels: List[str]) -> "SecurityNLPModel":
        encoded = self.label_encoder.fit_transform(labels)
        self.classes_ = self.label_encoder.classes_

        features = build_feature_union()
        clf = LogisticRegression(
            C=1.0,
            class_weight="balanced",
            max_iter=1000,
            random_state=self.random_seed,
            solver="lbfgs",
        )
        self.pipeline = Pipeline([
            ("features", features),
            ("classifier", clf),
        ])
        t0 = time.time()
        self.pipeline.fit(texts, encoded)
        train_time = time.time() - t0

        self.training_metadata = {
            "task_name": self.task_name,
            "n_samples": len(texts),
            "n_classes": len(self.classes_),
            "classes": list(self.classes_),
            "training_time_seconds": round(train_time, 3),
            "random_seed": self.random_seed,
        }
        return self

    def predict(self, texts: List[str]) -> List[Dict[str, Any]]:
        if self.pipeline is None:
            raise RuntimeError("Model is not fitted.")
        probas = self.pipeline.predict_proba(texts)
        results = []
        for text, proba in zip(texts, probas):
            top_idx = int(np.argmax(proba))
            top_label = str(self.classes_[top_idx])
            top_conf = float(proba[top_idx])
            results.append({
                "text": text,
                "prediction": top_label,
                "confidence": round(top_conf, 4),
            })
        return results

    def evaluate(self, texts: List[str], true_labels: List[str], split_name: str = "test") -> Dict[str, Any]:
        preds = self.predict(texts)
        pred_labels = [p["prediction"] for p in preds]

        acc = accuracy_score(true_labels, pred_labels)
        labels_present = sorted(set(true_labels + pred_labels))

        prec_macro = precision_score(true_labels, pred_labels, labels=labels_present, average="macro", zero_division=0)
        rec_macro = recall_score(true_labels, pred_labels, labels=labels_present, average="macro", zero_division=0)
        f1_m = f1_score(true_labels, pred_labels, labels=labels_present, average="macro", zero_division=0)
        prec_w = precision_score(true_labels, pred_labels, labels=labels_present, average="weighted", zero_division=0)
        rec_w = recall_score(true_labels, pred_labels, labels=labels_present, average="weighted", zero_division=0)
        f1_w = f1_score(true_labels, pred_labels, labels=labels_present, average="weighted", zero_division=0)

        report = classification_report(true_labels, pred_labels, output_dict=True, zero_division=0)
        cm = confusion_matrix(true_labels, pred_labels, labels=labels_present).tolist()

        # Security-specific metrics: False Positives & Critical Finding Recall
        critical_classes = [c for c in labels_present if "DEFAULT" in c or "UNRESTRICTED" in c or "TELNET" in c or "WEAK" in c or "NON_COMPLIANT" in c]
        crit_recs = []
        for c in critical_classes:
            if c in report:
                crit_recs.append(report[c]["recall"])
        avg_crit_rec = float(np.mean(crit_recs)) if crit_recs else rec_macro

        fp_count = 0
        fn_count = 0
        for t, p in zip(true_labels, pred_labels):
            if t != p:
                if "COMPLIANT" in t and "NON_COMPLIANT" in p:
                    fp_count += 1
                elif "NON_COMPLIANT" in t and "COMPLIANT" in p:
                    fn_count += 1

        self.metrics = {
            "task": self.task_name,
            "split": split_name,
            "total_samples": len(texts),
            "accuracy": round(float(acc), 4),
            "precision_macro": round(float(prec_macro), 4),
            "recall_macro": round(float(rec_macro), 4),
            "macro_f1": round(float(f1_m), 4),
            "weighted_f1": round(float(f1_w), 4),
            "precision_weighted": round(float(prec_w), 4),
            "recall_weighted": round(float(rec_w), 4),
            "critical_finding_recall": round(float(avg_crit_rec), 4),
            "false_positives": fp_count,
            "false_negatives": fn_count,
            "per_class": {k: v for k, v in report.items() if isinstance(v, dict)},
            "confusion_matrix": cm,
            "class_names": labels_present,
        }
        return self.metrics

    def save(self, output_dir: Path, dataset_version: str = "2.0.0") -> Path:
        output_dir = Path(output_dir) / self.task_name
        output_dir.mkdir(parents=True, exist_ok=True)

        joblib.dump(self.pipeline, output_dir / "model.joblib")
        joblib.dump(self.label_encoder, output_dir / "label_encoder.joblib")

        (output_dir / "training_config.json").write_text(json.dumps(self.training_metadata, indent=2), encoding="utf-8")
        (output_dir / "evaluation_metrics.json").write_text(json.dumps(self.metrics, indent=2), encoding="utf-8")
        (output_dir / "dataset_version.json").write_text(json.dumps({
            "dataset_version": dataset_version,
            "task": self.task_name,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }, indent=2), encoding="utf-8")

        return output_dir


class NLPTrainingPipeline:
    """Orchestrates training and evaluation across all 7 Security NLP tasks."""

    def __init__(self, dataset_dir: Path = Path("nlp_dataset"), models_dir: Path = Path("models")):
        self.dataset_dir = Path(dataset_dir)
        self.models_dir = Path(models_dir)

    def load_task_jsonl(self, split: str, filename: str) -> List[Dict[str, Any]]:
        path = self.dataset_dir / split / filename
        if not path.exists():
            # Fallback to raw
            path = self.dataset_dir / "raw" / filename
        if not path.exists():
            return []
        items = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    items.append(json.loads(line))
        return items

    def train_task(self, task_name: str, dry_run: bool = False) -> Dict[str, Any]:
        print(f"\\n--- Training NLP Model for Task: {task_name.upper()} ---")

        if task_name == "classification":
            train_items = self.load_task_jsonl("train", "classification.jsonl")
            val_items = self.load_task_jsonl("validation", "classification.jsonl")
            test_items = self.load_task_jsonl("test", "classification.jsonl")

            train_texts = [ex["input"] for ex in train_items]
            train_labels = [ex["output"] for ex in train_items]
            test_texts = [ex["input"] for ex in test_items]
            test_labels = [ex["output"] for ex in test_items]

        elif task_name == "security_detection":
            train_items = self.load_task_jsonl("train", "security_detection.jsonl")
            test_items = self.load_task_jsonl("test", "security_detection.jsonl")

            train_texts = [ex["input"] for ex in train_items]
            train_labels = [ex["output"]["finding"] if isinstance(ex["output"], dict) else ex["output"] for ex in train_items]
            test_texts = [ex["input"] for ex in test_items]
            test_labels = [ex["output"]["finding"] if isinstance(ex["output"], dict) else ex["output"] for ex in test_items]

        elif task_name == "compliance":
            train_items = self.load_task_jsonl("train", "compliance.jsonl")
            test_items = self.load_task_jsonl("test", "compliance.jsonl")

            train_texts = [ex["input"] for ex in train_items]
            train_labels = [ex["output"]["status"] if isinstance(ex["output"], dict) else ex["output"] for ex in train_items]
            test_texts = [ex["input"] for ex in test_items]
            test_labels = [ex["output"]["status"] if isinstance(ex["output"], dict) else ex["output"] for ex in test_items]

        elif task_name == "qa":
            train_items = self.load_task_jsonl("train", "qa.jsonl")
            test_items = self.load_task_jsonl("test", "qa.jsonl")

            train_texts = [ex["input"] for ex in train_items]
            train_labels = [ex["output"]["answer"] if isinstance(ex["output"], dict) else ex["output"] for ex in train_items]
            test_texts = [ex["input"] for ex in test_items]
            test_labels = [ex["output"]["answer"] if isinstance(ex["output"], dict) else ex["output"] for ex in test_items]

        elif task_name == "ner":
            train_items = self.load_task_jsonl("train", "ner.jsonl")
            test_items = self.load_task_jsonl("test", "ner.jsonl")

            train_texts = [ex["input"] for ex in train_items]
            train_labels = [ex["output"]["entities"][0]["type"] if (isinstance(ex["output"], dict) and ex["output"].get("entities")) else "UNKNOWN" for ex in train_items]
            test_texts = [ex["input"] for ex in test_items]
            test_labels = [ex["output"]["entities"][0]["type"] if (isinstance(ex["output"], dict) and ex["output"].get("entities")) else "UNKNOWN" for ex in test_items]
        else:
            raise ValueError(f"Unknown task: {task_name}")

        print(f"  Dataset: Train={len(train_texts)}, Test={len(test_texts)}, Classes={len(set(train_labels))}")

        if dry_run:
            print(f"  [DRY-RUN] Verified dataset and pipeline for {task_name}.")
            return {"status": "dry_run_passed", "task": task_name, "train_samples": len(train_texts)}

        model = SecurityNLPModel(task_name=task_name)
        model.fit(train_texts, train_labels)
        metrics = model.evaluate(test_texts, test_labels, split_name="test")

        print(f"  Accuracy:    {metrics['accuracy']:.4f}")
        print(f"  Precision:   {metrics['precision_macro']:.4f}")
        print(f"  Recall:      {metrics['recall_macro']:.4f}")
        print(f"  Macro-F1:    {metrics['macro_f1']:.4f}")
        print(f"  Weighted-F1: {metrics['weighted_f1']:.4f}")
        print(f"  Critical Finding Recall: {metrics['critical_finding_recall']:.4f}")

        saved_path = model.save(self.models_dir)
        print(f"  Model saved to {saved_path}/")

        return metrics

    def run_all(self, dry_run: bool = False) -> Dict[str, Any]:
        tasks = ["classification", "security_detection", "compliance", "qa", "ner"]
        all_metrics = {}
        for task in tasks:
            metrics = self.train_task(task, dry_run=dry_run)
            all_metrics[task] = metrics

        if not dry_run:
            # Vendor-wise evaluation matrix
            vendor_matrix = self.evaluate_vendor_generalization()
            all_metrics["vendor_evaluation"] = vendor_matrix

            # Save full evaluation summary
            (self.models_dir / "all_models_evaluation.json").write_text(json.dumps(all_metrics, indent=2), encoding="utf-8")

        return all_metrics

    def evaluate_vendor_generalization(self) -> Dict[str, Any]:
        """Evaluates model performance across major vendor platforms."""
        test_items = self.load_task_jsonl("test", "classification.jsonl")
        if not test_items:
            return {}

        model_path = self.models_dir / "classification" / "model.joblib"
        enc_path = self.models_dir / "classification" / "label_encoder.joblib"
        if not model_path.exists() or not enc_path.exists():
            return {}

        pipeline = joblib.load(model_path)
        encoder = joblib.load(enc_path)

        by_vendor = collections.defaultdict(list)
        for item in test_items:
            by_vendor[item.get("vendor", "generic")].append(item)

        vendor_results = {}
        for vendor, items in by_vendor.items():
            if len(items) < 2:
                continue
            texts = [ex["input"] for ex in items]
            true_labels = [ex["output"] for ex in items]
            probas = pipeline.predict_proba(texts)
            pred_indices = np.argmax(probas, axis=1)
            pred_labels = [encoder.classes_[i] for i in pred_indices]

            acc = accuracy_score(true_labels, pred_labels)
            labels_p = sorted(set(true_labels + pred_labels))
            prec = precision_score(true_labels, pred_labels, labels=labels_p, average="macro", zero_division=0)
            rec = recall_score(true_labels, pred_labels, labels=labels_p, average="macro", zero_division=0)
            f1 = f1_score(true_labels, pred_labels, labels=labels_p, average="macro", zero_division=0)

            vendor_results[vendor] = {
                "samples": len(items),
                "accuracy": round(float(acc), 4),
                "precision": round(float(prec), 4),
                "recall": round(float(rec), 4),
                "f1": round(float(f1), 4),
            }

        (self.models_dir / "vendor_evaluation.json").write_text(json.dumps(vendor_results, indent=2), encoding="utf-8")
        return vendor_results
'''
    Path('nlp_pipeline/trainer.py').write_text(code, encoding='utf-8')
    print('Generated nlp_pipeline/trainer.py')

    # Also generate top-level train_nlp.py
    cli_code = '''"""CLI entrypoint for training Network Security NLP Models.

Usage:
    python train_nlp.py --task security_detection
    python train_nlp.py --task compliance
    python train_nlp.py --task classification
    python train_nlp.py --task qa
    python train_nlp.py --task ner
    python train_nlp.py --task all
    python train_nlp.py --dry-run
"""

import argparse
import sys
from pathlib import Path

from nlp_pipeline.trainer import NLPTrainingPipeline

def main():
    parser = argparse.ArgumentParser(description="Train Network Security NLP Models across Multi-Vendor Corpus.")
    parser.add_argument("--task", type=str, default="all", choices=["all", "security_detection", "compliance", "classification", "qa", "ner"], help="Task to train.")
    parser.add_argument("--dataset-dir", type=Path, default=Path("nlp_dataset"), help="Path to NLP dataset directory.")
    parser.add_argument("--models-dir", type=Path, default=Path("models"), help="Where to save model artifacts.")
    parser.add_argument("--dry-run", action="store_true", help="Validate datasets and pipeline without fitting full models.")
    args = parser.parse_args()

    pipeline = NLPTrainingPipeline(dataset_dir=args.dataset_dir, models_dir=args.models_dir)

    if args.task == "all":
        pipeline.run_all(dry_run=args.dry_run)
    else:
        pipeline.train_task(args.task, dry_run=args.dry_run)

if __name__ == "__main__":
    main()
'''
    Path('train_nlp.py').write_text(cli_code, encoding='utf-8')
    print('Generated train_nlp.py')

if __name__ == '__main__':
    write_trainer()

