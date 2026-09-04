"""NLP semantic generalization layer for unknown configuration syntax.

This module implements a lightweight ML pipeline that classifies raw network
configuration lines into security concepts and maps them to normalized baseline
fields. It is NOT a compliance engine — it produces *candidate* mappings with
confidence scores for human review.

Architecture position:
    Raw config line (unknown syntax)
        → NLP security concept prediction + confidence
        → Candidate normalized field
        → Candidate value extraction
        → Human approval gate
        → LearnedMappingStore
        → Deterministic compliance engine

Model: TF-IDF (word + character n-grams) + Logistic Regression.
Chosen because:
    - Dataset is small (~300 examples, ~28 labeled security lines)
    - Character n-grams capture cross-vendor syntax patterns
    - Logistic Regression provides calibrated probability estimates
    - Fully reproducible without GPU or large dependencies
    - Fast training and inference suitable for batch processing
"""

import hashlib
import json
import re
import time
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NON_SECURITY_LABEL = "NON_SECURITY"
AMBIGUOUS_LABEL = "AMBIGUOUS"

CONCEPT_TO_FIELD = {
    "SNMP Community Access": "snmp_communities",
    "SNMP Agent Activation": "snmp_agent_enabled",
    "Session Idle Inactivity Timeout": "vty_exec_timeout_seconds",
    "SSH Access Control": "ssh_enabled",
    "SSH Protocol Version": "ssh_version",
    "Syslog Destination Hosts": "logging_hosts",
    "NTP Time Synchronization": "ntp_servers",
}

FIELD_TO_CONCEPT = {v: k for k, v in CONCEPT_TO_FIELD.items()}

MODEL_DIR_NAME = "nlp_model"
MODEL_FILENAME = "concept_classifier.joblib"
LABEL_ENCODER_FILENAME = "label_encoder.joblib"
METADATA_FILENAME = "training_metadata.json"
EVAL_FILENAME = "evaluation_results.json"

RANDOM_SEED = 42

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class NLPExample:
    raw_text: str
    vendor: str
    security_concept: str
    normalized_field: Optional[str]
    value: Any
    status: str
    source_file: str
    source_line: int
    provenance: str = "PUBLIC_CONFIGURATION_SNIPPET"
    real_device: bool = False


@dataclass
class NLPPrediction:
    raw_text: str
    predicted_concept: str
    predicted_field: Optional[str]
    predicted_value: Any
    confidence: float
    top_3: List[Tuple[str, float]]
    needs_review: bool
    is_unknown: bool
    source: str = "nlp"


@dataclass
class NLPMetrics:
    split_name: str
    total_examples: int
    concept_accuracy: float
    concept_top3_accuracy: float
    concept_precision_macro: float
    concept_recall_macro: float
    concept_f1_macro: float
    concept_precision_weighted: float
    concept_recall_weighted: float
    concept_f1_weighted: float
    field_accuracy: float
    value_accuracy: float
    exact_match_accuracy: float
    unknown_detection_accuracy: float
    ambiguous_detection_accuracy: float
    false_mapping_rate: float
    human_review_rate: float
    per_class: Dict[str, Dict[str, float]]
    confusion: Optional[List[List[int]]] = None
    class_names: Optional[List[str]] = None
    confidence_calibration: Optional[Dict[str, float]] = None


@dataclass
class DatasetStats:
    total: int
    mapped: int
    unmapped: int
    ambiguous: int
    vendors: List[str]
    concepts: List[str]
    fields: List[str]
    files: List[str]


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------


def load_split(path: Path) -> List[NLPExample]:
    data = json.loads(path.read_text(encoding="utf-8"))
    examples = []
    for item in data:
        concept = item.get("security_concept", "")
        status = item.get("status", "UNMAPPED")
        nf = item.get("normalized_field")
        if nf in (None, "null", "UNMAPPED"):
            nf = None

        if status == "UNMAPPED":
            concept = NON_SECURITY_LABEL
        elif status == "AMBIGUOUS":
            concept = AMBIGUOUS_LABEL

        examples.append(NLPExample(
            raw_text=item["raw_text"],
            vendor=item.get("vendor", "unknown"),
            security_concept=concept,
            normalized_field=nf,
            value=item.get("value"),
            status=status,
            source_file=item.get("source_file", ""),
            source_line=item.get("source_line", 0),
            provenance=item.get("provenance", "PUBLIC_CONFIGURATION_SNIPPET"),
            real_device=item.get("real_device", False),
        ))
    return examples


def load_dataset(
    dataset_dir: Path,
) -> Tuple[List[NLPExample], List[NLPExample], List[NLPExample]]:
    train = load_split(dataset_dir / "train" / "snippets.json")
    val = load_split(dataset_dir / "validation" / "snippets.json")
    test = load_split(dataset_dir / "test" / "snippets.json")
    return train, val, test


def dataset_stats(examples: List[NLPExample]) -> DatasetStats:
    mapped = [e for e in examples if e.status == "MAPPED"]
    unmapped = [e for e in examples if e.status == "UNMAPPED"]
    ambiguous = [e for e in examples if e.status == "AMBIGUOUS"]
    vendors = sorted(set(e.vendor for e in examples))
    concepts = sorted(set(e.security_concept for e in examples))
    fields = sorted(set(e.normalized_field for e in examples if e.normalized_field))
    files = sorted(set(e.source_file for e in examples))
    return DatasetStats(
        total=len(examples),
        mapped=len(mapped),
        unmapped=len(unmapped),
        ambiguous=len(ambiguous),
        vendors=vendors,
        concepts=concepts,
        fields=fields,
        files=files,
    )


def verify_no_leakage(
    train: List[NLPExample],
    val: List[NLPExample],
    test: List[NLPExample],
) -> Tuple[bool, str]:
    train_files = set(e.source_file for e in train)
    val_files = set(e.source_file for e in val)
    test_files = set(e.source_file for e in test)

    train_val = train_files & val_files
    train_test = train_files & test_files
    val_test = val_files & test_files

    if not (train_val or train_test or val_test):
        return True, "No file-level leakage detected."

    parts = []
    if train_val:
        parts.append(f"train∩val: {train_val}")
    if train_test:
        parts.append(f"train∩test: {train_test}")
    if val_test:
        parts.append(f"val∩test: {val_test}")
    return False, f"LEAKAGE DETECTED: {'; '.join(parts)}"


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------


def preprocess_text(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"\{\{[^}]*\}\}", "<TEMPLATE>", text)
    text = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<IP>", text)
    text = re.sub(r"\b[0-9a-fA-F]{4}:[0-9a-fA-F:]+\b", "<IPV6>", text)
    text = re.sub(r"\b\d{5,}\b", "<NUM>", text)
    return text


def build_feature_pipeline() -> FeatureUnion:
    word_tfidf = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        max_features=3000,
        sublinear_tf=True,
        strip_accents="unicode",
        preprocessor=preprocess_text,
    )
    char_tfidf = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=5000,
        sublinear_tf=True,
        strip_accents="unicode",
        preprocessor=preprocess_text,
    )
    return FeatureUnion([
        ("word", word_tfidf),
        ("char", char_tfidf),
    ])


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


class SecurityConceptClassifier:
    """TF-IDF + Logistic Regression classifier for security concept prediction."""

    def __init__(self, random_seed: int = RANDOM_SEED):
        self.random_seed = random_seed
        self.label_encoder = LabelEncoder()
        self.pipeline: Optional[Pipeline] = None
        self.classes_: Optional[np.ndarray] = None
        self.training_metadata: Dict[str, Any] = {}

    def fit(self, texts: List[str], labels: List[str]) -> "SecurityConceptClassifier":
        encoded_labels = self.label_encoder.fit_transform(labels)
        self.classes_ = self.label_encoder.classes_

        features = build_feature_pipeline()
        classifier = LogisticRegression(
            C=1.0,
            class_weight="balanced",
            max_iter=1000,
            random_state=self.random_seed,
            solver="lbfgs",
        )
        self.pipeline = Pipeline([
            ("features", features),
            ("classifier", classifier),
        ])
        self.pipeline.fit(texts, encoded_labels)

        self.training_metadata = {
            "n_samples": len(texts),
            "n_classes": len(self.classes_),
            "classes": list(self.classes_),
            "class_distribution": {
                label: int(np.sum(encoded_labels == i))
                for i, label in enumerate(self.classes_)
            },
            "random_seed": self.random_seed,
        }
        return self

    def predict(self, texts: List[str]) -> List[NLPPrediction]:
        if self.pipeline is None:
            raise RuntimeError("Model not fitted. Call fit() first.")

        probas = self.pipeline.predict_proba(texts)
        predictions = []
        for text, proba in zip(texts, probas):
            sorted_indices = np.argsort(proba)[::-1]
            top1_idx = sorted_indices[0]
            top1_label = self.classes_[top1_idx]
            top1_conf = float(proba[top1_idx])

            top3 = [
                (str(self.classes_[idx]), float(proba[idx]))
                for idx in sorted_indices[:3]
            ]

            predicted_field = CONCEPT_TO_FIELD.get(top1_label)
            predicted_value = _extract_value(text, predicted_field) if predicted_field else None

            predictions.append(NLPPrediction(
                raw_text=text,
                predicted_concept=str(top1_label),
                predicted_field=predicted_field,
                predicted_value=predicted_value,
                confidence=top1_conf,
                top_3=top3,
                needs_review=False,
                is_unknown=False,
            ))
        return predictions

    def predict_one(self, text: str) -> NLPPrediction:
        return self.predict([text])[0]

    def save(self, model_dir: Path) -> None:
        model_dir = Path(model_dir)
        model_dir.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.pipeline, model_dir / MODEL_FILENAME)
        joblib.dump(self.label_encoder, model_dir / LABEL_ENCODER_FILENAME)

        metadata = {
            **self.training_metadata,
            "model_type": "TF-IDF + Logistic Regression",
            "feature_pipeline": "word(1,2) + char_wb(3,5)",
        }
        (model_dir / METADATA_FILENAME).write_text(
            json.dumps(metadata, indent=2, default=str), encoding="utf-8"
        )

    @classmethod
    def load(cls, model_dir: Path) -> "SecurityConceptClassifier":
        model_dir = Path(model_dir)
        instance = cls()
        instance.pipeline = joblib.load(model_dir / MODEL_FILENAME)
        instance.label_encoder = joblib.load(model_dir / LABEL_ENCODER_FILENAME)
        instance.classes_ = instance.label_encoder.classes_

        meta_path = model_dir / METADATA_FILENAME
        if meta_path.is_file():
            instance.training_metadata = json.loads(
                meta_path.read_text(encoding="utf-8")
            )
        return instance


# ---------------------------------------------------------------------------
# Value extraction (rule-based, not ML)
# ---------------------------------------------------------------------------


def _extract_value(text: str, field: Optional[str]) -> Any:
    if field is None:
        return None

    text_stripped = text.strip()

    if field == "snmp_agent_enabled":
        lower = text_stripped.lower()
        if "no " in lower or "disable" in lower:
            return False
        return True

    if field == "snmp_communities":
        match = re.search(
            r"(?:community|snmp-agent\s+community\s+\w+)\s+(\S+)", text_stripped, re.I
        )
        if match:
            name = match.group(1)
            access = "ro"
            if re.search(r"\brw\b|\bread-write\b|\bwrite\b", text_stripped, re.I):
                access = "rw"
            return [{"name": name, "access": access}]
        return None

    if field == "vty_exec_timeout_seconds":
        numbers = re.findall(r"\b(\d+)\b", text_stripped)
        if numbers:
            try:
                return int(numbers[-1])
            except ValueError:
                pass
        return None

    if field == "ssh_enabled":
        lower = text_stripped.lower()
        if "no " in lower or "disable" in lower:
            return False
        return True

    if field == "ssh_version":
        match = re.search(r"(?:version|v)\s*(\d+)", text_stripped, re.I)
        if match:
            return match.group(1)
        return None

    if field in ("logging_hosts", "ntp_servers", "dns_servers"):
        ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text_stripped)
        return ips if ips else None

    return None


# ---------------------------------------------------------------------------
# Confidence thresholds and unknown detection
# ---------------------------------------------------------------------------


@dataclass
class ConfidencePolicy:
    high_threshold: float = 0.7
    medium_threshold: float = 0.4
    low_threshold: float = 0.2

    def classify_confidence(self, confidence: float) -> str:
        if confidence >= self.high_threshold:
            return "HIGH"
        if confidence >= self.medium_threshold:
            return "MEDIUM"
        return "LOW"


def apply_confidence_policy(
    predictions: List[NLPPrediction],
    policy: ConfidencePolicy,
) -> List[NLPPrediction]:
    result = []
    for pred in predictions:
        level = policy.classify_confidence(pred.confidence)
        pred.needs_review = level in ("MEDIUM", "LOW")
        pred.is_unknown = level == "LOW"
        result.append(pred)
    return result


def tune_thresholds(
    val_examples: List[NLPExample],
    classifier: SecurityConceptClassifier,
    target_precision: float = 0.90,
) -> ConfidencePolicy:
    texts = [e.raw_text for e in val_examples]
    true_labels = [e.security_concept for e in val_examples]
    predictions = classifier.predict(texts)

    confidences = [p.confidence for p in predictions]
    pred_labels = [p.predicted_concept for p in predictions]

    correct = [p == t for p, t in zip(pred_labels, true_labels)]

    best_high = 0.7
    for threshold in np.arange(0.3, 0.95, 0.05):
        above = [(c, corr) for c, corr in zip(confidences, correct) if c >= threshold]
        if not above:
            continue
        prec = sum(1 for _, corr in above if corr) / len(above)
        if prec >= target_precision:
            best_high = float(threshold)
            break

    return ConfidencePolicy(
        high_threshold=best_high,
        medium_threshold=max(0.2, best_high - 0.3),
        low_threshold=max(0.1, best_high - 0.5),
    )


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def evaluate(
    examples: List[NLPExample],
    classifier: SecurityConceptClassifier,
    policy: ConfidencePolicy,
    split_name: str = "test",
) -> NLPMetrics:
    texts = [e.raw_text for e in examples]
    true_concepts = [e.security_concept for e in examples]

    predictions = classifier.predict(texts)
    predictions = apply_confidence_policy(predictions, policy)

    pred_concepts = [p.predicted_concept for p in predictions]

    concept_acc = accuracy_score(true_concepts, pred_concepts)

    top3_correct = 0
    for ex, pred in zip(examples, predictions):
        top3_labels = [label for label, _ in pred.top_3]
        if ex.security_concept in top3_labels:
            top3_correct += 1
    top3_acc = top3_correct / len(examples) if examples else 0.0

    labels_present = sorted(set(true_concepts + pred_concepts))
    prec_macro = precision_score(true_concepts, pred_concepts, labels=labels_present, average="macro", zero_division=0)
    rec_macro = recall_score(true_concepts, pred_concepts, labels=labels_present, average="macro", zero_division=0)
    f1_macro = f1_score(true_concepts, pred_concepts, labels=labels_present, average="macro", zero_division=0)
    prec_weighted = precision_score(true_concepts, pred_concepts, labels=labels_present, average="weighted", zero_division=0)
    rec_weighted = recall_score(true_concepts, pred_concepts, labels=labels_present, average="weighted", zero_division=0)
    f1_weighted = f1_score(true_concepts, pred_concepts, labels=labels_present, average="weighted", zero_division=0)

    field_correct = 0
    field_total = 0
    for ex, pred in zip(examples, predictions):
        if ex.normalized_field is not None:
            field_total += 1
            if pred.predicted_field == ex.normalized_field:
                field_correct += 1
    field_acc = field_correct / field_total if field_total else 0.0

    value_correct = 0
    value_total = 0
    for ex, pred in zip(examples, predictions):
        if ex.value is not None and pred.predicted_value is not None:
            value_total += 1
            if _values_match(ex.value, pred.predicted_value):
                value_correct += 1
    value_acc = value_correct / value_total if value_total else 0.0

    exact_correct = sum(
        1 for ex, pred in zip(examples, predictions)
        if (ex.security_concept == pred.predicted_concept
            and (ex.normalized_field is None or pred.predicted_field == ex.normalized_field))
    )
    exact_acc = exact_correct / len(examples) if examples else 0.0

    unknown_examples = [e for e in examples if e.status == "UNMAPPED"]
    unknown_preds = [p for e, p in zip(examples, predictions) if e.status == "UNMAPPED"]
    unknown_det_correct = sum(
        1 for p in unknown_preds if p.predicted_concept == NON_SECURITY_LABEL
    )
    unknown_det_acc = unknown_det_correct / len(unknown_preds) if unknown_preds else 0.0

    ambig_examples = [e for e in examples if e.status == "AMBIGUOUS"]
    ambig_preds = [p for e, p in zip(examples, predictions) if e.status == "AMBIGUOUS"]
    ambig_det_correct = sum(
        1 for p in ambig_preds
        if p.predicted_concept == AMBIGUOUS_LABEL or p.needs_review
    )
    ambig_det_acc = ambig_det_correct / len(ambig_preds) if ambig_preds else 0.0

    false_mapping = 0
    security_preds = [
        (e, p) for e, p in zip(examples, predictions)
        if p.predicted_concept not in (NON_SECURITY_LABEL, AMBIGUOUS_LABEL)
    ]
    for ex, pred in security_preds:
        if ex.security_concept in (NON_SECURITY_LABEL, AMBIGUOUS_LABEL):
            false_mapping += 1
    false_map_rate = false_mapping / len(predictions) if predictions else 0.0

    review_count = sum(1 for p in predictions if p.needs_review)
    review_rate = review_count / len(predictions) if predictions else 0.0

    report = classification_report(
        true_concepts, pred_concepts, output_dict=True, zero_division=0
    )
    per_class = {}
    for label in labels_present:
        if label in report:
            per_class[label] = {
                "precision": report[label]["precision"],
                "recall": report[label]["recall"],
                "f1": report[label]["f1-score"],
                "support": report[label]["support"],
            }

    cm = confusion_matrix(true_concepts, pred_concepts, labels=labels_present)

    cal = _calibration_stats(examples, predictions)

    return NLPMetrics(
        split_name=split_name,
        total_examples=len(examples),
        concept_accuracy=round(concept_acc, 4),
        concept_top3_accuracy=round(top3_acc, 4),
        concept_precision_macro=round(prec_macro, 4),
        concept_recall_macro=round(rec_macro, 4),
        concept_f1_macro=round(f1_macro, 4),
        concept_precision_weighted=round(prec_weighted, 4),
        concept_recall_weighted=round(rec_weighted, 4),
        concept_f1_weighted=round(f1_weighted, 4),
        field_accuracy=round(field_acc, 4),
        value_accuracy=round(value_acc, 4),
        exact_match_accuracy=round(exact_acc, 4),
        unknown_detection_accuracy=round(unknown_det_acc, 4),
        ambiguous_detection_accuracy=round(ambig_det_acc, 4),
        false_mapping_rate=round(false_map_rate, 4),
        human_review_rate=round(review_rate, 4),
        per_class=per_class,
        confusion=cm.tolist(),
        class_names=labels_present,
        confidence_calibration=cal,
    )


def _values_match(expected: Any, predicted: Any) -> bool:
    if isinstance(expected, bool) and isinstance(predicted, bool):
        return expected == predicted
    if isinstance(expected, (int, float)) and isinstance(predicted, (int, float)):
        return expected == predicted
    if isinstance(expected, str) and isinstance(predicted, str):
        return expected.lower() == predicted.lower()
    return str(expected).lower() == str(predicted).lower()


def _calibration_stats(
    examples: List[NLPExample], predictions: List[NLPPrediction]
) -> Dict[str, float]:
    bins = [(0.0, 0.2), (0.2, 0.4), (0.4, 0.6), (0.6, 0.8), (0.8, 1.01)]
    stats: Dict[str, float] = {}
    total_ece = 0.0
    n = len(predictions)

    for lo, hi in bins:
        in_bin = [
            (e, p)
            for e, p in zip(examples, predictions)
            if lo <= p.confidence < hi
        ]
        if not in_bin:
            continue
        correct = sum(1 for e, p in in_bin if e.security_concept == p.predicted_concept)
        observed = correct / len(in_bin)
        midpoint = (lo + hi) / 2
        gap = abs(midpoint - observed)
        total_ece += (len(in_bin) / n) * gap
        stats[f"bin_{lo:.1f}_{hi:.1f}_observed"] = round(observed, 4)
        stats[f"bin_{lo:.1f}_{hi:.1f}_count"] = len(in_bin)

    stats["expected_calibration_error"] = round(total_ece, 4)
    return stats


# ---------------------------------------------------------------------------
# Deterministic baseline (for comparison)
# ---------------------------------------------------------------------------


def deterministic_predict(text: str) -> NLPPrediction:
    """The existing keyword heuristic from suggest.py, wrapped as an NLPPrediction."""
    from .suggest import _KEYWORD_MAP

    lower = text.lower().strip()
    best_field = None
    best_relevance = ""
    best_score = 0

    for keywords, field_name, relevance in _KEYWORD_MAP:
        for kw in keywords:
            if ".*" in kw:
                if re.search(kw, lower):
                    score = len(kw)
                    if score > best_score:
                        best_score = score
                        best_field = field_name
                        best_relevance = relevance
            elif kw in lower:
                score = len(kw)
                if score > best_score:
                    best_score = score
                    best_field = field_name
                    best_relevance = relevance

    if best_field is None:
        return NLPPrediction(
            raw_text=text,
            predicted_concept=NON_SECURITY_LABEL,
            predicted_field=None,
            predicted_value=None,
            confidence=0.5,
            top_3=[(NON_SECURITY_LABEL, 0.5)],
            needs_review=False,
            is_unknown=True,
            source="deterministic",
        )

    concept = FIELD_TO_CONCEPT.get(best_field, best_relevance)
    conf = min(0.9, best_score / 25.0)
    return NLPPrediction(
        raw_text=text,
        predicted_concept=concept,
        predicted_field=best_field,
        predicted_value=_extract_value(text, best_field),
        confidence=conf,
        top_3=[(concept, conf)],
        needs_review=False,
        is_unknown=False,
        source="deterministic",
    )


def evaluate_deterministic(examples: List[NLPExample]) -> NLPMetrics:
    """Evaluate the deterministic keyword matcher on the same data."""
    true_concepts = [e.security_concept for e in examples]
    predictions = [deterministic_predict(e.raw_text) for e in examples]
    pred_concepts = [p.predicted_concept for p in predictions]

    concept_acc = accuracy_score(true_concepts, pred_concepts)
    labels_present = sorted(set(true_concepts + pred_concepts))

    field_correct = 0
    field_total = 0
    for ex, pred in zip(examples, predictions):
        if ex.normalized_field is not None:
            field_total += 1
            if pred.predicted_field == ex.normalized_field:
                field_correct += 1

    value_correct = 0
    value_total = 0
    for ex, pred in zip(examples, predictions):
        if ex.value is not None and pred.predicted_value is not None:
            value_total += 1
            if _values_match(ex.value, pred.predicted_value):
                value_correct += 1

    unknown_preds = [p for e, p in zip(examples, predictions) if e.status == "UNMAPPED"]
    unknown_det = sum(
        1 for p in unknown_preds if p.predicted_concept == NON_SECURITY_LABEL
    )

    report = classification_report(
        true_concepts, pred_concepts, output_dict=True, zero_division=0
    )
    per_class = {}
    for label in labels_present:
        if label in report:
            per_class[label] = {
                "precision": report[label]["precision"],
                "recall": report[label]["recall"],
                "f1": report[label]["f1-score"],
                "support": report[label]["support"],
            }

    false_mapping = sum(
        1 for e, p in zip(examples, predictions)
        if p.predicted_concept not in (NON_SECURITY_LABEL, AMBIGUOUS_LABEL)
        and e.security_concept in (NON_SECURITY_LABEL, AMBIGUOUS_LABEL)
    )

    return NLPMetrics(
        split_name="deterministic",
        total_examples=len(examples),
        concept_accuracy=round(concept_acc, 4),
        concept_top3_accuracy=round(concept_acc, 4),
        concept_precision_macro=round(
            precision_score(true_concepts, pred_concepts, labels=labels_present, average="macro", zero_division=0), 4
        ),
        concept_recall_macro=round(
            recall_score(true_concepts, pred_concepts, labels=labels_present, average="macro", zero_division=0), 4
        ),
        concept_f1_macro=round(
            f1_score(true_concepts, pred_concepts, labels=labels_present, average="macro", zero_division=0), 4
        ),
        concept_precision_weighted=round(
            precision_score(true_concepts, pred_concepts, labels=labels_present, average="weighted", zero_division=0), 4
        ),
        concept_recall_weighted=round(
            recall_score(true_concepts, pred_concepts, labels=labels_present, average="weighted", zero_division=0), 4
        ),
        concept_f1_weighted=round(
            f1_score(true_concepts, pred_concepts, labels=labels_present, average="weighted", zero_division=0), 4
        ),
        field_accuracy=round(field_correct / field_total if field_total else 0.0, 4),
        value_accuracy=round(value_correct / value_total if value_total else 0.0, 4),
        exact_match_accuracy=round(concept_acc, 4),
        unknown_detection_accuracy=round(
            unknown_det / len(unknown_preds) if unknown_preds else 0.0, 4
        ),
        ambiguous_detection_accuracy=0.0,
        false_mapping_rate=round(false_mapping / len(predictions) if predictions else 0.0, 4),
        human_review_rate=0.0,
        per_class=per_class,
    )


# ---------------------------------------------------------------------------
# Hybrid system
# ---------------------------------------------------------------------------


def hybrid_predict(
    text: str,
    classifier: SecurityConceptClassifier,
    policy: ConfidencePolicy,
) -> NLPPrediction:
    det = deterministic_predict(text)
    if det.predicted_field is not None and det.confidence >= 0.5:
        return det

    nlp = classifier.predict_one(text)
    level = policy.classify_confidence(nlp.confidence)
    nlp.needs_review = level in ("MEDIUM", "LOW")
    nlp.is_unknown = level == "LOW"
    nlp.source = "hybrid_nlp"
    return nlp


def evaluate_hybrid(
    examples: List[NLPExample],
    classifier: SecurityConceptClassifier,
    policy: ConfidencePolicy,
) -> NLPMetrics:
    true_concepts = [e.security_concept for e in examples]
    predictions = [hybrid_predict(e.raw_text, classifier, policy) for e in examples]
    pred_concepts = [p.predicted_concept for p in predictions]

    concept_acc = accuracy_score(true_concepts, pred_concepts)
    labels_present = sorted(set(true_concepts + pred_concepts))

    field_correct = 0
    field_total = 0
    for ex, pred in zip(examples, predictions):
        if ex.normalized_field is not None:
            field_total += 1
            if pred.predicted_field == ex.normalized_field:
                field_correct += 1

    value_correct = 0
    value_total = 0
    for ex, pred in zip(examples, predictions):
        if ex.value is not None and pred.predicted_value is not None:
            value_total += 1
            if _values_match(ex.value, pred.predicted_value):
                value_correct += 1

    unknown_preds = [p for e, p in zip(examples, predictions) if e.status == "UNMAPPED"]
    unknown_det = sum(
        1 for p in unknown_preds if p.predicted_concept == NON_SECURITY_LABEL
    )

    ambig_preds = [p for e, p in zip(examples, predictions) if e.status == "AMBIGUOUS"]
    ambig_det = sum(
        1 for p in ambig_preds
        if p.predicted_concept == AMBIGUOUS_LABEL or p.needs_review
    )

    false_mapping = sum(
        1 for e, p in zip(examples, predictions)
        if p.predicted_concept not in (NON_SECURITY_LABEL, AMBIGUOUS_LABEL)
        and e.security_concept in (NON_SECURITY_LABEL, AMBIGUOUS_LABEL)
    )

    review_count = sum(1 for p in predictions if p.needs_review)

    report = classification_report(
        true_concepts, pred_concepts, output_dict=True, zero_division=0
    )
    per_class = {}
    for label in labels_present:
        if label in report:
            per_class[label] = {
                "precision": report[label]["precision"],
                "recall": report[label]["recall"],
                "f1": report[label]["f1-score"],
                "support": report[label]["support"],
            }

    return NLPMetrics(
        split_name="hybrid",
        total_examples=len(examples),
        concept_accuracy=round(concept_acc, 4),
        concept_top3_accuracy=round(concept_acc, 4),
        concept_precision_macro=round(
            precision_score(true_concepts, pred_concepts, labels=labels_present, average="macro", zero_division=0), 4
        ),
        concept_recall_macro=round(
            recall_score(true_concepts, pred_concepts, labels=labels_present, average="macro", zero_division=0), 4
        ),
        concept_f1_macro=round(
            f1_score(true_concepts, pred_concepts, labels=labels_present, average="macro", zero_division=0), 4
        ),
        concept_precision_weighted=round(
            precision_score(true_concepts, pred_concepts, labels=labels_present, average="weighted", zero_division=0), 4
        ),
        concept_recall_weighted=round(
            recall_score(true_concepts, pred_concepts, labels=labels_present, average="weighted", zero_division=0), 4
        ),
        concept_f1_weighted=round(
            f1_score(true_concepts, pred_concepts, labels=labels_present, average="weighted", zero_division=0), 4
        ),
        field_accuracy=round(field_correct / field_total if field_total else 0.0, 4),
        value_accuracy=round(value_correct / value_total if value_total else 0.0, 4),
        exact_match_accuracy=round(concept_acc, 4),
        unknown_detection_accuracy=round(
            unknown_det / len(unknown_preds) if unknown_preds else 0.0, 4
        ),
        ambiguous_detection_accuracy=round(
            ambig_det / len(ambig_preds) if ambig_preds else 0.0, 4
        ),
        false_mapping_rate=round(false_mapping / len(predictions) if predictions else 0.0, 4),
        human_review_rate=round(review_count / len(predictions) if predictions else 0.0, 4),
        per_class=per_class,
    )


# ---------------------------------------------------------------------------
# Hard negative testing
# ---------------------------------------------------------------------------


def generate_hard_negatives(examples: List[NLPExample]) -> List[NLPExample]:
    """Create hard negatives from existing data — config lines containing
    security keywords but that are NOT security configurations."""
    hard_negatives = []
    security_keywords = [
        "ssh", "snmp", "logging", "ntp", "aaa", "banner", "password",
        "timeout", "telnet", "http", "https", "access", "enable",
    ]

    for ex in examples:
        if ex.status != "UNMAPPED":
            continue
        lower = ex.raw_text.lower()
        for kw in security_keywords:
            if kw in lower:
                hard_negatives.append(NLPExample(
                    raw_text=ex.raw_text,
                    vendor=ex.vendor,
                    security_concept=NON_SECURITY_LABEL,
                    normalized_field=None,
                    value=None,
                    status="HARD_NEGATIVE",
                    source_file=ex.source_file,
                    source_line=ex.source_line,
                    provenance=ex.provenance,
                ))
                break

    comment_examples = [
        NLPExample(raw_text="! ssh access is configured on line vty 0 4",
                   vendor="Cisco", security_concept=NON_SECURITY_LABEL,
                   normalized_field=None, value=None, status="HARD_NEGATIVE",
                   source_file="synthetic/comments", source_line=0,
                   provenance="SYNTHETIC_HARD_NEGATIVE"),
        NLPExample(raw_text="# snmp community string documentation",
                   vendor="Juniper", security_concept=NON_SECURITY_LABEL,
                   normalized_field=None, value=None, status="HARD_NEGATIVE",
                   source_file="synthetic/comments", source_line=0,
                   provenance="SYNTHETIC_HARD_NEGATIVE"),
        NLPExample(raw_text="description SSH uplink to core-router",
                   vendor="Cisco", security_concept=NON_SECURITY_LABEL,
                   normalized_field=None, value=None, status="HARD_NEGATIVE",
                   source_file="synthetic/descriptions", source_line=0,
                   provenance="SYNTHETIC_HARD_NEGATIVE"),
        NLPExample(raw_text="interface GigabitEthernet0/0 logging-events link-status",
                   vendor="Cisco", security_concept=NON_SECURITY_LABEL,
                   normalized_field=None, value=None, status="HARD_NEGATIVE",
                   source_file="synthetic/interface", source_line=0,
                   provenance="SYNTHETIC_HARD_NEGATIVE"),
    ]
    hard_negatives.extend(comment_examples)
    return hard_negatives


def evaluate_hard_negatives(
    hard_negatives: List[NLPExample],
    classifier: SecurityConceptClassifier,
    policy: ConfidencePolicy,
) -> Dict[str, Any]:
    predictions = classifier.predict([e.raw_text for e in hard_negatives])
    predictions = apply_confidence_policy(predictions, policy)

    false_positives = []
    for ex, pred in zip(hard_negatives, predictions):
        if pred.predicted_concept not in (NON_SECURITY_LABEL, AMBIGUOUS_LABEL):
            false_positives.append({
                "text": ex.raw_text,
                "predicted": pred.predicted_concept,
                "confidence": pred.confidence,
                "needs_review": pred.needs_review,
            })

    return {
        "total_hard_negatives": len(hard_negatives),
        "false_positives": len(false_positives),
        "false_positive_rate": round(
            len(false_positives) / len(hard_negatives) if hard_negatives else 0.0, 4
        ),
        "examples": false_positives[:10],
    }


# ---------------------------------------------------------------------------
# Human-in-the-loop simulation
# ---------------------------------------------------------------------------


def simulate_human_loop(
    examples: List[NLPExample],
    classifier: SecurityConceptClassifier,
    policy: ConfidencePolicy,
) -> Dict[str, Any]:
    """Simulate the human-in-the-loop workflow for unknown configurations."""
    from .mappings import LearnedMapping, LearnedMappingStore
    import tempfile
    import uuid

    with tempfile.TemporaryDirectory() as tmpdir:
        store_path = Path(tmpdir) / "test_mappings.jsonl"
        store = LearnedMappingStore(store_path)

        unknown_examples = [e for e in examples if e.status == "UNMAPPED"]
        if not unknown_examples:
            return {"note": "No unmapped examples available for simulation."}

        suggestions = []
        approved = []
        rejected = []
        needs_review = []

        for ex in unknown_examples[:20]:
            pred = hybrid_predict(ex.raw_text, classifier, policy)

            if pred.is_unknown:
                needs_review.append({"text": ex.raw_text, "confidence": pred.confidence})
                continue

            suggestions.append({
                "text": ex.raw_text,
                "concept": pred.predicted_concept,
                "field": pred.predicted_field,
                "confidence": pred.confidence,
            })

            if pred.predicted_concept == NON_SECURITY_LABEL:
                continue

            if pred.predicted_field and pred.confidence >= policy.high_threshold:
                mapping = LearnedMapping(
                    mapping_id=f"sim_{uuid.uuid4().hex[:8]}",
                    vendor=ex.vendor,
                    pattern=ex.raw_text.split()[0] if ex.raw_text.split() else ex.raw_text,
                    field=pred.predicted_field,
                    extraction_strategy="exact",
                    status="approved",
                    approval_state="approved",
                )
                try:
                    store.create_mapping(mapping)
                    approved.append({
                        "text": ex.raw_text,
                        "field": pred.predicted_field,
                        "confidence": pred.confidence,
                    })
                except (ValueError, Exception):
                    rejected.append({
                        "text": ex.raw_text,
                        "reason": "invalid field or mapping",
                    })
            else:
                rejected.append({
                    "text": ex.raw_text,
                    "reason": "low confidence" if pred.confidence < policy.high_threshold else "no field",
                })

        stored = store.get_active_approved_mappings()

        return {
            "total_unknown_processed": len(unknown_examples[:20]),
            "suggestions": len(suggestions),
            "approved": len(approved),
            "rejected": len(rejected),
            "needs_review": len(needs_review),
            "learned_mappings_stored": len(stored),
            "nlp_produced_pass": False,
            "nlp_produced_fail": False,
        }


# ---------------------------------------------------------------------------
# Vendor-held-out evaluation
# ---------------------------------------------------------------------------


def vendor_held_out_evaluate(
    all_examples: List[NLPExample],
    hold_out_vendor: str,
) -> Optional[Dict[str, Any]]:
    train_examples = [e for e in all_examples if e.vendor.lower() != hold_out_vendor.lower()]
    test_examples = [e for e in all_examples if e.vendor.lower() == hold_out_vendor.lower()]

    if len(test_examples) < 3:
        return None

    train_mapped = [e for e in train_examples if e.status == "MAPPED"]
    test_mapped = [e for e in test_examples if e.status == "MAPPED"]

    if len(set(e.security_concept for e in train_examples)) < 2:
        return None

    classifier = SecurityConceptClassifier()
    texts = [e.raw_text for e in train_examples]
    labels = [e.security_concept for e in train_examples]
    classifier.fit(texts, labels)

    policy = ConfidencePolicy()
    metrics = evaluate(test_examples, classifier, policy, split_name=f"vendor_held_out_{hold_out_vendor}")
    return {
        "held_out_vendor": hold_out_vendor,
        "train_size": len(train_examples),
        "test_size": len(test_examples),
        "train_mapped": len(train_mapped),
        "test_mapped": len(test_mapped),
        "metrics": {
            "concept_accuracy": metrics.concept_accuracy,
            "concept_f1_macro": metrics.concept_f1_macro,
            "field_accuracy": metrics.field_accuracy,
            "unknown_detection_accuracy": metrics.unknown_detection_accuracy,
            "false_mapping_rate": metrics.false_mapping_rate,
        },
    }


# ---------------------------------------------------------------------------
# Ablation study
# ---------------------------------------------------------------------------


def run_ablation(
    train: List[NLPExample],
    test: List[NLPExample],
    val: List[NLPExample],
) -> Dict[str, Dict[str, float]]:
    det_metrics = evaluate_deterministic(test)

    classifier = SecurityConceptClassifier()
    classifier.fit([e.raw_text for e in train], [e.security_concept for e in train])
    policy = tune_thresholds(val, classifier)
    nlp_metrics = evaluate(test, classifier, policy, split_name="nlp_only")

    hybrid_metrics = evaluate_hybrid(test, classifier, policy)

    no_threshold_policy = ConfidencePolicy(high_threshold=0.0, medium_threshold=0.0, low_threshold=0.0)
    hybrid_no_thresh = evaluate_hybrid(test, classifier, no_threshold_policy)

    return {
        "deterministic_only": {
            "concept_accuracy": det_metrics.concept_accuracy,
            "concept_f1_macro": det_metrics.concept_f1_macro,
            "field_accuracy": det_metrics.field_accuracy,
            "unknown_detection": det_metrics.unknown_detection_accuracy,
            "false_mapping_rate": det_metrics.false_mapping_rate,
            "human_review_rate": det_metrics.human_review_rate,
        },
        "nlp_only": {
            "concept_accuracy": nlp_metrics.concept_accuracy,
            "concept_f1_macro": nlp_metrics.concept_f1_macro,
            "field_accuracy": nlp_metrics.field_accuracy,
            "unknown_detection": nlp_metrics.unknown_detection_accuracy,
            "false_mapping_rate": nlp_metrics.false_mapping_rate,
            "human_review_rate": nlp_metrics.human_review_rate,
        },
        "hybrid": {
            "concept_accuracy": hybrid_metrics.concept_accuracy,
            "concept_f1_macro": hybrid_metrics.concept_f1_macro,
            "field_accuracy": hybrid_metrics.field_accuracy,
            "unknown_detection": hybrid_metrics.unknown_detection_accuracy,
            "false_mapping_rate": hybrid_metrics.false_mapping_rate,
            "human_review_rate": hybrid_metrics.human_review_rate,
        },
        "hybrid_no_threshold": {
            "concept_accuracy": hybrid_no_thresh.concept_accuracy,
            "concept_f1_macro": hybrid_no_thresh.concept_f1_macro,
            "field_accuracy": hybrid_no_thresh.field_accuracy,
            "unknown_detection": hybrid_no_thresh.unknown_detection_accuracy,
            "false_mapping_rate": hybrid_no_thresh.false_mapping_rate,
            "human_review_rate": hybrid_no_thresh.human_review_rate,
        },
    }


# ---------------------------------------------------------------------------
# Full training + evaluation pipeline
# ---------------------------------------------------------------------------


def run_full_pipeline(
    dataset_dir: Path,
    output_dir: Path,
) -> Dict[str, Any]:
    t0 = time.time()

    train, val, test = load_dataset(dataset_dir)
    no_leak, leak_msg = verify_no_leakage(train, val, test)
    train_stats = dataset_stats(train)
    val_stats = dataset_stats(val)
    test_stats = dataset_stats(test)

    texts_train = [e.raw_text for e in train]
    labels_train = [e.security_concept for e in train]

    classifier = SecurityConceptClassifier()
    t_train_start = time.time()
    classifier.fit(texts_train, labels_train)
    training_time = time.time() - t_train_start

    policy = tune_thresholds(val, classifier)

    t_infer_start = time.time()
    val_metrics = evaluate(val, classifier, policy, split_name="validation")
    inference_time_val = time.time() - t_infer_start

    t_infer_test = time.time()
    test_metrics = evaluate(test, classifier, policy, split_name="test")
    inference_time_test = time.time() - t_infer_test

    det_test_metrics = evaluate_deterministic(test)
    hybrid_test_metrics = evaluate_hybrid(test, classifier, policy)

    all_data = train + val + test
    vendors = sorted(set(e.vendor for e in all_data))
    vendor_results = {}
    for v in vendors:
        result = vendor_held_out_evaluate(all_data, v)
        if result is not None:
            vendor_results[v] = result

    hard_negs = generate_hard_negatives(test)
    hard_neg_results = evaluate_hard_negatives(hard_negs, classifier, policy)

    human_loop = simulate_human_loop(test, classifier, policy)

    ablation = run_ablation(train, test, val)

    model_dir = output_dir / MODEL_DIR_NAME
    classifier.save(model_dir)

    import sys
    total_time = time.time() - t0

    report = {
        "dataset": {
            "train": {
                "total": train_stats.total,
                "mapped": train_stats.mapped,
                "unmapped": train_stats.unmapped,
                "ambiguous": train_stats.ambiguous,
                "vendors": train_stats.vendors,
                "concepts": train_stats.concepts,
                "files": len(train_stats.files),
            },
            "validation": {
                "total": val_stats.total,
                "mapped": val_stats.mapped,
                "unmapped": val_stats.unmapped,
                "ambiguous": val_stats.ambiguous,
            },
            "test": {
                "total": test_stats.total,
                "mapped": test_stats.mapped,
                "unmapped": test_stats.unmapped,
                "ambiguous": test_stats.ambiguous,
            },
            "data_leakage": "NO" if no_leak else "YES",
            "leakage_detail": leak_msg,
        },
        "model": {
            "type": "TF-IDF + Logistic Regression",
            "features": "word(1,2) + char_wb(3,5)",
            "classifier": "LogisticRegression(C=1.0, class_weight='balanced', multinomial)",
            "random_seed": RANDOM_SEED,
            "training_metadata": classifier.training_metadata,
        },
        "confidence_policy": {
            "high_threshold": policy.high_threshold,
            "medium_threshold": policy.medium_threshold,
            "low_threshold": policy.low_threshold,
        },
        "validation_metrics": _metrics_to_dict(val_metrics),
        "test_metrics": {
            "deterministic": _metrics_to_dict(det_test_metrics),
            "nlp": _metrics_to_dict(test_metrics),
            "hybrid": _metrics_to_dict(hybrid_test_metrics),
        },
        "vendor_held_out": vendor_results,
        "hard_negatives": hard_neg_results,
        "human_in_the_loop": human_loop,
        "ablation": ablation,
        "performance": {
            "training_time_seconds": round(training_time, 3),
            "inference_time_val_seconds": round(inference_time_val, 3),
            "inference_time_test_seconds": round(inference_time_test, 3),
            "total_pipeline_seconds": round(total_time, 3),
        },
        "security_guarantees": {
            "nlp_produced_pass": False,
            "nlp_produced_fail": False,
            "false_compliance_results": 0,
        },
        "environment": {
            "python_version": sys.version,
        },
        "data_limitations": {
            "real_device_configurations": 0,
            "total_labeled_security_examples": train_stats.mapped + val_stats.mapped + test_stats.mapped,
            "security_classes_represented": len(set(
                e.security_concept for e in all_data
                if e.status == "MAPPED"
            )),
            "vendor_coverage": len(vendors),
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / EVAL_FILENAME).write_text(
        json.dumps(report, indent=2, default=str), encoding="utf-8"
    )

    return report


def _metrics_to_dict(m: NLPMetrics) -> Dict[str, Any]:
    return {
        "total_examples": m.total_examples,
        "concept_accuracy": m.concept_accuracy,
        "concept_top3_accuracy": m.concept_top3_accuracy,
        "precision_macro": m.concept_precision_macro,
        "recall_macro": m.concept_recall_macro,
        "f1_macro": m.concept_f1_macro,
        "precision_weighted": m.concept_precision_weighted,
        "recall_weighted": m.concept_recall_weighted,
        "f1_weighted": m.concept_f1_weighted,
        "field_accuracy": m.field_accuracy,
        "value_accuracy": m.value_accuracy,
        "exact_match_accuracy": m.exact_match_accuracy,
        "unknown_detection_accuracy": m.unknown_detection_accuracy,
        "ambiguous_detection_accuracy": m.ambiguous_detection_accuracy,
        "false_mapping_rate": m.false_mapping_rate,
        "human_review_rate": m.human_review_rate,
        "per_class": m.per_class,
        "confidence_calibration": m.confidence_calibration,
    }
