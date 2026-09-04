"""Train the NLP semantic generalization model.

Usage:
    python -m auditor.training.train_nlp
    python -m auditor.training.train_nlp --dataset-dir dataset/public_config --output-dir training/nlp
"""

import argparse
import json
import sys
from pathlib import Path

from .nlp_pipeline import (
    SecurityConceptClassifier,
    dataset_stats,
    load_dataset,
    tune_thresholds,
    verify_no_leakage,
)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Train the NLP security concept classifier."
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=Path("dataset/public_config"),
        help="Directory containing train/validation/test splits.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("training/nlp"),
        help="Where to save model artifacts.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility.",
    )
    args = parser.parse_args(argv)

    print("=" * 70)
    print("NLP SECURITY CONCEPT CLASSIFIER — TRAINING")
    print("=" * 70)

    print(f"\nLoading dataset from {args.dataset_dir}...")
    train, val, test = load_dataset(args.dataset_dir)

    t_stats = dataset_stats(train)
    v_stats = dataset_stats(val)
    te_stats = dataset_stats(test)
    print(f"  Train:      {t_stats.total:>4} examples ({t_stats.mapped} mapped, {t_stats.unmapped} unmapped, {t_stats.ambiguous} ambiguous)")
    print(f"  Validation: {v_stats.total:>4} examples ({v_stats.mapped} mapped, {v_stats.unmapped} unmapped, {v_stats.ambiguous} ambiguous)")
    print(f"  Test:       {te_stats.total:>4} examples ({te_stats.mapped} mapped, {te_stats.unmapped} unmapped, {te_stats.ambiguous} ambiguous)")

    no_leak, msg = verify_no_leakage(train, val, test)
    print(f"\n  Data leakage check: {'PASS' if no_leak else 'FAIL'}")
    print(f"    {msg}")
    if not no_leak:
        print("ERROR: Data leakage detected. Fix the split before training.", file=sys.stderr)
        sys.exit(1)

    print(f"\n  Vendors: {', '.join(t_stats.vendors)}")
    print(f"  Security concepts: {', '.join(t_stats.concepts)}")

    print("\nTraining classifier...")
    classifier = SecurityConceptClassifier(random_seed=args.seed)
    texts = [e.raw_text for e in train]
    labels = [e.security_concept for e in train]
    classifier.fit(texts, labels)

    print(f"  Classes: {list(classifier.classes_)}")
    dist = classifier.training_metadata.get("class_distribution", {})
    for cls, count in sorted(dist.items()):
        print(f"    {cls}: {count}")

    print("\nTuning confidence thresholds on validation set...")
    policy = tune_thresholds(val, classifier)
    print(f"  High threshold:   {policy.high_threshold:.2f}")
    print(f"  Medium threshold: {policy.medium_threshold:.2f}")
    print(f"  Low threshold:    {policy.low_threshold:.2f}")

    model_dir = args.output_dir / "nlp_model"
    print(f"\nSaving model to {model_dir}/...")
    classifier.save(model_dir)

    policy_data = {
        "high_threshold": policy.high_threshold,
        "medium_threshold": policy.medium_threshold,
        "low_threshold": policy.low_threshold,
    }
    (model_dir / "confidence_policy.json").write_text(
        json.dumps(policy_data, indent=2), encoding="utf-8"
    )

    print("\nTraining complete.")
    print(f"  Model saved to:       {model_dir / 'concept_classifier.joblib'}")
    print(f"  Label encoder:        {model_dir / 'label_encoder.joblib'}")
    print(f"  Training metadata:    {model_dir / 'training_metadata.json'}")
    print(f"  Confidence policy:    {model_dir / 'confidence_policy.json'}")
    print("\nRun evaluation with:")
    print(f"  python -m auditor.training.evaluate_nlp --dataset-dir {args.dataset_dir} --model-dir {model_dir}")


if __name__ == "__main__":
    main()
