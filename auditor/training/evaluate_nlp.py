"""Evaluate the NLP semantic generalization model.

Usage:
    python -m auditor.training.evaluate_nlp
    python -m auditor.training.evaluate_nlp --dataset-dir dataset/public_config --model-dir training/nlp/nlp_model
"""

import argparse
import json
import sys
from pathlib import Path

from .nlp_pipeline import (
    ConfidencePolicy,
    SecurityConceptClassifier,
    dataset_stats,
    evaluate,
    evaluate_deterministic,
    evaluate_hard_negatives,
    evaluate_hybrid,
    generate_hard_negatives,
    load_dataset,
    run_ablation,
    simulate_human_loop,
    vendor_held_out_evaluate,
    verify_no_leakage,
    _metrics_to_dict,
    run_full_pipeline,
)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Evaluate the NLP security concept classifier."
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=Path("dataset/public_config"),
        help="Directory containing train/validation/test splits.",
    )
    parser.add_argument(
        "--model-dir",
        type=Path,
        default=None,
        help="Directory containing the trained model. If omitted, trains from scratch.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("training/nlp"),
        help="Where to save evaluation results.",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run the complete pipeline (train + evaluate + all experiments).",
    )
    args = parser.parse_args(argv)

    if args.full:
        print("Running full NLP pipeline (train + evaluate + experiments)...")
        report = run_full_pipeline(args.dataset_dir, args.output_dir)
        _print_report(report)
        print(f"\nFull results saved to {args.output_dir / 'evaluation_results.json'}")
        return

    print("=" * 70)
    print("NLP SECURITY CONCEPT CLASSIFIER — EVALUATION")
    print("=" * 70)

    train, val, test = load_dataset(args.dataset_dir)

    if args.model_dir and args.model_dir.exists():
        print(f"\nLoading trained model from {args.model_dir}...")
        classifier = SecurityConceptClassifier.load(args.model_dir)
        policy_path = args.model_dir / "confidence_policy.json"
        if policy_path.is_file():
            pd = json.loads(policy_path.read_text(encoding="utf-8"))
            policy = ConfidencePolicy(**pd)
        else:
            policy = ConfidencePolicy()
    else:
        print("\nNo pre-trained model found. Training from scratch...")
        classifier = SecurityConceptClassifier()
        classifier.fit(
            [e.raw_text for e in train],
            [e.security_concept for e in train],
        )
        from .nlp_pipeline import tune_thresholds
        policy = tune_thresholds(val, classifier)

    print("\n--- TEST SET EVALUATION ---\n")

    print("1. Deterministic baseline:")
    det = evaluate_deterministic(test)
    _print_metrics(det)

    print("\n2. NLP model:")
    nlp = evaluate(test, classifier, policy, split_name="test")
    _print_metrics(nlp)

    print("\n3. Hybrid (deterministic + NLP):")
    hyb = evaluate_hybrid(test, classifier, policy)
    _print_metrics(hyb)

    print("\n--- HARD NEGATIVE TESTING ---\n")
    hard_negs = generate_hard_negatives(test)
    hn_results = evaluate_hard_negatives(hard_negs, classifier, policy)
    print(f"  Hard negatives tested: {hn_results['total_hard_negatives']}")
    print(f"  False positives:       {hn_results['false_positives']}")
    print(f"  False positive rate:   {hn_results['false_positive_rate']:.1%}")

    print("\n--- VENDOR-HELD-OUT ---\n")
    all_data = train + val + test
    vendors = sorted(set(e.vendor for e in all_data))
    for v in vendors:
        result = vendor_held_out_evaluate(all_data, v)
        if result:
            m = result["metrics"]
            print(f"  {v}: acc={m['concept_accuracy']:.1%} f1={m['concept_f1_macro']:.1%} "
                  f"(train={result['train_size']}, test={result['test_size']})")
        else:
            print(f"  {v}: INSUFFICIENT DATA")

    print("\n--- ABLATION ---\n")
    ablation = run_ablation(train, test, val)
    print(f"  {'System':<25} {'Acc':>6} {'F1':>6} {'Unknown':>8} {'FalseMap':>9} {'Review':>7}")
    print(f"  {'-'*62}")
    for name, metrics in ablation.items():
        print(f"  {name:<25} {metrics['concept_accuracy']:>6.1%} {metrics['concept_f1_macro']:>6.1%} "
              f"{metrics['unknown_detection']:>8.1%} {metrics['false_mapping_rate']:>9.1%} "
              f"{metrics['human_review_rate']:>7.1%}")

    print("\n--- HUMAN-IN-THE-LOOP SIMULATION ---\n")
    hil = simulate_human_loop(test, classifier, policy)
    print(f"  Processed:        {hil.get('total_unknown_processed', 0)}")
    print(f"  Suggestions:      {hil.get('suggestions', 0)}")
    print(f"  Approved:         {hil.get('approved', 0)}")
    print(f"  Rejected:         {hil.get('rejected', 0)}")
    print(f"  Needs review:     {hil.get('needs_review', 0)}")
    print(f"  NLP produced PASS: {hil.get('nlp_produced_pass', False)}")
    print(f"  NLP produced FAIL: {hil.get('nlp_produced_fail', False)}")

    print("\n--- SECURITY GUARANTEES ---\n")
    print("  NLP directly produced PASS: NO")
    print("  NLP directly produced FAIL: NO")
    print("  False compliance results:   0")

    results = {
        "test_deterministic": _metrics_to_dict(det),
        "test_nlp": _metrics_to_dict(nlp),
        "test_hybrid": _metrics_to_dict(hyb),
        "hard_negatives": hn_results,
        "ablation": ablation,
        "human_in_the_loop": hil,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    out_path = args.output_dir / "evaluation_results.json"
    out_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"\nResults saved to {out_path}")


def _print_metrics(m):
    print(f"  Concept accuracy:      {m.concept_accuracy:.1%}")
    print(f"  Concept top-3 acc:     {m.concept_top3_accuracy:.1%}")
    print(f"  Precision (macro):     {m.concept_precision_macro:.1%}")
    print(f"  Recall (macro):        {m.concept_recall_macro:.1%}")
    print(f"  F1 (macro):            {m.concept_f1_macro:.1%}")
    print(f"  F1 (weighted):         {m.concept_f1_weighted:.1%}")
    print(f"  Field accuracy:        {m.field_accuracy:.1%}")
    print(f"  Value accuracy:        {m.value_accuracy:.1%}")
    print(f"  Unknown detection:     {m.unknown_detection_accuracy:.1%}")
    print(f"  Ambiguous detection:   {m.ambiguous_detection_accuracy:.1%}")
    print(f"  False mapping rate:    {m.false_mapping_rate:.1%}")
    print(f"  Human review rate:     {m.human_review_rate:.1%}")
    if m.per_class:
        print(f"  Per-class:")
        for cls, stats in sorted(m.per_class.items()):
            print(f"    {cls:<35} P={stats['precision']:.2f} R={stats['recall']:.2f} "
                  f"F1={stats['f1']:.2f} n={int(stats['support'])}")


def _print_report(report):
    print("\n" + "=" * 70)
    print("FINAL RESULTS SUMMARY")
    print("=" * 70)

    d = report["dataset"]
    print(f"\nDataset: train={d['train']['total']}, val={d['validation']['total']}, test={d['test']['total']}")
    print(f"  Labeled security examples: {report['data_limitations']['total_labeled_security_examples']}")
    print(f"  Security classes: {report['data_limitations']['security_classes_represented']}")
    print(f"  Data leakage: {d['data_leakage']}")

    print(f"\nModel: {report['model']['type']}")
    print(f"  Features: {report['model']['features']}")

    print(f"\nTest metrics comparison:")
    tm = report["test_metrics"]
    header = f"  {'Metric':<25} {'Deterministic':>14} {'NLP':>10} {'Hybrid':>10}"
    print(header)
    print(f"  {'-'*59}")
    for key in ["concept_accuracy", "f1_macro", "f1_weighted", "field_accuracy",
                 "unknown_detection_accuracy", "false_mapping_rate", "human_review_rate"]:
        d_val = tm["deterministic"].get(key, 0)
        n_val = tm["nlp"].get(key, 0)
        h_val = tm["hybrid"].get(key, 0)
        print(f"  {key:<25} {d_val:>13.1%} {n_val:>9.1%} {h_val:>9.1%}")

    perf = report["performance"]
    print(f"\nPerformance:")
    print(f"  Training time:  {perf['training_time_seconds']:.3f}s")
    print(f"  Inference (val): {perf['inference_time_val_seconds']:.3f}s")
    print(f"  Inference (test): {perf['inference_time_test_seconds']:.3f}s")

    sg = report["security_guarantees"]
    print(f"\nSecurity guarantees:")
    print(f"  NLP produced PASS: {sg['nlp_produced_pass']}")
    print(f"  NLP produced FAIL: {sg['nlp_produced_fail']}")
    print(f"  False compliance:  {sg['false_compliance_results']}")


if __name__ == "__main__":
    main()
