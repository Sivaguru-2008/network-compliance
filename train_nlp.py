"""CLI entrypoint for training Network Security NLP Models.

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
