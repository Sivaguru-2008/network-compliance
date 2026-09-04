#!/usr/bin/env python3
"""Comprehensive Performance Benchmark for SIH Compliance Pipeline.

Measures exact wall-clock time for each pipeline stage across increasing
batch sizes (1, 10, 100, 600 configs):
- Vendor Detection
- Parser Selection & Parsing
- Baseline Normalization
- Deterministic Multi-Framework Compliance
- Full Ingestion Pipeline
- Adaptive Training & Re-Evaluation

Usage:
    python benchmarks/perf.py
"""

import sys
import time
import tempfile
from pathlib import Path
from typing import List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

SAMPLES_DIR = PROJECT_ROOT / "samples"


def collect_configs() -> List[Tuple[Path, str]]:
    """Collect all sample configs with their text."""
    configs = []
    for ext in ("*.conf", "*.cfg", "*.xml", "*.rsc"):
        for path in SAMPLES_DIR.rglob(ext):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
                if text.strip():
                    configs.append((path, text))
            except Exception:
                pass
    return configs


def bench_detection(configs: List[Tuple[Path, str]]) -> float:
    """Measure vendor detection time across configs."""
    from auditor.parsers import registry

    start = time.perf_counter()
    for _, text in configs:
        registry.rank(text)
    return time.perf_counter() - start


def bench_parsing(configs: List[Tuple[Path, str]]) -> float:
    """Measure parsing time (detection + parse into baseline) across configs."""
    from auditor.parsers import registry
    from auditor.parsers.base import ParserError

    start = time.perf_counter()
    for _, text in configs:
        ranked = registry.rank(text)
        if ranked and ranked[0][0] >= 0.3:
            parser_cls = ranked[0][1]
            try:
                parser_cls().parse(text)
            except ParserError:
                pass
    return time.perf_counter() - start


def bench_compliance(configs: List[Tuple[Path, str]]) -> float:
    """Measure compliance evaluation time on parsed baselines."""
    from auditor.parsers import registry
    from auditor.engine.evaluator import ComplianceEngine
    from auditor.rules import load_framework

    # Pre-parse to isolate pure rule evaluation
    baselines = []
    for _, text in configs:
        ranked = registry.rank(text)
        if ranked and ranked[0][0] >= 0.3:
            parser_cls = ranked[0][1]
            try:
                baselines.append((parser_cls().parse(text), ranked[0][1].__name__))
            except Exception:
                pass

    engine = ComplianceEngine(load_framework("cis", "cisco_ios"))
    start = time.perf_counter()
    for baseline, _ in baselines:
        engine.evaluate(baseline)
    return time.perf_counter() - start


def bench_full_ingestion(configs: List[Tuple[Path, str]]) -> float:
    """Measure end-to-end ingestion pipeline."""
    from auditor.ingest import ingest_paths

    paths = [str(p) for p, _ in configs]
    start = time.perf_counter()
    ingest_paths(paths, ["cis"], offline=True)
    return time.perf_counter() - start


def bench_training_and_reeval(configs: List[Tuple[Path, str]]) -> Tuple[float, float]:
    """Measure training suggestion + re-evaluation time."""
    from auditor.training.suggest import suggest_mapping
    from auditor.training.mappings import LearnedMapping, LearnedMappingStore, resolve_learned_mappings
    from auditor.engine.evaluator import ComplianceEngine
    from auditor.rules import load_framework

    sample_text = configs[0][1] if configs else "set admin-session-limit 300\n"

    # Measure Training Suggestion & Save
    with tempfile.TemporaryDirectory() as tmp_dir:
        store = LearnedMappingStore(Path(tmp_dir) / "bench_mappings.jsonl")
        
        t_start = time.perf_counter()
        suggestion = suggest_mapping("set admin-session-limit 300", vendor="cisco", client=None)
        mapping = LearnedMapping(
            mapping_id="bench-01",
            vendor="cisco",
            pattern="set admin-session-limit",
            field=suggestion.field or "vty_exec_timeout_seconds",
            extraction_strategy="token",
            status="approved",
            approval_state="approved"
        )
        store.create_mapping(mapping)
        store.approve_mapping("bench-01")
        training_time = time.perf_counter() - t_start

        # Measure Re-evaluation across all configs in batch
        from auditor.parsers import registry
        engine = ComplianceEngine(load_framework("cis", "cisco_ios"))
        
        reeval_start = time.perf_counter()
        for _, text in configs:
            ranked = registry.rank(text)
            if ranked and ranked[0][0] >= 0.3:
                parser_cls = ranked[0][1]
                try:
                    baseline = parser_cls().parse(text)
                    resolved = resolve_learned_mappings(text, baseline, store)
                    engine.evaluate(resolved)
                except Exception:
                    pass
        reeval_time = time.perf_counter() - reeval_start

    return training_time, reeval_time


def main():
    base_configs = collect_configs()
    n_base = len(base_configs)
    print("=" * 76)
    print("  SIH PERFORMANCE & BENCHMARK AUDIT")
    print(f"  Available Distinct Sample Configurations: {n_base}")
    print("=" * 76)

    target_counts = [1, 10, 100, 600]

    print(f"\n{'Scale':<10} {'Stage':<25} {'Configs':<10} {'Total (s)':<12} {'Per-Config (ms)':<15}")
    print("-" * 76)

    for target in target_counts:
        # Scale dataset to target count
        if target <= n_base:
            batch = base_configs[:target]
        else:
            multiplier = (target // n_base) + 1
            batch = (base_configs * multiplier)[:target]
        
        count = len(batch)
        label = f"{target}x"

        t_detect = bench_detection(batch)
        print(f"{label:<10} {'Vendor Detection':<25} {count:<10} {t_detect:<12.4f} {t_detect/count*1000:<15.2f}")

        t_parse = bench_parsing(batch)
        print(f"{label:<10} {'Parsing & Normalization':<25} {count:<10} {t_parse:<12.4f} {t_parse/count*1000:<15.2f}")

        t_comp = bench_compliance(batch)
        print(f"{label:<10} {'Compliance Evaluation':<25} {count:<10} {t_comp:<12.4f} {t_comp/count*1000:<15.2f}")

        t_full = bench_full_ingestion(batch)
        print(f"{label:<10} {'Full Ingestion Pipeline':<25} {count:<10} {t_full:<12.4f} {t_full/count*1000:<15.2f}")

        t_train, t_reeval = bench_training_and_reeval(batch)
        print(f"{label:<10} {'Re-Evaluation Cycle':<25} {count:<10} {t_reeval:<12.4f} {t_reeval/count*1000:<15.2f}")
        print("-" * 76)

    print("\nBenchmark successfully executed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
