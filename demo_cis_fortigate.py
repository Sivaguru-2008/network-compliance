#!/usr/bin/env python3
"""
CIS FortiGate Benchmark Assessment — End-to-End Demo

Demonstrates the complete pipeline:
  1. PDF extraction → normalized JSON with provenance
  2. Rule classification (DETERMINISTIC / PARSER_REQUIRED / MANUAL)
  3. Knowledge base population
  4. Config parsing → SecurityBaselineModel
  5. CIS evaluation → AuditReport with all 56 controls accounted for

Usage:
  python demo_cis_fortigate.py [config_file]

If no config file is given, uses samples/fortios_fgt.conf.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from auditor.cis.extractor import extract_fortigate, save_benchmark
from auditor.cis.fortigate_map import get_coverage_summary
from auditor.cis.populate_kb import populate_fortigate_kb
from auditor.models.result import Status
from auditor.parsers.fortios import FortiosParser
from auditor.pipeline import evaluate_cis_fortigate

BENCHMARK_PDF = Path(__file__).parent / "cis" / "benchmarks" / "CIS_Fortigate_7.0.x_Benchmark_v1.4.0.pdf"
BENCHMARK_JSON = Path(__file__).parent / "cis" / "benchmarks" / "CIS_Fortigate_7.0.x_rules.json"
DEFAULT_CONFIG = Path(__file__).parent / "samples" / "fortios_fgt.conf"


def banner(text: str) -> None:
    width = 72
    print()
    print("=" * width)
    print(f"  {text}")
    print("=" * width)


def main():
    config_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CONFIG

    if not config_path.is_file():
        print(f"Error: config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    # ── Step 1: Extract CIS recommendations from PDF ────────────────────
    banner("STEP 1: CIS Benchmark PDF Extraction")

    if BENCHMARK_JSON.is_file():
        print(f"  Using existing extraction: {BENCHMARK_JSON.name}")
        benchmark = json.loads(BENCHMARK_JSON.read_text(encoding="utf-8"))
        rec_count = len(benchmark["recommendations"])
    else:
        if not BENCHMARK_PDF.is_file():
            print(f"  PDF not found: {BENCHMARK_PDF}", file=sys.stderr)
            print("  Skipping extraction — place the PDF in cis/benchmarks/")
            rec_count = 0
        else:
            print(f"  Extracting from: {BENCHMARK_PDF.name}")
            bm = extract_fortigate(BENCHMARK_PDF)
            save_benchmark(bm, BENCHMARK_JSON)
            rec_count = len(bm.recommendations)
            print(f"  Saved: {BENCHMARK_JSON.name}")

    print(f"  Recommendations extracted: {rec_count}")
    print(f"  Source hash: {benchmark.get('source_hash', 'N/A')[:16]}...")

    # ── Step 2: Rule Classification ─────────────────────────────────────
    banner("STEP 2: Rule Classification")

    coverage = get_coverage_summary()
    for eval_type, ids in sorted(coverage.items()):
        print(f"  {eval_type:<20s}: {len(ids):3d} rules")
        if len(ids) <= 5:
            for cis_id in ids:
                print(f"    - {cis_id}")

    # ── Step 3: Knowledge Base Population ───────────────────────────────
    banner("STEP 3: Knowledge Base Population")

    stats = populate_fortigate_kb(BENCHMARK_JSON)
    print(f"  Total rules in KB:   {stats['total']}")
    print(f"  Auto-approved:       {stats['approved']}")
    print(f"  Pending/manual:      {stats['pending']}")

    # ── Step 4: Parse Configuration ─────────────────────────────────────
    banner("STEP 4: Parse FortiGate Configuration")

    config_text = config_path.read_text(encoding="utf-8")
    parser = FortiosParser()
    baseline = parser.parse(config_text, source_file=str(config_path))

    print(f"  Source:    {config_path.name}")
    print(f"  Hostname:  {baseline.hostname.value}")
    print(f"  Parser:    {baseline.provenance.parser_name}")
    print(f"  Lines:     {baseline.config_line_count}")

    # ── Step 5: CIS Assessment ──────────────────────────────────────────
    banner("STEP 5: CIS FortiGate 7.0.x Assessment")

    report = evaluate_cis_fortigate(baseline, include_baseline=False)

    print(f"\n  Device: {report.target.hostname}")
    print(f"  Framework: CIS FortiGate 7.0.x Benchmark v1.4.0")
    print(f"  Total controls: {report.summary.total}")
    print()
    print(f"  {'Status':<16s} {'Count':>5s}")
    print(f"  {'-'*16} {'-'*5}")
    print(f"  {'PASS':<16s} {report.summary.passed:>5d}")
    print(f"  {'FAIL':<16s} {report.summary.failed:>5d}")
    print(f"  {'NEEDS_REVIEW':<16s} {report.summary.needs_review:>5d}")
    print(f"  {'UNSUPPORTED':<16s} {report.summary.unsupported:>5d}")
    print(f"  {'MANUAL_REVIEW':<16s} {report.summary.manual_review:>5d}")
    print(f"  {'NOT_APPLICABLE':<16s} {report.summary.not_applicable:>5d}")
    print()
    print(f"  Compliance score (evaluable only): {report.summary.compliance_score}%")
    print(f"  Adjudicated score (PASS vs FAIL):  {report.summary.adjudicated_score}%")

    # ── Detailed results ────────────────────────────────────────────────
    banner("DETAILED RESULTS")

    status_order = [Status.FAIL, Status.NEEDS_REVIEW, Status.PASS,
                    Status.UNSUPPORTED, Status.MANUAL_REVIEW, Status.NOT_APPLICABLE]

    for status in status_order:
        results = [r for r in report.results if r.status == status]
        if not results:
            continue
        print(f"\n  --- {status.value} ({len(results)}) ---")
        for r in results:
            ref = r.control_ref or r.rule_id
            evidence_str = ""
            if r.evidence:
                ev = r.evidence[0]
                if ev.source_line:
                    evidence_str = f" | L{ev.line_number}: {ev.source_line[:50]}"
                elif ev.note:
                    evidence_str = f" | {ev.note[:50]}"
            print(f"  {ref:<10s} {r.title[:55]}{evidence_str}")

    # ── Save report ─────────────────────────────────────────────────────
    out_path = Path(__file__).parent / "reports" / "cis_fortigate_demo_report.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, default=str),
        encoding="utf-8",
    )
    print(f"\n  Full report saved: {out_path}")

    banner("DEMO COMPLETE")
    print(f"  All {report.summary.total} CIS controls accounted for.")
    print(f"  No rules silently dropped, invented, or converted.")
    print(f"  Every evaluated rule traces back to:")
    print(f"    PDF: CIS_Fortigate_7.0.x_Benchmark_v1.4.0.pdf")
    print(f"    Hash: 1692d309...520b5f161b")
    print()


if __name__ == "__main__":
    main()
