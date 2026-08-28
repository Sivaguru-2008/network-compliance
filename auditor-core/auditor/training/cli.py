"""`python -m auditor.training` — run the loop, read the results, record a ruling.

Kept separate from the audit CLI on purpose. Auditing a device is a read-only
operation anyone can run; the loop spends money, sends every corpus config to
the model provider, and rewrites the policy the parser will use next time.
Those belong behind their own command.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from ..parsers.llm.client import DEFAULT_MODEL, AnthropicClient, LLMUnavailableError
from ..parsers.base import ParserError
from ..rules import RuleLoadError, load_framework
from .adjudication import Adjudication, AdjudicationStore
from .calibration import ALWAYS_ESCALATE, ThresholdPolicy
from .comparison import FieldOutcome
from .corpus import ConfigCorpus
from .loop import TrainingLoop, load_examples, load_policy
from .metrics import RunMetrics

DEFAULT_WORKDIR = Path("training")

EXIT_OK = 0
EXIT_REGRESSED = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m auditor.training",
        description="Measure the LLM parser against deterministic ground truth, and feed the result back.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Score the corpus, fit thresholds, mine examples.")
    run.add_argument("corpus", type=Path, nargs="+", help="Config files or directories to score.")
    run.add_argument("--out", type=Path, default=DEFAULT_WORKDIR, help="Where artifacts are written.")
    run.add_argument("--framework", default="CIS", help="Framework whose verdicts are compared (default: CIS).")
    run.add_argument("--max-configs", type=int, default=None, help="Cap the run - each config costs one API call.")
    run.add_argument("--target-precision", type=float, default=0.95, help="Precision floor each field must hold.")
    run.add_argument("--min-samples", type=int, default=10, help="Claims needed before a field's threshold is fitted.")
    run.add_argument("--adjudications", type=Path, default=None, help="JSONL store of human rulings to overlay.")
    run.add_argument("--llm-model", default=DEFAULT_MODEL, help=f"Model to score (default: {DEFAULT_MODEL}).")
    run.add_argument("--dry-run", action="store_true", help="Score and print, but write no artifacts.")
    run.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit 1 if dangerous verdict flips rose or precision fell. For CI.",
    )

    report = sub.add_parser("report", help="Print the last run's metrics and fitted policy.")
    report.add_argument("--out", type=Path, default=DEFAULT_WORKDIR, help="Directory holding the artifacts.")

    adjudicate = sub.add_parser("adjudicate", help="Record a human ruling on one field.")
    adjudicate.add_argument("config", type=Path, help="The configuration the ruling is about.")
    adjudicate.add_argument("--field", required=True, help="Baseline field being ruled on.")
    adjudicate.add_argument("--reviewer", required=True, help="Who is deciding.")
    adjudicate.add_argument("--value", default=None, help="Correct value as JSON (e.g. true, 2, '[\"ssh\"]').")
    adjudicate.add_argument("--source-line", default=None, help="The config line that establishes it.")
    adjudicate.add_argument(
        "--undetermined",
        action="store_true",
        help="Record that this genuinely cannot be determined from the config.",
    )
    adjudicate.add_argument("--note", default=None, help="Free-text reasoning.")
    adjudicate.add_argument("--store", type=Path, default=DEFAULT_WORKDIR / "adjudications.jsonl")

    server = sub.add_parser("server", help="Start the web training dashboard server.")
    server.add_argument("--port", type=int, default=8080, help="Port to run the server on.")
    server.add_argument("--store", type=Path, default=DEFAULT_WORKDIR / "learned_mappings.jsonl", help="Where mappings are stored.")
    server.add_argument("--stats", type=Path, default=DEFAULT_WORKDIR / "stats.json", help="Where stats are stored.")

    return parser


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


def command_run(args) -> int:
    corpus = ConfigCorpus.from_paths(args.corpus)
    if not corpus.labelled:
        print(
            "error: no configurations a deterministic parser recognises. The loop derives "
            "ground truth from those, so it cannot score anything without them.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    entries = corpus.labelled[: args.max_configs or None]
    print(
        f"Corpus: {len(corpus)} config(s), {len(corpus.labelled)} labelled, "
        f"{len(corpus.unlabelled)} unlabelled (no ground truth)."
    )
    print(f"Scoring {len(entries)} config(s) against {args.llm_model} - one API call each.\n")

    try:
        ruleset = load_framework(args.framework, "cisco_ios", allow_cross_platform=True)
        client = AnthropicClient(model=args.llm_model)
    except (RuleLoadError, LLMUnavailableError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    loop = TrainingLoop(
        ruleset,
        args.out,
        adjudications=AdjudicationStore(args.adjudications) if args.adjudications else None,
        target_precision=args.target_precision,
        min_samples=args.min_samples,
    )
    try:
        result = loop.run(corpus, client, max_configs=args.max_configs, write=not args.dry_run)
    except (ParserError, LLMUnavailableError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(render_metrics(result.metrics))
    print(render_policy(result.policy))
    if result.skipped:
        print("Skipped:")
        for item in result.skipped:
            print(f"  - {item}")
        print()

    verdict = "REGRESSED" if result.regression.regressed else "ok"
    print(f"Regression check: {verdict}")
    for reason in result.regression.reasons:
        print(f"  - {reason}")
    if not args.dry_run:
        print(f"\nArtifacts written to {args.out}/")
        print("The parser picks these up via auditor.training.tuned_parser().")

    if args.fail_on_regression and result.regression.regressed:
        return EXIT_REGRESSED
    return EXIT_OK


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


def command_report(args) -> int:
    metrics_path = Path(args.out) / "metrics.json"
    if not metrics_path.is_file():
        print(f"error: no metrics at {metrics_path}. Run the loop first.", file=sys.stderr)
        return EXIT_ERROR
    metrics = RunMetrics.model_validate_json(metrics_path.read_text(encoding="utf-8"))
    print(render_metrics(metrics))
    policy = load_policy(args.out)
    if policy:
        print(render_policy(policy))
    examples = load_examples(args.out)
    if examples.examples:
        print(f"Worked examples fed back into the prompt: {len(examples.examples)}")
        for example in examples.examples:
            print(f"  - {example.field}: {example.outcome.value}")
        print()
    return EXIT_OK


# ---------------------------------------------------------------------------
# adjudicate
# ---------------------------------------------------------------------------


def command_adjudicate(args) -> int:
    path = Path(args.config)
    if not path.is_file():
        print(f"error: configuration not found: {path}", file=sys.stderr)
        return EXIT_ERROR

    import hashlib

    text = path.read_text(encoding="utf-8", errors="replace")
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

    value = None
    if not args.undetermined:
        if args.value is None:
            print("error: --value is required unless --undetermined is given.", file=sys.stderr)
            return EXIT_ERROR
        try:
            value = json.loads(args.value)
        except json.JSONDecodeError:
            value = args.value  # a bare string is a reasonable thing to type

    store = AdjudicationStore(args.store)
    record = store.append(
        Adjudication(
            config_sha256=digest,
            field=args.field,
            detected=not args.undetermined,
            value=value,
            source_line=args.source_line,
            reviewer=args.reviewer,
            note=args.note,
        )
    )
    state = "cannot be determined" if args.undetermined else repr(record.value)
    print(f"Recorded: {record.field} = {state} for {path.name} (reviewer: {record.reviewer})")
    print(f"Store now holds {len(store)} ruling(s) at {args.store}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def render_metrics(metrics: RunMetrics) -> str:
    lines = ["SCORING", "=" * 96]
    lines.append(
        f"  Configs scored     : {metrics.configs_scored}    "
        f"fields compared: {metrics.fields_compared}"
    )
    lines.append(
        f"  Overall precision  : {metrics.overall_precision:.1%}   "
        f"(of what it claimed, how much was right)"
    )
    lines.append(
        f"  Overall coverage   : {metrics.overall_coverage:.1%}   "
        f"(of what ground truth knew, how much it also established)"
    )
    lines.append(f"  Ungrounded claims  : {metrics.ungrounded_claims_rejected} rejected before scoring")
    lines.append("")

    header = f"  {'FIELD':<28}{'CLAIMS':>7}{'CORRECT':>9}{'WRONG':>7}{'OVER':>6}{'MISSED':>8}{'PREC':>8}{'COV':>8}"
    lines.append(header)
    lines.append("  " + "-" * (len(header) - 2))
    for field in metrics.per_field:
        lines.append(
            f"  {field.field:<28}{field.claims:>7}{field.correct:>9}{field.wrong:>7}"
            f"{field.overreach:>6}{field.missed:>8}{field.precision:>8.0%}{field.coverage:>8.0%}"
        )
    lines.append("")

    calibration = metrics.calibration
    lines.append(
        f"  Calibration (ECE {calibration.expected_calibration_error:.3f}"
        + (", OVERCONFIDENT" if calibration.overconfident else "")
        + "):"
    )
    for bucket in calibration.bins:
        arrow = "over" if bucket.gap > 0.05 else ("under" if bucket.gap < -0.05 else "ok")
        lines.append(
            f"    conf {bucket.lower:.1f}-{bucket.upper:.1f}: {bucket.claims:>4} claims, "
            f"observed {bucket.observed_accuracy:.0%}  ({arrow})"
        )
    lines.append("")

    impact = metrics.verdict_impact
    lines.append("  Verdict impact (what the field errors did to control outcomes):")
    lines.append(f"    controls compared : {impact.total}")
    lines.append(f"    agreement         : {impact.agreement_rate:.1%}")
    lines.append(f"    DANGEROUS FLIPS   : {impact.dangerous_flips}   (ground truth not PASS -> candidate PASS)")
    lines.append(f"    false alarms      : {impact.false_alarms}")
    lines.append(f"    lost coverage     : {impact.lost_coverage}   (decided -> NEEDS_REVIEW)")
    for example in impact.dangerous_examples[:5]:
        lines.append(f"      ! {example}")
    lines.append("")
    return "\n".join(lines)


def render_policy(policy: ThresholdPolicy) -> str:
    lines = ["FITTED THRESHOLDS", "=" * 96]
    lines.append(
        f"  Target precision {policy.target_precision:.0%}, "
        f"min {policy.min_samples} claims per field, default {policy.default_threshold:.2f}"
    )
    lines.append("")
    for entry in policy.fields:
        if entry.escalates_always:
            marker = "ALWAYS ESCALATE"
        elif entry.fitted:
            marker = f"{entry.threshold:.2f}"
        else:
            marker = f"{entry.threshold:.2f} (default)"
        lines.append(f"  {entry.field:<28}{marker:<18}{entry.reason}")
    if policy.escalated_fields:
        lines.append("")
        lines.append(
            "  Fields pinned to always-escalate could not reach the precision target at any "
            "confidence. They will be reported as NEEDS_REVIEW until the model improves."
        )
    lines.append("")
    return "\n".join(lines)


def command_server(args) -> int:
    from .server import run_server
    try:
        run_server(port=args.port, store_path=args.store, stats_path=args.stats)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


def run(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    _force_utf8_stdout()
    if args.command == "run":
        return command_run(args)
    if args.command == "report":
        return command_report(args)
    if args.command == "adjudicate":
        return command_adjudicate(args)
    if args.command == "server":
        return command_server(args)
    return EXIT_ERROR


def _force_utf8_stdout() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover
                pass


def main(argv: Optional[List[str]] = None) -> None:
    sys.exit(run(argv))


if __name__ == "__main__":  # pragma: no cover
    main()
