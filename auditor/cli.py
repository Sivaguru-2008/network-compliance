"""Command-line entry point.

    python -m auditor samples/insecure_ios.conf --framework CIS

The CLI is a thin shell over the four pipeline stages -- read, parse, evaluate,
report.  It holds no compliance logic of its own, so an API server or a batch
runner added later can call the same three objects directly.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .engine import ComplianceEngine, RuleEvaluationError
from .models.result import AuditReport, Status
from .parsers import HybridParser, LLMParser, ParserError, VendorParser, registry
from .parsers.llm.client import DEFAULT_MODEL, AnthropicClient, LLMUnavailableError
from .report import render_report, write_json_report
from .rules import (
    RuleLoadError,
    available_frameworks,
    load_framework,
    load_ruleset,
    platform_mismatch_note,
)

TOOL_NAME = "netaudit"

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_REVIEW = 3

_EPILOG = """\
exit codes:
  0  completed (or, with --strict, every control passed)
  1  --strict and at least one control FAILED
  2  the configuration could not be read, parsed, or evaluated
  3  --strict and at least one control needs review (no outright failures)

Without --strict the tool always exits 0 on a successful run, so it can be used
in a pipeline that collects reports without gating on them.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m auditor",
        description="Audit a network device configuration against a security benchmark.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("config", type=Path, help="Path to the device configuration file.")
    parser.add_argument(
        "--framework",
        action="append",
        default=None,
        help="Compliance framework to evaluate (can specify multiple). Available: %s"
        % (", ".join(available_frameworks()) or "none found"),
    )
    parser.add_argument(
        "--vendor",
        default=None,
        choices=registry.names(),
        help="Force a specific parser instead of auto-detecting the vendor.",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=None,
        help="Path to an explicit rule pack JSON, bypassing framework/platform lookup.",
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        type=Path,
        default=None,
        help="Where to write the JSON report (default: reports/<config-name>.<framework>.json).",
    )
    parser.add_argument("--no-json", action="store_true", help="Do not write a JSON report.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colour in the table.")
    parser.add_argument("--quiet", action="store_true", help="Suppress the table; write the JSON report only.")
    parser.add_argument(
        "--no-baseline",
        action="store_true",
        help="Omit the full normalized baseline from the JSON report.",
    )
    llm = parser.add_argument_group(
        "LLM fallback",
        "For vendors no deterministic parser handles, and for the gaps the deterministic "
        "parser leaves open (--vendor hybrid). Parsing sends the configuration to the "
        "model provider, so it is opt-in.",
    )
    llm.add_argument(
        "--allow-llm",
        action="store_true",
        help="Permit the LLM fallback parser when no deterministic parser recognises the config.",
    )
    llm.add_argument(
        "--llm-model",
        default=DEFAULT_MODEL,
        help=f"Model to use for LLM parsing (default: {DEFAULT_MODEL}).",
    )
    llm.add_argument(
        "--llm-min-confidence",
        type=float,
        default=0.6,
        metavar="F",
        help="Discard model findings below this confidence, escalating them to NEEDS_REVIEW (default: 0.6).",
    )
    llm.add_argument(
        "--training-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="Apply the per-field thresholds and worked examples fitted by "
        "`python -m auditor.training run` in this directory.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return a non-zero exit code when controls fail or need review.",
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    return parser


def _read_config(path: Path) -> str:
    if not path.is_file():
        raise ParserError(f"Configuration file not found: {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def _select_parser(config_text: str, vendor: Optional[str], allow_llm: bool):
    """Explicit --vendor wins; otherwise rank the registered parsers."""
    if vendor:
        parser_cls = registry.get(vendor)
        return parser_cls, parser_cls.detect(config_text)
    return registry.detect(config_text, allow_fallback=allow_llm)


def _instantiate(parser_cls, args) -> "VendorParser":
    """Build the parser, passing LLM knobs only to the parsers that have them."""
    if parser_cls is LLMParser:
        return _llm_parser(args)
    if parser_cls is HybridParser:
        return HybridParser(llm=_llm_parser(args))
    return parser_cls()


def _llm_parser(args) -> LLMParser:
    """The LLM parser, tuned by a training run when one is pointed at.

    Without --training-dir this is the parser exactly as shipped: a flat
    confidence gate and the base prompt. With it, the thresholds the loop
    measured per field and the corrections it mined replace those defaults, so
    fields the model has proven unreliable at escalate instead of answering.
    """
    client = _llm_client(args)
    if args.training_dir is None:
        return LLMParser(client, min_confidence=args.llm_min_confidence)
    from .training import tuned_parser  # deferred: auditing never needs the loop

    return tuned_parser(args.training_dir, client, min_confidence=args.llm_min_confidence)


def _llm_client(args):
    """Constructed before the parse, so a missing SDK fails before anything is sent.

    A missing *key* surfaces on the first request instead: the SDK resolves
    credentials lazily. That is why a hybrid parse of a config with no gaps
    succeeds without one — it never makes a request.
    """
    return AnthropicClient(model=args.llm_model)


def _default_json_path(config: Path, framework: str) -> Path:
    return Path("reports") / f"{config.stem}.{framework.lower()}.json"


def run(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    _force_utf8_stdout()

    try:
        config_text = _read_config(args.config)
        parser_cls, confidence = _select_parser(config_text, args.vendor, args.allow_llm)
        parser = _instantiate(parser_cls, args)
        baseline = parser.parse(config_text, source_file=str(args.config))
        if parser_cls not in (LLMParser, HybridParser):
            # The LLM parser reports the vendor it identified, and the hybrid parser
            # carries the confidence of the deterministic parser it built on. Neither
            # is improved by the registry's score for the class itself.
            baseline.provenance.detection_confidence = confidence

        # Platform comes from the parsed baseline, not the parser class: the LLM
        # fallback only learns the vendor by reading the configuration.
        from .models.result import FrameworkInfo, ReportSummary, TargetInfo

        platform_key = f"{baseline.provenance.vendor}_{baseline.provenance.os_family}"
        
        frameworks_to_run = args.framework
        if not frameworks_to_run:
            frameworks_to_run = ["CIS"]

        all_results = []
        frameworks_info = []
        framework_summaries = {}
        primary_framework = None

        if args.rules:
            ruleset = load_ruleset(args.rules)
            engine = ComplianceEngine(ruleset)
            results = engine.evaluate(baseline)
            all_results.extend(results)
            fw_info = FrameworkInfo(
                name=ruleset.framework,
                version=ruleset.framework_version,
                rules_evaluated=len(results),
                source_note=ruleset.source_note,
                platform_note=platform_mismatch_note(
                    ruleset, baseline.provenance.vendor, baseline.provenance.os_family
                ),
            )
            frameworks_info.append(fw_info)
            framework_summaries[ruleset.framework] = ReportSummary.from_results(results)
            primary_framework = fw_info
        else:
            for fw in frameworks_to_run:
                ruleset = load_framework(fw, platform_key, allow_cross_platform=True)
                engine = ComplianceEngine(ruleset)
                results = engine.evaluate(baseline)
                all_results.extend(results)
                fw_info = FrameworkInfo(
                    name=ruleset.framework,
                    version=ruleset.framework_version,
                    rules_evaluated=len(results),
                    source_note=ruleset.source_note,
                    platform_note=platform_mismatch_note(
                        ruleset, baseline.provenance.vendor, baseline.provenance.os_family
                    ),
                )
                frameworks_info.append(fw_info)
                framework_summaries[ruleset.framework] = ReportSummary.from_results(results)
                if primary_framework is None:
                    primary_framework = fw_info

        # Overall summary of all results across all frameworks
        summary = ReportSummary.from_results(all_results)

        report = AuditReport(
            tool={"name": TOOL_NAME, "version": __version__},
            target=TargetInfo(
                source_file=baseline.source_file,
                source_sha256=baseline.source_sha256,
                hostname=baseline.hostname.value,
                vendor=baseline.provenance.vendor,
                os_family=baseline.provenance.os_family,
                parser=baseline.provenance.parser_name,
                parser_version=baseline.provenance.parser_version,
                detection_confidence=baseline.provenance.detection_confidence,
                config_line_count=baseline.config_line_count,
                parser_warnings=baseline.provenance.warnings,
            ),
            framework=primary_framework,
            frameworks=frameworks_info,
            framework_summaries=framework_summaries,
            summary=summary,
            results=all_results,
            baseline=baseline if not args.no_baseline else None,
        )
    except (ParserError, RuleLoadError, RuleEvaluationError, LLMUnavailableError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not args.quiet:
        print(render_report(report, color=False if args.no_color else None))

    if not args.no_json:
        if args.rules:
            fw_suffix = "rules"
        elif len(frameworks_to_run) > 1:
            fw_suffix = "multi"
        else:
            fw_suffix = primary_framework.name.lower()
        destination = args.json_path or _default_json_path(args.config, fw_suffix)
        written = write_json_report(report, destination, include_baseline=not args.no_baseline)
        print(f"JSON report written to {written}")

    return _exit_code(report, strict=args.strict)


def _exit_code(report: AuditReport, *, strict: bool) -> int:
    if not strict:
        return EXIT_OK
    if report.summary.failed:
        return EXIT_FINDINGS
    if report.summary.needs_review:
        return EXIT_REVIEW
    return EXIT_OK


def _force_utf8_stdout() -> None:
    """The table uses box-drawing characters; Windows consoles often default to cp1252."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover - stream already detached/redirected
                pass


def main(argv: Optional[List[str]] = None) -> None:
    sys.exit(run(argv))


if __name__ == "__main__":  # pragma: no cover
    main()
