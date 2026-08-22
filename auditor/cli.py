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
from .parsers import ParserError, registry
from .report import render_report, write_json_report
from .rules import RuleLoadError, available_frameworks, load_framework, load_ruleset

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
        default="CIS",
        help="Compliance framework to evaluate (default: CIS). Available: %s"
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


def _select_parser(config_text: str, vendor: Optional[str]):
    """Explicit --vendor wins; otherwise rank the registered parsers."""
    if vendor:
        parser_cls = registry.get(vendor)
        return parser_cls, parser_cls.detect(config_text)
    return registry.detect(config_text)


def _default_json_path(config: Path, framework: str) -> Path:
    return Path("reports") / f"{config.stem}.{framework.lower()}.json"


def run(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    _force_utf8_stdout()

    try:
        config_text = _read_config(args.config)
        parser_cls, confidence = _select_parser(config_text, args.vendor)
        baseline = parser_cls().parse(config_text, source_file=str(args.config))
        baseline.provenance.detection_confidence = confidence

        if args.rules:
            ruleset = load_ruleset(args.rules)
        else:
            platform_key = f"{parser_cls.vendor}_{parser_cls.os_family}"
            ruleset = load_framework(args.framework, platform_key)

        engine = ComplianceEngine(ruleset)
        report = engine.build_report(
            baseline,
            tool_name=TOOL_NAME,
            tool_version=__version__,
            include_baseline=not args.no_baseline,
        )
    except (ParserError, RuleLoadError, RuleEvaluationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if not args.quiet:
        print(render_report(report, color=False if args.no_color else None))

    if not args.no_json:
        destination = args.json_path or _default_json_path(args.config, ruleset.framework)
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
