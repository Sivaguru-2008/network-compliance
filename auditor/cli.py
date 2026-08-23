"""Command-line entry point.

    python -m auditor samples/insecure_ios.conf --framework CIS
    python -m auditor --bulk samples/configs/ --framework CIS --inventory-out inventory.json

The CLI is a thin shell over the four pipeline stages -- read, parse, evaluate,
report.  It holds no compliance logic of its own, so an API server or a batch
runner added later can call the same three objects directly.

``--bulk`` is the batch runner that was always anticipated: it adds no auditing
of its own, it loops ``auditor.ingest`` over the same ``auditor.pipeline``
stages this module calls for one file.  Without ``--bulk`` the single-file path
below runs exactly as it always has.
"""

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__, pipeline
from .engine import RuleEvaluationError
from .models.result import AuditReport
from .parsers import HybridParser, LLMParser, ParserError, VendorParser, registry
from .parsers.llm.client import DEFAULT_MODEL, AnthropicClient, LLMUnavailableError
from .pipeline import DEFAULT_FRAMEWORK, TOOL_NAME
from .report import render_inventory, render_report, write_json_report
from .rules import RuleLoadError, available_frameworks

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_REVIEW = 3

_EPILOG = """\
bulk ingestion:
  python -m auditor --bulk samples/configs/ --framework cis --framework nist_800_53
  python -m auditor --bulk a.conf b.conf c.conf --framework stig
  python -m auditor --bulk "configs/**/*.conf" --inventory-out inventory.json

  Directories are scanned recursively. Each file is parsed once and evaluated
  against every requested framework; a file that cannot be read, parsed, or
  identified becomes a record with a status and a reason, and the batch
  continues.

exit codes:
  0  completed (or, with --strict, every control passed)
  1  --strict and at least one control FAILED
  2  the configuration could not be read, parsed, or evaluated
  3  --strict and at least one control needs review (no outright failures)

Without --strict the tool always exits 0 on a successful run, so it can be used
in a pipeline that collects reports without gating on them.  Under --bulk,
--strict grades the batch by its worst device, and a file that could not be
audited counts as needing review.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m auditor",
        description="Audit a network device configuration against a security benchmark.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "config",
        type=Path,
        nargs="*",
        help=(
            "Path to the device configuration file. With --bulk, one or more files, "
            "directories or globs to ingest as a batch."
        ),
    )
    parser.add_argument(
        "--bulk",
        action="store_true",
        help=(
            "Ingest every configuration under the given paths as a batch, producing a device "
            "inventory instead of a single-device report. Directories are scanned recursively."
        ),
    )
    parser.add_argument(
        "--inventory-out",
        dest="inventory_path",
        type=Path,
        default=None,
        metavar="PATH",
        help="With --bulk, write the full device inventory as JSON to PATH.",
    )
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
    return pipeline.select_parser(config_text, vendor, allow_llm)


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

    frameworks_to_run = args.framework or [DEFAULT_FRAMEWORK]

    if not args.config:
        print("error: at least one configuration path is required.", file=sys.stderr)
        return EXIT_ERROR

    if args.bulk:
        return _run_bulk(args, frameworks_to_run)

    if len(args.config) > 1:
        print(
            "error: several configuration paths were given without --bulk. "
            "Pass --bulk to ingest them as a batch, or name one file.",
            file=sys.stderr,
        )
        return EXIT_ERROR
    args.config = args.config[0]

    try:
        config_text = _read_config(args.config)
        parser_cls, confidence = _select_parser(config_text, args.vendor, args.allow_llm)
        parser = _instantiate(parser_cls, args)
        baseline = pipeline.parse_config(
            parser,
            config_text,
            source_file=str(args.config),
            parser_cls=parser_cls,
            confidence=confidence,
        )
        report = pipeline.audit_baseline(
            baseline,
            frameworks_to_run,
            rules_path=args.rules,
            include_baseline=not args.no_baseline,
        )
        primary_framework = report.framework
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


def _run_bulk(args, frameworks_to_run: List[str]) -> int:
    """Ingest a batch and report the inventory.

    Deliberately has no try/except around the batch: per-file failures are
    already contained inside the orchestrator and come back as records. Letting
    the batch itself abort here would undo exactly the property this path
    exists to provide.
    """
    from .ingest import ingest_paths, write_inventory

    # A misspelled framework is one mistake, not one per device. Caught here so
    # bulk reports it the way the single-file path does -- once, and clearly --
    # instead of repeating it as a failure on every file in the batch.
    if not args.rules:
        known = {name.upper() for name in available_frameworks()}
        unknown = [name for name in frameworks_to_run if name.upper() not in known]
        if unknown:
            print(
                f"error: unknown framework(s): {', '.join(unknown)}. "
                f"Available: {', '.join(sorted(known))}.",
                file=sys.stderr,
            )
            return EXIT_ERROR

    inventory = ingest_paths(
        [str(path) for path in args.config],
        frameworks_to_run,
        vendor=args.vendor,
        allow_llm=args.allow_llm,
        rules_path=args.rules,
        parser_factory=lambda parser_cls: _instantiate(parser_cls, args),
    )

    for warning in inventory.warnings:
        print(f"warning: {warning}", file=sys.stderr)

    if not inventory.devices:
        print("error: no configuration files were found to ingest.", file=sys.stderr)
        return EXIT_ERROR

    if not args.quiet:
        print(render_inventory(inventory, color=False if args.no_color else None))

    if args.inventory_path:
        written = write_inventory(inventory, args.inventory_path)
        print(f"Inventory JSON written to {written}")

    return _inventory_exit_code(inventory, strict=args.strict)


def _exit_code(report: AuditReport, *, strict: bool) -> int:
    if not strict:
        return EXIT_OK
    if report.summary.failed:
        return EXIT_FINDINGS
    if report.summary.needs_review:
        return EXIT_REVIEW
    return EXIT_OK


def _inventory_exit_code(inventory, *, strict: bool) -> int:
    """The single-file gating rule, applied to the worst device in the batch.

    A file that could not be audited counts as needing review rather than as a
    failure: nothing was proven about the device, and NEEDS_REVIEW is precisely
    the verdict this tool uses for "no conclusive evidence".
    """
    if not strict:
        return EXIT_OK
    if any(summary.failed for summary in inventory.framework_rollup.values()):
        return EXIT_FINDINGS
    unaudited = inventory.counts.total - inventory.counts.audited
    if unaudited or any(summary.needs_review for summary in inventory.framework_rollup.values()):
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
