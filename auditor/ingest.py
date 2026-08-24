"""Bulk ingestion: orchestration over the single-file pipeline, and nothing more.

This module contains no parsing, no normalization and no rule evaluation.  It
collects files, calls the same ``pipeline`` stages the CLI calls for one config,
and assembles the results into an inventory.  If bulk ingestion and single-file
audit ever disagree about a device, that is a bug here, not a second opinion --
there is only one implementation of the audit.

Three behaviours are load-bearing:

* **Per-file isolation.**  Every file is wrapped in its own try/except. A parse
  error, an unrecognised vendor, or an outright exception becomes a record with
  a status and a message; the batch continues. A fleet upload where file 7 of
  200 is a truncated paste must still return 199 audits, and must still say
  plainly what happened to file 7.
* **Parse once per file.**  A file is read once, parsed once, and the resulting
  baseline is evaluated against every requested framework. Frameworks are a loop
  *inside* the file, never a loop around it.
* **Deterministic order.**  Files are sorted by path before anything runs, so
  two runs over one directory produce the same inventory in the same order.

No state is shared between files: each iteration builds its own parser instance
and its own baseline, so a malformed config cannot contaminate the next one.
"""

import glob as globlib
import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Type

from . import __version__, pipeline
from .engine import RuleEvaluationError
from .identity import companion_path, enrich_from_companion, extract_identity, is_companion_file
from .models.identity import UNKNOWN_VENDOR, DeviceIdentity
from .models.inventory import (
    DeviceInventory,
    DeviceKeyTier,
    DeviceRecord,
    DeviceStatus,
    DuplicateGroup,
    DuplicateKind,
    InventoryCounts,
)
from .models.result import ReportSummary, Status
from .parsers import ParserError, VendorParser
from .parsers.llm.client import LLMUnavailableError
from .pipeline import DEFAULT_FRAMEWORK, TOOL_NAME
from .rules import RuleLoadError

#: Extensions a directory scan treats as configurations. A path named explicitly
#: on the command line bypasses this: naming a file is a statement that it is one.
CONFIG_SUFFIXES = frozenset(
    {".conf", ".cfg", ".config", ".txt", ".text", ".ios", ".junos", ".fortios", ".rsc"}
)

#: Directory scans recurse. A fleet export is usually foldered by site or by
#: vendor, and a scan that stopped at the top level would silently ingest none
#: of it -- silence being the one outcome this tool is built to avoid.
RECURSIVE = True

_GLOB_MARKERS = ("*", "?", "[")

#: Builds a parser instance from the selected class. The CLI substitutes one that
#: threads the LLM/training flags through, so bulk honours them exactly as the
#: single-file path does.
ParserFactory = Callable[[Type[VendorParser]], VendorParser]


def _default_factory(parser_cls: Type[VendorParser]) -> VendorParser:
    return parser_cls()


# ---------------------------------------------------------------------------
# file collection
# ---------------------------------------------------------------------------


def looks_like_glob(value: str) -> bool:
    return any(marker in value for marker in _GLOB_MARKERS)


@dataclass
class Collection:
    """What a set of input paths resolved to, including what it failed to resolve."""

    #: Configuration files to ingest, sorted by path.
    files: List[Path] = field(default_factory=list)
    #: Paths named explicitly that do not exist. Each becomes a ``parse_error``
    #: record: a typo in a batch of 200 filenames has to be visible in the
    #: output, not merely absent from it.
    missing: List[Tuple[Path, str]] = field(default_factory=list)
    #: Directories and globs that matched nothing. Reported to the operator, but
    #: not as devices -- a directory is not a device, and inventing a record for
    #: one would corrupt the count the whole report rests on.
    warnings: List[str] = field(default_factory=list)


def collect_files(paths: Sequence[str]) -> Collection:
    """Expand directories, globs and explicit files into a sorted, unique list."""
    collection = Collection()
    found: List[Path] = []

    for raw in paths:
        candidate = Path(raw)
        if looks_like_glob(str(raw)):
            matches = [Path(match) for match in globlib.glob(str(raw), recursive=True)]
            files = [match for match in matches if match.is_file() and not is_companion_file(match)]
            if not files:
                collection.warnings.append(f"Glob matched no configuration files: {raw}")
            found.extend(files)
        elif candidate.is_dir():
            scanned = _scan_directory(candidate)
            if not scanned:
                collection.warnings.append(
                    f"Directory contains no configuration files: {_display_path(candidate)}"
                )
            found.extend(scanned)
        elif candidate.is_file():
            # Explicitly named: ingested whatever its extension.
            found.append(candidate)
        else:
            collection.missing.append((candidate, f"Configuration file not found: {candidate}"))

    unique: Dict[str, Path] = {}
    for path in found:
        unique.setdefault(_dedup_key_for_path(path), path)
    collection.files = sorted(unique.values(), key=lambda item: _display_path(item))
    return collection


def _dedup_key_for_path(path: Path) -> str:
    """Two spellings of one path must not become two devices."""
    try:
        return str(path.resolve()).lower()
    except OSError:  # pragma: no cover - resolve() on an exotic path
        return str(path).lower()


def _scan_directory(directory: Path) -> List[Path]:
    pattern = "**/*" if RECURSIVE else "*"
    files = []
    for path in directory.glob(pattern):
        if not path.is_file():
            continue
        if any(part.startswith(".") for part in path.parts):
            continue  # dotfiles and .git / .venv trees are not uploads
        if is_companion_file(path):
            continue  # show output belongs to a config; it is not a device itself
        if path.suffix.lower() not in CONFIG_SUFFIXES:
            continue
        files.append(path)
    return files


# ---------------------------------------------------------------------------
# one file -> one record
# ---------------------------------------------------------------------------


def ingest_file(
    path: Path,
    frameworks: Sequence[str],
    *,
    vendor: Optional[str] = None,
    allow_llm: bool = False,
    rules_path=None,
    parser_factory: ParserFactory = _default_factory,
    read_companion: bool = True,
    now: Optional[datetime] = None,
    resolver: Optional[pipeline.RulesetResolver] = None,
) -> DeviceRecord:
    """Audit one configuration and return its device record.

    Never raises for a bad input file: every failure mode is a record with a
    status and an error message. That is what lets the caller loop without a
    guard of its own, and what keeps one unusable file from costing the other
    199 their results.
    """
    ingested_at = now or datetime.now(timezone.utc)
    source_file = _display_path(path)

    try:
        config_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return _failed_record(
            source_file, ingested_at, DeviceStatus.PARSE_ERROR, f"Could not read file: {exc}", frameworks
        )

    source_hash = hashlib.sha256(config_text.encode("utf-8", errors="replace")).hexdigest()

    if not config_text.strip():
        return _failed_record(
            source_file,
            ingested_at,
            DeviceStatus.PARSE_ERROR,
            "Configuration file is empty.",
            frameworks,
            source_hash=source_hash,
            config_text=config_text,
        )

    # -- vendor selection: failing here means unknown vendor, not a bad file --
    try:
        parser_cls, confidence = pipeline.select_parser(config_text, vendor, allow_llm)
    except ParserError as exc:
        return _failed_record(
            source_file,
            ingested_at,
            DeviceStatus.UNKNOWN_VENDOR,
            str(exc),
            frameworks,
            source_hash=source_hash,
            config_text=config_text,
            path=path if read_companion else None,
        )

    # -- parse + evaluate: the same stages, in the same order, as one file ----
    try:
        parser = parser_factory(parser_cls)
        baseline = pipeline.parse_config(
            parser,
            config_text,
            source_file=source_file,
            parser_cls=parser_cls,
            confidence=confidence,
        )
    except (ParserError, LLMUnavailableError) as exc:
        return _failed_record(
            source_file,
            ingested_at,
            DeviceStatus.PARSE_ERROR,
            str(exc),
            frameworks,
            source_hash=source_hash,
            config_text=config_text,
            path=path if read_companion else None,
        )
    except Exception as exc:  # noqa: BLE001 - containment is the point
        # A parser bug is a bug in one file's parse, not grounds for abandoning
        # the batch. The exception type is kept in the message so it is still
        # diagnosable from the inventory alone.
        return _failed_record(
            source_file,
            ingested_at,
            DeviceStatus.PARSE_ERROR,
            f"{type(exc).__name__}: {exc}",
            frameworks,
            source_hash=source_hash,
            config_text=config_text,
            path=path if read_companion else None,
        )

    identity = _identity_for(config_text, baseline, path if read_companion else None)

    try:
        outcome = pipeline.evaluate(
            baseline, frameworks, rules_path=rules_path, resolver=resolver
        )
    except (RuleLoadError, RuleEvaluationError) as exc:
        record = _failed_record(
            source_file,
            ingested_at,
            DeviceStatus.PARSE_ERROR,
            f"Evaluation failed: {exc}",
            frameworks,
            source_hash=source_hash,
        )
        record.identity = identity
        record.target = pipeline.target_info(baseline)
        return record

    return audited_record(
        identity,
        source_file=source_file,
        source_hash=source_hash,
        ingested_at=ingested_at,
        framework_names=[info.name for info in outcome.frameworks],
        results=outcome.results,
        summaries=outcome.summaries,
        target=pipeline.target_info(baseline),
    )


def audited_record(
    identity: DeviceIdentity,
    *,
    source_file: str,
    source_hash: Optional[str],
    ingested_at: datetime,
    framework_names: Sequence[str],
    results: Sequence,
    summaries: Dict[str, ReportSummary],
    target=None,
) -> DeviceRecord:
    """Build one audited record and key it.

    Shared by the batch path and by ``record_from_audit`` below, so a record
    produced from a single-file audit is the same object, built the same way, as
    one produced by a bulk run. Two constructors would eventually disagree.
    """
    record = DeviceRecord(
        identity=identity,
        source_file=source_file,
        source_hash=source_hash,
        ingested_at=ingested_at,
        status=DeviceStatus.AUDITED,
        error=None,
        device_key="",  # assigned below, once identity is final
        device_key_tier=DeviceKeyTier.SOURCE_HASH,
        frameworks=list(framework_names),
        findings=list(results),
        framework_summaries=dict(summaries),
        summary=ReportSummary.from_results(list(results)),
        target=target,
        companion_file=identity.companion_file,
    )
    _assign_key(record)
    return record


def record_from_audit(
    report,
    config_text: str,
    path: Path,
    *,
    baseline=None,
    read_companion: bool = True,
    now: Optional[datetime] = None,
) -> DeviceRecord:
    """Adapt a finished single-file ``AuditReport`` into a device record.

    Lets the single-file path produce the same per-device deliverable a batch
    does, without re-parsing or re-evaluating anything: the report already holds
    the verdicts, and identity comes from the baseline that produced them.

    ``baseline`` is passed explicitly because ``--no-baseline`` strips it from
    the report; identity must not silently degrade to "unknown vendor" just
    because the caller chose a smaller JSON file.
    """
    baseline = baseline if baseline is not None else report.baseline
    identity = _identity_for(config_text, baseline, path if read_companion else None)
    return audited_record(
        identity,
        source_file=_display_path(path),
        source_hash=report.target.source_sha256,
        ingested_at=now or datetime.now(timezone.utc),
        framework_names=[info.name for info in report.frameworks],
        results=report.results,
        summaries=report.framework_summaries,
        target=report.target,
    )


def _identity_for(config_text: str, baseline, path: Optional[Path]) -> DeviceIdentity:
    """Identity from the parse already in hand, enriched only if a capture exists."""
    identity = extract_identity(config_text, baseline)
    if path is None:
        return identity
    companion = companion_path(path)
    if companion is None:
        return identity
    try:
        companion_text = companion.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return identity
    return enrich_from_companion(identity, companion_text, companion_file=_display_path(companion))


def _failed_record(
    source_file: str,
    ingested_at: datetime,
    status: DeviceStatus,
    error: str,
    frameworks: Sequence[str],
    *,
    source_hash: Optional[str] = None,
    config_text: Optional[str] = None,
    path: Optional[Path] = None,
) -> DeviceRecord:
    """A file that produced no audit still produces a record.

    Best-effort identity is still attempted on the raw text: an operator looking
    at a batch of failures is far better served by "BRANCH-SW-03, vendor
    unknown" than by a filename. Every hardware field stays null regardless --
    a file nothing could parse is the last place to start guessing at serials.
    """
    identity = DeviceIdentity()
    if config_text:
        identity = extract_identity(config_text, None, vendor=UNKNOWN_VENDOR)
        if path is not None:
            companion = companion_path(path)
            if companion is not None:
                try:
                    identity = enrich_from_companion(
                        identity,
                        companion.read_text(encoding="utf-8", errors="replace"),
                        companion_file=_display_path(companion),
                    )
                except OSError:
                    pass

    record = DeviceRecord(
        identity=identity,
        source_file=source_file,
        source_hash=source_hash,
        ingested_at=ingested_at,
        status=status,
        error=error,
        device_key="",
        device_key_tier=DeviceKeyTier.SOURCE_HASH,
        frameworks=[],
        findings=[],
        framework_summaries={},
        summary=ReportSummary(),
        target=None,
        companion_file=identity.companion_file,
    )
    _assign_key(record)
    return record


def _display_path(path: Path) -> str:
    """Forward slashes, so an inventory written on Windows reads the same anywhere."""
    return str(path).replace(os.sep, "/")


# ---------------------------------------------------------------------------
# device keying
# ---------------------------------------------------------------------------


def _assign_key(record: DeviceRecord) -> None:
    """Key a record by the strongest identity it actually has.

        1. serial_number      -- survives renames and rewrites; the real identity
        2. hostname + vendor  -- a convention, and only as unique as the operator
        3. source_hash        -- identifies the *file*, not the device

    The tier is stored on the record, so a reader can see at a glance whether
    two rows were matched on hardware identity or merely on a name.
    """
    serial = record.identity.field_value("serial_number")
    if serial:
        record.device_key = f"serial:{serial}"
        record.device_key_tier = DeviceKeyTier.SERIAL
        return

    hostname = record.identity.field_value("hostname")
    if hostname:
        record.device_key = f"host:{hostname.lower()}@{record.identity.vendor}"
        record.device_key_tier = DeviceKeyTier.HOSTNAME_VENDOR
        return

    record.device_key = f"file:{record.source_hash or record.source_file}"
    record.device_key_tier = DeviceKeyTier.SOURCE_HASH


def find_duplicates(devices: Sequence[DeviceRecord]) -> List[DuplicateGroup]:
    """Report what looks duplicated. Merge nothing, drop nothing.

    Three separate questions are asked, because they have three different
    answers and conflating them would lose information:

    * same serial       -> the same physical device was uploaded twice
    * identical bytes   -> the same *file* was uploaded twice
    * same name, different bytes -> either two snapshots of one device or two
      devices sharing a hostname. Nothing in the files distinguishes those, so
      the tool refuses to decide and flags ``possible_config_drift`` instead.
    """
    groups: List[DuplicateGroup] = []

    by_serial: Dict[str, List[DeviceRecord]] = {}
    by_hash: Dict[str, List[DeviceRecord]] = {}
    by_hostname: Dict[Tuple[str, str], List[DeviceRecord]] = {}

    for record in devices:
        serial = record.identity.field_value("serial_number")
        if serial:
            by_serial.setdefault(serial, []).append(record)
        if record.source_hash:
            by_hash.setdefault(record.source_hash, []).append(record)
        hostname = record.identity.field_value("hostname")
        if hostname:
            by_hostname.setdefault((hostname.lower(), record.identity.vendor), []).append(record)

    for serial, members in by_serial.items():
        if len(members) > 1:
            groups.append(
                DuplicateGroup(
                    kind=DuplicateKind.DUPLICATE_SERIAL,
                    key=serial,
                    key_tier=DeviceKeyTier.SERIAL,
                    source_files=[member.source_file for member in members],
                    note=(
                        f"{len(members)} files report serial {serial}: the same physical device. "
                        "Both records are kept; neither was merged."
                    ),
                )
            )

    for digest, members in by_hash.items():
        if len(members) > 1:
            groups.append(
                DuplicateGroup(
                    kind=DuplicateKind.DUPLICATE_CONTENT,
                    key=digest,
                    key_tier=DeviceKeyTier.SOURCE_HASH,
                    source_files=[member.source_file for member in members],
                    note=(
                        f"{len(members)} files are byte-identical (sha256 {digest[:12]}...). "
                        "Both records are kept."
                    ),
                )
            )

    for (hostname, vendor), members in by_hostname.items():
        if len(members) < 2:
            continue
        digests = {member.source_hash for member in members if member.source_hash}
        if len(digests) < 2:
            continue  # identical content: already reported as duplicate_content
        # Keyed case-insensitively, but quoted as the device spells it.
        as_written = members[0].identity.field_value("hostname") or hostname
        groups.append(
            DuplicateGroup(
                kind=DuplicateKind.POSSIBLE_CONFIG_DRIFT,
                key=f"{hostname}@{vendor}",
                key_tier=DeviceKeyTier.HOSTNAME_VENDOR,
                source_files=[member.source_file for member in members],
                note=(
                    f"{len(members)} files claim hostname {as_written!r} on {vendor} but differ in "
                    "content. Either two snapshots of one device or two devices sharing a name -- "
                    "the configurations do not say which, so both records are kept and neither "
                    "was merged."
                ),
            )
        )

    groups.sort(key=lambda group: (group.kind.value, group.key))
    return groups


# ---------------------------------------------------------------------------
# the batch
# ---------------------------------------------------------------------------


def ingest_paths(
    paths: Sequence[str],
    frameworks: Optional[Sequence[str]] = None,
    *,
    vendor: Optional[str] = None,
    allow_llm: bool = False,
    rules_path=None,
    parser_factory: ParserFactory = _default_factory,
    read_companion: bool = True,
    now: Optional[datetime] = None,
) -> DeviceInventory:
    """Ingest every configuration under ``paths`` into one inventory.

    ``paths`` may mix directories, explicit files and globs. ``now`` exists so a
    caller (a test, or a reproducible export) can pin the timestamps: everything
    else about the output is already deterministic, and the clock is the only
    part that is not.
    """
    frameworks = list(frameworks) if frameworks else [DEFAULT_FRAMEWORK]
    generated_at = now or datetime.now(timezone.utc)

    collection = collect_files(paths)
    # One resolver for this batch: rule packs are loaded once per
    # (framework, platform) instead of once per device per framework.
    resolver = pipeline.RulesetResolver()

    devices: List[DeviceRecord] = [
        ingest_file(
            path,
            frameworks,
            vendor=vendor,
            allow_llm=allow_llm,
            rules_path=rules_path,
            parser_factory=parser_factory,
            read_companion=read_companion,
            now=generated_at,
            resolver=resolver,
        )
        for path in collection.files
    ]
    devices.extend(
        _failed_record(_display_path(path), generated_at, DeviceStatus.PARSE_ERROR, message, frameworks)
        for path, message in collection.missing
    )

    inventory = build_inventory(devices, frameworks, generated_at=generated_at)
    inventory.warnings = list(collection.warnings)
    return inventory


def build_inventory(
    devices: Sequence[DeviceRecord],
    frameworks: Sequence[str],
    *,
    generated_at: Optional[datetime] = None,
) -> DeviceInventory:
    """Assemble records into an inventory: counts, rollup, duplicate groups."""
    devices = list(devices)
    duplicates = find_duplicates(devices)

    counts = InventoryCounts(
        total=len(devices),
        audited=sum(1 for device in devices if device.status is DeviceStatus.AUDITED),
        unknown_vendor=sum(1 for device in devices if device.status is DeviceStatus.UNKNOWN_VENDOR),
        parse_error=sum(1 for device in devices if device.status is DeviceStatus.PARSE_ERROR),
        duplicate_groups=len(duplicates),
    )

    return DeviceInventory(
        generated_at=generated_at or datetime.now(timezone.utc),
        tool={"name": TOOL_NAME, "version": __version__},
        frameworks=list(frameworks),
        counts=counts,
        framework_rollup=_rollup(devices),
        devices=devices,
        duplicates=duplicates,
    )


def _rollup(devices: Iterable[DeviceRecord]) -> Dict[str, ReportSummary]:
    """PASS/FAIL/REVIEW summed across devices, per framework.

    Built from the individual results rather than by adding up per-device
    summaries, so the fleet-wide compliance score is computed the same way a
    single device's is -- one definition of the score, not two.
    """
    by_framework: Dict[str, List] = {}
    for device in devices:
        for result in device.findings:
            by_framework.setdefault(result.framework, []).append(result)
    return {
        name: ReportSummary.from_results(results)
        for name, results in sorted(by_framework.items())
    }


def write_inventory(inventory: DeviceInventory, path) -> Path:
    """Write the inventory JSON: the contract the dashboard step will consume."""
    path = Path(path)
    if path.parent != Path(""):
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(inventory.to_json() + "\n", encoding="utf-8")
    return path


def read_inventory(path) -> DeviceInventory:
    """Load an inventory back. Round-trips exactly what ``write_inventory`` wrote."""
    return DeviceInventory.model_validate_json(Path(path).read_text(encoding="utf-8"))


__all__ = [
    "CONFIG_SUFFIXES",
    "DeviceInventory",
    "DeviceRecord",
    "DeviceStatus",
    "Status",
    "build_inventory",
    "collect_files",
    "find_duplicates",
    "ingest_file",
    "ingest_paths",
    "read_inventory",
    "write_inventory",
]
