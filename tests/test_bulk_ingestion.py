"""Bulk ingestion: a loop over the single-file pipeline, and provably nothing else.

The properties pinned here are the ones that make a fleet upload trustworthy:
one record per file, one parse per file however many frameworks are requested,
a bad file that costs only itself, identical output across runs, and results
that match what the single-file path produces for the same config. If bulk and
single-file ever disagree, the test that catches it is
``test_framework_results_match_a_single_file_run``.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from auditor import cli, pipeline
from auditor.ingest import (
    build_inventory,
    collect_files,
    find_duplicates,
    ingest_file,
    ingest_paths,
    read_inventory,
    write_inventory,
)
from auditor.models.inventory import DeviceKeyTier, DeviceStatus, DuplicateKind
from auditor.models.result import Status
from auditor.report import render_inventory

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = PROJECT_ROOT / "samples"

FIXED_CLOCK = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

CISCO_SHOW_VERSION = """\
Cisco IOS Software, C2900 Software (C2900-UNIVERSALK9-M), Version 15.7(3)M2, RELEASE SOFTWARE (fc2)
Cisco CISCO2911/K9 (revision 1.0) with 483328K/40960K bytes of memory.
Processor board ID FTX1840ALCK
"""


def _sample(name: str) -> str:
    return (SAMPLES / name).read_text(encoding="utf-8")


@pytest.fixture
def fleet(tmp_path: Path) -> Path:
    """One directory, three vendors, one file each."""
    directory = tmp_path / "fleet"
    directory.mkdir()
    for target, source in {
        "core-rtr-01.conf": "hardened_ios.conf",
        "branch-fw-02.conf": "junos_srx.conf",
        "fgt-01.conf": "fortios_fgt.conf",
    }.items():
        (directory / target).write_text(_sample(source), encoding="utf-8")
    return directory


class CountingFactory:
    """A parser factory that records how many times each file was parsed."""

    def __init__(self) -> None:
        self.parses: list = []

    def __call__(self, parser_cls):
        parser = parser_cls()
        original = parser.parse
        record = self.parses

        def counted(config_text, *, source_file=None):
            record.append(source_file)
            return original(config_text, source_file=source_file)

        parser.parse = counted
        return parser


# ---------------------------------------------------------------------------
# one config in, one device record out
# ---------------------------------------------------------------------------


def test_a_mixed_vendor_batch_produces_one_record_per_file(fleet: Path):
    inventory = ingest_paths([str(fleet)], ["CIS"], now=FIXED_CLOCK)

    assert inventory.counts.total == 3
    assert inventory.counts.audited == 3
    vendors = {Path(device.source_file).name: device.identity.vendor for device in inventory.devices}
    assert vendors == {
        "branch-fw-02.conf": "juniper_junos",
        "core-rtr-01.conf": "cisco_ios",
        "fgt-01.conf": "fortinet_fortios",
    }


def test_each_record_carries_its_own_identity_and_evidence(fleet: Path):
    inventory = ingest_paths([str(fleet)], ["CIS"], now=FIXED_CLOCK)

    hostnames = sorted(device.identity.hostname.value for device in inventory.devices)
    assert hostnames == ["BRANCH-FGT-11", "BRANCH-FW-02", "CORE-RTR-01"]
    for device in inventory.devices:
        assert device.identity.hostname.line_number is not None
        assert device.source_hash and len(device.source_hash) == 64
        assert device.ingested_at == FIXED_CLOCK


def test_explicit_file_list_is_accepted(fleet: Path):
    paths = sorted(str(path) for path in fleet.glob("*.conf"))

    inventory = ingest_paths(paths, ["CIS"], now=FIXED_CLOCK)

    assert inventory.counts.total == 3


def test_a_glob_is_accepted(fleet: Path):
    inventory = ingest_paths([str(fleet / "*.conf")], ["CIS"], now=FIXED_CLOCK)

    assert inventory.counts.total == 3


def test_directory_scanning_recurses(tmp_path: Path):
    nested = tmp_path / "site-a" / "closet-3"
    nested.mkdir(parents=True)
    (nested / "sw.conf").write_text(_sample("hardened_ios.conf"), encoding="utf-8")

    collection = collect_files([str(tmp_path)])

    assert [path.name for path in collection.files] == ["sw.conf"]


def test_a_companion_capture_is_not_ingested_as_a_device(tmp_path: Path):
    (tmp_path / "rtr.conf").write_text(_sample("hardened_ios.conf"), encoding="utf-8")
    (tmp_path / "rtr.show_version.txt").write_text(CISCO_SHOW_VERSION, encoding="utf-8")

    inventory = ingest_paths([str(tmp_path)], ["CIS"], now=FIXED_CLOCK)

    assert inventory.counts.total == 1
    device = inventory.devices[0]
    assert device.identity.serial_number.value == "FTX1840ALCK"
    assert device.companion_file.endswith("rtr.show_version.txt")


def test_serial_stays_null_without_a_companion(fleet: Path):
    inventory = ingest_paths([str(fleet)], ["CIS"], now=FIXED_CLOCK)

    for device in inventory.devices:
        assert device.identity.serial_number.value is None
        assert device.identity.field_value("serial_number") is None


# ---------------------------------------------------------------------------
# per-file isolation: one bad file costs only itself
# ---------------------------------------------------------------------------


def test_a_malformed_file_does_not_abort_the_batch(fleet: Path):
    (fleet / "truncated.conf").write_text("", encoding="utf-8")

    inventory = ingest_paths([str(fleet)], ["CIS"], now=FIXED_CLOCK)

    assert inventory.counts.total == 4
    assert inventory.counts.audited == 3
    assert inventory.counts.parse_error == 1
    broken = inventory.device_by_source(
        next(d.source_file for d in inventory.devices if "truncated" in d.source_file)
    )
    assert broken.status is DeviceStatus.PARSE_ERROR
    assert broken.error == "Configuration file is empty."
    assert broken.findings == []
    # the other three still produced full results
    for device in inventory.devices_with_status(DeviceStatus.AUDITED):
        assert device.findings


def test_an_exploding_parser_is_contained_to_its_own_file(fleet: Path):
    """Even an unexpected exception must not take the batch down."""

    class Exploding:
        def __call__(self, parser_cls):
            parser = parser_cls()
            if parser_cls.name == "juniper_junos":
                def boom(config_text, *, source_file=None):
                    raise RuntimeError("simulated parser defect")

                parser.parse = boom
            return parser

    inventory = ingest_paths([str(fleet)], ["CIS"], parser_factory=Exploding(), now=FIXED_CLOCK)

    assert inventory.counts.audited == 2
    assert inventory.counts.parse_error == 1
    failed = next(d for d in inventory.devices if d.status is DeviceStatus.PARSE_ERROR)
    assert "RuntimeError" in failed.error
    assert "simulated parser defect" in failed.error


def test_an_unrecognised_vendor_is_recorded_not_raised(fleet: Path):
    (fleet / "vrp.conf").write_text(_sample("unknown_vendor.conf"), encoding="utf-8")

    inventory = ingest_paths([str(fleet)], ["CIS"], now=FIXED_CLOCK)

    assert inventory.counts.unknown_vendor == 1
    unknown = next(d for d in inventory.devices if d.status is DeviceStatus.UNKNOWN_VENDOR)
    assert unknown.identity.vendor == "unknown"
    assert unknown.identity.hostname.value == "BRANCH-SW-03"
    assert unknown.identity.serial_number.value is None
    assert "identify the device vendor" in unknown.error


def test_a_named_path_that_does_not_exist_becomes_a_record(tmp_path: Path):
    """A typo in a batch of filenames must be visible, not merely absent."""
    inventory = ingest_paths([str(tmp_path / "nope.conf")], ["CIS"], now=FIXED_CLOCK)

    assert inventory.counts.total == 1
    assert inventory.counts.parse_error == 1
    assert "not found" in inventory.devices[0].error


def test_an_empty_directory_is_a_warning_not_a_device(tmp_path: Path):
    """A directory is not a device; inventing a record for one corrupts the count."""
    inventory = ingest_paths([str(tmp_path)], ["CIS"], now=FIXED_CLOCK)

    assert inventory.devices == []
    assert inventory.counts.total == 0
    assert any("no configuration files" in warning for warning in inventory.warnings)


# ---------------------------------------------------------------------------
# the pipeline is reused, not reimplemented
# ---------------------------------------------------------------------------


def test_framework_results_match_a_single_file_run(tmp_path: Path):
    """Same config, same frameworks -- bulk and single-file must agree exactly."""
    config = tmp_path / "rtr.conf"
    config.write_text(_sample("insecure_ios.conf"), encoding="utf-8")
    frameworks = ["CIS", "nist_800_53"]

    inventory = ingest_paths([str(config)], frameworks, now=FIXED_CLOCK)
    record = inventory.devices[0]

    from auditor.parsers import CiscoIOSParser

    baseline = CiscoIOSParser().parse(config.read_text(encoding="utf-8"), source_file=str(config))
    report = pipeline.audit_baseline(baseline, frameworks)

    assert len(record.findings) == len(report.results)
    for bulk_result, single_result in zip(record.findings, report.results):
        assert bulk_result.rule_id == single_result.rule_id
        assert bulk_result.framework == single_result.framework
        assert bulk_result.status is single_result.status
        assert bulk_result.message == single_result.message
        assert [e.line_number for e in bulk_result.evidence] == [
            e.line_number for e in single_result.evidence
        ]
    assert record.framework_summaries.keys() == report.framework_summaries.keys()
    for name, summary in record.framework_summaries.items():
        assert summary == report.framework_summaries[name]


def test_a_file_is_parsed_once_no_matter_how_many_frameworks_run(fleet: Path):
    """Frameworks are a loop inside the file, never a loop around it."""
    factory = CountingFactory()

    ingest_paths(
        [str(fleet)],
        ["CIS", "nist_800_53", "stig", "iso_27001"],
        parser_factory=factory,
        now=FIXED_CLOCK,
    )

    assert len(factory.parses) == 3, "one parse per file, not one per file per framework"
    assert len(set(factory.parses)) == 3


def test_rule_packs_are_loaded_once_per_batch_not_once_per_device(monkeypatch, tmp_path):
    """Four frameworks over ten Cisco devices is four pack loads, not forty."""
    for index in range(10):
        (tmp_path / f"sw-{index:02d}.conf").write_text(_sample("hardened_ios.conf"), encoding="utf-8")

    loads = []
    original = pipeline.load_framework

    def counted(name, platform_key, *args, **kwargs):
        loads.append((name, platform_key))
        return original(name, platform_key, *args, **kwargs)

    monkeypatch.setattr(pipeline, "load_framework", counted)

    ingest_paths([str(tmp_path)], ["CIS", "nist_800_53", "stig", "iso_27001"], now=FIXED_CLOCK)

    assert len(loads) == 4
    assert len(set(loads)) == 4


def test_the_resolver_does_not_leak_between_batches(tmp_path, monkeypatch):
    """A batch owns its cache; the next run loads its packs afresh."""
    (tmp_path / "sw.conf").write_text(_sample("hardened_ios.conf"), encoding="utf-8")
    loads = []
    original = pipeline.load_framework
    monkeypatch.setattr(
        pipeline,
        "load_framework",
        lambda name, key, *a, **k: (loads.append(name), original(name, key, *a, **k))[1],
    )

    ingest_paths([str(tmp_path)], ["CIS"], now=FIXED_CLOCK)
    ingest_paths([str(tmp_path)], ["CIS"], now=FIXED_CLOCK)

    assert loads == ["CIS", "CIS"]


def test_every_requested_framework_reaches_every_device(fleet: Path):
    frameworks = ["CIS", "nist_800_53", "stig", "iso_27001"]

    inventory = ingest_paths([str(fleet)], frameworks, now=FIXED_CLOCK)

    assert len(inventory.framework_rollup) == 4
    for device in inventory.devices:
        assert len(device.framework_summaries) == 4
        assert len(device.frameworks) == 4


def test_three_valued_logic_survives_the_batch(fleet: Path):
    """NEEDS_REVIEW must still be reachable per device, per framework."""
    inventory = ingest_paths([str(fleet)], ["CIS"], now=FIXED_CLOCK)

    statuses = {result.status for device in inventory.devices for result in device.findings}
    assert Status.PASS in statuses
    assert Status.FAIL in statuses
    assert Status.NEEDS_REVIEW in statuses
    fortigate = next(d for d in inventory.devices if d.identity.vendor == "fortinet_fortios")
    assert fortigate.framework_summaries["CIS"].needs_review > 0


def test_evidence_line_numbers_survive_end_to_end(tmp_path: Path):
    """A line number in the inventory must still point at the line it cites."""
    config = tmp_path / "rtr.conf"
    text = _sample("insecure_ios.conf")
    config.write_text(text, encoding="utf-8")
    lines = text.splitlines()

    inventory = ingest_paths([str(config)], ["CIS"], now=FIXED_CLOCK)

    checked = 0
    for result in inventory.devices[0].findings:
        for evidence in result.evidence:
            if evidence.line_number is None or evidence.source_line is None:
                continue
            assert evidence.source_line in lines[evidence.line_number - 1]
            checked += 1
    assert checked > 0, "no evidence carried a line number to verify"


def test_no_state_leaks_between_files(tmp_path: Path):
    """Two copies of one config, ingested next to two others, agree exactly."""
    for name, source in {
        "a.conf": "hardened_ios.conf",
        "b.conf": "insecure_ios.conf",
        "c.conf": "hardened_ios.conf",
    }.items():
        (tmp_path / name).write_text(_sample(source), encoding="utf-8")

    inventory = ingest_paths([str(tmp_path)], ["CIS"], now=FIXED_CLOCK)
    by_name = {Path(d.source_file).name: d for d in inventory.devices}

    assert by_name["a.conf"].framework_summaries == by_name["c.conf"].framework_summaries
    assert by_name["a.conf"].summary.failed == 0
    assert by_name["b.conf"].summary.failed > 0


# ---------------------------------------------------------------------------
# deduplication and collisions: flag, never merge
# ---------------------------------------------------------------------------


def test_two_files_with_the_same_serial_are_flagged_and_both_kept(tmp_path: Path):
    for name in ("rtr-primary.conf", "rtr-backup.conf"):
        (tmp_path / name).write_text(_sample("hardened_ios.conf"), encoding="utf-8")
        (tmp_path / f"{Path(name).stem}.show_version.txt").write_text(
            CISCO_SHOW_VERSION, encoding="utf-8"
        )
    # Make the two configs differ so only the serial groups them.
    backup = tmp_path / "rtr-backup.conf"
    backup.write_text(backup.read_text(encoding="utf-8") + "! taken from the standby\n", encoding="utf-8")

    inventory = ingest_paths([str(tmp_path)], ["CIS"], now=FIXED_CLOCK)

    assert inventory.counts.total == 2, "both records retained"
    serial_groups = [g for g in inventory.duplicates if g.kind is DuplicateKind.DUPLICATE_SERIAL]
    assert len(serial_groups) == 1
    group = serial_groups[0]
    assert group.key == "FTX1840ALCK"
    assert group.key_tier is DeviceKeyTier.SERIAL
    assert len(group.source_files) == 2
    for device in inventory.devices:
        assert device.device_key == "serial:FTX1840ALCK"
        assert device.device_key_tier is DeviceKeyTier.SERIAL


def test_same_hostname_different_content_is_flagged_as_drift(tmp_path: Path):
    text = _sample("insecure_ios.conf")
    (tmp_path / "snapshot-may.conf").write_text(text, encoding="utf-8")
    (tmp_path / "snapshot-june.conf").write_text(
        text.replace("exec-timeout 0 0", "exec-timeout 10 0"), encoding="utf-8"
    )

    inventory = ingest_paths([str(tmp_path)], ["CIS"], now=FIXED_CLOCK)

    assert inventory.counts.total == 2, "neither snapshot was dropped"
    drift = [g for g in inventory.duplicates if g.kind is DuplicateKind.POSSIBLE_CONFIG_DRIFT]
    assert len(drift) == 1
    assert drift[0].key_tier is DeviceKeyTier.HOSTNAME_VENDOR
    assert sorted(Path(f).name for f in drift[0].source_files) == [
        "snapshot-june.conf",
        "snapshot-may.conf",
    ]
    assert {d.source_hash for d in inventory.devices}.__len__() == 2


def test_byte_identical_files_are_reported_as_duplicate_content(tmp_path: Path):
    text = _sample("hardened_ios.conf")
    (tmp_path / "one.conf").write_text(text, encoding="utf-8")
    (tmp_path / "two.conf").write_text(text, encoding="utf-8")

    inventory = ingest_paths([str(tmp_path)], ["CIS"], now=FIXED_CLOCK)

    kinds = {group.kind for group in inventory.duplicates}
    assert DuplicateKind.DUPLICATE_CONTENT in kinds
    assert DuplicateKind.POSSIBLE_CONFIG_DRIFT not in kinds, "identical content is not drift"
    assert inventory.counts.total == 2


def test_distinct_devices_are_never_grouped(fleet: Path):
    inventory = ingest_paths([str(fleet)], ["CIS"], now=FIXED_CLOCK)

    assert inventory.duplicates == []
    assert inventory.counts.duplicate_groups == 0
    assert len({device.device_key for device in inventory.devices}) == 3


def test_key_tier_precedence_is_serial_then_hostname_then_hash(tmp_path: Path):
    (tmp_path / "named.conf").write_text(_sample("hardened_ios.conf"), encoding="utf-8")
    (tmp_path / "with-serial.conf").write_text(_sample("insecure_ios.conf"), encoding="utf-8")
    (tmp_path / "with-serial.show_version.txt").write_text(CISCO_SHOW_VERSION, encoding="utf-8")
    (tmp_path / "anonymous.conf").write_text("", encoding="utf-8")

    inventory = ingest_paths([str(tmp_path)], ["CIS"], now=FIXED_CLOCK)
    tiers = {Path(d.source_file).name: d.device_key_tier for d in inventory.devices}

    assert tiers["with-serial.conf"] is DeviceKeyTier.SERIAL
    assert tiers["named.conf"] is DeviceKeyTier.HOSTNAME_VENDOR
    assert tiers["anonymous.conf"] is DeviceKeyTier.SOURCE_HASH


def test_find_duplicates_is_pure(fleet: Path):
    inventory = ingest_paths([str(fleet)], ["CIS"], now=FIXED_CLOCK)

    assert find_duplicates(inventory.devices) == find_duplicates(inventory.devices)


# ---------------------------------------------------------------------------
# determinism and serialization
# ---------------------------------------------------------------------------


def test_the_same_directory_produces_identical_output_across_runs(fleet: Path):
    first = ingest_paths([str(fleet)], ["CIS", "nist_800_53"], now=FIXED_CLOCK)
    second = ingest_paths([str(fleet)], ["CIS", "nist_800_53"], now=FIXED_CLOCK)

    assert first.to_json() == second.to_json()


def test_device_ordering_is_stable_regardless_of_input_order(fleet: Path):
    paths = [str(path) for path in fleet.glob("*.conf")]

    forward = ingest_paths(paths, ["CIS"], now=FIXED_CLOCK)
    backward = ingest_paths(list(reversed(paths)), ["CIS"], now=FIXED_CLOCK)

    assert [d.source_file for d in forward.devices] == [d.source_file for d in backward.devices]


def test_inventory_json_has_sorted_keys(fleet: Path):
    inventory = ingest_paths([str(fleet)], ["CIS"], now=FIXED_CLOCK)

    payload = json.loads(inventory.to_json())
    assert list(payload) == sorted(payload)


def test_inventory_json_round_trips(tmp_path: Path, fleet: Path):
    inventory = ingest_paths([str(fleet)], ["CIS", "stig"], now=FIXED_CLOCK)
    destination = tmp_path / "inventory.json"

    write_inventory(inventory, destination)
    restored = read_inventory(destination)

    assert restored.to_json() == inventory.to_json()
    assert restored.counts == inventory.counts
    assert len(restored.devices) == len(inventory.devices)
    assert restored.devices[0].findings[0].evidence == inventory.devices[0].findings[0].evidence


def test_written_inventory_is_valid_json_with_the_documented_top_level_keys(tmp_path, fleet):
    destination = tmp_path / "inventory.json"
    write_inventory(ingest_paths([str(fleet)], ["CIS"], now=FIXED_CLOCK), destination)

    payload = json.loads(destination.read_text(encoding="utf-8"))

    assert set(payload) == {
        "schema_version",
        "generated_at",
        "tool",
        "frameworks",
        "counts",
        "framework_rollup",
        "devices",
        "duplicates",
        "warnings",
    }
    device = payload["devices"][0]
    assert set(device) >= {
        "identity",
        "source_file",
        "source_hash",
        "ingested_at",
        "status",
        "error",
        "frameworks",
        "findings",
        "framework_summaries",
        "device_key",
        "device_key_tier",
    }
    assert device["identity"]["serial_number"]["value"] is None


def test_a_null_serial_serializes_as_json_null(fleet: Path):
    payload = json.loads(ingest_paths([str(fleet)], ["CIS"], now=FIXED_CLOCK).to_json())

    for device in payload["devices"]:
        assert device["identity"]["serial_number"]["value"] is None
        assert device["identity"]["serial_number"]["detected"] is False


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------


def test_the_inventory_view_reports_every_bucket(fleet: Path):
    (fleet / "vrp.conf").write_text(_sample("unknown_vendor.conf"), encoding="utf-8")
    (fleet / "empty.conf").write_text("", encoding="utf-8")

    rendered = render_inventory(
        ingest_paths([str(fleet)], ["CIS", "nist_800_53"], now=FIXED_CLOCK), color=False
    )

    assert "INVENTORY SUMMARY" in rendered
    assert "Devices:        5" in rendered
    assert "Unknown vendor: 1" in rendered
    assert "Parse errors:   1" in rendered
    assert "PER-FRAMEWORK ROLLUP" in rendered
    assert "PER-DEVICE" in rendered
    assert "CORE-RTR-01" in rendered
    assert "NIST SP 800-53" in rendered


def test_the_inventory_view_prints_a_missing_serial_as_null(fleet: Path):
    rendered = render_inventory(ingest_paths([str(fleet)], ["CIS"], now=FIXED_CLOCK), color=False)

    assert "[serial: null]" in rendered


def test_the_inventory_view_names_the_files_it_could_not_audit(fleet: Path):
    (fleet / "empty.conf").write_text("", encoding="utf-8")

    rendered = render_inventory(ingest_paths([str(fleet)], ["CIS"], now=FIXED_CLOCK), color=False)

    assert "FILES NOT AUDITED" in rendered
    assert "empty.conf" in rendered
    assert "Configuration file is empty." in rendered


def test_the_inventory_view_reports_drift_without_merging(tmp_path: Path):
    text = _sample("insecure_ios.conf")
    (tmp_path / "may.conf").write_text(text, encoding="utf-8")
    (tmp_path / "june.conf").write_text(text.replace("exec-timeout 0 0", "exec-timeout 10 0"), encoding="utf-8")

    rendered = render_inventory(ingest_paths([str(tmp_path)], ["CIS"], now=FIXED_CLOCK), color=False)

    assert "possible_config_drift" in rendered
    assert "may.conf" in rendered and "june.conf" in rendered


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_single_file_cli_path_is_unchanged(tmp_path, capsys):
    """Regression: no --bulk means the original behaviour, byte for byte."""
    output = tmp_path / "report.json"

    code = cli.run(["samples/hardened_ios.conf", "--framework", "CIS", "--json", str(output)])
    captured = capsys.readouterr().out

    assert code == cli.EXIT_OK
    assert "NETWORK SECURITY COMPLIANCE AUDIT" in captured
    assert "NETWORK DEVICE INVENTORY" not in captured
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["target"]["hostname"] == "CORE-RTR-01"
    assert payload["summary"]["total"] == 13


def test_bulk_cli_renders_an_inventory_and_writes_json(tmp_path, fleet, capsys):
    destination = tmp_path / "inventory.json"

    code = cli.run(
        [
            "--bulk",
            str(fleet),
            "--framework",
            "CIS",
            "--framework",
            "nist_800_53",
            "--inventory-out",
            str(destination),
        ]
    )
    captured = capsys.readouterr().out

    assert code == cli.EXIT_OK
    assert "NETWORK DEVICE INVENTORY" in captured
    assert "NETWORK SECURITY COMPLIANCE AUDIT" not in captured
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["counts"]["total"] == 3
    assert payload["frameworks"] == ["CIS", "nist_800_53"]


def test_bulk_cli_accepts_several_explicit_files(tmp_path, fleet, capsys):
    files = sorted(str(path) for path in fleet.glob("*.conf"))

    code = cli.run(["--bulk", *files, "--framework", "CIS", "--quiet"])

    assert code == cli.EXIT_OK
    assert capsys.readouterr().out == ""


def test_bulk_cli_writes_no_single_device_json_report(tmp_path, fleet):
    """--bulk must not scatter per-device reports into reports/ as a side effect."""
    before = sorted(p.name for p in (PROJECT_ROOT / "reports").glob("*.json")) if (
        PROJECT_ROOT / "reports"
    ).is_dir() else []

    cli.run(["--bulk", str(fleet), "--framework", "CIS", "--quiet"])

    after = sorted(p.name for p in (PROJECT_ROOT / "reports").glob("*.json")) if (
        PROJECT_ROOT / "reports"
    ).is_dir() else []
    assert before == after


def test_bulk_cli_survives_a_bad_file_and_still_exits_cleanly(tmp_path, fleet, capsys):
    (fleet / "broken.conf").write_text("", encoding="utf-8")

    code = cli.run(["--bulk", str(fleet), "--framework", "CIS"])
    captured = capsys.readouterr().out

    assert code == cli.EXIT_OK
    assert "Parse errors:   1" in captured
    assert "Audited:        3" in captured


def test_bulk_cli_strict_flags_failures(tmp_path, capsys):
    (tmp_path / "weak.conf").write_text(_sample("insecure_ios.conf"), encoding="utf-8")

    code = cli.run(["--bulk", str(tmp_path), "--framework", "CIS", "--quiet"])
    strict = cli.run(["--bulk", str(tmp_path), "--framework", "CIS", "--quiet", "--strict"])

    assert code == cli.EXIT_OK
    assert strict == cli.EXIT_FINDINGS


def test_bulk_cli_strict_treats_an_unaudited_file_as_needing_review(tmp_path):
    (tmp_path / "good.conf").write_text(_sample("hardened_ios.conf"), encoding="utf-8")
    (tmp_path / "mystery.conf").write_text(_sample("unknown_vendor.conf"), encoding="utf-8")

    code = cli.run(["--bulk", str(tmp_path), "--framework", "CIS", "--quiet", "--strict"])

    assert code == cli.EXIT_REVIEW


def test_bulk_cli_reports_an_empty_directory_as_an_error(tmp_path, capsys):
    code = cli.run(["--bulk", str(tmp_path), "--framework", "CIS"])

    assert code == cli.EXIT_ERROR
    assert "no configuration files were found" in capsys.readouterr().err


def test_bulk_cli_rejects_an_unknown_framework_once(fleet, capsys):
    """A misspelled framework is one mistake, not one failure per device."""
    code = cli.run(["--bulk", str(fleet), "--framework", "NIST", "--quiet"])
    err = capsys.readouterr().err

    assert code == cli.EXIT_ERROR
    assert err.count("error:") == 1
    assert "unknown framework" in err
    assert "NIST_800_53" in err


def test_several_paths_without_bulk_is_a_clean_error(capsys):
    code = cli.run(["samples/hardened_ios.conf", "samples/insecure_ios.conf", "--no-json"])

    assert code == cli.EXIT_ERROR
    assert "--bulk" in capsys.readouterr().err


def test_no_path_at_all_is_a_clean_error(capsys):
    code = cli.run([])

    assert code == cli.EXIT_ERROR
    assert "required" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# the pieces, individually
# ---------------------------------------------------------------------------


def test_ingest_file_returns_a_record_rather_than_raising(tmp_path: Path):
    missing = tmp_path / "gone.conf"

    record = ingest_file(missing, ["CIS"], now=FIXED_CLOCK)

    assert record.status is DeviceStatus.PARSE_ERROR
    assert record.source_hash is None


def test_build_inventory_counts_match_the_records(fleet: Path):
    inventory = ingest_paths([str(fleet)], ["CIS"], now=FIXED_CLOCK)

    rebuilt = build_inventory(inventory.devices, ["CIS"], generated_at=FIXED_CLOCK)

    assert rebuilt.counts == inventory.counts
    assert rebuilt.counts.total == len(rebuilt.devices)


def test_the_rollup_sums_the_per_device_summaries(fleet: Path):
    inventory = ingest_paths([str(fleet)], ["CIS"], now=FIXED_CLOCK)

    expected_passed = sum(d.framework_summaries["CIS"].passed for d in inventory.devices)
    expected_failed = sum(d.framework_summaries["CIS"].failed for d in inventory.devices)

    assert inventory.framework_rollup["CIS"].passed == expected_passed
    assert inventory.framework_rollup["CIS"].failed == expected_failed


def test_records_expose_per_framework_drill_down(fleet: Path):
    inventory = ingest_paths([str(fleet)], ["CIS", "stig"], now=FIXED_CLOCK)
    device = inventory.devices[0]

    cis = device.findings_for("CIS")
    assert cis and all(result.framework == "CIS" for result in cis)
    assert len(cis) + len(device.findings_for(device.frameworks[1])) == len(device.findings)
