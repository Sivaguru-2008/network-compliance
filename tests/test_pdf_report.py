"""Per-device PDF reporting: a rendering of a finished audit, and provably nothing more.

A PDF is awkward to assert on, so nothing here checks pixels.  What is pinned is
the contract: the file opens, it carries the device's real identity, every
framework the operator asked for lands in *one* file, and each verdict, citation
and evidence line arrives on the page exactly as the rule engine stored it.

Two properties matter more than the rest, because they are the ones a reader
would have no way to detect from the page itself:

* ``test_rendering_never_parses_or_evaluates`` -- the renderer is a sink. The
  parsers and the rule engine are replaced with landmines before a PDF is drawn;
  if either is touched, the test fails. A PDF that re-derived anything would be
  a second opinion, and two opinions cannot both be the audit.
* the honesty tests -- a null serial prints as null, and an unverified control
  reference is never dressed up as an official clause number. Both are failures
  a plausible-looking report would hide.
"""

import re
from datetime import datetime, timezone
from pathlib import Path

import pytest

from auditor import cli
from auditor.ingest import ingest_file, ingest_paths
from auditor.models.inventory import DeviceStatus
from auditor.models.result import Status
from auditor.report import pdf_available, write_device_pdf, write_inventory_pdfs
from auditor.report.document import INTERNAL_MARK, NULL, build_device_document
from auditor.report.pdf import escape, pdf_filenames

pypdf = pytest.importorskip("pypdf", reason="text extraction is how a PDF is asserted on")

pytestmark = pytest.mark.skipif(
    not pdf_available(), reason="reportlab is not installed (pip install -r requirements-pdf.txt)"
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = PROJECT_ROOT / "samples"

ALL_FRAMEWORKS = ["cis", "nist_800_53", "stig", "iso_27001"]

#: The four framework display names, as the rule packs spell them. A PDF that
#: covered only some of them would still open cleanly, so the names are asserted
#: literally rather than by counting.
FRAMEWORK_NAMES = ["CIS", "NIST SP 800-53", "DISA STIG", "ISO/IEC 27001"]

FIXED_CLOCK = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def extract(path: Path) -> str:
    """Every page's text, joined. Line breaks are layout, so they are collapsed.

    reportlab wraps a long cell across lines; a command that reads
    ``transport input ssh`` on the page can extract as two fragments. Collapsing
    whitespace keeps assertions about *content* from failing over *layout*.
    """
    reader = pypdf.PdfReader(str(path))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    return " ".join(text.split())


def page_count(path: Path) -> int:
    return len(pypdf.PdfReader(str(path)).pages)


def record_for(name: str, frameworks=ALL_FRAMEWORKS):
    """One finished device record, straight from the Step 8 ingestion path."""
    return ingest_file(SAMPLES / name, frameworks, now=FIXED_CLOCK)


def finding_for(record, internal_control_id: str):
    """The rendered finding block for one semantic control on one device."""
    result = next(r for r in record.findings if r.internal_control_id == internal_control_id)
    document = build_device_document(record)
    return next(block for block in document.findings if block.rule_id == result.rule_id)


def non_passing(record):
    return [result for result in record.findings if result.status is not Status.PASS]


@pytest.fixture(scope="module")
def hardened_record():
    return record_for("hardened_ios.conf")


@pytest.fixture(scope="module")
def insecure_record():
    return record_for("insecure_ios.conf")


@pytest.fixture(scope="module")
def junos_record():
    return record_for("junos_srx.conf")


@pytest.fixture(scope="module")
def insecure_pdf(insecure_record, tmp_path_factory) -> Path:
    path = tmp_path_factory.mktemp("pdf") / "insecure.pdf"
    write_device_pdf(insecure_record, path)
    return path


@pytest.fixture
def fleet(tmp_path: Path) -> Path:
    """Three vendors, one unknown vendor, one unreadable file."""
    directory = tmp_path / "fleet"
    directory.mkdir()
    for target, source in {
        "core-rtr-01.conf": "hardened_ios.conf",
        "branch-fw-02.conf": "junos_srx.conf",
        "fgt-01.conf": "fortios_fgt.conf",
        "vrp-core-01.conf": "unknown_vendor.conf",
    }.items():
        (directory / target).write_text(
            (SAMPLES / source).read_text(encoding="utf-8"), encoding="utf-8"
        )
    (directory / "truncated.conf").write_text("", encoding="utf-8")
    return directory


# ---------------------------------------------------------------------------
# 1. it renders, and what comes out is a PDF
# ---------------------------------------------------------------------------


def test_renders_a_valid_non_empty_pdf(hardened_record, tmp_path):
    path = write_device_pdf(hardened_record, tmp_path / "report.pdf")

    assert path.exists()
    assert path.stat().st_size > 0
    assert path.read_bytes().startswith(b"%PDF-")
    assert page_count(path) > 0


def test_creates_the_output_directory_when_it_is_missing(hardened_record, tmp_path):
    """A path into a directory that does not exist yet is an instruction, not an error."""
    path = write_device_pdf(hardened_record, tmp_path / "nested" / "deeper" / "report.pdf")
    assert path.exists()


# ---------------------------------------------------------------------------
# 2. the page carries the device, the frameworks, the findings, the fix
# ---------------------------------------------------------------------------


def test_text_carries_hostname_frameworks_finding_and_remediation(insecure_record, insecure_pdf):
    text = extract(insecure_pdf)

    assert insecure_record.identity.hostname.value in text
    for framework in FRAMEWORK_NAMES:
        assert framework in text, f"{framework} missing from the report"

    titles = {result.title for result in non_passing(insecure_record)}
    assert any(title in text for title in titles), "no finding title reached the page"

    # The vendor's own command, not a framework-generic instruction to "harden SSH".
    assert "transport input ssh" in text
    assert "configure terminal" in text


def test_severity_is_rendered_for_every_finding(insecure_record, insecure_pdf):
    text = extract(insecure_pdf)

    severities = {result.severity.value for result in insecure_record.findings}
    assert severities, "fixture produced no results"
    for severity in severities:
        assert severity in text or severity.upper() in text


def test_status_words_reach_the_page(insecure_pdf):
    text = extract(insecure_pdf)

    assert "FAIL" in text
    assert "PASS" in text
    assert "NEEDS_REVIEW" in text


def test_the_summary_reports_the_counts_the_record_already_held(insecure_record):
    """Every per-framework tally is copied from the record, not recomputed."""
    document = build_device_document(insecure_record)

    assert {row.framework for row in document.summaries} == set(insecure_record.frameworks)
    for row in document.summaries:
        stored = insecure_record.framework_summaries[row.framework]
        assert (row.passed, row.failed, row.needs_review, row.total) == (
            stored.passed,
            stored.failed,
            stored.needs_review,
            stored.total,
        )


# ---------------------------------------------------------------------------
# 3. one device, one file, every framework inside it
# ---------------------------------------------------------------------------


def test_four_frameworks_produce_one_pdf_containing_all_four(hardened_record, tmp_path):
    assert len(hardened_record.framework_summaries) == 4

    path = write_device_pdf(hardened_record, tmp_path / "device.pdf")

    assert list(tmp_path.glob("*.pdf")) == [path], "one device must produce exactly one PDF"
    text = extract(path)
    for framework in FRAMEWORK_NAMES:
        assert framework in text


def test_every_stored_result_appears_in_the_single_document(hardened_record):
    """All four frameworks' controls live in one document, not split across files."""
    document = build_device_document(hardened_record)

    assert len(document.controls) == len(hardened_record.findings)
    assert {row.framework for row in document.controls} == set(hardened_record.frameworks)
    assert len(document.summaries) == 4


# ---------------------------------------------------------------------------
# 4. identity is rendered honestly, or not at all
# ---------------------------------------------------------------------------


def test_absent_serial_is_printed_as_null_with_its_reason(hardened_record, tmp_path):
    assert hardened_record.identity.field_value("serial_number") is None

    text = extract(write_device_pdf(hardened_record, tmp_path / "device.pdf"))

    assert "Serial number" in text
    assert NULL in text
    assert "requires show-command output" in text


def test_no_serial_is_ever_invented(hardened_record, tmp_path):
    """The absent field must print as absent -- never as a plausible serial.

    A fabricated serial is the single most damaging thing this report could
    contain: it is the field an asset register is keyed on, and a wrong one is
    worse than a missing one because nobody would think to check it.
    """
    path = write_device_pdf(hardened_record, tmp_path / "device.pdf")
    document = build_device_document(hardened_record)

    serial = next(
        f for f in document.section("Device Identification").fields if f.label == "Serial number"
    )
    assert serial.value == NULL
    assert serial.detected is False

    # Cisco serials look like FTX1840ALCK: three letters, four digits, four more.
    assert not re.search(r"\b[A-Z]{3}\d{4}[A-Z0-9]{4}\b", extract(path))


def test_a_detected_identity_field_is_printed_as_found(hardened_record):
    document = build_device_document(hardened_record)
    fields = {f.label: f for f in document.section("Device Identification").fields}

    hostname = fields["Hostname"]
    assert hostname.value == hardened_record.identity.hostname.value
    assert hostname.detected is True
    assert hostname.value != NULL


def test_a_serial_read_from_companion_output_is_credited_to_it(tmp_path):
    """When a serial *is* available it is printed -- and credited to show output.

    The counterpart to the null case: the tool prints what it has. What it must
    not do is cite a configuration line number for a value that came from a
    different file.
    """
    config = tmp_path / "core-rtr-01.conf"
    config.write_text((SAMPLES / "hardened_ios.conf").read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "core-rtr-01.show_version.txt").write_text(
        "Cisco IOS Software, C2900 Software, Version 15.7(3)M2\n"
        "Processor board ID FTX1840ALCK\n",
        encoding="utf-8",
    )

    record = ingest_file(config, ["cis"], now=FIXED_CLOCK)
    assert record.identity.field_value("serial_number") == "FTX1840ALCK"

    text = extract(write_device_pdf(record, tmp_path / "report.pdf"))
    assert "FTX1840ALCK" in text
    assert "companion show output" in text


# ---------------------------------------------------------------------------
# 5. NEEDS_REVIEW survives to the page, and stays distinct from PASS
# ---------------------------------------------------------------------------


def test_needs_review_is_labelled_and_never_collapsed_into_pass(insecure_record, insecure_pdf):
    review = insecure_record.findings_with_status(Status.NEEDS_REVIEW)
    assert review, "fixture no longer produces a NEEDS_REVIEW result"

    text = extract(insecure_pdf)
    assert "NEEDS_REVIEW" in text

    finding = review[0]
    assert finding.title in text

    document = build_device_document(insecure_record)
    row = next(
        r
        for r in document.controls
        if r.title == finding.title and r.framework == finding.framework
    )
    assert row.status is Status.NEEDS_REVIEW
    assert row.status_label not in ("PASS", "FAIL")


def test_a_review_result_is_written_up_alongside_the_failures(insecure_record):
    document = build_device_document(insecure_record)

    statuses = {block.status for block in document.findings}
    assert Status.NEEDS_REVIEW in statuses
    assert Status.FAIL in statuses
    assert Status.PASS not in statuses, "a passing control is not a finding"

    block = next(b for b in document.findings if b.status is Status.NEEDS_REVIEW)
    assert block.status_full == "NEEDS_REVIEW"
    assert block.status_label != "PASS"


def test_review_and_fail_are_drawn_in_different_colours():
    """Visually distinct, not merely differently worded."""
    from auditor.report.pdf import _STATUS_INK

    assert len({_STATUS_INK[status] for status in Status}) == 3


def test_the_three_counts_are_reported_separately_from_any_score(hardened_record):
    """PASS / FAIL / REVIEW are shown as three numbers, and both scores are labelled.

    A single percentage would have to make a silent choice about what an
    undecided control is worth. The report declines to make it: the counts are
    primary, and the two scores are printed side by side precisely so the
    treatment of NEEDS_REVIEW is visible rather than assumed.
    """
    document = build_device_document(hardened_record)

    for row in document.summaries:
        stored = hardened_record.framework_summaries[row.framework]
        assert row.compliance_score == stored.compliance_score
        assert row.adjudicated_score == stored.adjudicated_score


def test_both_scores_are_labelled_so_the_review_treatment_is_visible(insecure_pdf):
    text = extract(insecure_pdf)

    assert "SCORE" in text and "ADJUDICATED" in text
    assert "NEEDS_REVIEW means" in text  # the footnote that defines the third verdict


# ---------------------------------------------------------------------------
# 6. remediation is the vendor's, not the framework's
# ---------------------------------------------------------------------------


def test_remediation_is_vendor_specific_and_differs_between_vendors(
    insecure_record, junos_record, tmp_path
):
    """Same control, two vendors, two different sets of commands.

    The framework says why; the vendor says how. A report that printed the same
    generic advice for a Catalyst and an SRX would be useless to whoever has to
    type it.
    """
    cisco = finding_for(insecure_record, "secure_vty_transport")
    junos = finding_for(junos_record, "secure_vty_transport")

    assert cisco.remediation_cli and junos.remediation_cli
    assert cisco.remediation_cli != junos.remediation_cli

    cisco_text = extract(write_device_pdf(insecure_record, tmp_path / "cisco.pdf"))
    junos_text = extract(write_device_pdf(junos_record, tmp_path / "junos.pdf"))

    assert "transport input ssh" in cisco_text
    assert "delete system services telnet" in junos_text
    # And neither device is handed the other's CLI.
    assert "delete system services telnet" not in cisco_text
    assert "transport input ssh" not in junos_text


def test_every_finding_that_can_be_fixed_carries_its_commands(insecure_record):
    document = build_device_document(insecure_record)

    assert document.findings
    for block in document.findings:
        assert block.remediation_summary, f"{block.rule_id} has no remediation summary"
        assert block.remediation_cli, f"{block.rule_id} has no CLI to type"


def test_a_passing_control_carries_no_remediation(hardened_record):
    """Nothing to fix, so nothing to paste."""
    document = build_device_document(hardened_record)

    assert document.findings == []
    assert all(result.remediation is None for result in hardened_record.findings)


# ---------------------------------------------------------------------------
# 7. evidence still points at the configuration line it came from
# ---------------------------------------------------------------------------


def test_evidence_line_numbers_reach_the_page(insecure_record, insecure_pdf):
    document = build_device_document(insecure_record)
    numbered = [
        line for block in document.findings for line in block.evidence if line.line_number is not None
    ]
    assert numbered, "no finding carried a line number"

    text = extract(insecure_pdf)
    assert any(f"L{line.line_number}:" in text for line in numbered)


def test_every_evidence_line_number_matches_the_stored_result(insecure_record):
    """The renderer copies the line number; it never renumbers or drops one."""
    document = build_device_document(insecure_record)

    stored = {
        (result.rule_id, item.field, item.line_number)
        for result in non_passing(insecure_record)
        for item in result.evidence
    }
    rendered = {
        (block.rule_id, line.field, line.line_number)
        for block in document.findings
        for line in block.evidence
    }
    assert rendered == stored


def test_a_cited_line_number_matches_the_actual_source_file(insecure_record):
    """Spot-check the citation against the file on disk, end to end."""
    lines = (SAMPLES / "insecure_ios.conf").read_text(encoding="utf-8").splitlines()
    document = build_device_document(insecure_record)

    checked = 0
    for block in document.findings:
        for item in block.evidence:
            if item.line_number is None or not item.text.startswith("L"):
                continue
            snippet = item.text.split(": ", 1)[1]
            assert lines[item.line_number - 1].strip() == snippet.strip()
            checked += 1
    assert checked, "no evidence line was checkable against the source"


# ---------------------------------------------------------------------------
# 8. the renderer evaluates nothing
# ---------------------------------------------------------------------------


def test_rendering_never_parses_or_evaluates(hardened_record, tmp_path, monkeypatch):
    """Mine every analysis entry point, then draw the report anyway.

    This is the Step 8 "parse once" discipline carried into Step 9. The record
    handed to the renderer is already the finished audit; if drawing it reached
    back into a parser or the rule engine, the PDF could disagree with the JSON
    report and the CLI table for the same device.
    """
    from auditor import pipeline
    from auditor.engine import ComplianceEngine
    from auditor.parsers import CiscoIOSParser, FortiosParser, JunosParser

    def landmine(name):
        def explode(*args, **kwargs):
            raise AssertionError(f"the PDF renderer called {name}")

        return explode

    for target, attribute in (
        (pipeline, "parse_config"),
        (pipeline, "evaluate"),
        (pipeline, "audit_baseline"),
        (pipeline, "select_parser"),
        (pipeline, "build_report"),
        (ComplianceEngine, "evaluate"),
        (CiscoIOSParser, "parse"),
        (JunosParser, "parse"),
        (FortiosParser, "parse"),
    ):
        monkeypatch.setattr(target, attribute, landmine(f"{target.__name__}.{attribute}"))

    path = write_device_pdf(hardened_record, tmp_path / "report.pdf")
    assert page_count(path) > 0


def test_rendering_loads_no_rule_pack(hardened_record, tmp_path, monkeypatch):
    """Framework metadata is already on the record; the renderer re-reads nothing."""
    from auditor import rules

    def explode(*args, **kwargs):
        raise AssertionError("the PDF renderer loaded a rule pack")

    monkeypatch.setattr(rules, "load_framework", explode)

    write_device_pdf(hardened_record, tmp_path / "report.pdf")


def test_rendering_mutates_nothing_on_the_record(hardened_record, tmp_path):
    before = hardened_record.model_dump(mode="json")
    write_device_pdf(hardened_record, tmp_path / "report.pdf")
    assert hardened_record.model_dump(mode="json") == before


def test_the_document_is_deterministic_for_one_record(hardened_record):
    """Two builds of one record produce identical content."""
    assert build_device_document(hardened_record) == build_device_document(hardened_record)


def test_two_renders_of_one_record_carry_the_same_text(hardened_record, tmp_path):
    """PDF bytes may carry a creation timestamp; the words on the page may not."""
    first = write_device_pdf(hardened_record, tmp_path / "a.pdf")
    second = write_device_pdf(hardened_record, tmp_path / "b.pdf")

    assert extract(first) == extract(second)


# ---------------------------------------------------------------------------
# 9. bulk: one PDF per device, including the devices that failed
# ---------------------------------------------------------------------------


def test_bulk_writes_one_pdf_per_device(fleet, tmp_path):
    inventory = ingest_paths([str(fleet)], ["cis", "nist_800_53"], now=FIXED_CLOCK)
    assert len(inventory.devices) == 5

    written = write_inventory_pdfs(inventory, tmp_path / "reports")

    assert len(written) == len(inventory.devices)
    assert len(list((tmp_path / "reports").glob("*.pdf"))) == len(inventory.devices)
    for _, path in written:
        assert page_count(path) > 0


def test_an_unauditable_device_still_gets_a_pdf_stating_why(fleet, tmp_path):
    """A file that failed to audit is itself a finding. It is never skipped."""
    inventory = ingest_paths([str(fleet)], ["cis"], now=FIXED_CLOCK)
    written = {
        record.source_file: path
        for record, path in write_inventory_pdfs(inventory, tmp_path / "out")
    }

    failed = [d for d in inventory.devices if d.status is not DeviceStatus.AUDITED]
    assert len(failed) == 2, "fixture should carry one unknown vendor and one unreadable file"
    assert {d.status for d in failed} == {DeviceStatus.UNKNOWN_VENDOR, DeviceStatus.PARSE_ERROR}

    for record in failed:
        text = extract(written[record.source_file])
        assert record.status.value in text
        assert record.error
        assert record.error.split(".")[0][:40] in text

        # The source is named on the page, so the failure is traceable to a file.
        source = build_device_document(record).section("Source and Provenance")
        assert record.source_file in [field.value for field in source.fields]


def test_bulk_filenames_are_deterministic_and_collision_safe(fleet, tmp_path):
    inventory = ingest_paths([str(fleet)], ["cis"], now=FIXED_CLOCK)

    names = pdf_filenames(inventory.devices)
    assert len(set(names)) == len(names), "two devices would overwrite each other"
    assert names == pdf_filenames(inventory.devices), "naming is not deterministic"

    for record, name in zip(inventory.devices, names):
        assert name.endswith(".pdf")
        assert record.identity.vendor in name
        if record.source_hash:
            assert record.source_hash[:8] in name


def test_a_named_device_uses_its_hostname_in_the_filename(fleet, tmp_path):
    inventory = ingest_paths([str(fleet)], ["cis"], now=FIXED_CLOCK)
    record = next(d for d in inventory.devices if d.identity.hostname.value)

    name = pdf_filenames([record])[0]
    assert name.startswith(record.identity.hostname.value.lower())


def test_two_snapshots_of_one_device_do_not_overwrite_each_other(tmp_path):
    """Same hostname, same vendor, different content: two files, both kept."""
    directory = tmp_path / "snapshots"
    directory.mkdir()
    original = (SAMPLES / "hardened_ios.conf").read_text(encoding="utf-8")
    (directory / "today.conf").write_text(original, encoding="utf-8")
    (directory / "yesterday.conf").write_text(original + "\n! drift\n", encoding="utf-8")

    inventory = ingest_paths([str(directory)], ["cis"], now=FIXED_CLOCK)
    assert len({d.identity.hostname.value for d in inventory.devices}) == 1

    written = write_inventory_pdfs(inventory, tmp_path / "out")
    assert len({path.name for _, path in written}) == 2
    assert len(list((tmp_path / "out").glob("*.pdf"))) == 2


def test_a_device_with_no_hostname_falls_back_to_its_filename(tmp_path):
    directory = tmp_path / "nameless"
    directory.mkdir()
    (directory / "mystery-box.conf").write_text("", encoding="utf-8")

    inventory = ingest_paths([str(directory)], ["cis"], now=FIXED_CLOCK)
    record = inventory.devices[0]
    assert record.identity.hostname.value is None

    assert pdf_filenames([record])[0].startswith("mystery-box_")


# ---------------------------------------------------------------------------
# 10. verified vs internal control references
# ---------------------------------------------------------------------------


def test_a_verified_reference_is_printed_as_the_framework_publishes_it(insecure_record):
    document = build_device_document(insecure_record)
    verified = [row for row in document.controls if row.verified]
    assert verified, "fixture no longer contains a verified reference"

    for row in verified:
        assert INTERNAL_MARK not in row.control_display
        assert row.control_display == row.control


def test_an_unverified_reference_is_shown_as_an_internal_mapping(junos_record, tmp_path):
    """Junos CIS clause numbers were never verified, so none is asserted."""
    document = build_device_document(junos_record)
    unverified = [row for row in document.controls if not row.verified]
    assert unverified, "fixture no longer contains an unverified reference"

    for row in unverified:
        assert row.control_display.endswith(INTERNAL_MARK)

    text = extract(write_device_pdf(junos_record, tmp_path / "junos.pdf"))
    assert "Internal semantic mapping" in text
    assert "not an official framework clause number" in text


def test_the_renderer_never_upgrades_an_unverified_ref(junos_record):
    """Every citation on the page traces back to the flag on the stored result."""
    document = build_device_document(junos_record)

    for row, result in zip(document.controls, junos_record.findings):
        expected = bool(result.verified_ref and result.control_ref)
        assert row.verified is expected
        if not expected:
            assert row.control_display.endswith(INTERNAL_MARK)
            assert row.control != result.control_ref or result.control_ref is None


def test_an_unverified_finding_says_so_in_full(junos_record):
    document = build_device_document(junos_record)
    blocks = [
        block
        for block, result in zip(document.findings, non_passing(junos_record))
        if not result.verified_ref
    ]
    assert blocks, "fixture no longer contains an unverified finding"

    for block in blocks:
        assert "internal semantic mapping" in block.control


def test_a_verified_finding_is_labelled_verified(insecure_record):
    document = build_device_document(insecure_record)
    blocks = [
        block
        for block, result in zip(document.findings, non_passing(insecure_record))
        if result.verified_ref and result.control_ref
    ]
    assert blocks, "fixture no longer contains a verified finding"

    for block in blocks:
        assert "verified reference" in block.control
        assert "internal semantic mapping" not in block.control


# ---------------------------------------------------------------------------
# CLI wiring
# ---------------------------------------------------------------------------


def test_cli_pdf_out_writes_one_file_with_every_framework(tmp_path, capsys):
    destination = tmp_path / "report.pdf"
    code = cli.run(
        [
            str(SAMPLES / "insecure_ios.conf"),
            "--framework", "cis",
            "--framework", "nist_800_53",
            "--framework", "stig",
            "--framework", "iso_27001",
            "--pdf-out", str(destination),
            "--no-json",
            "--quiet",
        ]
    )

    assert code == cli.EXIT_OK
    assert "PDF report written to" in capsys.readouterr().out
    assert list(tmp_path.glob("*.pdf")) == [destination]

    text = extract(destination)
    for framework in FRAMEWORK_NAMES:
        assert framework in text


def test_cli_pdf_dir_writes_one_pdf_per_device(fleet, tmp_path, capsys):
    out = tmp_path / "reports"
    code = cli.run(["--bulk", str(fleet), "--framework", "cis", "--pdf-dir", str(out), "--quiet"])

    assert code == cli.EXIT_OK
    assert "per-device PDF report(s) written to" in capsys.readouterr().out
    assert len(list(out.glob("*.pdf"))) == 5


def test_cli_default_output_is_untouched_without_a_pdf_flag(tmp_path, capsys):
    """No PDF flag, no PDF -- and the table still prints exactly as before."""
    code = cli.run([str(SAMPLES / "insecure_ios.conf"), "--framework", "cis", "--no-json"])
    out = capsys.readouterr().out

    assert code == cli.EXIT_OK
    assert "PDF" not in out
    assert "CIS" in out  # the table is still the default rendering
    assert not list(tmp_path.glob("*.pdf"))


def test_cli_rejects_pdf_out_with_bulk(fleet, capsys):
    code = cli.run(["--bulk", str(fleet), "--pdf-out", "one.pdf", "--quiet"])

    assert code == cli.EXIT_ERROR
    assert "--pdf-dir" in capsys.readouterr().err


def test_cli_rejects_pdf_dir_without_bulk(tmp_path, capsys):
    code = cli.run([str(SAMPLES / "insecure_ios.conf"), "--pdf-dir", str(tmp_path), "--quiet"])

    assert code == cli.EXIT_ERROR
    assert "--pdf-out" in capsys.readouterr().err


def test_cli_single_file_pdf_agrees_with_the_bulk_record(tmp_path):
    """The two paths render the same device, so they must render the same verdicts.

    The single-file run adapts its finished ``AuditReport`` into the same
    ``DeviceRecord`` bulk builds. If they diverged, one of the two outputs would
    be wrong and nothing would say which.
    """
    config = tmp_path / "insecure_ios.conf"
    config.write_text((SAMPLES / "insecure_ios.conf").read_text(encoding="utf-8"), encoding="utf-8")

    cli.run(
        [
            str(config),
            "--framework", "cis",
            "--pdf-out", str(tmp_path / "single.pdf"),
            "--no-json",
            "--quiet",
        ]
    )
    write_device_pdf(ingest_file(config, ["cis"], now=FIXED_CLOCK), tmp_path / "bulk.pdf")

    single = extract(tmp_path / "single.pdf")
    bulk = extract(tmp_path / "bulk.pdf")

    # The ingest timestamp differs by construction; the verdicts must not.
    assert single.count("FAIL") == bulk.count("FAIL")
    assert single.count("NEEDS_REVIEW") == bulk.count("NEEDS_REVIEW")
    assert single.count("PASS") == bulk.count("PASS")


# ---------------------------------------------------------------------------
# robustness
# ---------------------------------------------------------------------------


def test_markup_in_a_configuration_line_is_neutralised_not_dropped():
    """reportlab parses paragraphs as mini-HTML; a configuration is not HTML.

    An ACL remark containing ``<`` or ``&`` must reach the page as text, not
    vanish into a malformed tag or abort the document.
    """
    assert escape("permit ip 10.0.0.0 <any> & log") == "permit ip 10.0.0.0 &lt;any&gt; &amp; log"
    assert escape("banner ^C\x00\x07 warning") == "banner ^C warning"
    assert escape(None) == ""


def test_a_config_containing_markup_still_renders(tmp_path):
    source = (SAMPLES / "insecure_ios.conf").read_text(encoding="utf-8")
    config = tmp_path / "markup.conf"
    config.write_text(source.replace("hostname", "! <b>&</b> remark\nhostname", 1), encoding="utf-8")

    record = ingest_file(config, ["cis"], now=FIXED_CLOCK)
    assert page_count(write_device_pdf(record, tmp_path / "markup.pdf")) > 0


def test_a_missing_pdf_backend_is_an_instruction_not_a_traceback(hardened_record, tmp_path, monkeypatch):
    """The deterministic core stays installable without reportlab."""
    from auditor.report import PdfUnavailableError, pdf

    def no_reportlab():
        raise PdfUnavailableError(
            "The 'reportlab' package is required to write PDF reports. Install it with "
            "`pip install -r requirements-pdf.txt`."
        )

    monkeypatch.setattr(pdf, "_import_reportlab", no_reportlab)

    with pytest.raises(PdfUnavailableError, match="requirements-pdf.txt"):
        write_device_pdf(hardened_record, tmp_path / "report.pdf")
