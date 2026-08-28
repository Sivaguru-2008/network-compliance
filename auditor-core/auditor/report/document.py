"""What a per-device report says, separated from how it is drawn.

A PDF is a rendering, never a second analysis.  Everything below is assembled
from a finished ``DeviceRecord`` -- the verdicts, the summaries and the evidence
are copied, not recomputed, and nothing here reads the configuration file.  If
the PDF and the CLI table ever disagreed about a device, one of them would be
wrong; building both from the same finished record is what makes that
impossible.

Keeping the content model separate from the renderer buys two things:

* the honesty guarantees are testable without parsing a PDF -- "the serial
  prints as ``null``", "every evidence row keeps its line number", "a
  NEEDS_REVIEW is never drawn as a pass" are assertions about this structure;
* the web dashboard in the next step can render the same document without
  reimplementing the decisions about what belongs in a device report.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Tuple

from ..identity.companion import is_from_companion
from ..models.identity import DeviceIdentity
from ..models.inventory import DeviceRecord, DeviceStatus
from ..models.result import ControlResult, Evidence, ReportSummary, Status

#: Printed wherever a field was never established. The literal word, not a blank:
#: an empty cell reads as a formatting slip, and a reader deserves to see that
#: the tool looked and found nothing.
NULL = "null"

_STATUS_LABEL = {Status.PASS: "PASS", Status.FAIL: "FAIL", Status.NEEDS_REVIEW: "REVIEW"}


@dataclass(frozen=True)
class Field_:
    """One labelled value, with the evidence behind it."""

    label: str
    value: str
    evidence: str = ""
    #: True when the value was established from the file. False means the value
    #: is ``NULL`` and ``evidence`` explains why -- never that it is secure.
    detected: bool = True


@dataclass
class Section:
    """A titled block of labelled values."""

    title: str
    fields: List[Field_] = field(default_factory=list)
    note: Optional[str] = None
    #: Column widths in millimetres (label, value, evidence). A hash or a long
    #: path needs a wider value column than a hostname does, and wrapping a
    #: SHA-256 into three ragged fragments makes it useless for comparison.
    widths: Tuple[float, float, float] = (32.0, 48.0, 97.0)


@dataclass
class SummaryRow:
    """One framework's tally for this device."""

    framework: str
    passed: int
    failed: int
    needs_review: int
    total: int
    compliance_score: float
    adjudicated_score: float


#: Appended to a citation the tool could not verify against an authoritative
#: copy of the framework. ASCII so it survives any font, and explained by a
#: legend beside every table that can print it -- an unexplained mark is only
#: marginally better than no mark.
INTERNAL_MARK = "*"

INTERNAL_LEGEND = (
    f"{INTERNAL_MARK} Internal semantic mapping, not an official framework clause number. "
    "The control intent is the framework's; the identifier is this tool's, because the "
    "clause could not be verified against a licensed copy of the benchmark."
)


@dataclass
class ControlRow:
    """One control, as it appears in the results table."""

    framework: str
    control: str
    severity: str
    status: Status
    title: str
    evidence: str
    #: False when the citation is this tool's own mapping rather than a clause
    #: number verified against the published framework.
    verified: bool = True

    @property
    def status_label(self) -> str:
        return _STATUS_LABEL[self.status]

    @property
    def control_display(self) -> str:
        """The citation, marked when it is not an official one.

        An unverified reference is never printed bare: side by side with a real
        ``AC-17`` in the same column, an unmarked internal id reads as though the
        framework published it. The mark is the whole point of carrying
        ``verified_ref`` through the pipeline.
        """
        return self.control if self.verified else f"{self.control} {INTERNAL_MARK}"


@dataclass
class EvidenceLine:
    """One piece of evidence, with the line number it came from preserved."""

    field: str
    text: str
    line_number: Optional[int]
    note: Optional[str] = None
    origin: str = "deterministic"


@dataclass
class FindingBlock:
    """A non-passing control, in full, with what to do about it."""

    rule_id: str
    title: str
    framework: str
    control: str
    severity: str
    status: Status
    description: str
    message: str
    evidence: List[EvidenceLine] = field(default_factory=list)
    remediation_summary: Optional[str] = None
    remediation_cli: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    @property
    def status_label(self) -> str:
        return _STATUS_LABEL[self.status]

    @property
    def status_full(self) -> str:
        """``NEEDS_REVIEW`` spelled out, not shortened to ``REVIEW``.

        The narrow results table has to abbreviate; a finding heading does not,
        and this is the one verdict whose meaning a reader must not have to
        infer. It is the value the JSON report carries, verbatim.
        """
        return self.status.value


@dataclass
class ReportDocument:
    """One device, ready to draw."""

    title: str
    subtitle: str
    generated_at: datetime
    tool: str
    status: DeviceStatus
    error: Optional[str] = None
    sections: List[Section] = field(default_factory=list)
    summaries: List[SummaryRow] = field(default_factory=list)
    controls: List[ControlRow] = field(default_factory=list)
    findings: List[FindingBlock] = field(default_factory=list)
    footnotes: List[str] = field(default_factory=list)

    def section(self, title: str) -> Optional[Section]:
        return next((item for item in self.sections if item.title == title), None)


# ---------------------------------------------------------------------------
# assembly
# ---------------------------------------------------------------------------


def build_device_document(
    record: DeviceRecord,
    *,
    tool: str = "netaudit",
    version: str = "",
) -> ReportDocument:
    """Assemble the per-device report from a finished record.

    Copies verdicts and evidence; computes nothing. The record has already been
    through the parser and the rule engine, and re-deciding anything here would
    make the PDF a second opinion rather than a rendering of the first.
    """
    identity = record.identity
    document = ReportDocument(
        title=identity.hostname.value or "(hostname not found)",
        subtitle=_subtitle(record),
        generated_at=record.ingested_at,
        tool=f"{tool} {version}".strip(),
        status=record.status,
        error=record.error,
    )

    document.sections.append(_identity_section(identity))
    document.sections.append(_source_section(record))

    document.summaries = [
        SummaryRow(
            framework=name,
            passed=summary.passed,
            failed=summary.failed,
            needs_review=summary.needs_review,
            total=summary.total,
            compliance_score=summary.compliance_score,
            adjudicated_score=summary.adjudicated_score,
        )
        for name, summary in record.framework_summaries.items()
    ]
    document.controls = [_control_row(result) for result in record.findings]
    document.findings = [
        _finding_block(result) for result in record.findings if result.status is not Status.PASS
    ]
    document.footnotes = _footnotes(record)
    return document


def _subtitle(record: DeviceRecord) -> str:
    identity = record.identity
    parts = [identity.vendor]
    version = identity.field_value("os_version")
    if version:
        parts.append(version)
    model = identity.field_value("model")
    if model:
        parts.append(model)
    return "  ·  ".join(parts)


def _identity_section(identity: DeviceIdentity) -> Section:
    """Device identification, including the hardware facts that are absent.

    The absent ones are the point. A report that simply omitted the serial would
    leave a reader to assume it was not collected, or worse that it was; this
    prints ``null`` and the reason, so the gap is a stated finding rather than a
    silence.
    """
    return Section(
        title="Device Identification",
        fields=[
            _observation_field("Hostname", identity.hostname),
            Field_(label="Vendor", value=identity.vendor, evidence="detected by parser selection"),
            Field_(label="OS family", value=identity.os_family, evidence="declared by the parser"),
            _observation_field("OS version", identity.os_version),
            _observation_field("Model", identity.model),
            _observation_field("Serial number", identity.serial_number),
        ],
        note=(
            "A configuration file does not carry the hardware serial number. Fields shown as "
            f"{NULL} were not present in the ingested file and were not inferred; the evidence "
            "column names the show command that would establish them."
        ),
    )


def _observation_field(label: str, observation) -> Field_:
    """An identity field, printed as found or printed as ``null`` with its reason."""
    if observation.detected and observation.value is not None:
        return Field_(
            label=label,
            value=str(observation.value),
            evidence=_identity_evidence(observation),
            detected=True,
        )
    return Field_(
        label=label,
        value=NULL,
        evidence=observation.note or "not present in the ingested file",
        detected=False,
    )


def _identity_evidence(observation) -> str:
    """Cite the evidence, and say which file the cited line is in.

    A bare ``L24:`` beside a serial number reads as line 24 of the running
    config -- precisely the claim this tool must never make, since a running
    config carries no serial on any line. Where the value came from a companion
    capture, the capture is named instead of a bare line number.
    """
    if not observation.source_line:
        return observation.note or ""
    if is_from_companion(observation):
        # The note already names the companion file and the line within it.
        return f"{observation.source_line}  ({observation.note})"
    prefix = f"L{observation.line_number}: " if observation.line_number else ""
    suffix = f"  ({observation.note})" if observation.note else ""
    return f"{prefix}{observation.source_line}{suffix}"


def _source_section(record: DeviceRecord) -> Section:
    """How the file was read -- the audit trail for the report itself."""
    fields = [
        Field_(label="Source file", value=record.source_file, evidence=""),
        Field_(label="SHA-256", value=record.source_hash or NULL, evidence="of the ingested bytes"),
        Field_(label="Ingested", value=record.ingested_at.strftime("%Y-%m-%d %H:%M:%S UTC"), evidence=""),
        Field_(label="Status", value=record.status.value, evidence=record.error or ""),
    ]
    target = record.target
    if target is not None:
        fields.extend(
            [
                Field_(
                    label="Parser",
                    value=f"{target.parser} v{target.parser_version}",
                    evidence=f"detection confidence {target.detection_confidence:.2f}",
                ),
                Field_(label="Config lines", value=str(target.config_line_count), evidence=""),
            ]
        )
        
        # Calculate AI / Training Mappings provenance
        ai_confirmed = 0
        admin_trained = 0
        for fnd in record.findings:
            for ev in fnd.evidence:
                origin_str = str(ev.origin.value if hasattr(ev.origin, "value") else ev.origin).lower()
                if "learned" in origin_str or ev.mapping_id:
                    admin_trained += 1
                elif "llm" in origin_str or "hybrid" in origin_str:
                    ai_confirmed += 1
                    
        if ai_confirmed > 0 or admin_trained > 0:
            fields.append(
                Field_(
                    label="AI Interpretation",
                    value=f"{ai_confirmed} AI-confirmed; {admin_trained} administrator-trained",
                    evidence="Dynamic baseline mappings resolved during audit"
                )
            )

        if target.parser_warnings:
            fields.append(
                Field_(
                    label="Parser notes",
                    value=f"{len(target.parser_warnings)} warning(s)",
                    evidence="; ".join(target.parser_warnings),
                )
            )
    if record.companion_file:
        fields.append(
            Field_(
                label="Companion",
                value=record.companion_file,
                evidence="show output supplied alongside the configuration",
            )
        )
    return Section(title="Source and Provenance", fields=fields, widths=(30.0, 82.0, 65.0))


def _control_row(result: ControlResult) -> ControlRow:
    """One results-table row, citing what was actually established.

    A verified clause number is printed as the framework publishes it. Anything
    else falls back to the internal semantic id and is flagged, including the
    case where a ``control_ref`` exists but was never verified -- that ref is
    the most dangerous one to print bare, because it looks official.
    """
    evidence = result.primary_evidence
    verified = bool(result.verified_ref and result.control_ref)
    if verified:
        control = result.control_ref
    else:
        control = result.internal_control_id or result.control_ref or result.rule_id
    return ControlRow(
        framework=result.framework,
        control=control,
        severity=result.severity.value,
        status=result.status,
        title=result.title,
        evidence=evidence.display if evidence else "(no evidence recorded)",
        verified=verified,
    )


def _finding_block(result: ControlResult) -> FindingBlock:
    return FindingBlock(
        rule_id=result.rule_id,
        title=result.title,
        framework=result.framework,
        control=_control_reference(result),
        severity=result.severity.value,
        status=result.status,
        description=result.description,
        message=result.message,
        evidence=[_evidence_line(item) for item in result.evidence],
        remediation_summary=result.remediation.summary if result.remediation else None,
        remediation_cli=list(result.remediation.cli) if result.remediation else [],
        references=list(result.references),
    )


def _control_reference(result: ControlResult) -> str:
    """Say plainly whether a citation was verified or is an internal mapping."""
    if result.control_ref and result.verified_ref:
        return f"{result.control_ref} (verified reference)"
    if result.internal_control_id:
        return f"{result.internal_control_id} (internal semantic mapping)"
    if result.control_ref:
        return f"{result.control_ref} (internal semantic mapping)"
    return "none (internal semantic mapping)"


def _evidence_line(item: Evidence) -> EvidenceLine:
    return EvidenceLine(
        field=item.field,
        text=item.display,
        line_number=item.line_number,
        note=item.note,
        origin=item.origin.value,
    )


def _footnotes(record: DeviceRecord) -> List[str]:
    """The caveats a reader needs in order not to over-read this report."""
    notes = [
        "NEEDS_REVIEW means the configuration carried no conclusive evidence either way. "
        "It is not a pass, and it is not a failure: it is an escalation to a human.",
        "Every line number cited above refers to the ingested configuration file identified "
        "under Source and Provenance.",
    ]
    if any(row.needs_review for row in record.framework_summaries.values()):
        undecided = sum(row.needs_review for row in record.framework_summaries.values())
        notes.append(
            f"{undecided} control result(s) on this device could not be decided from the "
            "configuration and require review."
        )
    if record.identity.field_value("serial_number") is None:
        notes.append(
            "No hardware serial number was available for this device. Supply the output of the "
            "vendor's show-version command alongside the configuration to record one."
        )
    non_deterministic = sorted(
        {
            item.origin.value
            for result in record.findings
            for item in result.evidence
            if item.origin.value != "deterministic"
        }
    )
    if non_deterministic:
        notes.append(
            "Some evidence on this device was produced by a non-deterministic source "
            f"({', '.join(non_deterministic)}); those rows are marked in the findings."
        )
    return notes


def summary_totals(document: ReportDocument) -> Tuple[int, int, int]:
    """PASS / FAIL / REVIEW across every framework on this device."""
    return (
        sum(row.passed for row in document.summaries),
        sum(row.failed for row in document.summaries),
        sum(row.needs_review for row in document.summaries),
    )


def summary_for(record: DeviceRecord, framework: str) -> Optional[ReportSummary]:
    return record.framework_summaries.get(framework)
