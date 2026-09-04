"""Per-device PDF rendering.

Draws a ``ReportDocument`` and nothing else: every verdict, tally and evidence
line on the page was decided by the rule engine and copied by
``document.build_device_document``.  This module makes no judgements, which is
why it can be swapped for an HTML or DOCX renderer without a compliance review.

``reportlab`` is imported lazily, exactly as the ``anthropic`` SDK is in the LLM
parser: the deterministic core stays installable with nothing but the config
parser and pydantic, and a machine that has never installed reportlab still runs
the whole test suite and every other command.  Asking for a PDF without it
produces a clear instruction, not a traceback.
"""

import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models.identity import UNKNOWN_VENDOR
from ..models.inventory import DeviceRecord, DeviceStatus
from ..models.result import Status
from .document import (
    INTERNAL_LEGEND,
    NULL,
    ReportDocument,
    build_device_document,
    summary_totals,
)


class PdfUnavailableError(Exception):
    """The PDF backend is not installed."""


# -- palette: the CLI table's status colours, in print ------------------------
_INK = "#1a1a1a"
_MUTED = "#6b6b6b"
_RULE = "#c8c8c8"
_BAND = "#f2f2f2"
_STATUS_INK = {
    Status.PASS: "#1a7f37",
    Status.FAIL: "#b42318",
    Status.NEEDS_REVIEW: "#a15c00",
    Status.NOT_APPLICABLE: "#6b6b6b",
    Status.UNSUPPORTED: "#7b5ea7",
    Status.ERROR: "#b42318",
    Status.MANUAL_REVIEW: "#a15c00",
}
_SEVERITY_INK = {"high": "#b42318", "medium": "#a15c00", "low": "#2c5aa0"}
_DEVICE_STATUS_INK = {
    DeviceStatus.AUDITED: "#1a7f37",
    DeviceStatus.UNKNOWN_VENDOR: "#a15c00",
    DeviceStatus.PARSE_ERROR: "#b42318",
}


def _import_reportlab():
    try:
        from reportlab.lib import colors  # noqa: PLC0415 - deliberately lazy
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            HRFlowable,
            KeepTogether,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise PdfUnavailableError(
            "The 'reportlab' package is required to write PDF reports. Install it with "
            "`pip install -r requirements-pdf.txt`, or use the table and JSON output, "
            "which need no extra dependencies."
        ) from exc
    return {
        "colors": colors,
        "TA_LEFT": TA_LEFT,
        "A4": A4,
        "ParagraphStyle": ParagraphStyle,
        "getSampleStyleSheet": getSampleStyleSheet,
        "mm": mm,
        "HRFlowable": HRFlowable,
        "KeepTogether": KeepTogether,
        "PageBreak": PageBreak,
        "Paragraph": Paragraph,
        "SimpleDocTemplate": SimpleDocTemplate,
        "Spacer": Spacer,
        "Table": Table,
        "TableStyle": TableStyle,
    }


def pdf_available() -> bool:
    """Whether a PDF can be written on this machine."""
    try:
        _import_reportlab()
    except PdfUnavailableError:
        return False
    return True


# ---------------------------------------------------------------------------
# text safety
# ---------------------------------------------------------------------------

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def escape(text: Any) -> str:
    """Make arbitrary configuration text safe to draw.

    Two hazards, both routine in real configs. reportlab paragraphs are parsed
    as mini-HTML, so an ACL line containing ``<`` or ``&`` would either vanish or
    abort the render; and control bytes from a truncated or binary paste have no
    glyph. Both are neutralised here rather than by sanitising the evidence
    upstream -- the evidence must stay byte-faithful to the file it came from.
    """
    if text is None:
        return ""
    text = _CONTROL_CHARS.sub("", str(text))
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _styles(rl: Dict[str, Any]) -> Dict[str, Any]:
    base = rl["getSampleStyleSheet"]()
    make = rl["ParagraphStyle"]
    return {
        "title": make("t", parent=base["Title"], fontSize=20, leading=24, textColor=_INK, alignment=rl["TA_LEFT"]),
        "subtitle": make("st", parent=base["Normal"], fontSize=10.5, leading=14, textColor=_MUTED),
        "h2": make("h2", parent=base["Heading2"], fontSize=12.5, leading=16, spaceBefore=14, spaceAfter=6, textColor=_INK),
        "h3": make("h3", parent=base["Heading3"], fontSize=10.5, leading=13, spaceBefore=8, spaceAfter=3, textColor=_INK),
        "body": make("b", parent=base["Normal"], fontSize=9, leading=12, textColor=_INK),
        "small": make("s", parent=base["Normal"], fontSize=7.6, leading=10, textColor=_MUTED),
        "cell": make("c", parent=base["Normal"], fontSize=8, leading=10.5, textColor=_INK),
        "mono": make("m", parent=base["Normal"], fontName="Courier", fontSize=7.6, leading=10, textColor=_INK),
        "null": make("n", parent=base["Normal"], fontSize=9, leading=12, fontName="Helvetica-Oblique", textColor=_MUTED),
    }


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------


def render_document(document: ReportDocument, path: Path) -> Path:
    """Draw one device report to ``path``."""
    rl = _import_reportlab()
    styles = _styles(rl)
    path = Path(path)
    if str(path.parent):
        path.parent.mkdir(parents=True, exist_ok=True)

    template = rl["SimpleDocTemplate"](
        str(path),
        pagesize=rl["A4"],
        leftMargin=16 * rl["mm"],
        rightMargin=16 * rl["mm"],
        topMargin=16 * rl["mm"],
        bottomMargin=18 * rl["mm"],
        title=f"Compliance report - {document.title}",
        author=document.tool,
        subject="Network device security compliance",
    )

    story: List[Any] = []
    story.extend(_header(document, rl, styles))
    story.extend(_summary(document, rl, styles))
    for section in document.sections:
        story.extend(_section(section, rl, styles))
    story.extend(_controls(document, rl, styles))
    story.extend(_findings(document, rl, styles))
    story.extend(_footnotes(document, rl, styles))

    template.build(story, onLaterPages=_stamp(document, rl), onFirstPage=_stamp(document, rl))
    return path


def _header(document: ReportDocument, rl, styles) -> List[Any]:
    passed, failed, review = summary_totals(document)
    out = [
        rl["Paragraph"](escape(document.title), styles["title"]),
        rl["Paragraph"](escape(document.subtitle), styles["subtitle"]),
        rl["Spacer"](1, 5),
        rl["HRFlowable"](width="100%", thickness=1, color=_RULE, spaceAfter=8),
    ]
    if document.status is not DeviceStatus.AUDITED:
        out.append(
            rl["Paragraph"](
                f'<font color="{_DEVICE_STATUS_INK[document.status]}"><b>{escape(document.status.value)}</b></font>'
                f" — {escape(document.error or 'this device was not audited')}",
                styles["body"],
            )
        )
        out.append(rl["Spacer"](1, 6))
        return out

    out.append(_verdict_bar(passed, failed, review, rl, styles))
    total = passed + failed + review
    frameworks = len({row.framework for row in document.summaries})
    if frameworks:
        out.append(rl["Spacer"](1, 4))
        out.append(
            rl["Paragraph"](
                f"{total} control result(s) across {frameworks} framework(s). "
                "A control evaluated under two frameworks is counted once per framework.",
                styles["small"],
            )
        )
    return out


def _verdict_bar(passed: int, failed: int, review: int, rl, styles) -> Any:
    """One row of counts, coloured the way the CLI colours them."""

    def cell(label: str, count: int, status: Status) -> Any:
        return rl["Paragraph"](
            f'<font color="{_STATUS_INK[status]}" size="15"><b>{count}</b></font><br/>'
            f'<font color="{_MUTED}" size="7.5">{label}</font>',
            styles["cell"],
        )

    table = rl["Table"](
        [[cell("PASSED", passed, Status.PASS), cell("FAILED", failed, Status.FAIL), cell("NEEDS REVIEW", review, Status.NEEDS_REVIEW)]],
        colWidths=[59 * rl["mm"]] * 3,
    )
    table.setStyle(
        rl["TableStyle"](
            [
                ("BACKGROUND", (0, 0), (-1, -1), rl["colors"].HexColor(_BAND)),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 7),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                ("LINEAFTER", (0, 0), (-2, -1), 0.5, rl["colors"].HexColor(_RULE)),
            ]
        )
    )
    return table


def _summary(document: ReportDocument, rl, styles) -> List[Any]:
    if not document.summaries:
        return []
    header = ["FRAMEWORK", "PASS", "FAIL", "REVIEW", "TOTAL", "SCORE", "ADJUDICATED"]
    rows = [[rl["Paragraph"](f"<b>{escape(col)}</b>", styles["small"]) for col in header]]
    for row in document.summaries:
        rows.append(
            [
                rl["Paragraph"](escape(row.framework), styles["cell"]),
                _count(row.passed, Status.PASS, rl, styles),
                _count(row.failed, Status.FAIL, rl, styles),
                _count(row.needs_review, Status.NEEDS_REVIEW, rl, styles),
                rl["Paragraph"](str(row.total), styles["cell"]),
                rl["Paragraph"](f"{row.compliance_score:.1f}%", styles["cell"]),
                rl["Paragraph"](f"{row.adjudicated_score:.1f}%", styles["cell"]),
            ]
        )
    widths = [52, 16, 16, 20, 18, 20, 36]
    table = rl["Table"](rows, colWidths=[w * rl["mm"] for w in widths], repeatRows=1)
    table.setStyle(_grid(rl))
    return [rl["Paragraph"]("Compliance Summary", styles["h2"]), table]


def _count(value: int, status: Status, rl, styles) -> Any:
    return rl["Paragraph"](f'<font color="{_STATUS_INK[status]}"><b>{value}</b></font>', styles["cell"])


def _section(section, rl, styles) -> List[Any]:
    rows = []
    for item in section.fields:
        value_style = styles["body"] if item.detected else styles["null"]
        rows.append(
            [
                rl["Paragraph"](f"<b>{escape(item.label)}</b>", styles["cell"]),
                rl["Paragraph"](escape(item.value), value_style),
                rl["Paragraph"](escape(item.evidence), styles["small"]),
            ]
        )
    table = rl["Table"](rows, colWidths=[w * rl["mm"] for w in section.widths])
    table.setStyle(_grid(rl, header=False))

    out = [rl["Paragraph"](escape(section.title), styles["h2"]), table]
    if section.note:
        out.append(rl["Spacer"](1, 4))
        out.append(rl["Paragraph"](escape(section.note), styles["small"]))
    return out


def _controls(document: ReportDocument, rl, styles) -> List[Any]:
    if not document.controls:
        return []
    header = ["FRAMEWORK", "CONTROL", "SEV", "RESULT", "TITLE", "EVIDENCE"]
    rows = [[rl["Paragraph"](f"<b>{escape(col)}</b>", styles["small"]) for col in header]]
    for row in document.controls:
        rows.append(
            [
                rl["Paragraph"](escape(row.framework), styles["cell"]),
                rl["Paragraph"](escape(row.control_display), styles["cell"]),
                rl["Paragraph"](
                    f'<font color="{_SEVERITY_INK.get(row.severity, _INK)}">{escape(row.severity)}</font>',
                    styles["cell"],
                ),
                rl["Paragraph"](
                    f'<font color="{_STATUS_INK[row.status]}"><b>{row.status_label}</b></font>',
                    styles["cell"],
                ),
                rl["Paragraph"](escape(row.title), styles["cell"]),
                rl["Paragraph"](escape(row.evidence), styles["mono"]),
            ]
        )
    # "medium" must fit the severity column on one line: a verdict broken across
    # two rows as "mediu / m" is the kind of detail that costs a reader's trust
    # in everything else on the page.
    widths = [24, 26, 16, 17, 39, 55]
    table = rl["Table"](rows, colWidths=[w * rl["mm"] for w in widths], repeatRows=1)
    table.setStyle(_grid(rl))

    out = [rl["Paragraph"]("Control Results", styles["h2"]), table]
    if any(not row.verified for row in document.controls):
        out.append(rl["Spacer"](1, 4))
        out.append(rl["Paragraph"](escape(INTERNAL_LEGEND), styles["small"]))
    return out


def _findings(document: ReportDocument, rl, styles) -> List[Any]:
    if not document.findings:
        if document.status is DeviceStatus.AUDITED:
            return [
                rl["Paragraph"]("Findings", styles["h2"]),
                rl["Paragraph"](
                    "No findings: every evaluated control passed on this device.", styles["body"]
                ),
            ]
        return []

    out = [rl["PageBreak"](), rl["Paragraph"]("Detailed Findings", styles["h2"])]
    for finding in document.findings:
        block: List[Any] = [
            rl["Paragraph"](
                f'<font color="{_STATUS_INK[finding.status]}"><b>{finding.status_full}</b></font>'
                f'&nbsp;&nbsp;<font color="{_SEVERITY_INK.get(finding.severity, _INK)}">'
                f"[{escape(finding.severity.upper())}]</font>&nbsp;&nbsp;{escape(finding.rule_id)}"
                f" — {escape(finding.title)}",
                styles["h3"],
            ),
            rl["Paragraph"](
                f"<b>Framework:</b> {escape(finding.framework)} &nbsp;·&nbsp; "
                f"<b>Control:</b> {escape(finding.control)}",
                styles["small"],
            ),
            rl["Spacer"](1, 3),
            rl["Paragraph"](escape(finding.description), styles["body"]),
            rl["Spacer"](1, 2),
            rl["Paragraph"](f"<b>Why:</b> {escape(finding.message)}", styles["body"]),
            rl["Spacer"](1, 4),
        ]

        evidence_rows = []
        for item in finding.evidence:
            marker = "" if item.origin == "deterministic" else f"[{escape(item.origin)}] "
            evidence_rows.append(
                [
                    rl["Paragraph"](escape(item.field), styles["small"]),
                    rl["Paragraph"](marker + escape(item.text), styles["mono"]),
                ]
            )
        if evidence_rows:
            evidence = rl["Table"](evidence_rows, colWidths=[42 * rl["mm"], 135 * rl["mm"]])
            evidence.setStyle(_grid(rl, header=False))
            block.append(rl["Paragraph"]("<b>Evidence</b>", styles["small"]))
            block.append(evidence)

        if finding.remediation_summary:
            block.append(rl["Spacer"](1, 4))
            block.append(
                rl["Paragraph"](f"<b>Remediation:</b> {escape(finding.remediation_summary)}", styles["body"])
            )
            for command in finding.remediation_cli:
                block.append(rl["Paragraph"](escape(command), styles["mono"]))

        block.append(rl["Spacer"](1, 9))
        out.append(rl["KeepTogether"](block))
    return out


def _footnotes(document: ReportDocument, rl, styles) -> List[Any]:
    if not document.footnotes:
        return []
    out = [
        rl["Spacer"](1, 6),
        rl["HRFlowable"](width="100%", thickness=0.5, color=_RULE, spaceAfter=6),
        rl["Paragraph"]("Notes", styles["h3"]),
    ]
    for note in document.footnotes:
        out.append(rl["Paragraph"](f"• {escape(note)}", styles["small"]))
    return out


def _grid(rl, *, header: bool = True):
    style = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, rl["colors"].HexColor(_RULE)),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    if header:
        style.append(("BACKGROUND", (0, 0), (-1, 0), rl["colors"].HexColor(_BAND)))
    else:
        style.append(("BACKGROUND", (0, 0), (0, -1), rl["colors"].HexColor(_BAND)))
    return rl["TableStyle"](style)


def _stamp(document: ReportDocument, rl):
    """Footer on every page: what made this, from what, and when."""
    generated = document.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    # ASCII only: this is drawn straight onto the canvas, so it must not depend
    # on the base font carrying any particular punctuation glyph.
    label = f"{document.tool}  |  {document.title}  |  generated {generated}"

    def draw(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(rl["colors"].HexColor(_MUTED))
        canvas.drawString(16 * rl["mm"], 11 * rl["mm"], label[:120])
        canvas.drawRightString(
            doc.pagesize[0] - 16 * rl["mm"], 11 * rl["mm"], f"page {canvas.getPageNumber()}"
        )
        canvas.restoreState()

    return draw


# ---------------------------------------------------------------------------
# entry points
# ---------------------------------------------------------------------------


def write_device_pdf(
    record: DeviceRecord,
    path: Path,
    *,
    tool: str = "netaudit",
    version: str = "",
) -> Path:
    """Write the per-device PDF for one record."""
    return render_document(build_device_document(record, tool=tool, version=version), Path(path))


def write_inventory_pdfs(
    inventory,
    directory: Path,
    *,
    tool: str = "netaudit",
    version: str = "",
) -> List[Tuple[DeviceRecord, Path]]:
    """One PDF per device in an inventory, into ``directory``.

    Every device gets a file, including the ones that could not be audited: a
    fleet report where the failures are simply missing looks complete when it is
    not.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    written = []
    for record, name in zip(inventory.devices, pdf_filenames(inventory.devices)):
        written.append((record, write_device_pdf(record, directory / name, tool=tool, version=version)))
    return written


_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")

#: Characters of the source SHA-256 carried into the filename. Eight is enough
#: to separate any realistic fleet while leaving the name readable; the full
#: hash is printed inside the report, which is where an exact comparison belongs.
SHORT_HASH = 8


def pdf_filenames(devices) -> List[str]:
    """Stable, collision-free filenames -- one per device, in inventory order.

    ``{hostname}_{vendor}_{shorthash}.pdf``, and every part earns its place. The
    hostname makes the file findable by a human. The vendor separates two boxes
    that a site naming convention gave the same name. The content hash separates
    two *snapshots* of one device, which share hostname and vendor by definition
    -- without it, last night's config would overwrite this morning's audit and a
    fleet of N would quietly produce fewer than N reports.

    Derived only from the record, so the same inventory always yields the same
    names in the same order; nothing here depends on the run.
    """
    bases = [_base_name(record) for record in devices]
    clashing = {name for name in bases if bases.count(name) > 1}

    names = []
    for record, base in zip(devices, bases):
        if base in clashing:
            # Byte-identical files ingested from two paths: same hostname, same
            # vendor, same content hash. The path is the only thing left that
            # differs, so it settles it -- hashed, because a path is not a
            # filename-safe string.
            base = f"{base}_{_digest(record.source_file)}"
        names.append(f"{base}.pdf")
    return names


def _base_name(record: DeviceRecord) -> str:
    """``hostname_vendor_shorthash``, with every component honestly sourced.

    A device whose configuration never named itself falls back to the source
    filename -- the one label that is certainly true of it -- rather than to an
    invented or numbered hostname.
    """
    hostname = record.identity.field_value("hostname") or Path(record.source_file).stem
    vendor = record.identity.vendor or UNKNOWN_VENDOR
    short = (record.source_hash or "")[:SHORT_HASH] or _digest(record.source_file)
    return "_".join((_slug(hostname) or "device", _slug(vendor) or UNKNOWN_VENDOR, short))


def _slug(raw: str) -> str:
    return _UNSAFE.sub("-", raw or "").strip("-.").lower()


def _digest(raw: str) -> str:
    """A filename-safe short hash of an arbitrary string, stable across runs."""
    return hashlib.sha256((raw or "").encode("utf-8")).hexdigest()[:SHORT_HASH]


__all__ = [
    "NULL",
    "PdfUnavailableError",
    "escape",
    "pdf_available",
    "pdf_filenames",
    "render_document",
    "write_device_pdf",
    "write_inventory_pdfs",
]
