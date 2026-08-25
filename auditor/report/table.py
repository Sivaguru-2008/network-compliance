"""Human-readable CLI rendering of an AuditReport.

Deliberately dependency-free: the table is drawn here rather than pulled in
from a formatting library, so the tool runs on a locked-down jump host with
nothing but the parser and pydantic installed.  Colour is opt-out and is
suppressed automatically when stdout is not a TTY, so piping to a file or to
CI produces clean text.
"""

import os
import sys
import textwrap
from typing import List, Optional, Sequence

from ..models.observation import Origin
from ..models.result import AuditReport, ControlResult, Evidence, Status
from ..models.rule import Severity

_RESET = "\033[0m"
_COLORS = {
    Status.PASS: "\033[32m",           # green
    Status.FAIL: "\033[31m",           # red
    Status.NEEDS_REVIEW: "\033[33m",   # yellow
    Status.UNSUPPORTED: "\033[35m",    # magenta
    Status.MANUAL_REVIEW: "\033[34m",  # blue
    Status.NOT_APPLICABLE: "\033[37m", # light grey
}
_SEVERITY_COLORS = {
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_STATUS_MARK = {
    Status.PASS: "PASS",
    Status.FAIL: "FAIL",
    Status.NEEDS_REVIEW: "REVIEW",
    Status.UNSUPPORTED: "UNSUPPORT",
    Status.MANUAL_REVIEW: "MANUAL",
    Status.NOT_APPLICABLE: "N/A",
}


def supports_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


class _Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, color: Optional[str]) -> str:
        if not self.enabled or not color:
            return text
        return f"{color}{text}{_RESET}"


def _truncate(text: str, width: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= width else text[: width - 1] + "…"


def _render_table(headers: Sequence[str], rows: Sequence[Sequence[str]], widths: Sequence[int]) -> List[str]:
    """Render a box-drawn table. ``rows`` may contain colour codes; ``widths`` are visible widths."""
    top = "┌" + "┬".join("─" * (w + 2) for w in widths) + "┐"
    sep = "├" + "┼".join("─" * (w + 2) for w in widths) + "┤"
    bottom = "└" + "┴".join("─" * (w + 2) for w in widths) + "┘"

    lines = [top, "│ " + " │ ".join(h.ljust(w) for h, w in zip(headers, widths)) + " │", sep]
    for row in rows:
        cells = []
        for cell, width in zip(row, widths):
            visible = _visible_len(cell)
            cells.append(cell + " " * max(0, width - visible))
        lines.append("│ " + " │ ".join(cells) + " │")
    lines.append(bottom)
    return lines


def _visible_len(text: str) -> int:
    """Length ignoring ANSI escape sequences."""
    length, index = 0, 0
    while index < len(text):
        if text[index] == "\033":
            while index < len(text) and text[index] != "m":
                index += 1
            index += 1
            continue
        length += 1
        index += 1
    return length


def render_report(report: AuditReport, *, color: Optional[bool] = None, width: int = 118) -> str:
    """Render the full CLI report: header, control table, detail, summary."""
    paint = _Painter(supports_color() if color is None else color)
    out: List[str] = []

    target = report.target
    out.append("")
    out.append(paint("NETWORK SECURITY COMPLIANCE AUDIT", "\033[1m"))
    out.append("=" * width)
    out.append(f"  Device        : {target.hostname or '(hostname not found)'}")
    out.append(f"  Config        : {target.source_file or '(stdin)'}  ({target.config_line_count} lines)")
    out.append(
        f"  Parsed as     : {target.vendor}/{target.os_family} via {target.parser} v{target.parser_version} "
        f"(detection confidence {target.detection_confidence:.2f})"
    )
    
    if report.frameworks:
        fws_str = ", ".join(f"{f.name} ({f.version})" for f in report.frameworks)
        out.append(f"  Frameworks    : {fws_str}")
    elif report.framework:
        out.append(f"  Framework     : {report.framework.name} - {report.framework.version}")
    else:
        out.append("  Framework     : None")

    llm_fields = _llm_field_count(report)
    if llm_fields:
        out.append(
            paint(
                f"  Evidence      : {llm_fields} setting(s) normalized by a language model "
                "and verified against the configuration text",
                _COLORS[Status.NEEDS_REVIEW],
            )
        )
    out.append(f"  Generated     : {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if target.source_sha256:
        out.append(f"  Config SHA256 : {target.source_sha256}")
    out.append("=" * width)

    platform_note = None
    if report.frameworks:
        platform_note = next((f.platform_note for f in report.frameworks if f.platform_note), None)
    elif report.framework:
        platform_note = report.framework.platform_note

    if platform_note:
        out.append("")
        for line in _wrap(f"! {platform_note}", width):
            out.append(paint(line, _COLORS[Status.NEEDS_REVIEW]))
    out.append("")

    # -- framework summary table ------------------------------------------
    if report.framework_summaries and len(report.framework_summaries) > 1:
        out.append(paint("FRAMEWORK SUMMARY", "\033[1m"))
        out.append("─" * width)
        for fw_name, fw_sum in report.framework_summaries.items():
            out.append(f"  {fw_name}")
            out.append(
                "    "
                + paint(f"PASS: {fw_sum.passed}", _COLORS[Status.PASS])
                + "    "
                + paint(f"FAIL: {fw_sum.failed}", _COLORS[Status.FAIL])
                + "    "
                + paint(f"REVIEW: {fw_sum.needs_review}", _COLORS[Status.NEEDS_REVIEW])
                + f"    of {fw_sum.total} controls"
            )
        out.append("─" * width)
        out.append("")

    # -- control table ----------------------------------------------------
    show_fw_col = bool(report.framework_summaries and len(report.framework_summaries) > 1)
    
    if show_fw_col:
        fw_col_w = 15
        id_w = 20
        sev_w = 6
        status_w = 6
        title_w = 34
        evidence_w = max(24, width - id_w - sev_w - status_w - title_w - fw_col_w - 5 * 3 - 4)
        widths = [fw_col_w, id_w, sev_w, status_w, title_w, evidence_w]
        headers = ["FRAMEWORK", "CONTROL", "SEV", "RESULT", "TITLE", "EVIDENCE"]
    else:
        id_w, sev_w, status_w = 24, 6, 6
        title_w = 34
        evidence_w = max(24, width - id_w - sev_w - status_w - title_w - 3 * 3 - 4)
        widths = [id_w, sev_w, status_w, title_w, evidence_w]
        headers = ["CONTROL", "SEV", "RESULT", "TITLE", "EVIDENCE"]

    rows = []
    for result in report.results:
        evidence_cell = _evidence_cell(result)
        row_data = [
            _truncate(result.rule_id, id_w),
            paint(_truncate(result.severity.value, sev_w), _SEVERITY_COLORS.get(result.severity)),
            paint(_STATUS_MARK[result.status], _COLORS.get(result.status)),
            _truncate(result.title, title_w),
            _truncate(evidence_cell, evidence_w),
        ]
        if show_fw_col:
            row_data.insert(0, _truncate(result.framework, fw_col_w))
        rows.append(row_data)

    out.extend(_render_table(headers, rows, widths))
    out.append("")

    # -- findings detail --------------------------------------------------
    actionable = [r for r in report.results if r.status is not Status.PASS]
    if actionable:
        out.append(paint("DETAILED FINDINGS", "\033[1m"))
        out.append("-" * width)
        for result in actionable:
            out.extend(_render_finding(result, paint, width))
    else:
        out.append(paint("No findings: every evaluated control passed.", _COLORS[Status.PASS]))
        out.append("")

    # -- summary ----------------------------------------------------------
    summary = report.summary
    out.append(paint("OVERALL SUMMARY", "\033[1m"))
    out.append("-" * width)
    out.append(
        "  "
        + paint(f"PASS {summary.passed}", _COLORS[Status.PASS])
        + "   "
        + paint(f"FAIL {summary.failed}", _COLORS[Status.FAIL])
        + "   "
        + paint(f"NEEDS_REVIEW {summary.needs_review}", _COLORS[Status.NEEDS_REVIEW])
        + f"   of {summary.total} controls evaluated"
    )
    if summary.failed_by_severity:
        breakdown = ", ".join(f"{count} {sev}" for sev, count in summary.failed_by_severity.items())
        out.append(f"  Failures by severity : {breakdown}")
    out.append(f"  Compliance score     : {summary.compliance_score:.1f}%  (passed / all controls)")
    out.append(
        f"  Adjudicated score    : {summary.adjudicated_score:.1f}%  (passed / decided controls, "
        f"excludes {summary.needs_review} needing review)"
    )
    if summary.needs_review:
        out.append(
            "  "
            + paint(
                f"{summary.needs_review} control(s) could not be decided from this configuration "
                "and require human review.",
                _COLORS[Status.NEEDS_REVIEW],
            )
        )
    if target.parser_warnings:
        out.append("")
        out.append("  Parser notes:")
        for warning in target.parser_warnings:
            out.append(f"    - {_truncate(warning, width - 8)}")
    out.append("")
    return "\n".join(out)


def _origin_tag(item: Evidence) -> str:
    """Mark evidence that a model produced, with the confidence it was accepted at."""
    if item.origin is Origin.DETERMINISTIC:
        return ""
    return f"[{item.origin.value} {item.confidence:.2f}] "


def _llm_field_count(report: AuditReport) -> int:
    fields = {
        item.field
        for result in report.results
        for item in result.evidence
        if item.origin is not Origin.DETERMINISTIC
    }
    return len(fields)


def _wrap(text: str, width: int, indent: str = "  ", hanging: str = "    ") -> List[str]:
    """Wrap a paragraph to the report width, indenting continuation lines."""
    return textwrap.wrap(
        " ".join(text.split()),
        width=width,
        initial_indent=indent,
        subsequent_indent=hanging,
    ) or [indent]


def _evidence_cell(result: ControlResult) -> str:
    evidence = result.primary_evidence
    if evidence is None:
        return "(no evidence recorded)"
    return f"{_origin_tag(evidence)}{evidence.display}"


def _render_finding(result: ControlResult, paint: _Painter, width: int) -> List[str]:
    lines = [
        "",
        "  "
        + paint(_STATUS_MARK[result.status], _COLORS.get(result.status))
        + f"  [{result.severity.value.upper()}]  {result.rule_id}  -  {result.title}",
    ]
    
    # Framework
    lines.append(f"    Framework   : {result.framework}")
    
    # Control (verified vs unverified)
    if result.control_ref and result.verified_ref:
        lines.append(f"    Control     : {result.control_ref} (verified reference)")
    elif result.internal_control_id:
        lines.append(f"    Control     : {result.internal_control_id} (internal semantic mapping)")
    elif result.control_ref:
        lines.append(f"    Control     : {result.control_ref} (internal semantic mapping)")
    else:
        lines.append("    Control     : None (internal semantic mapping)")

    # Explanation
    lines.append(f"    Explanation : {_truncate(result.description, width - 18)}")
    lines.append(f"    Why         : {_truncate(result.message, width - 18)}")
    
    lines.append("    Evidence    :")
    for item in result.evidence:
        prefix = f"      - {item.field}: {_origin_tag(item)}"
        lines.append(prefix + _truncate(item.display, max(24, width - len(prefix))))
        if item.source_line and item.note:
            note_prefix = "          note: "
            lines.append(note_prefix + _truncate(item.note, max(24, width - len(note_prefix))))
            
    if result.remediation:
        lines.append(f"    Remediation : {_truncate(result.remediation.summary, width - 18)}")
        for command in result.remediation.cli:
            lines.append(f"        {command}")
    return lines
