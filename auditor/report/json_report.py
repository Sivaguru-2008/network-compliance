"""Structured JSON output.

The JSON report is the machine-readable contract for everything downstream:
dashboards, ticketing, and -- in later steps -- the LLM remediation writer and
the training loop that scores parser output against reviewed ground truth.  It
therefore carries the full normalized baseline alongside the verdicts, not just
the verdicts.
"""

import json
from pathlib import Path
from typing import Any, Dict

from ..models.result import AuditReport


def report_to_dict(report: AuditReport, *, include_baseline: bool = True) -> Dict[str, Any]:
    payload = report.model_dump(mode="json", exclude_none=False)
    if not include_baseline:
        payload.pop("baseline", None)
    return payload


def report_to_json(report: AuditReport, *, indent: int = 2, include_baseline: bool = True) -> str:
    return json.dumps(report_to_dict(report, include_baseline=include_baseline), indent=indent, ensure_ascii=False)


def write_json_report(report: AuditReport, path: Path, *, include_baseline: bool = True) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report_to_json(report, include_baseline=include_baseline) + "\n", encoding="utf-8")
    return path
