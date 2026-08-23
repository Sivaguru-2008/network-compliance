"""Rendering an AuditReport for humans and for machines."""

from .inventory import render_inventory
from .json_report import report_to_dict, report_to_json, write_json_report
from .table import render_report, supports_color

__all__ = [
    "render_inventory",
    "render_report",
    "report_to_dict",
    "report_to_json",
    "supports_color",
    "write_json_report",
]
