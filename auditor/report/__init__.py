"""Rendering an AuditReport for humans and for machines."""

from .document import ReportDocument, build_device_document
from .inventory import render_inventory
from .json_report import report_to_dict, report_to_json, write_json_report
from .pdf import (
    PdfUnavailableError,
    pdf_available,
    pdf_filenames,
    write_device_pdf,
    write_inventory_pdfs,
)
from .table import render_report, supports_color

__all__ = [
    "PdfUnavailableError",
    "ReportDocument",
    "build_device_document",
    "pdf_available",
    "pdf_filenames",
    "render_inventory",
    "render_report",
    "report_to_dict",
    "report_to_json",
    "supports_color",
    "write_device_pdf",
    "write_inventory_pdfs",
    "write_json_report",
]
