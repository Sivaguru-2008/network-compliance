"""Formal JSON Schema generation and validation for Audit Reports."""

import json
from typing import Any, Dict, Optional

from .models.result import AuditReport


def get_audit_report_json_schema() -> Dict[str, Any]:
    """Generates the formal JSON Schema for AuditReport."""
    return AuditReport.model_json_schema()


def validate_audit_report_dict(data: Dict[str, Any]) -> AuditReport:
    """Validates that a raw dictionary strictly matches the AuditReport schema and invariants.

    Raises:
        pydantic.ValidationError if schema validation fails.
        ValueError if consistency invariants fail.
    """
    report = AuditReport.model_validate(data)
    report.validate_consistency()
    return report


def validate_audit_report_json(json_text: str) -> AuditReport:
    """Parses and validates a JSON string against AuditReport schema."""
    data = json.loads(json_text)
    return validate_audit_report_dict(data)
