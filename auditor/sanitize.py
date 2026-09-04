"""Report-level sanitization: strip sensitive values from audit output.

This module redacts identifying and credential data from *report text* —
evidence lines, source lines, remediation output — so that compliance
reports can be shared without leaking operational details.

It complements ``auditor.parsers.llm.client.redact_secrets`` which
operates on raw config text before it is sent to an LLM.  This module
operates *after* parsing and evaluation, on the structured report.
"""

import re
from typing import List

from .models.inventory import DeviceInventory, DeviceRecord
from .models.result import AuditReport, ControlResult, Evidence

_REDACTED = "<REDACTED>"

_IP_V4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_IP_V6 = re.compile(
    r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b"
)

_IOS_SECRET = re.compile(
    r"(?im)(\b(?:enable|username\s+\S+)\s+(?:secret|password)\s+\d+\s+)\S+",
)

_PASSWORD_VALUE = re.compile(
    r"(?im)(\b(?:password|secret|community|key|token|pre-shared-key|psk)\s*[:=]?\s*)\S+",
)

_SNMP_COMMUNITY = re.compile(
    r"(?im)(\bcommunity\s+)\S+",
)

_HOSTNAME = re.compile(
    r"(?im)^(hostname\s+)\S+",
)


def _redact_text(text: str) -> str:
    """Apply all redaction patterns to a single string."""
    if not text:
        return text
    result = _IP_V4.sub(_REDACTED, text)
    result = _IP_V6.sub(_REDACTED, result)
    result = _IOS_SECRET.sub(rf"\1{_REDACTED}", result)
    result = _PASSWORD_VALUE.sub(rf"\1{_REDACTED}", result)
    result = _SNMP_COMMUNITY.sub(rf"\1{_REDACTED}", result)
    result = _HOSTNAME.sub(rf"\1{_REDACTED}", result)
    return result


def sanitize_evidence(evidence: Evidence) -> Evidence:
    """Return a copy of *evidence* with sensitive values redacted."""
    return evidence.model_copy(
        update={
            "source_line": _redact_text(evidence.source_line) if evidence.source_line else evidence.source_line,
            "original_line": _redact_text(evidence.original_line) if evidence.original_line else evidence.original_line,
        }
    )


def sanitize_result(result: ControlResult) -> ControlResult:
    """Return a copy of *result* with evidence and message redacted."""
    return result.model_copy(
        update={
            "evidence": [sanitize_evidence(e) for e in result.evidence],
            "message": _redact_text(result.message),
        }
    )


def sanitize_report(report: AuditReport) -> AuditReport:
    """Return a deep copy of *report* with all sensitive data redacted.

    The report structure is preserved; only free-text fields that could
    contain operational secrets are scrubbed.
    """
    sanitized_results: List[ControlResult] = [sanitize_result(r) for r in report.results]

    target_update = {}
    if report.target.hostname:
        target_update["hostname"] = _REDACTED
    if report.target.source_file:
        target_update["source_file"] = _REDACTED

    return report.model_copy(
        update={
            "results": sanitized_results,
            "target": report.target.model_copy(update=target_update) if target_update else report.target,
        }
    )


def sanitize_record(record: DeviceRecord) -> DeviceRecord:
    """Return a copy of a device record with sensitive data redacted."""
    identity_update = {}
    if record.identity.hostname and record.identity.hostname.value:
        identity_update["hostname"] = record.identity.hostname.model_copy(
            update={"value": _REDACTED}
        )

    target_update = {}
    if record.target:
        if record.target.hostname:
            target_update["hostname"] = _REDACTED
        if record.target.source_file:
            target_update["source_file"] = _REDACTED

    return record.model_copy(
        update={
            "findings": [sanitize_result(r) for r in record.findings],
            "source_file": _REDACTED,
            "identity": record.identity.model_copy(update=identity_update) if identity_update else record.identity,
            "target": record.target.model_copy(update=target_update) if record.target and target_update else record.target,
        }
    )


def sanitize_inventory(inventory: DeviceInventory) -> DeviceInventory:
    """Return a copy of the full inventory with all devices sanitized."""
    return inventory.model_copy(
        update={
            "devices": [sanitize_record(d) for d in inventory.devices],
        }
    )
