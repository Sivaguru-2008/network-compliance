"""Tests for the report sanitization module."""

import pytest
from auditor.sanitize import _redact_text, sanitize_evidence, sanitize_result, sanitize_report
from auditor.models.result import (
    AuditReport,
    ControlResult,
    Evidence,
    FrameworkInfo,
    ReportSummary,
    Status,
    TargetInfo,
)
from auditor.models.observation import Origin
from auditor.models.rule import Severity


def _make_evidence(**overrides):
    defaults = dict(
        field="ssh_enabled",
        value=True,
        detected=True,
        source_line="ip ssh server 192.168.1.1",
        line_number=42,
        origin=Origin.DETERMINISTIC,
        confidence=1.0,
    )
    defaults.update(overrides)
    return Evidence(**defaults)


def _make_result(**overrides):
    defaults = dict(
        rule_id="CIS-1.1",
        title="SSH enabled",
        description="Ensure SSH is enabled",
        framework="CIS",
        severity=Severity.HIGH,
        status=Status.PASS,
        message="SSH is enabled on 192.168.1.1",
        evidence=[_make_evidence()],
    )
    defaults.update(overrides)
    return ControlResult(**defaults)


class TestRedactText:
    def test_ipv4_redacted(self):
        assert "<REDACTED>" in _redact_text("server 10.0.0.1 port 22")
        assert "10.0.0.1" not in _redact_text("server 10.0.0.1 port 22")

    def test_password_redacted(self):
        assert "s3cret" not in _redact_text("password s3cret")

    def test_snmp_community_redacted(self):
        assert "public" not in _redact_text("community public RO")

    def test_hostname_redacted(self):
        assert "core-rtr-01" not in _redact_text("hostname core-rtr-01")

    def test_empty_passthrough(self):
        assert _redact_text("") == ""

    def test_none_passthrough(self):
        assert _redact_text(None) is None


class TestSanitizeEvidence:
    def test_source_line_redacted(self):
        ev = _make_evidence(source_line="ip ssh server 10.0.0.1")
        san = sanitize_evidence(ev)
        assert "10.0.0.1" not in san.source_line
        assert san.field == ev.field
        assert san.detected == ev.detected

    def test_none_source_line_preserved(self):
        ev = _make_evidence(source_line=None)
        san = sanitize_evidence(ev)
        assert san.source_line is None


class TestSanitizeResult:
    def test_message_and_evidence_redacted(self):
        result = _make_result()
        san = sanitize_result(result)
        assert "192.168.1.1" not in san.message
        assert "192.168.1.1" not in san.evidence[0].source_line


class TestSanitizeReport:
    def test_full_report_sanitized(self):
        report = AuditReport(
            target=TargetInfo(
                source_file="samples/cisco/hardened_ios.conf",
                hostname="core-rtr-01",
                vendor="cisco",
                os_family="ios",
                parser="CiscoIOSParser",
                parser_version="1.0",
            ),
            framework=FrameworkInfo(
                name="CIS",
                version="1.0",
                rules_evaluated=1,
            ),
            summary=ReportSummary(total=1, passed=1),
            results=[_make_result()],
        )
        san = sanitize_report(report)
        assert san.target.hostname == "<REDACTED>"
        assert san.target.source_file == "<REDACTED>"
        assert "192.168.1.1" not in san.results[0].message
