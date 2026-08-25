"""Adversarial regression tests for corrected FortiGate CIS controls."""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from auditor.parsers.fortios import FortiosParser
from auditor.pipeline import evaluate_cis_fortigate
from auditor.models.result import Status


def evaluate_config(config_text: str):
    """Helper to parse a config string and evaluate it against CIS FortiGate rules."""
    parser = FortiosParser()
    baseline = parser.parse(config_text, source_file="adversarial_test.conf")
    return evaluate_cis_fortigate(baseline)


# ── CIS 2.1.1 and 2.1.2 — Banners ──────────────────────────────────────────

def test_banners_only_pre_login():
    config = """
    config system global
        set pre-login-banner enable
        set post-login-banner disable
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.1.1"].status == Status.PASS
    assert results["2.1.2"].status == Status.FAIL


def test_banners_only_post_login():
    config = """
    config system global
        set pre-login-banner disable
        set post-login-banner enable
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.1.1"].status == Status.FAIL
    assert results["2.1.2"].status == Status.PASS


def test_banners_both_enabled():
    config = """
    config system global
        set pre-login-banner enable
        set post-login-banner enable
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.1.1"].status == Status.PASS
    assert results["2.1.2"].status == Status.PASS


def test_banners_neither_enabled():
    config = """
    config system global
        set pre-login-banner disable
        set post-login-banner disable
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.1.1"].status == Status.FAIL
    assert results["2.1.2"].status == Status.FAIL


# ── CIS 2.2.2 — Lockout Duration ───────────────────────────────────────────

def test_lockout_absent():
    # Absent lockout settings should default to threshold=3, duration=60 (FAIL)
    config = """
    config system global
        set hostname "FGT-1"
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.2.2"].status == Status.FAIL


def test_lockout_duration_60():
    config = """
    config system global
        set admin-lockout-threshold 3
        set admin-lockout-duration 60
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.2.2"].status == Status.FAIL


def test_lockout_duration_300():
    config = """
    config system global
        set admin-lockout-threshold 3
        set admin-lockout-duration 300
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.2.2"].status == Status.FAIL


def test_lockout_duration_899():
    config = """
    config system global
        set admin-lockout-threshold 3
        set admin-lockout-duration 899
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.2.2"].status == Status.FAIL


def test_lockout_duration_900():
    config = """
    config system global
        set admin-lockout-threshold 3
        set admin-lockout-duration 900
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.2.2"].status == Status.PASS


def test_lockout_duration_1800():
    # Strict CIS Audit check requires exactly 900
    config = """
    config system global
        set admin-lockout-threshold 3
        set admin-lockout-duration 1800
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.2.2"].status == Status.FAIL


# ── CIS 2.3.1 — SNMPv3-only Requirement ─────────────────────────────────────

def test_snmp_v2c_only():
    config = """
    config system snmp sysinfo
        set status enable
    end
    config system snmp community
        edit 1
            set name "public"
        next
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.3.1"].status == Status.FAIL


def test_snmp_v3_only():
    config = """
    config system snmp sysinfo
        set status enable
    end
    config system snmp user
        edit "snmpv3_user"
            set security-level auth-priv
        next
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.3.1"].status == Status.PASS


def test_snmp_neither_configured():
    config = """
    config system snmp sysinfo
        set status disable
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.3.1"].status == Status.FAIL


def test_snmp_both():
    config = """
    config system snmp sysinfo
        set status enable
    end
    config system snmp community
        edit 1
            set name "public"
        next
    end
    config system snmp user
        edit "snmpv3_user"
            set security-level auth-priv
        next
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.3.1"].status == Status.FAIL


# ── CIS 2.4.7 — Default Admin Ports ────────────────────────────────────────

def test_ports_absent_defaults():
    config = """
    config system global
        set hostname "FGT-1"
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.4.7"].status == Status.FAIL


def test_ports_only_https_changed():
    config = """
    config system global
        set admin-sport 8443
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.4.7"].status == Status.FAIL


def test_ports_only_http_changed():
    config = """
    config system global
        set admin-port 8080
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.4.7"].status == Status.FAIL


def test_ports_both_changed():
    config = """
    config system global
        set admin-sport 8443
        set admin-port 8080
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.4.7"].status == Status.PASS


def test_ports_explicit_defaults():
    config = """
    config system global
        set admin-sport 443
        set admin-port 80
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["2.4.7"].status == Status.FAIL


# ── CIS 7.1.1 — Event Logging ──────────────────────────────────────────────

def test_event_logging_syslog_and_eventfilter_enabled():
    config = """
    config log syslogd setting
        set status enable
        set server "192.168.20.40"
    end
    config log eventfilter
        set event enable
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["7.1.1"].status == Status.PASS


def test_event_logging_syslog_enabled_but_eventfilter_disabled():
    config = """
    config log syslogd setting
        set status enable
        set server "192.168.20.40"
    end
    config log eventfilter
        set event disable
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["7.1.1"].status == Status.FAIL


def test_event_logging_syslog_disabled():
    config = """
    config log syslogd setting
        set status disable
    end
    config log memory setting
        set status disable
    end
    config log disk setting
        set status disable
    end
    config log eventfilter
        set event enable
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["7.1.1"].status == Status.FAIL


def test_event_logging_syslog_enabled_eventfilter_absent():
    # Absent eventfilter defaults to enable (PASS)
    config = """
    config log syslogd setting
        set status enable
        set server "192.168.20.40"
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["7.1.1"].status == Status.PASS


def test_syslog_status_absent_defaults_to_disabled():
    # If status is absent, it defaults to disable, so syslog is disabled.
    config = """
    config log syslogd setting
        set server "192.168.20.40"
    end
    """
    report = evaluate_config(config)
    results = {r.control_ref: r for r in report.results}
    assert results["7.3.1"].status == Status.FAIL
