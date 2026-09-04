"""Tests for Nokia SR OS configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.nokia_sros import NokiaSROSParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_NOKIA_CONFIG = """# TiMOS-B-22.2.R1 both/x86_64 Nokia 7750 SR Copyright (c) Nokia.
#--------------------------------------------------
echo "System Configuration"
#--------------------------------------------------
system
    name "nokia-edge-01"
    login-control
        idle-timeout 10
        pre-login-message "Authorized Access Only."
    exit
    security
        authentication-order tacplus radius local
        password
            minimum-length 12
        exit
        telnet-server
            shutdown
        exit
        ssh
            no server-shutdown
            version 2
        exit
        mgmt-access-filter
            default-action deny
        exit
    exit
    time
        ntp
            server 10.10.10.1 prefer
            server 10.10.10.2
            no shutdown
        exit
    exit
exit
#--------------------------------------------------
log
    syslog 1
        address 192.168.1.50
        no shutdown
    exit
exit
primary-dns 8.8.8.8
secondary-dns 8.8.4.4
"""

INSECURE_NOKIA_CONFIG = """# TiMOS-C-21.5.R2 both/x86_64
echo "System Configuration"
system
    name "insecure-nokia"
    login-control
        idle-timeout disable
        no login-banner
    exit
    security
        telnet-server
            no shutdown
        exit
        ssh
            server-shutdown
        exit
    exit
exit
"""


def test_nokia_detection():
    """Verify that detect() correctly identifies Nokia SR OS configuration outputs."""
    parser = NokiaSROSParser()
    assert parser.detect(COMPLIANT_NOKIA_CONFIG) == 1.0
    assert parser.detect(INSECURE_NOKIA_CONFIG) == 1.0

    # Ensure other formats are rejected
    cisco_text = "line vty 0 4\n transport input ssh\n"
    assert parser.detect(cisco_text) == 0.0

    juniper_text = "system {\n    host-name junos-fw;\n}\n"
    assert parser.detect(juniper_text) == 0.0


def test_compliant_parser_normalization():
    """Verify the compliant config is parsed correctly into baseline model."""
    parser = NokiaSROSParser()
    baseline = parser.parse(COMPLIANT_NOKIA_CONFIG)

    assert baseline.provenance.vendor == "nokia"
    assert baseline.provenance.os_family == "sros"

    assert baseline.hostname.value == "nokia-edge-01"
    assert baseline.ssh_enabled.value is True
    assert set(baseline.vty_transport_input.value) == {"ssh"}
    assert baseline.telnet_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is False
    assert baseline.vty_exec_timeout_seconds.value == 600
    assert baseline.dns_servers.value == ["8.8.8.8", "8.8.4.4"]
    assert baseline.ntp_servers.value == ["10.10.10.1", "10.10.10.2"]
    assert baseline.logging_enabled.value is True
    assert baseline.logging_hosts.value == ["192.168.1.50"]
    assert baseline.aaa_enabled.value is True
    assert baseline.password_min_length.value == 12
    assert baseline.management_acl_applied.value is True
    assert baseline.login_banner_present.value is True


def test_insecure_parser_normalization():
    """Verify the insecure config is parsed correctly into baseline model."""
    parser = NokiaSROSParser()
    baseline = parser.parse(INSECURE_NOKIA_CONFIG)

    assert baseline.hostname.value == "insecure-nokia"
    assert baseline.ssh_enabled.value is False
    assert set(baseline.vty_transport_input.value) == {"telnet"}
    assert baseline.telnet_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 0
    assert baseline.login_banner_present.value is False


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = NokiaSROSParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = NokiaSROSParser()
    baseline = parser.parse(COMPLIANT_NOKIA_CONFIG)
    identity = extract_identity(COMPLIANT_NOKIA_CONFIG, baseline)

    assert identity.vendor == "nokia_sros"
    assert identity.os_family == "sros"
    assert identity.hostname.value == "nokia-edge-01"
    assert identity.os_version.value == "B-22.2.R1"

    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against Nokia SR OS."""
    parser = NokiaSROSParser()
    ruleset = load_framework("CIS", "nokia_sros")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_NOKIA_CONFIG)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-NOKIA-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-NOKIA-IDLE-TIMEOUT"].status == Status.PASS
    assert compliant_results["CIS-NOKIA-NO-HTTP-SERVER"].status == Status.PASS
    assert compliant_results["CIS-NOKIA-SYSLOG-DESTINATION"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_NOKIA_CONFIG)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-NOKIA-NO-CLEARTEXT-SERVICES"].status == Status.FAIL
    assert insecure_results["CIS-NOKIA-IDLE-TIMEOUT"].status == Status.FAIL


def test_adversarial_inputs():
    """Verify Nokia parser handling of adversarial comments and values."""
    parser = NokiaSROSParser()

    # Comment containing secure-looking tags must be ignored
    comment_config = """# TiMOS-B-22.2.R1
    system
        # idle-timeout 10
        login-control
            idle-timeout 5
        exit
    exit
    """
    baseline = parser.parse(comment_config)
    assert baseline.vty_exec_timeout_seconds.value == 300

    # Unknown fields return needs review
    partial_config = """# TiMOS-B-22.2.R1
    system
        name "nokia-partial"
    exit
    """
    baseline = parser.parse(partial_config)
    assert baseline.logging_enabled.detected is False


def test_vendor_isolation():
    """Verify isolation of parser state across multiple platforms."""
    parser_nokia = NokiaSROSParser()
    from auditor.parsers.cisco_ios import CiscoIOSParser
    parser_cisco = CiscoIOSParser()

    nokia_baseline = parser_nokia.parse(COMPLIANT_NOKIA_CONFIG)
    cisco_baseline = parser_cisco.parse("hostname CiscoRouter\n")

    assert nokia_baseline.provenance.vendor == "nokia"
    assert cisco_baseline.provenance.vendor == "cisco"

    assert nokia_baseline.hostname.value == "nokia-edge-01"
    assert cisco_baseline.hostname.value == "CiscoRouter"
