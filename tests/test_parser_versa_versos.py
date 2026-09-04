"""Tests for Versa Networks VersaOS configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.versa_versos import VersaVersaOSParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_VERSA_CONFIG = """set system host-name "versa-edge-1"
set system login announcement "Authorized Access Only."
set system login idle-timeout 10
set system password-policy minimum-length 12
set system authentication-order [ tacplus radius local ]
set system ntp server 10.10.10.5
set system name-server 8.8.8.8
set system syslog server 192.168.1.100 selector 1 facility-list [ auth ] level alert
set system snmp community ro_community authorization read-only
set system services access-list ssh allow [ 10.0.0.0/8 ]
"""

INSECURE_VERSA_CONFIG = """set system host-name "insecure-versa"
set system services telnet enable
set system services ssh disable
set system login idle-timeout 0
"""


def test_versa_detection():
    """Verify that detect() correctly identifies VersaOS configuration outputs."""
    parser = VersaVersaOSParser()
    assert parser.detect(COMPLIANT_VERSA_CONFIG) == 1.0
    assert parser.detect(INSECURE_VERSA_CONFIG) == 1.0

    # Ensure other formats are rejected
    cisco_text = "line vty 0 4\n transport input ssh\n"
    assert parser.detect(cisco_text) == 0.0

    juniper_text = "system {\n    host-name junos-fw;\n}\n"
    assert parser.detect(juniper_text) == 0.0


def test_compliant_parser_normalization():
    """Verify the compliant config is parsed correctly into baseline model."""
    parser = VersaVersaOSParser()
    baseline = parser.parse(COMPLIANT_VERSA_CONFIG)

    assert baseline.provenance.vendor == "versa_networks"
    assert baseline.provenance.os_family == "versos"

    assert baseline.hostname.value == "versa-edge-1"
    assert baseline.ssh_enabled.value is True
    assert set(baseline.vty_transport_input.value) == {"ssh"}
    assert baseline.telnet_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 600
    assert baseline.dns_servers.value == ["8.8.8.8"]
    assert baseline.ntp_servers.value == ["10.10.10.5"]
    assert baseline.logging_enabled.value is True
    assert baseline.logging_hosts.value == ["192.168.1.100"]
    assert baseline.aaa_enabled.value is True
    assert baseline.password_min_length.value == 12
    assert baseline.management_acl_applied.value is True
    assert baseline.login_banner_present.value is True
    assert len(baseline.snmp_communities.value) == 1
    assert baseline.snmp_communities.value[0].name == "ro_community"
    assert baseline.snmp_communities.value[0].access == "ro"


def test_insecure_parser_normalization():
    """Verify the insecure config is parsed correctly into baseline model."""
    parser = VersaVersaOSParser()
    baseline = parser.parse(INSECURE_VERSA_CONFIG)

    assert baseline.hostname.value == "insecure-versa"
    assert baseline.ssh_enabled.value is False
    assert set(baseline.vty_transport_input.value) == {"telnet"}
    assert baseline.telnet_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 0


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = VersaVersaOSParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = VersaVersaOSParser()
    baseline = parser.parse(COMPLIANT_VERSA_CONFIG)
    identity = extract_identity(COMPLIANT_VERSA_CONFIG, baseline)

    assert identity.vendor == "versa_versos"
    assert identity.os_family == "versos"
    assert identity.hostname.value == "versa-edge-1"
    assert identity.os_version.detected is False

    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against Versa Networks VersaOS."""
    parser = VersaVersaOSParser()
    ruleset = load_framework("CIS", "versa_versos")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_VERSA_CONFIG)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-VERSA-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-VERSA-IDLE-TIMEOUT"].status == Status.PASS
    assert compliant_results["CIS-VERSA-NO-HTTP-SERVER"].status == Status.PASS
    assert compliant_results["CIS-VERSA-SYSLOG-DESTINATION"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_VERSA_CONFIG)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-VERSA-NO-CLEARTEXT-SERVICES"].status == Status.FAIL
    assert insecure_results["CIS-VERSA-IDLE-TIMEOUT"].status == Status.FAIL


def test_adversarial_inputs():
    """Verify Versa parser handling of adversarial comments and values."""
    parser = VersaVersaOSParser()

    # Comment containing secure-looking tags must be ignored
    comment_config = """# set system login idle-timeout 10
    set system services access-list ssh allow [ 10.0.0.0/8 ]
    set system login idle-timeout 5
    """
    baseline = parser.parse(comment_config)
    assert baseline.vty_exec_timeout_seconds.value == 300

    # Unknown fields return needs review
    partial_config = """set system services access-list ssh allow [ 10.0.0.0/8 ]
    set system host-name "versa-partial"
    """
    baseline = parser.parse(partial_config)
    assert baseline.logging_enabled.detected is False


def test_vendor_isolation():
    """Verify isolation of parser state across multiple platforms."""
    parser_versa = VersaVersaOSParser()
    from auditor.parsers.cisco_ios import CiscoIOSParser
    parser_cisco = CiscoIOSParser()

    versa_baseline = parser_versa.parse(COMPLIANT_VERSA_CONFIG)
    cisco_baseline = parser_cisco.parse("hostname CiscoRouter\n")

    assert versa_baseline.provenance.vendor == "versa_networks"
    assert cisco_baseline.provenance.vendor == "cisco"

    assert versa_baseline.hostname.value == "versa-edge-1"
    assert cisco_baseline.hostname.value == "CiscoRouter"
