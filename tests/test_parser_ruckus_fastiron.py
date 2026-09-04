"""Tests for Ruckus Networks FastIron configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.ruckus_fastiron import RuckusFastIronParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_RUCKUS_CONFIG = """hostname ruckus-switch-1
ip ssh server
no telnet server
no web-management http
web-management https
console timeout 10
enable strict-password-enforcement
enable super-user-password encrypted_hash_here
aaa authentication login default tacacs+ local
ntp server 192.168.1.50
ip dns server-address 8.8.8.8
logging host 10.10.10.100
ip ssh client-acl 15
snmp-server community read_only_key ro
banner motd ^
Authorized Access Only.
^
"""

INSECURE_RUCKUS_CONFIG = """hostname insecure-ruckus
telnet server
no ip ssh server
web-management http
no web-management https
console timeout 0
"""


def test_ruckus_detection():
    """Verify that detect() correctly identifies FastIron configuration outputs."""
    parser = RuckusFastIronParser()
    assert parser.detect(COMPLIANT_RUCKUS_CONFIG) == 1.0
    assert parser.detect(INSECURE_RUCKUS_CONFIG) == 1.0

    # Ensure other formats are rejected
    cisco_text = "line vty 0 4\n transport input ssh\n"
    assert parser.detect(cisco_text) == 0.0

    juniper_text = "system {\n    host-name junos-fw;\n}\n"
    assert parser.detect(juniper_text) == 0.0


def test_compliant_parser_normalization():
    """Verify the compliant config is parsed correctly into baseline model."""
    parser = RuckusFastIronParser()
    baseline = parser.parse(COMPLIANT_RUCKUS_CONFIG)

    assert baseline.provenance.vendor == "ruckus"
    assert baseline.provenance.os_family == "fastiron"

    assert baseline.hostname.value == "ruckus-switch-1"
    assert baseline.ssh_enabled.value is True
    assert set(baseline.vty_transport_input.value) == {"ssh"}
    assert baseline.telnet_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 600
    assert baseline.dns_servers.value == ["8.8.8.8"]
    assert baseline.ntp_servers.value == ["192.168.1.50"]
    assert baseline.logging_enabled.value is True
    assert baseline.logging_hosts.value == ["10.10.10.100"]
    assert baseline.aaa_enabled.value is True
    assert baseline.password_min_length.value == 8
    assert baseline.management_acl_applied.value is True
    assert baseline.login_banner_present.value is True
    assert len(baseline.snmp_communities.value) == 1
    assert baseline.snmp_communities.value[0].name == "read_only_key"
    assert baseline.snmp_communities.value[0].access == "ro"


def test_insecure_parser_normalization():
    """Verify the insecure config is parsed correctly into baseline model."""
    parser = RuckusFastIronParser()
    baseline = parser.parse(INSECURE_RUCKUS_CONFIG)

    assert baseline.hostname.value == "insecure-ruckus"
    assert baseline.ssh_enabled.value is False
    assert set(baseline.vty_transport_input.value) == {"telnet"}
    assert baseline.telnet_enabled.value is True
    assert baseline.http_server_enabled.value is True
    assert baseline.https_server_enabled.value is False
    assert baseline.vty_exec_timeout_seconds.value == 0


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = RuckusFastIronParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = RuckusFastIronParser()
    baseline = parser.parse(COMPLIANT_RUCKUS_CONFIG)
    identity = extract_identity(COMPLIANT_RUCKUS_CONFIG, baseline)

    assert identity.vendor == "ruckus_fastiron"
    assert identity.os_family == "fastiron"
    assert identity.hostname.value == "ruckus-switch-1"
    assert identity.os_version.detected is False

    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against Ruckus FastIron."""
    parser = RuckusFastIronParser()
    ruleset = load_framework("CIS", "ruckus_fastiron")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_RUCKUS_CONFIG)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-RUCKUS-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-RUCKUS-IDLE-TIMEOUT"].status == Status.PASS
    assert compliant_results["CIS-RUCKUS-NO-HTTP-SERVER"].status == Status.PASS
    assert compliant_results["CIS-RUCKUS-SYSLOG-DESTINATION"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_RUCKUS_CONFIG)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-RUCKUS-NO-CLEARTEXT-SERVICES"].status == Status.FAIL
    assert insecure_results["CIS-RUCKUS-IDLE-TIMEOUT"].status == Status.FAIL


def test_adversarial_inputs():
    """Verify Ruckus parser handling of adversarial comments and values."""
    parser = RuckusFastIronParser()

    comment_config = """! Ruckus FastIron Configuration
    ! ip ssh server
    ! no telnet server
    console timeout 5
    """
    baseline = parser.parse(comment_config)
    
    assert baseline.ssh_enabled.value is False
    assert baseline.telnet_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 300

    # Unknown fields return needs review
    partial_config = """! FastIron
    ip ssh server
    hostname "ruckus-partial"
    """
    baseline = parser.parse(partial_config)
    assert baseline.logging_enabled.detected is False


def test_vendor_isolation():
    """Verify isolation of parser state across multiple platforms."""
    parser_ruckus = RuckusFastIronParser()
    from auditor.parsers.cisco_ios import CiscoIOSParser
    parser_cisco = CiscoIOSParser()

    ruckus_baseline = parser_ruckus.parse(COMPLIANT_RUCKUS_CONFIG)
    cisco_baseline = parser_cisco.parse("hostname CiscoRouter\n")

    assert ruckus_baseline.provenance.vendor == "ruckus"
    assert cisco_baseline.provenance.vendor == "cisco"

    assert ruckus_baseline.hostname.value == "ruckus-switch-1"
    assert cisco_baseline.hostname.value == "CiscoRouter"
