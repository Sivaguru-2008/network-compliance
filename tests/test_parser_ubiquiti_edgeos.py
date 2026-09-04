"""Tests for Ubiquiti Networks EdgeOS configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.ubiquiti_edgeos import UbiquitiEdgeOSParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_UBIQUITI_CONFIG = """set system host-name "edge-router-1"
set system login banner pre-login "Authorized Access Only."
set system login radius-server 192.168.1.50 key secret
set system name-server 8.8.8.8
set system ntp server 0.ubnt.pool.ntp.org
set system syslog host 192.168.1.100 facility all level err
set service ssh protocol-version v2
set service ssh listen-address 192.168.1.1
set service gui listen-address 192.168.1.1
delete service telnet
delete service gui http-port
set service snmp community test_community authorization ro
"""

INSECURE_UBIQUITI_CONFIG = """set system host-name "insecure-edge"
set service telnet
set service gui http-port 80
delete service ssh
"""


def test_ubiquiti_detection():
    """Verify that detect() correctly identifies EdgeOS configuration outputs."""
    parser = UbiquitiEdgeOSParser()
    assert parser.detect(COMPLIANT_UBIQUITI_CONFIG) == 1.0
    assert parser.detect(INSECURE_UBIQUITI_CONFIG) == 1.0

    # Ensure other formats are rejected
    cisco_text = "line vty 0 4\n transport input ssh\n"
    assert parser.detect(cisco_text) == 0.0

    juniper_text = "system {\n    host-name junos-fw;\n}\n"
    assert parser.detect(juniper_text) == 0.0


def test_compliant_parser_normalization():
    """Verify the compliant config is parsed correctly into baseline model."""
    parser = UbiquitiEdgeOSParser()
    baseline = parser.parse(COMPLIANT_UBIQUITI_CONFIG)

    assert baseline.provenance.vendor == "ubiquiti"
    assert baseline.provenance.os_family == "edgeos"

    assert baseline.hostname.value == "edge-router-1"
    assert baseline.ssh_enabled.value is True
    assert set(baseline.vty_transport_input.value) == {"ssh"}
    assert baseline.telnet_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True
    assert baseline.dns_servers.value == ["8.8.8.8"]
    assert baseline.ntp_servers.value == ["0.ubnt.pool.ntp.org"]
    assert baseline.logging_enabled.value is True
    assert baseline.logging_hosts.value == ["192.168.1.100"]
    assert baseline.aaa_enabled.value is True
    assert baseline.management_acl_applied.value is True
    assert baseline.login_banner_present.value is True
    assert len(baseline.snmp_communities.value) == 1
    assert baseline.snmp_communities.value[0].name == "test_community"
    assert baseline.snmp_communities.value[0].access == "ro"


def test_insecure_parser_normalization():
    """Verify the insecure config is parsed correctly into baseline model."""
    parser = UbiquitiEdgeOSParser()
    baseline = parser.parse(INSECURE_UBIQUITI_CONFIG)

    assert baseline.hostname.value == "insecure-edge"
    assert baseline.ssh_enabled.value is False
    assert set(baseline.vty_transport_input.value) == {"telnet"}
    assert baseline.telnet_enabled.value is True
    assert baseline.http_server_enabled.value is True
    assert baseline.https_server_enabled.value is True


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = UbiquitiEdgeOSParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = UbiquitiEdgeOSParser()
    baseline = parser.parse(COMPLIANT_UBIQUITI_CONFIG)
    identity = extract_identity(COMPLIANT_UBIQUITI_CONFIG, baseline)

    assert identity.vendor == "ubiquiti_edgeos"
    assert identity.os_family == "edgeos"
    assert identity.hostname.value == "edge-router-1"
    assert identity.os_version.detected is False

    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against Ubiquiti EdgeOS."""
    parser = UbiquitiEdgeOSParser()
    ruleset = load_framework("CIS", "ubiquiti_edgeos")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_UBIQUITI_CONFIG)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-UBIQUITI-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-UBIQUITI-NO-HTTP-SERVER"].status == Status.PASS
    assert compliant_results["CIS-UBIQUITI-SYSLOG-DESTINATION"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_UBIQUITI_CONFIG)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-UBIQUITI-NO-CLEARTEXT-SERVICES"].status == Status.FAIL
    assert insecure_results["CIS-UBIQUITI-NO-HTTP-SERVER"].status == Status.FAIL


def test_adversarial_inputs():
    """Verify Ubiquiti parser handling of adversarial comments and values."""
    parser = UbiquitiEdgeOSParser()

    # Commented-out secure command must NOT cause a compliance PASS
    comment_config = """# set service ssh
    # set service gui listen-address 192.168.1.1
    set service gui
    """
    baseline = parser.parse(comment_config)
    
    assert baseline.ssh_enabled.value is False
    assert baseline.management_acl_applied.value is False

    # Unknown fields return needs review
    partial_config = """set service gui
    set system host-name "ubiquiti-partial"
    """
    baseline = parser.parse(partial_config)
    assert baseline.logging_enabled.detected is False


def test_vendor_isolation():
    """Verify isolation of parser state across multiple platforms."""
    parser_ubiquiti = UbiquitiEdgeOSParser()
    from auditor.parsers.cisco_ios import CiscoIOSParser
    parser_cisco = CiscoIOSParser()

    ubiquiti_baseline = parser_ubiquiti.parse(COMPLIANT_UBIQUITI_CONFIG)
    cisco_baseline = parser_cisco.parse("hostname CiscoRouter\n")

    assert ubiquiti_baseline.provenance.vendor == "ubiquiti"
    assert cisco_baseline.provenance.vendor == "cisco"

    assert ubiquiti_baseline.hostname.value == "edge-router-1"
    assert cisco_baseline.hostname.value == "CiscoRouter"
