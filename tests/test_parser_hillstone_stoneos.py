"""Tests for Hillstone Networks StoneOS configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.hillstone_stoneos import HillstoneStoneOSParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_HILLSTONE_CONFIG = """
! StoneOS Version 5.5
hostname HillstoneFW01
access http
no access http
access https
access ssh
console timeout 10
ip name-server 8.8.8.8
ip name-server 8.8.4.4
ntp server pool.ntp.org
logging syslog 192.168.1.100 udp 514 type event
"""

INSECURE_HILLSTONE_CONFIG = """
! StoneOS Version 5.5
hostname InsecureHillstone
access http
no access https
no access ssh
console timeout 60
"""


def test_hillstone_detection():
    """Verify that detect() correctly identifies Hillstone configuration text."""
    parser = HillstoneStoneOSParser()
    assert parser.detect(COMPLIANT_HILLSTONE_CONFIG) >= 0.70
    assert parser.detect(INSECURE_HILLSTONE_CONFIG) >= 0.70

    # Ensure other formats are rejected
    generic_ini = """[Settings]
    LogLevel=Debug
    """
    assert parser.detect(generic_ini) == 0.0

    cisco_text = "line vty 0 4\n ip http server\n"
    assert parser.detect(cisco_text) == 0.0


def test_compliant_parser_normalization():
    """Verify the compliant config is parsed correctly into baseline model."""
    parser = HillstoneStoneOSParser()
    baseline = parser.parse(COMPLIANT_HILLSTONE_CONFIG)

    assert baseline.provenance.vendor == "hillstone"
    assert baseline.provenance.os_family == "stoneos"
    
    assert baseline.hostname.value == "HillstoneFW01"
    assert baseline.ssh_enabled.value is True
    assert set(baseline.vty_transport_input.value) == {"ssh"}
    assert baseline.telnet_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 600
    assert baseline.dns_servers.value == ["8.8.8.8", "8.8.4.4"]
    assert baseline.ntp_servers.value == ["pool.ntp.org"]
    assert baseline.logging_enabled.value is True
    assert baseline.logging_hosts.value == ["192.168.1.100"]


def test_insecure_parser_normalization():
    """Verify the insecure config is parsed correctly into baseline model."""
    parser = HillstoneStoneOSParser()
    baseline = parser.parse(INSECURE_HILLSTONE_CONFIG)

    assert baseline.hostname.value == "InsecureHillstone"
    assert baseline.ssh_enabled.value is False
    assert set(baseline.vty_transport_input.value) == set()
    assert baseline.http_server_enabled.value is True
    assert baseline.https_server_enabled.value is False
    assert baseline.vty_exec_timeout_seconds.value == 3600


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = HillstoneStoneOSParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = HillstoneStoneOSParser()
    baseline = parser.parse(COMPLIANT_HILLSTONE_CONFIG)
    identity = extract_identity(COMPLIANT_HILLSTONE_CONFIG, baseline)

    assert identity.vendor == "hillstone_stoneos"
    assert identity.os_family == "stoneos"
    assert identity.hostname.value == "HillstoneFW01"
    assert identity.os_version.value == "5.5"
    
    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against Hillstone."""
    parser = HillstoneStoneOSParser()
    ruleset = load_framework("CIS", "hillstone_stoneos")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_HILLSTONE_CONFIG)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-HILLSTONE-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-HILLSTONE-IDLE-TIMEOUT"].status == Status.PASS
    assert compliant_results["CIS-HILLSTONE-NO-HTTP-SERVER"].status == Status.PASS
    assert compliant_results["CIS-HILLSTONE-SYSLOG-DESTINATION"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_HILLSTONE_CONFIG)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-HILLSTONE-NO-HTTP-SERVER"].status == Status.FAIL
    assert insecure_results["CIS-HILLSTONE-IDLE-TIMEOUT"].status == Status.FAIL
    assert insecure_results["CIS-HILLSTONE-SYSLOG-DESTINATION"].status == Status.NEEDS_REVIEW


def test_adversarial_inputs():
    """Verify Hillstone parser handling of adversarial comments and values."""
    parser = HillstoneStoneOSParser()

    # Comment containing secure keywords must be ignored
    comment_config = """
    ! access http
    access http
    """
    baseline = parser.parse(comment_config)
    assert baseline.http_server_enabled.value is True

    # Unknown fields return needs review
    partial_config = """
    hostname HillstoneTest
    """
    baseline = parser.parse(partial_config)
    assert baseline.logging_enabled.detected is False


def test_vendor_isolation():
    """Verify isolation of parser state across multiple platforms."""
    parser_hs = HillstoneStoneOSParser()
    from auditor.parsers.cisco_ios import CiscoIOSParser
    parser_cisco = CiscoIOSParser()

    hs_baseline = parser_hs.parse(COMPLIANT_HILLSTONE_CONFIG)
    cisco_baseline = parser_cisco.parse("hostname CiscoFW\n")

    assert hs_baseline.provenance.vendor == "hillstone"
    assert cisco_baseline.provenance.vendor == "cisco"

    assert hs_baseline.hostname.value == "HillstoneFW01"
    assert cisco_baseline.hostname.value == "CiscoFW"
