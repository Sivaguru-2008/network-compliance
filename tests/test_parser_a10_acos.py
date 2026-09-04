"""Tests for A10 Networks ACOS configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.a10_acos import A10ACOSParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_ACOS_CONFIG = """
! ACOS Version 4.1.4
hostname A10FW01
web-service server disable
enable-management service https
enable-management service ssh
console timeout 10
ip dns primary 8.8.8.8
ip dns secondary 8.8.4.4
ntp server pool.ntp.org
logging host 192.168.1.100
"""

INSECURE_ACOS_CONFIG = """
! ACOS Version 4.1.4
hostname InsecureA10
enable-management service http
web-service secure-server disable
enable-management service telnet
no enable-management service ssh
console timeout 60
"""


def test_acos_detection():
    """Verify that detect() correctly identifies A10 ACOS configuration text."""
    parser = A10ACOSParser()
    assert parser.detect(COMPLIANT_ACOS_CONFIG) >= 0.70
    assert parser.detect(INSECURE_ACOS_CONFIG) >= 0.70

    # Ensure other formats are rejected
    generic_ini = """[Settings]
    LogLevel=Debug
    """
    assert parser.detect(generic_ini) == 0.0

    cisco_text = "line vty 0 4\n ip http server\n"
    assert parser.detect(cisco_text) == 0.0


def test_compliant_parser_normalization():
    """Verify the compliant config is parsed correctly into baseline model."""
    parser = A10ACOSParser()
    baseline = parser.parse(COMPLIANT_ACOS_CONFIG)

    assert baseline.provenance.vendor == "a10"
    assert baseline.provenance.os_family == "acos"
    
    assert baseline.hostname.value == "A10FW01"
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
    parser = A10ACOSParser()
    baseline = parser.parse(INSECURE_ACOS_CONFIG)

    assert baseline.hostname.value == "InsecureA10"
    assert baseline.ssh_enabled.value is False
    assert set(baseline.vty_transport_input.value) == set()
    assert baseline.telnet_enabled.value is True
    assert baseline.http_server_enabled.value is True
    assert baseline.https_server_enabled.value is False
    assert baseline.vty_exec_timeout_seconds.value == 3600


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = A10ACOSParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = A10ACOSParser()
    baseline = parser.parse(COMPLIANT_ACOS_CONFIG)
    identity = extract_identity(COMPLIANT_ACOS_CONFIG, baseline)

    assert identity.vendor == "a10_acos"
    assert identity.os_family == "acos"
    assert identity.hostname.value == "A10FW01"
    assert identity.os_version.value == "4.1.4"
    
    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against A10."""
    parser = A10ACOSParser()
    ruleset = load_framework("CIS", "a10_acos")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_ACOS_CONFIG)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-A10-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-A10-IDLE-TIMEOUT"].status == Status.PASS
    assert compliant_results["CIS-A10-NO-HTTP-SERVER"].status == Status.PASS
    assert compliant_results["CIS-A10-SYSLOG-DESTINATION"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_ACOS_CONFIG)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-A10-NO-HTTP-SERVER"].status == Status.FAIL
    assert insecure_results["CIS-A10-IDLE-TIMEOUT"].status == Status.FAIL
    assert insecure_results["CIS-A10-SYSLOG-DESTINATION"].status == Status.NEEDS_REVIEW


def test_adversarial_inputs():
    """Verify A10 parser handling of adversarial comments and values."""
    parser = A10ACOSParser()

    # Comment containing secure keywords must be ignored
    comment_config = """
    ! enable-management service http
    enable-management service http
    """
    baseline = parser.parse(comment_config)
    assert baseline.http_server_enabled.value is True

    # Unknown fields return needs review
    partial_config = """
    hostname A10Test
    """
    baseline = parser.parse(partial_config)
    assert baseline.logging_enabled.detected is False


def test_vendor_isolation():
    """Verify isolation of parser state across multiple platforms."""
    parser_a10 = A10ACOSParser()
    from auditor.parsers.cisco_ios import CiscoIOSParser
    parser_cisco = CiscoIOSParser()

    a10_baseline = parser_a10.parse(COMPLIANT_ACOS_CONFIG)
    cisco_baseline = parser_cisco.parse("hostname CiscoFW\n")

    assert a10_baseline.provenance.vendor == "a10"
    assert cisco_baseline.provenance.vendor == "cisco"

    assert a10_baseline.hostname.value == "A10FW01"
    assert cisco_baseline.hostname.value == "CiscoFW"
