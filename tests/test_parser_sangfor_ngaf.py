"""Tests for Sangfor NGAF configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.sangfor_ngaf import SangforNGAFParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_SANGFOR_CONFIG = """
# Sangfor NGAF status configuration
System Name: SangforFW01
Firmware Version: NGAF 8.0.95
HTTP Service: disable
HTTPS Service: enable
SSH Service: enable
Session Timeout: 600
DNS Server: 8.8.8.8,8.8.4.4
NTP Server: pool.ntp.org
Syslog Server: 192.168.1.50
"""

INSECURE_SANGFOR_CONFIG = """
# Sangfor NGAF status configuration
System Name: InsecureSangfor
HTTP Service: enable
HTTPS Service: disable
SSH Service: disable
Session Timeout: 3600
"""


def test_sangfor_detection():
    """Verify that detect() correctly identifies Sangfor NGAF configuration status logs."""
    parser = SangforNGAFParser()
    assert parser.detect(COMPLIANT_SANGFOR_CONFIG) >= 0.70
    assert parser.detect(INSECURE_SANGFOR_CONFIG) >= 0.70

    # Ensure other formats are rejected
    generic_ini = """[Settings]
    LogLevel=Debug
    """
    assert parser.detect(generic_ini) == 0.0

    cisco_text = "line vty 0 4\n ip http server\n"
    assert parser.detect(cisco_text) == 0.0


def test_compliant_parser_normalization():
    """Verify the compliant config is parsed correctly into baseline model."""
    parser = SangforNGAFParser()
    baseline = parser.parse(COMPLIANT_SANGFOR_CONFIG)

    assert baseline.provenance.vendor == "sangfor"
    assert baseline.provenance.os_family == "ngaf"
    
    assert baseline.hostname.value == "SangforFW01"
    assert baseline.ssh_enabled.value is True
    assert set(baseline.vty_transport_input.value) == {"ssh"}
    assert baseline.telnet_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 600
    assert baseline.dns_servers.value == ["8.8.8.8", "8.8.4.4"]
    assert baseline.ntp_servers.value == ["pool.ntp.org"]
    assert baseline.logging_enabled.value is True
    assert baseline.logging_hosts.value == ["192.168.1.50"]


def test_insecure_parser_normalization():
    """Verify the insecure config is parsed correctly into baseline model."""
    parser = SangforNGAFParser()
    baseline = parser.parse(INSECURE_SANGFOR_CONFIG)

    assert baseline.hostname.value == "InsecureSangfor"
    assert baseline.ssh_enabled.value is False
    assert set(baseline.vty_transport_input.value) == set()
    assert baseline.http_server_enabled.value is True
    assert baseline.https_server_enabled.value is False
    assert baseline.vty_exec_timeout_seconds.value == 3600


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = SangforNGAFParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = SangforNGAFParser()
    baseline = parser.parse(COMPLIANT_SANGFOR_CONFIG)
    identity = extract_identity(COMPLIANT_SANGFOR_CONFIG, baseline)

    assert identity.vendor == "sangfor_ngaf"
    assert identity.os_family == "ngaf"
    assert identity.hostname.value == "SangforFW01"
    assert identity.os_version.value == "8.0.95"
    
    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against Sangfor."""
    parser = SangforNGAFParser()
    ruleset = load_framework("CIS", "sangfor_ngaf")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_SANGFOR_CONFIG)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-SANGFOR-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-SANGFOR-IDLE-TIMEOUT"].status == Status.PASS
    assert compliant_results["CIS-SANGFOR-NO-HTTP-SERVER"].status == Status.PASS
    assert compliant_results["CIS-SANGFOR-SYSLOG-DESTINATION"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_SANGFOR_CONFIG)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-SANGFOR-NO-HTTP-SERVER"].status == Status.FAIL
    assert insecure_results["CIS-SANGFOR-IDLE-TIMEOUT"].status == Status.FAIL
    assert insecure_results["CIS-SANGFOR-SYSLOG-DESTINATION"].status == Status.NEEDS_REVIEW


def test_adversarial_inputs():
    """Verify Sangfor NGAF parser handling of adversarial comments and values."""
    parser = SangforNGAFParser()

    # Comment containing secure keywords must be ignored
    comment_config = """
    # HTTP Service: disable
    HTTP Service: enable
    """
    baseline = parser.parse(comment_config)
    assert baseline.http_server_enabled.value is True

    # Unknown fields return needs review
    partial_config = """
    System Name: SangforTest
    """
    baseline = parser.parse(partial_config)
    assert baseline.logging_enabled.detected is False


def test_vendor_isolation():
    """Verify isolation of parser state across multiple platforms."""
    parser_sf = SangforNGAFParser()
    from auditor.parsers.cisco_ios import CiscoIOSParser
    parser_cisco = CiscoIOSParser()

    sf_baseline = parser_sf.parse(COMPLIANT_SANGFOR_CONFIG)
    cisco_baseline = parser_cisco.parse("hostname CiscoFW\n")

    assert sf_baseline.provenance.vendor == "sangfor"
    assert cisco_baseline.provenance.vendor == "cisco"

    assert sf_baseline.hostname.value == "SangforFW01"
    assert cisco_baseline.hostname.value == "CiscoFW"
