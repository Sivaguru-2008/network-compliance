"""Tests for the Stormshield SNS configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.stormshield_sns import StormshieldSNSParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_SNS_CONFIG = """
# Stormshield Network Security 4.3.4
[System]
Name=StormshieldFW01

[WebAdmin]
State=1
Port=443
HTTPEnable=0

[Console]
SSHEnable=1
Timeout=600

[DNS]
Primary=8.8.8.8
Secondary=8.8.4.4

[Time]
Server1=pool.ntp.org

[Syslog]
State=1
Server=192.168.1.50
"""

INSECURE_SNS_CONFIG = """
# Stormshield Network Security 4.3.4
[System]
Name=InsecureStormshield

[WebAdmin]
State=1
Port=8080
HTTPEnable=1

[Console]
SSHEnable=0
Timeout=3600

[Syslog]
State=0
Server=192.168.1.50
"""


def test_sns_detection():
    """Verify that detect() correctly identifies Stormshield SNS configuration blocks."""
    parser = StormshieldSNSParser()
    assert parser.detect(COMPLIANT_SNS_CONFIG) >= 0.80
    assert parser.detect(INSECURE_SNS_CONFIG) >= 0.80

    # Test generic config format without specific headers
    generic_ini = """[Settings]
    LogLevel=Debug
    Output=stdout
    """
    assert parser.detect(generic_ini) == 0.0

    # Test unrelated formats
    cisco_text = "line vty 0 4\n ip http server\n"
    assert parser.detect(cisco_text) == 0.0


def test_compliant_parser_normalization():
    """Verify the compliant config is parsed correctly into baseline model."""
    parser = StormshieldSNSParser()
    baseline = parser.parse(COMPLIANT_SNS_CONFIG)

    assert baseline.provenance.vendor == "stormshield"
    assert baseline.provenance.os_family == "sns"
    
    assert baseline.hostname.value == "StormshieldFW01"
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
    parser = StormshieldSNSParser()
    baseline = parser.parse(INSECURE_SNS_CONFIG)

    assert baseline.hostname.value == "InsecureStormshield"
    assert baseline.ssh_enabled.value is False
    assert set(baseline.vty_transport_input.value) == set()
    assert baseline.http_server_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 3600
    assert baseline.logging_enabled.value is False


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = StormshieldSNSParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = StormshieldSNSParser()
    baseline = parser.parse(COMPLIANT_SNS_CONFIG)
    identity = extract_identity(COMPLIANT_SNS_CONFIG, baseline)

    assert identity.vendor == "stormshield_sns"
    assert identity.os_family == "sns"
    assert identity.hostname.value == "StormshieldFW01"
    assert identity.os_version.value == "4.3.4"
    
    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against Stormshield SNS."""
    parser = StormshieldSNSParser()
    ruleset = load_framework("CIS", "stormshield_sns")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_SNS_CONFIG)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-STORMSHIELD-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-STORMSHIELD-IDLE-TIMEOUT"].status == Status.PASS
    assert compliant_results["CIS-STORMSHIELD-NO-HTTP-SERVER"].status == Status.PASS
    assert compliant_results["CIS-STORMSHIELD-SYSLOG-DESTINATION"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_SNS_CONFIG)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-STORMSHIELD-NO-HTTP-SERVER"].status == Status.FAIL
    assert insecure_results["CIS-STORMSHIELD-IDLE-TIMEOUT"].status == Status.FAIL
    assert insecure_results["CIS-STORMSHIELD-SYSLOG-DESTINATION"].status == Status.FAIL
