"""Tests for the SonicWall SonicOS configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.sonicwall_sonicos import SonicWallSonicOSParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_SONICOS_CLI = """
! SonicOS Preference Configuration
hostname SonicFW-01
no web-management allow-http
web-management https-port 443
management ssh
idle-logout-time 10
disclaimer enable
dns-server primary 8.8.8.8
dns-server secondary 8.8.4.4
ntp-server 10.0.0.1
syslog-server 192.168.1.50
snmp-server community read-only-comm
"""

INSECURE_SONICOS_CLI = """
! SonicOS Preference Configuration
hostname InsecureSonic
web-management allow-http
web-management https-port 8080
no management ssh
idle-logout-time 60
snmp-server community public
"""


def test_sonicos_detection():
    """Verify that detect() correctly identifies SonicOS configurations."""
    parser = SonicWallSonicOSParser()
    assert parser.detect(COMPLIANT_SONICOS_CLI) >= 0.80
    assert parser.detect(INSECURE_SONICOS_CLI) >= 0.80

    # Ensure other XML / CLI configs are rejected
    cisco_text = "line vty 0 4\n ip http server\n"
    assert parser.detect(cisco_text) == 0.0

    watchguard_xml = "<configuration><abs-policy-list><policy></policy></abs-policy-list></configuration>"
    assert parser.detect(watchguard_xml) == 0.0


def test_compliant_parser_normalization():
    """Verify the compliant config is parsed correctly into baseline model."""
    parser = SonicWallSonicOSParser()
    baseline = parser.parse(COMPLIANT_SONICOS_CLI)

    assert baseline.provenance.vendor == "sonicwall"
    assert baseline.provenance.os_family == "sonicos"
    
    assert baseline.hostname.value == "SonicFW-01"
    assert baseline.ssh_enabled.value is True
    assert set(baseline.vty_transport_input.value) == {"ssh"}
    assert baseline.telnet_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 600
    assert baseline.login_banner_present.value is True
    assert baseline.dns_servers.value == ["8.8.8.8", "8.8.4.4"]
    assert baseline.ntp_servers.value == ["10.0.0.1"]
    assert baseline.logging_enabled.value is True
    assert baseline.logging_hosts.value == ["192.168.1.50"]
    assert len(baseline.snmp_communities.value) == 1
    assert baseline.snmp_communities.value[0].name == "read-only-comm"


def test_insecure_parser_normalization():
    """Verify the insecure config is parsed correctly into baseline model."""
    parser = SonicWallSonicOSParser()
    baseline = parser.parse(INSECURE_SONICOS_CLI)

    assert baseline.hostname.value == "InsecureSonic"
    assert baseline.ssh_enabled.value is False
    assert set(baseline.vty_transport_input.value) == set()
    assert baseline.http_server_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 3600
    assert len(baseline.snmp_communities.value) == 1
    assert baseline.snmp_communities.value[0].name == "public"


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = SonicWallSonicOSParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = SonicWallSonicOSParser()
    config_with_version = "! SonicOS Enhanced 7.1.1-7058\nhostname SonicFW-01\n"
    baseline = parser.parse(config_with_version)
    identity = extract_identity(config_with_version, baseline)

    assert identity.vendor == "sonicwall_sonicos"
    assert identity.os_family == "sonicos"
    assert identity.hostname.value == "SonicFW-01"
    assert identity.os_version.value == "7.1.1-7058"
    assert identity.os_version.detected is True
    
    # Missing fields must return unknown
    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against SonicOS."""
    parser = SonicWallSonicOSParser()
    ruleset = load_framework("CIS", "sonicwall_sonicos")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_SONICOS_CLI)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-SONICWALL-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-SONICWALL-IDLE-TIMEOUT"].status == Status.PASS
    assert compliant_results["CIS-SONICWALL-NO-HTTP-SERVER"].status == Status.PASS
    assert compliant_results["CIS-SONICWALL-LOGIN-BANNER"].status == Status.PASS
    assert compliant_results["CIS-SONICWALL-NTP-CONFIGURED"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_SONICOS_CLI)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-SONICWALL-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert insecure_results["CIS-SONICWALL-IDLE-TIMEOUT"].status == Status.FAIL # timeout 60 minutes
    assert insecure_results["CIS-SONICWALL-NO-HTTP-SERVER"].status == Status.FAIL
    assert insecure_results["CIS-SONICWALL-SNMP-NO-DEFAULT-COMMUNITY"].status == Status.FAIL # public community


def test_adversarial_false_pass_attacks():
    """Verify that secure keywords inside comments or malformed options do not trigger False-PASS."""
    parser = SonicWallSonicOSParser()
    ruleset = load_framework("CIS", "sonicwall_sonicos")
    engine = ComplianceEngine(ruleset)

    adversarial_cli = """
    ! no web-management allow-http
    web-management allow-http
    """
    baseline = parser.parse(adversarial_cli)
    assert baseline.http_server_enabled.value is True

    results = {r.rule_id: r for r in engine.evaluate(baseline)}
    assert results["CIS-SONICWALL-NO-HTTP-SERVER"].status == Status.FAIL
