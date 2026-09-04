"""Tests for Alcatel-Lucent Enterprise AOS configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.alcatel_aos import AlcatelAOSParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_AOS_CONFIG = """! IP Setup
system name "ale-switch-1"
! Service Configuration
aaa authentication default local
ip service ssh
no ip service telnet
no ip service http
ip service secure-http
session timeout cli 10
session banner cli /flash/switch/banner.txt
user password-size min 12
user password-policy min-uppercase 1
user password-policy min-lowercase 1
user password-policy min-digit 1
user password-policy min-nonalpha 1
user password-expiration 90
swlog output socket 192.168.10.50
ntp server 192.168.1.100
ip name-server 8.8.8.8 8.8.4.4
policy rule AllowMgmt destination network group Switch
"""

INSECURE_AOS_CONFIG = """system name "insecure-switch"
ip service telnet
no ip service ssh
session timeout cli 0
user password-expiration disable
"""


def test_alcatel_detection():
    """Verify that detect() correctly identifies Alcatel AOS configuration outputs."""
    parser = AlcatelAOSParser()
    assert parser.detect(COMPLIANT_AOS_CONFIG) == 1.0
    assert parser.detect(INSECURE_AOS_CONFIG) == 1.0

    # Ensure other formats are rejected
    cisco_text = "line vty 0 4\n transport input ssh\n"
    assert parser.detect(cisco_text) == 0.0

    juniper_text = "system {\n    host-name junos-fw;\n}\n"
    assert parser.detect(juniper_text) == 0.0


def test_compliant_parser_normalization():
    """Verify the compliant config is parsed correctly into baseline model."""
    parser = AlcatelAOSParser()
    baseline = parser.parse(COMPLIANT_AOS_CONFIG)

    assert baseline.provenance.vendor == "alcatel_lucent_enterprise"
    assert baseline.provenance.os_family == "aos"

    assert baseline.hostname.value == "ale-switch-1"
    assert baseline.ssh_enabled.value is True
    assert set(baseline.vty_transport_input.value) == {"ssh"}
    assert baseline.telnet_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 600
    assert baseline.dns_servers.value == ["8.8.8.8", "8.8.4.4"]
    assert baseline.ntp_servers.value == ["192.168.1.100"]
    assert baseline.logging_enabled.value is True
    assert baseline.logging_hosts.value == ["192.168.10.50"]
    assert baseline.password_min_length.value == 12
    assert baseline.password_min_uppercase.value == 1
    assert baseline.password_min_lowercase.value == 1
    assert baseline.password_min_numeric.value == 1
    assert baseline.password_min_special.value == 1
    assert baseline.password_max_age_days.value == 90
    assert baseline.management_acl_applied.value is True
    assert baseline.login_banner_present.value is True


def test_insecure_parser_normalization():
    """Verify the insecure config is parsed correctly into baseline model."""
    parser = AlcatelAOSParser()
    baseline = parser.parse(INSECURE_AOS_CONFIG)

    assert baseline.hostname.value == "insecure-switch"
    assert baseline.ssh_enabled.value is False
    assert set(baseline.vty_transport_input.value) == {"telnet"}
    assert baseline.telnet_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 0
    assert baseline.password_max_age_days.value == 0


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = AlcatelAOSParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = AlcatelAOSParser()
    baseline = parser.parse(COMPLIANT_AOS_CONFIG)
    identity = extract_identity(COMPLIANT_AOS_CONFIG, baseline)

    assert identity.vendor == "alcatel_aos"
    assert identity.os_family == "aos"
    assert identity.hostname.value == "ale-switch-1"
    assert identity.os_version.detected is False

    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against Alcatel AOS."""
    parser = AlcatelAOSParser()
    ruleset = load_framework("CIS", "alcatel_aos")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_AOS_CONFIG)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-ALCATEL-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-ALCATEL-IDLE-TIMEOUT"].status == Status.PASS
    assert compliant_results["CIS-ALCATEL-NO-HTTP-SERVER"].status == Status.PASS
    assert compliant_results["CIS-ALCATEL-SYSLOG-DESTINATION"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_AOS_CONFIG)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-ALCATEL-NO-CLEARTEXT-SERVICES"].status == Status.FAIL
    assert insecure_results["CIS-ALCATEL-IDLE-TIMEOUT"].status == Status.FAIL


def test_adversarial_inputs():
    """Verify Alcatel parser handling of adversarial comments and values."""
    parser = AlcatelAOSParser()

    # Comment containing secure-looking tags must be ignored
    comment_config = """! session timeout cli 10
    system name "ale-cmt"
    session timeout cli 5
    """
    baseline = parser.parse(comment_config)
    assert baseline.vty_exec_timeout_seconds.value == 300

    # Unknown fields return needs review
    partial_config = """system name "ale-partial"
    session timeout cli 10
    """
    baseline = parser.parse(partial_config)
    assert baseline.logging_enabled.detected is False


def test_vendor_isolation():
    """Verify isolation of parser state across multiple platforms."""
    parser_alcatel = AlcatelAOSParser()
    from auditor.parsers.cisco_ios import CiscoIOSParser
    parser_cisco = CiscoIOSParser()

    alcatel_baseline = parser_alcatel.parse(COMPLIANT_AOS_CONFIG)
    cisco_baseline = parser_cisco.parse("hostname CiscoRouter\n")

    assert alcatel_baseline.provenance.vendor == "alcatel_lucent_enterprise"
    assert cisco_baseline.provenance.vendor == "cisco"

    assert alcatel_baseline.hostname.value == "ale-switch-1"
    assert cisco_baseline.hostname.value == "CiscoRouter"
