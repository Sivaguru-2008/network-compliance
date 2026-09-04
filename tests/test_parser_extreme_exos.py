"""Tests for the Extreme Networks EXOS (exos) configuration parser, identity extractor, and rule mapping."""

import pytest
from pathlib import Path

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.models.observation import Origin
from auditor.parsers import ParserError
from auditor.parsers.extreme_exos import ExtremeEXOSParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_CONFIG = """# Software Version: 32.6.1.5
configure switch sysname CORE-EX-01
enable ssh2
disable telnet
configure cli idle-timeout 10
enable cli idle-timeout
disable web
enable web https
create account admin admin encrypted "$6$rounds=65536$salt$encryptedpasswordhash"
enable radius mgmt-access
configure snmp add community secret-community readonly
configure syslog add 192.168.1.50 vr VR-Default
enable log target syslog 192.168.1.50 vr VR-Default
configure ntp server add 10.0.0.1 vr VR-Default
enable ntp
configure dns-client add name-server 8.8.8.8
configure account all password-policy min-length 12
configure account all password-policy char-validation all-char-groups
configure banner
WARNING: Authorized access only!
configure ssh2 access-profile SSH-ACL
"""

INSECURE_CONFIG = """# Software Version: 32.6.1.5
configure switch sysname INSECURE-EX-01
disable ssh2
enable telnet
disable cli idle-timeout
configure snmp add community public readonly
configure snmp add community private readwrite
configure account all password-policy min-length 6
"""


def test_exos_detection():
    """Verify that detect() correctly identifies Extreme EXOS configuration."""
    parser = ExtremeEXOSParser()
    assert parser.detect(COMPLIANT_CONFIG) >= 0.50
    assert parser.detect(INSECURE_CONFIG) >= 0.30

    # Ensure other vendor configurations are rejected (score < 0.3)
    cisco_text = "line vty 0 4\n ip http server\n"
    assert parser.detect(cisco_text) == 0.0

    junos_text = "system {\n    host-name branch-rtr;\n}\n"
    assert parser.detect(junos_text) == 0.0

    fortios_text = "config system global\n    set hostname FGT\nend\n"
    assert parser.detect(fortios_text) == 0.0


def test_compliant_parser_normalization():
    """Verify the compliant config is parsed correctly into baseline model."""
    parser = ExtremeEXOSParser()
    baseline = parser.parse(COMPLIANT_CONFIG)

    assert baseline.provenance.vendor == "extreme"
    assert baseline.provenance.os_family == "exos"
    
    assert baseline.hostname.value == "CORE-EX-01"
    assert baseline.ssh_enabled.value is True
    assert baseline.ssh_version.value == 2
    assert baseline.telnet_enabled.value is False
    assert set(baseline.vty_transport_input.value) == {"ssh"}
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 600
    assert baseline.login_banner_present.value is True
    assert baseline.enable_secret_set.value is True
    assert baseline.password_encryption.value is True
    assert baseline.password_min_length.value == 12
    assert baseline.aaa_enabled.value is True
    assert baseline.logging_enabled.value is True
    assert "192.168.1.50" in baseline.logging_hosts.value
    assert baseline.ntp_servers.value == ["10.0.0.1"]
    assert baseline.dns_servers.value == ["8.8.8.8"]
    assert baseline.management_acl_applied.value is True


def test_insecure_parser_normalization():
    """Verify that insecure configuration is normalized with appropriate values."""
    parser = ExtremeEXOSParser()
    baseline = parser.parse(INSECURE_CONFIG)

    assert baseline.hostname.value == "INSECURE-EX-01"
    assert baseline.ssh_enabled.value is False
    assert baseline.telnet_enabled.value is True
    assert set(baseline.vty_transport_input.value) == {"telnet"}
    assert baseline.https_server_enabled.value is False
    assert baseline.vty_exec_timeout_seconds.value == 0  # disabled / never time out
    assert baseline.login_banner_present.value is False
    assert baseline.password_min_length.value == 6
    assert baseline.aaa_enabled.value is False
    assert baseline.logging_hosts.value == []
    
    communities = baseline.snmp_communities.value
    assert len(communities) == 2
    assert communities[0].name == "public"
    assert communities[0].access == "ro"
    assert communities[1].name == "private"
    assert communities[1].access == "rw"


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = ExtremeEXOSParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = ExtremeEXOSParser()
    baseline = parser.parse(COMPLIANT_CONFIG)
    identity = extract_identity(COMPLIANT_CONFIG, baseline)

    assert identity.vendor == "extreme_exos"
    assert identity.os_family == "exos"
    assert identity.hostname.value == "CORE-EX-01"
    assert identity.os_version.value == "32.6.1.5"
    assert identity.os_version.detected is True
    
    # Missing fields must return unknown
    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against Extreme EXOS."""
    parser = ExtremeEXOSParser()
    ruleset = load_framework("CIS", "extreme_exos")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_CONFIG)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-EXOS-AAA-CENTRALISED"].status == Status.PASS
    assert compliant_results["CIS-EXOS-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-EXOS-IDLE-TIMEOUT"].status == Status.PASS
    assert compliant_results["CIS-EXOS-PASSWORD-HASHED"].status == Status.PASS
    assert compliant_results["CIS-EXOS-SNMP-NO-DEFAULT-COMMUNITY"].status == Status.PASS
    assert compliant_results["CIS-EXOS-NO-HTTP-SERVER"].status == Status.PASS
    assert compliant_results["CIS-EXOS-SSH-V2"].status == Status.PASS
    assert compliant_results["CIS-EXOS-SYSLOG-DESTINATION"].status == Status.PASS
    assert compliant_results["CIS-EXOS-MGMT-ACL"].status == Status.PASS
    assert compliant_results["CIS-EXOS-LOGIN-BANNER"].status == Status.PASS
    assert compliant_results["CIS-EXOS-PASSWORD-MIN-LENGTH"].status == Status.PASS
    assert compliant_results["CIS-EXOS-NTP-CONFIGURED"].status == Status.PASS
    assert compliant_results["CIS-EXOS-SNMP-NO-WRITE"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_CONFIG)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-EXOS-AAA-CENTRALISED"].status == Status.FAIL
    assert insecure_results["CIS-EXOS-NO-CLEARTEXT-SERVICES"].status == Status.FAIL
    assert insecure_results["CIS-EXOS-IDLE-TIMEOUT"].status == Status.FAIL
    assert insecure_results["CIS-EXOS-PASSWORD-HASHED"].status == Status.FAIL # encrypted password not set
    assert insecure_results["CIS-EXOS-SNMP-NO-DEFAULT-COMMUNITY"].status == Status.FAIL # has public/private
    assert insecure_results["CIS-EXOS-NO-HTTP-SERVER"].status == Status.PASS # HTTP server defaults disabled
    assert insecure_results["CIS-EXOS-SSH-V2"].status == Status.PASS # SSH disabled, which is secure
    assert insecure_results["CIS-EXOS-SYSLOG-DESTINATION"].status == Status.PASS # local buffer enabled by default
    assert insecure_results["CIS-EXOS-MGMT-ACL"].status == Status.FAIL
    assert insecure_results["CIS-EXOS-LOGIN-BANNER"].status == Status.FAIL
    assert insecure_results["CIS-EXOS-PASSWORD-MIN-LENGTH"].status == Status.FAIL
    assert insecure_results["CIS-EXOS-NTP-CONFIGURED"].status == Status.FAIL
    assert insecure_results["CIS-EXOS-SNMP-NO-WRITE"].status == Status.FAIL # private is readwrite (rw)


def test_adversarial_false_pass_attacks():
    """Verify that secure keywords inside comments or malformed options do not trigger False-PASS."""
    parser = ExtremeEXOSParser()
    ruleset = load_framework("CIS", "extreme_exos")
    engine = ComplianceEngine(ruleset)

    # Insecure with secure-looking comments
    adversarial_config = """# Software Version: 32.6.1.5
configure switch sysname ATTACKER-EX-01
# enable ssh2
# enable radius mgmt-access
# configure banner
# configure cli idle-timeout 5
# configure account all password-policy min-length 15
# configure account all password-policy char-validation all-char-groups
"""
    baseline = parser.parse(adversarial_config)
    
    assert baseline.ssh_enabled.value is False
    assert baseline.aaa_enabled.value is False
    assert baseline.login_banner_present.value is False
    assert baseline.password_min_length.value == 0
    assert baseline.vty_exec_timeout_seconds.value == 1200  # Default 20 min

    results = {r.rule_id: r for r in engine.evaluate(baseline)}
    assert results["CIS-EXOS-AAA-CENTRALISED"].status == Status.FAIL
    assert results["CIS-EXOS-NO-CLEARTEXT-SERVICES"].status == Status.FAIL # Telnet enabled by default
    assert results["CIS-EXOS-IDLE-TIMEOUT"].status == Status.FAIL # 1200 > 600
    assert results["CIS-EXOS-PASSWORD-MIN-LENGTH"].status == Status.FAIL
