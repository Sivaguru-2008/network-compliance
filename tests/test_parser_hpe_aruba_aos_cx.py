"""Tests for the HPE Aruba AOS-CX (aos_cx) configuration parser, identity extractor, and rule mapping."""

import pytest
from pathlib import Path

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.models.observation import Origin
from auditor.parsers import ParserError
from auditor.parsers.hpe_aruba_aos_cx import HPEArubaAosCxParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_CONFIG = """!Version AOS-CX 10.12.0001
hostname CORE-CX-01
ssh server vrf default
ssh server vrf mgmt
session-timeout 10
https-server vrf default
https-server vrf mgmt
user admin group administrators password ciphertext $6$rounds=65536$salt$encryptedpasswordhash
aaa authentication login default local
snmp-server community secret-community
  access-level ro
snmp-server community secure-ro acl SNMP-ACL
  access-level ro
logging 192.168.1.50 vrf mgmt
ntp server 10.0.0.1 prefer
ntp enable
ip dns server-address 8.8.8.8
password-complexity
    enable
    min-length 12
banner motd ^
WARNING: Authorized access only!
^
ssh server allow-list
    ip 10.0.0.0/24
    enable
"""

INSECURE_CONFIG = """!Version AOS-CX 10.12.0001
hostname INSECURE-CX-01
telnet server vrf default
session-timeout 0
user admin group administrators password ciphertext $6$rounds=65536$salt$encryptedpasswordhash
snmp-server community public
  access-level rw
snmp-server community private
  access-level rw
password-complexity
    min-length 6
"""


def test_aruba_detection():
    """Verify that detect() correctly identifies AOS-CX configuration."""
    parser = HPEArubaAosCxParser()
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
    parser = HPEArubaAosCxParser()
    baseline = parser.parse(COMPLIANT_CONFIG)

    assert baseline.provenance.vendor == "hpe_aruba"
    assert baseline.provenance.os_family == "aos_cx"
    
    assert baseline.hostname.value == "CORE-CX-01"
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
    parser = HPEArubaAosCxParser()
    baseline = parser.parse(INSECURE_CONFIG)

    assert baseline.hostname.value == "INSECURE-CX-01"
    assert baseline.ssh_enabled.value is False
    assert baseline.telnet_enabled.value is True
    assert set(baseline.vty_transport_input.value) == {"telnet"}
    assert baseline.https_server_enabled.value is False
    assert baseline.vty_exec_timeout_seconds.value == 0  # no timeout / never
    assert baseline.login_banner_present.value is False
    assert baseline.password_min_length.value == 0  # not enabled
    assert baseline.aaa_enabled.value is False
    assert baseline.logging_hosts.value == []
    
    communities = baseline.snmp_communities.value
    assert len(communities) == 2
    assert communities[0].name == "public"
    assert communities[0].access == "rw"
    assert communities[1].name == "private"
    assert communities[1].access == "rw"


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = HPEArubaAosCxParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = HPEArubaAosCxParser()
    baseline = parser.parse(COMPLIANT_CONFIG)
    identity = extract_identity(COMPLIANT_CONFIG, baseline)

    assert identity.vendor == "hpe_aruba_aos_cx"
    assert identity.os_family == "aos_cx"
    assert identity.hostname.value == "CORE-CX-01"
    assert identity.os_version.value == "10.12.0001"
    assert identity.os_version.detected is True
    
    # Missing fields must return unknown
    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against AOS-CX."""
    parser = HPEArubaAosCxParser()
    ruleset = load_framework("CIS", "hpe_aruba_aos_cx")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_CONFIG)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-AOSCX-AAA-CENTRALISED"].status == Status.PASS
    assert compliant_results["CIS-AOSCX-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-AOSCX-IDLE-TIMEOUT"].status == Status.PASS
    assert compliant_results["CIS-AOSCX-PASSWORD-HASHED"].status == Status.PASS
    assert compliant_results["CIS-AOSCX-SNMP-NO-DEFAULT-COMMUNITY"].status == Status.PASS
    assert compliant_results["CIS-AOSCX-NO-HTTP-SERVER"].status == Status.PASS
    assert compliant_results["CIS-AOSCX-SSH-V2"].status == Status.PASS
    assert compliant_results["CIS-AOSCX-SYSLOG-DESTINATION"].status == Status.PASS
    assert compliant_results["CIS-AOSCX-MGMT-ACL"].status == Status.PASS
    assert compliant_results["CIS-AOSCX-LOGIN-BANNER"].status == Status.PASS
    assert compliant_results["CIS-AOSCX-PASSWORD-MIN-LENGTH"].status == Status.PASS
    assert compliant_results["CIS-AOSCX-NTP-CONFIGURED"].status == Status.PASS
    assert compliant_results["CIS-AOSCX-SNMP-NO-WRITE"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_CONFIG)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-AOSCX-AAA-CENTRALISED"].status == Status.FAIL
    assert insecure_results["CIS-AOSCX-NO-CLEARTEXT-SERVICES"].status == Status.FAIL
    assert insecure_results["CIS-AOSCX-IDLE-TIMEOUT"].status == Status.FAIL
    assert insecure_results["CIS-AOSCX-PASSWORD-HASHED"].status == Status.PASS # AOS-CX hashes passwords by default
    assert insecure_results["CIS-AOSCX-SNMP-NO-DEFAULT-COMMUNITY"].status == Status.FAIL # has public/private
    assert insecure_results["CIS-AOSCX-NO-HTTP-SERVER"].status == Status.PASS # HTTP server always disabled
    assert insecure_results["CIS-AOSCX-SSH-V2"].status == Status.PASS # SSH disabled, which is secure
    assert insecure_results["CIS-AOSCX-SYSLOG-DESTINATION"].status == Status.PASS # local buffer enabled by default
    assert insecure_results["CIS-AOSCX-MGMT-ACL"].status == Status.FAIL
    assert insecure_results["CIS-AOSCX-LOGIN-BANNER"].status == Status.FAIL
    assert insecure_results["CIS-AOSCX-PASSWORD-MIN-LENGTH"].status == Status.FAIL
    assert insecure_results["CIS-AOSCX-NTP-CONFIGURED"].status == Status.FAIL
    assert insecure_results["CIS-AOSCX-SNMP-NO-WRITE"].status == Status.FAIL # Snmp access level rw


def test_adversarial_false_pass_attacks():
    """Verify that secure keywords inside comments or malformed options do not trigger False-PASS."""
    parser = HPEArubaAosCxParser()
    ruleset = load_framework("CIS", "hpe_aruba_aos_cx")
    engine = ComplianceEngine(ruleset)

    # Insecure with secure-looking comments
    adversarial_config = """!Version AOS-CX 10.12.0001
hostname ATTACKER-CX-01
! ssh server vrf default
! aaa authentication login default local
! banner motd ^ WARNING ^
! session-timeout 5
! password-complexity
!     enable
!     min-length 15
"""
    baseline = parser.parse(adversarial_config)
    
    assert baseline.ssh_enabled.value is False
    assert baseline.aaa_enabled.value is False
    assert baseline.login_banner_present.value is False
    assert baseline.password_min_length.value == 0
    assert baseline.vty_exec_timeout_seconds.value == 1800  # Default 30 min (since session-timeout 5 is a comment)

    results = {r.rule_id: r for r in engine.evaluate(baseline)}
    assert results["CIS-AOSCX-AAA-CENTRALISED"].status == Status.FAIL
    assert results["CIS-AOSCX-NO-CLEARTEXT-SERVICES"].status == Status.PASS # Neither enabled, which is secure
    assert results["CIS-AOSCX-IDLE-TIMEOUT"].status == Status.FAIL # 1800 > 600
    assert results["CIS-AOSCX-PASSWORD-MIN-LENGTH"].status == Status.FAIL
