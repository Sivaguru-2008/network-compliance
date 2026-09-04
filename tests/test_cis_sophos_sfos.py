"""Tests for the Sophos Firewall SFOS (sfos) configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.sophos_sfos import SophosSFOSParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

# Realistic selective configuration export example from a Sophos Firewall
REAL_SOPHOS_XML = """<Configuration>
  <IPHost transactionid="100">
    <Name>Internal_LAN</Name>
    <IPFamily>IPv4</IPFamily>
    <HostType>Network</HostType>
    <IPAddress>192.168.100.0</IPAddress>
    <Subnet>255.255.255.0</Subnet>
  </IPHost>
  <FQDNHost transactionid="101">
    <Name>Sophos_Update</Name>
    <FQDN>sophos.com</FQDN>
  </FQDNHost>
  <FirewallRule transactionid="102">
    <Name>Default_LAN_WAN</Name>
    <IPFamily>IPv4</IPFamily>
    <Status>Enable</Status>
    <Position>1</Position>
  </FirewallRule>
</Configuration>
"""


def test_sophos_detection():
    """Verify that detect() correctly identifies Sophos Firewall XML configurations."""
    parser = SophosSFOSParser()
    assert parser.detect(REAL_SOPHOS_XML) >= 0.80

    # Ensure other XML / CLI configs are rejected
    cisco_text = "line vty 0 4\n ip http server\n"
    assert parser.detect(cisco_text) == 0.0

    paloalto_xml = "<configuration><deviceconfig><system><hostname>PA-VM</hostname></system></deviceconfig></configuration>"
    assert parser.detect(paloalto_xml) == 0.0


def test_parser_normalization():
    """Verify the Sophos XML configuration is normalized to unknown for unexported system settings."""
    parser = SophosSFOSParser()
    baseline = parser.parse(REAL_SOPHOS_XML)

    assert baseline.provenance.vendor == "sophos"
    assert baseline.provenance.os_family == "sfos"
    
    # All baseline security controls must be unknown due to configuration export limitations
    assert baseline.hostname.detected is False
    assert baseline.ssh_enabled.detected is False
    assert baseline.telnet_enabled.detected is False
    assert baseline.http_server_enabled.detected is False
    assert baseline.https_server_enabled.detected is False
    assert baseline.vty_exec_timeout_seconds.detected is False
    assert baseline.login_banner_present.detected is False
    assert baseline.enable_secret_set.detected is False
    assert baseline.aaa_enabled.detected is False
    assert baseline.snmp_communities.detected is False
    assert baseline.logging_enabled.detected is False
    assert baseline.ntp_servers.detected is False
    assert baseline.dns_servers.detected is False
    assert baseline.password_min_length.detected is False


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = SophosSFOSParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are returned as unknown when not present in export."""
    parser = SophosSFOSParser()
    baseline = parser.parse(REAL_SOPHOS_XML)
    identity = extract_identity(REAL_SOPHOS_XML, baseline)

    assert identity.vendor == "sophos_sfos"
    assert identity.os_family == "sfos"
    assert identity.hostname.detected is False
    assert identity.os_version.detected is False
    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly and return NEEDS_REVIEW due to unknown status."""
    parser = SophosSFOSParser()
    ruleset = load_framework("CIS", "sophos_sfos")
    engine = ComplianceEngine(ruleset)

    baseline = parser.parse(REAL_SOPHOS_XML)
    results = {r.rule_id: r for r in engine.evaluate(baseline)}

    # All standard CIS benchmarks must report NEEDS_REVIEW (since values are unknown in config)
    for rule_id, res in results.items():
        assert res.status == Status.NEEDS_REVIEW


def test_vendor_isolation():
    """Verify that there is no cross-vendor state leakage."""
    parser = SophosSFOSParser()
    
    # Verify parsing Sophos config leaves parser clean
    baseline = parser.parse(REAL_SOPHOS_XML)
    assert baseline.provenance.vendor == "sophos"
    
    # Run other vendor parser to check isolation
    from auditor.parsers.cisco_ios import CiscoIOSParser
    cisco_parser = CiscoIOSParser()
    cisco_config = "hostname RouterA\n"
    cisco_baseline = cisco_parser.parse(cisco_config)
    assert cisco_baseline.provenance.vendor == "cisco"
    assert cisco_baseline.hostname.value == "RouterA"
