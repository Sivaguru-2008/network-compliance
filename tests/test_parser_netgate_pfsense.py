"""Tests for Netgate pfSense configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.netgate_pfsense import NetgatePfSenseParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_PFSENSE_CONFIG = """<?xml version="1.0"?>
<pfsense>
    <version>11.2</version>
    <system>
        <hostname>pfSenseFW01</hostname>
        <webgui>
            <protocol>https</protocol>
            <session_timeout>10</session_timeout>
        </webgui>
        <ssh>
            <enable>enabled</enable>
        </ssh>
        <dnsserver>8.8.8.8</dnsserver>
        <dnsserver>8.8.4.4</dnsserver>
        <timeservers>0.pfsense.pool.ntp.org 1.pfsense.pool.ntp.org</timeservers>
        <authservers>
            <authserver>
                <name>RADIUS_Server</name>
                <type>radius</type>
            </authserver>
        </authservers>
    </system>
    <syslog>
        <remoteserverenable>1</remoteserverenable>
        <remote-log-servers>192.168.1.100:514</remote-log-servers>
    </syslog>
    <snmpd>
        <enable>enabled</enable>
        <rocommunity>SecureString123</rocommunity>
    </snmpd>
</pfsense>
"""

INSECURE_PFSENSE_CONFIG = """<?xml version="1.0"?>
<pfsense>
    <version>11.2</version>
    <system>
        <hostname>InsecurePF</hostname>
        <webgui>
            <protocol>http</protocol>
            <session_timeout>240</session_timeout>
        </webgui>
        <ssh>
            <enable>disabled</enable>
        </ssh>
    </system>
    <snmpd>
        <enable>enabled</enable>
        <rocommunity>public</rocommunity>
    </snmpd>
</pfsense>
"""


def test_pfsense_detection():
    """Verify that detect() correctly identifies pfSense configuration backups."""
    parser = NetgatePfSenseParser()
    assert parser.detect(COMPLIANT_PFSENSE_CONFIG) == 1.0
    assert parser.detect(INSECURE_PFSENSE_CONFIG) == 1.0

    # Ensure other formats are rejected
    generic_ini = """[Settings]
    LogLevel=Debug
    """
    assert parser.detect(generic_ini) == 0.0

    cisco_text = "line vty 0 4\n ip http server\n"
    assert parser.detect(cisco_text) == 0.0


def test_compliant_parser_normalization():
    """Verify the compliant config is parsed correctly into baseline model."""
    parser = NetgatePfSenseParser()
    baseline = parser.parse(COMPLIANT_PFSENSE_CONFIG)

    assert baseline.provenance.vendor == "netgate"
    assert baseline.provenance.os_family == "pfsense"
    
    assert baseline.hostname.value == "pfSenseFW01"
    assert baseline.ssh_enabled.value is True
    assert set(baseline.vty_transport_input.value) == {"ssh"}
    assert baseline.telnet_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 600
    assert baseline.dns_servers.value == ["8.8.8.8", "8.8.4.4"]
    assert baseline.ntp_servers.value == ["0.pfsense.pool.ntp.org", "1.pfsense.pool.ntp.org"]
    assert baseline.logging_enabled.value is True
    assert baseline.logging_hosts.value == ["192.168.1.100"]
    assert baseline.aaa_enabled.value is True
    assert baseline.snmp_agent_enabled.value is True
    assert len(baseline.snmp_communities.value) == 1
    assert baseline.snmp_communities.value[0].name == "SecureString123"


def test_insecure_parser_normalization():
    """Verify the insecure config is parsed correctly into baseline model."""
    parser = NetgatePfSenseParser()
    baseline = parser.parse(INSECURE_PFSENSE_CONFIG)

    assert baseline.hostname.value == "InsecurePF"
    assert baseline.ssh_enabled.value is False
    assert set(baseline.vty_transport_input.value) == set()
    assert baseline.http_server_enabled.value is True
    assert baseline.https_server_enabled.value is False
    assert baseline.vty_exec_timeout_seconds.value == 14400
    assert baseline.snmp_agent_enabled.value is True
    assert len(baseline.snmp_communities.value) == 1
    assert baseline.snmp_communities.value[0].name == "public"


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = NetgatePfSenseParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_malformed_xml_rejection():
    """Verify parser rejects malformed XML structure with ParserError."""
    parser = NetgatePfSenseParser()
    with pytest.raises(ParserError):
        parser.parse("<pfsense><system><hostname>test</system></pfsense>")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = NetgatePfSenseParser()
    baseline = parser.parse(COMPLIANT_PFSENSE_CONFIG)
    identity = extract_identity(COMPLIANT_PFSENSE_CONFIG, baseline)

    assert identity.vendor == "netgate_pfsense"
    assert identity.os_family == "pfsense"
    assert identity.hostname.value == "pfSenseFW01"
    assert identity.os_version.value == "11.2"
    
    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against pfSense."""
    parser = NetgatePfSenseParser()
    ruleset = load_framework("CIS", "netgate_pfsense")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_PFSENSE_CONFIG)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-PFSENSE-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-PFSENSE-IDLE-TIMEOUT"].status == Status.PASS
    assert compliant_results["CIS-PFSENSE-NO-HTTP-SERVER"].status == Status.PASS
    assert compliant_results["CIS-PFSENSE-SYSLOG-DESTINATION"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_PFSENSE_CONFIG)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-PFSENSE-NO-HTTP-SERVER"].status == Status.FAIL
    assert insecure_results["CIS-PFSENSE-IDLE-TIMEOUT"].status == Status.FAIL
    assert insecure_results["CIS-PFSENSE-SYSLOG-DESTINATION"].status == Status.NEEDS_REVIEW


def test_adversarial_inputs():
    """Verify pfSense parser handling of adversarial XML comments and text values."""
    parser = NetgatePfSenseParser()

    # XML Comment containing secure-looking tags must be ignored
    comment_config = """<?xml version="1.0"?>
    <pfsense>
        <system>
            <!-- <hostname>FakeHost</hostname> -->
            <hostname>RealHost</hostname>
        </system>
    </pfsense>
    """
    baseline = parser.parse(comment_config)
    assert baseline.hostname.value == "RealHost"

    # Unknown fields return needs review
    partial_config = """<?xml version="1.0"?>
    <pfsense>
        <system>
            <hostname>pfsense-test</hostname>
        </system>
    </pfsense>
    """
    baseline = parser.parse(partial_config)
    assert baseline.logging_enabled.detected is False


def test_vendor_isolation():
    """Verify isolation of parser state across multiple platforms."""
    parser_pf = NetgatePfSenseParser()
    from auditor.parsers.cisco_ios import CiscoIOSParser
    parser_cisco = CiscoIOSParser()

    pf_baseline = parser_pf.parse(COMPLIANT_PFSENSE_CONFIG)
    cisco_baseline = parser_cisco.parse("hostname CiscoFW\n")

    assert pf_baseline.provenance.vendor == "netgate"
    assert cisco_baseline.provenance.vendor == "cisco"

    assert pf_baseline.hostname.value == "pfSenseFW01"
    assert cisco_baseline.hostname.value == "CiscoFW"
