"""Tests for the WatchGuard Fireware configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.watchguard_fireware import WatchGuardFirewareParser
from auditor.parsers.sonicwall_sonicos import SonicWallSonicOSParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

REAL_WATCHGUARD_XML = """<?xml version="1.0" encoding="UTF-8"?>
<configuration version="12.9">
  <abs-policy-list>
    <policy>
      <name>WatchGuard Web UI</name>
      <action>allow</action>
    </policy>
  </abs-policy-list>
  <alias-list>
    <alias>
      <name>Any-Trusted</name>
    </alias>
  </alias-list>
  <interface-list>
    <interface>
      <name>External</name>
    </interface>
  </interface-list>
</configuration>
"""


def test_watchguard_detection():
    """Verify that detect() correctly identifies WatchGuard XML configurations using fingerprint."""
    parser = WatchGuardFirewareParser()
    assert parser.detect(REAL_WATCHGUARD_XML) >= 0.80

    # Test generic XML root tag <configuration> without verified sub-elements -> low confidence
    generic_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <configuration version="12.9">
      <some-arbitrary-unverified-tag>
        <data>value</data>
      </some-arbitrary-unverified-tag>
    </configuration>
    """
    assert parser.detect(generic_xml) <= 0.20

    # Ensure other CLI configs are rejected
    cisco_text = "line vty 0 4\n ip http server\n"
    assert parser.detect(cisco_text) == 0.0


def test_parser_normalization():
    """Verify the parser reports baseline controls as unknown due to proprietary schema."""
    parser = WatchGuardFirewareParser()
    baseline = parser.parse(REAL_WATCHGUARD_XML)

    assert baseline.provenance.vendor == "watchguard"
    assert baseline.provenance.os_family == "fireware"
    
    # All baseline security controls must report unknown
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
    parser = WatchGuardFirewareParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly as unknown (excluding compatibility version)."""
    parser = WatchGuardFirewareParser()
    baseline = parser.parse(REAL_WATCHGUARD_XML)
    identity = extract_identity(REAL_WATCHGUARD_XML, baseline)

    assert identity.vendor == "watchguard_fireware"
    assert identity.os_family == "fireware"
    
    # OS compatibility version must NOT be mapped to OS version
    assert identity.os_version.detected is False
    assert identity.hostname.detected is False
    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly and report NEEDS_REVIEW due to unknown status."""
    parser = WatchGuardFirewareParser()
    ruleset = load_framework("CIS", "watchguard_fireware")
    engine = ComplianceEngine(ruleset)

    baseline = parser.parse(REAL_WATCHGUARD_XML)
    results = {r.rule_id: r for r in engine.evaluate(baseline)}

    # All standard CIS benchmarks must report NEEDS_REVIEW (since values are unknown in config XML)
    for rule_id, res in results.items():
        assert res.status == Status.NEEDS_REVIEW


def test_vendor_isolation():
    """Verify isolation of parser state across multiple platforms."""
    parser_wg = WatchGuardFirewareParser()
    parser_sw = SonicWallSonicOSParser()

    wg_baseline = parser_wg.parse(REAL_WATCHGUARD_XML)
    sw_baseline = parser_sw.parse(COMPLIANT_SONICOS_CLI_TEST := "hostname SonicFW-01\n")

    assert wg_baseline.provenance.vendor == "watchguard"
    assert sw_baseline.provenance.vendor == "sonicwall"

    assert wg_baseline.hostname.detected is False
    assert sw_baseline.hostname.value == "SonicFW-01"
