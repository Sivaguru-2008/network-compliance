"""Tests for the Cato Networks configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.cato_networks import CatoNetworksParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

REAL_CATO_JSON = """{
  "data": {
    "accountBySubdomain": {
      "id": 12345,
      "name": "AcmeCorp"
    },
    "auditFeed": {
      "marker": "abc123marker",
      "fetchedCount": 50,
      "hasMore": false
    }
  }
}
"""


def test_cato_detection():
    """Verify that detect() correctly identifies Cato Networks GraphQL response JSON configurations."""
    parser = CatoNetworksParser()
    assert parser.detect(REAL_CATO_JSON) >= 0.80

    # Test generic or unrelated JSON
    generic_json = """{
      "name": "generic_project",
      "version": "1.0.0",
      "description": "arbitrary JSON"
    }"""
    assert parser.detect(generic_json) == 0.0

    # Ensure other XML / CLI configs are rejected
    cisco_text = "line vty 0 4\n ip http server\n"
    assert parser.detect(cisco_text) == 0.0


def test_parser_normalization():
    """Verify that Cato API response JSON is parsed correctly into the baseline model."""
    parser = CatoNetworksParser()
    baseline = parser.parse(REAL_CATO_JSON)

    assert baseline.provenance.vendor == "cato"
    assert baseline.provenance.os_family == "cato_networks"
    
    assert baseline.hostname.value == "AcmeCorp"
    
    # Secure web administration and SSH are evaluated deterministically (disabled/HTTPS-only)
    assert baseline.telnet_enabled.value is False
    assert baseline.ssh_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True

    # Audit logging is verified via the auditFeed query presence
    assert baseline.logging_enabled.value is True
    assert baseline.logging_hosts.value == ["Cato SASE Log Cloud Engine"]

    # All other baseline security controls must report unknown
    assert baseline.vty_exec_timeout_seconds.detected is False
    assert baseline.login_banner_present.detected is False
    assert baseline.enable_secret_set.detected is False
    assert baseline.aaa_enabled.detected is False
    assert baseline.snmp_communities.detected is False
    assert baseline.ntp_servers.detected is False
    assert baseline.dns_servers.detected is False
    assert baseline.password_min_length.detected is False


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = CatoNetworksParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = CatoNetworksParser()
    baseline = parser.parse(REAL_CATO_JSON)
    identity = extract_identity(REAL_CATO_JSON, baseline)

    assert identity.vendor == "cato_cato_networks"
    assert identity.os_family == "cato_networks"
    assert identity.hostname.value == "AcmeCorp"
    
    # Firmware version, model, serial are unknown on cloud-native SASE endpoints
    assert identity.os_version.detected is False
    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify compliance rule status mappings for Cato SASE cloud."""
    parser = CatoNetworksParser()
    ruleset = load_framework("CIS", "cato_networks")
    engine = ComplianceEngine(ruleset)

    baseline = parser.parse(REAL_CATO_JSON)
    results = {r.rule_id: r for r in engine.evaluate(baseline)}

    # Enabled HTTPS/disabled cleartext transport are PASS
    assert results["CIS-CATO-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert results["CIS-CATO-NO-HTTP-SERVER"].status == Status.PASS
    assert results["CIS-CATO-SYSLOG-DESTINATION"].status == Status.PASS # auditFeed verified active
    
    # Missing/unexported system parameters evaluate to NEEDS_REVIEW
    assert results["CIS-CATO-AAA-CENTRALISED"].status == Status.NEEDS_REVIEW
    assert results["CIS-CATO-IDLE-TIMEOUT"].status == Status.NEEDS_REVIEW
    assert results["CIS-CATO-LOGIN-BANNER"].status == Status.NEEDS_REVIEW
    assert results["CIS-CATO-NTP-CONFIGURED"].status == Status.NEEDS_REVIEW


def test_vendor_isolation():
    """Verify isolation of parser state across multiple platforms."""
    parser_cato = CatoNetworksParser()
    from auditor.parsers.sonicwall_sonicos import SonicWallSonicOSParser
    parser_sw = SonicWallSonicOSParser()

    cato_baseline = parser_cato.parse(REAL_CATO_JSON)
    sw_baseline = parser_sw.parse("hostname SonicFW-01\n")

    assert cato_baseline.provenance.vendor == "cato"
    assert sw_baseline.provenance.vendor == "sonicwall"

    assert cato_baseline.hostname.value == "AcmeCorp"
    assert sw_baseline.hostname.value == "SonicFW-01"
