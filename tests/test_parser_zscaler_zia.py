"""Tests for Zscaler ZIA configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.zscaler_zia import ZscalerZIAParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

REAL_ZIA_JSON = """{
  "tenant": "AcmeZiaTenant",
  "zia_configuration": {
    "tenant": "AcmeZiaTenant"
  },
  "adminUsers": [
    {
      "id": 1,
      "loginName": "admin@acme.com",
      "userName": "Admin User"
    }
  ],
  "nssFeeds": [
    {
      "id": 12,
      "name": "NSS_Firewall_Feed",
      "type": "FIREWALL"
    }
  ]
}
"""


def test_zia_detection():
    """Verify that detect() correctly identifies ZIA API response JSON configuration."""
    parser = ZscalerZIAParser()
    assert parser.detect(REAL_ZIA_JSON) >= 0.80

    # Test generic or unrelated JSON
    generic_json = """{
      "name": "generic_project",
      "version": "1.0.0",
      "description": "arbitrary JSON"
    }"""
    assert parser.detect(generic_json) == 0.0

    # ZPA JSON must not match ZIA
    zpa_json = """{
      "tenant": "AcmeZpaTenant",
      "adminSso": {},
      "logReceivers": []
    }"""
    assert parser.detect(zpa_json) == 0.0


def test_parser_normalization():
    """Verify ZIA configuration is parsed correctly into baseline model."""
    parser = ZscalerZIAParser()
    baseline = parser.parse(REAL_ZIA_JSON)

    assert baseline.provenance.vendor == "zscaler"
    assert baseline.provenance.os_family == "zia"
    
    assert baseline.hostname.value == "AcmeZiaTenant"
    
    # Secure web administration and SSH are evaluated deterministically (disabled/HTTPS-only)
    assert baseline.telnet_enabled.value is False
    assert baseline.ssh_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True

    # NSS log forwarding verified active
    assert baseline.logging_enabled.value is True
    assert baseline.logging_hosts.value == ["Zscaler NSS Log Collector"]


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = ZscalerZIAParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = ZscalerZIAParser()
    baseline = parser.parse(REAL_ZIA_JSON)
    identity = extract_identity(REAL_ZIA_JSON, baseline)

    assert identity.vendor == "zscaler_zia"
    assert identity.os_family == "zia"
    assert identity.hostname.value == "AcmeZiaTenant"
    
    # Firmware version, model, serial are unknown on cloud-native tenant endpoints
    assert identity.os_version.detected is False
    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify compliance rule status mappings for Zscaler ZIA."""
    parser = ZscalerZIAParser()
    ruleset = load_framework("CIS", "zscaler_zia")
    engine = ComplianceEngine(ruleset)

    baseline = parser.parse(REAL_ZIA_JSON)
    results = {r.rule_id: r for r in engine.evaluate(baseline)}

    # Enabled HTTPS/disabled cleartext transport are PASS
    assert results["CIS-ZIA-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert results["CIS-ZIA-NO-HTTP-SERVER"].status == Status.PASS
    assert results["CIS-ZIA-SYSLOG-DESTINATION"].status == Status.PASS # NSS configured
    
    # Missing/unexported parameters evaluate to NEEDS_REVIEW
    assert results["CIS-ZIA-AAA-CENTRALISED"].status == Status.NEEDS_REVIEW
    assert results["CIS-ZIA-IDLE-TIMEOUT"].status == Status.NEEDS_REVIEW
