"""Tests for Zscaler ZPA configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.zscaler_zpa import ZscalerZPAParser
from auditor.parsers.zscaler_zia import ZscalerZIAParser
from auditor.parsers.stormshield_sns import StormshieldSNSParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

REAL_ZPA_JSON = """{
  "tenant": "AcmeZpaTenant",
  "zpa_configuration": {
    "tenant": "AcmeZpaTenant"
  },
  "adminSso": {
    "ssoEnabled": true,
    "idpId": "1234-abcd"
  },
  "logReceivers": [
    {
      "id": 99,
      "name": "LSS_Receiver",
      "host": "192.168.10.10"
    }
  ]
}
"""


def test_zpa_detection():
    """Verify that detect() correctly identifies ZPA API response JSON configuration."""
    parser = ZscalerZPAParser()
    assert parser.detect(REAL_ZPA_JSON) >= 0.80

    # Test generic or unrelated JSON
    generic_json = """{
      "name": "generic_project",
      "version": "1.0.0",
      "description": "arbitrary JSON"
    }"""
    assert parser.detect(generic_json) == 0.0

    # ZIA JSON must not match ZPA
    zia_json = """{
      "tenant": "AcmeZiaTenant",
      "adminUsers": [],
      "nssFeeds": []
    }"""
    assert parser.detect(zia_json) == 0.0


def test_parser_normalization():
    """Verify ZPA configuration is parsed correctly into baseline model."""
    parser = ZscalerZPAParser()
    baseline = parser.parse(REAL_ZPA_JSON)

    assert baseline.provenance.vendor == "zscaler"
    assert baseline.provenance.os_family == "zpa"
    
    assert baseline.hostname.value == "AcmeZpaTenant"
    
    # Secure web administration and SSH are evaluated deterministically (disabled/HTTPS-only)
    assert baseline.telnet_enabled.value is False
    assert baseline.ssh_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True

    # Log receivers verified active
    assert baseline.logging_enabled.value is True
    assert baseline.logging_hosts.value == ["Zscaler ZPA Log Receiver"]


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = ZscalerZPAParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = ZscalerZPAParser()
    baseline = parser.parse(REAL_ZPA_JSON)
    identity = extract_identity(REAL_ZPA_JSON, baseline)

    assert identity.vendor == "zscaler_zpa"
    assert identity.os_family == "zpa"
    assert identity.hostname.value == "AcmeZpaTenant"
    
    # Firmware version, model, serial are unknown on cloud-native tenant endpoints
    assert identity.os_version.detected is False
    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify compliance rule status mappings for Zscaler ZPA."""
    parser = ZscalerZPAParser()
    ruleset = load_framework("CIS", "zscaler_zpa")
    engine = ComplianceEngine(ruleset)

    baseline = parser.parse(REAL_ZPA_JSON)
    results = {r.rule_id: r for r in engine.evaluate(baseline)}

    # Enabled HTTPS/disabled cleartext transport are PASS
    assert results["CIS-ZPA-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert results["CIS-ZPA-NO-HTTP-SERVER"].status == Status.PASS
    assert results["CIS-ZPA-SYSLOG-DESTINATION"].status == Status.PASS # logReceiver configured
    
    # Missing/unexported parameters evaluate to NEEDS_REVIEW
    assert results["CIS-ZPA-AAA-CENTRALISED"].status == Status.NEEDS_REVIEW
    assert results["CIS-ZPA-IDLE-TIMEOUT"].status == Status.NEEDS_REVIEW


def test_vendor_isolation():
    """Verify isolation of parser state across multiple platforms."""
    parser_zpa = ZscalerZPAParser()
    parser_zia = ZscalerZIAParser()
    parser_sns = StormshieldSNSParser()

    zpa_baseline = parser_zpa.parse(REAL_ZPA_JSON)
    zia_baseline = parser_zia.parse(REAL_ZIA_JSON := "{\"tenant\": \"TestZia\", \"zia_configuration\": {\"tenant\": \"TestZia\"}, \"adminUsers\": []}")

    assert zpa_baseline.provenance.os_family == "zpa"
    assert zia_baseline.provenance.os_family == "zia"

    assert zpa_baseline.hostname.value == "AcmeZpaTenant"
    assert zia_baseline.hostname.value == "TestZia"
