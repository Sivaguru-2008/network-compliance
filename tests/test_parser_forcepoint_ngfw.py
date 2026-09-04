"""Tests for Forcepoint NGFW configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.forcepoint_ngfw import ForcepointNGFWParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_FORCEPOINT_XML = """<?xml version="1.0" encoding="UTF-8"?>
<firewall_node 
    name="ForcepointFW01" 
    engine_version="version 6.10 #26028"
    web_server_http="false" 
    web_server_https="true" 
    ssh_service="true">
</firewall_node>
"""

INSECURE_FORCEPOINT_XML = """<?xml version="1.0" encoding="UTF-8"?>
<firewall_node 
    name="InsecureForcepoint" 
    engine_version="version 6.10 #26028"
    web_server_http="true" 
    web_server_https="false" 
    ssh_service="false">
</firewall_node>
"""


def test_forcepoint_detection():
    """Verify that detect() correctly identifies Forcepoint configuration XML."""
    parser = ForcepointNGFWParser()
    assert parser.detect(COMPLIANT_FORCEPOINT_XML) >= 0.80
    assert parser.detect(INSECURE_FORCEPOINT_XML) >= 0.80

    # Ensure other XML formats are rejected
    palo_xml = "<config><mgt-config><users></users></mgt-config></config>"
    assert parser.detect(palo_xml) == 0.0

    cisco_text = "line vty 0 4\n ip http server\n"
    assert parser.detect(cisco_text) == 0.0


def test_compliant_parser_normalization():
    """Verify the compliant config is parsed correctly into baseline model."""
    parser = ForcepointNGFWParser()
    baseline = parser.parse(COMPLIANT_FORCEPOINT_XML)

    assert baseline.provenance.vendor == "forcepoint"
    assert baseline.provenance.os_family == "forcepoint_ngfw"
    
    assert baseline.hostname.value == "ForcepointFW01"
    assert baseline.ssh_enabled.value is True
    assert set(baseline.vty_transport_input.value) == {"ssh"}
    assert baseline.telnet_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True


def test_insecure_parser_normalization():
    """Verify the insecure config is parsed correctly into baseline model."""
    parser = ForcepointNGFWParser()
    baseline = parser.parse(INSECURE_FORCEPOINT_XML)

    assert baseline.hostname.value == "InsecureForcepoint"
    assert baseline.ssh_enabled.value is False
    assert set(baseline.vty_transport_input.value) == set()
    assert baseline.http_server_enabled.value is True
    assert baseline.https_server_enabled.value is False


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = ForcepointNGFWParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = ForcepointNGFWParser()
    baseline = parser.parse(COMPLIANT_FORCEPOINT_XML)
    identity = extract_identity(COMPLIANT_FORCEPOINT_XML, baseline)

    assert identity.vendor == "forcepoint_forcepoint_ngfw"
    assert identity.os_family == "forcepoint_ngfw"
    assert identity.hostname.value == "ForcepointFW01"
    assert identity.os_version.value == "6.10"
    
    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against Forcepoint."""
    parser = ForcepointNGFWParser()
    ruleset = load_framework("CIS", "forcepoint_ngfw")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_FORCEPOINT_XML)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-FORCEPOINT-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-FORCEPOINT-NO-HTTP-SERVER"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_FORCEPOINT_XML)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-FORCEPOINT-NO-HTTP-SERVER"].status == Status.FAIL


def test_vendor_isolation():
    """Verify isolation of parser state across multiple platforms."""
    parser_wg = ForcepointNGFWParser()
    from auditor.parsers.barracuda_cloudgen import BarracudaCloudGenParser
    parser_sw = BarracudaCloudGenParser()

    wg_baseline = parser_wg.parse(COMPLIANT_FORCEPOINT_XML)
    sw_baseline = parser_sw.parse("sys-name = \"TestBarracuda\"\n")

    assert wg_baseline.provenance.vendor == "forcepoint"
    assert sw_baseline.provenance.vendor == "barracuda"

    assert wg_baseline.hostname.value == "ForcepointFW01"
    assert sw_baseline.hostname.value == "TestBarracuda"
