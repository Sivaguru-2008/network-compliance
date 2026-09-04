"""Tests for Barracuda CloudGen Firewall configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.barracuda_cloudgen import BarracudaCloudGenParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_BARRACUDA_CONFIG = """
#scope:BoxAdministration
sys-name = "BarracudaFW01"
http-enable = "no"
https-enable = "yes"
ssh-enable = "yes"
timeout = "600"
dns-servers = "8.8.8.8,8.8.4.4"
ntp-servers = "pool.ntp.org"
logging-enabled = "yes"
logging-host = "192.168.1.100"
"""

INSECURE_BARRACUDA_CONFIG = """
#scope:BoxAdministration
sys-name = "InsecureBarracuda"
http-enable = "yes"
https-enable = "no"
ssh-enable = "no"
timeout = "3600"
logging-enabled = "no"
"""


def test_barracuda_detection():
    """Verify that detect() correctly identifies Barracuda configuration files."""
    parser = BarracudaCloudGenParser()
    assert parser.detect(COMPLIANT_BARRACUDA_CONFIG) >= 0.70
    assert parser.detect(INSECURE_BARRACUDA_CONFIG) >= 0.70

    # Ensure other formats are rejected
    generic_ini = """[Settings]
    LogLevel=Debug
    """
    assert parser.detect(generic_ini) == 0.0

    cisco_text = "line vty 0 4\n ip http server\n"
    assert parser.detect(cisco_text) == 0.0


def test_compliant_parser_normalization():
    """Verify the compliant config is parsed correctly into baseline model."""
    parser = BarracudaCloudGenParser()
    baseline = parser.parse(COMPLIANT_BARRACUDA_CONFIG)

    assert baseline.provenance.vendor == "barracuda"
    assert baseline.provenance.os_family == "barracuda_cloudgen"
    
    assert baseline.hostname.value == "BarracudaFW01"
    assert baseline.ssh_enabled.value is True
    assert set(baseline.vty_transport_input.value) == {"ssh"}
    assert baseline.telnet_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 600
    assert baseline.dns_servers.value == ["8.8.8.8", "8.8.4.4"]
    assert baseline.ntp_servers.value == ["pool.ntp.org"]
    assert baseline.logging_enabled.value is True
    assert baseline.logging_hosts.value == ["192.168.1.100"]


def test_insecure_parser_normalization():
    """Verify the insecure config is parsed correctly into baseline model."""
    parser = BarracudaCloudGenParser()
    baseline = parser.parse(INSECURE_BARRACUDA_CONFIG)

    assert baseline.hostname.value == "InsecureBarracuda"
    assert baseline.ssh_enabled.value is False
    assert set(baseline.vty_transport_input.value) == set()
    assert baseline.http_server_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 3600
    assert baseline.logging_enabled.value is False


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = BarracudaCloudGenParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = BarracudaCloudGenParser()
    config_with_version = "# Barracuda CloudGen Firewall 8.3.1\nsys-name = \"BarracudaFW01\"\n"
    baseline = parser.parse(config_with_version)
    identity = extract_identity(config_with_version, baseline)

    assert identity.vendor == "barracuda_barracuda_cloudgen"
    assert identity.os_family == "barracuda_cloudgen"
    assert identity.hostname.value == "BarracudaFW01"
    assert identity.os_version.value == "8.3.1"
    
    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against Barracuda."""
    parser = BarracudaCloudGenParser()
    ruleset = load_framework("CIS", "barracuda_cloudgen")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_BARRACUDA_CONFIG)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-BARRACUDA-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-BARRACUDA-IDLE-TIMEOUT"].status == Status.PASS
    assert compliant_results["CIS-BARRACUDA-NO-HTTP-SERVER"].status == Status.PASS
    assert compliant_results["CIS-BARRACUDA-SYSLOG-DESTINATION"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_BARRACUDA_CONFIG)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-BARRACUDA-NO-HTTP-SERVER"].status == Status.FAIL
    assert insecure_results["CIS-BARRACUDA-IDLE-TIMEOUT"].status == Status.FAIL
    assert insecure_results["CIS-BARRACUDA-SYSLOG-DESTINATION"].status == Status.FAIL
