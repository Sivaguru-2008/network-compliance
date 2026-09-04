"""Tests for F5 Networks BIG-IP TMOS configuration parser, identity extractor, and rule mapping."""

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import Status
from auditor.parsers import ParserError
from auditor.parsers.f5_bigip_tmos import F5BigIPTMOSParser
from auditor.identity.extractors import extract_identity
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

COMPLIANT_F5_CONFIG = """sys global-settings {
    hostname "bigip-active.local"
    console-inactivity-timeout 600
}
sys sshd {
    banner enabled
    banner-text "Authorized Access Only."
    inactivity-timeout 600
    allow {
        10.10.1.0/24
    }
}
sys httpd {
    auth-pam-idle-timeout 600
    allow {
        10.10.1.0/24
    }
}
auth source {
    type tacacs
}
auth password-policy {
    minimum-length 14
    required-lowercase 1
    required-uppercase 1
    required-numeric 1
    required-special 1
    max-duration 90
}
sys syslog {
    remote-servers {
        server_1 {
            host 192.168.10.50
        }
    }
}
sys ntp {
    servers {
        192.168.1.10
        192.168.1.11
    }
}
sys dns {
    name-servers {
        8.8.8.8
    }
}
sys snmp {
    communities {
        monitor {
            community-name monitor
        }
    }
}
"""

INSECURE_F5_CONFIG = """sys global-settings {
    hostname "insecure-f5"
}
sys sshd {
    inactivity-timeout 0
}
auth password-policy {
    minimum-length 8
}
"""


def test_f5_detection():
    """Verify that detect() correctly identifies F5 TMOS configuration outputs."""
    parser = F5BigIPTMOSParser()
    assert parser.detect(COMPLIANT_F5_CONFIG) == 1.0
    assert parser.detect(INSECURE_F5_CONFIG) == 1.0

    # Ensure other formats are rejected
    cisco_text = "line vty 0 4\n transport input ssh\n"
    assert parser.detect(cisco_text) == 0.0

    juniper_text = "system {\n    host-name junos-fw;\n}\n"
    assert parser.detect(juniper_text) == 0.0


def test_compliant_parser_normalization():
    """Verify the compliant config is parsed correctly into baseline model."""
    parser = F5BigIPTMOSParser()
    baseline = parser.parse(COMPLIANT_F5_CONFIG)

    assert baseline.provenance.vendor == "f5"
    assert baseline.provenance.os_family == "tmos"

    assert baseline.hostname.value == "bigip-active.local"
    assert baseline.ssh_enabled.value is True
    assert set(baseline.vty_transport_input.value) == {"ssh"}
    assert baseline.telnet_enabled.value is False
    assert baseline.http_server_enabled.value is False
    assert baseline.https_server_enabled.value is True
    assert baseline.vty_exec_timeout_seconds.value == 600
    assert baseline.dns_servers.value == ["8.8.8.8"]
    assert baseline.ntp_servers.value == ["192.168.1.10", "192.168.1.11"]
    assert baseline.logging_enabled.value is True
    assert baseline.logging_hosts.value == ["192.168.10.50"]
    assert baseline.aaa_enabled.value is True
    assert baseline.password_min_length.value == 14
    assert baseline.password_min_uppercase.value == 1
    assert baseline.password_min_lowercase.value == 1
    assert baseline.password_min_numeric.value == 1
    assert baseline.password_min_special.value == 1
    assert baseline.password_max_age_days.value == 90
    assert baseline.management_acl_applied.value is True
    assert baseline.login_banner_present.value is True
    assert len(baseline.snmp_communities.value) == 1
    assert baseline.snmp_communities.value[0].name == "monitor"
    assert baseline.snmp_communities.value[0].access == "ro"


def test_insecure_parser_normalization():
    """Verify the insecure config is parsed correctly into baseline model."""
    parser = F5BigIPTMOSParser()
    baseline = parser.parse(INSECURE_F5_CONFIG)

    assert baseline.hostname.value == "insecure-f5"
    assert baseline.vty_exec_timeout_seconds.value == 0
    assert baseline.password_min_length.value == 8


def test_empty_config_rejection():
    """Verify parser rejects empty config with ParserError."""
    parser = F5BigIPTMOSParser()
    with pytest.raises(ParserError):
        parser.parse("")


def test_identity_extraction():
    """Verify identity details are extracted correctly."""
    parser = F5BigIPTMOSParser()
    baseline = parser.parse(COMPLIANT_F5_CONFIG)
    identity = extract_identity(COMPLIANT_F5_CONFIG, baseline)

    assert identity.vendor == "f5_bigip_tmos"
    assert identity.os_family == "tmos"
    assert identity.hostname.value == "bigip-active.local"
    assert identity.os_version.detected is False

    assert identity.model.detected is False
    assert identity.serial_number.detected is False


def test_cis_compliance_evaluation():
    """Verify the compliance rules run correctly against F5 BIG-IP TMOS."""
    parser = F5BigIPTMOSParser()
    ruleset = load_framework("CIS", "f5_bigip_tmos")
    engine = ComplianceEngine(ruleset)

    # 1. Evaluate compliant config
    compliant_baseline = parser.parse(COMPLIANT_F5_CONFIG)
    compliant_results = {r.rule_id: r for r in engine.evaluate(compliant_baseline)}

    assert compliant_results["CIS-F5-NO-CLEARTEXT-SERVICES"].status == Status.PASS
    assert compliant_results["CIS-F5-IDLE-TIMEOUT"].status == Status.PASS
    assert compliant_results["CIS-F5-NO-HTTP-SERVER"].status == Status.PASS
    assert compliant_results["CIS-F5-SYSLOG-DESTINATION"].status == Status.PASS

    # 2. Evaluate insecure config
    insecure_baseline = parser.parse(INSECURE_F5_CONFIG)
    insecure_results = {r.rule_id: r for r in engine.evaluate(insecure_baseline)}

    assert insecure_results["CIS-F5-IDLE-TIMEOUT"].status == Status.FAIL


def test_adversarial_inputs():
    """Verify F5 parser handling of adversarial comments and values."""
    parser = F5BigIPTMOSParser()

    # Comment containing secure-looking tags must be ignored
    comment_config = """# sys global-settings { console-inactivity-timeout 900 }
    sys global-settings {
        console-inactivity-timeout 300
    }
    """
    baseline = parser.parse(comment_config)
    assert baseline.vty_exec_timeout_seconds.value == 300

    # Unknown fields return needs review
    partial_config = """sys global-settings {
        hostname "bigip-partial"
    }
    """
    baseline = parser.parse(partial_config)
    assert baseline.logging_enabled.detected is False


def test_vendor_isolation():
    """Verify isolation of parser state across multiple platforms."""
    parser_f5 = F5BigIPTMOSParser()
    from auditor.parsers.cisco_ios import CiscoIOSParser
    parser_cisco = CiscoIOSParser()

    f5_baseline = parser_f5.parse(COMPLIANT_F5_CONFIG)
    cisco_baseline = parser_cisco.parse("hostname CiscoRouter\n")

    assert f5_baseline.provenance.vendor == "f5"
    assert cisco_baseline.provenance.vendor == "cisco"

    assert f5_baseline.hostname.value == "bigip-active.local"
    assert cisco_baseline.hostname.value == "CiscoRouter"
