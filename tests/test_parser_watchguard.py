"""Tests for the WatchGuard Firebox / Fireware deterministic parser.

Verified against official WatchGuard technical documentation:
- WatchGuard Help Center: https://www.watchguard.com/help/docs/
- Fireware Web UI Help / Policy Manager Reference (v11.x, v12.x)
- Fireware Command Line Interface (CLI) Reference Guide
- WatchGuard Security Best Practices & Hardening Guidance

CONFIGURATION PROVENANCE:
- secure.xml: SYNTHETIC_DERIVED_FROM_OFFICIAL_SOURCE
- insecure.xml: SYNTHETIC_DERIVED_FROM_OFFICIAL_SOURCE
- ambiguous.xml: SYNTHETIC_DERIVED_FROM_OFFICIAL_SOURCE
- malformed.xml: SYNTHETIC_DERIVED_FROM_OFFICIAL_SOURCE
- official_example.xml: OFFICIAL_VENDOR_EXAMPLE
- cli_export.conf: SYNTHETIC_DERIVED_FROM_OFFICIAL_SOURCE

CIS / STIG STATUS:
- NO official CIS Benchmark exists for WatchGuard Firebox / Fireware.
- NO official DISA STIG exists for WatchGuard.
- Security controls are mapped to OFFICIAL_WATCHGUARD_GUIDANCE and INTERNAL_BASELINE.
"""

from pathlib import Path
from typing import List

import pytest

from auditor.engine import ComplianceEngine
from auditor.identity.extractors import extract_identity
from auditor.models.baseline import SecurityBaselineModel, SnmpCommunity
from auditor.models.observation import Observation, Origin
from auditor.models.result import Status
from auditor.parsers.base import ParserError, registry
from auditor.parsers.cisco_ios import CiscoIOSParser
from auditor.parsers.fortios import FortiosParser
from auditor.parsers.junos import JunosParser
from auditor.parsers.mikrotik_routeros import MikroTikROSParser
from auditor.parsers.sonicwall import SonicWallParser
from auditor.parsers.stormshield import StormshieldParser
from auditor.parsers.watchguard import WatchGuardParser
from auditor.pipeline import RulesetResolver, evaluate, parse_config, select_parser
from auditor.rules import load_framework

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "watchguard"
SECURE = (SAMPLES / "secure.xml").read_text(encoding="utf-8")
INSECURE = (SAMPLES / "insecure.xml").read_text(encoding="utf-8")
AMBIGUOUS = (SAMPLES / "ambiguous.xml").read_text(encoding="utf-8")
MALFORMED = (SAMPLES / "malformed.xml").read_text(encoding="utf-8")
UNKNOWN = (SAMPLES / "unknown.xml").read_text(encoding="utf-8")
OFFICIAL_EXAMPLE = (SAMPLES / "official_example.xml").read_text(encoding="utf-8")
CLI_EXPORT = (SAMPLES / "cli_export.conf").read_text(encoding="utf-8")


def _parse(text: str) -> SecurityBaselineModel:
    return WatchGuardParser().parse(text)


# ---------------------------------------------------------------------------
# 1. Detection
# ---------------------------------------------------------------------------


class TestDetection:

    def test_detects_secure_config(self):
        score = WatchGuardParser.detect(SECURE)
        assert score >= 0.5

    def test_detects_insecure_config(self):
        score = WatchGuardParser.detect(INSECURE)
        assert score >= 0.5

    def test_detects_ambiguous_config(self):
        score = WatchGuardParser.detect(AMBIGUOUS)
        assert score >= 0.3

    def test_detects_official_example(self):
        score = WatchGuardParser.detect(OFFICIAL_EXAMPLE)
        assert score >= 0.5

    def test_detects_cli_export(self):
        score = WatchGuardParser.detect(CLI_EXPORT)
        assert score >= 0.5

    def test_rejects_cisco_ios(self):
        ios = (SAMPLES.parent / "insecure_ios.conf").read_text()
        assert WatchGuardParser.detect(ios) == 0.0

    def test_rejects_junos(self):
        junos = (SAMPLES.parent / "junos_srx.conf").read_text()
        assert WatchGuardParser.detect(junos) == 0.0

    def test_rejects_fortios(self):
        fortios = (SAMPLES.parent / "fortios_fgt.conf").read_text()
        assert WatchGuardParser.detect(fortios) == 0.0

    def test_rejects_stormshield(self):
        sns = (SAMPLES.parent / "stormshield" / "insecure.conf").read_text()
        assert WatchGuardParser.detect(sns) == 0.0

    def test_rejects_sonicwall(self):
        sw = (SAMPLES.parent / "sonicwall" / "insecure.conf").read_text()
        assert WatchGuardParser.detect(sw) == 0.0

    def test_rejects_paloalto(self):
        panos = (SAMPLES.parent / "paloalto_panos.xml").read_text()
        assert WatchGuardParser.detect(panos) == 0.0

    def test_rejects_sonic(self):
        sonic = (SAMPLES.parent / "sonic" / "insecure.conf").read_text()
        assert WatchGuardParser.detect(sonic) == 0.0

    def test_rejects_checkpoint(self):
        gaia = (SAMPLES.parent / "checkpoint_gaia" / "insecure.conf").read_text()
        assert WatchGuardParser.detect(gaia) == 0.0

    def test_rejects_mikrotik(self):
        ros = (SAMPLES.parent / "mikrotik_routeros" / "insecure.conf").read_text()
        assert WatchGuardParser.detect(ros) == 0.0

    def test_rejects_unknown(self):
        assert WatchGuardParser.detect(UNKNOWN) == 0.0

    def test_rejects_empty(self):
        assert WatchGuardParser.detect("") == 0.0
        assert WatchGuardParser.detect("   \n\t  ") == 0.0


# ---------------------------------------------------------------------------
# 2. Registration & Discovery
# ---------------------------------------------------------------------------


class TestRegistration:

    def test_parser_is_registered(self):
        assert "watchguard_fireware" in registry.names()
        assert registry.get("watchguard_fireware") is WatchGuardParser

    def test_auto_detect_selects_watchguard(self):
        parser_cls, confidence = registry.detect(SECURE)
        assert parser_cls is WatchGuardParser
        assert confidence >= 0.5

    def test_parser_attributes(self):
        p = WatchGuardParser()
        assert p.name == "watchguard_fireware"
        assert p.vendor == "watchguard"
        assert p.os_family == "fireware"
        assert p.version == "1.0.0"
        assert p.base_confidence == 1.0


# ---------------------------------------------------------------------------
# 3. Extraction & Normalization (Secure)
# ---------------------------------------------------------------------------


class TestSecureConfigExtraction:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.model = _parse(SECURE)

    def test_provenance(self):
        assert self.model.provenance.vendor == "watchguard"
        assert self.model.provenance.os_family == "fireware"
        assert self.model.provenance.parser_name == "watchguard_fireware"
        assert self.model.provenance.detection_confidence >= 0.5

    def test_hostname(self):
        assert self.model.hostname.detected is True
        assert self.model.hostname.value == "WG-FIREBOX-SEC01"
        assert self.model.hostname.line_number is not None

    def test_platform_invariants(self):
        assert self.model.telnet_enabled.detected is True
        assert self.model.telnet_enabled.value is False
        assert self.model.http_server_enabled.detected is True
        assert self.model.http_server_enabled.value is False
        assert self.model.ssh_version.detected is True
        assert self.model.ssh_version.value == 2
        assert self.model.enable_secret_set.detected is True
        assert self.model.enable_secret_set.value is True
        assert self.model.password_encryption.detected is True
        assert self.model.password_encryption.value is True

    def test_https_web_ui(self):
        assert self.model.https_server_enabled.detected is True
        assert self.model.https_server_enabled.value is True

    def test_ssh_management(self):
        assert self.model.ssh_enabled.detected is True
        assert self.model.ssh_enabled.value is True
        assert self.model.vty_transport_input.detected is True
        assert self.model.vty_transport_input.value == ["ssh"]

    def test_idle_timeout(self):
        assert self.model.vty_exec_timeout_seconds.detected is True
        assert self.model.vty_exec_timeout_seconds.value == 600

    def test_logon_disclaimer(self):
        assert self.model.login_banner_present.detected is True
        assert self.model.login_banner_present.value is True
        assert self.model.pre_login_banner_present.detected is True
        assert self.model.pre_login_banner_present.value is True
        assert self.model.post_login_banner_present.detected is True
        assert self.model.post_login_banner_present.value is True

    def test_password_policy(self):
        assert self.model.password_min_length.detected is True
        assert self.model.password_min_length.value == 16
        assert self.model.password_max_age_days.detected is True
        assert self.model.password_max_age_days.value == 90

    def test_account_lockout(self):
        assert self.model.admin_lockout_threshold.detected is True
        assert self.model.admin_lockout_threshold.value == 3
        assert self.model.admin_lockout_duration.detected is True
        assert self.model.admin_lockout_duration.value == 900

    def test_aaa(self):
        assert self.model.aaa_enabled.detected is True
        assert self.model.aaa_enabled.value is True

    def test_management_acl(self):
        assert self.model.management_acl_applied.detected is True
        assert self.model.management_acl_applied.value is True

    def test_snmp(self):
        assert self.model.snmp_agent_enabled.detected is True
        assert self.model.snmp_agent_enabled.value is True
        assert self.model.snmp_communities.detected is True
        comms = self.model.snmp_communities.value
        assert len(comms) == 1
        assert comms[0].name == "SecMonWG2026"
        assert comms[0].access == "ro"
        assert comms[0].acl == "10.0.0.100"
        assert self.model.snmp_v3_users_present.detected is True
        assert self.model.snmp_v3_users_present.value is True

    def test_logging(self):
        assert self.model.logging_enabled.detected is True
        assert self.model.logging_enabled.value is True
        assert self.model.logging_hosts.detected is True
        assert len(self.model.logging_hosts.value) == 2
        assert "10.0.0.50" in self.model.logging_hosts.value

    def test_ntp(self):
        assert self.model.ntp_servers.detected is True
        assert len(self.model.ntp_servers.value) == 2
        assert self.model.ntp_redundant.detected is True
        assert self.model.ntp_redundant.value is True

    def test_dns(self):
        assert self.model.dns_servers.detected is True
        assert len(self.model.dns_servers.value) == 2

    def test_ha(self):
        assert self.model.ha_enabled.detected is True
        assert self.model.ha_enabled.value is True


# ---------------------------------------------------------------------------
# 4. Extraction & Normalization (Insecure)
# ---------------------------------------------------------------------------


class TestInsecureConfigExtraction:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.model = _parse(INSECURE)

    def test_hostname(self):
        assert self.model.hostname.value == "WG-FIREBOX-INSEC02"

    def test_idle_timeout(self):
        assert self.model.vty_exec_timeout_seconds.detected is True
        assert self.model.vty_exec_timeout_seconds.value == 0

    def test_logon_disclaimer_disabled(self):
        assert self.model.login_banner_present.detected is True
        assert self.model.login_banner_present.value is False

    def test_password_policy_weak(self):
        assert self.model.password_min_length.detected is True
        assert self.model.password_min_length.value == 6

    def test_account_lockout_disabled(self):
        assert self.model.admin_lockout_threshold.detected is True
        assert self.model.admin_lockout_threshold.value == 0
        assert self.model.admin_lockout_duration.detected is True
        assert self.model.admin_lockout_duration.value == 0

    def test_management_acl_insecure(self):
        assert self.model.management_acl_applied.detected is True
        assert self.model.management_acl_applied.value is False

    def test_snmp_v1_public(self):
        assert self.model.snmp_agent_enabled.detected is True
        assert self.model.snmp_agent_enabled.value is True
        comms = self.model.snmp_communities.value
        assert len(comms) == 1
        assert comms[0].name == "public"
        assert comms[0].access == "rw"

    def test_logging_disabled(self):
        assert self.model.logging_enabled.detected is True
        assert self.model.logging_enabled.value is False

    def test_ntp_disabled(self):
        assert self.model.ntp_servers.detected is True
        assert self.model.ntp_servers.value == []
        assert self.model.ntp_redundant.value is False


# ---------------------------------------------------------------------------
# 5. CLI Export Extraction
# ---------------------------------------------------------------------------


class TestCLIExportExtraction:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.model = _parse(CLI_EXPORT)

    def test_hostname(self):
        assert self.model.hostname.value == "WG-FIREBOX-CLI01"

    def test_idle_timeout(self):
        assert self.model.vty_exec_timeout_seconds.value == 600

    def test_logon_disclaimer(self):
        assert self.model.login_banner_present.value is True

    def test_password_min_length(self):
        assert self.model.password_min_length.value == 16

    def test_account_lockout(self):
        assert self.model.admin_lockout_threshold.value == 3
        assert self.model.admin_lockout_duration.value == 900

    def test_aaa(self):
        assert self.model.aaa_enabled.value is True

    def test_snmp(self):
        assert self.model.snmp_agent_enabled.value is True
        assert len(self.model.snmp_communities.value) == 1
        assert self.model.snmp_communities.value[0].name == "SecMonWG2026"

    def test_logging(self):
        assert self.model.logging_enabled.value is True
        assert len(self.model.logging_hosts.value) == 2

    def test_ntp(self):
        assert len(self.model.ntp_servers.value) == 2
        assert self.model.ntp_redundant.value is True


# ---------------------------------------------------------------------------
# 6. Official Example Extraction
# ---------------------------------------------------------------------------


class TestOfficialExampleExtraction:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.model = _parse(OFFICIAL_EXAMPLE)

    def test_hostname(self):
        assert self.model.hostname.value == "Firebox-T80-Office"

    def test_password_policy(self):
        assert self.model.password_min_length.value == 12

    def test_lockout(self):
        assert self.model.admin_lockout_threshold.value == 5
        assert self.model.admin_lockout_duration.value == 1800

    def test_snmp_v3(self):
        assert self.model.snmp_v3_users_present.value is True


# ---------------------------------------------------------------------------
# 7. Absence Semantics
# ---------------------------------------------------------------------------


class TestAbsenceSemantics:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.model = _parse(AMBIGUOUS)

    def test_missing_ntp_is_absent(self):
        assert self.model.ntp_servers.detected is True
        assert self.model.ntp_servers.source_line is None
        assert self.model.ntp_servers.value == []

    def test_missing_snmp_is_absent(self):
        assert self.model.snmp_agent_enabled.detected is True
        assert self.model.snmp_agent_enabled.source_line is None
        assert self.model.snmp_agent_enabled.value is False

    def test_missing_logging_is_unknown(self):
        assert self.model.logging_enabled.detected is False

    def test_missing_lockout_is_unknown(self):
        assert self.model.admin_lockout_threshold.detected is False

    def test_missing_banner_is_absent(self):
        assert self.model.login_banner_present.detected is True
        assert self.model.login_banner_present.source_line is None
        assert self.model.login_banner_present.value is False


# ---------------------------------------------------------------------------
# 8. Malformed & Empty Inputs
# ---------------------------------------------------------------------------


class TestMalformedAndEmpty:

    def test_malformed_xml_raises_parser_error(self):
        with pytest.raises(ParserError):
            WatchGuardParser().parse(MALFORMED)

    def test_empty_string_raises_parser_error(self):
        with pytest.raises(ParserError):
            WatchGuardParser().parse("")

    def test_whitespace_raises_parser_error(self):
        with pytest.raises(ParserError):
            WatchGuardParser().parse("   \n\t  ")


# ---------------------------------------------------------------------------
# 9. Cross-Vendor Isolation
# ---------------------------------------------------------------------------


class TestCrossVendorIsolation:

    def test_vendor_sequence_isolation(self):
        cisco_sample = (SAMPLES.parent / "insecure_ios.conf").read_text()
        junos_sample = (SAMPLES.parent / "junos_srx.conf").read_text()

        m1 = WatchGuardParser().parse(SECURE)
        assert m1.provenance.vendor == "watchguard"
        assert m1.hostname.value == "WG-FIREBOX-SEC01"

        m2 = CiscoIOSParser().parse(cisco_sample)
        assert m2.provenance.vendor == "cisco"
        assert m2.hostname.value == "BRANCH-SW-07"

        m3 = JunosParser().parse(junos_sample)
        assert m3.provenance.vendor == "juniper"

        m4 = WatchGuardParser().parse(INSECURE)
        assert m4.provenance.vendor == "watchguard"
        assert m4.hostname.value == "WG-FIREBOX-INSEC02"

    def test_stormshield_watchguard_isolation(self):
        sns_sample = (SAMPLES.parent / "stormshield" / "secure.conf").read_text()

        m_sns = StormshieldParser().parse(sns_sample)
        assert m_sns.provenance.vendor == "stormshield"
        assert m_sns.hostname.value == "SNS-SECURE-GW01"

        m_wg = WatchGuardParser().parse(SECURE)
        assert m_wg.provenance.vendor == "watchguard"
        assert m_wg.hostname.value == "WG-FIREBOX-SEC01"


# ---------------------------------------------------------------------------
# 10. False-Pass Testing
# ---------------------------------------------------------------------------


class TestFalsePassResilience:

    def test_adversarial_comments_not_parsed_as_config(self):
        xml_with_comment = """<?xml version="1.0" encoding="UTF-8"?>
<configuration version="12.10.2">
  <system-parameters>
    <device-name>WG-COMMENT-TEST</device-name>
    <!-- <idle-timeout>10</idle-timeout> -->
  </system-parameters>
</configuration>
"""
        model = _parse(xml_with_comment)
        assert model.vty_exec_timeout_seconds.detected is False

    def test_decoy_hostname_keywords(self):
        xml_decoy = """<?xml version="1.0" encoding="UTF-8"?>
<configuration version="12.10.2">
  <system-parameters>
    <device-name>WG-SECURE-HTTPS-SSH-ENABLE-NTP-SNMP</device-name>
  </system-parameters>
</configuration>
"""
        model = _parse(xml_decoy)
        assert model.hostname.value == "WG-SECURE-HTTPS-SSH-ENABLE-NTP-SNMP"
        assert model.ntp_servers.source_line is None
        assert model.snmp_agent_enabled.source_line is None


# ---------------------------------------------------------------------------
# 11. Device Identity Extraction
# ---------------------------------------------------------------------------


class TestDeviceIdentity:

    def test_extract_identity_from_secure_xml(self):
        model = _parse(SECURE)
        ident = extract_identity(SECURE, model)
        assert ident.vendor == "watchguard_fireware"
        assert ident.hostname.value == "WG-FIREBOX-SEC01"
        assert ident.os_version.value == "12.10.2"

    def test_extract_identity_from_cli_export(self):
        model = _parse(CLI_EXPORT)
        ident = extract_identity(CLI_EXPORT, model)
        assert ident.vendor == "watchguard_fireware"
        assert ident.hostname.value == "WG-FIREBOX-CLI01"
        assert "12.10.2" in ident.os_version.value
        assert ident.model.value == "T80"


# ---------------------------------------------------------------------------
# 12. Full Pipeline & Compliance Engine Flow
# ---------------------------------------------------------------------------


class TestComplianceEngineFlow:

    def test_pipeline_evaluate_secure(self):
        rules = load_framework("CIS", "watchguard_fireware", allow_cross_platform=True)
        engine = ComplianceEngine(rules)
        results = engine.evaluate(_parse(SECURE))
        assert len(results) > 0
        # Hostname and other verified fields should evaluate
        pass_results = [r for r in results if r.status == Status.PASS]
        assert len(pass_results) > 0

    def test_pipeline_evaluate_insecure(self):
        rules = load_framework("CIS", "watchguard_fireware", allow_cross_platform=True)
        engine = ComplianceEngine(rules)
        results = engine.evaluate(_parse(INSECURE))
        assert len(results) > 0
        fail_results = [r for r in results if r.status == Status.FAIL]
        assert len(fail_results) > 0
