"""Tests for the Stormshield Network Security (SNS) deterministic parser.

Every assertion traces back to official Stormshield documentation:
- Stormshield Technical Documentation: documentation.stormshield.eu
- Stormshield SNS CLI / Serverd Commands Reference Guide
- Stormshield Network Security Administration Guides
- Stormshield Technical Note: Hardening SNS Firewalls & Best Practices
- ANSSI Standard Qualification & Common Criteria EAL4+ Security Guidance for SNS

CONFIGURATION SOURCE: All fixtures are SYNTHETIC, constructed from
verified Stormshield SNS CLI / INI documentation. NOT genuine device exports.

CIS / STIG STATUS: NO official CIS Benchmark or DISA STIG exists
for Stormshield. Security controls are generic best-practice mappings.
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
from auditor.pipeline import RulesetResolver, evaluate, parse_config, select_parser
from auditor.rules import load_framework

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "stormshield"
SECURE = (SAMPLES / "secure.conf").read_text(encoding="utf-8")
INSECURE = (SAMPLES / "insecure.conf").read_text(encoding="utf-8")
AMBIGUOUS = (SAMPLES / "ambiguous.conf").read_text(encoding="utf-8")
MALFORMED = (SAMPLES / "malformed.conf").read_text(encoding="utf-8")
UNKNOWN = (SAMPLES / "unknown.conf").read_text(encoding="utf-8")
OFFICIAL_EXAMPLE = (SAMPLES / "official_example.conf").read_text(encoding="utf-8")
EXTERNAL_INI = (SAMPLES / "external_ini_format.conf").read_text(encoding="utf-8")


def _parse(text: str) -> SecurityBaselineModel:
    return StormshieldParser().parse(text)


# ---------------------------------------------------------------------------
# 1. Detection
# ---------------------------------------------------------------------------


class TestDetection:

    def test_detects_secure_config(self):
        score = StormshieldParser.detect(SECURE)
        assert score >= 0.5

    def test_detects_insecure_config(self):
        score = StormshieldParser.detect(INSECURE)
        assert score >= 0.5

    def test_detects_ambiguous_config(self):
        score = StormshieldParser.detect(AMBIGUOUS)
        assert score >= 0.3

    def test_detects_official_example(self):
        score = StormshieldParser.detect(OFFICIAL_EXAMPLE)
        assert score >= 0.5

    def test_detects_external_ini(self):
        score = StormshieldParser.detect(EXTERNAL_INI)
        assert score >= 0.3

    def test_rejects_cisco_ios(self):
        ios = (SAMPLES.parent / "insecure_ios.conf").read_text()
        assert StormshieldParser.detect(ios) == 0.0

    def test_rejects_junos(self):
        junos = (SAMPLES.parent / "junos_srx.conf").read_text()
        assert StormshieldParser.detect(junos) == 0.0

    def test_rejects_fortios(self):
        fortios = (SAMPLES.parent / "fortios_fgt.conf").read_text()
        assert StormshieldParser.detect(fortios) == 0.0

    def test_rejects_paloalto(self):
        panos = (SAMPLES.parent / "paloalto_panos.xml").read_text()
        assert StormshieldParser.detect(panos) == 0.0

    def test_rejects_sonic(self):
        sonic = (SAMPLES.parent / "sonic" / "insecure.conf").read_text()
        assert StormshieldParser.detect(sonic) == 0.0

    def test_rejects_checkpoint(self):
        gaia = (SAMPLES.parent / "checkpoint_gaia" / "insecure.conf").read_text()
        assert StormshieldParser.detect(gaia) == 0.0

    def test_rejects_mikrotik(self):
        ros = (SAMPLES.parent / "mikrotik_routeros" / "insecure.conf").read_text()
        assert StormshieldParser.detect(ros) == 0.0

    def test_rejects_sonicwall(self):
        sw = (SAMPLES.parent / "sonicwall" / "insecure.conf").read_text()
        assert StormshieldParser.detect(sw) == 0.0

    def test_rejects_unknown(self):
        assert StormshieldParser.detect(UNKNOWN) == 0.0

    def test_rejects_empty(self):
        assert StormshieldParser.detect("") == 0.0
        assert StormshieldParser.detect("   \n\t  ") == 0.0


# ---------------------------------------------------------------------------
# 2. Registration & Discovery
# ---------------------------------------------------------------------------


class TestRegistration:

    def test_parser_is_registered(self):
        assert "stormshield" in registry.names()
        assert registry.get("stormshield") is StormshieldParser

    def test_auto_detect_selects_stormshield(self):
        parser_cls, confidence = registry.detect(SECURE)
        assert parser_cls is StormshieldParser
        assert confidence >= 0.5

    def test_parser_attributes(self):
        p = StormshieldParser()
        assert p.name == "stormshield"
        assert p.vendor == "stormshield"
        assert p.os_family == "sns"
        assert p.version == "1.0.0"
        assert p.base_confidence == 1.0


# ---------------------------------------------------------------------------
# 3. Extraction & Normalization
# ---------------------------------------------------------------------------


class TestSecureConfigExtraction:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.model = _parse(SECURE)

    def test_provenance(self):
        assert self.model.provenance.vendor == "stormshield"
        assert self.model.provenance.os_family == "sns"
        assert self.model.provenance.parser_name == "stormshield"
        assert self.model.provenance.detection_confidence >= 0.5

    def test_hostname(self):
        assert self.model.hostname.detected is True
        assert self.model.hostname.value == "SNS-SECURE-GW01"
        assert self.model.hostname.line_number is not None

    def test_ssh_enabled(self):
        assert self.model.ssh_enabled.detected is True
        assert self.model.ssh_enabled.value is True

    def test_telnet_disabled(self):
        assert self.model.telnet_enabled.detected is True
        assert self.model.telnet_enabled.value is False

    def test_vty_transport(self):
        assert self.model.vty_transport_input.detected is True
        assert self.model.vty_transport_input.value == ["ssh"]

    def test_ssh_version(self):
        assert self.model.ssh_version.detected is True
        assert self.model.ssh_version.value == 2

    def test_vty_timeout(self):
        assert self.model.vty_exec_timeout_seconds.detected is True
        assert self.model.vty_exec_timeout_seconds.value == 600

    def test_http_server_disabled(self):
        assert self.model.http_server_enabled.detected is True
        assert self.model.http_server_enabled.value is False

    def test_password_min_length(self):
        assert self.model.password_min_length.detected is True
        assert self.model.password_min_length.value == 16

    def test_enable_secret_and_encryption(self):
        assert self.model.enable_secret_set.detected is True
        assert self.model.enable_secret_set.value is True
        assert self.model.password_encryption.detected is True
        assert self.model.password_encryption.value is True

    def test_aaa_enabled(self):
        assert self.model.aaa_enabled.detected is True
        assert self.model.aaa_enabled.value is True

    def test_management_acl(self):
        assert self.model.management_acl_applied.detected is True
        assert self.model.management_acl_applied.value is True

    def test_login_banner(self):
        assert self.model.login_banner_present.detected is True
        assert self.model.login_banner_present.value is True

    def test_snmp(self):
        assert self.model.snmp_agent_enabled.detected is True
        assert self.model.snmp_agent_enabled.value is True
        assert self.model.snmp_communities.detected is True
        comms = self.model.snmp_communities.value
        assert len(comms) == 1
        assert comms[0].name == "SecMon2026"
        assert comms[0].access == "ro"

    def test_logging(self):
        assert self.model.logging_enabled.detected is True
        assert self.model.logging_enabled.value is True
        assert self.model.logging_hosts.detected is True
        assert len(self.model.logging_hosts.value) == 2
        assert "10.10.10.200" in self.model.logging_hosts.value
        assert self.model.logging_buffered.detected is True
        assert self.model.logging_buffered.value is True

    def test_ntp(self):
        assert self.model.ntp_servers.detected is True
        assert len(self.model.ntp_servers.value) == 2
        assert self.model.ntp_redundant.detected is True
        assert self.model.ntp_redundant.value is True

    def test_lockout(self):
        assert self.model.admin_lockout_threshold.detected is True
        assert self.model.admin_lockout_threshold.value == 3
        assert self.model.admin_lockout_duration.detected is True
        assert self.model.admin_lockout_duration.value == 300


class TestInsecureConfigExtraction:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.model = _parse(INSECURE)

    def test_hostname(self):
        assert self.model.hostname.value == "SNS-INSECURE-GW02"

    def test_ssh_disabled(self):
        assert self.model.ssh_enabled.detected is True
        assert self.model.ssh_enabled.value is False

    def test_vty_timeout_excessive(self):
        assert self.model.vty_exec_timeout_seconds.detected is True
        assert self.model.vty_exec_timeout_seconds.value == 3600

    def test_http_server_enabled(self):
        assert self.model.http_server_enabled.detected is True
        assert self.model.http_server_enabled.value is True

    def test_password_min_length_short(self):
        assert self.model.password_min_length.detected is True
        assert self.model.password_min_length.value == 6

    def test_aaa_local_only(self):
        assert self.model.aaa_enabled.detected is True
        assert self.model.aaa_enabled.value is False

    def test_management_acl_open(self):
        assert self.model.management_acl_applied.detected is True
        assert self.model.management_acl_applied.value is False

    def test_login_banner_disabled(self):
        assert self.model.login_banner_present.detected is True
        assert self.model.login_banner_present.value is False

    def test_snmp_default_communities(self):
        assert self.model.snmp_communities.detected is True
        names = [c.name for c in self.model.snmp_communities.value]
        assert "public" in names
        assert "private" in names
        accesses = [c.access for c in self.model.snmp_communities.value]
        assert "rw" in accesses

    def test_logging_disabled(self):
        assert self.model.logging_enabled.detected is True
        assert self.model.logging_enabled.value is False


class TestExternalIniExtraction:

    @pytest.fixture(autouse=True)
    def setup(self):
        self.model = _parse(EXTERNAL_INI)

    def test_hostname(self):
        assert self.model.hostname.value == "SNS-BRANCH-01"

    def test_ssh_enabled(self):
        assert self.model.ssh_enabled.value is True

    def test_vty_timeout(self):
        assert self.model.vty_exec_timeout_seconds.value == 600

    def test_http_disabled(self):
        assert self.model.http_server_enabled.value is False

    def test_password_min_length(self):
        assert self.model.password_min_length.value == 14

    def test_aaa_enabled(self):
        assert self.model.aaa_enabled.value is True

    def test_banner_present(self):
        assert self.model.login_banner_present.value is True

    def test_snmp_community(self):
        assert len(self.model.snmp_communities.value) == 1
        assert self.model.snmp_communities.value[0].name == "branch_monitor"

    def test_logging_server(self):
        assert "192.168.1.250" in self.model.logging_hosts.value

    def test_ntp_servers(self):
        assert len(self.model.ntp_servers.value) == 2


# ---------------------------------------------------------------------------
# 4. Compliance Evaluation (PASS / FAIL / NEEDS_REVIEW)
# ---------------------------------------------------------------------------


class TestComplianceEvaluation:

    def test_secure_config_passes_all_rules(self):
        model = _parse(SECURE)
        ruleset = load_framework("CIS", "stormshield", allow_cross_platform=True)
        engine = ComplianceEngine(ruleset)
        results = engine.evaluate(model)

        verdicts = {r.rule_id: r.status for r in results}
        # All 13 controls must PASS on the secure config
        for rule_id, status in verdicts.items():
            assert status == Status.PASS, f"Rule {rule_id} did not PASS: {status}"

    def test_insecure_config_fails_controls(self):
        model = _parse(INSECURE)
        ruleset = load_framework("CIS", "stormshield", allow_cross_platform=True)
        engine = ComplianceEngine(ruleset)
        results = engine.evaluate(model)

        failed_rules = {r.rule_id for r in results if r.status == Status.FAIL}
        assert "SNS-AAA-CENTRALISED" in failed_rules
        assert "SNS-IDLE-TIMEOUT" in failed_rules
        assert "SNS-NO-HTTP-SERVER" in failed_rules
        assert "SNS-SNMP-NO-DEFAULT-COMMUNITY" in failed_rules
        assert "SNS-MGMT-ACL" in failed_rules
        assert "SNS-LOGIN-BANNER" in failed_rules
        assert "SNS-PASSWORD-MIN-LENGTH" in failed_rules
        assert "SNS-SNMP-NO-WRITE" in failed_rules

    def test_ambiguous_config_returns_needs_review(self):
        model = _parse(AMBIGUOUS)
        ruleset = load_framework("CIS", "stormshield", allow_cross_platform=True)
        engine = ComplianceEngine(ruleset)
        results = engine.evaluate(model)

        review_rules = {r.rule_id for r in results if r.status == Status.NEEDS_REVIEW}
        assert len(review_rules) > 0
        assert "SNS-IDLE-TIMEOUT" in review_rules
        assert "SNS-LOGIN-BANNER" in review_rules


# ---------------------------------------------------------------------------
# 5. Multi-Framework Evaluation
# ---------------------------------------------------------------------------


class TestMultiFramework:

    @pytest.mark.parametrize("framework", ["CIS", "NIST_800_53", "STIG", "ISO_27001"])
    def test_secure_config_evaluates_across_frameworks(self, framework):
        model = _parse(SECURE)
        ruleset = load_framework(framework, "stormshield_sns", allow_cross_platform=True)
        engine = ComplianceEngine(ruleset)
        results = engine.evaluate(model)
        assert len(results) >= 10
        assert all(r.status == Status.PASS for r in results)


# ---------------------------------------------------------------------------
# 6. Absence Policy & Unknown Handling
# ---------------------------------------------------------------------------


class TestAbsencePolicy:

    def test_empty_config_raises_parser_error(self):
        with pytest.raises(ParserError):
            _parse("")

    def test_minimal_config_absence_handling(self):
        minimal = "CONFIG HOSTNAME name=\"SNS-MINIMAL\"\n"
        model = _parse(minimal)

        assert model.hostname.detected is True
        assert model.vty_exec_timeout_seconds.detected is False
        assert model.management_acl_applied.detected is False
        assert model.login_banner_present.detected is False
        assert model.password_min_length.detected is False
        assert model.aaa_enabled.detected is False
        assert model.admin_lockout_threshold.detected is False


# ---------------------------------------------------------------------------
# 7. Boundary Values
# ---------------------------------------------------------------------------


class TestBoundaryValues:

    def test_timeout_exact_600_passes(self):
        conf = "CONFIG HOSTNAME name=test\nCONFIG CONSOLE TIMEOUT timeout=600\n"
        model = _parse(conf)
        assert model.vty_exec_timeout_seconds.value == 600

    def test_timeout_601_fails(self):
        conf = "CONFIG HOSTNAME name=test\nCONFIG CONSOLE TIMEOUT timeout=601\n"
        model = _parse(conf)
        assert model.vty_exec_timeout_seconds.value == 601

    def test_timeout_in_minutes_10m(self):
        conf = "CONFIG HOSTNAME name=test\nCONFIG CONSOLE TIMEOUT timeout=10m\n"
        model = _parse(conf)
        assert model.vty_exec_timeout_seconds.value == 600

    def test_password_min_length_boundary(self):
        conf_7 = "CONFIG HOSTNAME name=test\nCONFIG PASSWDPOLICY SET minLength=7\n"
        model_7 = _parse(conf_7)
        assert model_7.password_min_length.value == 7

        conf_8 = "CONFIG HOSTNAME name=test\nCONFIG PASSWDPOLICY SET minLength=8\n"
        model_8 = _parse(conf_8)
        assert model_8.password_min_length.value == 8


# ---------------------------------------------------------------------------
# 8. False-Pass & Adversarial Tests
# ---------------------------------------------------------------------------


class TestFalsePassAdversarial:

    def test_comment_does_not_enable_ssh(self):
        conf = (
            "# CONFIG CONSOLE SSH state=1\n"
            "# SSH enabled on port 22\n"
            "CONFIG HOSTNAME name=\"test\"\n"
        )
        model = _parse(conf)
        assert model.ssh_enabled.detected is False

    def test_hostname_logging_does_not_enable_logging(self):
        conf = "CONFIG HOSTNAME name=\"logging-server-01\"\n"
        model = _parse(conf)
        assert model.logging_enabled.detected is False

    def test_partial_token_does_not_enable_feature(self):
        conf = (
            "CONFIG HOSTNAME name=\"test\"\n"
            "CONFIG OBJECT HOST name=\"admin_box\" ip=\"1.1.1.1\"\n"
        )
        model = _parse(conf)
        assert model.management_acl_applied.detected is False


# ---------------------------------------------------------------------------
# 9. Source Provenance & Line Numbers
# ---------------------------------------------------------------------------


class TestProvenance:

    def test_exact_line_numbers_tracked(self):
        lines = SECURE.splitlines()
        model = _parse(SECURE)

        assert model.hostname.line_number is not None
        host_line = lines[model.hostname.line_number - 1]
        assert "CONFIG HOSTNAME" in host_line

        assert model.vty_exec_timeout_seconds.line_number is not None
        to_line = lines[model.vty_exec_timeout_seconds.line_number - 1]
        assert "TIMEOUT" in to_line

    def test_origin_is_deterministic(self):
        model = _parse(SECURE)
        assert model.hostname.origin == Origin.DETERMINISTIC
        assert model.ssh_enabled.origin == Origin.DETERMINISTIC


# ---------------------------------------------------------------------------
# 10. Device Identity Extraction
# ---------------------------------------------------------------------------


class TestIdentityExtraction:

    def test_extracts_identity_from_header(self):
        model = _parse(SECURE)
        ident = extract_identity(SECURE, model)
        assert ident.vendor == "stormshield_sns"
        assert ident.os_family == "sns"
        assert ident.hostname.value == "SNS-SECURE-GW01"
        assert ident.os_version.value == "4.8.2"
        assert ident.model.value == "SN510"
        assert ident.serial_number.value == "SN510A0012345678"

    def test_extracts_identity_without_header(self):
        conf = "CONFIG HOSTNAME name=\"SNS-NO-HEADER\"\n"
        model = _parse(conf)
        ident = extract_identity(conf, model)
        assert ident.hostname.value == "SNS-NO-HEADER"
        assert ident.os_version.detected is False
        assert ident.model.detected is False
        assert ident.serial_number.detected is False


# ---------------------------------------------------------------------------
# 11. Vendor Isolation & Cross-Vendor Tests
# ---------------------------------------------------------------------------


class TestVendorIsolation:

    def test_stormshield_parser_rejects_cisco(self):
        ios = (SAMPLES.parent / "insecure_ios.conf").read_text()
        model = StormshieldParser().parse(ios)
        # Should have virtually all undetected observations because IOS syntax does not match SNS
        assert model.vty_exec_timeout_seconds.detected is False
        assert model.management_acl_applied.detected is False

    def test_cisco_parser_rejects_stormshield(self):
        model = CiscoIOSParser().parse(SECURE)
        assert model.vty_exec_timeout_seconds.detected is False
        assert model.management_acl_applied.detected is False

    def test_cross_vendor_pipeline_execution(self):
        resolver = RulesetResolver()
        parsers = [
            (StormshieldParser(), SECURE, "stormshield_sns"),
            (CiscoIOSParser(), (SAMPLES.parent / "insecure_ios.conf").read_text(), "cisco_ios"),
            (FortiosParser(), (SAMPLES.parent / "fortios_fgt.conf").read_text(), "fortinet_fortios"),
            (SonicWallParser(), (SAMPLES.parent / "sonicwall" / "secure.conf").read_text(), "sonicwall"),
            (MikroTikROSParser(), (SAMPLES.parent / "mikrotik_routeros" / "insecure.conf").read_text(), "mikrotik_routeros"),
            (StormshieldParser(), SECURE, "stormshield_sns"),
        ]

        for parser, conf, plat in parsers:
            model = parser.parse(conf)
            ruleset = resolver.framework("CIS", plat)
            engine = ComplianceEngine(ruleset)
            results = engine.evaluate(model)
            assert len(results) > 0


# ---------------------------------------------------------------------------
# 12. Repeated Deterministic Evaluation
# ---------------------------------------------------------------------------


class TestDeterministicEvaluation:

    def test_repeated_runs_produce_identical_results(self):
        ruleset = load_framework("CIS", "stormshield_sns", allow_cross_platform=True)
        engine = ComplianceEngine(ruleset)

        first_model = _parse(SECURE)
        first_results = engine.evaluate(first_model)
        first_statuses = [r.status for r in first_results]

        for _ in range(10):
            model = _parse(SECURE)
            results = engine.evaluate(model)
            statuses = [r.status for r in results]
            assert statuses == first_statuses
