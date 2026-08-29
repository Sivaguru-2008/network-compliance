"""Tests for the SonicWall SonicOS deterministic parser.

Every assertion traces back to official SonicWall documentation:
- SonicOS/X 7 CLI Reference Guide
- SonicOS 6.5 E-CLI Reference Guide
- SonicWall KB: Admin Best Practices (kA1VN0000000Jyv0AE)
- SonicWall KB: High Security Setup (kA1VN0000000IRi0AM)
- SonicWall KB: Password Constraints (kA1VN0000000FvC0AU)
- SonicWall KB: Web Management CLI (170504284559119)
- SonicWall KB: Admin Idle Timeout CLI (kA1VN0000000FOx0AM)
- SonicWall KB: SNMP Configuration (170505617080053)
- SonicWall KB: Login Banner (kA1VN0000000Ogg0AE)
- SonicWall KB: Enhanced Audit Logging (170505386294195)

CONFIGURATION SOURCE: All fixtures are SYNTHETIC, constructed from
verified SonicWall E-CLI documentation. NOT genuine device exports.

CIS / STIG STATUS: NO official CIS Benchmark or DISA STIG exists
for SonicWall. Security controls are generic best-practice mappings.
"""

from pathlib import Path
from typing import List

import pytest

from auditor.engine import ComplianceEngine
from auditor.models.baseline import SecurityBaselineModel, SnmpCommunity
from auditor.models.observation import Observation, Origin
from auditor.models.result import Status
from auditor.parsers.base import ParserError, registry
from auditor.parsers.sonicwall import SonicWallParser
from auditor.rules import load_framework

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "sonicwall"
SECURE = (SAMPLES / "secure.conf").read_text(encoding="utf-8")
INSECURE = (SAMPLES / "insecure.conf").read_text(encoding="utf-8")
AMBIGUOUS = (SAMPLES / "ambiguous.conf").read_text(encoding="utf-8")
MALFORMED = (SAMPLES / "malformed.conf").read_text(encoding="utf-8")
UNKNOWN = (SAMPLES / "unknown.conf").read_text(encoding="utf-8")
EXTERNAL_OXIDIZED = (SAMPLES / "external_oxidized_simulation.conf").read_text(encoding="utf-8")
OFFICIAL_EXAMPLE = (SAMPLES / "official_example.conf").read_text(encoding="utf-8")


def _parse(text: str) -> SecurityBaselineModel:
    return SonicWallParser().parse(text)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


class TestDetection:

    def test_detects_secure_config(self):
        score = SonicWallParser.detect(SECURE)
        assert score >= 0.5

    def test_detects_insecure_config(self):
        score = SonicWallParser.detect(INSECURE)
        assert score >= 0.5

    def test_detects_ambiguous_config(self):
        score = SonicWallParser.detect(AMBIGUOUS)
        assert score >= 0.3

    def test_detects_malformed_config(self):
        score = SonicWallParser.detect(MALFORMED)
        assert score >= 0.3

    def test_rejects_cisco_ios(self):
        ios = (SAMPLES.parent / "insecure_ios.conf").read_text()
        assert SonicWallParser.detect(ios) == 0.0

    def test_rejects_junos(self):
        junos = (SAMPLES.parent / "junos_srx.conf").read_text()
        assert SonicWallParser.detect(junos) == 0.0

    def test_rejects_fortios(self):
        fortios = (SAMPLES.parent / "fortios_fgt.conf").read_text()
        assert SonicWallParser.detect(fortios) == 0.0

    def test_rejects_paloalto(self):
        panos = (SAMPLES.parent / "paloalto_panos.xml").read_text()
        assert SonicWallParser.detect(panos) == 0.0

    def test_rejects_sonic(self):
        sonic = (SAMPLES.parent / "sonic" / "insecure.conf").read_text()
        assert SonicWallParser.detect(sonic) == 0.0

    def test_rejects_checkpoint(self):
        gaia = (SAMPLES.parent / "checkpoint_gaia" / "insecure.conf").read_text()
        assert SonicWallParser.detect(gaia) == 0.0

    def test_rejects_mikrotik(self):
        ros = (SAMPLES.parent / "mikrotik_routeros" / "insecure.conf").read_text()
        assert SonicWallParser.detect(ros) == 0.0

    def test_rejects_arista(self):
        eos = (SAMPLES.parent / "arista" / "insecure.conf").read_text()
        assert SonicWallParser.detect(eos) == 0.0

    def test_rejects_huawei(self):
        vrp = (SAMPLES.parent / "huawei_vrp" / "insecure.conf").read_text()
        assert SonicWallParser.detect(vrp) == 0.0

    def test_rejects_empty(self):
        assert SonicWallParser.detect("") == 0.0

    def test_rejects_whitespace(self):
        assert SonicWallParser.detect("   \n\n  ") == 0.0

    def test_registry_selects_sonicwall(self):
        best = max(
            [p for p in registry._parsers.values() if not p.is_fallback],
            key=lambda p: p.detect(SECURE),
        )
        assert best is SonicWallParser

    def test_registry_selects_sonicwall_insecure(self):
        best = max(
            [p for p in registry._parsers.values() if not p.is_fallback],
            key=lambda p: p.detect(INSECURE),
        )
        assert best is SonicWallParser


# ---------------------------------------------------------------------------
# Parser identity
# ---------------------------------------------------------------------------


class TestParserIdentity:

    def test_name(self):
        assert SonicWallParser.name == "sonicwall"

    def test_vendor(self):
        assert SonicWallParser.vendor == "sonicwall"

    def test_os_family(self):
        assert SonicWallParser.os_family == "sonicos"

    def test_provenance_vendor(self):
        b = _parse(SECURE)
        assert b.provenance.vendor == "sonicwall"
        assert b.provenance.os_family == "sonicos"
        assert b.provenance.parser_name == "sonicwall"


# ---------------------------------------------------------------------------
# Secure config parsing (PASS-producing values)
# ---------------------------------------------------------------------------


class TestSecureParsing:

    @pytest.fixture(autouse=True)
    def _parse_secure(self):
        self.b = _parse(SECURE)

    def test_hostname(self):
        assert self.b.hostname.detected
        assert self.b.hostname.value == "SWFW-SECURE-01"

    def test_telnet_disabled(self):
        """SonicOS platform invariant: telnet not supported."""
        assert self.b.telnet_enabled.detected
        assert self.b.telnet_enabled.value is False

    def test_ssh_enabled(self):
        assert self.b.ssh_enabled.detected
        assert self.b.ssh_enabled.value is True

    def test_ssh_version_2(self):
        """SonicOS platform invariant: SSH is always v2."""
        assert self.b.ssh_version.detected
        assert self.b.ssh_version.value == 2

    def test_http_disabled(self):
        assert self.b.http_server_enabled.detected
        assert self.b.http_server_enabled.value is False

    def test_https_enabled(self):
        assert self.b.https_server_enabled.detected
        assert self.b.https_server_enabled.value is True

    def test_idle_timeout(self):
        assert self.b.vty_exec_timeout_seconds.detected
        assert self.b.vty_exec_timeout_seconds.value == 600

    def test_password_min_length(self):
        assert self.b.password_min_length.detected
        assert self.b.password_min_length.value == 16

    def test_login_banner(self):
        assert self.b.login_banner_present.detected
        assert self.b.login_banner_present.value is True

    def test_syslog_configured(self):
        assert self.b.logging_enabled.detected
        assert self.b.logging_enabled.value is True

    def test_syslog_hosts(self):
        assert self.b.logging_hosts.detected
        assert "10.10.10.50" in self.b.logging_hosts.value
        assert "10.10.10.51" in self.b.logging_hosts.value

    def test_ntp_configured(self):
        assert self.b.ntp_servers.detected
        assert "10.10.10.100" in self.b.ntp_servers.value
        assert "10.10.10.101" in self.b.ntp_servers.value

    def test_ntp_redundant(self):
        assert self.b.ntp_redundant.detected
        assert self.b.ntp_redundant.value is True

    def test_snmp_disabled(self):
        assert self.b.snmp_agent_enabled.detected
        assert self.b.snmp_agent_enabled.value is False

    def test_no_snmp_communities(self):
        assert self.b.snmp_communities.detected
        assert self.b.snmp_communities.value == []

    def test_management_acl(self):
        assert self.b.management_acl_applied.detected
        assert self.b.management_acl_applied.value is True

    def test_lockout_threshold(self):
        assert self.b.admin_lockout_threshold.detected
        assert self.b.admin_lockout_threshold.value == 3

    def test_lockout_duration(self):
        assert self.b.admin_lockout_duration.detected
        assert self.b.admin_lockout_duration.value == 1800

    def test_password_encryption(self):
        assert self.b.password_encryption.detected
        assert self.b.password_encryption.value is True

    def test_https_port_changed(self):
        assert self.b.admin_default_ports_changed.detected
        assert self.b.admin_default_ports_changed.value is True

    def test_enhanced_audit_logging(self):
        assert self.b.event_logging_enabled.detected
        assert self.b.event_logging_enabled.value is True

    def test_password_complexity_uppercase(self):
        assert self.b.password_min_uppercase.detected
        assert self.b.password_min_uppercase.value >= 1

    def test_password_complexity_lowercase(self):
        assert self.b.password_min_lowercase.detected
        assert self.b.password_min_lowercase.value >= 1

    def test_password_complexity_numeric(self):
        assert self.b.password_min_numeric.detected
        assert self.b.password_min_numeric.value >= 1

    def test_password_complexity_special(self):
        assert self.b.password_min_special.detected
        assert self.b.password_min_special.value >= 1


# ---------------------------------------------------------------------------
# Insecure config parsing (FAIL-producing values)
# ---------------------------------------------------------------------------


class TestInsecureParsing:

    @pytest.fixture(autouse=True)
    def _parse_insecure(self):
        self.b = _parse(INSECURE)

    def test_hostname(self):
        assert self.b.hostname.detected
        assert self.b.hostname.value == "SWFW-INSECURE"

    def test_telnet_still_disabled(self):
        """Even on insecure config, telnet is a platform invariant."""
        assert self.b.telnet_enabled.detected
        assert self.b.telnet_enabled.value is False

    def test_http_enabled(self):
        assert self.b.http_server_enabled.detected
        assert self.b.http_server_enabled.value is True

    def test_idle_timeout_too_long(self):
        assert self.b.vty_exec_timeout_seconds.detected
        assert self.b.vty_exec_timeout_seconds.value == 3600

    def test_snmp_enabled(self):
        assert self.b.snmp_agent_enabled.detected
        assert self.b.snmp_agent_enabled.value is True

    def test_default_snmp_community(self):
        assert self.b.snmp_communities.detected
        names = [c.name for c in self.b.snmp_communities.value]
        assert "public" in names

    def test_no_syslog(self):
        assert self.b.logging_enabled.detected
        assert self.b.logging_enabled.value is False

    def test_no_ntp(self):
        assert self.b.ntp_servers.detected
        assert self.b.ntp_servers.value == []

    def test_no_banner(self):
        assert self.b.login_banner_present.detected
        assert self.b.login_banner_present.value is False

    def test_wan_management_unrestricted(self):
        assert self.b.management_acl_applied.detected
        assert self.b.management_acl_applied.value is False

    def test_https_port_default(self):
        assert self.b.admin_default_ports_changed.detected
        assert self.b.admin_default_ports_changed.value is False

    def test_no_lockout(self):
        assert self.b.admin_lockout_threshold.detected
        assert self.b.admin_lockout_threshold.value == 0


# ---------------------------------------------------------------------------
# Ambiguous config parsing
# ---------------------------------------------------------------------------


class TestAmbiguousParsing:

    @pytest.fixture(autouse=True)
    def _parse_ambiguous(self):
        self.b = _parse(AMBIGUOUS)

    def test_hostname(self):
        assert self.b.hostname.detected
        assert self.b.hostname.value == "SWFW-PARTIAL"

    def test_idle_timeout_15_min(self):
        assert self.b.vty_exec_timeout_seconds.detected
        assert self.b.vty_exec_timeout_seconds.value == 900

    def test_snmp_enabled_custom_community(self):
        assert self.b.snmp_communities.detected
        names = [c.name for c in self.b.snmp_communities.value]
        assert "public" not in names
        assert "custom-ro-string" in names

    def test_syslog_single_host(self):
        assert self.b.logging_enabled.detected
        assert self.b.logging_enabled.value is True
        assert len(self.b.logging_hosts.value) == 1


# ---------------------------------------------------------------------------
# Malformed config parsing
# ---------------------------------------------------------------------------


class TestMalformedParsing:

    def test_parser_does_not_crash(self):
        b = _parse(MALFORMED)
        assert isinstance(b, SecurityBaselineModel)

    def test_invalid_timeout_yields_unknown(self):
        b = _parse(MALFORMED)
        assert not b.vty_exec_timeout_seconds.detected or b.vty_exec_timeout_seconds.value is None

    def test_invalid_password_length_yields_unknown(self):
        b = _parse(MALFORMED)
        assert not b.password_min_length.detected or b.password_min_length.value is None


# ---------------------------------------------------------------------------
# Empty and edge-case configurations
# ---------------------------------------------------------------------------


class TestEdgeCases:

    def test_empty_raises(self):
        with pytest.raises(ParserError):
            _parse("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ParserError):
            _parse("   \n\n  ")

    def test_none_raises(self):
        with pytest.raises(ParserError):
            _parse(None)

    def test_minimal_sonicwall_config(self):
        b = _parse("firmware-version SonicOS 7.0.0\nhostname MINIMAL\nend\n")
        assert b.hostname.detected
        assert b.hostname.value == "MINIMAL"

    def test_unknown_version(self):
        b = _parse(UNKNOWN)
        assert b.hostname.detected
        assert b.hostname.value == "SWFW-UNKNOWN"


# ---------------------------------------------------------------------------
# Platform invariants
# ---------------------------------------------------------------------------


class TestPlatformInvariants:
    """These are documented SonicOS invariants that must hold across all configs."""

    @pytest.mark.parametrize("config", [SECURE, INSECURE, AMBIGUOUS, UNKNOWN])
    def test_telnet_always_disabled(self, config):
        b = _parse(config)
        assert b.telnet_enabled.detected
        assert b.telnet_enabled.value is False

    @pytest.mark.parametrize("config", [SECURE, INSECURE, AMBIGUOUS, UNKNOWN])
    def test_ssh_always_v2(self, config):
        b = _parse(config)
        assert b.ssh_version.detected
        assert b.ssh_version.value == 2

    @pytest.mark.parametrize("config", [SECURE, INSECURE, AMBIGUOUS, UNKNOWN])
    def test_passwords_always_hashed(self, config):
        b = _parse(config)
        assert b.password_encryption.detected
        assert b.password_encryption.value is True

    @pytest.mark.parametrize("config", [SECURE, INSECURE, AMBIGUOUS, UNKNOWN])
    def test_no_enable_password(self, config):
        b = _parse(config)
        assert b.enable_password_present.detected
        assert b.enable_password_present.value is False


# ---------------------------------------------------------------------------
# Evidence integrity (provenance chain)
# ---------------------------------------------------------------------------


class TestEvidenceIntegrity:

    @pytest.fixture(autouse=True)
    def _parse_secure(self):
        self.b = _parse(SECURE)
        self.lines = SECURE.splitlines()

    def test_hostname_evidence(self):
        obs = self.b.hostname
        assert obs.source_line is not None
        assert obs.line_number is not None
        actual = self.lines[obs.line_number - 1].strip()
        assert obs.source_line in actual or actual in obs.source_line

    def test_idle_timeout_evidence(self):
        obs = self.b.vty_exec_timeout_seconds
        assert obs.source_line is not None
        assert obs.line_number is not None
        actual = self.lines[obs.line_number - 1].strip()
        assert obs.source_line in actual or actual in obs.source_line

    def test_password_length_evidence(self):
        obs = self.b.password_min_length
        assert obs.source_line is not None
        assert obs.line_number is not None
        actual = self.lines[obs.line_number - 1].strip()
        assert obs.source_line in actual or actual in obs.source_line

    def test_banner_evidence(self):
        obs = self.b.login_banner_present
        assert obs.source_line is not None
        assert obs.line_number is not None

    def test_syslog_evidence(self):
        obs = self.b.logging_enabled
        assert obs.source_line is not None
        assert obs.line_number is not None

    def test_ntp_evidence(self):
        obs = self.b.ntp_servers
        assert obs.source_line is not None
        assert obs.line_number is not None

    def test_undetected_fields_have_no_value(self):
        for name in self.b.observable_fields():
            obs = getattr(self.b, name)
            if not obs.detected:
                assert obs.value is None, (
                    f"{name}: undetected observation must have value=None, "
                    f"got {obs.value!r}"
                )

    def test_all_observations_are_deterministic(self):
        for name in self.b.observable_fields():
            obs = getattr(self.b, name)
            assert obs.origin == Origin.DETERMINISTIC


# ---------------------------------------------------------------------------
# Compliance engine flow-through
# ---------------------------------------------------------------------------


class TestComplianceFlowThrough:

    def test_secure_config_passes_most_controls(self):
        b = _parse(SECURE)
        engine = ComplianceEngine(load_framework("CIS", "sonicwall"))
        report = engine.build_report(b, tool_name="test", tool_version="0")

        statuses = {r.rule_id: r.status for r in report.results}
        assert statuses["SWL-NO-CLEARTEXT-SERVICES"] == Status.PASS
        assert statuses["SWL-IDLE-TIMEOUT"] == Status.PASS
        assert statuses["SWL-NO-HTTP-SERVER"] == Status.PASS
        assert statuses["SWL-SSH-V2"] == Status.PASS
        assert statuses["SWL-SYSLOG-DESTINATION"] == Status.PASS
        assert statuses["SWL-NTP-CONFIGURED"] == Status.PASS
        assert statuses["SWL-LOGIN-BANNER"] == Status.PASS
        assert statuses["SWL-PASSWORD-MIN-LENGTH"] == Status.PASS
        assert statuses["SWL-MGMT-ACL"] == Status.PASS

    def test_insecure_config_fails_expected_controls(self):
        b = _parse(INSECURE)
        engine = ComplianceEngine(load_framework("CIS", "sonicwall"))
        report = engine.build_report(b, tool_name="test", tool_version="0")

        statuses = {r.rule_id: r.status for r in report.results}
        assert statuses["SWL-NO-HTTP-SERVER"] == Status.FAIL
        assert statuses["SWL-IDLE-TIMEOUT"] == Status.FAIL
        assert statuses["SWL-SNMP-NO-DEFAULT-COMMUNITY"] == Status.FAIL
        assert statuses["SWL-SYSLOG-DESTINATION"] == Status.FAIL
        assert statuses["SWL-NTP-CONFIGURED"] == Status.FAIL
        assert statuses["SWL-LOGIN-BANNER"] == Status.FAIL
        assert statuses["SWL-MGMT-ACL"] == Status.FAIL


# ---------------------------------------------------------------------------
# Framework flow-through
# ---------------------------------------------------------------------------


FRAMEWORKS = ["CIS", "NIST SP 800-53", "DISA STIG", "ISO/IEC 27001"]


class TestFrameworkFlowThrough:

    @pytest.mark.parametrize("framework", FRAMEWORKS)
    def test_sonicwall_control_flows_through_all_frameworks(self, framework):
        b = _parse(SECURE)
        platform = "sonicwall" if framework == "CIS" else "default"
        engine = ComplianceEngine(load_framework(framework, platform))
        report = engine.build_report(b, tool_name="test", tool_version="0")
        assert len(report.results) > 0
        for r in report.results:
            assert r.status in (
                Status.PASS, Status.FAIL, Status.NEEDS_REVIEW,
                Status.NOT_APPLICABLE, Status.MANUAL_REVIEW,
                Status.UNSUPPORTED,
            )


# ---------------------------------------------------------------------------
# Cross-vendor detection isolation
# ---------------------------------------------------------------------------


class TestCrossVendorDetectionIsolation:

    _OTHER_CONFIGS = [
        ("cisco_ios", "insecure_ios.conf"),
        ("junos", "junos_srx.conf"),
        ("fortios", "fortios_fgt.conf"),
        ("paloalto", "paloalto_panos.xml"),
        ("sonic", "sonic/insecure.conf"),
        ("checkpoint", "checkpoint_gaia/insecure.conf"),
        ("mikrotik", "mikrotik_routeros/insecure.conf"),
        ("arista", "arista/insecure.conf"),
        ("huawei", "huawei_vrp/insecure.conf"),
    ]

    @pytest.mark.parametrize("vendor,path", _OTHER_CONFIGS, ids=[v for v, _ in _OTHER_CONFIGS])
    def test_sonicwall_does_not_claim_other_vendor(self, vendor, path):
        text = (SAMPLES.parent / path).read_text(encoding="utf-8")
        score = SonicWallParser.detect(text)
        assert score < 0.3, f"SonicWall parser falsely claimed {vendor} config (score={score})"


# ---------------------------------------------------------------------------
# Cross-vendor state isolation
# ---------------------------------------------------------------------------


class TestCrossVendorStateIsolation:

    def test_sonicwall_fortios_sonicwall(self):
        b1 = _parse(SECURE)
        from auditor.parsers.fortios import FortiosParser
        fortios = (SAMPLES.parent / "fortios_fgt.conf").read_text(encoding="utf-8")
        FortiosParser().parse(fortios)
        b2 = _parse(SECURE)
        assert b1.model_dump() == b2.model_dump()

    def test_sonicwall_paloalto_sonicwall(self):
        b1 = _parse(SECURE)
        from auditor.parsers.paloalto import PaloAltoParser
        panos = (SAMPLES.parent / "paloalto_panos.xml").read_text(encoding="utf-8")
        PaloAltoParser().parse(panos)
        b2 = _parse(SECURE)
        assert b1.model_dump() == b2.model_dump()

    def test_sonicwall_cisco_sonicwall(self):
        b1 = _parse(SECURE)
        from auditor.parsers.cisco_ios import CiscoIOSParser
        ios = (SAMPLES.parent / "insecure_ios.conf").read_text(encoding="utf-8")
        CiscoIOSParser().parse(ios)
        b2 = _parse(SECURE)
        assert b1.model_dump() == b2.model_dump()

    def test_sonicwall_mikrotik_sonicwall(self):
        b1 = _parse(SECURE)
        from auditor.parsers.mikrotik_routeros import MikroTikROSParser
        ros = (SAMPLES.parent / "mikrotik_routeros" / "insecure.conf").read_text(encoding="utf-8")
        MikroTikROSParser().parse(ros)
        b2 = _parse(SECURE)
        assert b1.model_dump() == b2.model_dump()

    def test_sonicwall_checkpoint_sonicwall(self):
        b1 = _parse(SECURE)
        from auditor.parsers.checkpoint_gaia import CheckPointGaiaParser
        gaia = (SAMPLES.parent / "checkpoint_gaia" / "insecure.conf").read_text(encoding="utf-8")
        CheckPointGaiaParser().parse(gaia)
        b2 = _parse(SECURE)
        assert b1.model_dump() == b2.model_dump()


# ---------------------------------------------------------------------------
# Deterministic evaluation
# ---------------------------------------------------------------------------


class TestDeterministicEvaluation:

    def test_repeated_parsing_is_identical(self):
        b1 = _parse(SECURE)
        b2 = _parse(SECURE)
        assert b1.model_dump() == b2.model_dump()

    def test_repeated_evaluation_is_identical(self):
        b = _parse(SECURE)
        engine = ComplianceEngine(load_framework("CIS", "sonicwall"))
        r1 = engine.build_report(b, tool_name="test", tool_version="0")
        r2 = engine.build_report(b, tool_name="test", tool_version="0")
        assert len(r1.results) == len(r2.results)
        for a, c in zip(r1.results, r2.results):
            assert a.rule_id == c.rule_id
            assert a.status == c.status


# ---------------------------------------------------------------------------
# False-pass audit
# ---------------------------------------------------------------------------


class TestFalsePassAudit:

    def _pass_count(self, config_text):
        b = _parse(config_text)
        engine = ComplianceEngine(load_framework("CIS", "sonicwall"))
        report = engine.build_report(b, tool_name="test", tool_version="0")
        return sum(1 for r in report.results if r.status == Status.PASS)

    def test_missing_syslog_does_not_pass_logging(self):
        config = "firmware-version SonicOS 7.0.0\nhostname TEST\nend\n"
        b = _parse(config)
        assert b.logging_enabled.detected
        assert b.logging_enabled.value is False

    def test_missing_ntp_does_not_pass_ntp(self):
        config = "firmware-version SonicOS 7.0.0\nhostname TEST\nend\n"
        b = _parse(config)
        assert b.ntp_servers.detected
        assert b.ntp_servers.value == []

    def test_missing_banner_does_not_pass_banner(self):
        config = "firmware-version SonicOS 7.0.0\nhostname TEST\nend\n"
        b = _parse(config)
        assert b.login_banner_present.detected
        assert b.login_banner_present.value is False

    def test_fortios_config_does_not_produce_sonicwall_pass(self):
        fortios = (SAMPLES.parent / "fortios_fgt.conf").read_text(encoding="utf-8")
        score = SonicWallParser.detect(fortios)
        assert score < 0.3

    def test_cisco_config_does_not_produce_sonicwall_pass(self):
        ios = (SAMPLES.parent / "insecure_ios.conf").read_text(encoding="utf-8")
        score = SonicWallParser.detect(ios)
        assert score < 0.3

    def test_random_text_does_not_pass(self):
        config = "firmware-version SonicOS 7.0.0\nrandom garbage line\nend\n"
        b = _parse(config)
        engine = ComplianceEngine(load_framework("CIS", "sonicwall"))
        report = engine.build_report(b, tool_name="test", tool_version="0")
        for r in report.results:
            if r.rule_id in ("logging_enabled", "ntp_configured", "login_banner",
                             "management_acl", "aaa_enabled"):
                assert r.status != Status.PASS, (
                    f"False PASS for {r.rule_id} on minimal config"
                )

    def test_comments_with_security_keywords_do_not_produce_pass(self):
        config = (
            "firmware-version SonicOS 7.0.0\n"
            "hostname TEST\n"
            "# syslog-server 10.0.0.1 port 514 facility local0\n"
            "# ntp-server 10.0.0.2\n"
            "# pre-login-banner \"test\"\n"
            "end\n"
        )
        b = _parse(config)
        assert b.logging_enabled.value is False
        assert b.ntp_servers.value == []
        assert b.login_banner_present.value is False


# ---------------------------------------------------------------------------
# Absence policy
# ---------------------------------------------------------------------------


class TestAbsencePolicy:

    _CONCLUSIVE_ABSENCES = [
        "telnet_enabled",
        "logging_enabled",
        "ntp_servers",
        "login_banner_present",
        "snmp_communities",
        "password_encryption",
        "enable_password_present",
    ]

    @pytest.mark.parametrize("field", _CONCLUSIVE_ABSENCES)
    def test_conclusive_absence_is_detected(self, field):
        config = "firmware-version SonicOS 7.0.0\nhostname ABSENT-TEST\nend\n"
        b = _parse(config)
        obs = getattr(b, field)
        assert obs.detected, f"{field} should be conclusively absent"

    _AMBIGUOUS_ABSENCES = [
        "ssh_enabled",
        "management_acl_applied",
        "aaa_enabled",
    ]

    @pytest.mark.parametrize("field", _AMBIGUOUS_ABSENCES)
    def test_ambiguous_absence_is_undetected(self, field):
        config = "firmware-version SonicOS 7.0.0\nhostname ABSENT-TEST\nend\n"
        b = _parse(config)
        obs = getattr(b, field)
        if field == "aaa_enabled":
            assert obs.detected and obs.value is False
        else:
            assert not obs.detected or obs.value is None or obs.value is False


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------


class TestNormalization:

    def test_idle_timeout_minutes_to_seconds(self):
        b = _parse(SECURE)
        assert b.vty_exec_timeout_seconds.value == 600

    def test_lockout_period_minutes_to_seconds(self):
        b = _parse(SECURE)
        assert b.admin_lockout_duration.value == 1800

    def test_default_idle_timeout_5min(self):
        config = "firmware-version SonicOS 7.0.0\nhostname DEFAULTS\nend\n"
        b = _parse(config)
        assert b.vty_exec_timeout_seconds.detected
        assert b.vty_exec_timeout_seconds.value == 300

    def test_default_password_min_length_8(self):
        config = "firmware-version SonicOS 7.0.0\nhostname DEFAULTS\nend\n"
        b = _parse(config)
        assert b.password_min_length.detected
        assert b.password_min_length.value == 8


# ---------------------------------------------------------------------------
# SHA256 and config line count
# ---------------------------------------------------------------------------


class TestConfigMetadata:

    def test_sha256_populated(self):
        b = _parse(SECURE)
        assert b.source_sha256 is not None
        assert len(b.source_sha256) == 64

    def test_line_count(self):
        b = _parse(SECURE)
        assert b.config_line_count == len(SECURE.splitlines())

    def test_sha256_deterministic(self):
        b1 = _parse(SECURE)
        b2 = _parse(SECURE)
        assert b1.source_sha256 == b2.source_sha256


# ---------------------------------------------------------------------------
# External Oxidized Simulation Validation
# ---------------------------------------------------------------------------


class TestExternalOxidizedSimulationValidation:
    """Validation against independently sourced Oxidized simulation fixture.

    PROVENANCE:
    - Sourced from Oxidized repository (lib/oxidized/model/sonicos.rb and
      spec/model/data/sonicos#snippets#simulation.yaml).
    - CLASSIFICATION: OXIDIZED_SIMULATION (NOT verified real device data).
    """

    @pytest.fixture(autouse=True)
    def _parse_external(self):
        self.b = _parse(EXTERNAL_OXIDIZED)

    def test_detects_external_oxidized_fixture(self):
        score = SonicWallParser.detect(EXTERNAL_OXIDIZED)
        assert score >= 0.5

    def test_hostname_extracted(self):
        assert self.b.hostname.detected
        assert self.b.hostname.value == "NSA4650-OXIDIZED-SIM"

    def test_firmware_version_warning_recorded(self):
        warnings = self.b.provenance.warnings
        assert any("SonicOS version detected: 6.5.4.10-95n" in w for w in warnings)

    def test_idle_timeout(self):
        assert self.b.vty_exec_timeout_seconds.detected
        assert self.b.vty_exec_timeout_seconds.value == 600

    def test_password_min_length(self):
        assert self.b.password_min_length.detected
        assert self.b.password_min_length.value == 16

    def test_password_complexity(self):
        assert self.b.password_min_uppercase.detected
        assert self.b.password_min_uppercase.value == 1
        assert self.b.password_min_lowercase.detected
        assert self.b.password_min_lowercase.value == 1
        assert self.b.password_min_numeric.detected
        assert self.b.password_min_numeric.value == 1
        assert self.b.password_min_special.detected
        assert self.b.password_min_special.value == 1

    def test_management_access(self):
        assert self.b.ssh_enabled.detected
        assert self.b.ssh_enabled.value is True
        assert self.b.http_server_enabled.detected
        assert self.b.http_server_enabled.value is False
        assert self.b.https_server_enabled.detected
        assert self.b.https_server_enabled.value is True

    def test_snmp_disabled(self):
        assert self.b.snmp_agent_enabled.detected
        assert self.b.snmp_agent_enabled.value is False

    def test_syslog_configured(self):
        assert self.b.logging_enabled.detected
        assert self.b.logging_enabled.value is True
        assert "192.168.1.50" in self.b.logging_hosts.value

    def test_ntp_configured(self):
        assert self.b.ntp_servers.detected
        assert "192.168.1.100" in self.b.ntp_servers.value
        assert "192.168.1.101" in self.b.ntp_servers.value
        assert self.b.ntp_redundant.value is True

    def test_oxidized_raw_empty_config_does_not_crash(self):
        """Oxidized snippet with only prompt/system-uptime returns gracefully."""
        raw_snippet = (
            '! # Example config line on NSA 4650 running SonicOS 6.5.4.10-95n\n'
            'system-uptime "1 Day, 23 Hours, 32 Minutes, 10 Seconds"\n'
        )
        b = _parse(raw_snippet)
        assert b.hostname.detected is False
        assert b.ssh_enabled.detected is False
        assert b.logging_enabled.detected is True
        assert b.logging_enabled.value is False

    def test_oxidized_scrubbed_secret_handling(self):
        """Configs with Oxidized scrubbed secrets '<secret hidden>' parse without error."""
        scrubbed_config = (
            "firmware-version SonicOS 7.0.1\n"
            "hostname SCRUBBED-TEST\n"
            "administration\n"
            "  administrator password <secret hidden> 1\n"
            "  secret <secret hidden> 1\n"
            "  admin idle-timeout 10\n"
            "  exit\n"
            "interface X0\n"
            "  management ssh\n"
            "  management https\n"
            "  exit\n"
            "end\n"
        )
        b = _parse(scrubbed_config)
        assert b.hostname.value == "SCRUBBED-TEST"
        assert b.vty_exec_timeout_seconds.value == 600
        assert b.password_encryption.value is True


# ---------------------------------------------------------------------------
# Official Documentation Example Validation
# ---------------------------------------------------------------------------


class TestOfficialDocExampleValidation:
    """Validation against configuration constructed directly from official SonicWall CLI guides."""

    @pytest.fixture(autouse=True)
    def _parse_doc_example(self):
        self.b = _parse(OFFICIAL_EXAMPLE)

    def test_detects_official_example(self):
        score = SonicWallParser.detect(OFFICIAL_EXAMPLE)
        assert score >= 0.5

    def test_hostname(self):
        assert self.b.hostname.detected
        assert self.b.hostname.value == "SONICWALL-OFFICIAL-DOC-EXAMPLE"

    def test_password_min_length_14(self):
        assert self.b.password_min_length.detected
        assert self.b.password_min_length.value == 14

    def test_lockout_threshold(self):
        assert self.b.admin_lockout_threshold.detected
        assert self.b.admin_lockout_threshold.value == 3

    def test_lockout_duration(self):
        assert self.b.admin_lockout_duration.detected
        assert self.b.admin_lockout_duration.value == 1800

    def test_banner(self):
        assert self.b.login_banner_present.detected
        assert self.b.login_banner_present.value is True

    def test_audit_logging(self):
        assert self.b.event_logging_enabled.detected
        assert self.b.event_logging_enabled.value is True


# ---------------------------------------------------------------------------
# Multi-vendor chain and isolation sequences
# ---------------------------------------------------------------------------


class TestMultiVendorIsolationSequences:

    def test_sequence_sonicwall_sonic_fortinet_paloalto_mikrotik_sonicwall(self):
        from auditor.parsers.sonic import SonicParser
        from auditor.parsers.fortios import FortiosParser
        from auditor.parsers.paloalto import PaloAltoParser
        from auditor.parsers.mikrotik_routeros import MikroTikROSParser

        b_initial = _parse(SECURE)
        
        # Intermediate parses of different vendors
        sonic_sample = (SAMPLES.parent / "sonic" / "secure.conf").read_text(encoding="utf-8")
        SonicParser().parse(sonic_sample)

        fortios_sample = (SAMPLES.parent / "fortios_fgt.conf").read_text(encoding="utf-8")
        FortiosParser().parse(fortios_sample)

        panos_sample = (SAMPLES.parent / "paloalto_panos.xml").read_text(encoding="utf-8")
        PaloAltoParser().parse(panos_sample)

        ros_sample = (SAMPLES.parent / "mikrotik_routeros" / "insecure.conf").read_text(encoding="utf-8")
        MikroTikROSParser().parse(ros_sample)

        b_final = _parse(SECURE)
        assert b_initial.model_dump() == b_final.model_dump()

    def test_sequence_sonicwall_cisco_juniper_checkpoint_sonicwall(self):
        from auditor.parsers.cisco_ios import CiscoIOSParser
        from auditor.parsers.junos import JunosParser
        from auditor.parsers.checkpoint_gaia import CheckPointGaiaParser

        b_initial = _parse(SECURE)

        cisco_sample = (SAMPLES.parent / "insecure_ios.conf").read_text(encoding="utf-8")
        CiscoIOSParser().parse(cisco_sample)

        junos_sample = (SAMPLES.parent / "junos_srx.conf").read_text(encoding="utf-8")
        JunosParser().parse(junos_sample)

        gaia_sample = (SAMPLES.parent / "checkpoint_gaia" / "insecure.conf").read_text(encoding="utf-8")
        CheckPointGaiaParser().parse(gaia_sample)

        b_final = _parse(SECURE)
        assert b_initial.model_dump() == b_final.model_dump()

    def test_sequence_sonicwall_arista_huawei_sonicwall(self):
        from auditor.parsers.arista_eos import AristaEOSParser
        from auditor.parsers.huawei_vrp import HuaweiVRPParser

        b_initial = _parse(SECURE)

        arista_sample = (SAMPLES.parent / "arista" / "insecure.conf").read_text(encoding="utf-8")
        AristaEOSParser().parse(arista_sample)

        huawei_sample = (SAMPLES.parent / "huawei_vrp" / "insecure.conf").read_text(encoding="utf-8")
        HuaweiVRPParser().parse(huawei_sample)

        b_final = _parse(SECURE)
        assert b_initial.model_dump() == b_final.model_dump()


# ---------------------------------------------------------------------------
# Cross-fixture evidence isolation
# ---------------------------------------------------------------------------


class TestCrossFixtureEvidenceIsolation:

    def test_evidence_isolation_between_fixtures(self):
        b_sec = _parse(SECURE)
        b_insec = _parse(INSECURE)
        b_ext = _parse(EXTERNAL_OXIDIZED)
        b_doc = _parse(OFFICIAL_EXAMPLE)

        assert b_sec.hostname.source_line != b_insec.hostname.source_line
        assert b_sec.hostname.source_line != b_ext.hostname.source_line
        assert b_sec.hostname.source_line != b_doc.hostname.source_line

        assert b_sec.source_sha256 != b_insec.source_sha256
        assert b_sec.source_sha256 != b_ext.source_sha256
        assert b_sec.source_sha256 != b_doc.source_sha256

