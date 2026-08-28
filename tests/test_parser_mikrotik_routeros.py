"""Tests for the MikroTik RouterOS deterministic parser.

Every assertion traces back to official MikroTik documentation at
help.mikrotik.com (RouterOS 7.x):
- IP Services: help.mikrotik.com/docs/spaces/ROS/pages/328229/IP+Services
- SSH: help.mikrotik.com/docs/spaces/ROS/pages/132350014/SSH
- SNMP: help.mikrotik.com/docs/spaces/ROS/pages/8978519/SNMP
- User: help.mikrotik.com/docs/spaces/ROS/pages/8978504/User
- NTP: help.mikrotik.com/docs/spaces/ROS/pages/40992869/NTP
- Log: help.mikrotik.com/docs/spaces/ROS/pages/328094/Log
- Note: help.mikrotik.com/docs/spaces/ROS/pages/40992863/Note
- Identity: help.mikrotik.com/docs/display/ROS/Identity
- Securing: help.mikrotik.com/docs/spaces/ROS/pages/328353/Securing+your+router
"""

from pathlib import Path
from typing import List

import pytest

from auditor.engine import ComplianceEngine
from auditor.models.baseline import SecurityBaselineModel, SnmpCommunity
from auditor.models.observation import Observation, Origin
from auditor.models.result import Status
from auditor.parsers.base import ParserError, registry
from auditor.parsers.mikrotik_routeros import MikroTikROSParser, _parse_ros_time
from auditor.rules import load_framework

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "mikrotik_routeros"
INSECURE = (SAMPLES / "insecure.conf").read_text(encoding="utf-8")
SECURE = (SAMPLES / "secure.conf").read_text(encoding="utf-8")


def _parse(text: str) -> SecurityBaselineModel:
    return MikroTikROSParser().parse(text)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


class TestDetection:

    def test_detects_routeros_config(self):
        score = MikroTikROSParser.detect(INSECURE)
        assert score >= 0.5

    def test_detects_secure_config(self):
        score = MikroTikROSParser.detect(SECURE)
        assert score >= 0.5

    def test_rejects_cisco_ios(self):
        ios = (SAMPLES.parent / "insecure_ios.conf").read_text()
        assert MikroTikROSParser.detect(ios) == 0.0

    def test_rejects_junos(self):
        junos = (SAMPLES.parent / "junos_srx.conf").read_text()
        assert MikroTikROSParser.detect(junos) == 0.0

    def test_rejects_fortios(self):
        fortios = (SAMPLES.parent / "fortios_fgt.conf").read_text()
        assert MikroTikROSParser.detect(fortios) == 0.0

    def test_rejects_paloalto(self):
        panos = (SAMPLES.parent / "paloalto_panos.xml").read_text()
        assert MikroTikROSParser.detect(panos) == 0.0

    def test_rejects_sonic(self):
        sonic = (SAMPLES.parent / "sonic" / "insecure.conf").read_text()
        assert MikroTikROSParser.detect(sonic) == 0.0

    def test_rejects_checkpoint(self):
        gaia = (SAMPLES.parent / "checkpoint_gaia" / "insecure.conf").read_text()
        assert MikroTikROSParser.detect(gaia) == 0.0

    def test_rejects_empty(self):
        assert MikroTikROSParser.detect("") == 0.0

    def test_rejects_whitespace(self):
        assert MikroTikROSParser.detect("   \n\n  ") == 0.0

    def test_registry_selects_mikrotik(self):
        best = max(
            [p for p in registry._parsers.values() if not p.is_fallback],
            key=lambda p: p.detect(INSECURE),
        )
        assert best is MikroTikROSParser


# ---------------------------------------------------------------------------
# Insecure sample parsing
# ---------------------------------------------------------------------------


class TestInsecureParsing:

    @pytest.fixture(autouse=True)
    def _parse(self):
        self.b = _parse(INSECURE)

    def test_hostname_is_default(self):
        assert self.b.hostname.detected
        assert self.b.hostname.value == "MikroTik"

    def test_telnet_enabled(self):
        assert self.b.telnet_enabled.detected
        assert self.b.telnet_enabled.value is True

    def test_ssh_enabled(self):
        assert self.b.ssh_enabled.detected
        assert self.b.ssh_enabled.value is True

    def test_ssh_version_2(self):
        assert self.b.ssh_version.detected
        assert self.b.ssh_version.value == 2

    def test_http_enabled(self):
        assert self.b.http_server_enabled.detected
        assert self.b.http_server_enabled.value is True

    def test_no_management_acl(self):
        assert self.b.management_acl_applied.detected
        assert self.b.management_acl_applied.value is False

    def test_snmp_enabled(self):
        assert self.b.snmp_agent_enabled.detected
        assert self.b.snmp_agent_enabled.value is True

    def test_snmp_public_community(self):
        assert self.b.snmp_communities.detected
        comms = self.b.snmp_communities.value
        assert len(comms) == 1
        assert comms[0].name == "public"

    def test_snmp_write_access(self):
        comms = self.b.snmp_communities.value
        assert comms[0].access == "rw"

    def test_no_v3_security(self):
        assert self.b.snmp_v3_users_present.detected
        assert self.b.snmp_v3_users_present.value is False

    def test_no_ntp(self):
        assert self.b.ntp_servers.value == []

    def test_no_remote_logging(self):
        assert self.b.logging_enabled.value is False

    def test_no_banner(self):
        assert self.b.login_banner_present.detected
        assert self.b.login_banner_present.value is False

    def test_no_aaa(self):
        assert self.b.aaa_enabled.detected
        assert self.b.aaa_enabled.value is False

    def test_strong_crypto_off(self):
        assert self.b.strong_crypto_enabled.detected
        assert self.b.strong_crypto_enabled.value is False

    def test_password_always_hashed(self):
        assert self.b.password_encryption.detected
        assert self.b.password_encryption.value is True

    def test_enable_secret_set(self):
        assert not self.b.enable_secret_set.detected

    def test_dns_servers(self):
        assert self.b.dns_servers.detected
        assert self.b.dns_servers.value == ["8.8.8.8"]

    def test_default_ports(self):
        assert self.b.admin_default_ports_changed.detected
        assert self.b.admin_default_ports_changed.value is False

    def test_default_timeout(self):
        assert self.b.vty_exec_timeout_seconds.detected
        assert self.b.vty_exec_timeout_seconds.value == 0

    def test_provenance(self):
        assert self.b.provenance.vendor == "mikrotik"
        assert self.b.provenance.os_family == "routeros"
        assert self.b.provenance.parser_name == "mikrotik_routeros"


# ---------------------------------------------------------------------------
# Secure sample parsing
# ---------------------------------------------------------------------------


class TestSecureParsing:

    @pytest.fixture(autouse=True)
    def _parse(self):
        self.b = _parse(SECURE)

    def test_hostname_custom(self):
        assert self.b.hostname.detected
        assert self.b.hostname.value == "core-rtr-01"

    def test_telnet_disabled(self):
        assert self.b.telnet_enabled.detected
        assert self.b.telnet_enabled.value is False

    def test_ssh_enabled(self):
        assert self.b.ssh_enabled.detected
        assert self.b.ssh_enabled.value is True

    def test_http_disabled(self):
        assert self.b.http_server_enabled.detected
        assert self.b.http_server_enabled.value is False

    def test_management_acl_applied(self):
        assert self.b.management_acl_applied.detected
        assert self.b.management_acl_applied.value is True

    def test_snmp_custom_community(self):
        comms = self.b.snmp_communities.value
        assert len(comms) == 1
        assert comms[0].name == "s3cur3Str1ng"

    def test_snmp_no_write(self):
        comms = self.b.snmp_communities.value
        assert comms[0].access == "ro"

    def test_snmp_v3_configured(self):
        assert self.b.snmp_v3_users_present.detected
        assert self.b.snmp_v3_users_present.value is True

    def test_ntp_servers(self):
        assert self.b.ntp_servers.detected
        assert len(self.b.ntp_servers.value) == 2

    def test_ntp_redundant(self):
        assert self.b.ntp_redundant.detected
        assert self.b.ntp_redundant.value is True

    def test_remote_logging(self):
        assert self.b.logging_enabled.detected
        assert self.b.logging_enabled.value is True

    def test_logging_hosts(self):
        assert self.b.logging_hosts.detected
        hosts = self.b.logging_hosts.value
        assert "10.0.1.100" in hosts
        assert "10.0.1.101" in hosts

    def test_banner_present(self):
        assert self.b.login_banner_present.detected
        assert self.b.login_banner_present.value is True

    def test_aaa_enabled(self):
        assert self.b.aaa_enabled.detected
        assert self.b.aaa_enabled.value is True

    def test_strong_crypto_on(self):
        assert self.b.strong_crypto_enabled.detected
        assert self.b.strong_crypto_enabled.value is True

    def test_port_changed(self):
        assert self.b.admin_default_ports_changed.detected
        assert self.b.admin_default_ports_changed.value is True

    def test_dns_servers(self):
        assert self.b.dns_servers.detected
        assert len(self.b.dns_servers.value) == 2

    def test_vty_transport_ssh_only(self):
        assert self.b.vty_transport_input.detected
        assert self.b.vty_transport_input.value == ["ssh"]


# ---------------------------------------------------------------------------
# Absent and edge cases
# ---------------------------------------------------------------------------


class TestAbsentSettings:

    def test_minimal_config(self):
        text = "# 2024/jan/01 00:00:00 by RouterOS 7.14\n/system identity\nset name=test\n"
        b = _parse(text)
        assert b.hostname.value == "test"
        assert b.ntp_servers.value == []

    def test_empty_raises(self):
        with pytest.raises(ParserError):
            _parse("   \n\n")

    def test_none_raises(self):
        with pytest.raises(ParserError):
            MikroTikROSParser().parse(None)

    def test_no_hostname(self):
        text = "# by RouterOS 7.14\n/ip service\nset telnet disabled=yes\n"
        b = _parse(text)
        assert not b.hostname.detected

    def test_default_timeout_when_no_user_section(self):
        text = "# by RouterOS 7.14\n/system identity\nset name=test\n"
        b = _parse(text)
        assert b.vty_exec_timeout_seconds.value == 0

    def test_snmp_disabled_by_default(self):
        text = "# by RouterOS 7.14\n/system identity\nset name=test\n"
        b = _parse(text)
        assert b.snmp_agent_enabled.value is False

    def test_password_policy_unknown(self):
        text = "# by RouterOS 7.14\n/system identity\nset name=test\n"
        b = _parse(text)
        assert b.password_min_length.value is None
        assert b.admin_lockout_threshold.value is None


# ---------------------------------------------------------------------------
# Time parsing
# ---------------------------------------------------------------------------


class TestTimeParsing:

    def test_minutes(self):
        assert _parse_ros_time("10m") == 600

    def test_hours(self):
        assert _parse_ros_time("1h") == 3600

    def test_seconds(self):
        assert _parse_ros_time("30s") == 30

    def test_combined(self):
        assert _parse_ros_time("1h30m") == 5400

    def test_complex(self):
        assert _parse_ros_time("1d2h3m4s") == 93784

    def test_weeks(self):
        assert _parse_ros_time("1w") == 604800

    def test_just_number(self):
        assert _parse_ros_time("600") == 600


# ---------------------------------------------------------------------------
# Evidence tracing
# ---------------------------------------------------------------------------


class TestEvidence:

    @pytest.fixture(autouse=True)
    def _parse(self):
        self.b = _parse(INSECURE)
        self.lines = INSECURE.splitlines()

    def test_hostname_evidence(self):
        obs = self.b.hostname
        assert obs.line_number is not None
        assert self.lines[obs.line_number - 1].strip() == obs.source_line
        assert obs.origin is Origin.DETERMINISTIC

    def test_telnet_evidence(self):
        obs = self.b.telnet_enabled
        assert obs.line_number is not None
        assert self.lines[obs.line_number - 1].strip() == obs.source_line

    def test_snmp_evidence(self):
        obs = self.b.snmp_agent_enabled
        assert obs.line_number is not None
        assert self.lines[obs.line_number - 1].strip() == obs.source_line

    def test_snmp_community_evidence(self):
        obs = self.b.snmp_communities
        assert obs.line_number is not None
        assert self.lines[obs.line_number - 1].strip() == obs.source_line

    def test_aaa_evidence(self):
        obs = self.b.aaa_enabled
        assert obs.line_number is not None
        assert self.lines[obs.line_number - 1].strip() == obs.source_line

    def test_banner_evidence(self):
        obs = self.b.login_banner_present
        assert obs.line_number is not None
        assert self.lines[obs.line_number - 1].strip() == obs.source_line

    def test_all_deterministic(self):
        for field in SecurityBaselineModel.observable_fields():
            obs = getattr(self.b, field)
            assert obs.origin is Origin.DETERMINISTIC, field


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:

    def test_insecure_deterministic(self):
        b1 = _parse(INSECURE)
        b2 = _parse(INSECURE)
        for field in SecurityBaselineModel.observable_fields():
            o1 = getattr(b1, field)
            o2 = getattr(b2, field)
            assert o1.value == o2.value, field
            assert o1.detected == o2.detected, field
            assert o1.line_number == o2.line_number, field

    def test_secure_deterministic(self):
        b1 = _parse(SECURE)
        b2 = _parse(SECURE)
        for field in SecurityBaselineModel.observable_fields():
            o1 = getattr(b1, field)
            o2 = getattr(b2, field)
            assert o1.value == o2.value, field
            assert o1.detected == o2.detected, field


# ---------------------------------------------------------------------------
# CIS compliance
# ---------------------------------------------------------------------------


class TestCISCompliance:

    def test_insecure_has_failures(self):
        baseline = _parse(INSECURE)
        engine = ComplianceEngine(load_framework("CIS", "mikrotik_routeros"))
        report = engine.build_report(baseline, tool_name="test", tool_version="0")
        statuses = {r.rule_id: r.status for r in report.results}

        assert statuses["MTR-NO-CLEARTEXT-SERVICES"] is Status.FAIL
        assert statuses["MTR-SNMP-NO-DEFAULT-COMMUNITY"] is Status.FAIL
        assert statuses["MTR-SNMP-NO-WRITE"] is Status.FAIL
        assert statuses["MTR-NO-HTTP-SERVER"] is Status.FAIL
        assert statuses["MTR-AAA-CENTRALISED"] is Status.FAIL
        assert statuses["MTR-NTP-CONFIGURED"] is Status.FAIL
        assert statuses["MTR-LOGIN-BANNER"] is Status.FAIL
        assert statuses["MTR-MGMT-ACL"] is Status.FAIL
        assert statuses["MTR-SYSLOG-DESTINATION"] is Status.FAIL
        assert statuses["MTR-IDLE-TIMEOUT"] is Status.FAIL
        # Password encryption/hash checks require config evidence (NEEDS_REVIEW)
        assert statuses["MTR-PASSWORD-HASHED"] is Status.NEEDS_REVIEW

    def test_secure_has_passes(self):
        baseline = _parse(SECURE)
        engine = ComplianceEngine(load_framework("CIS", "mikrotik_routeros"))
        report = engine.build_report(baseline, tool_name="test", tool_version="0")
        statuses = {r.rule_id: r.status for r in report.results}

        assert statuses["MTR-NO-CLEARTEXT-SERVICES"] is Status.PASS
        assert statuses["MTR-SNMP-NO-DEFAULT-COMMUNITY"] is Status.PASS
        assert statuses["MTR-SNMP-NO-WRITE"] is Status.PASS
        assert statuses["MTR-NO-HTTP-SERVER"] is Status.PASS
        assert statuses["MTR-AAA-CENTRALISED"] is Status.PASS
        assert statuses["MTR-NTP-CONFIGURED"] is Status.PASS
        assert statuses["MTR-LOGIN-BANNER"] is Status.PASS
        assert statuses["MTR-MGMT-ACL"] is Status.PASS
        assert statuses["MTR-SYSLOG-DESTINATION"] is Status.PASS
        assert statuses["MTR-PASSWORD-HASHED"] is Status.NEEDS_REVIEW

    def test_ssh_v2_always_passes(self):
        baseline = _parse(INSECURE)
        engine = ComplianceEngine(load_framework("CIS", "mikrotik_routeros"))
        report = engine.build_report(baseline, tool_name="test", tool_version="0")
        statuses = {r.rule_id: r.status for r in report.results}
        assert statuses["MTR-SSH-V2"] is Status.PASS

    def test_case_a_no_inactivity_config(self):
        # Case A: No inactivity configuration. Expected: UNKNOWN / 0 / FAIL
        text = "# by RouterOS 7.16\n/system identity\nset name=test\n"
        b = _parse(text)
        assert b.vty_exec_timeout_seconds.value == 0
        engine = ComplianceEngine(load_framework("CIS", "mikrotik_routeros"))
        report = engine.build_report(b, tool_name="test", tool_version="0")
        statuses = {r.rule_id: r.status for r in report.results}
        assert statuses["MTR-IDLE-TIMEOUT"] is Status.FAIL

    def test_case_b_policy_none(self):
        # Case B: inactivity-policy=none. Expected: no effective logout/lock timeout.
        text = "# by RouterOS 7.16\n/user\nset [ find default=yes ] inactivity-policy=none inactivity-timeout=10m\n"
        b = _parse(text)
        assert b.vty_exec_timeout_seconds.value == 0
        engine = ComplianceEngine(load_framework("CIS", "mikrotik_routeros"))
        report = engine.build_report(b, tool_name="test", tool_version="0")
        statuses = {r.rule_id: r.status for r in report.results}
        assert statuses["MTR-IDLE-TIMEOUT"] is Status.FAIL

    def test_case_c_policy_logout_default_time(self):
        # Case C: inactivity-policy=logout + inactivity-timeout=10m. Expected: 600s
        text = "# by RouterOS 7.16\n/user\nset [ find default=yes ] inactivity-policy=logout inactivity-timeout=10m\n"
        b = _parse(text)
        assert b.vty_exec_timeout_seconds.value == 600

    def test_case_d_policy_logout_timeout_above_limit(self):
        # Case D: inactivity-policy=logout + timeout above maximum limit (15m/900s). Expected: FAIL
        text = "# by RouterOS 7.16\n/user\nset [ find default=yes ] inactivity-policy=logout inactivity-timeout=15m\n"
        b = _parse(text)
        assert b.vty_exec_timeout_seconds.value == 900
        engine = ComplianceEngine(load_framework("CIS", "mikrotik_routeros"))
        report = engine.build_report(b, tool_name="test", tool_version="0")
        statuses = {r.rule_id: r.status for r in report.results}
        assert statuses["MTR-IDLE-TIMEOUT"] is Status.FAIL

    def test_case_e_policy_logout_timeout_exactly_limit(self):
        # Case E: inactivity-policy=logout + timeout exactly at limit (10m/600s). Expected: PASS
        text = "# by RouterOS 7.16\n/user\nset [ find default=yes ] inactivity-policy=logout inactivity-timeout=10m\n"
        b = _parse(text)
        assert b.vty_exec_timeout_seconds.value == 600
        engine = ComplianceEngine(load_framework("CIS", "mikrotik_routeros"))
        report = engine.build_report(b, tool_name="test", tool_version="0")
        statuses = {r.rule_id: r.status for r in report.results}
        assert statuses["MTR-IDLE-TIMEOUT"] is Status.PASS

    def test_case_f_policy_logout_timeout_below_limit(self):
        # Case F: inactivity-policy=logout + timeout below limit (5m/300s). Expected: PASS
        text = "# by RouterOS 7.16\n/user\nset [ find default=yes ] inactivity-policy=logout inactivity-timeout=5m\n"
        b = _parse(text)
        assert b.vty_exec_timeout_seconds.value == 300
        engine = ComplianceEngine(load_framework("CIS", "mikrotik_routeros"))
        report = engine.build_report(b, tool_name="test", tool_version="0")
        statuses = {r.rule_id: r.status for r in report.results}
        assert statuses["MTR-IDLE-TIMEOUT"] is Status.PASS

    def test_regression_policy_lockscreen_fails(self):
        # Regression test: inactivity-policy=lockscreen has no effective logout session teardown. Expected: FAIL
        text = "# by RouterOS 7.16\n/user\nset [ find default=yes ] inactivity-policy=lockscreen inactivity-timeout=5m\n"
        b = _parse(text)
        assert b.vty_exec_timeout_seconds.value == 0
        engine = ComplianceEngine(load_framework("CIS", "mikrotik_routeros"))
        report = engine.build_report(b, tool_name="test", tool_version="0")
        statuses = {r.rule_id: r.status for r in report.results}
        assert statuses["MTR-IDLE-TIMEOUT"] is Status.FAIL


# ---------------------------------------------------------------------------
# Cross-vendor isolation
# ---------------------------------------------------------------------------


class TestVendorIsolation:

    def test_other_parsers_score_low_on_mikrotik(self):
        from auditor.parsers import (
            CiscoIOSParser, JunosParser, FortiosParser, PaloAltoParser,
        )
        from auditor.parsers.arista_eos import AristaEOSParser
        from auditor.parsers.sonic import SonicParser
        from auditor.parsers.checkpoint_gaia import CheckPointGaiaParser

        for parser_cls in [CiscoIOSParser, JunosParser, FortiosParser,
                           PaloAltoParser, AristaEOSParser, SonicParser,
                           CheckPointGaiaParser]:
            score = parser_cls.detect(INSECURE)
            assert score < 0.3, f"{parser_cls.name} scored {score} on MikroTik config"

    def test_mikrotik_scores_low_on_others(self):
        other_samples = [
            "insecure_ios.conf",
            "junos_srx.conf",
            "fortios_fgt.conf",
            "paloalto_panos.xml",
            "arista/insecure.conf",
            "sonic/insecure.conf",
            "checkpoint_gaia/insecure.conf",
        ]
        for sample in other_samples:
            text = (SAMPLES.parent / sample).read_text()
            score = MikroTikROSParser.detect(text)
            assert score < 0.3, f"MikroTik scored {score} on {sample}"

    def test_sequential_parsing_is_isolated(self):
        b1 = _parse(INSECURE)
        b2 = _parse(SECURE)
        assert b1.hostname.value == "MikroTik"
        assert b2.hostname.value == "core-rtr-01"
        assert b1.source_sha256 != b2.source_sha256


# ---------------------------------------------------------------------------
# Terse format support
# ---------------------------------------------------------------------------


class TestTerseFormat:

    def test_terse_identity(self):
        text = "# by RouterOS 7.14\n/system identity set name=terse-test\n"
        b = _parse(text)
        assert b.hostname.value == "terse-test"

    def test_terse_service_disable(self):
        text = (
            "# by RouterOS 7.14\n"
            "/system identity set name=test\n"
            "/ip service set telnet disabled=yes\n"
            "/ip service set ftp disabled=yes\n"
            "/ip service set www disabled=yes\n"
        )
        b = _parse(text)
        assert b.telnet_enabled.value is False
        assert b.http_server_enabled.value is False
