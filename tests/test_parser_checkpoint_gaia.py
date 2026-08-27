"""Tests for the Check Point Gaia OS deterministic parser.

Covers: vendor detection, real configuration parsing, compliant/non-compliant
configurations, absent settings, boundary values, malformed/partial input,
normalized values, evidence provenance, deterministic repeated evaluation,
remediation, and vendor isolation.

Configuration syntax verified against the R81 Gaia Administration Guide at
sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_Gaia_AdminGuide/.
"""

from pathlib import Path
from typing import List

import pytest

from auditor.engine import ComplianceEngine
from auditor.models.baseline import SecurityBaselineModel, SnmpCommunity
from auditor.models.observation import Observation, Origin
from auditor.models.result import Status
from auditor.parsers.base import ParserError, registry
from auditor.parsers.checkpoint_gaia import CheckPointGaiaParser
from auditor.rules import load_framework

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "checkpoint_gaia"


def read(name: str) -> str:
    return (SAMPLES / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# PHASE 1: vendor detection
# ---------------------------------------------------------------------------


class TestDetection:
    def test_detects_gaia_config(self):
        text = read("insecure.conf")
        assert CheckPointGaiaParser.detect(text) >= 0.5

    def test_detects_secure_gaia_config(self):
        text = read("secure.conf")
        assert CheckPointGaiaParser.detect(text) >= 0.5

    def test_rejects_empty(self):
        assert CheckPointGaiaParser.detect("") == 0.0
        assert CheckPointGaiaParser.detect("   \n  ") == 0.0

    def test_rejects_cisco_ios(self):
        ios = (SAMPLES.parent / "insecure_ios.conf").read_text()
        assert CheckPointGaiaParser.detect(ios) < 0.3

    def test_rejects_junos(self):
        junos = (SAMPLES.parent / "junos_srx.conf").read_text()
        assert CheckPointGaiaParser.detect(junos) < 0.3

    def test_rejects_fortios(self):
        fortios = (SAMPLES.parent / "fortios_fgt.conf").read_text()
        assert CheckPointGaiaParser.detect(fortios) < 0.3

    def test_rejects_paloalto_xml(self):
        pa = (SAMPLES.parent / "paloalto_panos.xml").read_text()
        assert CheckPointGaiaParser.detect(pa) < 0.3

    def test_rejects_huawei_vrp(self):
        vrp = (SAMPLES.parent / "huawei_vrp" / "insecure.conf").read_text()
        assert CheckPointGaiaParser.detect(vrp) < 0.3

    def test_registry_selects_gaia(self):
        text = read("insecure.conf")
        best_cls, score = registry.detect(text)
        assert best_cls is CheckPointGaiaParser
        assert score >= 0.5


# ---------------------------------------------------------------------------
# PHASE 2: real configuration parsing (insecure sample)
# ---------------------------------------------------------------------------


class TestInsecureParsing:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.baseline = CheckPointGaiaParser().parse(
            read("insecure.conf"), source_file="insecure.conf"
        )

    def test_provenance(self):
        p = self.baseline.provenance
        assert p.parser_name == "checkpoint_gaia"
        assert p.vendor == "checkpoint"
        assert p.os_family == "gaia"
        assert p.detection_confidence >= 0.5

    def test_hostname(self):
        assert self.baseline.hostname.value == "INSECURE-GW"
        assert self.baseline.hostname.detected is True
        assert self.baseline.hostname.source_line is not None

    def test_ntp_single_server(self):
        assert self.baseline.ntp_servers.value == ["10.0.0.1"]
        assert self.baseline.ntp_redundant.value is False

    def test_dns_servers(self):
        assert self.baseline.dns_servers.value == ["8.8.8.8", "8.8.4.4"]

    def test_snmp_agent_enabled(self):
        assert self.baseline.snmp_agent_enabled.value is True

    def test_snmp_default_communities(self):
        names = [c.name for c in self.baseline.snmp_communities.value]
        assert "public" in names
        assert "private" in names
        for c in self.baseline.snmp_communities.value:
            assert c.line_number is not None

    def test_snmp_community_access(self):
        comms = {c.name: c.access for c in self.baseline.snmp_communities.value}
        assert comms["public"] == "ro"
        assert comms["private"] == "rw"

    def test_no_syslog(self):
        assert self.baseline.logging_enabled.value is False
        assert self.baseline.logging_hosts.value == []

    def test_weak_password(self):
        assert self.baseline.password_min_length.value == 4
        assert self.baseline.password_max_age_days.value == 0

    def test_no_lockout(self):
        assert self.baseline.admin_lockout_threshold.value == 0

    def test_long_timeout(self):
        assert self.baseline.vty_exec_timeout_seconds.value == 43200  # 720 * 60

    def test_no_banner(self):
        assert self.baseline.login_banner_present.value is False
        assert self.baseline.pre_login_banner_present.value is False
        assert self.baseline.post_login_banner_present.value is False

    def test_no_aaa(self):
        assert self.baseline.aaa_enabled.value is False

    def test_telnet_disabled(self):
        assert self.baseline.telnet_enabled.value is False

    def test_ssh_enabled(self):
        assert self.baseline.ssh_enabled.value is True
        assert self.baseline.ssh_version.value == 2

    def test_http_disabled(self):
        assert self.baseline.http_server_enabled.value is False

    def test_https_enabled(self):
        assert self.baseline.https_server_enabled.value is True

    def test_default_port(self):
        assert self.baseline.admin_default_ports_changed.value is False


# ---------------------------------------------------------------------------
# PHASE 3: compliant (secure) configuration
# ---------------------------------------------------------------------------


class TestSecureParsing:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.baseline = CheckPointGaiaParser().parse(
            read("secure.conf"), source_file="secure.conf"
        )

    def test_hostname(self):
        assert self.baseline.hostname.value == "SECURE-GW-01"

    def test_strong_password(self):
        assert self.baseline.password_min_length.value == 12

    def test_password_expiration(self):
        assert self.baseline.password_max_age_days.value == 90

    def test_password_complexity(self):
        assert self.baseline.password_min_uppercase.value >= 1
        assert self.baseline.password_min_lowercase.value >= 1
        assert self.baseline.password_min_numeric.value >= 1
        assert self.baseline.password_min_special.value >= 1

    def test_password_history(self):
        assert self.baseline.password_history_reuse_limit.value == 12

    def test_password_encryption(self):
        assert self.baseline.password_encryption.value is True

    def test_lockout(self):
        assert self.baseline.admin_lockout_threshold.value == 3
        assert self.baseline.admin_lockout_duration.value == 1800

    def test_timeout(self):
        assert self.baseline.vty_exec_timeout_seconds.value == 600

    def test_banner(self):
        assert self.baseline.login_banner_present.value is True
        assert self.baseline.pre_login_banner_present.value is True
        assert self.baseline.post_login_banner_present.value is True

    def test_syslog(self):
        assert self.baseline.logging_enabled.value is True
        assert len(self.baseline.logging_hosts.value) == 2

    def test_ntp_redundant(self):
        assert len(self.baseline.ntp_servers.value) == 2
        assert self.baseline.ntp_redundant.value is True

    def test_aaa(self):
        assert self.baseline.aaa_enabled.value is True

    def test_non_default_port(self):
        assert self.baseline.admin_default_ports_changed.value is True

    def test_snmpv3_only(self):
        assert self.baseline.snmp_v3_users_present.value is True


# ---------------------------------------------------------------------------
# PHASE 4: absent/minimal configuration
# ---------------------------------------------------------------------------


class TestAbsentSettings:
    def test_minimal_config(self):
        config = "set hostname MINIMAL-GW\n"
        baseline = CheckPointGaiaParser().parse(config)
        assert baseline.hostname.value == "MINIMAL-GW"
        assert baseline.ntp_servers.value == []
        assert baseline.logging_enabled.value is False
        assert baseline.password_min_length.value == 0
        assert baseline.aaa_enabled.value is False

    def test_empty_raises(self):
        with pytest.raises(ParserError):
            CheckPointGaiaParser().parse("")

    def test_whitespace_only_raises(self):
        with pytest.raises(ParserError):
            CheckPointGaiaParser().parse("   \n  \n  ")

    def test_no_hostname(self):
        config = "set ntp active on\nset ntp server primary 10.0.0.1 version 4\n"
        baseline = CheckPointGaiaParser().parse(config)
        assert baseline.hostname.detected is False

    def test_default_timeout_when_absent(self):
        config = "set hostname TEST\n"
        baseline = CheckPointGaiaParser().parse(config)
        assert baseline.vty_exec_timeout_seconds.value == 600
        assert baseline.vty_exec_timeout_seconds.detected is True


# ---------------------------------------------------------------------------
# PHASE 5: boundary values
# ---------------------------------------------------------------------------


class TestBoundaryValues:
    def test_min_timeout(self):
        config = "set hostname T\nset inactivity-timeout 1\n"
        b = CheckPointGaiaParser().parse(config)
        assert b.vty_exec_timeout_seconds.value == 60

    def test_max_timeout(self):
        config = "set hostname T\nset inactivity-timeout 720\n"
        b = CheckPointGaiaParser().parse(config)
        assert b.vty_exec_timeout_seconds.value == 43200

    def test_min_password_length_6(self):
        config = "set hostname T\nset password-controls min-password-length 6\n"
        b = CheckPointGaiaParser().parse(config)
        assert b.password_min_length.value == 6

    def test_max_password_length_128(self):
        config = "set hostname T\nset password-controls min-password-length 128\n"
        b = CheckPointGaiaParser().parse(config)
        assert b.password_min_length.value == 128

    def test_lockout_boundary(self):
        config = (
            "set hostname T\n"
            "set password-controls deny-on-fail enable on\n"
            "set password-controls deny-on-fail failures-allowed 2\n"
            "set password-controls deny-on-fail allow-after 60\n"
        )
        b = CheckPointGaiaParser().parse(config)
        assert b.admin_lockout_threshold.value == 2
        assert b.admin_lockout_duration.value == 60

    def test_password_expiration_never(self):
        config = "set hostname T\nset password-controls password-expiration never\n"
        b = CheckPointGaiaParser().parse(config)
        assert b.password_max_age_days.value == 0

    def test_password_expiration_1_day(self):
        config = "set hostname T\nset password-controls password-expiration 1\n"
        b = CheckPointGaiaParser().parse(config)
        assert b.password_max_age_days.value == 1

    def test_complexity_level_1(self):
        config = "set hostname T\nset password-controls complexity 1\n"
        b = CheckPointGaiaParser().parse(config)
        assert b.password_min_uppercase.value == 0
        assert b.password_min_special.value == 0

    def test_complexity_level_4(self):
        config = "set hostname T\nset password-controls complexity 4\n"
        b = CheckPointGaiaParser().parse(config)
        assert b.password_min_uppercase.value >= 1
        assert b.password_min_lowercase.value >= 1
        assert b.password_min_numeric.value >= 1
        assert b.password_min_special.value >= 1


# ---------------------------------------------------------------------------
# PHASE 6: malformed / partial configuration
# ---------------------------------------------------------------------------


class TestMalformedInput:
    def test_comment_only(self):
        config = "# Just comments\n# Nothing else\nset hostname WORKS\n"
        b = CheckPointGaiaParser().parse(config)
        assert b.hostname.value == "WORKS"

    def test_garbage_lines_ignored(self):
        config = (
            "GARBAGE LINE\n"
            "set hostname GOOD\n"
            "random text here\n"
            "set ntp active on\n"
        )
        b = CheckPointGaiaParser().parse(config)
        assert b.hostname.value == "GOOD"

    def test_partial_password_controls(self):
        config = (
            "set hostname T\n"
            "set password-controls min-password-length 10\n"
        )
        b = CheckPointGaiaParser().parse(config)
        assert b.password_min_length.value == 10
        assert b.password_max_age_days.value == 0  # absent

    def test_lockout_enabled_without_params(self):
        config = (
            "set hostname T\n"
            "set password-controls deny-on-fail enable on\n"
        )
        b = CheckPointGaiaParser().parse(config)
        assert b.admin_lockout_threshold.value == 0
        assert b.admin_lockout_duration.value == 0


# ---------------------------------------------------------------------------
# PHASE 7: evidence provenance
# ---------------------------------------------------------------------------


class TestEvidence:
    def test_hostname_evidence(self):
        config = "# comment\nset hostname MY-FW\n"
        b = CheckPointGaiaParser().parse(config)
        assert b.hostname.source_line == "set hostname MY-FW"
        assert b.hostname.line_number == 2

    def test_ntp_evidence(self):
        config = "set hostname T\nset ntp server primary 1.2.3.4 version 4\n"
        b = CheckPointGaiaParser().parse(config)
        assert "1.2.3.4" in b.ntp_servers.source_line
        assert b.ntp_servers.line_number == 2

    def test_snmp_community_evidence(self):
        config = "set hostname T\nset snmp community mycomm read-only\n"
        b = CheckPointGaiaParser().parse(config)
        c = b.snmp_communities.value[0]
        assert "mycomm" in c.source_line
        assert c.line_number == 2

    def test_syslog_evidence(self):
        config = "set hostname T\nadd syslog log-remote-address 10.0.0.5 level info\n"
        b = CheckPointGaiaParser().parse(config)
        assert "10.0.0.5" in b.logging_hosts.source_line
        assert b.logging_hosts.line_number == 2

    def test_all_observations_are_deterministic(self):
        b = CheckPointGaiaParser().parse(read("secure.conf"))
        for field_name in b.observable_fields():
            obs = getattr(b, field_name)
            assert obs.origin == Origin.DETERMINISTIC

    def test_all_observations_detected_or_noted(self):
        b = CheckPointGaiaParser().parse(read("insecure.conf"))
        for field_name in b.observable_fields():
            obs = getattr(b, field_name)
            assert obs.note is not None or obs.detected, (
                f"{field_name} has no note and is not detected"
            )


# ---------------------------------------------------------------------------
# PHASE 8: deterministic repeated evaluation
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_parse_twice_identical(self):
        text = read("insecure.conf")
        parser = CheckPointGaiaParser()
        b1 = parser.parse(text)
        b2 = parser.parse(text)
        assert b1.model_dump() == b2.model_dump()

    def test_parse_secure_twice_identical(self):
        text = read("secure.conf")
        parser = CheckPointGaiaParser()
        b1 = parser.parse(text)
        b2 = parser.parse(text)
        assert b1.model_dump() == b2.model_dump()


# ---------------------------------------------------------------------------
# PHASE 9: CIS compliance pipeline
# ---------------------------------------------------------------------------


class TestCISCompliance:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.rules = load_framework("CIS", "checkpoint_gaia")

    def test_insecure_has_failures(self):
        text = read("insecure.conf")
        baseline = CheckPointGaiaParser().parse(text)
        engine = ComplianceEngine(self.rules)
        report = engine.build_report(baseline, tool_name="test", tool_version="1")
        statuses = {r.rule_id: r.status for r in report.results}
        assert Status.FAIL in statuses.values()

    def test_secure_has_passes(self):
        text = read("secure.conf")
        baseline = CheckPointGaiaParser().parse(text)
        engine = ComplianceEngine(self.rules)
        report = engine.build_report(baseline, tool_name="test", tool_version="1")
        statuses = {r.rule_id: r.status for r in report.results}
        fail_ids = [k for k, v in statuses.items() if v == Status.FAIL]
        assert len(fail_ids) == 0, f"Unexpected failures: {fail_ids}"

    def test_insecure_banner_fails(self):
        text = read("insecure.conf")
        baseline = CheckPointGaiaParser().parse(text)
        engine = ComplianceEngine(self.rules)
        report = engine.build_report(baseline, tool_name="test", tool_version="1")
        banner_result = next(
            (r for r in report.results if "BANNER" in r.rule_id), None
        )
        assert banner_result is not None
        assert banner_result.status == Status.FAIL

    def test_secure_banner_passes(self):
        text = read("secure.conf")
        baseline = CheckPointGaiaParser().parse(text)
        engine = ComplianceEngine(self.rules)
        report = engine.build_report(baseline, tool_name="test", tool_version="1")
        banner_result = next(
            (r for r in report.results if "BANNER" in r.rule_id), None
        )
        assert banner_result is not None
        assert banner_result.status == Status.PASS


# ---------------------------------------------------------------------------
# PHASE 10: vendor isolation
# ---------------------------------------------------------------------------


class TestVendorIsolation:
    def test_gaia_does_not_detect_ios(self):
        ios = (SAMPLES.parent / "insecure_ios.conf").read_text()
        assert CheckPointGaiaParser.detect(ios) < 0.3

    def test_ios_does_not_detect_gaia(self):
        from auditor.parsers.cisco_ios import CiscoIOSParser

        gaia = read("insecure.conf")
        assert CiscoIOSParser.detect(gaia) < 0.3

    def test_sequential_parsing_isolation(self):
        """Parse Gaia -> IOS -> Gaia and verify Gaia results are identical."""
        from auditor.parsers.cisco_ios import CiscoIOSParser

        gaia_text = read("insecure.conf")
        ios_text = (SAMPLES.parent / "insecure_ios.conf").read_text()

        gaia_parser = CheckPointGaiaParser()
        ios_parser = CiscoIOSParser()

        b1 = gaia_parser.parse(gaia_text)
        _ = ios_parser.parse(ios_text)
        b2 = gaia_parser.parse(gaia_text)

        assert b1.model_dump() == b2.model_dump()

    def test_registry_never_selects_gaia_for_other_vendors(self):
        other_samples = [
            SAMPLES.parent / "insecure_ios.conf",
            SAMPLES.parent / "junos_srx.conf",
            SAMPLES.parent / "fortios_fgt.conf",
        ]
        for path in other_samples:
            if path.exists():
                text = path.read_text()
                ranked = registry.rank(text)
                if ranked:
                    assert ranked[0][1] is not CheckPointGaiaParser, (
                        f"Gaia wrongly ranked first for {path.name}"
                    )
