"""Arista EOS parser: normalization contract, detection, identity, and evidence.

Mirrors the structure of test_parser_cisco_ios.py — pins the value,
detected flag, and evidence line for every observable field so that
everything downstream (rules, reports, frameworks) is known-correct.
"""

import pytest

from pathlib import Path
from auditor.models.baseline import SecurityBaselineModel
from auditor.models.observation import Observation, Origin
from auditor.models.result import Status
from auditor.parsers import ParserError, registry
from auditor.parsers.arista_eos import AristaEOSParser
from auditor.identity.extractors import extract_identity, platform_key
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "arista"


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def secure_text() -> str:
    return (SAMPLES / "secure.conf").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def insecure_text() -> str:
    return (SAMPLES / "insecure.conf").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def ambiguous_text() -> str:
    return (SAMPLES / "ambiguous.conf").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def unknown_text() -> str:
    return (SAMPLES / "unknown.conf").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def malformed_text() -> str:
    return (SAMPLES / "malformed.conf").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def secure(secure_text) -> SecurityBaselineModel:
    return AristaEOSParser().parse(secure_text, source_file="samples/arista/secure.conf")


@pytest.fixture(scope="module")
def insecure(insecure_text) -> SecurityBaselineModel:
    return AristaEOSParser().parse(insecure_text, source_file="samples/arista/insecure.conf")


# ---------------------------------------------------------------------------
# vendor detection
# ---------------------------------------------------------------------------


class TestDetection:
    def test_secure_config_is_detected_as_eos(self, secure_text):
        assert AristaEOSParser.detect(secure_text) >= 0.5

    def test_insecure_config_is_detected_as_eos(self, insecure_text):
        assert AristaEOSParser.detect(insecure_text) >= 0.5

    def test_registry_auto_detects_the_arista_parser(self, secure_text):
        parser_cls, score = registry.detect(secure_text)
        assert parser_cls is AristaEOSParser
        assert score >= 0.5

    def test_ios_config_scores_low(self):
        ios_config = "hostname R1\nline vty 0 4\n transport input ssh\nip http server\nend\n"
        assert AristaEOSParser.detect(ios_config) < 0.3

    def test_junos_config_scores_low(self):
        junos_config = "set system host-name fw01\nset system services ssh\n"
        assert AristaEOSParser.detect(junos_config) < 0.3

    def test_fortios_config_scores_low(self):
        fortios_config = "config system global\n set hostname FGT\nend\n"
        assert AristaEOSParser.detect(fortios_config) < 0.3

    def test_empty_config_scores_zero(self):
        assert AristaEOSParser.detect("") == 0.0
        assert AristaEOSParser.detect("   \n\n  ") == 0.0


# ---------------------------------------------------------------------------
# device identity
# ---------------------------------------------------------------------------


class TestIdentity:
    def test_secure_hostname(self, secure):
        assert secure.hostname.value == "sw-core-01"
        assert secure.hostname.detected is True

    def test_insecure_hostname(self, insecure):
        assert insecure.hostname.value == "sw-branch-02"
        assert insecure.hostname.detected is True

    def test_provenance(self, secure):
        assert secure.provenance.vendor == "arista"
        assert secure.provenance.os_family == "eos"
        assert secure.provenance.parser_name == "arista_eos"
        assert secure.source_sha256 and len(secure.source_sha256) == 64

    def test_device_identity_extraction(self, secure_text, secure):
        identity = extract_identity(secure_text, secure)
        assert identity.vendor == "arista_eos"
        assert identity.hostname.value == "sw-core-01"
        assert identity.model.detected is True
        assert identity.model.value == "DCS-7050SX3-48YC12"
        assert identity.os_version.detected is True
        assert "4.28.0F" in identity.os_version.value

    def test_platform_key(self, secure):
        assert platform_key(secure) == "arista_eos"


# ---------------------------------------------------------------------------
# hardened (secure) sample — all controls PASS
# ---------------------------------------------------------------------------


class TestSecureValues:
    @pytest.mark.parametrize(
        "field, expected_value",
        [
            ("ssh_enabled", True),
            ("telnet_enabled", False),
            ("enable_secret_set", True),
            ("enable_password_present", False),
            ("password_encryption", True),
            ("aaa_enabled", True),
            ("logging_enabled", True),
            ("logging_buffered", True),
            ("management_acl_applied", True),
            ("login_banner_present", True),
            ("password_min_length", 8),
        ],
    )
    def test_detected_values(self, secure, field, expected_value):
        observation = getattr(secure, field)
        assert observation.detected is True, f"{field} should be conclusively determined"
        assert observation.value == expected_value

    def test_ssh_version_is_unknown(self, secure):
        assert secure.ssh_version.detected is False
        assert "EOS" in secure.ssh_version.note

    def test_http_disabled(self, secure):
        assert secure.http_server_enabled.detected is True
        assert secure.http_server_enabled.value is False

    def test_https_enabled(self, secure):
        assert secure.https_server_enabled.detected is True
        assert secure.https_server_enabled.value is True

    def test_snmp_community_not_default(self, secure):
        communities = secure.snmp_communities.value
        assert secure.snmp_communities.detected is True
        assert [c.name for c in communities] == ["s3cur3RO"]
        assert communities[0].access == "ro"

    def test_logging_hosts(self, secure):
        assert secure.logging_hosts.detected is True
        assert secure.logging_hosts.value == ["10.1.1.100"]

    def test_ntp_servers(self, secure):
        assert secure.ntp_servers.detected is True
        assert sorted(secure.ntp_servers.value) == ["10.1.1.10", "10.1.1.11"]

    def test_idle_timeout(self, secure):
        assert secure.vty_exec_timeout_seconds.detected is True
        assert secure.vty_exec_timeout_seconds.value == 600

    def test_vty_transport_derived(self, secure):
        assert secure.vty_transport_input.detected is True
        assert "ssh" in secure.vty_transport_input.value
        assert "telnet" not in secure.vty_transport_input.value


# ---------------------------------------------------------------------------
# insecure sample — many controls FAIL
# ---------------------------------------------------------------------------


class TestInsecureValues:
    @pytest.mark.parametrize(
        "field, expected_value",
        [
            ("ssh_enabled", True),
            ("telnet_enabled", True),
            ("enable_secret_set", False),
            ("enable_password_present", True),
            ("password_encryption", False),
            ("aaa_enabled", False),
            ("logging_enabled", False),
            ("management_acl_applied", False),
            ("login_banner_present", False),
            ("password_min_length", 0),
        ],
    )
    def test_detected_values(self, insecure, field, expected_value):
        observation = getattr(insecure, field)
        assert observation.detected is True, f"{field} should be conclusively determined"
        assert observation.value == expected_value

    def test_insecure_snmp_defaults(self, insecure):
        communities = insecure.snmp_communities.value
        names = [c.name for c in communities]
        assert "public" in names
        assert "private" in names

    def test_insecure_http_enabled(self, insecure):
        assert insecure.http_server_enabled.detected is True
        assert insecure.http_server_enabled.value is True

    def test_insecure_idle_timeout_disabled(self, insecure):
        assert insecure.vty_exec_timeout_seconds.detected is True
        assert insecure.vty_exec_timeout_seconds.value == 0

    def test_insecure_no_logging_hosts(self, insecure):
        assert insecure.logging_hosts.detected is True
        assert insecure.logging_hosts.value == []

    def test_insecure_no_ntp(self, insecure):
        assert insecure.ntp_servers.detected is True
        assert insecure.ntp_servers.value == []

    def test_insecure_vty_transport_includes_telnet(self, insecure):
        assert insecure.vty_transport_input.detected is True
        assert "telnet" in insecure.vty_transport_input.value


# ---------------------------------------------------------------------------
# evidence integrity
# ---------------------------------------------------------------------------


class TestEvidenceIntegrity:
    @pytest.mark.parametrize("fixture_name", ["secure", "insecure"])
    def test_reported_line_numbers_match_source_file(self, request, fixture_name):
        baseline = request.getfixturevalue(fixture_name)
        raw_lines = request.getfixturevalue(f"{fixture_name}_text").splitlines()

        checked = 0
        for field in SecurityBaselineModel.observable_fields():
            observation = getattr(baseline, field)
            if observation.line_number is None:
                continue
            actual = raw_lines[observation.line_number - 1].strip()
            assert actual == observation.source_line, f"{field} cites line {observation.line_number}"
            checked += 1
        assert checked >= 5

    @pytest.mark.parametrize("fixture_name", ["secure", "insecure"])
    def test_every_field_has_evidence_or_reason(self, request, fixture_name):
        baseline = request.getfixturevalue(fixture_name)
        for field in SecurityBaselineModel.observable_fields():
            observation = getattr(baseline, field)
            if observation.detected:
                assert observation.source_line or observation.note, (
                    f"{field} is detected but carries neither a source line nor a justification"
                )
            else:
                assert observation.value is None
                assert observation.note, f"{field} is undetected but does not say why"

    def test_provenance_origin_is_deterministic(self, secure):
        for field in SecurityBaselineModel.observable_fields():
            obs = getattr(secure, field)
            if obs.detected:
                assert obs.origin in (Origin.DETERMINISTIC, None)


# ---------------------------------------------------------------------------
# golden config variants
# ---------------------------------------------------------------------------


class TestGoldenConfigs:
    def test_ambiguous_config_parses(self, ambiguous_text):
        baseline = AristaEOSParser().parse(ambiguous_text)
        assert baseline.hostname.detected is True

    def test_unknown_commands_config_parses(self, unknown_text):
        baseline = AristaEOSParser().parse(unknown_text)
        assert baseline.hostname.detected is True

    def test_malformed_config_parses_partially(self, malformed_text):
        baseline = AristaEOSParser().parse(malformed_text)
        assert baseline.provenance.parser_name == "arista_eos"


# ---------------------------------------------------------------------------
# error handling
# ---------------------------------------------------------------------------


class TestErrors:
    def test_empty_config_raises(self):
        with pytest.raises(ParserError):
            AristaEOSParser().parse("   \n\n")

    def test_none_config_raises(self):
        with pytest.raises(ParserError):
            AristaEOSParser().parse(None)


# ---------------------------------------------------------------------------
# absence policy
# ---------------------------------------------------------------------------


MINIMAL_EOS = "hostname EDGE-01\n!\nend\n"


class TestAbsencePolicy:
    @pytest.fixture(scope="class")
    def minimal(self):
        return AristaEOSParser().parse(MINIMAL_EOS)

    @pytest.mark.parametrize(
        "field",
        ["ssh_enabled", "ssh_version", "vty_exec_timeout_seconds"],
    )
    def test_ambiguous_absence_is_undetected(self, minimal, field):
        assert getattr(minimal, field).detected is False

    @pytest.mark.parametrize(
        "field, expected",
        [
            ("enable_secret_set", False),
            ("password_encryption", False),
            ("aaa_enabled", False),
            ("logging_enabled", False),
            ("login_banner_present", False),
            ("password_min_length", 0),
            ("ntp_servers", []),
        ],
    )
    def test_conclusive_absence_is_detected_as_insecure(self, minimal, field, expected):
        observation = getattr(minimal, field)
        assert observation.detected is True
        assert observation.value == expected


# ---------------------------------------------------------------------------
# framework flow-through
# ---------------------------------------------------------------------------


class TestFrameworkFlowThrough:
    @pytest.fixture(scope="class")
    def eos_baseline(self, secure_text=None):
        text = (SAMPLES / "secure.conf").read_text(encoding="utf-8")
        return AristaEOSParser().parse(text)

    def test_cis_framework_loads_for_arista_eos(self):
        ruleset = load_framework("CIS", "arista_eos")
        assert len(ruleset.rules) == 13
        assert ruleset.platform.vendor == "arista"

    def test_nist_framework_loads_for_arista_eos(self):
        ruleset = load_framework("NIST_800_53", "arista_eos")
        assert len(ruleset.rules) == 13

    def test_stig_framework_loads_for_arista_eos(self):
        ruleset = load_framework("STIG", "arista_eos")
        assert len(ruleset.rules) == 13

    def test_iso_framework_loads_for_arista_eos(self):
        ruleset = load_framework("ISO_27001", "arista_eos")
        assert len(ruleset.rules) == 13

    @pytest.mark.parametrize("fw", ["CIS", "NIST_800_53", "STIG", "ISO_27001"])
    def test_arista_control_flows_through_all_frameworks(self, fw, eos_baseline):
        ruleset = load_framework(fw, "arista_eos")
        engine = ComplianceEngine(ruleset)
        results = engine.evaluate(eos_baseline)
        by_control = {r.internal_control_id: r for r in results}
        assert "aaa_enabled" in by_control
        assert by_control["aaa_enabled"].status == Status.PASS

    def test_cis_insecure_produces_failures(self, insecure_text):
        baseline = AristaEOSParser().parse(insecure_text)
        ruleset = load_framework("CIS", "arista_eos")
        engine = ComplianceEngine(ruleset)
        results = engine.evaluate(baseline)
        statuses = {r.internal_control_id: r.status for r in results}
        assert statuses["aaa_enabled"] == Status.FAIL
        assert statuses["no_default_snmp_community"] == Status.FAIL
        assert statuses["logging_enabled"] == Status.FAIL


# ---------------------------------------------------------------------------
# cross-vendor detection isolation
# ---------------------------------------------------------------------------


class TestCrossVendorDetection:
    def test_eos_does_not_match_ios_config(self):
        ios = "hostname R1\nline vty 0 4\n transport input ssh\nip http server\nend\n"
        assert AristaEOSParser.detect(ios) < 0.3

    def test_ios_does_not_match_eos_config(self, secure_text):
        from auditor.parsers.cisco_ios import CiscoIOSParser
        assert CiscoIOSParser.detect(secure_text) < AristaEOSParser.detect(secure_text)
