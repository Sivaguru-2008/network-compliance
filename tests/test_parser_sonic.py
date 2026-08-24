"""SONiC parser: normalization contract, detection, identity, and evidence.

Mirrors the Arista EOS and Cisco IOS test structure — pins the value,
detected flag, and evidence for every observable field.
"""

import json
import pytest

from pathlib import Path
from auditor.models.baseline import SecurityBaselineModel
from auditor.models.observation import Observation, Origin
from auditor.models.result import Status
from auditor.parsers import ParserError, registry
from auditor.parsers.sonic import SonicParser
from auditor.identity.extractors import extract_identity, platform_key
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "sonic"


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
    return SonicParser().parse(secure_text, source_file="samples/sonic/secure.conf")


@pytest.fixture(scope="module")
def insecure(insecure_text) -> SecurityBaselineModel:
    return SonicParser().parse(insecure_text, source_file="samples/sonic/insecure.conf")


# ---------------------------------------------------------------------------
# vendor detection
# ---------------------------------------------------------------------------


class TestDetection:
    def test_secure_config_is_detected_as_sonic(self, secure_text):
        assert SonicParser.detect(secure_text) >= 0.5

    def test_insecure_config_is_detected_as_sonic(self, insecure_text):
        assert SonicParser.detect(insecure_text) >= 0.5

    def test_registry_auto_detects_the_sonic_parser(self, secure_text):
        parser_cls, score = registry.detect(secure_text)
        assert parser_cls is SonicParser
        assert score >= 0.5

    def test_non_json_config_scores_zero(self):
        assert SonicParser.detect("hostname R1\nend\n") == 0.0

    def test_plain_json_without_sonic_keys_scores_low(self):
        assert SonicParser.detect('{"foo": "bar"}') < 0.3

    def test_empty_config_scores_zero(self):
        assert SonicParser.detect("") == 0.0

    def test_json_with_device_metadata_scores_high(self):
        config = json.dumps({"DEVICE_METADATA": {"localhost": {"hostname": "test"}}})
        assert SonicParser.detect(config) >= 0.4


# ---------------------------------------------------------------------------
# device identity
# ---------------------------------------------------------------------------


class TestIdentity:
    def test_secure_hostname(self, secure):
        assert secure.hostname.value == "sonic-leaf-01"
        assert secure.hostname.detected is True

    def test_insecure_hostname(self, insecure):
        assert insecure.hostname.value == "sonic-lab-insecure"
        assert insecure.hostname.detected is True

    def test_provenance(self, secure):
        assert secure.provenance.vendor == "sonic"
        assert secure.provenance.os_family == "sonic"
        assert secure.provenance.parser_name == "sonic"
        assert secure.source_sha256 and len(secure.source_sha256) == 64

    def test_device_identity_extraction(self, secure_text, secure):
        identity = extract_identity(secure_text, secure)
        assert identity.vendor == "sonic_sonic"
        assert identity.hostname.value == "sonic-leaf-01"
        assert identity.model.detected is True
        assert "mlnx" in identity.model.value.lower() or "Mellanox" in identity.model.value

    def test_platform_key(self, secure):
        assert platform_key(secure) == "sonic_sonic"


# ---------------------------------------------------------------------------
# secure sample values
# ---------------------------------------------------------------------------


class TestSecureValues:
    def test_aaa_enabled(self, secure):
        assert secure.aaa_enabled.detected is True
        assert secure.aaa_enabled.value is True

    def test_ssh_enabled(self, secure):
        assert secure.ssh_enabled.detected is True
        assert secure.ssh_enabled.value is True

    def test_ssh_version_is_unknown(self, secure):
        assert secure.ssh_version.detected is False

    def test_snmp_community_not_default(self, secure):
        assert secure.snmp_communities.detected is True
        names = [c.name for c in secure.snmp_communities.value]
        assert "s3cur3RO" in names
        assert "public" not in names
        assert "private" not in names

    def test_logging_enabled(self, secure):
        assert secure.logging_enabled.detected is True
        assert secure.logging_enabled.value is True

    def test_logging_hosts(self, secure):
        assert secure.logging_hosts.detected is True
        assert "10.1.1.100" in secure.logging_hosts.value

    def test_ntp_servers(self, secure):
        assert secure.ntp_servers.detected is True
        assert sorted(secure.ntp_servers.value) == ["10.1.1.10", "10.1.1.11"]

    def test_management_acl_applied(self, secure):
        assert secure.management_acl_applied.detected is True
        assert secure.management_acl_applied.value is True

    def test_vty_transport(self, secure):
        assert secure.vty_transport_input.detected is True
        assert "ssh" in secure.vty_transport_input.value

    def test_linux_level_fields_are_unknown(self, secure):
        assert secure.vty_exec_timeout_seconds.detected is False
        assert secure.login_banner_present.detected is False
        assert secure.enable_secret_set.detected is False
        assert secure.password_min_length.detected is False


# ---------------------------------------------------------------------------
# insecure sample values
# ---------------------------------------------------------------------------


class TestInsecureValues:
    def test_aaa_disabled(self, insecure):
        assert insecure.aaa_enabled.detected is True
        assert insecure.aaa_enabled.value is False

    def test_telnet_enabled(self, insecure):
        assert insecure.telnet_enabled.detected is True
        assert insecure.telnet_enabled.value is True

    def test_insecure_snmp_defaults(self, insecure):
        assert insecure.snmp_communities.detected is True
        names = [c.name for c in insecure.snmp_communities.value]
        assert "public" in names
        assert "private" in names

    def test_insecure_no_logging(self, insecure):
        assert insecure.logging_hosts.detected is True
        assert insecure.logging_hosts.value == []

    def test_insecure_no_ntp(self, insecure):
        assert insecure.ntp_servers.detected is True
        assert insecure.ntp_servers.value == []

    def test_insecure_no_management_acl(self, insecure):
        assert insecure.management_acl_applied.detected is True
        assert insecure.management_acl_applied.value is False

    def test_insecure_vty_transport_includes_telnet(self, insecure):
        assert insecure.vty_transport_input.detected is True
        assert "telnet" in insecure.vty_transport_input.value


# ---------------------------------------------------------------------------
# evidence integrity
# ---------------------------------------------------------------------------


class TestEvidenceIntegrity:
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


# ---------------------------------------------------------------------------
# golden config variants
# ---------------------------------------------------------------------------


class TestGoldenConfigs:
    def test_ambiguous_config_parses(self, ambiguous_text):
        baseline = SonicParser().parse(ambiguous_text)
        assert baseline.hostname.detected is True

    def test_unknown_tables_config_parses(self, unknown_text):
        baseline = SonicParser().parse(unknown_text)
        assert baseline.hostname.detected is True

    def test_malformed_config_raises(self, malformed_text):
        with pytest.raises(ParserError):
            SonicParser().parse(malformed_text)


# ---------------------------------------------------------------------------
# error handling
# ---------------------------------------------------------------------------


class TestErrors:
    def test_empty_config_raises(self):
        with pytest.raises(ParserError):
            SonicParser().parse("   \n\n")

    def test_none_config_raises(self):
        with pytest.raises(ParserError):
            SonicParser().parse(None)

    def test_non_json_config_raises(self):
        with pytest.raises(ParserError):
            SonicParser().parse("hostname R1\nend\n")

    def test_non_object_json_raises(self):
        with pytest.raises(ParserError):
            SonicParser().parse("[1, 2, 3]")

    def test_json_without_sonic_keys_raises(self):
        with pytest.raises(ParserError):
            SonicParser().parse('{"foo": "bar"}')


# ---------------------------------------------------------------------------
# framework flow-through
# ---------------------------------------------------------------------------


class TestFrameworkFlowThrough:
    @pytest.fixture(scope="class")
    def sonic_baseline(self):
        text = (SAMPLES / "secure.conf").read_text(encoding="utf-8")
        return SonicParser().parse(text)

    def test_cis_framework_loads_for_sonic(self):
        ruleset = load_framework("CIS", "sonic")
        assert len(ruleset.rules) == 13
        assert ruleset.platform.vendor == "sonic"

    def test_nist_framework_loads_for_sonic(self):
        ruleset = load_framework("NIST_800_53", "sonic")
        assert len(ruleset.rules) == 13

    def test_stig_framework_loads_for_sonic(self):
        ruleset = load_framework("STIG", "sonic")
        assert len(ruleset.rules) == 13

    def test_iso_framework_loads_for_sonic(self):
        ruleset = load_framework("ISO_27001", "sonic")
        assert len(ruleset.rules) == 13

    @pytest.mark.parametrize("fw", ["CIS", "NIST_800_53", "STIG", "ISO_27001"])
    def test_sonic_control_flows_through_all_frameworks(self, fw, sonic_baseline):
        ruleset = load_framework(fw, "sonic")
        engine = ComplianceEngine(ruleset)
        results = engine.evaluate(sonic_baseline)
        by_control = {r.internal_control_id: r for r in results}
        assert "aaa_enabled" in by_control
        assert by_control["aaa_enabled"].status == Status.PASS

    def test_cis_insecure_produces_failures(self, insecure_text):
        baseline = SonicParser().parse(insecure_text)
        ruleset = load_framework("CIS", "sonic")
        engine = ComplianceEngine(ruleset)
        results = engine.evaluate(baseline)
        statuses = {r.internal_control_id: r.status for r in results}
        assert statuses["aaa_enabled"] == Status.FAIL
        assert statuses["no_default_snmp_community"] == Status.FAIL


# ---------------------------------------------------------------------------
# cross-vendor detection isolation
# ---------------------------------------------------------------------------


class TestCrossVendorDetection:
    def test_sonic_does_not_match_cli_configs(self):
        ios = "hostname R1\nline vty 0 4\n transport input ssh\nend\n"
        assert SonicParser.detect(ios) == 0.0

    def test_sonic_does_not_match_eos_config(self):
        eos = "! device: sw01 (DCS-7050, EOS-4.28)\nhostname sw01\nmanagement ssh\n no shutdown\nend\n"
        assert SonicParser.detect(eos) == 0.0

    def test_eos_does_not_match_sonic_config(self, secure_text):
        from auditor.parsers.arista_eos import AristaEOSParser
        assert AristaEOSParser.detect(secure_text) < SonicParser.detect(secure_text)
