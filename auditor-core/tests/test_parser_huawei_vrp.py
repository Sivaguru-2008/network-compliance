"""Huawei VRP parser tests: normalization contract, detection, identity, and evidence.

Mirrors the Cisco IOS and SONiC test structure.
"""

from pathlib import Path
import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.observation import Observation, Origin
from auditor.models.result import Status
from auditor.parsers import ParserError, registry
from auditor.parsers.huawei_vrp import HuaweiVRPParser
from auditor.identity.extractors import extract_identity, platform_key
from auditor.rules import load_framework
from auditor.engine import ComplianceEngine

SAMPLES = Path(__file__).resolve().parents[1] / "samples" / "huawei_vrp"


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
    return HuaweiVRPParser().parse(secure_text, source_file="samples/huawei_vrp/secure.conf")


@pytest.fixture(scope="module")
def insecure(insecure_text) -> SecurityBaselineModel:
    return HuaweiVRPParser().parse(insecure_text, source_file="samples/huawei_vrp/insecure.conf")


# ---------------------------------------------------------------------------
# vendor detection
# ---------------------------------------------------------------------------

class TestDetection:
    def test_secure_config_is_detected_as_vrp(self, secure_text):
        assert HuaweiVRPParser.detect(secure_text) >= 0.5

    def test_insecure_config_is_detected_as_vrp(self, insecure_text):
        assert HuaweiVRPParser.detect(insecure_text) >= 0.5

    def test_registry_auto_detects_the_vrp_parser(self, secure_text):
        parser_cls, score = registry.detect(secure_text)
        assert parser_cls is HuaweiVRPParser
        assert score >= 0.5

    def test_cisco_config_scores_low(self, unknown_text):
        assert HuaweiVRPParser.detect(unknown_text) < 0.2

    def test_empty_config_scores_zero(self):
        assert HuaweiVRPParser.detect("") == 0.0


# ---------------------------------------------------------------------------
# device identity
# ---------------------------------------------------------------------------

class TestIdentity:
    def test_secure_hostname(self, secure):
        assert secure.hostname.value == "SECURE-VRP"

    def test_insecure_hostname(self, insecure):
        assert insecure.hostname.value == "INSECURE-VRP"

    def test_identity_extraction(self, secure_text, secure):
        identity = extract_identity(secure_text, secure)
        assert identity.vendor == "huawei_vrp"
        assert identity.os_family == "vrp"
        assert identity.hostname.value == "SECURE-VRP"
        assert identity.os_version.value == "V200R010C00SPC600"


# ---------------------------------------------------------------------------
# normalization details
# ---------------------------------------------------------------------------

class TestNormalization:
    def test_vty_transport_secure(self, secure):
        assert secure.telnet_enabled.value is False
        assert secure.ssh_enabled.value is True
        assert secure.vty_transport_input.value == ["ssh"]

    def test_vty_transport_insecure(self, insecure):
        # telnet server enable is configured, VTY idle-timeout is 0, no protocol restrict
        assert insecure.telnet_enabled.value is True
        assert insecure.ssh_enabled.value is False
        assert insecure.vty_transport_input.value == ["telnet"]

    def test_idle_timeout_secure(self, secure):
        # secure.conf VTY timeout is "idle-timeout 10 0" -> 600
        assert secure.vty_exec_timeout_seconds.value == 600

    def test_idle_timeout_insecure(self, insecure):
        # insecure.conf VTY timeout is "idle-timeout 0" -> 0 (infinite)
        assert insecure.vty_exec_timeout_seconds.value == 0

    def test_logging_secure(self, secure):
        assert secure.logging_enabled.value is True
        assert secure.logging_hosts.value == ["10.30.40.50"]

    def test_logging_insecure(self, insecure):
        assert insecure.logging_enabled.value is False
        assert insecure.logging_hosts.value == []

    def test_ntp_secure(self, secure):
        assert secure.ntp_servers.value == ["10.30.40.41"]

    def test_ntp_insecure(self, insecure):
        assert insecure.ntp_servers.value == []

    def test_snmp_secure(self, secure):
        assert secure.snmp_agent_enabled.value is True
        communities = secure.snmp_communities.value
        assert len(communities) == 1
        assert communities[0].name == "%#Zx4Vb8Nm1Qw#%"
        assert communities[0].access == "ro"
        assert communities[0].acl == "2000"

    def test_snmp_insecure(self, insecure):
        assert insecure.snmp_agent_enabled.value is True
        communities = insecure.snmp_communities.value
        assert len(communities) == 2
        names = [c.name for c in communities]
        assert "public" in names
        assert "private" in names

    def test_aaa_and_credentials_secure(self, secure):
        assert secure.aaa_enabled.value is True
        assert secure.enable_secret_set.value is True  # super password irreversible-cipher
        assert secure.password_encryption.value is True

    def test_aaa_and_credentials_insecure(self, insecure):
        assert insecure.aaa_enabled.value is True
        assert insecure.enable_secret_set.value is False  # super password simple
        assert insecure.enable_password_present.value is True
        assert insecure.password_encryption.value is False  # has simple password


# ---------------------------------------------------------------------------
# absence / boundary tests
# ---------------------------------------------------------------------------

class TestAbsencePolicy:
    @pytest.mark.parametrize(
        "field",
        [
            "vty_exec_timeout_seconds",
            "ssh_version",
        ],
    )
    def test_ambiguous_absence_is_undetected(self, ambiguous_text, field):
        baseline = HuaweiVRPParser().parse(ambiguous_text)
        observation = getattr(baseline, field)
        assert observation.detected is False


# ---------------------------------------------------------------------------
# compliance integration
# ---------------------------------------------------------------------------

class TestFrameworkFlowThrough:
    @pytest.mark.parametrize("framework", ["CIS", "NIST_800_53", "ISO_27001"])
    def test_vrp_control_flows_through_all_frameworks(self, secure, framework):
        ruleset = load_framework(framework, "huawei_vrp")
        assert len(ruleset.rules) > 0

        engine = ComplianceEngine(ruleset)
        results = engine.evaluate(secure)

        # Secure config should pass major security rules
        assert len(results) > 0
        
        # Verify that all results preserve evidence/source
        for r in results:
            assert r.device == "SECURE-VRP"
            assert r.vendor == "huawei"
            assert r.parser == "huawei_vrp"
            if r.status != Status.PASS:
                assert r.remediation is not None
                assert r.remediation.summary != "No remediation provided."
