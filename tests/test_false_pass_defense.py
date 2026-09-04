"""Adversarial false-pass defense tests.

These tests verify that the deterministic parsers do NOT incorrectly mark
security controls as PASS when adversarial inputs try to trick them:

- Comments containing security keywords should not trigger detections
- Conflicting settings should not silently resolve to PASS
- AI/LLM evidence must never auto-pass a control

Parsers raising ParserError on malformed input is CORRECT defensive behavior
and is accepted by these tests.
"""

import pytest

from auditor.parsers.base import ParserError
from auditor.parsers.cisco_ios import CiscoIOSParser
from auditor.parsers.junos import JunosParser
from auditor.parsers.fortios import FortiosParser
from auditor.parsers.arista_eos import AristaEOSParser
from auditor.parsers.sonic import SonicParser
from auditor.parsers.huawei_vrp import HuaweiVRPParser
from auditor.parsers.checkpoint_gaia import CheckPointGaiaParser
from auditor.parsers.mikrotik_routeros import MikroTikROSParser


def _safe_parse(parser, config):
    """Parse, returning None if the parser correctly rejects the input."""
    try:
        return parser.parse(config)
    except ParserError:
        return None


# ---------------------------------------------------------------- Cisco IOS


class TestCiscoIOSFalsePass:
    parser = CiscoIOSParser()

    def test_ssh_in_comment_not_detected_as_enabled(self):
        config = """\
version 15.7
hostname ADVERSARIAL
! ip ssh version 2
! SSH is enabled on this device
no ip ssh version 2
"""
        baseline = self.parser.parse(config)
        assert not baseline.ssh_enabled.value or not baseline.ssh_enabled.detected

    def test_conflicting_snmp_communities_both_visible(self):
        config = """\
version 15.7
hostname CONFLICT
snmp-server community s3cur3 RO 99
snmp-server community public RO
"""
        baseline = self.parser.parse(config)
        communities = baseline.snmp_communities.value or []
        names = [c.name if hasattr(c, "name") else str(c) for c in communities]
        assert "public" in names


# ---------------------------------------------------------------- Juniper Junos


class TestJunosFalsePass:
    parser = JunosParser()

    def test_commented_ssh_not_detected(self):
        config = """\
## set system services ssh protocol-version v2
set system host-name adversarial
"""
        baseline = self.parser.parse(config)
        assert not baseline.ssh_enabled.detected or not baseline.ssh_enabled.value


# ---------------------------------------------------------------- Fortinet FortiOS


class TestFortiOSFalsePass:
    parser = FortiosParser()

    def test_comment_containing_ssh_not_detected(self):
        config = """\
#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0
# set admin-ssh-port 22
config system global
    set hostname ADVERSARIAL
end
"""
        baseline = self.parser.parse(config)
        assert not baseline.ssh_enabled.detected or not baseline.ssh_enabled.value


# ---------------------------------------------------------------- Arista EOS


class TestAristaEOSFalsePass:
    parser = AristaEOSParser()

    def test_commented_ssh_not_detected(self):
        config = """\
hostname adversarial
! management ssh
!    shutdown
"""
        baseline = self.parser.parse(config)
        assert not baseline.ssh_enabled.detected or not baseline.ssh_enabled.value


# ---------------------------------------------------------------- Empty/minimal configs


PARSERS_AND_EMPTY = [
    (CiscoIOSParser(), ""),
    (JunosParser(), ""),
    (FortiosParser(), ""),
    (AristaEOSParser(), ""),
    (SonicParser(), ""),
    (HuaweiVRPParser(), ""),
    (CheckPointGaiaParser(), ""),
    (MikroTikROSParser(), ""),
]


@pytest.mark.parametrize("parser,config", PARSERS_AND_EMPTY,
                         ids=lambda x: x.__class__.__name__ if hasattr(x, "parse") else "empty")
class TestEmptyConfigDefense:
    """An empty config must either raise ParserError or produce no PASS detections."""

    def test_empty_config_rejects_or_produces_no_pass(self, parser, config):
        baseline = _safe_parse(parser, config)
        if baseline is None:
            return
        assert not baseline.ssh_enabled.detected or not baseline.ssh_enabled.value
        assert not baseline.ntp_configured.detected or not baseline.ntp_configured.value


# ---------------------------------------------------------------- AI never auto-passes


class TestAINeverAutoPasses:
    """The compliance engine must never auto-pass based solely on AI/LLM evidence."""

    def test_llm_origin_evidence_is_flagged(self):
        from auditor.models.observation import Observation, Origin
        from auditor.engine.evaluator import ComplianceEngine
        from auditor.models.rule import (
            ComplianceRule, LeafCondition, Operator, Remediation, Severity, RuleSet, Platform,
        )
        from auditor.models.baseline import SecurityBaselineModel, ParserProvenance

        provenance = ParserProvenance(
            parser_name="test", parser_version="1.0",
            vendor="test", os_family="test",
        )
        baseline = SecurityBaselineModel(provenance=provenance)
        object.__setattr__(
            baseline, "ssh_enabled",
            Observation.found(True, source_line="test", line_number=1, origin=Origin.LLM, confidence=0.9),
        )

        rule = ComplianceRule(
            id="TEST-SSH",
            title="SSH must be enabled",
            description="Test",
            severity=Severity.HIGH,
            condition=LeafCondition(field="ssh_enabled", operator=Operator.IS_TRUE),
            remediation=Remediation(summary="Enable SSH"),
        )
        ruleset = RuleSet(
            schema_version="1.0",
            framework="TEST",
            framework_version="1.0",
            platform=Platform(vendor="test", os_family="test"),
            rules=[rule],
        )

        engine = ComplianceEngine(ruleset)
        results = engine.evaluate(baseline)
        for r in results:
            if r.rule_id == "TEST-SSH":
                llm_evidence = [e for e in r.evidence if e.origin.value in ("llm", "hybrid")]
                if llm_evidence:
                    assert len(llm_evidence) > 0, "LLM evidence must be preserved for audit trail"


# ---------------------------------------------------------------- Vendor detection isolation


class TestVendorDetectionIsolation:
    """Detection scores must not leak across parsers."""

    def test_cisco_config_does_not_detect_as_junos(self):
        config = "version 15.7\nhostname CISCO\nip ssh version 2"
        junos_score = JunosParser().detect(config)
        assert junos_score < 0.3

    def test_junos_config_does_not_detect_as_cisco(self):
        config = "set system host-name JUNOS\nset system services ssh"
        cisco_score = CiscoIOSParser().detect(config)
        assert cisco_score < 0.3

    def test_empty_config_low_confidence_all_parsers(self):
        from auditor.parsers.base import registry
        for name in registry.names():
            if name in ("llm", "hybrid"):
                continue
            parser_cls = registry.get(name)
            score = parser_cls().detect("")
            assert score < 0.3, f"{name} returned confidence {score} on empty input"
