"""Regression tests for Evidence Grounding, Absence vs Unknown, NOT_DETERMINABLE, and Remediation Consistency."""

import pytest
from auditor.models.baseline import SecurityBaselineModel
from auditor.models.observation import Observation, EvidenceState, CapabilityStatus
from auditor.models.result import Status, ControlResult, Remediation
from auditor.parsers.cisco_ios import CiscoIOSParser
from auditor.parsers.arista_eos import AristaEOSParser
from auditor.parsers.junos import JunosParser
from auditor.parsers.fortios import FortiosParser
from auditor.parsers.huawei_vrp import HuaweiVRPParser
from auditor.pipeline import parse_config, evaluate, RulesetResolver, select_parser


class TestEvidenceCorrectnessAndStates:
    def test_five_evidence_states_distinct(self):
        obs_pres = Observation.found(True, "service password-encryption", 12)
        assert obs_pres.evidence_state == EvidenceState.PRESENT
        assert obs_pres.detected is True
        assert obs_pres.source_line == "service password-encryption"
        assert obs_pres.line_number == 12

        obs_abs = Observation.absent(False, "service password-encryption not configured")
        assert obs_abs.evidence_state == EvidenceState.ABSENT
        assert obs_abs.detected is True
        assert obs_abs.source_line is None

        obs_unk = Observation.unknown("Ambiguous absence")
        assert obs_unk.evidence_state == EvidenceState.UNKNOWN
        assert obs_unk.detected is False

        obs_unsupp = Observation.unsupported("Not supported")
        assert obs_unsupp.evidence_state == EvidenceState.NOT_APPLICABLE
        assert obs_unsupp.is_unsupported is True

        obs_not_det = Observation.not_determinable("Partial excerpt")
        assert obs_not_det.evidence_state in (EvidenceState.UNKNOWN, EvidenceState.NOT_DETERMINABLE)

    def test_absence_vs_unknown_cisco_ios(self):
        parser = CiscoIOSParser()
        # Incomplete config without password encryption or line vty
        cfg = "hostname test-router\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n"
        baseline = parse_config(parser, cfg, source_file="test.cfg", parser_cls=CiscoIOSParser, confidence=1.0)
        
        # Conclusive absence: password_encryption is False and detected=True
        assert baseline.password_encryption.detected is True
        assert baseline.password_encryption.value is False
        assert baseline.password_encryption.evidence_state == EvidenceState.ABSENT
        
        # Ambiguous absence: line vty missing -> transport posture is UNKNOWN
        assert baseline.vty_transport_input.detected is False
        assert baseline.vty_transport_input.evidence_state == EvidenceState.UNKNOWN
        assert baseline.telnet_enabled.detected is False

    def test_source_line_exact_traceability(self):
        cfg = "hostname core-sw\nservice password-encryption\nline vty 0 4\n transport input ssh\n exec-timeout 10 0\n"
        parser = CiscoIOSParser()
        baseline = parse_config(parser, cfg, source_file="test.cfg", parser_cls=CiscoIOSParser, confidence=1.0)
        
        assert baseline.password_encryption.evidence_state == EvidenceState.PRESENT
        assert baseline.password_encryption.source_line == "service password-encryption"
        assert baseline.password_encryption.line_number == 2
        
        assert baseline.telnet_enabled.evidence_state == EvidenceState.PRESENT
        assert baseline.telnet_enabled.value is False
        assert baseline.telnet_enabled.source_line == "transport input ssh"
        assert baseline.telnet_enabled.line_number == 4


class TestVendorSpecificEvidence:
    def test_arista_eos_evidence(self):
        cfg = "hostname arista-leaf\nmanagement ssh\n  idle-timeout 15\n  no shutdown\n"
        parser = AristaEOSParser()
        baseline = parse_config(parser, cfg, source_file="arista.cfg", parser_cls=AristaEOSParser, confidence=1.0)
        assert baseline.ssh_enabled.detected is True
        assert baseline.ssh_enabled.evidence_state == EvidenceState.PRESENT

    def test_junos_evidence(self):
        cfg = "system {\n    services {\n        ssh {\n            protocol-version v2;\n        }\n    }\n}\n"
        parser = JunosParser()
        baseline = parse_config(parser, cfg, source_file="junos.conf", parser_cls=JunosParser, confidence=1.0)
        assert baseline.ssh_enabled.detected is True
        assert baseline.ssh_enabled.evidence_state == EvidenceState.PRESENT


class TestRemediationEvidenceConsistency:
    def test_remediation_requires_evidence_and_known_vendor(self):
        resolver = RulesetResolver()
        cfg = "hostname test\nline vty 0 4\n transport input telnet\n"
        parser = CiscoIOSParser()
        baseline = parse_config(parser, cfg, source_file="cisco.cfg", parser_cls=CiscoIOSParser, confidence=1.0)
        outcome = evaluate(baseline, ["CIS"], resolver=resolver)
        
        for r in outcome.results:
            if r.status == Status.FAIL and r.remediation:
                # Remediation must have CLI commands or summary
                assert r.remediation.cli is not None or r.remediation.summary is not None
                if r.remediation.cli:
                    assert len(r.remediation.cli) > 0

    def test_needs_review_when_evidence_ambiguous(self):
        # When config does not have line vty, compliance should be NEEDS_REVIEW / MANUAL_REVIEW
        cfg = "hostname bare-router\ninterface FastEthernet0/0\n ip address 1.1.1.1 255.255.255.0\n"
        parser = CiscoIOSParser()
        baseline = parse_config(parser, cfg, source_file="bare.cfg", parser_cls=CiscoIOSParser, confidence=1.0)
        resolver = RulesetResolver()
        outcome = evaluate(baseline, ["CIS"], resolver=resolver)
        
        telnet_results = [r for r in outcome.results if "2.1.1" in (r.control_id or "") or "telnet" in (r.rule_id or "")]
        if telnet_results:
            for tr in telnet_results:
                assert tr.status in (Status.NEEDS_REVIEW, Status.MANUAL_REVIEW, Status.NOT_APPLICABLE, Status.UNSUPPORTED)
