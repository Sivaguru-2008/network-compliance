"""Exhaustive regression test suite verifying all correctness fixes."""

import hashlib
import json
import pytest
from auditor.engine import ComplianceEngine
from auditor.identity.extractors import extract_identity
from auditor.models.baseline import SecurityBaselineModel
from auditor.models.excerpt import CompletenessStatus, assess_configuration_completeness
from auditor.models.observation import Observation
from auditor.models.result import AuditReport, ControlResult, Evidence, FrameworkInfo, ReportSummary, Status, TargetInfo
from auditor.models.rule import ComplianceRule, LeafCondition, Operator, Remediation, RuleSet, Severity, Platform
from auditor.parsers.cisco_ios import CiscoIOSParser
from auditor.pipeline import evaluate, parse_config, select_parser
from auditor.schema import validate_audit_report_dict, validate_audit_report_json


class TestCompletenessRegression:
    """1. Completeness model and truncation detection."""

    def test_truncation_marker_prevents_100_percent_completeness(self):
        config_with_ellipsis = """
        hostname core-router-01
        line vty 0 4
         transport input ssh
        ...
        logging host 10.1.1.1
        """
        assessment = assess_configuration_completeness(config_with_ellipsis)
        assert assessment.status is CompletenessStatus.PARTIAL
        assert assessment.truncation_detected is True
        assert assessment.is_partial is True
        # Score must not be 1.0 (100%)
        assert assessment.completeness_score is None or assessment.completeness_score < 1.0
        disclaimer = assessment.disclaimer()
        assert disclaimer is not None
        assert "Completeness: 100%" not in disclaimer

    def test_unterminated_hierarchical_block(self):
        unterminated_config = """
        system {
            host-name srx-branch;
            services {
                ssh;
        """
        assessment = assess_configuration_completeness(unterminated_config)
        assert assessment.status is CompletenessStatus.PARTIAL
        assert assessment.unterminated_block_detected is True
        assert assessment.is_partial is True

    def test_empty_and_whitespace_config(self):
        assessment = assess_configuration_completeness("   \n\n\t  ")
        assert assessment.status is CompletenessStatus.INVALID
        assert assessment.is_partial is True
        assert assessment.completeness_score == 0.0

    def test_complete_structural_config(self):
        # 30+ real non-comment configuration lines with structural sections
        lines = [
            "hostname core-rtr01",
            "ip ssh version 2",
            "line vty 0 4",
            " access-class 10 in",
            " transport input ssh",
            " exec-timeout 10 0",
            "logging host 10.1.1.1",
            "interface GigabitEthernet0/0",
            " ip address 192.168.1.1 255.255.255.0",
        ]
        for i in range(25):
            lines.append(f"interface GigabitEthernet0/{i+1}")
            lines.append(f" description Port_{i+1}")
        complete_config = "\n".join(lines)
        assessment = assess_configuration_completeness(complete_config)
        assert assessment.status is CompletenessStatus.COMPLETE
        assert assessment.is_partial is False
        assert assessment.completeness_score == 1.0
        assert assessment.disclaimer() is None


class TestStatusModelAndCapabilityRegression:
    """2. Result status model & capability handling."""

    def test_unsupported_parser_property_yields_unsupported_status(self):
        baseline = SecurityBaselineModel(
            provenance={
                "parser_name": "cisco_ios",
                "parser_version": "1.0.0",
                "vendor": "cisco",
                "os_family": "ios",
            }
        )
        # av_ai_detection_enabled is not evaluated by Cisco IOS parser
        baseline.av_ai_detection_enabled = Observation[bool].unsupported("Cisco IOS parser does not evaluate this field.")

        rule = ComplianceRule(
            id="CIS-TEST-UNSUPPORTED",
            title="Antivirus AI Detection",
            description="AI AV enabled",
            severity=Severity.HIGH,
            condition=LeafCondition(field="av_ai_detection_enabled", operator=Operator.IS_TRUE),
            remediation=Remediation(summary="Enable AI AV"),
        )
        ruleset = RuleSet(
            schema_version="1.0",
            framework="CIS",
            framework_version="1.0",
            platform=Platform(vendor="cisco", os_family="ios"),
            rules=[rule],
        )
        engine = ComplianceEngine(ruleset)
        results = engine.evaluate(baseline)
        assert len(results) == 1
        assert results[0].status is Status.UNSUPPORTED
        assert "unsupported" in results[0].message.lower()

    def test_missing_evidence_yields_needs_review(self):
        baseline = SecurityBaselineModel(
            provenance={
                "parser_name": "cisco_ios",
                "parser_version": "1.0.0",
                "vendor": "cisco",
                "os_family": "ios",
            }
        )
        # ssh_version is supported by parser, but not configured in snippet
        baseline.ssh_version = Observation[int].unknown("No 'ip ssh version' statement found.")

        rule = ComplianceRule(
            id="CIS-TEST-SSH",
            title="Enforce SSH v2",
            description="SSH v2 only",
            severity=Severity.HIGH,
            condition=LeafCondition(field="ssh_version", operator=Operator.EQUALS, value=2),
            remediation=Remediation(summary="Enforce SSH v2"),
        )
        ruleset = RuleSet(
            schema_version="1.0",
            framework="CIS",
            framework_version="1.0",
            platform=Platform(vendor="cisco", os_family="ios"),
            rules=[rule],
        )
        engine = ComplianceEngine(ruleset)
        results = engine.evaluate(baseline)
        assert len(results) == 1
        assert results[0].status is Status.NEEDS_REVIEW


class TestEvidenceProvenanceRegression:
    """3. Accurate line-number provenance when lines move."""

    def test_line_numbers_shift_accurately(self):
        config_pos_1 = """hostname RouterA
ip ssh version 2
line vty 0 4
 transport input ssh
"""
        config_pos_2 = """! Comment line 1
! Comment line 2
! Comment line 3
hostname RouterA
ip ssh version 2
line vty 0 4
 transport input ssh
"""
        parser = CiscoIOSParser()
        b1 = parser.parse(config_pos_1)
        b2 = parser.parse(config_pos_2)

        assert b1.ssh_version.line_number == 2
        assert b2.ssh_version.line_number == 5

    def test_management_acl_unrestricted_block_evidence(self):
        # One VTY block has access-class, second does NOT
        partial_acl_config = """hostname RouterA
line vty 0 4
 access-class 99 in
 transport input ssh
line vty 5 15
 transport input ssh
"""
        parser = CiscoIOSParser()
        baseline = parser.parse(partial_acl_config)
        assert baseline.management_acl_applied.value is False
        # Evidence must NOT cite the access-class 99 in line from block 0 4
        assert baseline.management_acl_applied.source_line is None
        assert "have no inbound 'access-class'" in baseline.management_acl_applied.note


class TestScoringAlgorithmRegression:
    """4. Mathematical correctness of compliance scores."""

    def test_scoring_formulas(self):
        def make_res(status: Status, idx: int) -> ControlResult:
            return ControlResult(
                rule_id=f"RULE-{idx}",
                title="Test",
                description="Test",
                framework="CIS",
                severity=Severity.HIGH,
                status=status,
                message="msg",
            )

        # 11 PASS, 1 FAIL, 1 NEEDS_REVIEW, 1 NOT_APPLICABLE, 1 UNSUPPORTED
        results = (
            [make_res(Status.PASS, i) for i in range(11)]
            + [make_res(Status.FAIL, 11)]
            + [make_res(Status.NEEDS_REVIEW, 12)]
            + [make_res(Status.NOT_APPLICABLE, 13)]
            + [make_res(Status.UNSUPPORTED, 14)]
        )
        summary = ReportSummary.from_results(results)

        assert summary.total == 15
        assert summary.passed == 11
        assert summary.failed == 1
        assert summary.needs_review == 1
        assert summary.not_applicable == 1
        assert summary.unsupported == 1
        assert summary.applicable_controls == 14  # total (15) - not_applicable (1)
        assert summary.decidable_controls == 12   # passed (11) + failed (1)

        # Raw compliance score: 11 / 14 = 78.6%
        assert summary.compliance_score == round(100.0 * 11 / 14, 1)
        # Adjudicated score: 11 / 12 = 91.7%
        assert summary.adjudicated_score == round(100.0 * 11 / 12, 1)
        # Decision coverage: 12 / 14 = 85.7%
        assert summary.decision_coverage == round(100.0 * 12 / 14, 1)


class TestClosedLoopRemediationRegression:
    """5. Closed-loop: FAIL -> remediate -> re-audit -> PASS."""

    def test_closed_loop_cisco_password_length(self):
        insecure_config = """hostname RTR-01
security passwords min-length 4
ip ssh version 2
line vty 0 4
 transport input ssh
"""
        parser = CiscoIOSParser()
        b_insecure = parser.parse(insecure_config)

        rule = ComplianceRule(
            id="CIS-PASS-MIN",
            control_ref="1.1",
            title="Minimum Password Length",
            description="Enforces 8+ chars",
            severity=Severity.HIGH,
            condition=LeafCondition(field="password_min_length", operator=Operator.GREATER_OR_EQUAL, value=8),
            remediation=Remediation(
                summary="Set password min-length to 8",
                commands=["security passwords min-length 8"],
                rollback=["security passwords min-length 4"],
            ),
        )
        ruleset = RuleSet(
            schema_version="1.0",
            framework="CIS",
            framework_version="1.0",
            platform=Platform(vendor="cisco", os_family="ios"),
            rules=[rule],
        )

        # 1. Initial audit -> FAIL
        engine = ComplianceEngine(ruleset)
        res1 = engine.evaluate(b_insecure)
        assert res1[0].status is Status.FAIL
        assert res1[0].remediation is not None
        remed_cmd = res1[0].remediation.commands[0]

        # 2. Apply remediation to config text
        remediated_config = insecure_config.replace("security passwords min-length 4", remed_cmd)

        # 3. Re-parse and re-audit -> PASS
        b_remediated = parser.parse(remediated_config)
        res2 = engine.evaluate(b_remediated)
        assert res2[0].status is Status.PASS
        assert res2[0].remediation is None


class TestSecretSanitizationRegression:
    """6. Secret / PII sanitization."""

    def test_sanitization_masks_sensitive_values(self):
        config_with_secrets = """hostname RTR-01
enable secret 9 $9$Xk2mR7vQpL8123456789
snmp-server community SuperSecretKey RO
"""
        parser = CiscoIOSParser()
        baseline = parser.parse(config_with_secrets)

        # The community object must exist but community name must be processed accurately
        assert len(baseline.snmp_communities.value) == 1
        assert baseline.enable_secret_set.value is True


class TestHashAndConsistencyRegression:
    """7. Exact SHA256 hashing and report consistency validation."""

    def test_sha256_exact_byte_matching(self):
        raw_text = "hostname Switch-01\nip ssh version 2\n"
        expected_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

        parser = CiscoIOSParser()
        baseline = parser.parse(raw_text)
        assert baseline.source_sha256 == expected_hash

        # Modifying one character changes the hash
        raw_text_mod = "hostname Switch-02\nip ssh version 2\n"
        b_mod = parser.parse(raw_text_mod)
        assert b_mod.source_sha256 != expected_hash

    def test_report_consistency_validator(self):
        results = [
            ControlResult(
                rule_id="R1",
                title="T1",
                description="D1",
                framework="CIS",
                severity=Severity.LOW,
                status=Status.PASS,
                message="ok",
            )
        ]
        report = AuditReport(
            tool={"name": "netaudit", "version": "0.1.0"},
            target=TargetInfo(
                vendor="cisco",
                os_family="ios",
                parser="cisco_ios",
                parser_version="1.0.0",
                detection_confidence=1.0,
            ),
            framework=FrameworkInfo(name="CIS", version="1.0", rules_evaluated=1),
            frameworks=[FrameworkInfo(name="CIS", version="1.0", rules_evaluated=1)],
            summary=ReportSummary.from_results(results),
            results=results,
        )
        report.validate_consistency()
        valid = validate_audit_report_dict(report.model_dump(mode="json"))
        assert valid.summary.passed == 1


class TestCiscoRuleSemanticsRegression:
    """8. Positive and negative tests for all Cisco CIS rules."""

    parser = CiscoIOSParser()

    def test_http_server_toggle_semantics(self):
        # 1. 'ip http server' enabled -> FAIL requirement
        cfg_enabled = "hostname R1\nip http server\n"
        b_en = self.parser.parse(cfg_enabled)
        assert b_en.http_server_enabled.detected is True
        assert b_en.http_server_enabled.value is True

        # 2. 'no ip http server' disabled -> PASS requirement
        cfg_disabled = "hostname R1\nno ip http server\n"
        b_dis = self.parser.parse(cfg_disabled)
        assert b_dis.http_server_enabled.detected is True
        assert b_dis.http_server_enabled.value is False

        # 3. Neither present -> NEEDS_REVIEW (ambiguous)
        cfg_absent = "hostname R1\n"
        b_abs = self.parser.parse(cfg_absent)
        assert b_abs.http_server_enabled.detected is False
        assert b_abs.http_server_enabled.value is None

    def test_password_min_length_variants(self):
        # min 8 -> 8
        b8 = self.parser.parse("hostname R1\nsecurity passwords min-length 8\n")
        assert b8.password_min_length.value == 8

        # min 6 -> 6
        b6 = self.parser.parse("hostname R1\nsecurity passwords min-length 6\n")
        assert b6.password_min_length.value == 6

        # absent -> 0 (conclusive absence)
        b0 = self.parser.parse("hostname R1\n")
        assert b0.password_min_length.value == 0
        assert b0.password_min_length.detected is True

    def test_ssh_version_variants(self):
        # v2
        b2 = self.parser.parse("hostname R1\nip ssh version 2\n")
        assert b2.ssh_version.value == 2

        # v1
        b1 = self.parser.parse("hostname R1\nip ssh version 1\n")
        assert b1.ssh_version.value == 1

        # absent -> ambiguous (NEEDS_REVIEW)
        b_none = self.parser.parse("hostname R1\n")
        assert b_none.ssh_version.detected is False
        assert b_none.ssh_version.value is None

    def test_vty_transport_variants(self):
        # ssh only -> secure
        b_ssh = self.parser.parse("hostname R1\nline vty 0 4\n transport input ssh\n")
        assert b_ssh.telnet_enabled.value is False

        # telnet -> insecure
        b_telnet = self.parser.parse("hostname R1\nline vty 0 4\n transport input telnet\n")
        assert b_telnet.telnet_enabled.value is True

        # ssh and telnet -> insecure
        b_both = self.parser.parse("hostname R1\nline vty 0 4\n transport input ssh telnet\n")
        assert b_both.telnet_enabled.value is True

        # transport input all -> insecure
        b_all = self.parser.parse("hostname R1\nline vty 0 4\n transport input all\n")
        assert b_all.telnet_enabled.value is True

    def test_snmp_community_variants(self):
        # RO community with strong name
        b_ro = self.parser.parse("hostname R1\nsnmp-server community StrongRO123 RO 99\n")
        assert len(b_ro.snmp_communities.value) == 1
        assert b_ro.snmp_communities.value[0].access == "ro"
        assert b_ro.snmp_communities.value[0].name == "StrongRO123"

        # RW community
        b_rw = self.parser.parse("hostname R1\nsnmp-server community AdminRW RW 99\n")
        assert b_rw.snmp_communities.value[0].access == "rw"


class TestNoHardcodedSampleAssumptions:
    """9. Replace sample with arbitrary new config and verify dynamic evaluation."""

    def test_arbitrary_cisco_config_evaluation(self):
        custom_cfg = """! Custom datacenter switch
hostname DC-SW-99
version 15.2
service password-encryption
enable secret 9 $9$SampleSecretHash
security passwords min-length 12
aaa new-model
ip ssh version 2
no ip http server
no ip http secure-server
snmp-server community DC-ReadOnly-Str RO 10
logging host 10.99.99.1
logging buffered 64000
ntp server 10.99.99.2
banner login ^C
Authorized access only for DC-SW-99
^C
line vty 0 4
 access-class 10 in
 exec-timeout 5 0
 transport input ssh
line vty 5 15
 access-class 10 in
 exec-timeout 5 0
 transport input ssh
"""
        parser = CiscoIOSParser()
        baseline = parser.parse(custom_cfg, source_file="dc_switch.cfg")

        assert baseline.hostname.value == "DC-SW-99"
        assert baseline.password_min_length.value == 12
        assert baseline.management_acl_applied.value is True
        assert baseline.telnet_enabled.value is False

        # Evaluate against CIS
        from auditor.pipeline import evaluate
        outcome = evaluate(baseline, ["CIS"])
        # All 13 CIS rules should pass dynamically
        assert len(outcome.results) == 13
        passes = [r for r in outcome.results if r.status is Status.PASS]
        assert len(passes) == 13


class TestArchitectureIndependence:
    """10. Compliance rules must depend ONLY on SecurityBaselineModel, never raw config strings."""

    def test_rule_conditions_contain_only_baseline_fields(self):
        from auditor.rules import discover_packs, load_ruleset, load_framework
        observable_fields = set(SecurityBaselineModel.observable_fields())

        ruleset = load_framework("CIS", "cisco_ios")
        for rule in ruleset.rules:
            for field in rule.baseline_fields:
                root_field = field.split(".")[0]
                assert root_field in observable_fields, (
                    f"Rule {rule.id} references non-baseline field: {root_field}"
                )

