"""Tests for the CIS FortiGate extraction, classification, and evaluation pipeline."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from auditor.cis.schema import (
    AssessmentStatus,
    CISBenchmark,
    CISRecommendation,
    EvaluationType,
    Profile,
    SourceProvenance,
)
from auditor.cis.fortigate_map import FORTIGATE_RULE_MAP, get_coverage_summary
from auditor.models.result import Status


CIS_JSON = Path(__file__).parents[1] / "cis" / "benchmarks" / "CIS_Fortigate_7.0.x_rules.json"
SAMPLE_CONFIG = Path(__file__).parents[1] / "samples" / "fortios_fgt.conf"


# ── Extraction tests ────────────────────────────────────────────────────────


class TestCISExtraction:
    @pytest.fixture(scope="class")
    def benchmark(self) -> CISBenchmark:
        data = json.loads(CIS_JSON.read_text(encoding="utf-8"))
        return CISBenchmark(**data)

    def test_total_recommendations(self, benchmark):
        assert len(benchmark.recommendations) == 56

    def test_no_warnings(self, benchmark):
        assert benchmark.extraction_warnings == []

    def test_source_hash_present(self, benchmark):
        assert len(benchmark.source_hash) == 64
        assert benchmark.source_hash == "1692d30903ede16bd849aec848659520582b3d3154fd7e67de1794520b5f161b"

    def test_every_rec_has_description(self, benchmark):
        missing = [r.rule_id for r in benchmark.recommendations if not r.description]
        assert missing == [], f"Recommendations missing description: {missing}"

    def test_every_rec_has_audit(self, benchmark):
        missing = [r.rule_id for r in benchmark.recommendations if not r.audit]
        assert missing == [], f"Recommendations missing audit: {missing}"

    def test_every_rec_has_remediation(self, benchmark):
        missing = [r.rule_id for r in benchmark.recommendations if not r.remediation]
        assert missing == [], f"Recommendations missing remediation: {missing}"

    def test_provenance_page_numbers(self, benchmark):
        for rec in benchmark.recommendations:
            assert rec.source.page > 0, f"{rec.rule_id} has invalid page number"
            assert rec.source.file == "CIS_Fortigate_7.0.x_Benchmark_v1.4.0.pdf"

    def test_profiles_are_valid(self, benchmark):
        for rec in benchmark.recommendations:
            assert len(rec.profile) > 0, f"{rec.rule_id} has no profile"
            for p in rec.profile:
                assert p in (Profile.LEVEL_1, Profile.LEVEL_2)

    def test_assessment_statuses(self, benchmark):
        automated = [r for r in benchmark.recommendations if r.assessment_status == AssessmentStatus.AUTOMATED]
        manual = [r for r in benchmark.recommendations if r.assessment_status == AssessmentStatus.MANUAL]
        assert len(automated) + len(manual) == 56

    def test_sections_assigned(self, benchmark):
        for rec in benchmark.recommendations:
            assert rec.section, f"{rec.rule_id} has no section"


# ── Classification tests ────────────────────────────────────────────────────


class TestRuleClassification:
    def test_all_56_rules_mapped(self):
        assert len(FORTIGATE_RULE_MAP) == 56

    def test_coverage_summary(self):
        summary = get_coverage_summary()
        total = sum(len(v) for v in summary.values())
        assert total == 56

    def test_deterministic_rules_have_conditions(self):
        for cis_id, mapping in FORTIGATE_RULE_MAP.items():
            if mapping.evaluation_type == EvaluationType.DETERMINISTIC:
                assert mapping.condition_json, f"{cis_id} is DETERMINISTIC but has no condition"

    def test_no_silently_converted_unsupported(self):
        for cis_id, mapping in FORTIGATE_RULE_MAP.items():
            if mapping.evaluation_type == EvaluationType.PARSER_REQUIRED:
                assert mapping.condition_json is None, (
                    f"{cis_id} is PARSER_REQUIRED but has a condition — "
                    "this would silently evaluate to PASS/FAIL without parser support"
                )


# ── End-to-end pipeline tests ───────────────────────────────────────────────


class TestFortiGatePipeline:
    @pytest.fixture(scope="class")
    def report(self):
        from auditor.parsers.fortios import FortiosParser
        from auditor.pipeline import evaluate_cis_fortigate

        config_text = SAMPLE_CONFIG.read_text(encoding="utf-8")
        parser = FortiosParser()
        baseline = parser.parse(config_text, source_file=str(SAMPLE_CONFIG))
        return evaluate_cis_fortigate(baseline)

    def test_all_56_controls_present(self, report):
        assert report.summary.total == 56

    def test_no_silent_drops(self, report):
        rule_ids = {r.control_ref or r.rule_id for r in report.results}
        for cis_id in FORTIGATE_RULE_MAP:
            assert cis_id in rule_ids, f"CIS {cis_id} missing from report"

    def test_unsupported_not_converted_to_pass(self, report):
        unsupported = [r for r in report.results if r.status == Status.UNSUPPORTED]
        for r in unsupported:
            assert r.status != Status.PASS
            assert r.status != Status.NOT_APPLICABLE

    def test_sample_config_expected_fails(self, report):
        results_by_ref = {r.control_ref: r for r in report.results}
        assert results_by_ref["2.1.1"].status == Status.FAIL  # no banner
        assert results_by_ref["2.4.5"].status == Status.FAIL  # telnet + HTTP enabled
        assert results_by_ref["2.3.1"].status == Status.FAIL  # public SNMP community
        assert results_by_ref["2.4.7"].status == Status.FAIL  # admin-sport at default 443
        assert results_by_ref["2.5.1"].status == Status.FAIL  # HA not configured
        assert results_by_ref["2.5.2"].status == Status.FAIL  # HA monitor interfaces empty
        assert results_by_ref["4.2.1"].status == Status.FAIL  # AV push updates not configured
        assert results_by_ref["4.2.4"].status == Status.FAIL  # AI malware detection not configured
        assert results_by_ref["4.2.5"].status == Status.FAIL  # Grayware detection not configured
        assert results_by_ref["5.2.1.1"].status == Status.FAIL # CSF not configured
        assert results_by_ref["7.2.1"].status == Status.FAIL  # Log encryption not configured

    def test_sample_config_expected_passes(self, report):
        results_by_ref = {r.control_ref: r for r in report.results}
        assert results_by_ref["2.1.5"].status == Status.PASS  # hostname set
        assert results_by_ref["7.1.1"].status == Status.PASS  # logging enabled
        assert results_by_ref["7.3.1"].status == Status.PASS  # centralized logging

    def test_compliance_score_excludes_non_evaluable(self, report):
        evaluable = report.summary.passed + report.summary.failed + report.summary.needs_review
        assert evaluable == 27
        assert report.summary.unsupported == 5
        assert report.summary.manual_review == 24

    def test_evidence_present_on_evaluated(self, report):
        evaluated = [
            r for r in report.results
            if r.status in (Status.PASS, Status.FAIL, Status.NEEDS_REVIEW)
        ]
        for r in evaluated:
            assert len(r.evidence) > 0, f"{r.rule_id} has no evidence"


# ── Status enum tests ───────────────────────────────────────────────────────


class TestStatusEnum:
    def test_all_statuses_exist(self):
        assert hasattr(Status, "PASS")
        assert hasattr(Status, "FAIL")
        assert hasattr(Status, "NEEDS_REVIEW")
        assert hasattr(Status, "NOT_APPLICABLE")
        assert hasattr(Status, "UNSUPPORTED")
        assert hasattr(Status, "MANUAL_REVIEW")

    def test_unsupported_is_distinct(self):
        assert Status.UNSUPPORTED != Status.PASS
        assert Status.UNSUPPORTED != Status.NOT_APPLICABLE
        assert Status.UNSUPPORTED != Status.NEEDS_REVIEW
