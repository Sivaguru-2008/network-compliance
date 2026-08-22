"""The engine must return the expected verdict for every control.

The two matrices below are the specification: they state what a correct audit
of each sample looks like, control by control.  They are written against rule
ids and expected statuses only, so they stay meaningful if the parser
internals change.
"""

import pytest

from auditor.engine import ComplianceEngine, Ternary, apply_operator, evaluate_condition
from auditor.engine.conditions import RuleEvaluationError
from auditor.models.observation import Observation
from auditor.models.result import Status
from auditor.models.rule import LeafCondition, Operator, RuleSet
from auditor.parsers import CiscoIOSParser

HARDENED_EXPECTATIONS = {
    "CIS-IOS-1.1.1": Status.PASS,            # aaa new-model
    "CIS-IOS-1.2.2": Status.PASS,            # transport input ssh
    "CIS-IOS-1.2.9": Status.PASS,            # exec-timeout 5 0
    "CIS-IOS-1.4.1-1.4.2": Status.PASS,      # enable secret + service password-encryption
    "CIS-IOS-1.5.2-1.5.3": Status.PASS,      # non-default SNMP community
    "CIS-IOS-2.1.1.6": Status.PASS,          # ip ssh version 2
    "CIS-IOS-2.1-HTTP-SERVER": Status.PASS,  # no ip http server
    "CIS-IOS-2.2.2-2.2.4": Status.PASS,      # logging buffered + logging host
}

INSECURE_EXPECTATIONS = {
    "CIS-IOS-1.1.1": Status.FAIL,                    # no aaa new-model
    "CIS-IOS-1.2.2": Status.FAIL,                    # transport input telnet / all
    "CIS-IOS-1.2.9": Status.FAIL,                    # exec-timeout 0 0
    "CIS-IOS-1.4.1-1.4.2": Status.FAIL,              # enable password, no encryption
    "CIS-IOS-1.5.2-1.5.3": Status.FAIL,              # public / private
    "CIS-IOS-2.1.1.6": Status.NEEDS_REVIEW,          # no ip ssh version line at all
    "CIS-IOS-2.1-HTTP-SERVER": Status.FAIL,          # ip http server
    "CIS-IOS-2.2.2-2.2.4": Status.FAIL,              # no logging destination
}


@pytest.mark.parametrize("rule_id, expected", sorted(HARDENED_EXPECTATIONS.items()))
def test_hardened_verdicts(hardened_results, rule_id, expected):
    assert hardened_results[rule_id].status is expected


@pytest.mark.parametrize("rule_id, expected", sorted(INSECURE_EXPECTATIONS.items()))
def test_insecure_verdicts(insecure_results, rule_id, expected):
    assert insecure_results[rule_id].status is expected


def test_every_rule_in_the_pack_is_evaluated(ruleset, hardened_results, insecure_results):
    expected_ids = {rule.id for rule in ruleset.rules}
    assert set(hardened_results) == expected_ids
    assert set(insecure_results) == expected_ids
    assert set(HARDENED_EXPECTATIONS) == expected_ids, "expectation matrix is out of date"
    assert set(INSECURE_EXPECTATIONS) == expected_ids, "expectation matrix is out of date"


def test_summary_counts_match_the_matrices(engine, hardened, insecure):
    hardened_report = engine.build_report(hardened, tool_name="t", tool_version="0")
    insecure_report = engine.build_report(insecure, tool_name="t", tool_version="0")

    assert (hardened_report.summary.passed, hardened_report.summary.failed) == (8, 0)
    assert hardened_report.summary.compliance_score == 100.0

    assert insecure_report.summary.failed == 7
    assert insecure_report.summary.needs_review == 1
    assert insecure_report.summary.passed == 0
    assert insecure_report.summary.failed_by_severity == {"medium": 4, "high": 3}


# ---------------------------------------------------------------------------
# every verdict must carry evidence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sample", ["hardened_results", "insecure_results"])
def test_every_result_carries_evidence(request, sample):
    for result in request.getfixturevalue(sample).values():
        assert result.evidence, f"{result.rule_id} produced no evidence"
        assert result.primary_evidence is not None
        assert result.primary_evidence.display


@pytest.mark.parametrize("sample", ["hardened_results", "insecure_results"])
def test_remediation_is_attached_to_findings_only(request, sample):
    for result in request.getfixturevalue(sample).values():
        if result.status is Status.PASS:
            assert result.remediation is None
        else:
            assert result.remediation is not None
            assert result.remediation.cli, f"{result.rule_id} has no remediation commands"


def test_needs_review_result_explains_the_missing_evidence(insecure_results):
    result = insecure_results["CIS-IOS-2.1.1.6"]
    assert result.status is Status.NEEDS_REVIEW
    assert "No conclusive evidence" in result.message
    assert result.primary_evidence.detected is False


# ---------------------------------------------------------------------------
# the verdict follows the config, not the filename
# ---------------------------------------------------------------------------


def test_verdicts_track_edits_to_the_config(engine, hardened_text):
    """Flip one line in the hardened config and only that control must change."""
    weakened = hardened_text.replace(" transport input ssh", " transport input telnet ssh")
    baseline = CiscoIOSParser().parse(weakened, source_file="weakened")
    results = {r.rule_id: r.status for r in engine.evaluate(baseline)}

    assert results["CIS-IOS-1.2.2"] is Status.FAIL
    unchanged = {k: v for k, v in results.items() if k != "CIS-IOS-1.2.2"}
    assert all(status is Status.PASS for status in unchanged.values())


def test_removing_evidence_yields_review_not_pass(engine, hardened_text):
    """Deleting the ssh version line must escalate, never quietly pass."""
    stripped = "\n".join(l for l in hardened_text.splitlines() if not l.startswith("ip ssh version"))
    baseline = CiscoIOSParser().parse(stripped, source_file="stripped")
    results = {r.rule_id: r.status for r in engine.evaluate(baseline)}
    assert results["CIS-IOS-2.1.1.6"] is Status.NEEDS_REVIEW


def test_fixing_the_insecure_config_turns_findings_into_passes(engine, insecure_text):
    remediated = (
        insecure_text.replace("ip http server", "no ip http server")
        .replace("no ip http secure-server\n", "")
        .replace("transport input telnet", "transport input ssh")
        .replace("transport input all", "transport input ssh")
        .replace("exec-timeout 0 0", "exec-timeout 10 0")
        .replace("enable password cisco123", "enable secret 9 $9$abcdefghijklmnop")
        .replace("snmp-server community public RO", "snmp-server community Uniq-C0mm RO 99")
        .replace("snmp-server community private RW", "snmp-server community An0ther-C0mm RO 99")
        .replace("hostname BRANCH-SW-07", "hostname BRANCH-SW-07\nservice password-encryption\naaa new-model")
        + "\nlogging host 10.0.0.5\nlogging buffered 64000\nip ssh version 2\n"
    )
    baseline = CiscoIOSParser().parse(remediated, source_file="remediated")
    results = {r.rule_id: r.status for r in engine.evaluate(baseline)}
    assert set(results.values()) == {Status.PASS}, results


# ---------------------------------------------------------------------------
# three-valued logic
# ---------------------------------------------------------------------------


class _Baseline:
    """Minimal stand-in exposing Observations by name, for logic tests."""

    def __init__(self, **fields):
        for name, observation in fields.items():
            setattr(self, name, observation)

    @staticmethod
    def observable_fields():
        return ["t", "f", "u"]


@pytest.fixture
def logic_baseline():
    return _Baseline(
        t=Observation[bool].found(True, "line-true", 1),
        f=Observation[bool].found(False, "line-false", 2),
        u=Observation[bool].unknown("nothing found"),
    )


def _leaf(field, operator=Operator.IS_TRUE):
    return LeafCondition(field=field, operator=operator)


@pytest.mark.parametrize(
    "fields, expected",
    [
        (["t", "t"], Ternary.TRUE),
        (["t", "u"], Ternary.UNKNOWN),
        (["t", "f"], Ternary.FALSE),
        (["u", "f"], Ternary.FALSE),   # a proven violation outranks an unknown
        (["u", "u"], Ternary.UNKNOWN),
    ],
)
def test_all_of_kleene_logic(logic_baseline, fields, expected):
    from auditor.models.rule import AllOfCondition

    condition = AllOfCondition(all_of=[_leaf(f) for f in fields])
    assert evaluate_condition(condition, logic_baseline).ternary is expected


@pytest.mark.parametrize(
    "fields, expected",
    [
        (["f", "f"], Ternary.FALSE),
        (["f", "u"], Ternary.UNKNOWN),
        (["f", "t"], Ternary.TRUE),    # one proven pass is enough
        (["u", "t"], Ternary.TRUE),
        (["u", "u"], Ternary.UNKNOWN),
    ],
)
def test_any_of_kleene_logic(logic_baseline, fields, expected):
    from auditor.models.rule import AnyOfCondition

    condition = AnyOfCondition(any_of=[_leaf(f) for f in fields])
    assert evaluate_condition(condition, logic_baseline).ternary is expected


@pytest.mark.parametrize(
    "field, expected",
    [("t", Ternary.FALSE), ("f", Ternary.TRUE), ("u", Ternary.UNKNOWN)],
)
def test_not_preserves_unknown(logic_baseline, field, expected):
    from auditor.models.rule import NotCondition

    condition = NotCondition.model_validate({"not": {"field": field, "operator": "is_true"}})
    assert evaluate_condition(condition, logic_baseline).ternary is expected


def test_undetected_field_never_evaluates_to_pass(logic_baseline):
    """The core design decision, asserted directly."""
    for operator in (Operator.IS_TRUE, Operator.IS_FALSE):
        outcome = evaluate_condition(_leaf("u", operator), logic_baseline)
        assert outcome.ternary is Ternary.UNKNOWN


def test_unknown_field_reference_is_an_error(logic_baseline):
    with pytest.raises(RuleEvaluationError, match="no field"):
        evaluate_condition(_leaf("does_not_exist"), logic_baseline)


# ---------------------------------------------------------------------------
# operators
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "operator, actual, expected_operand, result",
    [
        (Operator.EQUALS, 2, 2, True),
        (Operator.NOT_EQUALS, 1, 2, True),
        (Operator.GREATER_THAN, 300, 0, True),
        (Operator.GREATER_THAN, 0, 0, False),
        (Operator.LESS_OR_EQUAL, 600, 600, True),
        (Operator.LESS_OR_EQUAL, 601, 600, False),
        (Operator.SUBSET_OF, ["ssh"], ["ssh"], True),
        (Operator.SUBSET_OF, ["ssh", "telnet"], ["ssh"], False),
        (Operator.CONTAINS_NONE, ["corp1"], ["public", "private"], True),
        (Operator.CONTAINS_NONE, ["public"], ["public", "private"], False),
        (Operator.CONTAINS_ANY, ["a", "b"], ["b"], True),
        (Operator.IN_SET, "ro", ["ro", "rw"], True),
        (Operator.NOT_IN_SET, "rx", ["ro", "rw"], True),
        (Operator.MATCHES_REGEX, "version 2", r"^version \d$", True),
    ],
)
def test_operator_truth_table(operator, actual, expected_operand, result):
    assert apply_operator(operator, actual, expected_operand) is result


@pytest.mark.parametrize("operator", [Operator.IS_EMPTY, Operator.IS_NOT_EMPTY])
def test_empty_operators_treat_none_as_empty(operator):
    assert apply_operator(operator, None, None) is (operator is Operator.IS_EMPTY)


def test_case_insensitive_comparison_catches_capitalised_defaults():
    assert apply_operator(Operator.CONTAINS_NONE, ["Public"], ["public"], ignore_case=True) is False
    assert apply_operator(Operator.CONTAINS_NONE, ["Public"], ["public"], ignore_case=False) is True


def test_numeric_operator_rejects_a_non_numeric_value():
    with pytest.raises(RuleEvaluationError, match="numeric"):
        apply_operator(Operator.GREATER_THAN, "ten", 0)


def test_missing_operand_is_a_rule_authoring_error():
    with pytest.raises(RuleEvaluationError, match="requires a 'value' operand"):
        apply_operator(Operator.EQUALS, 2, None)


# ---------------------------------------------------------------------------
# engine guards
# ---------------------------------------------------------------------------


def test_engine_rejects_a_rule_referencing_an_unknown_baseline_field():
    payload = {
        "schema_version": "1.0",
        "framework": "TEST",
        "framework_version": "0",
        "platform": {"vendor": "cisco", "os_family": "ios"},
        "rules": [
            {
                "id": "T-1",
                "title": "typo",
                "description": "references a field that does not exist",
                "severity": "low",
                "condition": {"field": "telnet_enabld", "operator": "is_false"},
                "remediation": {"summary": "n/a", "cli": []},
            }
        ],
    }
    ruleset = RuleSet.model_validate(payload)
    with pytest.raises(RuleEvaluationError, match="telnet_enabld"):
        ComplianceEngine(ruleset)


def test_results_are_ordered_worst_first(insecure_results, engine, insecure):
    statuses = [r.status for r in engine.evaluate(insecure)]
    order = [Status.FAIL, Status.NEEDS_REVIEW, Status.PASS]
    positions = [order.index(s) for s in statuses]
    assert positions == sorted(positions)


def test_passing_control_never_cites_missing_evidence(engine):
    """A PASS row must point at a field that was actually established.

    Rules with an `any_of` can pass while one operand stays undetected; the
    report must cite the operand that carried it, not the one that was silent.
    """
    from auditor.parsers import CiscoIOSParser

    config = (
        "hostname PARTIAL-LOG\n"
        "service password-encryption\n"
        "aaa new-model\n"
        "enable secret 9 $9$abcdefghijklmnop\n"
        "ip ssh version 2\n"
        "no ip http server\n"
        "logging host 10.0.0.5\n"  # a destination exists, but nothing is buffered
        "snmp-server community Uniq-C0mm RO\n"
        "line vty 0 15\n"
        " exec-timeout 10 0\n"
        " transport input ssh\n"
        "end\n"
    )
    baseline = CiscoIOSParser().parse(config)
    baseline.logging_buffered = baseline.logging_buffered.model_copy(
        update={"detected": False, "value": None, "note": "simulated missing evidence"}
    )

    result = next(r for r in engine.evaluate(baseline) if r.rule_id == "CIS-IOS-2.2.2-2.2.4")
    assert result.status is Status.PASS
    assert result.primary_evidence.detected is True
    assert result.primary_evidence.source_line == "logging host 10.0.0.5"


def test_failing_control_still_cites_the_field_that_fell_short(insecure_results):
    result = insecure_results["CIS-IOS-1.4.1-1.4.2"]
    assert result.status is Status.FAIL
    assert result.primary_evidence.field == "enable_secret_set"
