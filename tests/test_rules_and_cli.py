"""The shipped rule pack must be well-formed, and the CLI must work end to end."""

import json

import pytest

from auditor import cli
from auditor.models.baseline import SecurityBaselineModel
from auditor.models.rule import ComplianceRule, RuleSet, Severity, referenced_fields
from auditor.rules import RuleLoadError, available_frameworks, discover_packs, load_ruleset

EXPECTED_CONTROL_IDS = {
    "CIS-IOS-1.1.1",
    "CIS-IOS-1.2.2",
    "CIS-IOS-1.2.9",
    "CIS-IOS-1.4.1-1.4.2",
    "CIS-IOS-1.5.2-1.5.3",
    "CIS-IOS-2.1.1.6",
    "CIS-IOS-2.1-HTTP-SERVER",
    "CIS-IOS-2.2.2-2.2.4",
    "CIS-IOS-1.2-VTY-ACCESS-CLASS",
    "CIS-IOS-1.6-LOGIN-BANNER",
    "CIS-IOS-1.1-PASSWORD-MIN-LENGTH",
    "CIS-IOS-2.3-NTP-CONFIGURED",
    "CIS-IOS-1.5-SNMP-NO-WRITE",
}


# ---------------------------------------------------------------------------
# rule pack
# ---------------------------------------------------------------------------


def test_cis_pack_is_discovered():
    assert "CIS" in available_frameworks()
    assert ("CIS", "cisco_ios") in discover_packs()


def test_pack_contains_the_expected_controls(ruleset: RuleSet):
    assert {rule.id for rule in ruleset.rules} == EXPECTED_CONTROL_IDS


def test_every_rule_is_complete(ruleset: RuleSet):
    for rule in ruleset.rules:
        assert rule.framework == "CIS"
        assert rule.title and rule.description and rule.rationale
        assert isinstance(rule.severity, Severity)
        assert rule.remediation.summary
        assert rule.remediation.cli, f"{rule.id} ships no remediation commands"
        assert rule.references, f"{rule.id} cites no source"


def test_declared_fields_match_the_condition(ruleset: RuleSet):
    for rule in ruleset.rules:
        assert set(rule.baseline_fields) == referenced_fields(rule.condition)


def test_every_referenced_field_exists_on_the_baseline(ruleset: RuleSet):
    known = set(SecurityBaselineModel.observable_fields())
    for rule in ruleset.rules:
        assert set(rule.baseline_fields) <= known, rule.id


def test_severities_match_the_agreed_risk_ranking(ruleset: RuleSet):
    expected = {
        "CIS-IOS-1.2.2": Severity.HIGH,
        "CIS-IOS-2.1.1.6": Severity.HIGH,
        "CIS-IOS-1.4.1-1.4.2": Severity.HIGH,
        "CIS-IOS-1.5.2-1.5.3": Severity.HIGH,
        "CIS-IOS-2.1-HTTP-SERVER": Severity.MEDIUM,
        "CIS-IOS-1.2.9": Severity.MEDIUM,
        "CIS-IOS-2.2.2-2.2.4": Severity.MEDIUM,
        "CIS-IOS-1.1.1": Severity.MEDIUM,
        "CIS-IOS-1.2-VTY-ACCESS-CLASS": Severity.HIGH,
        "CIS-IOS-1.5-SNMP-NO-WRITE": Severity.HIGH,
        "CIS-IOS-1.1-PASSWORD-MIN-LENGTH": Severity.MEDIUM,
        "CIS-IOS-2.3-NTP-CONFIGURED": Severity.MEDIUM,
        "CIS-IOS-1.6-LOGIN-BANNER": Severity.LOW,
    }
    assert {rule.id: rule.severity for rule in ruleset.rules} == expected


def test_declared_fields_inconsistent_with_condition_are_rejected():
    with pytest.raises(ValueError, match="do not match"):
        ComplianceRule.model_validate(
            {
                "id": "BAD-1",
                "title": "mismatch",
                "description": "declares one field but checks another",
                "severity": "low",
                "baseline_fields": ["aaa_enabled"],
                "condition": {"field": "telnet_enabled", "operator": "is_false"},
                "remediation": {"summary": "n/a", "cli": []},
            }
        )


def test_duplicate_rule_ids_are_rejected(ruleset: RuleSet):
    payload = ruleset.model_dump(mode="json")
    payload["rules"] = [payload["rules"][0], payload["rules"][0]]
    with pytest.raises(ValueError, match="Duplicate rule id"):
        RuleSet.model_validate(payload)


def test_missing_pack_reports_what_is_available(tmp_path):
    with pytest.raises(RuleLoadError, match="Rule pack not found"):
        load_ruleset(tmp_path / "nope.json")


def test_malformed_pack_is_rejected_with_a_readable_error(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"framework": "X"}', encoding="utf-8")
    with pytest.raises(RuleLoadError, match="does not satisfy the rule schema"):
        load_ruleset(bad)


def test_discovery_ignores_unrelated_json_files(tmp_path):
    (tmp_path / "notes.json").write_text('{"hello": "world"}', encoding="utf-8")
    assert discover_packs(tmp_path) == {}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_prints_a_table_and_writes_json(tmp_path, capsys):
    output = tmp_path / "report.json"
    exit_code = cli.run(
        ["samples/insecure_ios.conf", "--framework", "CIS", "--no-color", "--json", str(output)]
    )
    captured = capsys.readouterr().out

    assert exit_code == cli.EXIT_OK
    assert "NETWORK SECURITY COMPLIANCE AUDIT" in captured
    assert "BRANCH-SW-07" in captured
    assert "FAIL" in captured and "REVIEW" in captured
    assert output.is_file()

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["target"]["hostname"] == "BRANCH-SW-07"
    assert payload["framework"]["name"] == "CIS"
    assert payload["summary"]["failed"] == 12
    assert payload["summary"]["needs_review"] == 1
    assert len(payload["results"]) == 13
    assert payload["baseline"]["telnet_enabled"]["value"] is True


def test_json_report_carries_evidence_for_every_control(tmp_path):
    output = tmp_path / "r.json"
    cli.run(["samples/insecure_ios.conf", "--quiet", "--json", str(output)])
    payload = json.loads(output.read_text(encoding="utf-8"))
    for result in payload["results"]:
        assert result["evidence"], result["rule_id"]
        for item in result["evidence"]:
            assert item["source_line"] is not None or item["note"]


def test_strict_mode_signals_findings(tmp_path):
    code = cli.run(["samples/insecure_ios.conf", "--quiet", "--strict", "--json", str(tmp_path / "a.json")])
    assert code == cli.EXIT_FINDINGS


def test_strict_mode_passes_a_hardened_config(tmp_path):
    code = cli.run(["samples/hardened_ios.conf", "--quiet", "--strict", "--json", str(tmp_path / "b.json")])
    assert code == cli.EXIT_OK


def test_strict_mode_distinguishes_review_from_failure(tmp_path, hardened_text):
    """A config that only lacks evidence exits 3, not 1."""
    config = tmp_path / "no_ssh_version.conf"
    config.write_text(
        "\n".join(l for l in hardened_text.splitlines() if not l.startswith("ip ssh version")),
        encoding="utf-8",
    )
    code = cli.run([str(config), "--quiet", "--strict", "--json", str(tmp_path / "c.json")])
    assert code == cli.EXIT_REVIEW


def test_missing_file_is_a_clean_error(tmp_path, capsys):
    code = cli.run([str(tmp_path / "absent.conf"), "--no-json"])
    assert code == cli.EXIT_ERROR
    assert "not found" in capsys.readouterr().err


def test_unknown_framework_is_a_clean_error(capsys):
    code = cli.run(["samples/hardened_ios.conf", "--framework", "NIST", "--no-json", "--quiet"])
    assert code == cli.EXIT_ERROR
    assert "No rule pack for framework" in capsys.readouterr().err


def test_no_baseline_flag_omits_the_baseline(tmp_path):
    output = tmp_path / "slim.json"
    cli.run(["samples/hardened_ios.conf", "--quiet", "--no-baseline", "--json", str(output)])
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert "baseline" not in payload
    assert payload["results"]
