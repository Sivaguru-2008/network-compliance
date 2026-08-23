"""The feedback loop: measure, fit, feed back, refuse to regress.

Everything here runs against a stub client, like the parser tests — a loop run
is deterministic once the model's claims are fixed, and that is exactly the
property that lets it be tested at all.

The assertions worth reading are the ones about *direction*. Precision is a
floor that is never traded for coverage; a field that cannot reach the target
is pinned to always-escalate rather than allowed to answer badly; a human
ruling outranks the deterministic parser that would otherwise be ground truth;
and a run that raises dangerous verdict flips is a regression even if every
average improved.
"""

import json
from pathlib import Path

import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.models.observation import Observation, Origin
from auditor.models.result import Status
from auditor.parsers import CiscoIOSParser
from auditor.parsers.llm import LLMExtraction, LLMParser
from auditor.training import (
    ALWAYS_ESCALATE,
    Adjudication,
    AdjudicationStore,
    ConfigCorpus,
    ExampleSet,
    FieldComparison,
    FieldOutcome,
    RunSummary,
    ThresholdPolicy,
    TrainingLoop,
    WorkedExample,
    compare_baselines,
    fit_policy,
    load_examples,
    load_policy,
    pending_reviews,
    render_examples_block,
    select_examples,
    tuned_parser,
)
from auditor.training.loop import RegressionReport
from llm_stub import StubClient, found, make_extraction, undetermined

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


# ---------------------------------------------------------------------------
# a client that answers differently per config, so a run produces a real mix
# ---------------------------------------------------------------------------


class ScriptedClient(StubClient):
    """Returns the extraction scripted for whichever config it is shown."""

    def __init__(self, by_marker):
        super().__init__(make_extraction())
        self.by_marker = by_marker

    def extract(self, config_text: str) -> LLMExtraction:
        self.calls += 1
        self.seen_config = config_text
        for marker, extraction in self.by_marker.items():
            if marker in config_text:
                return extraction
        return make_extraction()


HARDENED_CLAIMS = make_extraction(
    vendor="cisco",
    os_family="ios",
    hostname=found("CORE-RTR-01", "hostname CORE-RTR-01", confidence=0.95),
    # Wrong, and stated confidently: the device only accepts ssh.
    telnet_enabled=found(True, "transport input ssh", confidence=0.9),
    http_server_enabled=found(False, "no ip http server", confidence=0.85),
    ssh_version=found(2, "ip ssh version 2", confidence=0.8),
)

INSECURE_CLAIMS = make_extraction(
    vendor="cisco",
    os_family="ios",
    hostname=found("BRANCH-SW-07", "hostname BRANCH-SW-07", confidence=0.95),
    telnet_enabled=found(True, "transport input telnet", confidence=0.9),
    http_server_enabled=found(True, "ip http server", confidence=0.75),
    # Over-claimed: the config never states an SSH version. The line is real,
    # so grounding passes and only ground truth can catch this.
    ssh_version=found(1, "version 12.4", confidence=0.7),
)


@pytest.fixture
def corpus_dir(tmp_path, hardened_text, insecure_text) -> Path:
    directory = tmp_path / "corpus"
    directory.mkdir()
    (directory / "hardened.conf").write_text(hardened_text, encoding="utf-8")
    (directory / "insecure.conf").write_text(insecure_text, encoding="utf-8")
    return directory


@pytest.fixture
def scripted_client() -> ScriptedClient:
    return ScriptedClient(
        {"Deliberately weak": INSECURE_CLAIMS, "Reasonably hardened": HARDENED_CLAIMS}
    )


@pytest.fixture
def loop(ruleset, tmp_path) -> TrainingLoop:
    return TrainingLoop(ruleset, tmp_path / "training", min_samples=1)


# ---------------------------------------------------------------------------
# corpus: ground truth is whatever a deterministic parser can read
# ---------------------------------------------------------------------------


def test_corpus_splits_labelled_from_unlabelled(corpus_dir):
    (corpus_dir / "unknown_vendor.conf").write_text(
        (SAMPLES / "unknown_vendor.conf").read_text(encoding="utf-8"), encoding="utf-8"
    )
    corpus = ConfigCorpus.from_paths([corpus_dir])

    assert len(corpus) == 3
    assert {entry.name for entry in corpus.labelled} == {"hardened.conf", "insecure.conf"}
    assert [entry.name for entry in corpus.unlabelled] == ["unknown_vendor.conf"]
    assert corpus.labelled[0].deterministic_parser() is CiscoIOSParser


def test_the_same_config_under_two_names_is_loaded_once(corpus_dir, hardened_text):
    (corpus_dir / "copy-of-hardened.conf").write_text(hardened_text, encoding="utf-8")
    corpus = ConfigCorpus.from_paths([corpus_dir])

    assert len(corpus) == 2, "duplicate content teaches nothing twice"


def test_corpus_ignores_empty_and_unreadable_entries(corpus_dir):
    (corpus_dir / "blank.conf").write_text("   \n\n", encoding="utf-8")
    (corpus_dir / "notes.md").write_text("not a config", encoding="utf-8")

    assert len(ConfigCorpus.from_paths([corpus_dir])) == 2


# ---------------------------------------------------------------------------
# comparison: what counts as an error
# ---------------------------------------------------------------------------


def make_comparison(field="telnet_enabled", *, truth, candidate) -> FieldComparison:
    return FieldComparison.build(field, truth, candidate)


def test_every_outcome_is_reachable():
    known = Observation.found(True, "transport input telnet")
    other = Observation.found(False, "transport input ssh", origin=Origin.LLM, confidence=0.8)
    unknown = Observation.unknown("nothing said")

    assert make_comparison(truth=known, candidate=known).outcome is FieldOutcome.CORRECT
    assert make_comparison(truth=known, candidate=other).outcome is FieldOutcome.WRONG
    assert make_comparison(truth=unknown, candidate=known).outcome is FieldOutcome.OVERREACH
    assert make_comparison(truth=known, candidate=unknown).outcome is FieldOutcome.MISSED
    assert make_comparison(truth=unknown, candidate=unknown).outcome is FieldOutcome.BOTH_UNKNOWN


def test_only_claims_count_toward_precision():
    assert FieldOutcome.CORRECT.is_claim and FieldOutcome.WRONG.is_claim
    assert FieldOutcome.OVERREACH.is_claim
    assert not FieldOutcome.MISSED.is_claim, "silence is not a wrong answer"
    assert not FieldOutcome.BOTH_UNKNOWN.is_claim
    assert FieldOutcome.WRONG.is_error and FieldOutcome.OVERREACH.is_error
    assert not FieldOutcome.MISSED.is_error


def test_list_values_compare_order_and_case_insensitively():
    truth = Observation.found(["ssh", "telnet"], "transport input ssh telnet")
    candidate = Observation.found(["TELNET", "SSH"], "transport input ssh telnet", origin=Origin.LLM)

    assert make_comparison("vty_transport_input", truth=truth, candidate=candidate).outcome is FieldOutcome.CORRECT


def test_comparing_baselines_from_different_configs_is_refused(hardened_text, insecure_text):
    hardened = CiscoIOSParser().parse(hardened_text, source_file="a.conf")
    insecure = CiscoIOSParser().parse(insecure_text, source_file="b.conf")

    with pytest.raises(ValueError, match="different configurations"):
        compare_baselines(hardened, insecure)


# ---------------------------------------------------------------------------
# calibration: precision is a floor, never traded for coverage
# ---------------------------------------------------------------------------


def claim(outcome: FieldOutcome, confidence: float, field="telnet_enabled") -> FieldComparison:
    return FieldComparison(
        field=field,
        outcome=outcome,
        truth_detected=True,
        candidate_detected=outcome.is_claim,
        candidate_confidence=confidence,
    )


def comparison_of(claims):
    from auditor.training.comparison import BaselineComparison

    return BaselineComparison(truth_parser="cisco_ios", candidate_parser="llm", fields=claims)


def test_the_lowest_threshold_meeting_the_target_is_chosen():
    """Wrong answers up to 0.7, correct ones from 0.8: the fit lands just above 0.7.

    Just above, not comfortably above. Every point of threshold costs coverage,
    so the fit takes the lowest grid step that clears the target rather than the
    safest-looking round number.
    """
    claims = [claim(FieldOutcome.WRONG, c) for c in (0.3, 0.5, 0.7)]
    claims += [claim(FieldOutcome.CORRECT, c) for c in (0.8, 0.85, 0.9, 0.95, 1.0)]

    policy = fit_policy([comparison_of(claims)], target_precision=0.95, min_samples=4)
    entry = next(e for e in policy.fields if e.field == "telnet_enabled")

    assert entry.fitted is True
    assert entry.threshold == 0.75
    assert entry.precision_at_threshold == 1.0
    assert entry.claims_kept == 5
    assert policy.as_mapping()["telnet_enabled"] == 0.75


def test_a_field_that_cannot_reach_the_target_always_escalates():
    claims = [claim(FieldOutcome.WRONG, c) for c in (0.9, 0.95, 1.0)]
    claims += [claim(FieldOutcome.CORRECT, c) for c in (0.9, 0.95)]

    policy = fit_policy([comparison_of(claims)], target_precision=0.95, min_samples=1)
    entry = next(e for e in policy.fields if e.field == "telnet_enabled")

    assert entry.threshold == ALWAYS_ESCALATE
    assert entry.escalates_always is True
    assert policy.escalated_fields == ["telnet_enabled"]
    assert policy.threshold_for("telnet_enabled") == ALWAYS_ESCALATE
    assert ALWAYS_ESCALATE > 1.0, "no confidence can satisfy it, which is the point"


def test_a_field_with_too_little_evidence_keeps_the_default_unfitted():
    policy = fit_policy(
        [comparison_of([claim(FieldOutcome.CORRECT, 0.9)])], min_samples=10, default_threshold=0.6
    )
    entry = next(e for e in policy.fields if e.field == "telnet_enabled")

    assert entry.fitted is False
    assert entry.threshold == 0.6
    assert "need 10" in entry.reason
    assert entry.field not in policy.as_mapping(), "an unfitted default is not a learned threshold"


def test_a_thin_run_cannot_relax_a_threshold_an_earlier_run_tightened():
    previous = fit_policy(
        [
            comparison_of(
                [claim(FieldOutcome.WRONG, c) for c in (0.3, 0.5, 0.7)]
                + [claim(FieldOutcome.CORRECT, c) for c in (0.8, 0.85, 0.9, 0.95)]
            )
        ],
        target_precision=0.95,
        min_samples=4,
    )
    assert previous.threshold_for("telnet_enabled") == 0.75

    thin = fit_policy(
        [comparison_of([claim(FieldOutcome.CORRECT, 0.1)])],
        min_samples=10,
        default_threshold=0.6,
        previous=previous,
    )
    entry = next(e for e in thin.fields if e.field == "telnet_enabled")

    assert entry.fitted is False
    assert entry.threshold == 0.75, "the earlier, better-evidenced fit is carried forward"


# ---------------------------------------------------------------------------
# examples: teach the model its own mistakes, worst kind first
# ---------------------------------------------------------------------------


def test_wrong_answers_are_selected_before_overreach():
    fields = [
        claim(FieldOutcome.OVERREACH, 0.99, field="http_server_enabled"),
        claim(FieldOutcome.WRONG, 0.6, field="telnet_enabled"),
    ]
    selected = select_examples([comparison_of(fields)])

    assert [e.outcome for e in selected] == [FieldOutcome.WRONG, FieldOutcome.OVERREACH]


def test_examples_are_capped_per_field_and_overall():
    fields = [claim(FieldOutcome.WRONG, 0.9, field="telnet_enabled") for _ in range(5)]
    fields += [claim(FieldOutcome.WRONG, 0.9, field=f"field_{i}") for i in range(10)]

    selected = select_examples([comparison_of(fields)])

    assert len(selected) <= 8
    assert sum(1 for e in selected if e.field == "telnet_enabled") <= 2


def test_an_overreach_example_asks_for_silence_not_a_different_value():
    example = WorkedExample(
        field="ssh_version", outcome=FieldOutcome.OVERREACH, mistaken_value=1, correct_value=None
    )
    rendered = example.render()

    assert "determined: false" in rendered
    assert "did not settle the question" in rendered


def test_the_examples_block_is_empty_when_there_is_nothing_to_teach():
    assert render_examples_block([]) == ""
    assert ExampleSet().block == ""


def test_the_examples_block_forbids_copying_values_across_configs():
    block = ExampleSet(
        examples=[
            WorkedExample(
                field="telnet_enabled",
                outcome=FieldOutcome.WRONG,
                config_line="transport input ssh",
                correct_value=False,
                mistaken_value=True,
            )
        ]
    ).block

    assert "transport input ssh" in block
    assert "never copy a value or a source_line from here" in block


# ---------------------------------------------------------------------------
# adjudication: a person outranks a parser
# ---------------------------------------------------------------------------


def test_a_human_ruling_overrides_the_deterministic_parser(tmp_path, insecure_text):
    baseline = CiscoIOSParser().parse(insecure_text, source_file="insecure.conf")
    assert baseline.telnet_enabled.value is True

    store = AdjudicationStore(tmp_path / "adjudications.jsonl")
    store.append(
        Adjudication(
            config_sha256=baseline.source_sha256,
            field="telnet_enabled",
            detected=True,
            value=False,
            source_line="transport input telnet",
            reviewer="netops@example.net",
            note="vty lines are unreachable behind the ACL",
        )
    )

    overlaid = store.overlay(baseline)

    assert overlaid.telnet_enabled.value is False
    assert overlaid.telnet_enabled.origin is Origin.HUMAN
    assert any("human adjudication" in w for w in overlaid.provenance.warnings)
    assert baseline.telnet_enabled.value is True, "the original baseline is not mutated"


def test_a_ruling_can_confirm_that_a_field_is_undeterminable(tmp_path, hardened_text):
    baseline = CiscoIOSParser().parse(hardened_text, source_file="hardened.conf")
    store = AdjudicationStore(tmp_path / "adjudications.jsonl")
    store.append(
        Adjudication(
            config_sha256=baseline.source_sha256,
            field="ssh_version",
            detected=False,
            reviewer="reviewer",
        )
    )

    overlaid = store.overlay(baseline)

    assert overlaid.ssh_version.detected is False
    assert "not determinable" in overlaid.ssh_version.note


def test_the_latest_ruling_on_a_field_wins_and_the_store_survives_a_bad_line(tmp_path, insecure_text):
    baseline = CiscoIOSParser().parse(insecure_text, source_file="insecure.conf")
    path = tmp_path / "adjudications.jsonl"
    store = AdjudicationStore(path)
    for value in (2, 1):
        store.append(
            Adjudication(
                config_sha256=baseline.source_sha256,
                field="ssh_version",
                detected=True,
                value=value,
                source_line="version 12.4",
                reviewer="reviewer",
            )
        )
    with path.open("a", encoding="utf-8") as handle:
        handle.write("{ not json\n")

    reloaded = AdjudicationStore(path)

    assert len(reloaded) == 2
    assert reloaded.overlay(baseline).ssh_version.value == 1


def test_the_review_queue_is_what_the_tool_escalated_and_nobody_ruled_on(tmp_path, insecure_text):
    baseline = CiscoIOSParser().parse(insecure_text, source_file="insecure.conf")
    store = AdjudicationStore(tmp_path / "adjudications.jsonl")

    assert pending_reviews(baseline, store) == ["ssh_version"]

    store.append(
        Adjudication(
            config_sha256=baseline.source_sha256,
            field="ssh_version",
            detected=False,
            reviewer="reviewer",
        )
    )

    assert pending_reviews(baseline, store) == []


# ---------------------------------------------------------------------------
# a whole run
# ---------------------------------------------------------------------------


def test_a_run_scores_every_labelled_config_and_writes_its_artifacts(loop, corpus_dir, scripted_client):
    corpus = ConfigCorpus.from_paths([corpus_dir])
    result = loop.run(corpus, scripted_client)

    assert scripted_client.calls == 2
    assert result.metrics.configs_scored == 2
    for artifact in ("metrics.json", "thresholds.json", "examples.json", "comparisons.json", "history.jsonl"):
        assert (loop.workdir / artifact).is_file(), artifact

    written = json.loads((loop.workdir / "metrics.json").read_text(encoding="utf-8"))
    assert written["configs_scored"] == 2


def test_a_run_finds_the_planted_wrong_answer_and_the_planted_overreach(loop, corpus_dir, scripted_client):
    result = loop.run(ConfigCorpus.from_paths([corpus_dir]), scripted_client)
    by_field = {field.field: field for field in result.metrics.per_field}

    assert by_field["telnet_enabled"].wrong == 1, "the hardened config only accepts ssh"
    assert by_field["telnet_enabled"].correct == 1
    assert by_field["ssh_version"].overreach == 1, "the insecure config never states a version"
    assert by_field["hostname"].correct == 2
    assert result.metrics.overall_precision < 1.0


def test_a_run_measures_what_the_errors_did_to_verdicts(loop, corpus_dir, scripted_client):
    """Field accuracy is the input; control verdicts are what anyone acts on."""
    result = loop.run(ConfigCorpus.from_paths([corpus_dir]), scripted_client)
    impact = result.metrics.verdict_impact

    assert impact.total > 0
    assert 0.0 <= impact.agreement_rate <= 1.0
    assert impact.lost_coverage > 0, "fields the model stayed silent on cost decided verdicts"


def test_examples_and_thresholds_are_mined_from_the_run(loop, corpus_dir, scripted_client):
    result = loop.run(ConfigCorpus.from_paths([corpus_dir]), scripted_client)

    assert {e.field for e in result.examples.examples} >= {"telnet_enabled", "ssh_version"}
    assert loop.load_policy() is not None
    assert loop.load_examples().examples, "the next run must be able to read these back"


def test_a_dry_run_measures_without_changing_anything(loop, corpus_dir, scripted_client):
    result = loop.run(ConfigCorpus.from_paths([corpus_dir]), scripted_client, write=False)

    assert result.metrics.configs_scored == 2
    assert not loop.workdir.exists(), "a dry run must not rewrite the policy"


def test_a_corpus_with_no_ground_truth_is_refused(loop, tmp_path):
    directory = tmp_path / "unknown"
    directory.mkdir()
    (directory / "unknown_vendor.conf").write_text(
        (SAMPLES / "unknown_vendor.conf").read_text(encoding="utf-8"), encoding="utf-8"
    )

    with pytest.raises(ValueError, match="No labelled configurations"):
        loop.run(ConfigCorpus.from_paths([directory]), StubClient())


def test_human_rulings_are_used_as_ground_truth_by_the_run(ruleset, tmp_path, corpus_dir, scripted_client):
    """Adjudicating the model's 'wrong' answer as correct must clear the error."""
    hardened = CiscoIOSParser().parse((corpus_dir / "hardened.conf").read_text(encoding="utf-8"))
    store = AdjudicationStore(tmp_path / "adjudications.jsonl")
    store.append(
        Adjudication(
            config_sha256=hardened.source_sha256,
            field="telnet_enabled",
            detected=True,
            value=True,
            source_line="transport input ssh",
            reviewer="reviewer",
        )
    )

    loop = TrainingLoop(ruleset, tmp_path / "training", adjudications=store, min_samples=1)
    result = loop.run(ConfigCorpus.from_paths([corpus_dir]), scripted_client)
    by_field = {field.field: field for field in result.metrics.per_field}

    assert by_field["telnet_enabled"].wrong == 0
    assert by_field["telnet_enabled"].correct == 2


# ---------------------------------------------------------------------------
# the gate
# ---------------------------------------------------------------------------


def test_more_dangerous_flips_is_a_regression_however_good_the_averages():
    previous = RunSummary(precision=0.80, dangerous_flips=1)
    current = RunSummary(precision=0.99, dangerous_flips=2)

    report = RegressionReport.compare(current, previous)

    assert report.regressed is True
    assert any("dangerous verdict flips rose" in reason for reason in report.reasons)


def test_a_small_precision_dip_is_tolerated_but_a_real_one_is_not():
    previous = RunSummary(precision=0.90)

    assert RegressionReport.compare(RunSummary(precision=0.89), previous).regressed is False
    assert RegressionReport.compare(RunSummary(precision=0.70), previous).regressed is True


def test_the_first_run_has_nothing_to_regress_against():
    report = RegressionReport.compare(RunSummary(precision=0.5), None)

    assert report.regressed is False
    assert report.reasons == ["no previous run to compare against"]


def test_a_second_run_is_compared_against_the_first(loop, corpus_dir, scripted_client):
    loop.run(ConfigCorpus.from_paths([corpus_dir]), scripted_client)
    result = loop.run(ConfigCorpus.from_paths([corpus_dir]), scripted_client)

    assert result.regression.compared_against is not None
    assert result.regression.regressed is False, "the same run twice cannot be worse"
    assert result.regression.precision_delta == 0.0


# ---------------------------------------------------------------------------
# feeding back into production
# ---------------------------------------------------------------------------


class PromptCarryingClient(StubClient):
    """A client with a system prompt, the way the real one has."""

    def __init__(self, extraction=None):
        super().__init__(extraction)
        self.system_prompt = "BASE PROMPT"


def test_a_tuned_parser_applies_the_fitted_threshold_to_the_field_it_was_fitted_for(tmp_path, hardened_text):
    workdir = tmp_path / "training"
    workdir.mkdir()
    policy = fit_policy(
        [
            comparison_of(
                [claim(FieldOutcome.WRONG, c, field="ssh_version") for c in (0.3, 0.6, 0.7)]
                + [claim(FieldOutcome.CORRECT, c, field="ssh_version") for c in (0.9, 0.95, 1.0)]
            )
        ],
        target_precision=0.95,
        min_samples=3,
    )
    (workdir / "thresholds.json").write_text(policy.model_dump_json(), encoding="utf-8")

    client = PromptCarryingClient(
        make_extraction(
            vendor="cisco",
            os_family="ios",
            ssh_version=found(2, "ip ssh version 2", confidence=0.7),
            hostname=found("CORE-RTR-01", "hostname CORE-RTR-01", confidence=0.7),
        )
    )
    parser = tuned_parser(workdir, client, min_confidence=0.6)
    baseline = parser.parse(hardened_text)

    assert parser.field_thresholds["ssh_version"] == 0.75
    assert baseline.ssh_version.detected is False, "below the fitted threshold for this field"
    assert baseline.hostname.detected is True, "other fields keep the flat default"


def test_worked_examples_ride_along_in_the_system_prompt(tmp_path, hardened_text):
    workdir = tmp_path / "training"
    workdir.mkdir()
    examples = ExampleSet(
        examples=[
            WorkedExample(
                field="telnet_enabled",
                outcome=FieldOutcome.WRONG,
                config_line="transport input ssh",
                correct_value=False,
                mistaken_value=True,
            )
        ]
    )
    (workdir / "examples.json").write_text(examples.model_dump_json(), encoding="utf-8")

    client = PromptCarryingClient()
    tuned_parser(workdir, client)

    assert client.system_prompt.startswith("BASE PROMPT") is False, "the base prompt is replaced, not appended to"
    assert "Corrections from previous runs" in client.system_prompt
    assert "telnet_enabled" in client.system_prompt


def test_a_workdir_with_no_run_yet_yields_the_parser_exactly_as_shipped(tmp_path):
    parser = tuned_parser(tmp_path, StubClient(), min_confidence=0.6)

    assert load_policy(tmp_path) is None
    assert load_examples(tmp_path).examples == []
    assert isinstance(parser, LLMParser)
    assert parser.field_thresholds == {}
    assert parser.min_confidence == 0.6


def test_corrupt_artifacts_are_ignored_rather_than_crashing_an_audit(tmp_path):
    (tmp_path / "thresholds.json").write_text("{ not json", encoding="utf-8")
    (tmp_path / "examples.json").write_text("{ not json", encoding="utf-8")

    assert load_policy(tmp_path) is None
    assert load_examples(tmp_path).examples == []


# ---------------------------------------------------------------------------
# the training CLI
# ---------------------------------------------------------------------------


def test_report_needs_a_run_first(tmp_path, capsys):
    from auditor.training import cli as training_cli

    code = training_cli.run(["report", "--out", str(tmp_path)])

    assert code == training_cli.EXIT_ERROR
    assert "Run the loop first" in capsys.readouterr().err


def test_report_prints_the_last_runs_numbers(loop, corpus_dir, scripted_client, capsys):
    from auditor.training import cli as training_cli

    loop.run(ConfigCorpus.from_paths([corpus_dir]), scripted_client)
    capsys.readouterr()

    code = training_cli.run(["report", "--out", str(loop.workdir)])
    out = capsys.readouterr().out

    assert code == training_cli.EXIT_OK
    assert "Overall precision" in out
    assert "FITTED THRESHOLDS" in out
    assert "DANGEROUS FLIPS" in out


def test_adjudicate_records_a_ruling_against_the_configs_hash(tmp_path, corpus_dir, capsys):
    from auditor.training import cli as training_cli

    store_path = tmp_path / "adjudications.jsonl"
    code = training_cli.run(
        [
            "adjudicate",
            str(corpus_dir / "insecure.conf"),
            "--field",
            "ssh_version",
            "--reviewer",
            "netops",
            "--undetermined",
            "--store",
            str(store_path),
        ]
    )

    assert code == training_cli.EXIT_OK
    assert "cannot be determined" in capsys.readouterr().out

    baseline = CiscoIOSParser().parse((corpus_dir / "insecure.conf").read_text(encoding="utf-8"))
    store = AdjudicationStore(store_path)
    assert store.for_config(baseline.source_sha256)["ssh_version"].reviewer == "netops"


def test_adjudicate_without_a_value_is_a_clean_error(tmp_path, corpus_dir, capsys):
    from auditor.training import cli as training_cli

    code = training_cli.run(
        [
            "adjudicate",
            str(corpus_dir / "insecure.conf"),
            "--field",
            "ssh_version",
            "--reviewer",
            "netops",
            "--store",
            str(tmp_path / "a.jsonl"),
        ]
    )

    assert code == training_cli.EXIT_ERROR
    assert "--value is required" in capsys.readouterr().err
