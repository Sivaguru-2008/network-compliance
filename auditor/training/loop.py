"""The loop: measure, fit, feed back, and refuse to regress.

One run does five things, in order:

1. **Label.** For every config a deterministic parser recognises, its output is
   ground truth. Human adjudications are overlaid on top, because a reviewer
   outranks a parser.
2. **Score.** Run the candidate parser over the same configs and diff field by
   field, then run the rule engine over *both* baselines so the damage is also
   measured where it counts — in control verdicts.
3. **Fit.** Derive a per-field confidence threshold that holds precision at the
   target while giving up as little coverage as possible.
4. **Feed back.** Write the thresholds and a set of worked examples mined from
   the errors. The parser loads both on its next run. This is the only step
   that changes behaviour; everything before it just produces numbers.
5. **Gate.** Compare against the previous run and refuse to call it an
   improvement if dangerous verdict flips went up or precision fell.

Scoring deliberately runs the candidate with its confidence gate wide open
(``min_confidence=0``). A gated parser only ever reports claims that already
passed the previous threshold, which would make the next fit a function of the
last one — the thresholds would ratchet and never recover. Fitting needs the
raw, ungated distribution. Every *other* policy is left exactly as shipped, so
the numbers describe the real parser.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, List, Optional

from pydantic import BaseModel, Field

from ..engine import ComplianceEngine
from ..models.baseline import SecurityBaselineModel
from ..models.rule import RuleSet
from ..parsers.base import ParserError
from ..parsers.llm.client import LLMClient
from ..parsers.llm.parser import LLMParser
from .adjudication import AdjudicationStore
from .calibration import ThresholdPolicy, fit_policy
from .comparison import BaselineComparison, compare_baselines
from .corpus import ConfigCorpus, CorpusEntry
from .examples import ExampleSet, select_examples
from .metrics import RunMetrics, VerdictImpact

METRICS_FILE = "metrics.json"
THRESHOLDS_FILE = "thresholds.json"
EXAMPLES_FILE = "examples.json"
COMPARISONS_FILE = "comparisons.json"
HISTORY_FILE = "history.jsonl"


class RunSummary(BaseModel):
    """One line of history — enough to detect a regression against."""

    ran_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    configs_scored: int = 0
    precision: float = 0.0
    coverage: float = 0.0
    dangerous_flips: int = 0
    expected_calibration_error: float = 0.0


class RegressionReport(BaseModel):
    """Did this run get worse than the last one?"""

    compared_against: Optional[datetime] = None
    regressed: bool = False
    reasons: List[str] = Field(default_factory=list)
    precision_delta: float = 0.0
    dangerous_flip_delta: int = 0

    @classmethod
    def compare(
        cls,
        current: RunSummary,
        previous: Optional[RunSummary],
        *,
        precision_tolerance: float = 0.02,
    ) -> "RegressionReport":
        if previous is None:
            return cls(reasons=["no previous run to compare against"])

        precision_delta = round(current.precision - previous.precision, 4)
        flip_delta = current.dangerous_flips - previous.dangerous_flips
        reasons: List[str] = []

        # Dangerous flips have no tolerance band. One more device wrongly
        # reported clean is a regression regardless of what the averages did.
        if flip_delta > 0:
            reasons.append(
                f"dangerous verdict flips rose from {previous.dangerous_flips} to {current.dangerous_flips}"
            )
        if precision_delta < -precision_tolerance:
            reasons.append(
                f"precision fell from {previous.precision:.1%} to {current.precision:.1%}"
            )
        return cls(
            compared_against=previous.ran_at,
            regressed=bool(reasons),
            reasons=reasons or ["no regression detected"],
            precision_delta=precision_delta,
            dangerous_flip_delta=flip_delta,
        )


class LoopResult(BaseModel):
    summary: RunSummary
    metrics: RunMetrics
    policy: ThresholdPolicy
    examples: ExampleSet
    regression: RegressionReport
    skipped: List[str] = Field(default_factory=list)


class TrainingLoop:
    """Runs the measure-fit-feed back cycle over a corpus."""

    def __init__(
        self,
        ruleset: RuleSet,
        workdir: Path,
        *,
        adjudications: Optional[AdjudicationStore] = None,
        target_precision: float = 0.95,
        min_samples: int = 10,
    ) -> None:
        self.engine = ComplianceEngine(ruleset)
        self.workdir = Path(workdir)
        self.adjudications = adjudications
        self.target_precision = target_precision
        self.min_samples = min_samples

    # -- one config --------------------------------------------------------

    def ground_truth(self, entry: CorpusEntry) -> SecurityBaselineModel:
        parser_cls = entry.deterministic_parser()
        if parser_cls is None:
            raise ParserError(f"No deterministic parser recognises {entry.name}.")
        baseline = parser_cls().parse(entry.text, source_file=str(entry.path))
        if self.adjudications is not None:
            baseline = self.adjudications.overlay(baseline)
        return baseline

    def score_one(self, entry: CorpusEntry, candidate_parser: LLMParser) -> BaselineComparison:
        """Diff one config. Verdict impact is computed separately by the caller."""
        truth = self.ground_truth(entry)
        candidate = candidate_parser.parse(entry.text, source_file=str(entry.path))
        return compare_baselines(truth, candidate)

    def verdict_impact(
        self, truth: SecurityBaselineModel, candidate: SecurityBaselineModel, source_file: str
    ) -> VerdictImpact:
        return VerdictImpact.from_results(
            self.engine.evaluate(truth), self.engine.evaluate(candidate), source_file=source_file
        )

    # -- a whole run -------------------------------------------------------

    def run(
        self,
        corpus: ConfigCorpus,
        client: LLMClient,
        *,
        max_configs: Optional[int] = None,
        parser_factory: Optional[Callable[[LLMClient], LLMParser]] = None,
        write: bool = True,
    ) -> LoopResult:
        entries = corpus.labelled[: max_configs or None]
        if not entries:
            raise ValueError(
                "No labelled configurations in the corpus. The loop needs configs a "
                "deterministic parser recognises, since those supply ground truth."
            )

        # Ungated on purpose: fitting thresholds requires the raw confidence
        # distribution, not one already filtered by the last fit.
        build = parser_factory or (lambda c: LLMParser(c, min_confidence=0.0))

        comparisons: List[BaselineComparison] = []
        impact = VerdictImpact()
        skipped: List[str] = []

        for entry in entries:
            candidate_parser = build(client)
            try:
                truth = self.ground_truth(entry)
                candidate = candidate_parser.parse(entry.text, source_file=str(entry.path))
            except ParserError as exc:
                skipped.append(f"{entry.name}: {exc}")
                continue
            comparisons.append(compare_baselines(truth, candidate))
            impact = impact.merged_with(self.verdict_impact(truth, candidate, entry.name))

        if not comparisons:
            raise ParserError(
                "Every configuration failed to score. First failure: "
                + (skipped[0] if skipped else "unknown")
            )

        metrics = RunMetrics.from_comparisons(comparisons, verdict_impact=impact)
        policy = fit_policy(
            comparisons,
            target_precision=self.target_precision,
            min_samples=self.min_samples,
            previous=self.load_policy(),
        )
        examples = ExampleSet(examples=select_examples(comparisons))
        summary = RunSummary(
            configs_scored=metrics.configs_scored,
            precision=metrics.overall_precision,
            coverage=metrics.overall_coverage,
            dangerous_flips=impact.dangerous_flips,
            expected_calibration_error=metrics.calibration.expected_calibration_error,
        )
        regression = RegressionReport.compare(summary, self.last_summary())

        result = LoopResult(
            summary=summary,
            metrics=metrics,
            policy=policy,
            examples=examples,
            regression=regression,
            skipped=skipped,
        )
        if write:
            self._write(result, comparisons)
        return result

    # -- artifacts ---------------------------------------------------------

    def _write(self, result: LoopResult, comparisons: List[BaselineComparison]) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)
        self._dump(METRICS_FILE, result.metrics)
        self._dump(THRESHOLDS_FILE, result.policy)
        self._dump(EXAMPLES_FILE, result.examples)
        (self.workdir / COMPARISONS_FILE).write_text(
            json.dumps([c.model_dump(mode="json") for c in comparisons], indent=2), encoding="utf-8"
        )
        with (self.workdir / HISTORY_FILE).open("a", encoding="utf-8") as handle:
            handle.write(result.summary.model_dump_json() + "\n")

    def _dump(self, filename: str, model: BaseModel) -> None:
        (self.workdir / filename).write_text(
            json.dumps(model.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8"
        )

    def load_policy(self) -> Optional[ThresholdPolicy]:
        return load_policy(self.workdir)

    def load_examples(self) -> ExampleSet:
        return load_examples(self.workdir)

    def last_summary(self) -> Optional[RunSummary]:
        path = self.workdir / HISTORY_FILE
        if not path.is_file():
            return None
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        for line in reversed(lines):
            try:
                return RunSummary.model_validate_json(line)
            except ValueError:
                continue
        return None


def load_policy(workdir: Path) -> Optional[ThresholdPolicy]:
    """Read a fitted threshold policy, or None if this directory has no run yet."""
    path = Path(workdir) / THRESHOLDS_FILE
    if not path.is_file():
        return None
    try:
        return ThresholdPolicy.model_validate_json(path.read_text(encoding="utf-8"))
    except ValueError:
        return None


def load_examples(workdir: Path) -> ExampleSet:
    """Read the worked examples, or an empty set if there are none."""
    path = Path(workdir) / EXAMPLES_FILE
    if not path.is_file():
        return ExampleSet()
    try:
        return ExampleSet.model_validate_json(path.read_text(encoding="utf-8"))
    except ValueError:
        return ExampleSet()


def tuned_parser(workdir: Path, client: LLMClient, **kwargs) -> LLMParser:
    """An LLMParser configured from the last loop run's artifacts.

    This is how the loop's output reaches production: fitted thresholds gate
    the claims, and worked examples ride along in the system prompt.
    """
    policy = load_policy(workdir)
    examples = load_examples(workdir)
    if examples.block and hasattr(client, "system_prompt"):
        from ..parsers.llm.prompt import build_system_prompt

        client.system_prompt = build_system_prompt(examples.block)
    return LLMParser(client, field_thresholds=policy.as_mapping() if policy else {}, **kwargs)
