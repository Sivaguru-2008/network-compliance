"""The feedback loop: measure the LLM parser, fit its policy, feed the result back.

The audit pipeline is read-only and deterministic once a baseline exists. This
package is the part that *changes* the parser, so it is kept separate: it costs
API calls, it sends every corpus configuration to the model provider, and it
rewrites the thresholds and prompt examples the next audit will use.

The cycle is closed by two objects. ``TrainingLoop`` produces the artifacts
(metrics, thresholds, worked examples) from a corpus whose ground truth a
deterministic parser supplies for free; ``tuned_parser`` is the only thing
production needs to consume them.

    from auditor.training import tuned_parser

    parser = tuned_parser(Path("training"), client)   # fitted thresholds + examples

Human rulings enter through ``AdjudicationStore`` and outrank every parser,
including the deterministic one that would otherwise be ground truth.
"""

from .adjudication import Adjudication, AdjudicationStore, pending_reviews
from .calibration import ALWAYS_ESCALATE, FieldThreshold, ThresholdPolicy, fit_policy
from .comparison import (
    BaselineComparison,
    FieldComparison,
    FieldOutcome,
    compare_baselines,
)
from .corpus import ConfigCorpus, CorpusEntry
from .examples import ExampleSet, WorkedExample, render_examples_block, select_examples
from .loop import (
    LoopResult,
    RegressionReport,
    RunSummary,
    TrainingLoop,
    load_examples,
    load_policy,
    tuned_parser,
)
from .metrics import Calibration, FieldMetrics, RunMetrics, VerdictImpact

__all__ = [
    "ALWAYS_ESCALATE",
    "Adjudication",
    "AdjudicationStore",
    "BaselineComparison",
    "Calibration",
    "ConfigCorpus",
    "CorpusEntry",
    "ExampleSet",
    "FieldComparison",
    "FieldMetrics",
    "FieldOutcome",
    "FieldThreshold",
    "LoopResult",
    "RegressionReport",
    "RunMetrics",
    "RunSummary",
    "ThresholdPolicy",
    "TrainingLoop",
    "VerdictImpact",
    "WorkedExample",
    "compare_baselines",
    "fit_policy",
    "load_examples",
    "load_policy",
    "pending_reviews",
    "render_examples_block",
    "select_examples",
    "tuned_parser",
]
