"""Worked examples mined from the parser's own mistakes.

The second half of the feedback path. Thresholds decide *whether* to trust a
claim; examples try to make the claim right in the first place, by showing the
model cases it previously got wrong next to the ground truth.

Selection is biased hard toward WRONG over OVERREACH: a confidently false value
is the failure worth spending prompt tokens to prevent, while over-claiming is
already handled by thresholds. Examples are capped per field and overall, so
one pathological field cannot crowd out the rest of the prompt.

Note that examples embed real configuration lines from the corpus, and are sent
with every subsequent request. That is fine for a corpus of your own devices;
it is not fine for a corpus of someone else's, and the loop says so rather than
deciding for you.
"""

from typing import Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from .comparison import BaselineComparison, FieldComparison, FieldOutcome

MAX_PER_FIELD = 2
MAX_TOTAL = 8


class WorkedExample(BaseModel):
    """One past mistake, stated as a correction."""

    model_config = ConfigDict(frozen=True)

    field: str
    outcome: FieldOutcome
    config_line: Optional[str] = None
    correct_value: object = None
    mistaken_value: object = None
    source_file: Optional[str] = None

    def render(self) -> str:
        if self.outcome is FieldOutcome.OVERREACH:
            return (
                f"- `{self.field}`: you previously answered {self.mistaken_value!r} for this device, "
                "but the configuration did not settle the question. The correct answer was "
                "`determined: false`."
            )
        evidence = f" The deciding line was: `{self.config_line}`." if self.config_line else ""
        return (
            f"- `{self.field}`: you previously answered {self.mistaken_value!r}; "
            f"the correct value was {self.correct_value!r}.{evidence}"
        )


def select_examples(
    comparisons: List[BaselineComparison],
    *,
    max_per_field: int = MAX_PER_FIELD,
    max_total: int = MAX_TOTAL,
) -> List[WorkedExample]:
    """Pick the most instructive errors, worst kind first, capped per field."""
    ranked: List[Tuple[FieldComparison, Optional[str]]] = []
    for comparison in comparisons:
        for field_comparison in comparison.fields:
            if field_comparison.outcome.is_error:
                ranked.append((field_comparison, comparison.source_file))

    # WRONG before OVERREACH; within a kind, higher confidence first - a
    # confident mistake is the one most worth correcting.
    ranked.sort(
        key=lambda pair: (
            0 if pair[0].outcome is FieldOutcome.WRONG else 1,
            -pair[0].candidate_confidence,
            pair[0].field,
        )
    )

    per_field: Dict[str, int] = {}
    selected: List[WorkedExample] = []
    for field_comparison, source_file in ranked:
        if len(selected) >= max_total:
            break
        if per_field.get(field_comparison.field, 0) >= max_per_field:
            continue
        per_field[field_comparison.field] = per_field.get(field_comparison.field, 0) + 1
        selected.append(
            WorkedExample(
                field=field_comparison.field,
                outcome=field_comparison.outcome,
                config_line=field_comparison.truth_source_line,
                correct_value=field_comparison.truth_value,
                mistaken_value=field_comparison.candidate_value,
                source_file=source_file,
            )
        )
    return selected


def render_examples_block(examples: List[WorkedExample]) -> str:
    """The prompt fragment appended to the system prompt. Empty if no examples."""
    if not examples:
        return ""
    lines = [
        "# Corrections from previous runs",
        "",
        "These are mistakes this parser has made before on devices of the kinds you "
        "will see, each shown with the correct answer. They are illustrative, not "
        "rules: apply the reasoning, and never copy a value or a source_line from "
        "here into an answer about a different configuration.",
        "",
    ]
    lines.extend(example.render() for example in examples)
    return "\n".join(lines)


class ExampleSet(BaseModel):
    """The examples artifact written by a loop run."""

    examples: List[WorkedExample] = Field(default_factory=list)

    @property
    def block(self) -> str:
        return render_examples_block(self.examples)
