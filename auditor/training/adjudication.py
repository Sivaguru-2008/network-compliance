"""Human decisions on the findings the tool deliberately escalated.

Deterministic ground truth is free but only covers vendors we already parse.
The configs that most need labels are exactly the ones no deterministic parser
reads — and there the only label source is a person.

So NEEDS_REVIEW is not just a safe verdict; it is the collection mechanism. Each
adjudication is one high-value label on a case both parsers found hard, and it
is stored append-only as JSONL so the record of who decided what, and when,
survives.

Adjudications overlay onto a baseline to form ground truth for scoring. A human
decision always outranks a parser's, including a deterministic one — if a
reviewer says the parser was wrong, the parser was wrong.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from ..models.baseline import SecurityBaselineModel
from ..models.observation import Observation, Origin


class Adjudication(BaseModel):
    """One reviewer's ruling on one field of one configuration."""

    model_config = ConfigDict(frozen=True)

    config_sha256: str
    field: str
    detected: bool = Field(description="False records a confirmed 'cannot be determined from this config'.")
    value: Any = None
    source_line: Optional[str] = None
    reviewer: str
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    note: Optional[str] = None


class AdjudicationStore:
    """Append-only JSONL store of human labels."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._records: List[Adjudication] = []
        if self.path.is_file():
            self._records = list(self._read())

    def _read(self) -> Iterable[Adjudication]:
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                yield Adjudication.model_validate_json(line)
            except ValueError:
                continue  # a malformed line must not lose the rest of the record

    def __len__(self) -> int:
        return len(self._records)

    @property
    def records(self) -> List[Adjudication]:
        return list(self._records)

    def append(self, adjudication: Adjudication) -> Adjudication:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(adjudication.model_dump_json() + "\n")
        self._records.append(adjudication)
        return adjudication

    def for_config(self, sha256: str) -> Dict[str, Adjudication]:
        """Latest ruling per field for one configuration."""
        latest: Dict[str, Adjudication] = {}
        for record in self._records:
            if record.config_sha256 != sha256:
                continue
            existing = latest.get(record.field)
            if existing is None or record.decided_at >= existing.decided_at:
                latest[record.field] = record
        return latest

    def overlay(self, baseline: SecurityBaselineModel) -> SecurityBaselineModel:
        """Return a copy of ``baseline`` with human rulings applied.

        Used to build ground truth: a reviewed field becomes authoritative,
        whatever the parser said about it.
        """
        rulings = self.for_config(baseline.source_sha256 or "")
        if not rulings:
            return baseline

        updated = baseline.model_copy(deep=True)
        applied = []
        for field, ruling in rulings.items():
            if field not in SecurityBaselineModel.observable_fields():
                continue
            value_type = type(getattr(updated, field)).__pydantic_generic_metadata__["args"][0]
            note = f"Adjudicated by {ruling.reviewer}." + (f" {ruling.note}" if ruling.note else "")
            if not ruling.detected:
                observation = Observation[value_type].unknown(
                    f"{note} Confirmed as not determinable from this configuration."
                )
            elif ruling.source_line:
                observation = Observation[value_type].found(
                    ruling.value, ruling.source_line, note=note, origin=Origin.HUMAN
                )
            else:
                observation = Observation[value_type].absent(ruling.value, note, origin=Origin.HUMAN)
            setattr(updated, field, observation)
            applied.append(field)

        updated.provenance.warnings = [
            *updated.provenance.warnings,
            f"{len(applied)} field(s) overridden by human adjudication: {', '.join(sorted(applied))}.",
        ]
        return updated


def pending_reviews(baseline: SecurityBaselineModel, store: AdjudicationStore) -> List[str]:
    """Fields still undetected and not yet ruled on — the review queue."""
    already = set(store.for_config(baseline.source_sha256 or ""))
    return [
        field
        for field in SecurityBaselineModel.observable_fields()
        if not getattr(baseline, field).detected and field not in already
    ]
