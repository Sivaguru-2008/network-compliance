"""Evidence-carrying wrapper for every normalized security setting.

The whole auditor rests on one idea: a normalized value is worthless without
the evidence that produced it.  ``Observation`` binds the two together so that
every downstream verdict can point at the exact configuration line it came
from -- or state plainly that no evidence was found.
"""

from enum import Enum
from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class Origin(str, Enum):
    """Where an observation came from.

    Step 1 only ever emits ``DETERMINISTIC``.  ``LLM`` / ``HYBRID`` exist now so
    that the later ``LLMParser`` can populate the *same* baseline model without
    a schema migration, and so the training loop can diff LLM observations
    against deterministic ones on configs both can parse.
    """

    DETERMINISTIC = "deterministic"
    LLM = "llm"
    HYBRID = "hybrid"


class Observation(BaseModel, Generic[T]):
    """A single normalized setting plus the evidence behind it.

    Attributes:
        value: The normalized, vendor-neutral value. ``None`` when undetected.
        detected: ``True`` only when the parser could *conclusively* determine
            the value from the configuration -- either because an explicit line
            was found, or because the absence of a line is unambiguous for this
            setting on this platform (see ``AbsencePolicy`` in the parser).
            ``False`` means "unknown", which the engine turns into
            ``NEEDS_REVIEW``.  It never means "secure".
        source_line: The raw configuration line the value was derived from,
            verbatim.  ``None`` for conclusive-absence observations.
        line_number: 1-based line number of ``source_line`` in the source config.
        origin: Which class of parser produced this observation.
        confidence: 0.0-1.0.  Deterministic parses are 1.0; an LLM parser is
            expected to emit lower, calibrated values.
        note: Human-readable explanation, especially for absence / unknown.
    """

    model_config = ConfigDict(frozen=True)

    value: Optional[T] = None
    detected: bool = False
    source_line: Optional[str] = None
    line_number: Optional[int] = None
    origin: Origin = Origin.DETERMINISTIC
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    note: Optional[str] = None

    # -- constructors: the three ways a setting can be known ---------------

    @classmethod
    def found(
        cls,
        value: Any,
        source_line: str,
        line_number: Optional[int] = None,
        note: Optional[str] = None,
        origin: Origin = Origin.DETERMINISTIC,
        confidence: float = 1.0,
    ) -> "Observation[T]":
        """Explicit evidence was found in the config."""
        return cls(
            value=value,
            detected=True,
            source_line=source_line.strip() if source_line else source_line,
            line_number=line_number,
            origin=origin,
            confidence=confidence,
            note=note,
        )

    @classmethod
    def absent(cls, value: Any, note: str, origin: Origin = Origin.DETERMINISTIC) -> "Observation[T]":
        """No line was found, and that absence is itself conclusive evidence.

        Used only for settings that always appear in a running-config when
        enabled (e.g. ``aaa new-model``), so "not present" provably means
        "not configured".  The caller must justify this in ``note``.
        """
        return cls(
            value=value,
            detected=True,
            source_line=None,
            line_number=None,
            origin=origin,
            confidence=1.0,
            note=note,
        )

    @classmethod
    def unknown(cls, note: str = "No evidence found in configuration.") -> "Observation[T]":
        """No conclusive evidence either way -> the engine must escalate."""
        return cls(value=None, detected=False, source_line=None, line_number=None, confidence=0.0, note=note)

    # -- presentation ------------------------------------------------------

    @property
    def evidence_line(self) -> str:
        """One-line, always-populated evidence string for reports."""
        if self.source_line:
            prefix = f"L{self.line_number}: " if self.line_number else ""
            return f"{prefix}{self.source_line}"
        if self.detected:
            return f"<absent> {self.note or 'setting not present in configuration'}"
        return f"<no evidence> {self.note or 'not found in configuration'}"
