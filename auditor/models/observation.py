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

    Recording this per observation is what lets the training loop diff a model's
    output against deterministic ground truth field by field, and what lets a
    report say which findings a human should weigh differently.
    """

    DETERMINISTIC = "deterministic"
    LLM = "llm"
    HYBRID = "hybrid"
    HUMAN = "human"
    LEARNED = "learned"


class EvidenceState(str, Enum):
    """Canonical evidence state for compliance reporting.

    Every observation maps into exactly one of these five states.
    ``PRESENT`` and ``ABSENT`` are both valid evidence -- they differ only
    in whether a config line exists to point at.  ``UNKNOWN`` means the
    parser could not determine the state from the available text.
    ``NOT_DETERMINABLE`` means the information is structurally unavailable
    (e.g., a partial config excerpt).
    """

    PRESENT = "PRESENT"
    ABSENT = "ABSENT"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_DETERMINABLE = "NOT_DETERMINABLE"


class CapabilityStatus(str, Enum):
    """Parser support and detection capability state for a baseline field."""

    SUPPORTED_AND_FOUND = "SUPPORTED_AND_FOUND"
    SUPPORTED_AND_NOT_FOUND = "SUPPORTED_AND_NOT_FOUND"
    SUPPORTED_BUT_UNKNOWN = "SUPPORTED_BUT_UNKNOWN"
    NOT_DETERMINABLE = "NOT_DETERMINABLE"
    UNSUPPORTED = "UNSUPPORTED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Observation(BaseModel, Generic[T]):
    """A single normalized setting plus the evidence behind it."""

    model_config = ConfigDict(frozen=True)

    value: Optional[T] = None
    detected: bool = False
    is_unsupported: bool = False
    source_line: Optional[str] = None
    line_number: Optional[int] = None
    origin: Origin = Origin.DETERMINISTIC
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    note: Optional[str] = None
    mapping_id: Optional[str] = None
    original_line_number: Optional[int] = None
    original_line: Optional[str] = None

    # -- constructors: the four ways a setting can be known ---------------

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
            is_unsupported=False,
            source_line=source_line.strip() if source_line else source_line,
            line_number=line_number,
            origin=origin,
            confidence=confidence,
            note=note,
        )

    @classmethod
    def absent(cls, value: Any, note: str, origin: Origin = Origin.DETERMINISTIC) -> "Observation[T]":
        """No line was found, and that absence is itself conclusive evidence."""
        return cls(
            value=value,
            detected=True,
            is_unsupported=False,
            source_line=None,
            line_number=None,
            origin=origin,
            confidence=1.0,
            note=note,
        )

    @classmethod
    def unknown(cls, note: str = "No evidence found in configuration.") -> "Observation[T]":
        """No conclusive evidence either way -> the engine must escalate."""
        return cls(
            value=None,
            detected=False,
            is_unsupported=False,
            source_line=None,
            line_number=None,
            confidence=0.0,
            note=note,
        )

    @classmethod
    def unsupported(cls, note: str = "Parser does not evaluate this field.") -> "Observation[T]":
        """Parser does not evaluate or support this property."""
        return cls(
            value=None,
            detected=False,
            is_unsupported=True,
            source_line=None,
            line_number=None,
            confidence=0.0,
            note=note,
        )

    @classmethod
    def not_determinable(cls, note: str = "Insufficient configuration data to determine state.") -> "Observation[T]":
        """Configuration evidence is structurally unavailable (e.g. partial excerpt)."""
        return cls(
            value=None,
            detected=False,
            is_unsupported=False,
            source_line=None,
            line_number=None,
            confidence=0.0,
            note=note,
        )

    @property
    def evidence_state(self) -> EvidenceState:
        """Canonical five-state evidence classification for compliance reporting."""
        if self.is_unsupported:
            return EvidenceState.NOT_APPLICABLE
        if self.detected and self.source_line is not None:
            return EvidenceState.PRESENT
        if self.detected and self.source_line is None:
            return EvidenceState.ABSENT
        return EvidenceState.UNKNOWN

    @property
    def capability_status(self) -> CapabilityStatus:
        if self.is_unsupported:
            return CapabilityStatus.UNSUPPORTED
        if self.detected and self.source_line is not None:
            return CapabilityStatus.SUPPORTED_AND_FOUND
        if self.detected and self.source_line is None:
            return CapabilityStatus.SUPPORTED_AND_NOT_FOUND
        return CapabilityStatus.SUPPORTED_BUT_UNKNOWN

    # -- presentation ------------------------------------------------------

    @property
    def evidence_line(self) -> str:
        """One-line, always-populated evidence string for reports."""
        if self.source_line:
            prefix = f"L{self.line_number}: " if self.line_number else ""
            return f"{prefix}{self.source_line}"
        if self.detected:
            return f"<absent> {self.note or 'setting not present in configuration'}"
        if self.is_unsupported:
            return f"<unsupported> {self.note or 'parser does not evaluate this field'}"
        return f"<no evidence> {self.note or 'not found in configuration'}"
