"""Parser interface + registry.

Every parser -- deterministic today, LLM-backed later -- honours one contract:

    parse(config_text: str) -> SecurityBaselineModel

That single signature is what lets an ``LLMParser`` for an unknown vendor drop
in without the rule engine, the rule packs, or the report layer changing at all.

A parser declares:

* ``name`` / ``vendor`` / ``os_family`` -- identity, recorded in the report.
* ``version``                          -- bumped when normalization semantics change.
* ``base_confidence``                  -- 1.0 for grammar-based parsing, lower for
  probabilistic parsing, so downstream consumers can weight results.
* ``detect()``                         -- cheap 0..1 "does this look like mine?"
  score used by the registry to auto-select.  The future ``LLMParser`` returns a
  small constant floor (e.g. 0.05) so it wins only when nothing else claims the
  config, making it the natural fallback with no dispatch logic to rewrite.
"""

from abc import ABC, abstractmethod
from typing import ClassVar, Dict, List, Optional, Tuple, Type

from ..models.baseline import SecurityBaselineModel


class ParserError(Exception):
    """Raised when a parser cannot process the supplied configuration text."""


class VendorParser(ABC):
    """Abstract base class for all configuration parsers."""

    name: ClassVar[str] = "abstract"
    vendor: ClassVar[str] = "unknown"
    os_family: ClassVar[str] = "unknown"
    version: ClassVar[str] = "0.0.0"
    base_confidence: ClassVar[float] = 1.0

    @classmethod
    @abstractmethod
    def detect(cls, config_text: str) -> float:
        """Return 0.0-1.0 confidence that this parser handles ``config_text``."""

    @abstractmethod
    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        """Normalize raw configuration text into the vendor-neutral baseline.

        Implementations must never raise on merely *unrecognised* content: an
        unparseable setting becomes an undetected ``Observation`` (which the
        engine reports as NEEDS_REVIEW), not an exception.  Raise
        ``ParserError`` only when the input is not a config this parser can
        process at all.
        """


class ParserRegistry:
    """Name -> parser lookup with confidence-ranked auto-detection."""

    def __init__(self) -> None:
        self._parsers: Dict[str, Type[VendorParser]] = {}

    def register(self, parser_cls: Type[VendorParser]) -> Type[VendorParser]:
        """Register a parser class. Usable as a decorator."""
        if parser_cls.name in self._parsers:
            raise ValueError(f"Parser already registered under name {parser_cls.name!r}")
        self._parsers[parser_cls.name] = parser_cls
        return parser_cls

    def get(self, name: str) -> Type[VendorParser]:
        try:
            return self._parsers[name]
        except KeyError:
            raise ParserError(
                f"Unknown parser {name!r}. Available: {', '.join(sorted(self._parsers)) or '(none)'}"
            ) from None

    def names(self) -> List[str]:
        return sorted(self._parsers)

    def rank(self, config_text: str) -> List[Tuple[float, Type[VendorParser]]]:
        """All parsers scored against the config, best first."""
        scored = [(cls.detect(config_text), cls) for cls in self._parsers.values()]
        return sorted(scored, key=lambda pair: (-pair[0], pair[1].name))

    def detect(self, config_text: str, *, threshold: float = 0.3) -> Tuple[Type[VendorParser], float]:
        """Pick the best-matching parser, or raise if none is confident enough."""
        ranked = self.rank(config_text)
        if not ranked:
            raise ParserError("No parsers registered.")
        score, parser_cls = ranked[0]
        if score < threshold:
            raise ParserError(
                "Could not confidently identify the device vendor from this configuration "
                f"(best guess {parser_cls.name!r} at {score:.2f}, threshold {threshold:.2f}). "
                "Pass --vendor to force a parser. A future LLMParser will register as the "
                "fallback for exactly this case."
            )
        return parser_cls, score


registry = ParserRegistry()
