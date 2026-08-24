"""HybridParser — deterministic first, model only for what it could not settle.

The deterministic parser is exact but narrow: on a Cisco IOS config it leaves a
handful of fields undetected on purpose, because the effective value depends on
a platform default it cannot confirm from text. Those fields become
NEEDS_REVIEW, which is honest but costs coverage.

This parser keeps the exactness and buys some of that coverage back. It runs
the grammar-based parser first and keeps every field it established — a
deterministic reading is never overruled by a model. Only the gaps go to the
LLM, and what comes back is stamped ``Origin.HYBRID``: produced by a model that
had deterministic results in hand, which is a different reliability class from
a model reading an unknown vendor cold, and is measured separately by the
training loop.

It is never auto-selected. ``detect()`` returns 0.0 so the registry will not
choose it on its own, because it costs an API call and sends the configuration
off-box; reaching it takes an explicit ``--vendor hybrid``.

A useful side effect: the LLM is asked about the *whole* config, not just the
gaps, so every hybrid parse also yields a full model reading of fields the
deterministic parser already knows. That is exactly the labelled comparison
data the training loop consumes, harvested for free from ordinary audits
(``last_llm_baseline``).
"""

from pathlib import Path
from typing import Any, List, Optional, Type

from ..models.baseline import SecurityBaselineModel
from ..models.observation import Origin
from .base import ParserError, VendorParser, registry
from .cisco_ios import CiscoIOSParser
from .llm.parser import LLMParser


@registry.register
class HybridParser(VendorParser):
    """Deterministic parse, with model-supplied answers for the undetected fields."""

    name = "hybrid"
    vendor = "multi"
    os_family = "multi"
    version = "1.0.0"
    base_confidence = 0.9

    def __init__(
        self,
        deterministic: Optional[VendorParser] = None,
        llm: Optional[LLMParser] = None,
        training_dir: Optional[Path] = None,
        mapping_store: Optional[Any] = None,
    ) -> None:
        self._deterministic = deterministic
        self._llm = llm or LLMParser()
        self.training_dir = Path(training_dir) if training_dir else Path("training")
        self.mapping_store = mapping_store
        self.last_llm_baseline: Optional[SecurityBaselineModel] = None
        self.filled_fields: List[str] = []

    @classmethod
    def detect(cls, config_text: str) -> float:
        """Never auto-selected: it costs an API call, so it must be asked for."""
        return 0.0

    def _resolve_deterministic(self, config_text: str) -> VendorParser:
        if self._deterministic is not None:
            return self._deterministic
        ranked = registry.rank(config_text)
        for score, parser_cls in ranked:
            if parser_cls is not type(self) and score >= 0.3:
                return parser_cls()
        raise ParserError(
            "The hybrid parser needs a deterministic parser to build on, and none "
            "recognised this configuration. Use --vendor llm for an unknown vendor."
        )

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        deterministic = self._resolve_deterministic(config_text)
        baseline = deterministic.parse(config_text, source_file=source_file)

        # Apply learned mappings
        if self.mapping_store is None:
            from ..training.mappings import LearnedMappingStore
            store_path = self.training_dir / "learned_mappings.jsonl"
            self.mapping_store = LearnedMappingStore(store_path)

        from ..training.mappings import resolve_learned_mappings, get_unrecognized_lines, check_all_unrecognized_lines_matched
        unrecognized = get_unrecognized_lines(config_text, baseline)
        approved = self.mapping_store.get_active_approved_mappings()
        vendor_approved = [m for m in approved if m.vendor.lower() == baseline.provenance.vendor.lower()]
        all_matched = check_all_unrecognized_lines_matched(unrecognized, vendor_approved)

        stats_path = self.training_dir / "stats.json"
        baseline = resolve_learned_mappings(config_text, baseline, self.mapping_store, stats_path=stats_path)

        fields = SecurityBaselineModel.observable_fields()
        gaps = [field for field in fields if not getattr(baseline, field).detected]
        if all_matched or not gaps:
            baseline.provenance.parser_name = self.name
            baseline.provenance.warnings.append(
                "Hybrid parse: the deterministic parser and learned mappings established every field, "
                "so no model call was needed."
            )
            return baseline

        try:
            llm_baseline = self._llm.parse(config_text, source_file=source_file)
            self.last_llm_baseline = llm_baseline

            filled: List[str] = []
            for field in gaps:
                candidate = getattr(llm_baseline, field)
                if not candidate.detected:
                    continue
                setattr(baseline, field, candidate.model_copy(update={"origin": Origin.HYBRID}))
                filled.append(field)

            self.filled_fields = filled
            baseline.provenance.parser_name = self.name
            baseline.provenance.parser_version = (
                f"{self.version} ({deterministic.name} v{deterministic.version} + {self._llm.name})"
            )
            baseline.provenance.warnings = [
                *baseline.provenance.warnings,
                *llm_baseline.provenance.warnings,
                (
                    f"Hybrid parse: {len(filled)} of {len(gaps)} field(s) the deterministic parser "
                    f"could not establish were filled by a language model"
                    + (f" ({', '.join(filled)})" if filled else "")
                    + ". Deterministic findings were never overruled."
                ),
            ]
        except Exception as exc:
            self.filled_fields = []
            baseline.provenance.parser_name = self.name
            baseline.provenance.parser_version = (
                f"{self.version} ({deterministic.name} v{deterministic.version})"
            )
            baseline.provenance.warnings = [
                *baseline.provenance.warnings,
                f"Hybrid parse: LLM is unavailable or failed ({exc}). Remaining gaps left as NEEDS_REVIEW."
            ]
        return baseline
