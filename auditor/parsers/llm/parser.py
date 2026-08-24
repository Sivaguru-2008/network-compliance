"""LLMParser — the fallback parser for vendors nothing deterministic handles.

It satisfies exactly the same contract as ``CiscoIOSParser``:

    parse(config_text) -> SecurityBaselineModel

so the rule engine, the rule packs, and the report layer are untouched by its
existence. What differs is provenance, not interface: every Observation it
produces is stamped ``origin=llm`` with the model's calibrated confidence, so
downstream consumers can weight, filter, or audit LLM-derived findings — and
the training loop can diff them field-by-field against deterministic output on
configs both parsers can read.

It is registered as the registry's *fallback*: it is never auto-selected while
a deterministic parser claims the configuration, and — because parsing sends
the configuration to a third-party API — auto-selection additionally requires
the caller to opt in.
"""

import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from ...models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ...models.observation import Observation
from ..base import ParserError, VendorParser, registry
from .client import LLMClient, LLMResponseError, LLMUnavailableError
from .grounding import Grounder
from .schema import LLMExtraction

# The baseline type each finding must satisfy. Also the coverage contract
# between the extraction schema and the baseline - asserted in the tests.
FIELD_TYPES: Dict[str, Any] = {
    "hostname": str,
    "telnet_enabled": bool,
    "vty_transport_input": List[str],
    "vty_exec_timeout_seconds": int,
    "ssh_enabled": bool,
    "ssh_version": int,
    "http_server_enabled": bool,
    "https_server_enabled": bool,
    "management_acl_applied": bool,
    "login_banner_present": bool,
    "enable_secret_set": bool,
    "enable_password_present": bool,
    "password_encryption": bool,
    "password_min_length": int,
    "aaa_enabled": bool,
    "snmp_communities": List[SnmpCommunity],
    "logging_enabled": bool,
    "logging_hosts": List[str],
    "logging_buffered": bool,
    "ntp_servers": List[str],
}

_FALLBACK_SCORE = 0.05
_SAFE_IDENTIFIER = re.compile(r"[^a-z0-9_]+")


@registry.register
class LLMParser(VendorParser):
    """Normalizes an arbitrary vendor's configuration using a language model."""

    name = "llm"
    vendor = "unknown"
    os_family = "unknown"
    version = "1.0.0"
    base_confidence = 0.7
    is_fallback = True

    def __init__(
        self,
        client: Optional[LLMClient] = None,
        *,
        min_confidence: float = 0.6,
        trust_absence_claims: bool = False,
        field_thresholds: Optional[Dict[str, float]] = None,
        training_dir: Optional[Path] = None,
        mapping_store: Optional[Any] = None,
    ) -> None:
        self._client = client
        self.min_confidence = min_confidence
        self.trust_absence_claims = trust_absence_claims
        self.field_thresholds = dict(field_thresholds or {})
        self.training_dir = Path(training_dir) if training_dir else Path("training")
        self.mapping_store = mapping_store

    # -- detection ---------------------------------------------------------

    @classmethod
    def detect(cls, config_text: str) -> float:
        """A constant floor: this parser claims anything, but only ever last.

        The registry keeps fallback parsers out of normal ranking, so this
        score is informational. Returning a small constant rather than
        competing on pattern matching is the point — a deterministic parser
        that recognises the syntax should always win.
        """
        return _FALLBACK_SCORE if config_text and config_text.strip() else 0.0

    # -- entry point -------------------------------------------------------

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        # Load mapping store
        if self.mapping_store is None:
            from ...training.mappings import LearnedMappingStore
            store_path = self.training_dir / "learned_mappings.jsonl"
            self.mapping_store = LearnedMappingStore(store_path)

        # Detect matching mappings to see if we can resolve the vendor and fields without calling the LLM
        from ...training.mappings import resolve_learned_mappings, get_unrecognized_lines, check_all_unrecognized_lines_matched
        import hashlib
        
        approved = self.mapping_store.get_active_approved_mappings()
        matching_mappings = []
        lines = config_text.splitlines()
        for mapping in approved:
            for line in lines:
                line_stripped = line.strip()
                if not line_stripped:
                    continue
                matched = False
                if mapping.extraction_strategy == "regex":
                    try:
                        if re.search(mapping.regex_pattern, line_stripped):
                            matched = True
                    except Exception:
                        pass
                else:
                    if line_stripped.startswith(mapping.pattern) or mapping.pattern in line_stripped:
                        matched = True
                if matched:
                    matching_mappings.append(mapping)
                    break

        if matching_mappings:
            vendors = [m.vendor for m in matching_mappings]
            detected_vendor = max(set(vendors), key=vendors.count)
            os_families = [m.os_family for m in matching_mappings if m.vendor == detected_vendor]
            detected_os = max(set(os_families), key=os_families.count) if os_families else "unknown"

            dummy_baseline = SecurityBaselineModel(
                provenance=ParserProvenance(
                    parser_name=self.name,
                    parser_version=self.version,
                    vendor=detected_vendor,
                    os_family=detected_os,
                    detection_confidence=1.0,
                ),
                source_file=source_file,
                source_sha256=hashlib.sha256(config_text.encode("utf-8", errors="replace")).hexdigest(),
                config_line_count=len(lines),
            )

            unrecognized = get_unrecognized_lines(config_text, dummy_baseline)
            vendor_approved = [m for m in approved if m.vendor.lower() == detected_vendor.lower()]
            all_matched = check_all_unrecognized_lines_matched(unrecognized, vendor_approved)

            stats_path = self.training_dir / "stats.json"
            resolved_baseline = resolve_learned_mappings(config_text, dummy_baseline, self.mapping_store, stats_path=stats_path)

            fields = SecurityBaselineModel.observable_fields()
            gaps = [f for f in fields if not getattr(resolved_baseline, f).detected]
            if all_matched or not gaps:
                # All unrecognized lines resolved by approved mappings! Return immediately, avoiding LLM call!
                return resolved_baseline

        # Fallback to LLM call
        client = self._resolve_client()
        try:
            extraction = client.extract(config_text)
        except (LLMUnavailableError, LLMResponseError) as exc:
            raise ParserError(str(exc)) from exc

        grounder = Grounder(
            config_text,
            min_confidence=self.min_confidence,
            trust_absence_claims=self.trust_absence_claims,
            field_thresholds=self.field_thresholds,
        )

        baseline = SecurityBaselineModel(
            provenance=ParserProvenance(
                parser_name=self.name,
                parser_version=self.version,
                vendor=_sanitize(extraction.vendor) or "unknown",
                os_family=_sanitize(extraction.os_family) or "unknown",
                detection_confidence=max(0.0, min(1.0, extraction.identification_confidence)),
            ),
            source_file=source_file,
            source_sha256=hashlib.sha256(config_text.encode("utf-8", errors="replace")).hexdigest(),
            config_line_count=len(config_text.splitlines()),
        )

        for field, value_type in FIELD_TYPES.items():
            finding = getattr(extraction, field)
            setattr(baseline, field, grounder.observe(field, finding, value_type))

        # Overlay approved learned mappings
        stats_path = self.training_dir / "stats.json"
        baseline = resolve_learned_mappings(config_text, baseline, self.mapping_store, stats_path=stats_path)

        baseline.provenance.warnings = [
            f"Parsed by a language model ({client.description}); every finding is "
            "checked against the configuration text before it is accepted.",
            *grounder.warnings,
        ]
        self._warn_if_mostly_undetermined(baseline)
        return baseline

    # -- helpers -----------------------------------------------------------

    def _resolve_client(self) -> LLMClient:
        if self._client is not None:
            return self._client
        from .client import AnthropicClient  # deferred: keeps `anthropic` optional

        try:
            self._client = AnthropicClient()
        except LLMUnavailableError as exc:
            raise ParserError(str(exc)) from exc
        return self._client

    @staticmethod
    def _warn_if_mostly_undetermined(baseline: SecurityBaselineModel) -> None:
        """Say so plainly when the model understood little of this configuration."""
        fields = SecurityBaselineModel.observable_fields()
        undetected = [f for f in fields if not getattr(baseline, f).detected]
        if len(undetected) > len(fields) / 2:
            baseline.provenance.warnings.append(
                f"{len(undetected)} of {len(fields)} settings could not be established from this "
                "configuration. Treat this audit as indicative only and review the device manually."
            )


def _sanitize(text: str) -> str:
    """Model-supplied vendor/os strings become identifiers in report paths and lookups."""
    return _SAFE_IDENTIFIER.sub("_", (text or "").strip().lower()).strip("_")[:32]


__all__ = ["LLMParser", "FIELD_TYPES"]
