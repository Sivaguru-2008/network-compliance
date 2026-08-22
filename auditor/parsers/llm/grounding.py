"""Verification of model claims against the actual configuration text.

This is the load-bearing part of the LLM parser. A language model can produce a
fluent, plausible, correctly-typed claim about a line that does not exist. If
such a claim reached a verdict, the report would cite evidence the device never
had — the worst possible failure for an audit tool, because it is invisible.

So nothing the model says is trusted on its own. Every claim passes three
gates before it becomes an ``Observation``:

1. **Confidence** — below the caller's threshold, the claim is discarded.
2. **Grounding** — a cited line must actually occur in the configuration. The
   line stored on the Observation is then the text *from the file*, not the
   model's copy of it, so a report can never display a line the device lacks.
3. **Type** — the value must satisfy the baseline's schema for that field.

A claim that fails any gate is not deleted and is not believed: it degrades to
``detected=False``, which the engine reports as NEEDS_REVIEW. Every degradation
is recorded as a parser warning, so a hallucinating model shows up in the
report as review load rather than as silent wrong answers.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

from pydantic import ValidationError

from ...models.baseline import SnmpCommunity
from ...models.observation import Observation, Origin
from .schema import SnmpCommunityFinding, _Finding

_WHITESPACE = re.compile(r"\s+")


def _normalize(line: str) -> str:
    """Collapse whitespace and case so trivial reformatting still matches."""
    return _WHITESPACE.sub(" ", line.strip()).casefold()


class GroundingIndex:
    """Lookup from a claimed configuration line to its real position in the file."""

    def __init__(self, config_text: str) -> None:
        self._lines = config_text.splitlines()
        self._exact: Dict[str, int] = {}
        self._normalized: Dict[str, int] = {}
        for offset, raw in enumerate(self._lines):
            stripped = raw.strip()
            if not stripped:
                continue
            self._exact.setdefault(stripped, offset + 1)
            self._normalized.setdefault(_normalize(raw), offset + 1)

    def locate(self, claimed: str) -> Optional[Tuple[int, str]]:
        """Return the (1-based line number, verbatim line) for a claimed line, if it exists."""
        if not claimed or not claimed.strip():
            return None
        stripped = claimed.strip()
        line_number = self._exact.get(stripped) or self._normalized.get(_normalize(claimed))
        if line_number is None:
            return None
        return line_number, self._lines[line_number - 1].strip()


class Grounder:
    """Applies the confidence, grounding, and type gates to model claims."""

    def __init__(
        self,
        config_text: str,
        *,
        min_confidence: float = 0.6,
        trust_absence_claims: bool = False,
    ) -> None:
        self.index = GroundingIndex(config_text)
        self.min_confidence = min_confidence
        # Absence is only evidence when you know the platform's defaults and
        # NVGEN behaviour. For an unknown vendor we do not, so by default an
        # "it isn't configured" claim escalates instead of failing the device.
        # A later step can enable this per vendor once semantics are known.
        self.trust_absence_claims = trust_absence_claims
        self.warnings: List[str] = []

    def _warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    def observe(self, field: str, finding: _Finding, value_type: Any) -> Observation:
        """Turn one model claim into a verified (or degraded) Observation."""
        confidence = max(0.0, min(1.0, finding.confidence))
        reasoning = (finding.reasoning or "").strip()

        if not finding.determined:
            return Observation[value_type].unknown(
                f"Model could not determine this setting. {reasoning}".strip()
            )

        if confidence < self.min_confidence:
            note = (
                f"Model reported this setting with confidence {confidence:.2f}, below the "
                f"{self.min_confidence:.2f} threshold, so it was not accepted. {reasoning}"
            ).strip()
            self._warn(f"{field}: discarded low-confidence claim ({confidence:.2f}).")
            return Observation[value_type].unknown(note)

        value = finding.value
        if value is None:
            self._warn(f"{field}: model claimed the setting was determined but returned no value.")
            return Observation[value_type].unknown(
                f"Model reported this setting as determined but supplied no value. {reasoning}".strip()
            )

        if isinstance(finding, SnmpCommunityFinding):
            return self._observe_communities(field, finding, confidence, reasoning)

        if finding.source_line is None:
            return self._observe_absence_claim(field, value, value_type, confidence, reasoning)

        located = self.index.locate(finding.source_line)
        if located is None:
            self._warn(
                f"{field}: rejected an ungrounded claim - the model cited "
                f"{finding.source_line.strip()!r}, which is not in the configuration."
            )
            return Observation[value_type].unknown(
                "Model cited a configuration line that does not appear in the file "
                f"({finding.source_line.strip()!r}), so the claim was rejected as ungrounded."
            )

        line_number, verbatim = located
        return self._build(field, value, value_type, verbatim, line_number, confidence, reasoning)

    # -- individual gates --------------------------------------------------

    def _observe_absence_claim(
        self, field: str, value: Any, value_type: Any, confidence: float, reasoning: str
    ) -> Observation:
        """A claim resting on a line *not* being there."""
        if not self.trust_absence_claims:
            self._warn(f"{field}: escalated an absence-based claim (no citable configuration line).")
            return Observation[value_type].unknown(
                "Model inferred this from the absence of a configuration line. Absence is only "
                "evidence when the platform's defaults are known, and they are not for this "
                f"vendor, so the finding was escalated for review. {reasoning}".strip()
            )
        try:
            return Observation[value_type].absent(
                value,
                f"Model reports this setting is not configured. {reasoning}".strip(),
                origin=Origin.LLM,
            )
        except ValidationError:
            return self._type_failure(field, value, value_type)

    def _build(
        self,
        field: str,
        value: Any,
        value_type: Any,
        verbatim: str,
        line_number: int,
        confidence: float,
        reasoning: str,
    ) -> Observation:
        try:
            return Observation[value_type].found(
                value,
                verbatim,
                line_number,
                note=reasoning or None,
                origin=Origin.LLM,
                confidence=confidence,
            )
        except ValidationError:
            return self._type_failure(field, value, value_type)

    def _type_failure(self, field: str, value: Any, value_type: Any) -> Observation:
        self._warn(f"{field}: rejected a value of the wrong type ({value!r}).")
        return Observation[value_type].unknown(
            f"Model returned {value!r}, which does not satisfy this field's type, so it was rejected."
        )

    def _observe_communities(
        self, field: str, finding: SnmpCommunityFinding, confidence: float, reasoning: str
    ) -> Observation[List[SnmpCommunity]]:
        """SNMP communities are grounded one line at a time.

        If any single community cannot be grounded the whole finding is
        escalated rather than partially trusted: dropping an ungrounded entry
        could hide a default community (a false PASS), and keeping it could
        invent one (a false FAIL). Neither is acceptable, so a human decides.
        """
        claims = finding.value or []
        if not claims:
            if not self.trust_absence_claims:
                self._warn(f"{field}: escalated an empty-list claim (nothing to ground).")
                return Observation[List[SnmpCommunity]].unknown(
                    "Model reports no SNMP v1/v2c communities, but that rests on absence rather "
                    f"than on a citable line, so it was escalated for review. {reasoning}".strip()
                )
            return Observation[List[SnmpCommunity]].absent(
                [], f"Model reports no SNMP v1/v2c communities configured. {reasoning}".strip(), origin=Origin.LLM
            )

        communities: List[SnmpCommunity] = []
        for claim in claims:
            located = self.index.locate(claim.source_line)
            if located is None:
                self._warn(
                    f"{field}: rejected the whole finding - community {claim.name!r} cited "
                    f"{claim.source_line.strip()!r}, which is not in the configuration."
                )
                return Observation[List[SnmpCommunity]].unknown(
                    f"Model cited a line for community {claim.name!r} that does not appear in the "
                    "configuration. The SNMP finding was escalated rather than partially trusted, "
                    "because dropping the entry could hide a default community and keeping it could "
                    "invent one."
                )
            line_number, verbatim = located
            access = (claim.access or "").lower() or None
            communities.append(
                SnmpCommunity(
                    name=claim.name,
                    access=access if access in ("ro", "rw") else None,
                    acl=claim.acl,
                    view=claim.view,
                    source_line=verbatim,
                    line_number=line_number,
                )
            )

        first = communities[0]
        return Observation[List[SnmpCommunity]].found(
            communities,
            first.source_line,
            first.line_number,
            note=(reasoning or f"{len(communities)} SNMP v1/v2c community string(s) reported.").strip(),
            origin=Origin.LLM,
            confidence=confidence,
        )
