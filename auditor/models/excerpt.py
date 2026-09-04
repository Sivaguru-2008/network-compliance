"""Intelligent Partial-Configuration and Excerpt Detection.

Analyzes ingested network configurations to determine whether the text represents
a complete running-config or an isolated excerpt / snippet. This helps prevent
false-negative or false-positive compliance verdicts caused by truncated configurations.
"""

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import List, Optional


class CompletenessStatus(str, Enum):
    """Classification of configuration completeness."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"


@dataclass
class ExcerptAssessment:
    """Assessment of configuration completeness."""

    status: CompletenessStatus = CompletenessStatus.COMPLETE
    is_partial: bool = False
    confidence: float = 1.0  # 1.0 = completely sure it is full / partial
    completeness_score: Optional[float] = 1.0  # 0.0 to 1.0, or None when truncated
    detected_sections: List[str] = field(default_factory=list)
    missing_sections: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    reason: Optional[str] = None
    truncation_detected: bool = False
    unterminated_block_detected: bool = False

    def disclaimer(self) -> Optional[str]:
        """Returns a user-facing warning if the configuration is partial."""
        if not self.is_partial and self.status is CompletenessStatus.COMPLETE:
            return None
        joined_reasons = "; ".join(self.reasons) if self.reasons else "Incomplete configuration provided"
        if self.truncation_detected:
            return (
                f"PARTIAL CONFIGURATION DETECTED: {joined_reasons}. "
                "Explicit truncation marker detected; configuration cannot be classified as complete."
            )
        if self.status is CompletenessStatus.INVALID:
            return f"INVALID CONFIGURATION DETECTED: {joined_reasons}."
        if self.completeness_score is not None:
            score_disp = min(self.completeness_score, 0.85) if self.is_partial else self.completeness_score
            return (
                f"PARTIAL CONFIGURATION DETECTED (Completeness: {score_disp:.0%}): "
                f"{joined_reasons}. Compliance findings may contain unverified controls."
            )
        return f"PARTIAL CONFIGURATION DETECTED: {joined_reasons}."

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "score": self.completeness_score,
            "reason": self.reason or (self.reasons[0] if self.reasons else None),
            "reasons": self.reasons,
            "truncation_detected": self.truncation_detected,
            "detected_sections": self.detected_sections,
            "missing_sections": self.missing_sections,
        }


def assess_configuration_completeness(config_text: str, vendor: Optional[str] = None) -> ExcerptAssessment:
    """Analyze text to determine if it is a complete running-config or a snippet.

    Checks:
    1. Line count thresholds.
    2. Presence of global system identifiers (hostname, version/header).
    3. Structural block markers (management, AAA, logging, interfaces).
    4. Explicit truncation markers (e.g., '...', '[truncated]', '[edit]').
    5. Unterminated hierarchical blocks (e.g. unbalanced braces).
    """
    if not config_text or not config_text.strip():
        reasons = ["Empty configuration provided"]
        return ExcerptAssessment(
            status=CompletenessStatus.INVALID,
            is_partial=True,
            confidence=1.0,
            completeness_score=0.0,
            reasons=reasons,
            reason=reasons[0],
            truncation_detected=False,
        )

    lines = [ln.strip() for ln in config_text.splitlines() if ln.strip() and not ln.strip().startswith("!")]
    line_count = len(lines)
    reasons: List[str] = []
    detected: List[str] = []
    missing: List[str] = []
    truncation_detected = False
    unterminated_block_detected = False

    # 1. Explicit truncation markers
    truncation_patterns = [
        r"(?:^|\s)\.\.\.(?:\s|$)",
        r"\[truncated\]",
        r"\[output omitted\]",
        r"--- cut ---",
        r"<snip>",
        r"\[snip\]",
        r"#\s*more\b",
    ]
    for pat in truncation_patterns:
        if re.search(pat, config_text, re.IGNORECASE | re.MULTILINE):
            truncation_detected = True
            reasons.append(f"Explicit truncation marker found matching '{pat}'")

    # 2. Check for unbalanced hierarchical blocks in curly-brace or block-structured configs
    open_braces = config_text.count("{")
    close_braces = config_text.count("}")
    if open_braces > close_braces:
        unterminated_block_detected = True
        reasons.append(f"Unterminated hierarchical block detected ({open_braces} open '{{' vs {close_braces} close '}}')")

    # 3. Hostname / system header detection
    has_hostname = bool(re.search(r"^(sysname|hostname|host-name|set\s+system\s+host-name)\s+\S+", config_text, re.MULTILINE | re.IGNORECASE))
    if has_hostname:
        detected.append("hostname")
    else:
        missing.append("hostname")

    # 4. Management / AAA / Admin sections
    has_mgmt = bool(re.search(r"(line\s+vty|system\s+services|config\s+system\s+admin|management-api|user-interface\s+vty|ssh\s+\S+|http\s+server)", config_text, re.IGNORECASE))
    if has_mgmt:
        detected.append("management_lines")
    else:
        missing.append("management_lines")

    has_logging = bool(re.search(r"(logging\s+(host|buffered|trap|enable)|set\s+system\s+syslog|config\s+log|info-center)", config_text, re.IGNORECASE))
    if has_logging:
        detected.append("logging")
    else:
        missing.append("logging")

    has_interfaces = bool(re.search(r"(interface\s+\S+|interfaces\s*\{|config\s+system\s+interface|PORT\b)", config_text, re.IGNORECASE))
    if has_interfaces:
        detected.append("interfaces")

    # 5. Score calculation
    score = 0.0
    if line_count >= 25:
        score += 0.4
    elif line_count >= 10:
        score += 0.2
    else:
        score += 0.05
        reasons.append(f"Very short configuration ({line_count} non-comment lines)")

    if has_hostname:
        score += 0.3
    if has_mgmt:
        score += 0.15
    if has_logging:
        score += 0.15

    # Check for single-feature excerpt pattern
    if detected == ["interfaces"] and line_count < 25:
        reasons.append("Configuration contains only interface block without system definitions")
        score = min(score, 0.2)

    # Truncation or unterminated block overrides completeness
    if truncation_detected:
        status = CompletenessStatus.PARTIAL
        is_partial = True
        completeness_score = None
    elif unterminated_block_detected:
        status = CompletenessStatus.PARTIAL
        is_partial = True
        completeness_score = min(score, 0.5)
    elif score < 0.6 or len(reasons) > 0:
        status = CompletenessStatus.PARTIAL
        is_partial = True
        completeness_score = min(score, 0.85)
    else:
        status = CompletenessStatus.COMPLETE
        is_partial = False
        completeness_score = 1.0

    primary_reason = reasons[0] if reasons else "Configuration appears structurally complete"

    return ExcerptAssessment(
        status=status,
        is_partial=is_partial,
        confidence=0.95 if truncation_detected else (0.9 if reasons else 0.85),
        completeness_score=completeness_score,
        detected_sections=detected,
        missing_sections=missing,
        reasons=reasons if reasons else ["Configuration appears structurally complete"],
        reason=primary_reason,
        truncation_detected=truncation_detected,
        unterminated_block_detected=unterminated_block_detected,
    )
