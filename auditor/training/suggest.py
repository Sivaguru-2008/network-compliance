"""AI-suggested candidate mappings for the training workflow.

When an administrator sees an unrecognized configuration line in the training
center, this module produces a candidate mapping suggestion: which baseline
field the line likely maps to, what extraction strategy and pattern to use,
and why.

The suggestion is NEVER used directly for compliance evaluation.  It
populates the mapping editor form; the administrator reviews, modifies if
needed, and approves or rejects.  Only an approved mapping enters the
compliance path through the deterministic engine.

Two suggestion paths:

1. **AI-assisted** (LLM client available): the line and its context are
   analyzed by the model, which proposes a field and explains the security
   relevance.  Pattern and extraction strategy are then derived from the
   line structure.

2. **Heuristic-only** (offline / no API key): keyword matching against known
   configuration patterns.  Less accurate, but deterministic and always
   available.
"""

import re
from dataclasses import dataclass, field as dc_field
from typing import Any, Dict, List, Optional, Tuple

from ..models.baseline import SecurityBaselineModel


@dataclass
class MappingSuggestion:
    """One candidate mapping suggestion for an unrecognized config line."""

    field: str
    pattern: str
    extraction_strategy: str
    regex_pattern: Optional[str] = None
    confidence: float = 0.0
    reasoning: str = ""
    compliance_relevance: str = ""
    source: str = "heuristic"
    alternatives: List[Dict[str, Any]] = dc_field(default_factory=list)


_OBSERVABLE = None


def _observable_fields() -> List[str]:
    global _OBSERVABLE
    if _OBSERVABLE is None:
        _OBSERVABLE = SecurityBaselineModel.observable_fields()
    return _OBSERVABLE


# ---- keyword → baseline-field heuristics --------------------------------

_KEYWORD_MAP: List[Tuple[List[str], str, str]] = [
    (["exec-timeout", "idle-timeout", "admintimeout"],
     "vty_exec_timeout_seconds", "Session idle timeout"),
    (["ssh", "ip ssh", "set admin-ssh"],
     "ssh_enabled", "SSH access control"),
    (["ssh version", "ip ssh version"],
     "ssh_version", "SSH protocol version"),
    (["transport input"],
     "vty_transport_input", "VTY transport protocols"),
    (["telnet", "set allowaccess.*telnet"],
     "telnet_enabled", "Plaintext management access"),
    (["http server", "ip http server", "no ip http server", "set admin-https"],
     "http_server_enabled", "HTTP management access"),
    (["https", "ip http secure", "set admin-https"],
     "https_server_enabled", "HTTPS management access"),
    (["access-class", "access-list", "trusted-host", "set trusthost"],
     "management_acl_applied", "Management ACL restriction"),
    (["banner", "pre-login-banner", "post-login-banner"],
     "login_banner_present", "Login banner"),
    (["enable secret", "enable password"],
     "enable_secret_set", "Privileged-mode credential"),
    (["service password-encryption", "password-encryption"],
     "password_encryption", "Password storage obfuscation"),
    (["password min-length", "min-length", "password-policy.*min"],
     "password_min_length", "Minimum password length"),
    (["aaa new-model", "aaa authentication", "set admin-auth"],
     "aaa_enabled", "AAA authentication"),
    (["snmp-server community", "snmp community"],
     "snmp_communities", "SNMP community strings"),
    (["snmp-server enable", "snmp enable", "set snmp"],
     "snmp_agent_enabled", "SNMP agent"),
    (["logging", "syslog", "log host", "config log syslogd"],
     "logging_enabled", "Logging configuration"),
    (["logging host", "logging server", "set server"],
     "logging_hosts", "Syslog destinations"),
    (["logging buffered"],
     "logging_buffered", "Local log buffer"),
    (["ntp server", "ntp peer", "set ntpserver", "set type ntp"],
     "ntp_servers", "NTP time sources"),
    (["dns", "name-server", "ip name-server", "set dns"],
     "dns_servers", "DNS servers"),
    (["usb", "auto-install"],
     "usb_auto_install_disabled", "USB auto-install"),
    (["ssl", "tls", "strong-crypto", "admin-https-ssl-versions"],
     "strong_crypto_enabled", "Strong cryptographic ciphers"),
    (["admin-sport", "admin-port", "admin-https-port"],
     "admin_default_ports_changed", "Admin port defaults"),
    (["lockout-threshold", "admin-lockout"],
     "admin_lockout_threshold", "Admin lockout threshold"),
    (["lockout-duration"],
     "admin_lockout_duration", "Admin lockout duration"),
    (["password.*upper", "min-upper"],
     "password_min_uppercase", "Password uppercase requirement"),
    (["password.*lower", "min-lower"],
     "password_min_lowercase", "Password lowercase requirement"),
    (["password.*number", "min-number", "password.*numeric"],
     "password_min_numeric", "Password numeric requirement"),
    (["password.*special", "min-non-alphanumeric"],
     "password_min_special", "Password special char requirement"),
    (["password.*expire", "max-age", "password.*age"],
     "password_max_age_days", "Password expiration policy"),
    (["password.*reuse", "reuse-limit", "password.*history"],
     "password_history_reuse_limit", "Password reuse prevention"),
    (["ha ", "high-availability", "config system ha"],
     "ha_enabled", "High availability"),
    (["security-fabric", "config system csf"],
     "security_fabric_enabled", "Security Fabric"),
    (["update-server", "set update-server-check"],
     "verify_update_server_identity", "Update server identity verification"),
    (["antivirus", "av ", "set grayware"],
     "av_grayware_enabled", "Antivirus grayware detection"),
    (["log.*encrypt", "enc-algorithm"],
     "log_encryption_enabled", "Log encryption"),
    (["eventfilter", "event logging"],
     "event_logging_enabled", "Event log filtering"),
]


def _heuristic_suggest(
    line: str, context: str, vendor: str
) -> Optional[MappingSuggestion]:
    """Keyword-match a config line against known patterns."""
    lower = line.lower().strip()
    valid = set(_observable_fields())

    best_field = None
    best_relevance = ""
    best_score = 0

    for keywords, field, relevance in _KEYWORD_MAP:
        if field not in valid:
            continue
        for kw in keywords:
            if ".*" in kw:
                if re.search(kw, lower):
                    score = len(kw)
                    if score > best_score:
                        best_score = score
                        best_field = field
                        best_relevance = relevance
            elif kw in lower:
                score = len(kw)
                if score > best_score:
                    best_score = score
                    best_field = field
                    best_relevance = relevance

    if best_field is None:
        return None

    pattern, strategy, regex = _derive_pattern(line, best_field)
    return MappingSuggestion(
        field=best_field,
        pattern=pattern,
        extraction_strategy=strategy,
        regex_pattern=regex,
        confidence=min(0.6, best_score / 30.0),
        reasoning=f"Keyword match: line contains terms associated with '{best_field}'.",
        compliance_relevance=best_relevance,
        source="heuristic",
    )


def _derive_pattern(
    line: str, field: str
) -> Tuple[str, str, Optional[str]]:
    """Given a config line and target field, choose pattern + extraction strategy."""
    stripped = line.strip()
    tokens = stripped.split()

    from ..parsers.llm.parser import FIELD_TYPES
    field_type = FIELD_TYPES.get(field, str)

    if field_type is bool:
        if len(tokens) <= 4:
            return stripped, "exact", None
        return " ".join(tokens[:3]), "exact", None

    if field_type is int:
        numbers = re.findall(r"\b(\d+)\b", stripped)
        if numbers:
            prefix_end = stripped.find(numbers[-1])
            prefix = stripped[:prefix_end].strip()
            if prefix:
                return prefix, "token", None
        if len(tokens) >= 2:
            return " ".join(tokens[:-1]), "token", None
        return stripped, "exact", None

    if field_type is str:
        if len(tokens) >= 2:
            return " ".join(tokens[:-1]), "token", None
        return stripped, "exact", None

    origin = getattr(field_type, "__origin__", None)
    if origin is list:
        if len(tokens) >= 2:
            return tokens[0], "token_list", None
        return stripped, "token_list", None

    if len(tokens) >= 2:
        return " ".join(tokens[:-1]), "token", None
    return stripped, "exact", None


# ---- AI-assisted suggestion path ----------------------------------------


def _ai_suggest(
    client: Any, line: str, context: str, vendor: str
) -> Optional[MappingSuggestion]:
    """Use an LLM client to suggest a mapping, then derive pattern/strategy."""
    from ..parsers.llm.client import LLMResponseError, LLMUnavailableError

    try:
        result = client.propose_mapping(vendor, "unknown", line)
    except (LLMUnavailableError, LLMResponseError):
        return None
    except Exception:
        return None

    if not isinstance(result, dict) or "field" not in result:
        return None

    suggested_field = result["field"]
    valid = set(_observable_fields())
    if suggested_field not in valid:
        closest = _closest_field(suggested_field, valid)
        if closest:
            suggested_field = closest
        else:
            return None

    pattern, strategy, regex = _derive_pattern(line, suggested_field)
    reasoning = result.get("reasoning", "AI model analysis.")
    relevance = result.get("compliance_relevance", "")

    return MappingSuggestion(
        field=suggested_field,
        pattern=pattern,
        extraction_strategy=strategy,
        regex_pattern=regex,
        confidence=0.75,
        reasoning=reasoning,
        compliance_relevance=relevance,
        source="ai",
    )


def _closest_field(candidate: str, valid: set) -> Optional[str]:
    """Find the closest valid field name by substring match."""
    candidate_lower = candidate.lower().replace("-", "_").replace(" ", "_")
    if candidate_lower in valid:
        return candidate_lower
    for field in sorted(valid):
        if candidate_lower in field or field in candidate_lower:
            return field
    return None


# ---- public API ---------------------------------------------------------


def suggest_mapping(
    line: str,
    context: str = "",
    vendor: str = "unknown",
    client: Any = None,
) -> MappingSuggestion:
    """Produce a mapping suggestion for an unrecognized configuration line.

    Tries the AI path first (if ``client`` is provided), then falls back to
    heuristic matching.  Always returns a suggestion — the worst case is a
    low-confidence heuristic guess that the admin will override.

    The returned suggestion is NEVER applied to the compliance engine.  It
    populates the training center's mapping editor for human review.
    """
    if client is not None:
        ai_result = _ai_suggest(client, line, context, vendor)
        if ai_result is not None:
            heuristic = _heuristic_suggest(line, context, vendor)
            if heuristic and heuristic.field != ai_result.field:
                ai_result.alternatives.append({
                    "field": heuristic.field,
                    "confidence": heuristic.confidence,
                    "source": "heuristic",
                    "reasoning": heuristic.reasoning,
                })
            return ai_result

    heuristic = _heuristic_suggest(line, context, vendor)
    if heuristic is not None:
        return heuristic

    return _fallback_suggestion(line)


def _fallback_suggestion(line: str) -> MappingSuggestion:
    """When neither AI nor heuristics match, return a minimal suggestion."""
    stripped = line.strip()
    tokens = stripped.split()
    pattern = tokens[0] if tokens else stripped
    return MappingSuggestion(
        field="",
        pattern=pattern,
        extraction_strategy="exact",
        confidence=0.0,
        reasoning="No matching pattern found. Please select the target field manually.",
        compliance_relevance="Unknown",
        source="none",
    )
