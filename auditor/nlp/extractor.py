"""Intent, entity, and parameter extraction from preprocessed requirement text."""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from .preprocessor import PreprocessedText, NEGATION_WORDS, POSITIVE_WORDS


class Intent(str, Enum):
    ENFORCE = "ENFORCE"
    PROHIBIT = "PROHIBIT"
    CONFIGURE = "CONFIGURE"
    VERIFY = "VERIFY"
    UNKNOWN = "UNKNOWN"


@dataclass
class SecurityEntity:
    """A security-relevant concept extracted from the requirement text."""
    concept: str
    source_span: str
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExtractionResult:
    """Output of the extraction phase."""
    intent: Intent
    is_negative_requirement: bool
    entities: List[SecurityEntity] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    source_text: str = ""


# Maps surface-form keywords to the security concept they indicate.
# Each concept aligns with one or more control IDs in security_controls.json.
CONCEPT_KEYWORDS: Dict[str, List[str]] = {
    "aaa": [
        "aaa", "authentication authorization accounting",
        "centralized authentication", "central authentication",
        "radius", "tacacs", "authentication server",
        "aaa new-model", "aaa authentication",
        "remote authentication", "central auth",
    ],
    "vty_transport": [
        "vty transport", "virtual terminal transport",
        "transport input", "secure transport",
        "management transport", "remote access protocol",
        "console transport", "admin access protocol",
        "secure protocol only", "secure protocols only",
        "management protocol", "encrypted protocol",
        "encrypted remote", "remote administration",
    ],
    "telnet": [
        "telnet", "cleartext remote", "unencrypted terminal",
        "cleartext protocol", "plaintext access",
        "insecure remote access",
    ],
    "idle_timeout": [
        "idle timeout", "session timeout", "inactivity timeout",
        "exec timeout", "exec-timeout", "vty timeout",
        "idle session", "automatic disconnect",
        "session idle", "automatic logout",
        "idle timer", "session expiry", "vty idle",
    ],
    "enable_secret": [
        "enable secret", "privileged credential",
        "privileged exec password", "enable password",
        "root authentication", "root password", "root credential",
        "privileged password", "admin password hash",
        "privileged access credential",
    ],
    "password_encryption": [
        "password encryption", "service password-encryption",
        "encrypt password", "hash password", "password hashing",
        "password obfuscation", "credential encryption",
        "stored password", "password at rest",
        "plaintext password", "cleartext password",
    ],
    "snmp_default": [
        "default snmp community", "snmp community public",
        "snmp community private", "well-known community",
        "default community string", "snmp public",
        "snmp private", "default snmp",
        "community string public", "community string private",
        "default community", "community default",
        "community public", "community private",
        "snmp community string",
    ],
    "snmp_write": [
        "snmp read-write", "snmp rw", "snmp write access",
        "read-write community", "rw community",
        "write community", "snmp write",
        "read write snmp", "snmp read write",
        "read-write snmp", "read-write communities",
    ],
    "http_server": [
        "http server", "http management", "web server",
        "web management", "http service",
        "http interface", "web interface",
        "web gui", "management http",
        "unencrypted http", "unencrypted web",
        "http access", "hypertext transfer protocol",
    ],
    "ssh_version": [
        "ssh version", "ssh protocol version",
        "ssh v2", "ssh version 2", "sshv2",
        "secure shell version", "ssh protocol",
    ],
    "logging": [
        "logging", "syslog", "log destination",
        "log host", "logging host", "audit log",
        "event logging", "system log",
        "remote logging", "log server",
        "logging destination", "log buffer",
    ],
    "management_acl": [
        "management acl", "management access control",
        "access control list", "source ip restriction",
        "management filter", "admin access restriction",
        "management plane filter", "restrict management",
        "restrict admin", "authorized source",
        "source subnet", "management restriction",
        "restrict access by ip", "restrict access by source",
        "lo0 filter", "loopback filter",
        "administrative access", "limited to specific ip",
        "limited to ip", "limit access",
    ],
    "login_banner": [
        "login banner", "banner motd", "warning banner",
        "legal notice", "unauthorized access warning",
        "pre-login banner", "banner message",
        "message of the day", "access warning",
        "login warning", "authorization warning",
        "legal banner", "warning message",
        "login prompt",
    ],
    "password_min_length": [
        "password minimum length", "password min length",
        "minimum password length", "password length",
        "password policy length", "password complexity",
        "password requirement", "short password",
        "character minimum", "characters long",
        "password characters", "password minimum",
        "passphrase length", "passphrase minimum",
        "minimum passphrase",
    ],
    "ntp": [
        "ntp", "time synchronization", "time server",
        "network time protocol", "clock synchronization",
        "time source", "ntp server", "time sync",
    ],
}


def _classify_intent(preprocessed: PreprocessedText) -> Intent:
    """Determine the intent (enforce, prohibit, configure, verify) from the text."""
    text = preprocessed.normalized
    negations = preprocessed.detected_negations

    strong_prohibit = [
        r"\b(?:must\s+not|should\s+not|shall\s+not|do\s+not|cannot)\b",
        r"\b(?:disable|disallow|prohibit|prevent|forbid)\b",
        r"\b(?:unset|eliminate|turn\s+off|shut\s+off|deactivate)\b",
    ]
    for pat in strong_prohibit:
        if re.search(pat, text):
            return Intent.PROHIBIT

    enforce_patterns = [
        r"\b(?:enable|require|must|shall|should|enforce|mandate|ensure|restrict)\b",
        r"\b(?:configure|set|apply|implement|deploy|activate|turn\s+on)\b",
        r"\b(?:verify|check|validate|confirm|assert)\b",
    ]
    weak_prohibit = [
        r"\bno\s+(?:snmp|telnet|http|default|write|read-write|cleartext|plaintext)\b",
        r"\b(?:deny|block|reject|remove)\b",
    ]

    has_enforce = any(re.search(p, text) for p in enforce_patterns)
    has_weak_prohibit = any(re.search(p, text) for p in weak_prohibit)

    if has_weak_prohibit and not has_enforce:
        return Intent.PROHIBIT

    if negations and not has_enforce:
        return Intent.PROHIBIT

    if has_enforce:
        if re.search(r"\b(?:verify|check|validate|confirm|assert)\b", text):
            return Intent.VERIFY
        return Intent.ENFORCE

    return Intent.UNKNOWN


def _is_negative_requirement(preprocessed: PreprocessedText, intent: Intent) -> bool:
    """Determine if the requirement asks for something to NOT be present/enabled."""
    if intent == Intent.PROHIBIT:
        return True
    text = preprocessed.normalized
    neg_patterns = [
        r"\b(?:no|not|don't|disable|disallow|prevent|block|remove|without)\b.*\b(?:snmp|telnet|http|community|password|access)\b",
        r"\b(?:must\s+not|should\s+not|shall\s+not)\b",
    ]
    for pat in neg_patterns:
        if re.search(pat, text):
            return True
    return bool(preprocessed.detected_negations) and intent == Intent.UNKNOWN


def _phrase_match(phrase: str, text: str) -> bool:
    """Check if a keyword phrase matches the text.

    Single words use word-boundary matching. Multi-word phrases try substring
    matching first, then check if all phrase words appear in the text in order
    (allowing gaps of up to 4 intervening words).
    """
    if " " not in phrase:
        return bool(re.search(r"\b" + re.escape(phrase) + r"\b", text))
    if phrase in text:
        return True
    parts = phrase.split()
    pat = r"\b" + r"\b(?:\s+\S+){0,4}\s+\b".join(re.escape(p) for p in parts) + r"\b"
    return bool(re.search(pat, text))


def _extract_entities(preprocessed: PreprocessedText) -> List[SecurityEntity]:
    """Identify security concepts from the preprocessed text."""
    text = preprocessed.normalized
    entities = []
    seen_concepts: Set[str] = set()

    for concept, keywords in CONCEPT_KEYWORDS.items():
        for kw in keywords:
            if _phrase_match(kw, text) and concept not in seen_concepts:
                params: Dict[str, Any] = {}
                if concept == "ssh_version":
                    m = re.search(r"version\s*(\d+)", text)
                    if m:
                        params["version"] = int(m.group(1))
                    elif "v2" in text or "version 2" in text:
                        params["version"] = 2
                elif concept == "idle_timeout":
                    if "seconds" in preprocessed.numeric_params:
                        params["timeout_seconds"] = preprocessed.numeric_params["seconds"]
                    elif "maximum" in preprocessed.numeric_params:
                        params["timeout_seconds"] = preprocessed.numeric_params["maximum"]
                    elif "minimum" in preprocessed.numeric_params:
                        params["timeout_seconds"] = preprocessed.numeric_params["minimum"]
                elif concept == "password_min_length":
                    for k in ("min_length", "minimum", "length", "characters"):
                        if k in preprocessed.numeric_params:
                            params["min_length"] = int(preprocessed.numeric_params[k])
                            break

                entities.append(SecurityEntity(
                    concept=concept,
                    source_span=kw,
                    parameters=params,
                ))
                seen_concepts.add(concept)
                break

    return entities


def extract(preprocessed: PreprocessedText) -> ExtractionResult:
    """Run full extraction on preprocessed text."""
    intent = _classify_intent(preprocessed)
    is_neg = _is_negative_requirement(preprocessed, intent)
    entities = _extract_entities(preprocessed)

    return ExtractionResult(
        intent=intent,
        is_negative_requirement=is_neg,
        entities=entities,
        parameters=preprocessed.numeric_params,
        source_text=preprocessed.original,
    )
