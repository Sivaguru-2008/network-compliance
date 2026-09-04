"""NLP preprocessing: normalization, tokenization, synonym expansion, negation detection."""

import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Synonym / abbreviation dictionaries
# ---------------------------------------------------------------------------

ABBREVIATIONS: Dict[str, str] = {
    "aaa": "authentication authorization accounting",
    "acl": "access control list",
    "ssh": "secure shell",
    "ntp": "network time protocol",
    "snmp": "simple network management protocol",
    "vty": "virtual terminal",
    "http": "hypertext transfer protocol",
    "https": "hypertext transfer protocol secure",
    "tls": "transport layer security",
    "ssl": "secure sockets layer",
    "tacacs": "terminal access controller access control system",
    "radius": "remote authentication dial in user service",
    "cli": "command line interface",
    "ip": "internet protocol",
    "mgmt": "management",
    "auth": "authentication",
    "passwd": "password",
    "pwd": "password",
    "config": "configuration",
    "configs": "configurations",
    "syslog": "system log",
    "exec": "executive",
    "min": "minimum",
    "max": "maximum",
    "len": "length",
    "sec": "seconds",
    "mins": "minutes",
    "hrs": "hours",
    "proto": "protocol",
    "ver": "version",
    "v2": "version 2",
    "v1": "version 1",
    "rw": "read write",
    "ro": "read only",
    "motd": "message of the day",
}

VENDOR_TERMS: Dict[str, str] = {
    "enable secret": "privileged credential hash",
    "enable password": "privileged credential plaintext",
    "service password-encryption": "password encryption",
    "ip ssh version": "ssh version",
    "ip http server": "http management server",
    "no ip http server": "disable http management server",
    "line vty": "virtual terminal line",
    "exec-timeout": "idle timeout",
    "login banner": "login banner",
    "banner motd": "login banner",
    "banner login": "login banner",
    "snmp-server community": "snmp community string",
    "snmp community": "snmp community string",
    "access-class": "management access control list",
    "ntp server": "ntp time source",
    "logging host": "syslog destination",
    "logging buffered": "local log buffer",
    "aaa new-model": "aaa authentication",
    "aaa authentication": "aaa authentication",
    "security passwords min-length": "password minimum length",
    "root-authentication": "privileged credential",
    "system login password": "password policy",
    "protocol-version v2": "ssh version 2",
    "system services ssh": "ssh service",
    "set system syslog host": "syslog destination",
    "set system ntp server": "ntp time source",
    "authentication-order": "aaa authentication order",
}

CONCEPT_SYNONYMS: Dict[str, List[str]] = {
    "authentication": ["auth", "login", "sign-in", "logon", "credential verification"],
    "authorization": ["authz", "access rights", "permissions"],
    "accounting": ["audit trail", "audit logging", "session accounting"],
    "password": ["passphrase", "credential", "secret", "passcode"],
    "encryption": ["hashing", "obfuscation", "ciphertext", "encrypted", "hashed", "hash"],
    "timeout": ["idle timeout", "session timeout", "inactivity timeout", "exec-timeout", "idle-timeout"],
    "banner": ["warning message", "login message", "motd", "message of the day", "legal notice", "warning banner"],
    "logging": ["syslog", "log", "audit log", "event log", "system log"],
    "community": ["community string", "community name"],
    "access control list": ["acl", "filter", "firewall filter", "access list", "packet filter"],
    "management": ["admin", "administrative", "device management"],
    "ntp": ["time synchronization", "clock synchronization", "time source", "time server"],
    "ssh": ["secure shell", "ssh access", "ssh protocol"],
    "snmp": ["simple network management protocol", "snmp agent", "network monitoring protocol"],
    "http": ["web server", "web management", "http server", "web interface", "web gui"],
    "telnet": ["cleartext remote access", "unencrypted terminal"],
    "privileged": ["enable", "root", "superuser", "admin", "elevated"],
}

NEGATION_WORDS: FrozenSet[str] = frozenset({
    "no", "not", "don't", "dont", "doesn't", "doesnt",
    "shouldn't", "shouldnt", "must not", "mustn't", "mustn",
    "never", "disable", "disabled", "disallow", "disallowed",
    "prevent", "prohibit", "prohibited", "forbid", "forbidden",
    "remove", "unset", "block", "deny", "denied", "reject",
    "without", "absence", "absent", "lack", "eliminate",
    "turn off", "shut off", "deactivate", "deactivated",
})

POSITIVE_WORDS: FrozenSet[str] = frozenset({
    "enable", "enabled", "activate", "activated", "allow", "allowed",
    "require", "required", "must", "shall", "should", "ensure",
    "configure", "configured", "set", "enforce", "enforced",
    "turn on", "mandate", "mandated", "implement", "implemented",
    "verify", "present", "apply", "applied", "restrict", "restricted",
})

REQUIREMENT_SPLITTERS = re.compile(
    r"(?:\.\s+(?=[A-Z]))"           # period + space + capital letter
    r"|(?:;\s*)"                     # semicolons
    r"|(?:\band\b\s+(?=\b(?:"       # "and" before a new requirement verb
    r"ensure|require|disable|enable|configure|set|enforce|verify|restrict"
    r"|block|prevent|remove|use|deploy|implement|mandate"
    r")\b))",
    re.IGNORECASE,
)


@dataclass
class Token:
    text: str
    lower: str
    is_negation: bool = False
    is_number: bool = False
    numeric_value: Optional[float] = None


@dataclass
class PreprocessedText:
    original: str
    normalized: str
    normalized_expanded: str = ""
    tokens: List[Token] = field(default_factory=list)
    expanded_synonyms: Dict[str, List[str]] = field(default_factory=dict)
    detected_negations: List[str] = field(default_factory=list)
    detected_vendor_terms: List[str] = field(default_factory=list)
    numeric_params: Dict[str, float] = field(default_factory=dict)


def normalize(text: str) -> str:
    """Lowercase, collapse whitespace, strip punctuation except hyphens in compound terms."""
    text = text.strip()
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r"[''`]", "'", text)
    text = re.sub(r'["""]', '"', text)
    text = re.sub(r"[^\w\s\-./']", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def tokenize(text: str) -> List[Token]:
    """Split normalized text into tokens with metadata."""
    words = text.split()
    tokens = []
    for w in words:
        is_neg = w in NEGATION_WORDS
        num_val = None
        is_num = False
        try:
            num_val = float(w)
            is_num = True
        except ValueError:
            pass
        tokens.append(Token(text=w, lower=w.lower(), is_negation=is_neg,
                            is_number=is_num, numeric_value=num_val))
    return tokens


def expand_vendor_terms(text: str) -> Tuple[str, List[str]]:
    """Replace vendor-specific CLI syntax with generic security concepts."""
    detected = []
    result = text
    for vendor_term, generic in sorted(VENDOR_TERMS.items(), key=lambda x: -len(x[0])):
        if vendor_term in result:
            detected.append(vendor_term)
            result = result.replace(vendor_term, generic)
    return result, detected


def expand_abbreviations(text: str) -> str:
    """Expand known abbreviations to full forms."""
    words = text.split()
    expanded = []
    for w in words:
        if w in ABBREVIATIONS:
            expanded.append(ABBREVIATIONS[w])
        else:
            expanded.append(w)
    return " ".join(expanded)


def detect_negation_scope(tokens: List[Token]) -> List[str]:
    """Identify negation words and phrases in the token stream."""
    negations = []
    text = " ".join(t.lower for t in tokens)
    for phrase in sorted(NEGATION_WORDS, key=lambda x: -len(x)):
        if " " in phrase and phrase in text:
            negations.append(phrase)
    for t in tokens:
        if t.lower in NEGATION_WORDS and t.lower not in negations:
            negations.append(t.lower)
    return negations


def extract_numeric_params(text: str) -> Dict[str, float]:
    """Extract numeric parameters with their context (e.g. 'timeout 600 seconds')."""
    params = {}
    patterns = [
        (r"(\d+)\s*(?:seconds?|secs?)\b", "seconds"),
        (r"(\d+)\s*(?:minutes?|mins?)\b", "minutes"),
        (r"(\d+)\s*(?:hours?|hrs?)\b", "hours"),
        (r"(\d+)\s*(?:characters?|chars?)\b", "characters"),
        (r"(?:version|ver\.?|v)\s*(\d+)", "version"),
        (r"(?:minimum|min\.?)\s*(?:length|len\.?)?\s*(?:of\s+)?(\d+)", "min_length"),
        (r"(?:at\s+least|>=?|minimum)\s*(\d+)", "minimum"),
        (r"(?:at\s+most|<=?|maximum|no\s+more\s+than|within)\s*(\d+)", "maximum"),
        (r"(?:length|len)\s+(?:of\s+)?(\d+)", "length"),
        (r"(\d+)\s+(?:or\s+more|minimum|\+)", "minimum"),
    ]
    for pattern, key in patterns:
        m = re.search(pattern, text, re.IGNORECASE)
        if m:
            val = float(m.group(1))
            if key == "minutes":
                params["seconds"] = val * 60
            elif key == "hours":
                params["seconds"] = val * 3600
            else:
                params[key] = val
    return params


def split_requirements(text: str) -> List[str]:
    """Split a multi-requirement input into individual requirements."""
    text = text.strip()
    if not text:
        return []
    parts = REQUIREMENT_SPLITTERS.split(text)
    results = []
    for part in parts:
        part = part.strip()
        if part and len(part) > 3:
            results.append(part)
    return results if results else [text]


def preprocess(text: str) -> PreprocessedText:
    """Full preprocessing pipeline: normalize, expand, tokenize, extract."""
    if not text or not text.strip():
        return PreprocessedText(original=text or "", normalized="")

    norm = normalize(text)
    vendor_expanded, vendor_terms = expand_vendor_terms(norm)
    fully_expanded = expand_abbreviations(vendor_expanded)
    tokens = tokenize(vendor_expanded)
    negations = detect_negation_scope(tokens)
    numerics = extract_numeric_params(norm)

    synonym_hits: Dict[str, List[str]] = {}
    for concept, syns in CONCEPT_SYNONYMS.items():
        found = [s for s in syns if s in vendor_expanded]
        if found:
            synonym_hits[concept] = found

    return PreprocessedText(
        original=text,
        normalized=vendor_expanded,
        normalized_expanded=fully_expanded,
        tokens=tokens,
        expanded_synonyms=synonym_hits,
        detected_negations=negations,
        detected_vendor_terms=vendor_terms,
        numeric_params=numerics,
    )
