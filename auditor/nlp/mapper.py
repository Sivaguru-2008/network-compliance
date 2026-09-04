"""Requirement-to-rule mapping: scores extracted concepts against compliance controls."""

import json
import math
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .extractor import ExtractionResult, Intent, SecurityEntity

CONTROLS_PATH = Path(__file__).resolve().parent.parent / "rules" / "security_controls.json"

CONFIDENCE_THRESHOLD = 0.40
AMBIGUITY_GAP = 0.15


class MappingStatus(str, Enum):
    MAPPED = "MAPPED"
    AMBIGUOUS = "AMBIGUOUS"
    UNKNOWN = "UNKNOWN"


@dataclass
class RuleMapping:
    """A single requirement mapped to a compliance control."""
    rule_id: str
    title: str
    description: str
    confidence: float
    status: MappingStatus
    matched_concepts: List[str] = field(default_factory=list)
    is_negative: bool = False
    parameters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MappingResult:
    """Output of the mapping phase for one requirement."""
    source_text: str
    intent: Intent
    is_negative_requirement: bool
    mappings: List[RuleMapping] = field(default_factory=list)
    entities: List[SecurityEntity] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: MappingStatus = MappingStatus.UNKNOWN

    @property
    def primary_mapping(self) -> Optional[RuleMapping]:
        mapped = [m for m in self.mappings if m.status == MappingStatus.MAPPED]
        return mapped[0] if mapped else None

    @property
    def mapped_rule_ids(self) -> List[str]:
        return [m.rule_id for m in self.mappings if m.status == MappingStatus.MAPPED]


# Concept → control_id mapping. Some concepts map to multiple controls.
CONCEPT_TO_CONTROLS: Dict[str, List[str]] = {
    "aaa":                ["aaa_enabled"],
    "vty_transport":      ["secure_vty_transport"],
    "telnet":             ["secure_vty_transport"],
    "idle_timeout":       ["vty_idle_timeout"],
    "enable_secret":      ["enable_secret_encrypted"],
    "password_encryption":["enable_secret_encrypted"],
    "snmp_default":       ["no_default_snmp_community"],
    "snmp_write":         ["no_write_snmp_community"],
    "http_server":        ["http_server_disabled"],
    "ssh_version":        ["ssh_version_2"],
    "logging":            ["logging_enabled"],
    "management_acl":     ["management_acl"],
    "login_banner":       ["login_banner"],
    "password_min_length":["password_min_length"],
    "ntp":                ["ntp_configured"],
}

# Additional keywords per control for fallback TF-IDF-style scoring
CONTROL_KEYWORDS: Dict[str, Set[str]] = {
    "aaa_enabled": {
        "aaa", "authentication", "authorization", "accounting",
        "centralized", "radius", "tacacs", "login", "new-model",
    },
    "secure_vty_transport": {
        "vty", "transport", "ssh", "telnet", "cleartext",
        "secure", "protocol", "terminal", "remote", "access",
        "console", "management",
    },
    "vty_idle_timeout": {
        "idle", "timeout", "session", "inactivity", "exec",
        "disconnect", "automatic", "timer", "expiry", "vty",
    },
    "enable_secret_encrypted": {
        "enable", "secret", "password", "encryption", "hash",
        "privileged", "credential", "plaintext", "cleartext",
        "obfuscation", "hashed", "root",
    },
    "no_default_snmp_community": {
        "snmp", "community", "default", "public", "private",
        "string", "well-known",
    },
    "http_server_disabled": {
        "http", "web", "server", "management", "gui",
        "interface", "unencrypted", "disable",
    },
    "ssh_version_2": {
        "ssh", "version", "protocol", "v2", "secure", "shell",
    },
    "logging_enabled": {
        "logging", "syslog", "log", "destination", "host",
        "buffer", "audit", "event", "remote",
    },
    "management_acl": {
        "management", "acl", "access", "control", "list",
        "filter", "source", "ip", "restriction", "subnet",
        "authorized", "restrict", "loopback",
    },
    "login_banner": {
        "banner", "login", "warning", "motd", "message",
        "legal", "notice", "unauthorized", "day",
    },
    "password_min_length": {
        "password", "minimum", "length", "characters",
        "policy", "complexity", "short",
    },
    "ntp_configured": {
        "ntp", "time", "synchronization", "clock", "server",
        "source", "network", "protocol",
    },
    "no_write_snmp_community": {
        "snmp", "community", "write", "read-write", "rw",
        "access", "read", "string",
    },
}


def _load_controls() -> Dict[str, Dict[str, Any]]:
    """Load control definitions from security_controls.json."""
    with open(CONTROLS_PATH, encoding="utf-8") as f:
        return json.load(f)


def _keyword_overlap_score(text_words: Set[str], control_id: str) -> float:
    """Jaccard-like overlap between requirement words and control keywords."""
    kw = CONTROL_KEYWORDS.get(control_id, set())
    if not kw:
        return 0.0
    intersection = text_words & kw
    union = text_words | kw
    if not union:
        return 0.0
    return len(intersection) / len(union)


def _concept_match_score(
    extraction: ExtractionResult,
    control_id: str,
) -> Tuple[float, List[str]]:
    """Score based on extracted concepts matching the control."""
    matched_concepts = []
    for entity in extraction.entities:
        target_controls = CONCEPT_TO_CONTROLS.get(entity.concept, [])
        if control_id in target_controls:
            matched_concepts.append(entity.concept)

    if not matched_concepts:
        return 0.0, []

    base = 0.70
    bonus = min(0.30, len(matched_concepts) * 0.15)
    return base + bonus, matched_concepts


def map_requirement(extraction: ExtractionResult, expanded_text: str = "") -> MappingResult:
    """Map an extracted requirement to compliance controls."""
    controls = _load_controls()
    scoring_text = expanded_text or extraction.source_text
    text_words = set(scoring_text.lower().split())

    scores: List[Tuple[str, float, List[str]]] = []

    for control_id in controls:
        concept_score, matched = _concept_match_score(extraction, control_id)
        kw_score = _keyword_overlap_score(text_words, control_id)
        combined = max(concept_score, kw_score * 0.8)

        if concept_score > 0:
            combined = concept_score + kw_score * 0.2
            combined = min(combined, 1.0)

        if combined > 0.05:
            scores.append((control_id, combined, matched))

    scores.sort(key=lambda x: -x[1])

    mappings: List[RuleMapping] = []
    result_status = MappingStatus.UNKNOWN

    if not scores:
        return MappingResult(
            source_text=extraction.source_text,
            intent=extraction.intent,
            is_negative_requirement=extraction.is_negative_requirement,
            mappings=[],
            entities=extraction.entities,
            parameters=extraction.parameters,
            status=MappingStatus.UNKNOWN,
        )

    top_score = scores[0][1]

    if top_score < CONFIDENCE_THRESHOLD:
        result_status = MappingStatus.UNKNOWN
        for cid, sc, matched in scores[:3]:
            info = controls[cid]
            mappings.append(RuleMapping(
                rule_id=cid,
                title=info["title"],
                description=info["description"],
                confidence=round(sc, 4),
                status=MappingStatus.UNKNOWN,
                matched_concepts=matched,
                is_negative=extraction.is_negative_requirement,
                parameters=extraction.parameters,
            ))
    else:
        second_score = scores[1][1] if len(scores) > 1 else 0.0
        if top_score - second_score < AMBIGUITY_GAP and second_score >= CONFIDENCE_THRESHOLD:
            result_status = MappingStatus.AMBIGUOUS
            for cid, sc, matched in scores:
                if sc >= CONFIDENCE_THRESHOLD:
                    info = controls[cid]
                    mappings.append(RuleMapping(
                        rule_id=cid,
                        title=info["title"],
                        description=info["description"],
                        confidence=round(sc, 4),
                        status=MappingStatus.AMBIGUOUS,
                        matched_concepts=matched,
                        is_negative=extraction.is_negative_requirement,
                        parameters=extraction.parameters,
                    ))
        else:
            result_status = MappingStatus.MAPPED
            cid, sc, matched = scores[0]
            info = controls[cid]
            mappings.append(RuleMapping(
                rule_id=cid,
                title=info["title"],
                description=info["description"],
                confidence=round(sc, 4),
                status=MappingStatus.MAPPED,
                matched_concepts=matched,
                is_negative=extraction.is_negative_requirement,
                parameters=extraction.parameters,
            ))
            for cid2, sc2, matched2 in scores[1:]:
                if sc2 >= CONFIDENCE_THRESHOLD:
                    info2 = controls[cid2]
                    mappings.append(RuleMapping(
                        rule_id=cid2,
                        title=info2["title"],
                        description=info2["description"],
                        confidence=round(sc2, 4),
                        status=MappingStatus.UNKNOWN,
                        matched_concepts=matched2,
                        is_negative=extraction.is_negative_requirement,
                        parameters=extraction.parameters,
                    ))

    return MappingResult(
        source_text=extraction.source_text,
        intent=extraction.intent,
        is_negative_requirement=extraction.is_negative_requirement,
        mappings=mappings,
        entities=extraction.entities,
        parameters=extraction.parameters,
        status=result_status,
    )
