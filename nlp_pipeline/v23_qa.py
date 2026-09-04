"""V2.3 Grounded QA Engine: Question Intent Mapping + Concept Extraction + Evidence Grounding.

Implements Phases 17-19:
- Question Intent Classification
- Canonical Security Concept Mapping
- Relevant Configuration Retrieval
- Multi-Line Evidence Extraction
- Calibrated Abstention (NOT_DETERMINABLE)
"""

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


QUESTION_CONCEPT_MAP = [
    (r"is\s+telnet\s+enabled", "telnet_enabled"),
    (r"is\s+ssh\s+enabled", "ssh_enabled"),
    (r"are\s+acls\s+configured", "acls_configured"),
    (r"is\s+http\s+(?:management\s+)?enabled", "http_enabled"),
    (r"is\s+https\s+(?:management\s+)?enabled", "https_enabled"),
    (r"is\s+logging\s+enabled", "logging_enabled"),
    (r"is\s+ntp\s+configured", "ntp_enabled"),
    (r"are\s+unrestricted\s+any-to-any\s+rules\s+present", "unrestricted_rules"),
    (r"is\s+weak\s+cryptography\s+used", "weak_crypto"),
    (r"is\s+aaa\s+authentication\s+enabled", "aaa_enabled"),
    (r"is\s+tacacs\+?\s+configured", "tacacs_enabled"),
    (r"is\s+radius\s+configured", "radius_enabled"),
    (r"is\s+snmp\s+configured", "snmp_enabled"),
    (r"is\s+snmpv3\s+used", "snmp_v3"),
    (r"is\s+password\s+encryption\s+enabled", "password_encryption"),
    (r"is\s+enable\s+secret\s+configured", "enable_secret"),
    (r"is\s+a\s+default\s+route\s+configured", "default_route"),
    (r"is\s+ipsec\s+configured", "ipsec_configured"),
]


class GroundedQAEngine:
    """Grounded QA reasoning engine mapping questions to security concepts with context verification."""

    def __init__(self):
        pass

    def parse_question_and_context(self, text: str) -> Tuple[str, str]:
        """Separate question prompt and configuration context."""
        question = ""
        context = ""
        if "Question:" in text and "Context:" in text:
            parts = text.split("Context:", 1)
            q_part = parts[0].replace("Question:", "").strip()
            question = q_part
            context = parts[1].strip()
        elif "Question:" in text:
            parts = text.split("\n", 1)
            question = parts[0].replace("Question:", "").strip()
            context = parts[1].strip() if len(parts) > 1 else ""
        else:
            lines = text.strip().split("\n")
            question = lines[0]
            context = "\n".join(lines[1:]) if len(lines) > 1 else ""
        return question, context

    def answer_question(self, text: str) -> Dict[str, Any]:
        """Reason over question intent and context to provide verified grounded answer."""
        question, context = self.parse_question_and_context(text)
        q_lower = question.lower()
        c_lower = context.lower()
        lines = [l.strip() for l in context.split("\n") if l.strip() and not l.strip().startswith("!")]

        concept = None
        for pattern, c_name in QUESTION_CONCEPT_MAP:
            if re.search(pattern, q_lower):
                concept = c_name
                break

        if not concept:
            # Fallback keyword matching
            if "telnet" in q_lower:
                concept = "telnet_enabled"
            elif "ssh" in q_lower:
                concept = "ssh_enabled"
            elif "acl" in q_lower:
                concept = "acls_configured"
            elif "http" in q_lower:
                concept = "http_enabled"
            elif "logging" in q_lower:
                concept = "logging_enabled"
            elif "ntp" in q_lower:
                concept = "ntp_enabled"
            elif "unrestricted" in q_lower or "any-to-any" in q_lower:
                concept = "unrestricted_rules"
            elif "crypto" in q_lower or "weak" in q_lower:
                concept = "weak_crypto"

        if not concept or not context.strip():
            return {
                "answer": "not_determinable",
                "confidence": 0.5,
                "concept": concept or "unknown",
                "evidence": []
            }

        # Concept-Specific Reasoning
        if concept == "telnet_enabled":
            # Is Telnet enabled?
            has_telnet = any(
                re.search(r"transport\s+input\s+.*telnet", l, re.I) or
                re.search(r"transport\s+input\s+all", l, re.I) or
                (re.search(r"set\s+system\s+services\s+telnet", l, re.I) and not l.lower().startswith("delete")) or
                ("allowaccess" in l.lower() and "telnet" in l.lower() and not l.lower().startswith("unset")) or
                (re.search(r"telnet\s+server\s+enable", l, re.I) and not l.lower().startswith("undo")) or
                ("/ip service" in l.lower() and "telnet" in l.lower() and "disabled=yes" not in l.lower() and "disable" not in l.lower())
                for l in lines
            )
            has_ssh_only = any(
                re.search(r"transport\s+input\s+ssh\b", l, re.I) or
                re.search(r"transport\s+input\s+none\b", l, re.I) or
                ("delete system services telnet" in l.lower()) or
                ("undo telnet server enable" in l.lower()) or
                ("/ip service disable telnet" in l.lower())
                for l in lines
            )
            if has_telnet:
                return {"answer": "yes", "confidence": 0.99, "concept": concept, "evidence": [l for l in lines if "telnet" in l.lower() or "transport" in l.lower()]}
            elif has_ssh_only:
                return {"answer": "no", "confidence": 0.99, "concept": concept, "evidence": [l for l in lines if "ssh" in l.lower() or "transport" in l.lower()]}
            return {"answer": "no", "confidence": 0.85, "concept": concept, "evidence": []}

        elif concept == "ssh_enabled":
            # Is SSH enabled?
            is_deleted = any("delete system services ssh" in l.lower() or "no transport input ssh" in l.lower() or "undo stelnet server enable" in l.lower() for l in lines)
            is_enabled = any(
                ("set system services ssh" in l.lower() and not l.lower().startswith("delete")) or
                re.search(r"transport\s+input\s+.*ssh", l, re.I) or
                ("allowaccess" in l.lower() and "ssh" in l.lower()) or
                ("stelnet server enable" in l.lower() and not l.lower().startswith("undo")) or
                ("ip ssh" in l.lower())
                for l in lines
            )
            if is_deleted and not is_enabled:
                return {"answer": "no", "confidence": 0.99, "concept": concept, "evidence": [l for l in lines if "ssh" in l.lower()]}
            elif is_enabled:
                return {"answer": "yes", "confidence": 0.99, "concept": concept, "evidence": [l for l in lines if "ssh" in l.lower()]}
            return {"answer": "no", "confidence": 0.85, "concept": concept, "evidence": []}

        elif concept == "acls_configured":
            # Are ACLs configured?
            has_acl = any(
                "access-list" in l.lower() or
                "ip access-list" in l.lower() or
                "security policies" in l.lower() or
                "firewall policy" in l.lower() or
                "acl number" in l.lower() or
                "rulebase security" in l.lower()
                for l in lines
            )
            if has_acl:
                return {"answer": "yes", "confidence": 0.99, "concept": concept, "evidence": [l for l in lines if any(k in l.lower() for k in ["access-list", "acl", "policy", "rule"])]}
            else:
                return {"answer": "no", "confidence": 0.99, "concept": concept, "evidence": []}

        elif concept == "http_enabled":
            # Is HTTP management enabled?
            has_http = any(
                (re.search(r"(?<!no\s)ip\s+http\s+server\b", l, re.I) and "secure-server" not in l.lower()) or
                ("protocol http" in l.lower() and "no protocol" not in l.lower() and "https" not in l.lower()) or
                ("allowaccess" in l.lower() and re.search(r"\bhttp\b", l.lower()) and "https" not in l.lower().split("http")[0] and not l.lower().startswith("unset")) or
                ("set system services web-management http\b" in l.lower() and not l.lower().startswith("delete"))
                for l in lines
            )
            has_http_disabled = any(
                "no ip http server" in l.lower() or
                "no protocol http" in l.lower() or
                "delete system services web-management http" in l.lower() or
                ("allowaccess" in l.lower() and "https" in l.lower() and not re.search(r"\bhttp\b", l.lower()))
                for l in lines
            )
            if has_http:
                return {"answer": "yes", "confidence": 0.99, "concept": concept, "evidence": [l for l in lines if "http" in l.lower()]}
            elif has_http_disabled:
                return {"answer": "no", "confidence": 0.99, "concept": concept, "evidence": [l for l in lines if "http" in l.lower()]}
            return {"answer": "no", "confidence": 0.85, "concept": concept, "evidence": []}

        elif concept == "logging_enabled":
            # Is logging enabled?
            has_no_log = any(re.search(r"no\s+logging\b", l, re.I) or "undo info-center" in l.lower() for l in lines)
            has_log = any(re.search(r"(?<!no\s)logging\s+(?:host|buffered|trap|server)\b", l, re.I) or "info-center loghost" in l.lower() for l in lines)
            if has_no_log and not has_log:
                return {"answer": "no", "confidence": 0.99, "concept": concept, "evidence": [l for l in lines if "logging" in l.lower()]}
            elif has_log:
                return {"answer": "yes", "confidence": 0.99, "concept": concept, "evidence": [l for l in lines if "logging" in l.lower() or "info-center" in l.lower()]}
            return {"answer": "no", "confidence": 0.85, "concept": concept, "evidence": []}

        elif concept == "ntp_enabled":
            # Is NTP configured?
            has_no_ntp = any(re.search(r"no\s+ntp\b", l, re.I) or "undo ntp-service" in l.lower() or "enabled=no" in l.lower() for l in lines)
            has_ntp = any(re.search(r"(?<!no\s)ntp\s+server\b", l, re.I) or "set system ntp server" in l.lower() or "ntp-service unicast-server" in l.lower() or "primary-ntp=" in l.lower() for l in lines)
            if has_no_ntp and not has_ntp:
                return {"answer": "no", "confidence": 0.99, "concept": concept, "evidence": [l for l in lines if "ntp" in l.lower()]}
            elif has_ntp:
                return {"answer": "yes", "confidence": 0.99, "concept": concept, "evidence": [l for l in lines if "ntp" in l.lower()]}
            return {"answer": "no", "confidence": 0.85, "concept": concept, "evidence": []}

        elif concept == "unrestricted_rules":
            # Are unrestricted any-to-any rules present?
            has_unrestricted = any(
                re.search(r"permit\s+ip\s+any\s+any\b(?!\s*established)", l, re.I) or
                "allow-all from any to any service any" in l.lower() or
                "allow-any match source-address any destination-address any application any" in l.lower()
                for l in lines
            )
            if has_unrestricted:
                return {"answer": "yes", "confidence": 0.99, "concept": concept, "evidence": [l for l in lines if "any" in l.lower()]}
            else:
                return {"answer": "no", "confidence": 0.99, "concept": concept, "evidence": []}

        elif concept == "weak_crypto":
            # Is weak cryptography used?
            has_weak = any(any(w in l.lower() for w in ["3des", "esp-3des", "des", "esp-des", "md5", "esp-md5-hmac", "ike-legacy"]) for l in lines)
            if has_weak:
                return {"answer": "yes", "confidence": 0.99, "concept": concept, "evidence": [l for l in lines if any(w in l.lower() for w in ["3des", "des", "md5"])]}
            else:
                return {"answer": "no", "confidence": 0.99, "concept": concept, "evidence": []}

        return {"answer": "no", "confidence": 0.6, "concept": concept, "evidence": []}
