"""V2.3 Control-Specific Compliance Engine with Grounded Semantic Extraction.

Implements Phases 3-7:
- Control Identification
- Relevant Section Retrieval
- Semantic & Multi-Line Evidence Extraction
- Control-Specific Independent Evaluation
- NOT_DETERMINABLE Abstention Support
- Hybrid Rule + NLP Evaluation
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np


@dataclass
class ControlDefinition:
    control_id: str
    name: str
    category: str
    required_state: str
    positive_patterns: List[str] = field(default_factory=list)
    negative_patterns: List[str] = field(default_factory=list)
    severity: str = "HIGH"
    remediation: str = ""


# Authoritative CIS Control Registry
CIS_CONTROL_REGISTRY: Dict[str, ControlDefinition] = {
    "CIS-2.1.1": ControlDefinition(
        control_id="CIS-2.1.1",
        name="Disable plaintext Telnet administration",
        category="MANAGEMENT",
        required_state="telnet_disabled",
        positive_patterns=[
            r"transport\s+input\s+ssh",
            r"transport\s+input\s+none",
            r"no\s+transport\s+input\s+telnet",
            r"delete\s+system\s+services\s+telnet",
            r"set\s+system\s+services\s+ssh",
            r"undo\s+telnet\s+server\s+enable",
            r"stelnet\s+server\s+enable",
            r"set\s+deviceconfig\s+system\s+service\s+disable-telnet\s+yes",
            r"/ip\s+service\s+disable\s+telnet",
            r"/ip\s+service\s+set\s+telnet\s+disabled=yes",
            r"protocol\s+https",
            r"no\s+protocol\s+telnet",
            r"no\s+telnet-server",
        ],
        negative_patterns=[
            r"transport\s+input\s+telnet",
            r"transport\s+input\s+all",
            r"transport\s+input\s+.*telnet",
            r"set\s+system\s+services\s+telnet",
            r"allowaccess\s+.*telnet",
            r"telnet\s+server\s+enable",
            r"/ip\s+service\s+enable\s+telnet",
            r"/ip\s+service\s+set\s+telnet\s+disabled=no",
            r"set\s+deviceconfig\s+system\s+service\s+disable-telnet\s+no",
            r"protocol\s+telnet",
        ],
        severity="HIGH",
        remediation="Disable telnet and enforce SSHv2.",
    ),
    "CIS-2.2.1": ControlDefinition(
        control_id="CIS-2.2.1",
        name="Disable HTTP web management",
        category="MANAGEMENT",
        required_state="http_disabled",
        positive_patterns=[
            r"no\s+ip\s+http\s+server",
            r"ip\s+http\s+secure-server",
            r"no\s+protocol\s+http",
            r"delete\s+system\s+services\s+web-management\s+http",
            r"set\s+system\s+services\s+web-management\s+https",
            r"undo\s+http\s+server\s+enable",
            r"http\s+secure-server\s+enable",
            r"/ip\s+service\s+disable\s+www\b",
            r"/ip\s+service\s+set\s+www\s+disabled=yes",
            r"set\s+allowaccess\s+(?!.*\bhttp\b).*https",
        ],
        negative_patterns=[
            r"(?<!no\s)ip\s+http\s+server\b",
            r"protocol\s+http\b(?!\s*secure)",
            r"set\s+system\s+services\s+web-management\s+http\b",
            r"allowaccess\s+.*\bhttp\b",
            r"(?<!undo\s)http\s+server\s+enable\b",
            r"/ip\s+service\s+enable\s+www\b",
            r"/ip\s+service\s+set\s+www\s+disabled=no",
        ],
        severity="HIGH",
        remediation="Disable unencrypted HTTP server and enable HTTPS.",
    ),
    "CIS-1.3.1": ControlDefinition(
        control_id="CIS-1.3.1",
        name="Unset default SNMP community strings",
        category="SNMP",
        required_state="default_snmp_unset",
        positive_patterns=[
            r"snmp-server\s+community\s+(?!public|private)\w+",
            r"set\s+snmp\s+community\s+(?!public|private)\w+",
            r"snmp-server\s+group\s+\w+\s+v3",
            r"snmp-server\s+user\s+\w+\s+\w+\s+v3",
            r"no\s+snmp-server\s+community",
            r"delete\s+snmp\s+community",
        ],
        negative_patterns=[
            r"snmp-server\s+community\s+.*public.*",
            r"snmp-server\s+community\s+.*private.*",
            r"set\s+snmp\s+community\s+.*public.*",
            r"set\s+snmp\s+community\s+.*private.*",
            r"snmp-community\s+.*public.*",
            r"community\s+.*public.*",
        ],
        severity="HIGH",
        remediation="Remove default SNMP community strings 'public' and 'private'.",
    ),
    "CIS-4.1.2": ControlDefinition(
        control_id="CIS-4.1.2",
        name="Enforce modern cryptographic algorithms",
        category="VPN",
        required_state="modern_crypto_enforced",
        positive_patterns=[
            r"transform-set\s+\S+\s+esp-gcm\s+256",
            r"transform-set\s+\S+\s+esp-aes\s+256\s+esp-sha256-hmac",
            r"transform-set\s+\S+\s+esp-aes\s+256\s+esp-sha-hmac",
            r"encryption\s+aes-256-gcm\s+hash\s+sha256",
            r"encryption\s+aes-256\b",
            r"transform-set\s+ESP-GCM-256",
            r"set\s+pfs\s+group19",
            r"set\s+pfs\s+group14",
            r"set\s+pfs\s+group20",
        ],
        negative_patterns=[
            r"\besp-des\b",
            r"\besp-3des\b",
            r"\besp-md5-hmac\b",
            r"\b3des\b",
            r"\bdes\b",
            r"\bmd5\b",
            r"\bike-legacy\b",
            r"\bgroup1\b",
            r"\bgroup2\b",
            r"\bgroup5\b",
        ],
        severity="HIGH",
        remediation="Upgrade IPsec transform sets to AES-256 / AES-GCM and SHA-256.",
    ),
    "CIS-3.1.4": ControlDefinition(
        control_id="CIS-3.1.4",
        name="Restrict any-to-any firewall rules",
        category="FIREWALL",
        required_state="any_to_any_restricted",
        positive_patterns=[
            r"permit\s+tcp\s+\S+\s+\S+\s+\S+\s+\S+\s+eq\s+\d+",
            r"permit\s+\w+\s+(?!any\s+any)\S+\s+\S+",
            r"deny\s+ip\s+any\s+any\s+log",
            r"deny\s+ip\s+any\s+any",
            r"permit\s+tcp\s+any\s+any\s+established",
            r"source-address\s+(?!any)\S+\s+destination-address\s+(?!any)\S+",
            r"match\s+source-address\s+(?!any)\S+",
        ],
        negative_patterns=[
            r"permit\s+ip\s+any\s+any\b(?!\s*established)",
            r"allow-any\s+match\s+source-address\s+any\s+destination-address\s+any\s+application\s+any",
            r"rules\s+allow-all\s+from\s+any\s+to\s+any\s+service\s+any\s+action\s+allow",
            r"permit\s+any\s+any\b",
        ],
        severity="CRITICAL",
        remediation="Remove broad any-to-any permit rules and implement least-privilege filtering.",
    ),
    "CIS-1.4.1": ControlDefinition(
        control_id="CIS-1.4.1",
        name="Configure remote audit logging",
        category="LOGGING",
        required_state="remote_logging_enabled",
        positive_patterns=[
            r"logging\s+host\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"logging\s+server\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"info-center\s+loghost\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"configure\s+log\s+syslog\s+\d+\s+address\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"logging\s+buffered\s+\d+",
            r"set\s+system\s+syslog\s+host\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        ],
        negative_patterns=[
            r"no\s+logging\s+host",
            r"no\s+logging\s+buffered",
            r"no\s+logging\s+on",
            r"undo\s+info-center\s+enable",
            r"/system\s+logging\s+action\s+set\s+remote\s+remote=0.0.0.0",
        ],
        severity="HIGH",
        remediation="Configure remote syslog aggregation hosts for centralized audit trail.",
    ),
    "CIS-1.4.2": ControlDefinition(
        control_id="CIS-1.4.2",
        name="Configure authoritative NTP time sources",
        category="NTP",
        required_state="ntp_configured",
        positive_patterns=[
            r"ntp\s+server\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"set\s+system\s+ntp\s+server\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"ntp-service\s+unicast-server\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
            r"/system\s+ntp\s+client\s+set\s+(?!.*enabled=no)enabled=yes",
            r"/system\s+ntp\s+client\s+set\s+primary-ntp=\d+",
        ],
        negative_patterns=[
            r"no\s+ntp\s+server",
            r"no\s+ntp\b",
            r"undo\s+ntp-service",
            r"/system\s+ntp\s+client\s+set\s+.*enabled=no",
        ],
        severity="HIGH",
        remediation="Configure authoritative NTP time servers for accurate log correlation.",
    ),
    "CIS-1.1.2": ControlDefinition(
        control_id="CIS-1.1.2",
        name="Configure privileged secret hashing",
        category="AAA",
        required_state="enable_secret_configured",
        positive_patterns=[
            r"enable\s+secret\b",
            r"password\s+algorithm\s+sha-512",
            r"password\s+algorithm\s+sha-256",
            r"set\s+system\s+root-authentication\s+encrypted-password",
        ],
        negative_patterns=[
            r"enable\s+password\b",
            r"no\s+enable\s+secret\b",
        ],
        severity="HIGH",
        remediation="Configure 'enable secret' with SHA-256 or Scrypt instead of plaintext enable password.",
    ),
}


class GroundedComplianceEngine:
    """Evaluates configurations against CIS controls using grounded semantic extraction."""

    def __init__(self):
        self.registry = CIS_CONTROL_REGISTRY

    def parse_control_and_snippet(self, text: str) -> Tuple[Optional[ControlDefinition], str]:
        """Extract CIS control identifier and the configuration snippet."""
        cid = None
        for c in self.registry:
            if c in text:
                cid = c
                break
        
        # Fallback: check control names
        if not cid:
            lower = text.lower()
            if "telnet" in lower:
                cid = "CIS-2.1.1"
            elif "http" in lower:
                cid = "CIS-2.2.1"
            elif "snmp" in lower:
                cid = "CIS-1.3.1"
            elif "cryptograph" in lower or "crypto" in lower:
                cid = "CIS-4.1.2"
            elif "any-to-any" in lower or "firewall" in lower:
                cid = "CIS-3.1.4"
            elif "logging" in lower or "audit" in lower:
                cid = "CIS-1.4.1"
            elif "ntp" in lower or "time" in lower:
                cid = "CIS-1.4.2"
            elif "secret" in lower or "password" in lower:
                cid = "CIS-1.1.2"

        control_def = self.registry.get(cid) if cid else None

        # Extract snippet
        if "Config Snippet:" in text:
            snippet = text.split("Config Snippet:", 1)[1].strip()
        elif "Context:" in text:
            snippet = text.split("Context:", 1)[1].strip()
        else:
            snippet = text.strip()

        return control_def, snippet

    def evaluate_snippet(self, text: str, default_on_absence: bool = False) -> Dict[str, Any]:
        """Evaluate a text snippet for compliance with multi-line evidence."""
        control_def, snippet = self.parse_control_and_snippet(text)

        if not control_def:
            # Cannot determine control
            return {
                "status": "NOT_DETERMINABLE",
                "control_id": "UNKNOWN",
                "confidence": 0.5,
                "evidence": [],
                "reason": "Control identifier not recognized in prompt."
            }

        lines = [line.strip() for line in snippet.split("\n") if line.strip() and not line.strip().startswith("!")]
        cid = control_def.control_id

        # Control-specific evaluation logic
        if cid == "CIS-2.1.1":
            # Multi-line VTY / Telnet check
            has_telnet_neg = False
            has_telnet_pos = False
            ev_neg = []
            ev_pos = []

            # Check for Fortinet / Junos / Huawei / MikroTik / Arista
            for line in lines:
                l_lower = line.lower()
                if re.search(r"transport\s+input\s+.*telnet", l_lower) or re.search(r"transport\s+input\s+all", l_lower):
                    has_telnet_neg = True
                    ev_neg.append(line)
                elif re.search(r"set\s+system\s+services\s+telnet", l_lower) and not l_lower.startswith("delete"):
                    has_telnet_neg = True
                    ev_neg.append(line)
                elif "allowaccess" in l_lower and "telnet" in l_lower and not l_lower.startswith("unset"):
                    has_telnet_neg = True
                    ev_neg.append(line)
                elif re.search(r"telnet\s+server\s+enable", l_lower) and not l_lower.startswith("undo"):
                    has_telnet_neg = True
                    ev_neg.append(line)
                elif "/ip service" in l_lower and "telnet" in l_lower and "disabled=yes" not in l_lower and "disable" not in l_lower:
                    has_telnet_neg = True
                    ev_neg.append(line)
                elif "protocol telnet" in l_lower and not l_lower.startswith("no "):
                    has_telnet_neg = True
                    ev_neg.append(line)

                # Positive indicators
                if re.search(r"transport\s+input\s+ssh\b", l_lower) or re.search(r"transport\s+input\s+none\b", l_lower):
                    has_telnet_pos = True
                    ev_pos.append(line)
                elif "delete system services telnet" in l_lower or ("set system services ssh" in l_lower and not has_telnet_neg):
                    has_telnet_pos = True
                    ev_pos.append(line)
                elif "allowaccess" in l_lower and "ssh" in l_lower and "telnet" not in l_lower:
                    has_telnet_pos = True
                    ev_pos.append(line)
                elif "undo telnet server enable" in l_lower or "stelnet server enable" in l_lower:
                    has_telnet_pos = True
                    ev_pos.append(line)
                elif "/ip service disable telnet" in l_lower or "disabled=yes" in l_lower:
                    has_telnet_pos = True
                    ev_pos.append(line)
                elif "protocol https" in l_lower or "no protocol telnet" in l_lower:
                    has_telnet_pos = True
                    ev_pos.append(line)

            if has_telnet_neg:
                return {"status": "NON_COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_neg, "reason": "Plaintext telnet enabled on management line."}
            elif has_telnet_pos:
                return {"status": "COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_pos, "reason": "SSH enforced and Telnet disabled."}
            else:
                if default_on_absence:
                    return {"status": "COMPLIANT", "control_id": cid, "confidence": 0.95, "evidence": [], "reason": "No telnet enabled (compliant by absence)."}
                return {"status": "NOT_DETERMINABLE", "control_id": cid, "confidence": 0.6, "evidence": [], "reason": "No management access lines in snippet."}

        elif cid == "CIS-2.2.1":
            # HTTP web management check
            has_http_neg = False
            has_http_pos = False
            ev_neg = []
            ev_pos = []

            for line in lines:
                l_lower = line.lower()
                if (re.search(r"(?<!no\s)ip\s+http\s+server\b", l_lower) and not "secure-server" in l_lower) or \
                   ("protocol http" in l_lower and "no protocol" not in l_lower and "https" not in l_lower) or \
                   ("allowaccess" in l_lower and re.search(r"\bhttp\b", l_lower) and "https" not in l_lower.split("http")[0] and not "unset" in l_lower) or \
                   ("set system services web-management http" in l_lower and not "delete" in l_lower and "https" not in l_lower) or \
                   ("http server enable" in l_lower and not "undo" in l_lower and "secure" not in l_lower) or \
                   ("/ip service" in l_lower and "www" in l_lower and "disabled=yes" not in l_lower and "disable" not in l_lower and "ssl" not in l_lower):
                    has_http_neg = True
                    ev_neg.append(line)

                if "no ip http server" in l_lower or "ip http secure-server" in l_lower or \
                   "no protocol http" in l_lower or "protocol https" in l_lower or \
                   "delete system services web-management http" in l_lower or "set system services web-management https" in l_lower or \
                   "undo http server enable" in l_lower or "http secure-server enable" in l_lower or \
                   "/ip service disable www" in l_lower or "disabled=yes" in l_lower or \
                   ("allowaccess" in l_lower and "https" in l_lower and not re.search(r"\bhttp\b", l_lower)):
                    has_http_pos = True
                    ev_pos.append(line)

            if has_http_neg:
                return {"status": "NON_COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_neg, "reason": "Unencrypted HTTP server active."}
            elif has_http_pos:
                return {"status": "COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_pos, "reason": "HTTP disabled or HTTPS secure server configured."}
            else:
                if default_on_absence:
                    return {"status": "COMPLIANT", "control_id": cid, "confidence": 0.95, "evidence": [], "reason": "No HTTP management enabled (compliant by absence)."}
                return {"status": "NOT_DETERMINABLE", "control_id": cid, "confidence": 0.6, "evidence": [], "reason": "No web management lines in snippet."}

        elif cid == "CIS-1.3.1":
            # SNMP Community Strings Check
            has_default_snmp = False
            has_secure_snmp = False
            ev_neg = []
            ev_pos = []

            for line in lines:
                l_lower = line.lower()
                if "snmp" in l_lower and ("community" in l_lower or "group" in l_lower or "user" in l_lower):
                    if "public" in l_lower or "private" in l_lower:
                        has_default_snmp = True
                        ev_neg.append(line)
                    else:
                        has_secure_snmp = True
                        ev_pos.append(line)

            if has_default_snmp:
                return {"status": "NON_COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_neg, "reason": "Default SNMP community string (public/private) detected."}
            elif has_secure_snmp:
                return {"status": "COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_pos, "reason": "Custom SNMP community or SNMPv3 user configured."}
            else:
                if default_on_absence:
                    return {"status": "COMPLIANT", "control_id": cid, "confidence": 0.95, "evidence": [], "reason": "No default SNMP community configured."}
                return {"status": "NOT_DETERMINABLE", "control_id": cid, "confidence": 0.6, "evidence": [], "reason": "No SNMP lines in snippet."}

        elif cid == "CIS-4.1.2":
            # Cryptography check (check for any weak cipher)
            has_weak_crypto = False
            has_strong_crypto = False
            ev_neg = []
            ev_pos = []

            for line in lines:
                l_lower = line.lower()
                if any(k in l_lower for k in ["crypto", "ipsec", "transform-set", "encryption", "ike", "pfs", "esp-"]):
                    if any(re.search(rf"\b{w}\b", l_lower) for w in ["3des", "esp-3des", "des", "esp-des", "md5", "esp-md5-hmac", "ike-legacy", "group1", "group2", "group5"]):
                        has_weak_crypto = True
                        ev_neg.append(line)
                    elif any(s in l_lower for s in ["aes", "aes-256", "aes-128", "aes-256-gcm", "esp-gcm", "sha256", "sha-256", "group14", "group19", "group20", "suite-b"]):
                        has_strong_crypto = True
                        ev_pos.append(line)

            if has_weak_crypto:
                return {"status": "NON_COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_neg, "reason": "Legacy weak cryptography algorithms (DES/3DES/MD5) detected."}
            elif has_strong_crypto:
                return {"status": "COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_pos, "reason": "Modern cryptographic algorithms (AES-GCM / SHA-256) enforced."}
            else:
                if default_on_absence:
                    return {"status": "COMPLIANT", "control_id": cid, "confidence": 0.95, "evidence": [], "reason": "No weak cryptography used."}
                return {"status": "NOT_DETERMINABLE", "control_id": cid, "confidence": 0.6, "evidence": [], "reason": "No crypto configurations in snippet."}

        elif cid == "CIS-3.1.4":
            # Firewall Any-to-Any check
            has_any_any = False
            has_restricted = False
            ev_neg = []
            ev_pos = []

            for line in lines:
                l_lower = line.lower()
                if re.search(r"permit\s+ip\s+any\s+any\b(?!\s*established)", l_lower) or \
                   "allow-any match source-address any destination-address any" in l_lower or \
                   "rules allow-all from any to any service any action allow" in l_lower or \
                   "permit any any" in l_lower:
                    has_any_any = True
                    ev_neg.append(line)
                elif "permit tcp" in l_lower or "permit udp" in l_lower or "deny ip any any" in l_lower or "destination-address" in l_lower:
                    has_restricted = True
                    ev_pos.append(line)

            if has_any_any:
                return {"status": "NON_COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_neg, "reason": "Overly permissive any-to-any firewall permit rule present."}
            elif has_restricted:
                return {"status": "COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_pos, "reason": "Restricted firewall access-list with specific ports or default deny."}
            else:
                if default_on_absence:
                    return {"status": "COMPLIANT", "control_id": cid, "confidence": 0.95, "evidence": [], "reason": "No any-to-any firewall rule configured."}
                return {"status": "NOT_DETERMINABLE", "control_id": cid, "confidence": 0.6, "evidence": [], "reason": "No firewall rules in snippet."}

        elif cid == "CIS-1.4.1":
            # Remote Logging Check
            has_logging_disabled = False
            has_logging_enabled = False
            ev_neg = []
            ev_pos = []

            for line in lines:
                l_lower = line.lower()
                if re.search(r"no\s+logging\s+host\b", l_lower) or "no logging buffered" in l_lower or "undo info-center enable" in l_lower:
                    has_logging_disabled = True
                    ev_neg.append(line)
                elif re.search(r"logging\s+host\s+\d+", l_lower) or "info-center loghost" in l_lower or "configure log syslog" in l_lower or "logging buffered" in l_lower or "set system syslog host" in l_lower:
                    has_logging_enabled = True
                    ev_pos.append(line)

            if has_logging_disabled and not has_logging_enabled:
                return {"status": "NON_COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_neg, "reason": "Remote logging disabled or host explicitly unset."}
            elif has_logging_enabled and not has_logging_disabled:
                return {"status": "COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_pos, "reason": "Remote audit syslog host configured."}
            elif has_logging_disabled and has_logging_enabled:
                return {"status": "NON_COMPLIANT", "control_id": cid, "confidence": 0.95, "evidence": ev_neg, "reason": "Logging host removed or disabled."}
            else:
                if default_on_absence:
                    return {"status": "NON_COMPLIANT", "control_id": cid, "confidence": 0.95, "evidence": [], "reason": "No remote syslog host configured."}
                return {"status": "NOT_DETERMINABLE", "control_id": cid, "confidence": 0.6, "evidence": [], "reason": "No logging lines in snippet."}

        elif cid == "CIS-1.4.2":
            # NTP Configuration Check
            has_ntp_disabled = False
            has_ntp_enabled = False
            ev_neg = []
            ev_pos = []

            for line in lines:
                l_lower = line.lower()
                if "no ntp server" in l_lower or "no ntp" in l_lower or "enabled=no" in l_lower or "undo ntp-service" in l_lower:
                    has_ntp_disabled = True
                    ev_neg.append(line)
                elif re.search(r"ntp\s+server\s+\d+", l_lower) or "set system ntp server" in l_lower or "ntp-service unicast-server" in l_lower or "primary-ntp=" in l_lower:
                    has_ntp_enabled = True
                    ev_pos.append(line)

            if has_ntp_disabled:
                return {"status": "NON_COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_neg, "reason": "NTP server disabled or unset."}
            elif has_ntp_enabled:
                return {"status": "COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_pos, "reason": "Authoritative NTP server configured."}
            else:
                if default_on_absence:
                    return {"status": "NON_COMPLIANT", "control_id": cid, "confidence": 0.95, "evidence": [], "reason": "No authoritative NTP server configured."}
                return {"status": "NOT_DETERMINABLE", "control_id": cid, "confidence": 0.6, "evidence": [], "reason": "No NTP lines in snippet."}

        elif cid == "CIS-1.1.2":
            # Password Encryption / Enable Secret Check
            has_enable_pw = False
            has_enable_secret = False
            ev_neg = []
            ev_pos = []

            for line in lines:
                l_lower = line.lower()
                if re.search(r"enable\s+password\b", l_lower):
                    has_enable_pw = True
                    ev_neg.append(line)
                elif re.search(r"enable\s+secret\b", l_lower) or "encrypted-password" in l_lower:
                    has_enable_secret = True
                    ev_pos.append(line)

            if has_enable_pw and not has_enable_secret:
                return {"status": "NON_COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_neg, "reason": "Plaintext enable password configured."}
            elif has_enable_secret:
                return {"status": "COMPLIANT", "control_id": cid, "confidence": 0.99, "evidence": ev_pos, "reason": "Hashed enable secret configured."}
            else:
                if default_on_absence:
                    return {"status": "COMPLIANT", "control_id": cid, "confidence": 0.95, "evidence": [], "reason": "No plaintext enable password configured."}
                return {"status": "NOT_DETERMINABLE", "control_id": cid, "confidence": 0.6, "evidence": [], "reason": "No enable secret lines in snippet."}

        return {"status": "NOT_DETERMINABLE", "control_id": cid, "confidence": 0.5, "evidence": [], "reason": "Unable to evaluate control."}
