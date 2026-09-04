"""Security and secret sanitization module for vendor configuration fixtures."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class SanitizationFinding:
    line_number: int
    secret_type: str  # "enable_secret", "password", "snmp_community", "private_key", "psk", "api_token"
    original_match: str
    replacement: str


@dataclass
class SanitizationResult:
    is_clean: bool
    findings_count: int
    findings: List[SanitizationFinding]
    sanitized_content: str


SECRET_PATTERNS = [
    # Cisco enable secret / password
    (r"(enable\s+secret\s+(?:5|8|9|\d+)\s+)(\S+)", r"\g<1><SANITIZED_ENABLE_SECRET>", "enable_secret"),
    (r"(enable\s+password\s+(?:7|\d+)?\s*)(\S+)", r"\g<1><SANITIZED_ENABLE_PASSWORD>", "enable_password"),
    (r"(username\s+\S+\s+(?:secret|password)\s+(?:5|7|8|9|\d+)?\s*)(\S+)", r"\g<1><SANITIZED_USER_SECRET>", "username_password"),
    # SNMP communities
    (r"(snmp-server\s+community\s+)(\S+)(\s+.*)?", r"\g<1><SANITIZED_SNMP_COMMUNITY>\g<3>", "snmp_community"),
    (r"(set\s+snmp\s+community\s+)(\S+)", r"\g<1><SANITIZED_SNMP_COMMUNITY>", "snmp_community"),
    (r"(set\s+snmp-agent\s+sys-info\s+.*community\s+)(\S+)", r"\g<1><SANITIZED_SNMP_COMMUNITY>", "snmp_community"),
    (r"(/snmp\s+community\s+set\s+.*name=)(\S+)", r"\g<1><SANITIZED_SNMP_COMMUNITY>", "snmp_community"),
    # Pre-shared keys / IPsec / BGP / OSPF / NTP keys
    (r"(pre-shared-key\s+(?:ascii|hex|\d+)\s+)(\S+)", r"\g<1><SANITIZED_PSK>", "psk"),
    (r"(set\s+psksecret\s+)(\S+)", r"\g<1><SANITIZED_PSK>", "psk"),
    (r"(set\s+password\s+ENC\s+)(\S+)", r"\g<1><SANITIZED_PASSWORD_ENC>", "password_enc"),
    (r"(password\s+7\s+)(\S+)", r"\g<1><SANITIZED_TYPE7_PASSWORD>", "type7_password"),
    (r"(ntp\s+authentication-key\s+\d+\s+md5\s+)(\S+)", r"\g<1><SANITIZED_NTP_KEY>", "ntp_key"),
    (r"(neighbor\s+\S+\s+password\s+)(\S+)", r"\g<1><SANITIZED_BGP_PASSWORD>", "bgp_password"),
    # Private keys / PEM blocks
    (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "<SANITIZED_PRIVATE_KEY_BLOCK>", "private_key_block"),
    # API tokens / Bearer headers
    (r"(api[-_]?key\s*[:=]\s*[\"']?)([A-Za-z0-9_\-\.]{16,})([\"']?)", r"\g<1><SANITIZED_API_KEY>\g<3>", "api_key"),
    (r"(bearer\s+)([A-Za-z0-9_\-\.]{20,})", r"\g<1><SANITIZED_BEARER_TOKEN>", "bearer_token"),
]


class SecretSanitizer:
    """Scans and sanitizes network configuration fixtures to prevent credential leakage."""

    @classmethod
    def scan_and_sanitize(cls, text: str) -> SanitizationResult:
        findings: List[SanitizationFinding] = []
        sanitized = text

        for pattern, replacement, sec_type in SECRET_PATTERNS:
            matches = list(re.finditer(pattern, sanitized, re.IGNORECASE))
            if matches:
                for m in matches:
                    # Calculate line number
                    line_no = sanitized[: m.start()].count("\n") + 1
                    match_snippet = m.group(0)[:60]
                    findings.append(SanitizationFinding(
                        line_number=line_no,
                        secret_type=sec_type,
                        original_match=match_snippet,
                        replacement=replacement,
                    ))
                sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

        is_clean = len(findings) == 0
        return SanitizationResult(
            is_clean=is_clean,
            findings_count=len(findings),
            findings=findings,
            sanitized_content=sanitized,
        )

    @classmethod
    def sanitize_file(cls, input_path: Path, output_path: Path) -> SanitizationResult:
        content = input_path.read_text(encoding="utf-8", errors="ignore")
        res = cls.scan_and_sanitize(content)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(res.sanitized_content, encoding="utf-8")
        return res
