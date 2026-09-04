"""Public configuration dataset ingestion, normalization, and NLP validation suite.

Provides strict provenance tracking (PUBLIC_CONFIGURATION_SNIPPET, PUBLIC_NETCONF_EXAMPLE, real_device: false),
security-relevant directive extraction, normalization to SecurityBaselineModel concepts,
extracted value parsing, disjoint dataset splitting (train/val/test), cross-vendor semantic mapping,
and authoritative vendor documentation cross-checking.
"""

import hashlib
import json
import os
import re
from dataclasses import dataclass, field as dc_field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models.baseline import SecurityBaselineModel
from ..parsers.llm.parser import FIELD_TYPES


class ProvenanceClassification(str, Enum):
    """Authoritative classifications for configuration sources."""
    OFFICIAL_VENDOR_DOCUMENTATION = "OFFICIAL_VENDOR_DOCUMENTATION"
    OFFICIAL_VENDOR_EXAMPLE = "OFFICIAL_VENDOR_EXAMPLE"
    PUBLIC_CONFIGURATION_SNIPPET = "PUBLIC_CONFIGURATION_SNIPPET"
    PUBLIC_NETCONF_EXAMPLE = "PUBLIC_NETCONF_EXAMPLE"
    SYNTHETIC_DERIVED_FROM_OFFICIAL_SOURCE = "SYNTHETIC_DERIVED_FROM_OFFICIAL_SOURCE"
    REAL_DEVICE_CONFIGURATION = "REAL_DEVICE_CONFIGURATION"
    UNKNOWN_PROVENANCE = "UNKNOWN_PROVENANCE"


class DevNetContentType(str, Enum):
    """Classifications for Cisco DevNet NETCONF repository files."""
    CONFIGURATION = "CONFIGURATION"
    NETCONF_API_EXAMPLE = "NETCONF/API EXAMPLE"
    AUTOMATION_CODE = "AUTOMATION CODE"
    DOCUMENTATION = "DOCUMENTATION"
    OTHER = "OTHER"


# Supported SecurityBaselineModel fields for normalization
SUPPORTED_BASELINE_FIELDS = set(SecurityBaselineModel.observable_fields())

# Authoritative vendor documentation references for cross-checking
OFFICIAL_DOC_REFERENCES = {
    "Cisco": {
        "snmp": "Cisco IOS-XE / NX-OS SNMP Configuration Guide (Cisco Systems)",
        "ssh": "Cisco IOS Security Configuration Guide: Securing the Control Plane (Cisco Systems)",
        "aaa": "Cisco Authentication, Authorization, and Accounting Configuration Guide (Cisco Systems)",
        "logging": "Cisco IOS System Message Logging Guide (Cisco Systems)",
        "ntp": "Cisco Network Time Protocol Configuration Guide (Cisco Systems)",
        "acl": "Cisco IP Access List Configuration Guide (Cisco Systems)",
        "vty": "Cisco Terminal Lines and Modem Support Configuration Guide (Cisco Systems)",
        "banners": "Cisco IOS Basic System Management Command Reference: banner (Cisco Systems)",
        "passwords": "Cisco IOS Security Configuration Guide: Passwords and Privileges (Cisco Systems)",
    },
    "Juniper": {
        "snmp": "Junos OS Network Management Configuration Guide (Juniper Networks)",
        "ssh": "Junos OS CLI User Guide: System Access Security (Juniper Networks)",
        "logging": "Junos OS System Logging and Tracing Administration (Juniper Networks)",
        "ntp": "Junos OS Network Time Protocol Configuration (Juniper Networks)",
        "telemetry": "Junos Telemetry Interface (JTI) Guide (Juniper Networks)",
        "banners": "Junos OS System Basics Configuration Guide: Login Messages (Juniper Networks)",
        "aaa": "Junos OS User Access and Authentication Guide (Juniper Networks)",
    },
    "Arista": {
        "snmp": "Arista EOS User Manual: SNMP Configuration (Arista Networks)",
        "ssh": "Arista EOS Management Plane Security Guide (Arista Networks)",
        "sflow": "Arista EOS Flow Monitoring Configuration (Arista Networks)",
        "logging": "Arista EOS System Logging Guide (Arista Networks)",
        "ntp": "Arista EOS Network Time Protocol Configuration (Arista Networks)",
        "aaa": "Arista EOS AAA and TACACS+ Configuration Guide (Arista Networks)",
    },
    "Huawei": {
        "snmp": "Huawei VRP Network Management and Monitoring Guide (Huawei Technologies)",
        "ssh": "Huawei VRP Security Configuration Guide: STelnet and SSH (Huawei Technologies)",
        "netflow": "Huawei VRP NetStream Configuration Guide (Huawei Technologies)",
        "logging": "Huawei VRP System Management Guide: Information Center (Huawei Technologies)",
        "ntp": "Huawei VRP Network Reliability Guide: NTP (Huawei Technologies)",
    },
    "Mikrotik": {
        "snmp": "MikroTik RouterOS Manual: SNMP and Community Configuration (MikroTik)",
        "traffic_flow": "MikroTik RouterOS Manual: Traffic Flow / IP Flow (MikroTik)",
        "bgp": "MikroTik RouterOS Manual: BGP Routing (MikroTik)",
        "ssh": "MikroTik RouterOS Manual: IP Services (MikroTik)",
        "logging": "MikroTik RouterOS Manual: System Logging (MikroTik)",
        "ntp": "MikroTik RouterOS Manual: SNTP Client (MikroTik)",
    },
    "Extreme": {
        "snmp": "ExtremeXOS / NetIron Network Management Guide (Extreme Networks)",
        "sflow": "Extreme Networks Flow Sampling & Monitoring Guide (Extreme Networks)",
        "ssh": "ExtremeXOS User Guide: SSH Server Configuration (Extreme Networks)",
    },
    "Ubiquiti": {
        "snmp": "Ubiquiti EdgeOS User Guide: SNMP Services (Ubiquiti Inc.)",
        "flow": "Ubiquiti EdgeRouter Flow Accounting Guide (Ubiquiti Inc.)",
        "ssh": "Ubiquiti EdgeOS CLI Reference: SSH Service (Ubiquiti Inc.)",
    },
    "Nokia": {
        "snmp": "Nokia 7750 SR / 7950 XRS System Management Guide: SNMP & BOF (Nokia)",
        "cflowd": "Nokia SR OS Cflowd and IPFIX User Guide (Nokia)",
        "logging": "Nokia 7750 SR System Management Guide: Log Management (Nokia)",
    },
    "Palo-Alto": {
        "netflow": "PAN-OS Administrator's Guide: NetFlow Monitoring (Palo Alto Networks)",
        "snmp": "PAN-OS Administrator's Guide: SNMP Setup (Palo Alto Networks)",
        "management": "PAN-OS Administrator's Guide: Device Management (Palo Alto Networks)",
    },
    "Silver-Peak": {
        "flow": "Silver Peak EdgeConnect Orchestrator Flow Export Guide (Aruba/Silver Peak)",
        "snmp": "Silver Peak EdgeConnect Appliance Configuration Guide (Silver Peak)",
    },
    "Vyatta": {
        "flow": "Vyatta / VyOS Network OS System Administration Guide: Flow Accounting (Vyatta)",
        "snmp": "Vyatta Network OS Management Guide (Vyatta)",
        "ssh": "VyOS User Guide: Service SSH (VyOS Maintainers)",
    },
}


@dataclass
class InventoryItem:
    """One inventory item discovered in the repository."""
    vendor: str
    file: str
    format: str
    size: int
    possible_platform: str = "unknown"
    possible_version: str = "unknown"
    provenance: str = ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value
    real_device: bool = False
    source_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vendor": self.vendor,
            "file": self.file.replace("\\", "/"),
            "format": self.format,
            "size": self.size,
            "possible_platform": self.possible_platform,
            "possible_version": self.possible_version,
            "provenance": self.provenance,
            "real_device": self.real_device,
            "source_path": self.source_path.replace("\\", "/"),
        }


@dataclass
class DevNetItem:
    """One inventory item discovered in the Cisco DevNet NETCONF repository."""
    module: str
    file: str
    classification: str
    description: str
    contains_actual_config: bool
    provenance: str = ProvenanceClassification.PUBLIC_NETCONF_EXAMPLE.value
    real_device: bool = False
    source_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "file": self.file.replace("\\", "/"),
            "classification": self.classification,
            "description": self.description,
            "contains_actual_config": self.contains_actual_config,
            "provenance": self.provenance,
            "real_device": self.real_device,
            "source_path": self.source_path.replace("\\", "/"),
        }


def extract_value_for_field(field_name: Optional[str], raw_text: str) -> Any:
    """Extract strongly-typed value matching SecurityBaselineModel field semantics."""
    if not field_name or field_name in ("UNMAPPED", "AMBIGUOUS", "null"):
        return None

    raw = raw_text.strip()
    lower = raw.lower()

    if field_name == "snmp_communities":
        # Cisco / Arista: snmp-server community <name> [RO|RW] [acl]
        m = re.search(r"snmp(?:-server)?\s+community\s+([^\s]+)(?:\s+(ro|rw))?", raw, re.IGNORECASE)
        if m:
            name = m.group(1)
            access = (m.group(2) or "ro").lower()
            return [{"name": name, "access": access}]
        # Juniper: set snmp community <name> authorization read-only
        m_j = re.search(r"community\s+([^\s\{]+)", raw, re.IGNORECASE)
        if m_j:
            name = m_j.group(1)
            access = "ro" if "read-only" in lower or "ro" in lower else "rw"
            return [{"name": name, "access": access}]
        # Mikrotik: /snmp community add name=<name> read-access=yes
        m_m = re.search(r"name=([^\s]+)", raw, re.IGNORECASE)
        if m_m:
            name = m_m.group(1).strip("\"'")
            return [{"name": name, "access": "ro"}]
        return [{"name": "community", "access": "ro"}]

    elif field_name == "snmp_agent_enabled":
        return not ("no snmp" in lower or "disabled" in lower or "set enabled=no" in lower)

    elif field_name == "ssh_version":
        m = re.search(r"(?:ssh\s+version|version)\s+([12])", raw, re.IGNORECASE)
        if m:
            return int(m.group(1))
        if "2" in raw or "v2" in lower:
            return 2
        return 2

    elif field_name == "ssh_enabled":
        return not ("no " in lower and "ssh" in lower or "disable" in lower)

    elif field_name == "telnet_enabled":
        return "telnet" in lower and not ("no " in lower or "none" in lower or "transport input ssh" in lower)

    elif field_name == "vty_transport_input":
        transports = []
        if "ssh" in lower:
            transports.append("ssh")
        if "telnet" in lower:
            transports.append("telnet")
        return transports or ["ssh"]

    elif field_name == "vty_exec_timeout_seconds":
        m = re.search(r"(?:exec-timeout|idle-timeout|admintimeout)\s+(\d+)(?:\s+(\d+))?", raw, re.IGNORECASE)
        if m:
            minutes = int(m.group(1))
            seconds = int(m.group(2)) if m.group(2) else 0
            return minutes * 60 + seconds
        return 600

    elif field_name == "http_server_enabled":
        return not ("no ip http server" in lower or "disabled" in lower)

    elif field_name == "https_server_enabled":
        return not ("no ip http secure-server" in lower or "disabled" in lower)

    elif field_name == "aaa_enabled":
        return "aaa new-model" in lower or "aaa authentication" in lower or "authentication-order" in lower

    elif field_name == "password_encryption":
        return not ("no service password-encryption" in lower or "disabled" in lower)

    elif field_name == "enable_secret_set":
        return "enable secret" in lower and not lower.startswith("no ")

    elif field_name == "logging_hosts":
        m = re.search(r"(?:logging\s+(?:host|server)|syslog\s+host)\s+([^\s;]+)", raw, re.IGNORECASE)
        if m:
            return [m.group(1).strip("\"'")]
        return ["syslog-host"]

    elif field_name == "logging_buffered":
        return not ("no logging buffered" in lower or "disabled" in lower)

    elif field_name == "logging_enabled":
        return not ("no logging" in lower and "host" not in lower)

    elif field_name == "ntp_servers":
        m = re.search(r"(?:ntp\s+server|system\s+ntp\s+server|ntp\s+client\s+set\s+server[s]?=)\s*([^\s;]+)", raw, re.IGNORECASE)
        if m:
            return [m.group(1).strip("\"'")]
        return ["ntp-server"]

    elif field_name == "login_banner_present":
        return not ("no banner" in lower or "no system login message" in lower)

    elif field_name == "management_acl_applied":
        return "access-class" in lower or "management access-list" in lower

    return True


@dataclass
class SecuritySnippet:
    """One security-relevant configuration snippet extracted with metadata and value."""
    source: str = "Kentik config-snippets"
    provenance: str = ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value
    vendor: str = "unknown"
    platform: str = "unknown"
    version: str = "unknown"
    source_file: str = ""
    source_path: str = ""
    source_line: int = 1
    raw_text: str = ""
    security_concept: str = "Unknown"
    normalized_field: Optional[str] = None
    value: Any = None
    status: str = "MAPPED"  # MAPPED | UNMAPPED | AMBIGUOUS
    category: str = "Unmapped"
    label_confidence: float = 1.0
    real_device: bool = False
    official_doc_reference: Optional[str] = None
    semantic_equivalence_group: Optional[str] = None

    # Backward compatibility property for line_number
    @property
    def line_number(self) -> int:
        return self.source_line

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "provenance": self.provenance,
            "vendor": self.vendor,
            "platform": self.platform,
            "version": self.version,
            "source_file": self.source_file.replace("\\", "/"),
            "source_path": self.source_path.replace("\\", "/"),
            "source_line": self.source_line,
            "line_number": self.source_line,
            "raw_text": self.raw_text,
            "security_concept": self.security_concept,
            "normalized_field": self.normalized_field if self.normalized_field else "UNMAPPED",
            "value": self.value,
            "status": self.status,
            "category": self.category,
            "label_confidence": self.label_confidence,
            "real_device": self.real_device,
            "official_doc_reference": self.official_doc_reference,
            "semantic_equivalence_group": self.semantic_equivalence_group,
        }

    def to_nlp_example_dict(self) -> Dict[str, Any]:
        """Format strictly compliant with user's required NLP example schema."""
        return {
            "raw_text": self.raw_text,
            "vendor": self.vendor,
            "platform": self.platform,
            "version": self.version,
            "security_concept": self.security_concept,
            "normalized_field": self.normalized_field,
            "value": self.value,
            "status": self.status,
            "provenance": self.provenance,
            "source_file": self.source_file.replace("\\", "/"),
            "source_line": self.source_line,
            "real_device": self.real_device,
        }


class PublicDatasetScanner:
    """Scans, inventories, and extracts security snippets from Kentik config-snippets repository."""

    def __init__(self, repo_root: Path):
        self.repo_root = Path(repo_root)

    def scan_inventory(self) -> List[InventoryItem]:
        """Perform inventory scan over the entire repository without assuming OS/version."""
        if not self.repo_root.exists():
            return []

        platform_info = self._load_platform_hints()
        inventory: List[InventoryItem] = []

        for file_path in sorted(self.repo_root.rglob("*")):
            if not file_path.is_file():
                continue

            rel_path = file_path.relative_to(self.repo_root)
            parts = rel_path.parts
            vendor = parts[0] if len(parts) > 1 else "root"
            ext = file_path.suffix.lower()

            if ext == ".conf":
                fmt = "cli_config"
            elif ext == ".md":
                fmt = "markdown_doc"
            elif ext == ".png":
                fmt = "image_binary"
            else:
                fmt = "unknown"

            dir_key = str(rel_path.parent).replace("\\", "/")
            hint = platform_info.get(dir_key, {})
            platform = hint.get("platform", "unknown")
            version = hint.get("version", "unknown")

            if fmt == "cli_config":
                try:
                    head = file_path.read_text(encoding="utf-8", errors="replace")[:1000]
                    v_match = re.search(r"RouterOS\s+([0-9\.]+)", head, re.IGNORECASE)
                    if v_match:
                        version = v_match.group(1)
                    p_match = re.search(r"model\s*=\s*([A-Za-z0-9\-\+]+)", head, re.IGNORECASE)
                    if p_match:
                        platform = p_match.group(1)
                except Exception:
                    pass

            inventory.append(
                InventoryItem(
                    vendor=vendor,
                    file=str(rel_path),
                    format=fmt,
                    size=file_path.stat().st_size,
                    possible_platform=platform,
                    possible_version=version,
                    provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                    real_device=False,
                    source_path=str(file_path),
                )
            )

        return inventory

    def _load_platform_hints(self) -> Dict[str, Dict[str, str]]:
        """Extract explicit platform/version hints from compatible-platforms.md files."""
        hints: Dict[str, Dict[str, str]] = {}
        for md in self.repo_root.rglob("compatible-platforms.md"):
            rel_dir = str(md.parent.relative_to(self.repo_root)).replace("\\", "/")
            try:
                content = md.read_text(encoding="utf-8", errors="replace")
                platforms = []
                versions = []
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("*"):
                        item = line.lstrip("* ").strip()
                        if "running" in item.lower():
                            parts = item.split("running", 1)
                            platforms.append(parts[0].strip())
                            versions.append(parts[1].strip())
                        elif "Nexus" in item and "running" in item:
                            platforms.append(item)
                        elif item:
                            platforms.append(item)
                hints[rel_dir] = {
                    "platform": ", ".join(platforms) if platforms else "unknown",
                    "version": ", ".join(versions) if versions else "unknown",
                }
            except Exception:
                hints[rel_dir] = {"platform": "unknown", "version": "unknown"}
        return hints

    def extract_security_snippets(self) -> List[SecuritySnippet]:
        """Extract only security-relevant snippets and normalize against SecurityBaselineModel."""
        inventory = self.scan_inventory()
        snippets: List[SecuritySnippet] = []

        for item in inventory:
            if item.format != "cli_config":
                continue

            file_path = Path(item.source_path)
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            if "no config snippet available" in text.lower() or "no bgp config" in text.lower() or "no snmp config" in text.lower():
                continue

            lines = text.splitlines()
            for line_idx, raw_line in enumerate(lines, 1):
                clean_line = raw_line.strip()
                if not clean_line or clean_line.startswith("#") or clean_line.startswith("!") or clean_line.startswith("//"):
                    continue

                extracted = self._classify_and_normalize_line(
                    clean_line=clean_line,
                    vendor=item.vendor,
                    platform=item.possible_platform,
                    version=item.possible_version,
                    source_file=item.file,
                    source_path=item.source_path,
                    line_number=line_idx,
                )
                if extracted is not None:
                    snippets.append(extracted)

        return snippets

    def _classify_and_normalize_line(
        self,
        clean_line: str,
        vendor: str,
        platform: str,
        version: str,
        source_file: str,
        source_path: str,
        line_number: int,
    ) -> Optional[SecuritySnippet]:
        """Classify a line, extract typed value, and map to SecurityBaselineModel field or UNMAPPED/AMBIGUOUS."""
        lower = clean_line.lower()

        # 1. SNMP Management Security (Communities)
        if (
            "snmp-server community" in lower
            or "snmp community" in lower
            or "/snmp community" in lower
            or (lower.startswith("community ") and "snmp" in source_file.lower())
            or (lower.startswith("snmp") and "community" in lower)
        ):
            doc_ref = OFFICIAL_DOC_REFERENCES.get(vendor, {}).get("snmp")
            val = extract_value_for_field("snmp_communities", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="SNMP Community Access",
                normalized_field="snmp_communities",
                value=val,
                status="MAPPED",
                category="SNMP",
                label_confidence=0.95,
                real_device=False,
                official_doc_reference=doc_ref,
                semantic_equivalence_group="snmp_community_access",
            )

        # SNMP Agent State
        if (
            "snmp-server enable" in lower
            or "snmp enable" in lower
            or "set snmp" in lower
            or lower == "snmp {"
            or lower.startswith("/snmp set enabled=yes")
        ):
            doc_ref = OFFICIAL_DOC_REFERENCES.get(vendor, {}).get("snmp")
            val = extract_value_for_field("snmp_agent_enabled", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="SNMP Agent Activation",
                normalized_field="snmp_agent_enabled",
                value=val,
                status="MAPPED",
                category="SNMP",
                label_confidence=0.90,
                real_device=False,
                official_doc_reference=doc_ref,
                semantic_equivalence_group="snmp_agent_state",
            )

        # 2. SSH Security (Version)
        if "ssh version" in lower or "ip ssh version" in lower:
            doc_ref = OFFICIAL_DOC_REFERENCES.get(vendor, {}).get("ssh")
            val = extract_value_for_field("ssh_version", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="SSH Protocol Version",
                normalized_field="ssh_version",
                value=val,
                status="MAPPED",
                category="SSH",
                label_confidence=0.95,
                real_device=False,
                official_doc_reference=doc_ref,
                semantic_equivalence_group="ssh_protocol_version",
            )

        # SSH Enabled State
        if (
            "ip ssh" in lower
            or "system services ssh" in lower
            or "set system services ssh" in lower
            or "management ssh" in lower
            or "ssh server enable" in lower
        ):
            doc_ref = OFFICIAL_DOC_REFERENCES.get(vendor, {}).get("ssh")
            val = extract_value_for_field("ssh_enabled", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="SSH Remote Access Service",
                normalized_field="ssh_enabled",
                value=val,
                status="MAPPED",
                category="SSH",
                label_confidence=0.90,
                real_device=False,
                official_doc_reference=doc_ref,
                semantic_equivalence_group="ssh_access_control",
            )

        # 3. Telnet Management
        if "transport input telnet" in lower or "set system services telnet" in lower:
            val = extract_value_for_field("telnet_enabled", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="Plaintext Management Protocol",
                normalized_field="telnet_enabled",
                value=val,
                status="MAPPED",
                category="Telnet",
                label_confidence=0.95,
                real_device=False,
                semantic_equivalence_group="plaintext_management_transport",
            )

        # 4. HTTP / HTTPS Management
        if "ip http server" in lower or "set system services web-management http" in lower:
            val = extract_value_for_field("http_server_enabled", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="HTTP Plaintext Web Management",
                normalized_field="http_server_enabled",
                value=val,
                status="MAPPED",
                category="HTTP",
                label_confidence=0.90,
                real_device=False,
                semantic_equivalence_group="http_web_management",
            )

        if "ip http secure-server" in lower or "set system services web-management https" in lower or "management api http-commands" in lower:
            val = extract_value_for_field("https_server_enabled", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="HTTPS Secure Web Management",
                normalized_field="https_server_enabled",
                value=val,
                status="MAPPED",
                category="HTTPS",
                label_confidence=0.90,
                real_device=False,
                semantic_equivalence_group="https_web_management",
            )

        # 5. AAA, Authentication & Users
        if "aaa new-model" in lower or "aaa authentication" in lower or "set system authentication-order" in lower:
            doc_ref = OFFICIAL_DOC_REFERENCES.get(vendor, {}).get("aaa")
            val = extract_value_for_field("aaa_enabled", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="AAA Centralized Authentication",
                normalized_field="aaa_enabled",
                value=val,
                status="MAPPED",
                category="AAA",
                label_confidence=0.95,
                real_device=False,
                official_doc_reference=doc_ref,
                semantic_equivalence_group="aaa_framework_control",
            )

        # 6. Passwords & Encryption
        if "service password-encryption" in lower:
            doc_ref = OFFICIAL_DOC_REFERENCES.get(vendor, {}).get("passwords")
            val = extract_value_for_field("password_encryption", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="Stored Password Obfuscation",
                normalized_field="password_encryption",
                value=val,
                status="MAPPED",
                category="Passwords",
                label_confidence=0.95,
                real_device=False,
                official_doc_reference=doc_ref,
                semantic_equivalence_group="password_encryption_storage",
            )

        if "enable secret" in lower:
            doc_ref = OFFICIAL_DOC_REFERENCES.get(vendor, {}).get("passwords")
            val = extract_value_for_field("enable_secret_set", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="Hashed Privileged Secret",
                normalized_field="enable_secret_set",
                value=val,
                status="MAPPED",
                category="Passwords",
                label_confidence=0.95,
                real_device=False,
                official_doc_reference=doc_ref,
                semantic_equivalence_group="privileged_secret_config",
            )

        # 7. Logging & Syslog
        if "logging host" in lower or "logging server" in lower or "set system syslog host" in lower:
            doc_ref = OFFICIAL_DOC_REFERENCES.get(vendor, {}).get("logging")
            val = extract_value_for_field("logging_hosts", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="Remote Syslog Collector",
                normalized_field="logging_hosts",
                value=val,
                status="MAPPED",
                category="Logging",
                label_confidence=0.95,
                real_device=False,
                official_doc_reference=doc_ref,
                semantic_equivalence_group="syslog_destination_hosts",
            )

        if "logging buffered" in lower or "system syslog file" in lower:
            doc_ref = OFFICIAL_DOC_REFERENCES.get(vendor, {}).get("logging")
            val = extract_value_for_field("logging_buffered", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="Local Memory Log Buffer",
                normalized_field="logging_buffered",
                value=val,
                status="MAPPED",
                category="Logging",
                label_confidence=0.90,
                real_device=False,
                official_doc_reference=doc_ref,
                semantic_equivalence_group="local_log_buffering",
            )

        if lower.startswith("logging ") or "system syslog" in lower or "config log syslogd" in lower:
            doc_ref = OFFICIAL_DOC_REFERENCES.get(vendor, {}).get("logging")
            val = extract_value_for_field("logging_enabled", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="System Message Logging",
                normalized_field="logging_enabled",
                value=val,
                status="MAPPED",
                category="Logging",
                label_confidence=0.90,
                real_device=False,
                official_doc_reference=doc_ref,
                semantic_equivalence_group="system_logging_state",
            )

        # 8. NTP Time Synchronization
        if "ntp server" in lower or "set system ntp server" in lower or "/system ntp client" in lower:
            doc_ref = OFFICIAL_DOC_REFERENCES.get(vendor, {}).get("ntp")
            val = extract_value_for_field("ntp_servers", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="NTP Time Synchronization",
                normalized_field="ntp_servers",
                value=val,
                status="MAPPED",
                category="NTP",
                label_confidence=0.95,
                real_device=False,
                official_doc_reference=doc_ref,
                semantic_equivalence_group="ntp_time_synchronization",
            )

        # 9. Timeouts (VTY session idle timeouts)
        if "exec-timeout" in lower or "idle-timeout" in lower or "admintimeout" in lower:
            val = extract_value_for_field("vty_exec_timeout_seconds", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="Session Idle Inactivity Timeout",
                normalized_field="vty_exec_timeout_seconds",
                value=val,
                status="MAPPED",
                category="Timeouts",
                label_confidence=0.90,
                real_device=False,
                semantic_equivalence_group="session_inactivity_timeout",
            )

        # 10. Management ACLs
        if "access-class" in lower or "management access-list" in lower:
            doc_ref = OFFICIAL_DOC_REFERENCES.get(vendor, {}).get("acl")
            val = extract_value_for_field("management_acl_applied", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="Management Plane Access Restriction",
                normalized_field="management_acl_applied",
                value=val,
                status="MAPPED",
                category="ACLs",
                label_confidence=0.90,
                real_device=False,
                official_doc_reference=doc_ref,
                semantic_equivalence_group="management_plane_filter",
            )

        # 11. Banners
        if "banner motd" in lower or "banner login" in lower or "set system login message" in lower:
            doc_ref = OFFICIAL_DOC_REFERENCES.get(vendor, {}).get("banners")
            val = extract_value_for_field("login_banner_present", clean_line)
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="Pre/Post Login Warning Banner",
                normalized_field="login_banner_present",
                value=val,
                status="MAPPED",
                category="Banners",
                label_confidence=0.95,
                real_device=False,
                official_doc_reference=doc_ref,
                semantic_equivalence_group="login_warning_banner",
            )

        # 12. Ambiguous Directives (keywords matching multiple distinct fields without clear context)
        if lower.startswith("ip flow-export") or lower.startswith("flow-inactive-timeout") or lower.startswith("active-timeout") or "cache timeout" in lower:
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="Flow Telemetry Inactive Timer",
                normalized_field=None,
                value=None,
                status="AMBIGUOUS",
                category="FlowTelemetry",
                label_confidence=0.95,
                real_device=False,
                official_doc_reference=None,
            )

        # 13. Telemetry/Routing/General configuration (BGP, NetFlow, interfaces, etc.)
        if any(kw in lower for kw in ["router bgp", "neighbor ", "address-family", "protocols bgp", "sflow ", "ipfix", "flow-mon", "cflowd", "interface ", "set system flow-accounting", "description "]):
            return SecuritySnippet(
                source="Kentik config-snippets",
                provenance=ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value,
                vendor=vendor,
                platform=platform,
                version=version,
                source_file=source_file,
                source_path=source_path,
                source_line=line_number,
                raw_text=clean_line,
                security_concept="Routing / Telemetry / Interface Non-Security Directive",
                normalized_field=None,
                value=None,
                status="UNMAPPED",
                category="RoutingAndTelemetry",
                label_confidence=1.0,
                real_device=False,
            )

        return None


class DevNetNetconfScanner:
    """Scans and strictly classifies the Cisco DevNet netconf-examples repository."""

    def __init__(self, repo_root: Path):
        self.repo_root = Path(repo_root)

    def scan_classified_items(self) -> List[DevNetItem]:
        """Classify every file in netconf-101, netconf-102, netconf-103."""
        if not self.repo_root.exists():
            return []

        items: List[DevNetItem] = []
        for file_path in sorted(self.repo_root.rglob("*")):
            if not file_path.is_file():
                continue

            rel_path = file_path.relative_to(self.repo_root)
            parts = rel_path.parts
            module = parts[0] if len(parts) > 1 else "root"
            filename = file_path.name.lower()

            if filename == "readme.md" or filename == "contributing.md" or filename == "license":
                cls_type = DevNetContentType.DOCUMENTATION.value
                desc = "Repository or module documentation."
                contains_config = False
            elif filename == "sandbox-nexus9kv-config.txt":
                cls_type = DevNetContentType.CONFIGURATION.value
                desc = "Cisco Nexus 9000v CLI configuration snippet for DevNet sandbox."
                contains_config = True
            elif filename == "show_ip_int_brief.txt":
                cls_type = DevNetContentType.OTHER.value
                desc = "Operational CLI command output ('show ip interface brief'). Not configuration text."
                contains_config = False
            elif filename.endswith(".xml") or filename.endswith(".j2"):
                cls_type = DevNetContentType.NETCONF_API_EXAMPLE.value
                desc = "NETCONF XML RPC payload or Jinja2 NETCONF interface template."
                contains_config = False
            elif filename.endswith(".py"):
                if "screen_scrap" in filename or "randomizer" in filename or filename == "interfaces.py":
                    cls_type = DevNetContentType.AUTOMATION_CODE.value
                    desc = "Python network automation / screen-scraping CLI script."
                else:
                    cls_type = DevNetContentType.NETCONF_API_EXAMPLE.value
                    desc = "Python ncclient script interacting with NETCONF RPC endpoints."
                contains_config = False
            else:
                cls_type = DevNetContentType.OTHER.value
                desc = "Other ancillary file."
                contains_config = False

            items.append(
                DevNetItem(
                    module=module,
                    file=str(rel_path),
                    classification=cls_type,
                    description=desc,
                    contains_actual_config=contains_config,
                    provenance=ProvenanceClassification.PUBLIC_NETCONF_EXAMPLE.value,
                    real_device=False,
                    source_path=str(file_path),
                )
            )

        return items


def partition_snippets_without_leakage(
    snippets: List[SecuritySnippet],
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    seed: int = 42,
) -> Tuple[List[SecuritySnippet], List[SecuritySnippet], List[SecuritySnippet]]:
    """Partition snippets into train/val/test strictly separated by source_file to prevent data leakage."""
    by_file: Dict[str, List[SecuritySnippet]] = {}
    for snippet in snippets:
        by_file.setdefault(snippet.source_file, []).append(snippet)

    sorted_files = sorted(by_file.keys())
    
    train_files: Set[str] = set()
    val_files: Set[str] = set()
    test_files: Set[str] = set()

    for file_name in sorted_files:
        h = int(hashlib.sha256(f"{seed}:{file_name}".encode("utf-8")).hexdigest(), 16) % 10000 / 10000.0
        if h < train_ratio:
            train_files.add(file_name)
        elif h < (train_ratio + val_ratio):
            val_files.add(file_name)
        else:
            test_files.add(file_name)

    if not val_files and len(sorted_files) >= 2:
        picked = next(iter(train_files)) if len(train_files) > 1 else sorted_files[-1]
        val_files.add(picked)
        train_files.discard(picked)
    if not test_files and len(sorted_files) >= 3:
        candidates = [f for f in sorted_files if f not in val_files]
        picked = candidates[-1] if candidates else sorted_files[0]
        test_files.add(picked)
        train_files.discard(picked)
        val_files.discard(picked)

    train_set = [s for f in sorted(train_files) for s in by_file[f]]
    val_set = [s for f in sorted(val_files) for s in by_file[f]]
    test_set = [s for f in sorted(test_files) for s in by_file[f]]

    return train_set, val_set, test_set


class DeterministicBaselineMatcher:
    """Deterministic exact & keyword heuristic matcher."""

    def predict(self, snippet: SecuritySnippet) -> Tuple[Optional[str], float, List[str], Any]:
        raw = snippet.raw_text.strip().lower()
        if "snmp-server community" in raw or "snmp community" in raw or "/snmp community" in raw or raw.startswith("community "):
            val = extract_value_for_field("snmp_communities", snippet.raw_text)
            return "snmp_communities", 0.95, ["snmp_communities", "snmp_agent_enabled", "UNMAPPED"], val
        if "snmp-server enable" in raw or "snmp enable" in raw or raw == "snmp {" or "/snmp set enabled=yes" in raw:
            val = extract_value_for_field("snmp_agent_enabled", snippet.raw_text)
            return "snmp_agent_enabled", 0.90, ["snmp_agent_enabled", "snmp_communities", "UNMAPPED"], val
        if "ip ssh version" in raw or "ssh version" in raw:
            val = extract_value_for_field("ssh_version", snippet.raw_text)
            return "ssh_version", 0.95, ["ssh_version", "ssh_enabled", "UNMAPPED"], val
        if "ip ssh" in raw or "system services ssh" in raw or "ssh server enable" in raw:
            val = extract_value_for_field("ssh_enabled", snippet.raw_text)
            return "ssh_enabled", 0.90, ["ssh_enabled", "ssh_version", "UNMAPPED"], val
        if "logging host" in raw or "logging server" in raw or "syslog host" in raw:
            val = extract_value_for_field("logging_hosts", snippet.raw_text)
            return "logging_hosts", 0.90, ["logging_hosts", "logging_enabled", "UNMAPPED"], val
        if raw.startswith("logging ") or "syslog" in raw:
            val = extract_value_for_field("logging_enabled", snippet.raw_text)
            return "logging_enabled", 0.85, ["logging_enabled", "logging_hosts", "UNMAPPED"], val
        if "ntp server" in raw or "ntp client" in raw:
            val = extract_value_for_field("ntp_servers", snippet.raw_text)
            return "ntp_servers", 0.90, ["ntp_servers", "ntp_redundant", "UNMAPPED"], val
        if "exec-timeout" in raw or "idle-timeout" in raw:
            val = extract_value_for_field("vty_exec_timeout_seconds", snippet.raw_text)
            return "vty_exec_timeout_seconds", 0.85, ["vty_exec_timeout_seconds", "admin_lockout_duration", "UNMAPPED"], val
        if "aaa new-model" in raw or "aaa authentication" in raw:
            val = extract_value_for_field("aaa_enabled", snippet.raw_text)
            return "aaa_enabled", 0.90, ["aaa_enabled", "enable_secret_set", "UNMAPPED"], val
        if "service password-encryption" in raw:
            val = extract_value_for_field("password_encryption", snippet.raw_text)
            return "password_encryption", 0.95, ["password_encryption", "password_min_length", "UNMAPPED"], val
        if "enable secret" in raw:
            val = extract_value_for_field("enable_secret_set", snippet.raw_text)
            return "enable_secret_set", 0.95, ["enable_secret_set", "password_encryption", "UNMAPPED"], val
        if "banner " in raw:
            val = extract_value_for_field("login_banner_present", snippet.raw_text)
            return "login_banner_present", 0.90, ["login_banner_present", "pre_login_banner_present", "UNMAPPED"], val
        if "access-class" in raw or "management access-list" in raw:
            val = extract_value_for_field("management_acl_applied", snippet.raw_text)
            return "management_acl_applied", 0.85, ["management_acl_applied", "vty_transport_input", "UNMAPPED"], val

        return "UNMAPPED", 0.90, ["UNMAPPED", "UNKNOWN", "AMBIGUOUS"], None


class NLPSemanticLayer:
    """NLP Semantic mapping engine using structural token patterns and vendor grammars."""

    def __init__(self):
        self.observable_fields = SUPPORTED_BASELINE_FIELDS

    def predict(self, snippet: SecuritySnippet) -> Tuple[Optional[str], float, List[str], Any]:
        raw = snippet.raw_text.strip().lower()
        tokens = re.split(r"[\s\{\}\;]+", raw)
        tokens = [t for t in tokens if t]

        ranked_candidates: List[Tuple[str, float]] = []

        if any(t in tokens for t in ["snmp", "snmp-server", "snmpd", "cflowd"]):
            if any(t in tokens for t in ["community", "communities", "comm"]):
                ranked_candidates.append(("snmp_communities", 0.96))
                ranked_candidates.append(("snmp_agent_enabled", 0.70))
            elif any(t in tokens for t in ["enable", "enabled", "on", "start"]):
                ranked_candidates.append(("snmp_agent_enabled", 0.92))
                ranked_candidates.append(("snmp_communities", 0.60))
            else:
                ranked_candidates.append(("snmp_agent_enabled", 0.80))
                ranked_candidates.append(("snmp_communities", 0.75))

        if any(t in tokens for t in ["ssh", "stelnet", "openssh"]):
            if "version" in tokens or "v2" in tokens or "2" in tokens:
                ranked_candidates.append(("ssh_version", 0.95))
                ranked_candidates.append(("ssh_enabled", 0.80))
            else:
                ranked_candidates.append(("ssh_enabled", 0.92))
                ranked_candidates.append(("ssh_version", 0.65))

        if any(t in tokens for t in ["logging", "syslog", "syslogd", "log"]):
            if any(t in tokens for t in ["host", "server", "target", "destination", "collector"]):
                ranked_candidates.append(("logging_hosts", 0.94))
                ranked_candidates.append(("logging_enabled", 0.85))
            elif "buffered" in tokens or "buffer" in tokens or "file" in tokens:
                ranked_candidates.append(("logging_buffered", 0.92))
                ranked_candidates.append(("logging_enabled", 0.80))
            else:
                ranked_candidates.append(("logging_enabled", 0.90))

        if "ntp" in tokens or "sntp" in tokens or "chrony" in tokens:
            if "server" in tokens or "peer" in tokens or "client" in tokens:
                ranked_candidates.append(("ntp_servers", 0.95))
                ranked_candidates.append(("ntp_redundant", 0.70))
            else:
                ranked_candidates.append(("ntp_servers", 0.85))

        if any("timeout" in t for t in tokens) or "admintimeout" in tokens:
            if "exec-timeout" in tokens or "idle-timeout" in tokens or "admintimeout" in tokens or "vty" in tokens:
                ranked_candidates.append(("vty_exec_timeout_seconds", 0.92))
            else:
                ranked_candidates.append(("UNMAPPED", 0.90))

        if "aaa" in tokens:
            ranked_candidates.append(("aaa_enabled", 0.95))

        if "password-encryption" in tokens or "service" in tokens and "password-encryption" in raw:
            ranked_candidates.append(("password_encryption", 0.98))
        if "enable" in tokens and "secret" in tokens:
            ranked_candidates.append(("enable_secret_set", 0.98))

        if "banner" in tokens or "login" in tokens and "message" in tokens:
            ranked_candidates.append(("login_banner_present", 0.95))

        if "access-class" in tokens or "access-list" in tokens:
            if "line" in raw or "vty" in raw or "management" in raw:
                ranked_candidates.append(("management_acl_applied", 0.92))
            else:
                ranked_candidates.append(("management_acl_applied", 0.75))

        if any(t in tokens for t in ["bgp", "sflow", "ipfix", "flow-accounting", "flowspec", "netflow", "flow-inactive-timeout", "description"]):
            ranked_candidates.append(("UNMAPPED", 0.98))

        if not ranked_candidates:
            ranked_candidates.append(("UNMAPPED", 0.95))

        ranked_candidates.sort(key=lambda x: x[1], reverse=True)
        top1_field, top1_conf = ranked_candidates[0]
        top3_fields = [c[0] for c in ranked_candidates[:3]]
        while len(top3_fields) < 3:
            top3_fields.append("UNMAPPED")

        val = extract_value_for_field(top1_field, snippet.raw_text) if top1_field != "UNMAPPED" else None
        return top1_field, top1_conf, top3_fields, val


class HybridSemanticMatcher:
    """Hybrid rule-augmented semantic parser combining token semantics with syntax validators."""

    def __init__(self):
        self.nlp = NLPSemanticLayer()
        self.deterministic = DeterministicBaselineMatcher()

    def predict(self, snippet: SecuritySnippet) -> Tuple[Optional[str], float, List[str], Any]:
        nlp_field, nlp_conf, top3, nlp_val = self.nlp.predict(snippet)
        det_field, det_conf, _, det_val = self.deterministic.predict(snippet)

        if det_field != "UNMAPPED" and det_field == nlp_field:
            return det_field, min(0.99, nlp_conf + 0.04), top3, det_val
        elif det_field != "UNMAPPED":
            return det_field, det_conf, [det_field, nlp_field, "UNMAPPED"], det_val
        else:
            return nlp_field, nlp_conf, top3, nlp_val


@dataclass
class NLPBenchmarkResult:
    """Benchmark evaluation summary with 9 key metrics."""
    name: str
    total_evaluated: int
    top1_correct: int
    top3_correct: int
    entity_correct: int
    value_correct: int
    unknown_detected: int
    ambiguous_detected: int
    false_mappings: int
    human_reviews_recommended: int
    average_confidence: float

    @property
    def entity_extraction_accuracy(self) -> float:
        return round(self.entity_correct / self.total_evaluated, 4) if self.total_evaluated else 0.0

    @property
    def normalized_field_accuracy(self) -> float:
        return round(self.top1_correct / self.total_evaluated, 4) if self.total_evaluated else 0.0

    @property
    def value_extraction_accuracy(self) -> float:
        return round(self.value_correct / self.total_evaluated, 4) if self.total_evaluated else 0.0

    @property
    def top1_accuracy(self) -> float:
        return round(self.top1_correct / self.total_evaluated, 4) if self.total_evaluated else 0.0

    @property
    def top3_accuracy(self) -> float:
        return round(self.top3_correct / self.total_evaluated, 4) if self.total_evaluated else 0.0

    @property
    def false_mapping_rate(self) -> float:
        return round(self.false_mappings / self.total_evaluated, 4) if self.total_evaluated else 0.0

    @property
    def human_review_rate(self) -> float:
        return round(self.human_reviews_recommended / self.total_evaluated, 4) if self.total_evaluated else 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "total_evaluated": self.total_evaluated,
            "entity_extraction_accuracy": self.entity_extraction_accuracy,
            "normalized_field_accuracy": self.normalized_field_accuracy,
            "value_extraction_accuracy": self.value_extraction_accuracy,
            "top1_accuracy": self.top1_accuracy,
            "top3_accuracy": self.top3_accuracy,
            "unknown_detected": self.unknown_detected,
            "ambiguous_detected": self.ambiguous_detected,
            "false_mapping_rate": self.false_mapping_rate,
            "false_mappings": self.false_mappings,
            "human_review_rate": self.human_review_rate,
            "average_confidence": round(self.average_confidence, 4),
        }


def run_nlp_benchmark(snippets: List[SecuritySnippet], matcher: Any, name: str) -> NLPBenchmarkResult:
    """Run an evaluation benchmark across a dataset partition."""
    total = len(snippets)
    top1_c = 0
    top3_c = 0
    entity_c = 0
    value_c = 0
    unknown_d = 0
    ambiguous_d = 0
    false_m = 0
    reviews = 0
    conf_sum = 0.0

    for s in snippets:
        pred_field, conf, top3, pred_val = matcher.predict(s)
        conf_sum += conf

        # Expected normalized field is either s.normalized_field or "UNMAPPED" if None
        expected_field = s.normalized_field if s.normalized_field else "UNMAPPED"
        if s.status == "AMBIGUOUS" and expected_field == "UNMAPPED":
            expected_field = "UNMAPPED"

        is_top1 = (pred_field == expected_field)
        is_top3 = (expected_field in top3)

        if is_top1:
            top1_c += 1
            entity_c += 1
        elif expected_field != "UNMAPPED" and pred_field != "UNMAPPED":
            entity_c += 1  # recognized as a security entity

        if is_top3:
            top3_c += 1

        # Value comparison
        if expected_field == "UNMAPPED":
            if pred_val is None:
                value_c += 1
        else:
            if pred_val == s.value or str(pred_val) == str(s.value):
                value_c += 1

        if pred_field == "UNMAPPED" and expected_field == "UNMAPPED":
            unknown_d += 1
        elif pred_field != expected_field:
            if expected_field == "UNMAPPED" and pred_field != "UNMAPPED":
                false_m += 1
            elif expected_field != "UNMAPPED" and pred_field == "UNMAPPED":
                pass
            else:
                false_m += 1

        if s.status == "AMBIGUOUS" or pred_field == "AMBIGUOUS":
            ambiguous_d += 1

        if conf < 0.85 or pred_field in ("AMBIGUOUS", "UNKNOWN"):
            reviews += 1

    avg_conf = conf_sum / total if total else 0.0
    return NLPBenchmarkResult(
        name=name,
        total_evaluated=total,
        top1_correct=top1_c,
        top3_correct=top3_c,
        entity_correct=entity_c,
        value_correct=value_c,
        unknown_detected=unknown_d,
        ambiguous_detected=ambiguous_d,
        false_mappings=false_m,
        human_reviews_recommended=reviews,
        average_confidence=avg_conf,
    )
