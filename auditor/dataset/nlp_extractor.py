"""NLP and pattern-based structured command and configuration extraction pipeline."""

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .extractor import DocumentSection, ExtractedDocument

logger = logging.getLogger(__name__)

# Security domain mappings
SECURITY_DOMAINS = {
    "ssh": "management_ssh",
    "http": "management_http",
    "https": "management_https",
    "telnet": "management_telnet",
    "snmp": "management_snmp",
    "ntp": "time_synchronization",
    "logging": "system_logging",
    "log": "system_logging",
    "syslog": "system_logging",
    "aaa": "authentication_authorization_accounting",
    "tacacs": "authentication_tacacs",
    "radius": "authentication_radius",
    "password": "credential_protection",
    "secret": "credential_protection",
    "banner": "warning_banners",
    "motd": "warning_banners",
    "acl": "access_control",
    "access-list": "access_control",
    "firewall": "firewall_filter",
    "rule": "firewall_rule",
    "security-zone": "zone_security",
    "zone": "zone_security",
    "tls": "transport_layer_security",
    "ssl": "transport_layer_security",
    "session-timeout": "session_timeout",
    "exec-timeout": "session_timeout",
    "admin-lockout": "account_lockout",
}


@dataclass
class ExtractedCommand:
    vendor: str
    command: str
    negated_command: Optional[str]
    mode: str
    security_relevance: Optional[str]
    source_document: str
    source_url: str
    page_or_section: str
    version: str
    extraction_method: str  # "deterministic_pattern", "nlp_section_classifier", "ast_hierarchy"
    provenance_status: str  # "SOURCE VERIFIED" or "MODEL INFERRED"
    arguments: List[str] = field(default_factory=list)
    default_value: Optional[str] = None
    prerequisites: Optional[str] = None
    warning_note: Optional[str] = None
    is_authoritative: bool = True


class NLPCommandExtractor:
    """Extracts structured vendor command and configuration syntax from extracted document sections."""

    def __init__(self, dataset_base: Path = Path("dataset")):
        self.dataset_base = Path(dataset_base)
        self.vendor_ref_base = self.dataset_base / "vendor_references"

    def _classify_security_relevance(self, command_str: str) -> Optional[str]:
        lower = command_str.lower()
        for kw, domain in SECURITY_DOMAINS.items():
            # Match whole words or prefixes
            if re.search(r"\b" + re.escape(kw) + r"\b", lower):
                return domain
        return None

    def _extract_cisco_commands(self, text: str, source_doc: str, source_url: str, section_name: str, version: str) -> List[ExtractedCommand]:
        results: List[ExtractedCommand] = []
        seen = set()

        patterns = [
            # Global config commands: ip ssh ..., service ..., no ip ..., username ..., etc.
            r"^(?:(?:switch|router)\(config[a-z0-9-]*\)#\s*|\b)((?:ip\s+ssh|ip\s+http|ip\s+domain|service\s+password-encryption|service\s+timestamps|logging\s+[a-z0-9-]+|snmp-server\s+[a-z0-9-]+|ntp\s+[a-z0-9-]+|aaa\s+[a-z0-9-]+|banner\s+[a-z0-9-]+|line\s+(?:vty|con|aux)|transport\s+input|exec-timeout|access-class|enable\s+secret|username\s+\S+\s+secret|no\s+ip\s+http\s+server|no\s+ip\s+http\s+secure-server|no\s+service\s+password-recovery)[^\n\r]*)",
            # Standard command lines in code blocks or lists
            r"^\s*([a-z0-9-]+\s+[a-z0-9-]+(?:\s+[a-z0-9-]+)*)\s*$",
        ]

        for line in text.splitlines():
            clean = line.strip()
            if not clean or clean.startswith("!") or clean.startswith("#"):
                continue

            for pat in patterns:
                m = re.match(pat, clean, re.IGNORECASE)
                if m:
                    cmd_raw = m.group(1).strip()
                    if len(cmd_raw) < 5 or cmd_raw in seen:
                        continue

                    # Filter out non-command English sentences
                    if any(w in cmd_raw.lower() for w in ["the following", "this section", "for example", "to configure", "refer to"]):
                        continue

                    seen.add(cmd_raw)
                    negated = None
                    if cmd_raw.startswith("no "):
                        negated = cmd_raw
                    else:
                        negated = f"no {cmd_raw}"

                    mode = "global_config"
                    if "line vty" in cmd_raw or "line con" in cmd_raw:
                        mode = "line_config"
                    elif "interface" in cmd_raw:
                        mode = "interface_config"
                    elif "transport" in cmd_raw or "exec-timeout" in cmd_raw or "access-class" in cmd_raw:
                        mode = "line_submode"

                    sec_rel = self._classify_security_relevance(cmd_raw)
                    parts = cmd_raw.split()
                    args = parts[2:] if len(parts) > 2 else []

                    results.append(ExtractedCommand(
                        vendor="cisco_ios",
                        command=cmd_raw,
                        negated_command=negated,
                        mode=mode,
                        security_relevance=sec_rel,
                        source_document=source_doc,
                        source_url=source_url,
                        page_or_section=section_name,
                        version=version or "IOS-XE",
                        extraction_method="deterministic_pattern",
                        provenance_status="SOURCE VERIFIED",
                        arguments=args,
                    ))

        return results

    def _extract_junos_commands(self, text: str, source_doc: str, source_url: str, section_name: str, version: str) -> List[ExtractedCommand]:
        results: List[ExtractedCommand] = []
        seen = set()

        for line in text.splitlines():
            clean = line.strip()
            # set system services ssh ...
            m_set = re.match(r"^set\s+([a-z0-9-_\s]+)", clean, re.IGNORECASE)
            if m_set:
                cmd_raw = clean
                if cmd_raw in seen:
                    continue
                seen.add(cmd_raw)
                sec_rel = self._classify_security_relevance(cmd_raw)
                negated = "delete " + clean[4:]
                results.append(ExtractedCommand(
                    vendor="juniper_junos",
                    command=cmd_raw,
                    negated_command=negated,
                    mode="set_syntax",
                    security_relevance=sec_rel,
                    source_document=source_doc,
                    source_url=source_url,
                    page_or_section=section_name,
                    version=version or "Junos OS",
                    extraction_method="deterministic_pattern",
                    provenance_status="SOURCE VERIFIED",
                ))

        return results

    def _extract_fortinet_commands(self, text: str, source_doc: str, source_url: str, section_name: str, version: str) -> List[ExtractedCommand]:
        results: List[ExtractedCommand] = []
        seen = set()

        for line in text.splitlines():
            clean = line.strip()
            if clean.startswith("config ") or clean.startswith("set ") or clean.startswith("edit ") or clean.startswith("unset "):
                if clean in seen or len(clean) < 5:
                    continue
                seen.add(clean)
                sec_rel = self._classify_security_relevance(clean)
                negated = clean.replace("set ", "unset ") if clean.startswith("set ") else None
                mode = "config_block" if clean.startswith("config ") else "set_statement"
                results.append(ExtractedCommand(
                    vendor="fortinet_fortios",
                    command=clean,
                    negated_command=negated,
                    mode=mode,
                    security_relevance=sec_rel,
                    source_document=source_doc,
                    source_url=source_url,
                    page_or_section=section_name,
                    version=version or "FortiOS",
                    extraction_method="deterministic_pattern",
                    provenance_status="SOURCE VERIFIED",
                ))
        return results

    def _extract_generic_vendor_commands(self, vendor_key: str, text: str, source_doc: str, source_url: str, section_name: str, version: str) -> List[ExtractedCommand]:
        results: List[ExtractedCommand] = []
        seen = set()

        # Keywords per vendor
        for line in text.splitlines():
            clean = line.strip()
            if not clean or len(clean) < 4:
                continue

            matched = False
            mode = "cli_command"
            negated = None

            if vendor_key == "arista_eos":
                if re.match(r"^(?:no\s+)?(?:ip|management|service|logging|snmp-server|ntp|banner|username|aaa|line)\b", clean, re.IGNORECASE):
                    matched = True
                    mode = "global_config"
                    negated = f"no {clean}" if not clean.startswith("no ") else clean
            elif vendor_key == "checkpoint_gaia":
                if re.match(r"^(?:set|show|add|delete)\s+(?:snmp|ntp|syslog|aaa|user|banner|password-controls|sshd)\b", clean, re.IGNORECASE):
                    matched = True
                    mode = "clish"
                    negated = clean.replace("set ", "delete ") if clean.startswith("set ") else None
            elif vendor_key == "mikrotik_routeros":
                if re.match(r"^(?:/ip|/system|/user|/interface|/tool|/certificate|/routing)\s+[a-z0-9-_]+", clean, re.IGNORECASE):
                    matched = True
                    mode = "routeros_tree"
            elif vendor_key == "sonicwall":
                if re.match(r"^(?:config|set|no|show|user|administration|logging|snmp|ntp)\b", clean, re.IGNORECASE):
                    matched = True
                    mode = "sonicos_cli"
            elif vendor_key == "stormshield":
                if re.match(r"^(?:CONFIG|HELP|SYSTEM|PKI|OBJECT|AUTH|HA|ALARM)\s+[A-Z0-9_]+", clean):
                    matched = True
                    mode = "serverd_config"
            elif vendor_key == "watchguard_fireware":
                if re.match(r"^(?:global|diagnose|show|ip|logging|ntp|snmp|user|interface)\b", clean, re.IGNORECASE):
                    matched = True
                    mode = "fireware_cli"
            elif vendor_key == "paloalto_panos":
                if re.match(r"^set\s+(?:deviceconfig|system|security-profiles|rulebase|mgt-config)\b", clean, re.IGNORECASE):
                    matched = True
                    mode = "panos_set"
            elif vendor_key == "sonic":
                if re.match(r"^(?:config\s+|show\s+|sonic-cli|sonic-cfggen)\b", clean, re.IGNORECASE):
                    matched = True
                    mode = "sonic_cli"
            elif vendor_key == "huawei_vrp":
                if re.match(r"^(?:undo\s+)?(?:stelnet|ssh|snmp-agent|ntp-service|info-center|header|local-user|aaa)\b", clean, re.IGNORECASE):
                    matched = True
                    mode = "system_view"
                    negated = f"undo {clean}" if not clean.startswith("undo ") else clean

            if matched:
                if clean in seen:
                    continue
                seen.add(clean)
                sec_rel = self._classify_security_relevance(clean)
                results.append(ExtractedCommand(
                    vendor=vendor_key,
                    command=clean,
                    negated_command=negated,
                    mode=mode,
                    security_relevance=sec_rel,
                    source_document=source_doc,
                    source_url=source_url,
                    page_or_section=section_name,
                    version=version,
                    extraction_method="deterministic_pattern",
                    provenance_status="SOURCE VERIFIED",
                ))

        return results

    def extract_from_document(self, extracted_doc: ExtractedDocument, source_url: str = "") -> List[ExtractedCommand]:
        """Extract structured commands from an ExtractedDocument across all sections."""
        all_commands: List[ExtractedCommand] = []
        vendor = extracted_doc.vendor_key

        for section in extracted_doc.sections:
            sec_text = section.content + "\n" + "\n".join(section.code_blocks)
            sec_name = section.heading

            if vendor == "cisco_ios":
                cmds = self._extract_cisco_commands(sec_text, extracted_doc.source_filename, source_url, sec_name, extracted_doc.version)
            elif vendor == "juniper_junos":
                cmds = self._extract_junos_commands(sec_text, extracted_doc.source_filename, source_url, sec_name, extracted_doc.version)
            elif vendor == "fortinet_fortios":
                cmds = self._extract_fortinet_commands(sec_text, extracted_doc.source_filename, source_url, sec_name, extracted_doc.version)
            else:
                cmds = self._extract_generic_vendor_commands(vendor, sec_text, extracted_doc.source_filename, source_url, sec_name, extracted_doc.version)

            all_commands.extend(cmds)

        return all_commands

    def save_vendor_commands(self, vendor_key: str, commands: List[ExtractedCommand]) -> Path:
        """Persist structured command knowledge base for a vendor."""
        cmd_dir = self.vendor_ref_base / vendor_key / "commands"
        cmd_dir.mkdir(parents=True, exist_ok=True)
        json_path = cmd_dir / "commands.json"
        jsonl_path = cmd_dir / "commands.jsonl"

        # Deduplicate commands by command string + mode
        unique_cmds: Dict[str, ExtractedCommand] = {}
        for c in commands:
            key = f"{c.mode}:{c.command}"
            if key not in unique_cmds:
                unique_cmds[key] = c

        cmd_list = list(unique_cmds.values())

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump([asdict(c) for c in cmd_list], f, indent=2)

        with open(jsonl_path, "w", encoding="utf-8") as f:
            for c in cmd_list:
                f.write(json.dumps(asdict(c)) + "\n")

        return json_path
