"""Deterministic Stormshield SNS (Stormshield Network Security) configuration parser.

This parser processes Stormshield SNS INI-style configuration files (e.g. conf/admin, conf/syslog)
or CLI show outputs, normalizes verified settings into the SecurityBaselineModel,
and preserves configuration lines and line numbers for compliance audit evidence.
"""

import hashlib
import re
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class StormshieldSNSParser(VendorParser):
    """INI-style configuration parser for Stormshield SNS."""

    name = "stormshield_sns"
    vendor = "stormshield"
    os_family = "sns"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        
        score = 0.0
        if "[WebAdmin]" in config_text:
            score += 0.4
        if "[Console]" in config_text:
            score += 0.4
        if "HTTPEnable=" in config_text:
            score += 0.2
        if "SSHEnable=" in config_text:
            score += 0.2
        if "CONFIG WEBADMIN SHOW" in config_text:
            score += 0.5
            
        return min(1.0, score)

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        self._raw_lines = config_text.splitlines()
        
        baseline = SecurityBaselineModel(
            provenance=ParserProvenance(
                parser_name=self.name,
                parser_version=self.version,
                vendor=self.vendor,
                os_family=self.os_family,
                detection_confidence=self.detect(config_text),
            ),
            source_file=source_file,
            source_sha256=hashlib.sha256(config_text.encode("utf-8", errors="replace")).hexdigest(),
            config_line_count=len(self._raw_lines),
        )

        # Parse sections
        sections = self._parse_ini_sections()

        self._normalize_hostname(sections, baseline)
        self._normalize_http_https(sections, baseline)
        self._normalize_ssh_telnet(sections, baseline)
        self._normalize_session_timeout(sections, baseline)
        self._normalize_dns(sections, baseline)
        self._normalize_ntp(sections, baseline)
        self._normalize_logging(sections, baseline)

        # Set all remaining unparsed fields to unknown
        for field in baseline.observable_fields():
            observation = getattr(baseline, field)
            if observation.note == "Parser did not evaluate this field.":
                setattr(
                    baseline,
                    field,
                    type(observation).unknown(
                        "Stormshield SNS parser does not evaluate this field."
                    )
                )

        return baseline

    def _parse_ini_sections(self) -> Dict[str, Dict[str, Tuple[str, int]]]:
        """Parse configuration into sections, key-value pairs, and line numbers."""
        sections = {}
        current_section = "default"
        sections[current_section] = {}

        section_pat = re.compile(r'^\s*\[([^\]]+)\]\s*$')
        kv_pat = re.compile(r'^\s*([^\s=]+)\s*=\s*(.*?)\s*$')

        for idx, line in enumerate(self._raw_lines):
            line_strip = line.strip()
            if not line_strip or line_strip.startswith('#') or line_strip.startswith(';'):
                continue

            sec_match = section_pat.match(line_strip)
            if sec_match:
                current_section = sec_match.group(1).strip()
                if current_section not in sections:
                    sections[current_section] = {}
                continue

            kv_match = kv_pat.match(line_strip)
            if kv_match:
                key = kv_match.group(1).strip()
                val = kv_match.group(2).strip()
                sections[current_section][key] = (val, idx + 1)

        return sections

    def _evidence(self, section: str, key: str, value: str, line_num: int) -> Tuple[str, int, str]:
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"Section [{section}], Line {line_num}: {key}={value}"

    def _normalize_hostname(self, sections: dict, baseline: SecurityBaselineModel) -> None:
        # Match Name in [System] or [Active]
        name_info = None
        for sec in ["System", "Active"]:
            if sec in sections and "Name" in sections[sec]:
                name_info = (sec, "Name", sections[sec]["Name"])
                break

        if name_info:
            sec, key, (val, line) = name_info
            raw, line_num, note = self._evidence(sec, key, val, line)
            baseline.hostname = Observation[str].found(val, raw, line_num, note=note)
        else:
            baseline.hostname = Observation[str].unknown("Hostname is not configured in this config file.")

    def _normalize_http_https(self, sections: dict, baseline: SecurityBaselineModel) -> None:
        # WebAdmin section
        sec = "WebAdmin"
        if sec in sections:
            # HTTP Status
            if "HTTPEnable" in sections[sec]:
                val, line = sections[sec]["HTTPEnable"]
                raw, line_num, note = self._evidence(sec, "HTTPEnable", val, line)
                is_enabled = val.lower() in ("1", "yes", "true", "enable", "on")
                baseline.http_server_enabled = Observation[bool].found(is_enabled, raw, line_num, note=note)
            else:
                # Default WebAdmin HTTP is disabled in Stormshield SNS
                baseline.http_server_enabled = Observation[bool].absent(
                    False, "WebAdmin HTTP is disabled by default in Stormshield SNS."
                )

            # HTTPS Status
            if "State" in sections[sec]:
                val, line = sections[sec]["State"]
                raw, line_num, note = self._evidence(sec, "State", val, line)
                is_enabled = val.lower() in ("1", "yes", "true", "enable", "on")
                baseline.https_server_enabled = Observation[bool].found(is_enabled, raw, line_num, note=note)
            else:
                # Default WebAdmin HTTPS is enabled
                baseline.https_server_enabled = Observation[bool].absent(
                    True, "WebAdmin HTTPS is enabled by default in Stormshield SNS."
                )
        else:
            baseline.http_server_enabled = Observation[bool].unknown("WebAdmin section not found.")
            baseline.https_server_enabled = Observation[bool].unknown("WebAdmin section not found.")

    def _normalize_ssh_telnet(self, sections: dict, baseline: SecurityBaselineModel) -> None:
        # Telnet is disabled/unsupported on modern SNS firewalls
        baseline.telnet_enabled = Observation[bool].absent(
            False, "Telnet is unsupported on Stormshield SNS."
        )

        # SSH Console section
        sec = "Console"
        if sec in sections:
            if "SSHEnable" in sections[sec]:
                val, line = sections[sec]["SSHEnable"]
                raw, line_num, note = self._evidence(sec, "SSHEnable", val, line)
                is_enabled = val.lower() in ("1", "yes", "true", "enable", "on")
                baseline.ssh_enabled = Observation[bool].found(is_enabled, raw, line_num, note=note)
                baseline.vty_transport_input = Observation[List[str]].found(
                    ["ssh"] if is_enabled else [], raw, line_num, note=note
                )
            else:
                # Default SSH: Return unknown because interface access rules may vary
                baseline.ssh_enabled = Observation[bool].unknown("SSH configuration is absent.")
                baseline.vty_transport_input = Observation[List[str]].unknown("VTY allowed transports are unknown.")
        else:
            baseline.ssh_enabled = Observation[bool].unknown("Console section not found.")
            baseline.vty_transport_input = Observation[List[str]].unknown("Console section not found.")

        baseline.ssh_version = Observation[int].unknown("SSH protocol version is not configured in this file.")

    def _normalize_session_timeout(self, sections: dict, baseline: SecurityBaselineModel) -> None:
        sec = "Console"
        if sec in sections and "Timeout" in sections[sec]:
            val, line = sections[sec]["Timeout"]
            raw, line_num, note = self._evidence(sec, "Timeout", val, line)
            try:
                seconds = int(val)
                baseline.vty_exec_timeout_seconds = Observation[int].found(seconds, raw, line_num, note=note)
                return
            except ValueError:
                pass
        
        # Documented default: 10 minutes (600 seconds)
        baseline.vty_exec_timeout_seconds = Observation[int].absent(
            600, "VTY session timeout defaults to 10 minutes (600 seconds)."
        )

    def _normalize_dns(self, sections: dict, baseline: SecurityBaselineModel) -> None:
        sec = "DNS"
        servers = []
        line_num = None
        
        if sec in sections:
            for k in ["Primary", "Secondary", "Tertiary"]:
                if k in sections[sec]:
                    val, line = sections[sec][k]
                    servers.append(val)
                    if not line_num:
                        line_num = line

        if servers and line_num:
            raw, line_idx, note = self._evidence(sec, "Primary", servers[0], line_num)
            baseline.dns_servers = Observation[List[str]].found(servers, raw, line_idx, note=note)
        else:
            baseline.dns_servers = Observation[List[str]].unknown("DNS configuration is not present.")

    def _normalize_ntp(self, sections: dict, baseline: SecurityBaselineModel) -> None:
        sec = "Time"
        servers = []
        line_num = None

        if sec in sections:
            for k in ["Server1", "Server2", "Server3"]:
                if k in sections[sec]:
                    val, line = sections[sec][k]
                    servers.append(val)
                    if not line_num:
                        line_num = line

        if servers and line_num:
            raw, line_idx, note = self._evidence(sec, "Server1", servers[0], line_num)
            baseline.ntp_servers = Observation[List[str]].found(servers, raw, line_idx, note=note)
        else:
            baseline.ntp_servers = Observation[List[str]].unknown("NTP configuration is not present.")

    def _normalize_logging(self, sections: dict, baseline: SecurityBaselineModel) -> None:
        sec = "Syslog"
        if sec in sections:
            if "State" in sections[sec] and "Server" in sections[sec]:
                state_val, state_line = sections[sec]["State"]
                srv_val, srv_line = sections[sec]["Server"]
                
                is_enabled = state_val.lower() in ("1", "yes", "true", "enable", "on")
                raw, line_num, note = self._evidence(sec, "State", state_val, state_line)
                
                baseline.logging_enabled = Observation[bool].found(is_enabled, raw, line_num, note=note)
                baseline.logging_hosts = Observation[List[str]].found([srv_val], raw, line_num, note=note)
                return

        baseline.logging_enabled = Observation[bool].unknown("Syslog server configuration is not present.")
        baseline.logging_hosts = Observation[List[str]].unknown("Syslog destination hosts are not present.")
