"""Deterministic Sangfor NGAF configuration and status parser.

Validation Status: SYNTHETIC / UNSUPPORTED CLI FORMAT.
Sangfor NGAF is a Web GUI / proprietary appliance without an open standardized
human-readable text running-config format. This parser processes synthetic key-value
status fixtures for architectural compatibility and must not be claimed as verified
real-world production grammar.
"""

import hashlib
import re
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class SangforNGAFParser(VendorParser):
    """Configuration/status parser for Sangfor NGAF (Next-Generation Application Firewall)."""

    name = "sangfor_ngaf"
    vendor = "sangfor"
    os_family = "ngaf"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        
        score = 0.0
        # Check for Sangfor specific keywords or command outputs
        if "sangfor" in config_text.lower() or "ngaf" in config_text.lower():
            score += 0.4
        if "System Name:" in config_text or "Device Name:" in config_text:
            score += 0.3
        if "SSH Service:" in config_text or "HTTP Service:" in config_text or "HTTPS Service:" in config_text:
            score += 0.3
            
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

        settings = self._parse_key_values()

        self._normalize_hostname(settings, baseline)
        self._normalize_http_https(settings, baseline)
        self._normalize_ssh_telnet(settings, baseline)
        self._normalize_session_timeout(settings, baseline)
        self._normalize_dns(settings, baseline)
        self._normalize_ntp(settings, baseline)
        self._normalize_logging(settings, baseline)

        # Set all remaining unparsed fields to unknown
        for field in baseline.observable_fields():
            observation = getattr(baseline, field)
            if observation.note == "Parser did not evaluate this field.":
                setattr(
                    baseline,
                    field,
                    type(observation).unknown(
                        "Sangfor NGAF parser does not evaluate this field."
                    )
                )

        return baseline

    def _parse_key_values(self) -> Dict[str, Tuple[str, int]]:
        """Parse configuration text into key-value pairs based on colons or equals."""
        settings = {}
        for idx, line in enumerate(self._raw_lines):
            line_strip = line.strip()
            if not line_strip or line_strip.startswith('#') or line_strip.startswith(';'):
                continue

            # Handle either Key: Value or Key = Value format
            if ":" in line_strip:
                key, val = line_strip.split(":", 1)
            elif "=" in line_strip:
                key, val = line_strip.split("=", 1)
            else:
                continue

            settings[key.strip().lower()] = (val.strip(), idx + 1)

        return settings

    def _evidence(self, key: str, value: str, line_num: int) -> Tuple[str, int, str]:
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"Line {line_num}: {key}={value}"

    def _normalize_hostname(self, settings: dict, baseline: SecurityBaselineModel) -> None:
        for possible_key in ("system name", "device name", "hostname"):
            if possible_key in settings:
                val, line = settings[possible_key]
                raw, line_num, note = self._evidence(possible_key, val, line)
                baseline.hostname = Observation[str].found(val, raw, line_num, note=note)
                return
        baseline.hostname = Observation[str].unknown("Hostname is not configured in this file.")

    def _normalize_http_https(self, settings: dict, baseline: SecurityBaselineModel) -> None:
        # HTTP access status
        if "http service" in settings:
            val, line = settings["http-service"] if "http-service" in settings else settings["http service"]
            raw, line_num, note = self._evidence("http service", val, line)
            is_enabled = val.lower() in ("1", "yes", "true", "enable", "on", "enabled")
            baseline.http_server_enabled = Observation[bool].found(is_enabled, raw, line_num, note=note)
        else:
            # Default HTTP access is disabled
            baseline.http_server_enabled = Observation[bool].absent(
                False, "Web Management HTTP is disabled by default in Sangfor NGAF."
            )

        # HTTPS access status
        if "https service" in settings:
            val, line = settings["https-service"] if "https-service" in settings else settings["https service"]
            raw, line_num, note = self._evidence("https service", val, line)
            is_enabled = val.lower() in ("1", "yes", "true", "enable", "on", "enabled")
            baseline.https_server_enabled = Observation[bool].found(is_enabled, raw, line_num, note=note)
        else:
            # Default HTTPS access is enabled
            baseline.https_server_enabled = Observation[bool].absent(
                True, "Web Management HTTPS is enabled by default in Sangfor NGAF."
            )

    def _normalize_ssh_telnet(self, settings: dict, baseline: SecurityBaselineModel) -> None:
        # Telnet is disabled/unsupported on Sangfor NGAF
        baseline.telnet_enabled = Observation[bool].absent(
            False, "Telnet console access is unsupported on Sangfor NGAF."
        )

        # SSH Console status
        if "ssh service" in settings:
            val, line = settings["ssh-service"] if "ssh-service" in settings else settings["ssh service"]
            raw, line_num, note = self._evidence("ssh service", val, line)
            is_enabled = val.lower() in ("1", "yes", "true", "enable", "on", "enabled")
            baseline.ssh_enabled = Observation[bool].found(is_enabled, raw, line_num, note=note)
            baseline.vty_transport_input = Observation[List[str]].found(
                ["ssh"] if is_enabled else [], raw, line_num, note=note
            )
        else:
            baseline.ssh_enabled = Observation[bool].unknown("SSH service status is not configured.")
            baseline.vty_transport_input = Observation[List[str]].unknown("SSH console transport configuration is absent.")

        baseline.ssh_version = Observation[int].unknown("SSH version is not configured in this file.")

    def _normalize_session_timeout(self, settings: dict, baseline: SecurityBaselineModel) -> None:
        if "session timeout" in settings:
            val, line = settings["session timeout"]
            raw, line_num, note = self._evidence("session timeout", val, line)
            try:
                seconds = int(val)
                baseline.vty_exec_timeout_seconds = Observation[int].found(seconds, raw, line_num, note=note)
                return
            except ValueError:
                pass
        
        # Documented default: 15 minutes (900 seconds)
        baseline.vty_exec_timeout_seconds = Observation[int].absent(
            900, "Web console session timeout defaults to 15 minutes (900 seconds)."
        )

    def _normalize_dns(self, settings: dict, baseline: SecurityBaselineModel) -> None:
        if "dns server" in settings:
            val, line = settings["dns server"]
            raw, line_num, note = self._evidence("dns server", val, line)
            servers = [s.strip() for s in val.split(",") if s.strip()]
            baseline.dns_servers = Observation[List[str]].found(servers, raw, line_num, note=note)
        else:
            baseline.dns_servers = Observation[List[str]].unknown("DNS server configuration is not present.")

    def _normalize_ntp(self, settings: dict, baseline: SecurityBaselineModel) -> None:
        if "ntp server" in settings:
            val, line = settings["ntp server"]
            raw, line_num, note = self._evidence("ntp server", val, line)
            servers = [s.strip() for s in val.split(",") if s.strip()]
            baseline.ntp_servers = Observation[List[str]].found(servers, raw, line_num, note=note)
        else:
            baseline.ntp_servers = Observation[List[str]].unknown("NTP server configuration is not present.")

    def _normalize_logging(self, settings: dict, baseline: SecurityBaselineModel) -> None:
        if "syslog server" in settings:
            val, line = settings["syslog server"]
            raw, line_num, note = self._evidence("syslog server", val, line)
            baseline.logging_enabled = Observation[bool].found(True, raw, line_num, note=note)
            baseline.logging_hosts = Observation[List[str]].found([val], raw, line_num, note=note)
        else:
            baseline.logging_enabled = Observation[bool].unknown("Syslog server configuration is not present.")
            baseline.logging_hosts = Observation[List[str]].unknown("Syslog destination hosts are not present.")
