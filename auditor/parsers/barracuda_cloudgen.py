"""Deterministic Barracuda CloudGen Firewall configuration parser.

This parser processes Barracuda CloudGen text-based configuration files,
normalizes verified settings into the SecurityBaselineModel, and preserves
configuration lines and line numbers for compliance audit evidence.
"""

import hashlib
import re
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class BarracudaCloudGenParser(VendorParser):
    """Text-based configuration parser for Barracuda CloudGen Firewall."""

    name = "barracuda_cloudgen"
    vendor = "barracuda"
    os_family = "barracuda_cloudgen"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        
        score = 0.0
        if "#scope:" in config_text:
            score += 0.4
        if "sys-name = " in config_text or "sys-name=" in config_text:
            score += 0.3
        if "boxadm.conf" in config_text or "phion" in config_text:
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
                        "Barracuda CloudGen parser does not evaluate this field."
                    )
                )

        return baseline

    def _parse_key_values(self) -> Dict[str, Tuple[str, int]]:
        """Parse configuration file into key-value pairs and line numbers."""
        settings = {}
        kv_pat = re.compile(r'^\s*([a-zA-Z0-9._-]+)\s*=\s*"(.*?)"\s*$')
        kv_pat_unquoted = re.compile(r'^\s*([a-zA-Z0-9._-]+)\s*=\s*(.*?)\s*$')

        for idx, line in enumerate(self._raw_lines):
            line_strip = line.strip()
            if not line_strip or line_strip.startswith('#') or line_strip.startswith(';'):
                continue

            match = kv_pat.match(line_strip)
            if not match:
                match = kv_pat_unquoted.match(line_strip)

            if match:
                key = match.group(1).strip()
                val = match.group(2).strip()
                # Remove quotes if present
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                settings[key] = (val, idx + 1)

        return settings

    def _evidence(self, key: str, value: str, line_num: int) -> Tuple[str, int, str]:
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"Line {line_num}: {key}={value}"

    def _normalize_hostname(self, settings: dict, baseline: SecurityBaselineModel) -> None:
        if "sys-name" in settings:
            val, line = settings["sys-name"]
            raw, line_num, note = self._evidence("sys-name", val, line)
            baseline.hostname = Observation[str].found(val, raw, line_num, note=note)
        else:
            baseline.hostname = Observation[str].unknown("Hostname is not configured in this file.")

    def _normalize_http_https(self, settings: dict, baseline: SecurityBaselineModel) -> None:
        # HTTP access status
        if "http-enable" in settings:
            val, line = settings["http-enable"]
            raw, line_num, note = self._evidence("http-enable", val, line)
            is_enabled = val.lower() in ("1", "yes", "true", "enable", "on")
            baseline.http_server_enabled = Observation[bool].found(is_enabled, raw, line_num, note=note)
        else:
            # Default HTTP access is disabled
            baseline.http_server_enabled = Observation[bool].absent(
                False, "WebAdmin HTTP is disabled by default in Barracuda CloudGen."
            )

        # HTTPS access status
        if "https-enable" in settings:
            val, line = settings["https-enable"]
            raw, line_num, note = self._evidence("https-enable", val, line)
            is_enabled = val.lower() in ("1", "yes", "true", "enable", "on")
            baseline.https_server_enabled = Observation[bool].found(is_enabled, raw, line_num, note=note)
        else:
            # Default HTTPS access is enabled
            baseline.https_server_enabled = Observation[bool].absent(
                True, "WebAdmin HTTPS is enabled by default in Barracuda CloudGen."
            )

    def _normalize_ssh_telnet(self, settings: dict, baseline: SecurityBaselineModel) -> None:
        # Telnet is disabled/unsupported on Barracuda CloudGen appliances
        baseline.telnet_enabled = Observation[bool].absent(
            False, "Telnet is unsupported on Barracuda CloudGen."
        )

        # SSH Console status
        if "ssh-enable" in settings:
            val, line = settings["ssh-enable"]
            raw, line_num, note = self._evidence("ssh-enable", val, line)
            is_enabled = val.lower() in ("1", "yes", "true", "enable", "on")
            baseline.ssh_enabled = Observation[bool].found(is_enabled, raw, line_num, note=note)
            baseline.vty_transport_input = Observation[List[str]].found(
                ["ssh"] if is_enabled else [], raw, line_num, note=note
            )
        else:
            baseline.ssh_enabled = Observation[bool].unknown("SSH console configuration is absent.")
            baseline.vty_transport_input = Observation[List[str]].unknown("SSH console transport configuration is absent.")

        baseline.ssh_version = Observation[int].unknown("SSH version is not configured in this file.")

    def _normalize_session_timeout(self, settings: dict, baseline: SecurityBaselineModel) -> None:
        if "timeout" in settings:
            val, line = settings["timeout"]
            raw, line_num, note = self._evidence("timeout", val, line)
            try:
                seconds = int(val)
                baseline.vty_exec_timeout_seconds = Observation[int].found(seconds, raw, line_num, note=note)
                return
            except ValueError:
                pass
        
        # Documented default: 15 minutes (900 seconds)
        baseline.vty_exec_timeout_seconds = Observation[int].absent(
            900, "VTY session timeout defaults to 15 minutes (900 seconds)."
        )

    def _normalize_dns(self, settings: dict, baseline: SecurityBaselineModel) -> None:
        if "dns-servers" in settings:
            val, line = settings["dns-servers"]
            raw, line_num, note = self._evidence("dns-servers", val, line)
            servers = [s.strip() for s in val.split(",") if s.strip()]
            baseline.dns_servers = Observation[List[str]].found(servers, raw, line_num, note=note)
        else:
            baseline.dns_servers = Observation[List[str]].unknown("DNS configuration is not present.")

    def _normalize_ntp(self, settings: dict, baseline: SecurityBaselineModel) -> None:
        if "ntp-servers" in settings:
            val, line = settings["ntp-servers"]
            raw, line_num, note = self._evidence("ntp-servers", val, line)
            servers = [s.strip() for s in val.split(",") if s.strip()]
            baseline.ntp_servers = Observation[List[str]].found(servers, raw, line_num, note=note)
        else:
            baseline.ntp_servers = Observation[List[str]].unknown("NTP configuration is not present.")

    def _normalize_logging(self, settings: dict, baseline: SecurityBaselineModel) -> None:
        if "logging-enabled" in settings:
            val, line = settings["logging-enabled"]
            raw, line_num, note = self._evidence("logging-enabled", val, line)
            is_enabled = val.lower() in ("1", "yes", "true", "enable", "on")
            
            baseline.logging_enabled = Observation[bool].found(is_enabled, raw, line_num, note=note)
            if is_enabled and "logging-host" in settings:
                srv, srv_line = settings["logging-host"]
                baseline.logging_hosts = Observation[List[str]].found([srv], raw, srv_line, note=note)
            else:
                baseline.logging_hosts = Observation[List[str]].unknown("Logging destination server is not specified.")
        else:
            baseline.logging_enabled = Observation[bool].unknown("Syslog server configuration is not present.")
            baseline.logging_hosts = Observation[List[str]].unknown("Syslog destination hosts are not present.")
