"""Deterministic Hillstone Networks StoneOS configuration parser.

This parser processes Hillstone Networks StoneOS plain-text CLI configuration dumps,
normalizes settings into the SecurityBaselineModel, and preserves
configuration lines and line numbers for compliance audit evidence.
"""

import hashlib
import re
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class HillstoneStoneOSParser(VendorParser):
    """Configuration parser for Hillstone Networks StoneOS."""

    name = "hillstone_stoneos"
    vendor = "hillstone"
    os_family = "stoneos"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        
        score = 0.0
        # Check for Hillstone specific comments or patterns
        if "stoneos" in config_text.lower() or "hillstone" in config_text.lower():
            score += 0.4
        if "access http" in config_text or "access https" in config_text or "access ssh" in config_text:
            score += 0.3
        if "console timeout" in config_text or "logging syslog" in config_text:
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

        self._parse_config(baseline)

        # Set all remaining unparsed fields to unknown
        for field in baseline.observable_fields():
            observation = getattr(baseline, field)
            if observation.note == "Parser did not evaluate this field.":
                setattr(
                    baseline,
                    field,
                    type(observation).unknown(
                        "Hillstone StoneOS parser does not evaluate this field."
                    )
                )

        return baseline

    def _evidence(self, line_num: int) -> Tuple[str, int, str]:
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"Line {line_num}: {raw_line}"

    def _parse_config(self, baseline: SecurityBaselineModel) -> None:
        # Defaults
        baseline.telnet_enabled = Observation[bool].absent(
            False, "Telnet console access is disabled by default in Hillstone StoneOS."
        )
        baseline.http_server_enabled = Observation[bool].absent(
            False, "HTTP Web management is disabled by default in Hillstone StoneOS."
        )
        baseline.https_server_enabled = Observation[bool].absent(
            True, "HTTPS Web management is enabled by default in Hillstone StoneOS."
        )
        baseline.vty_exec_timeout_seconds = Observation[int].absent(
            600, "Console session idle timeout defaults to 10 minutes (600 seconds)."
        )

        dns_servers = []
        ntp_servers = []
        logging_hosts = []

        for idx, line in enumerate(self._raw_lines):
            line_num = idx + 1
            line_strip = line.strip()
            if not line_strip or line_strip.startswith('!') or line_strip.startswith('#'):
                continue

            # Hostname: hostname <name>
            if line_strip.startswith("hostname "):
                name = line_strip.split(" ", 1)[1].strip()
                raw, _, note = self._evidence(line_num)
                baseline.hostname = Observation[str].found(name, raw, line_num, note=note)

            # Web Management and SSH Access
            elif line_strip == "access http":
                raw, _, note = self._evidence(line_num)
                baseline.http_server_enabled = Observation[bool].found(True, raw, line_num, note=note)
            elif line_strip == "no access http":
                raw, _, note = self._evidence(line_num)
                baseline.http_server_enabled = Observation[bool].found(False, raw, line_num, note=note)

            elif line_strip == "access https":
                raw, _, note = self._evidence(line_num)
                baseline.https_server_enabled = Observation[bool].found(True, raw, line_num, note=note)
            elif line_strip == "no access https":
                raw, _, note = self._evidence(line_num)
                baseline.https_server_enabled = Observation[bool].found(False, raw, line_num, note=note)

            elif line_strip == "access ssh":
                raw, _, note = self._evidence(line_num)
                baseline.ssh_enabled = Observation[bool].found(True, raw, line_num, note=note)
                baseline.vty_transport_input = Observation[List[str]].found(["ssh"], raw, line_num, note=note)
            elif line_strip == "no access ssh":
                raw, _, note = self._evidence(line_num)
                baseline.ssh_enabled = Observation[bool].found(False, raw, line_num, note=note)
                baseline.vty_transport_input = Observation[List[str]].found([], raw, line_num, note=note)

            elif line_strip == "access telnet":
                raw, _, note = self._evidence(line_num)
                baseline.telnet_enabled = Observation[bool].found(True, raw, line_num, note=note)
            elif line_strip == "no access telnet":
                raw, _, note = self._evidence(line_num)
                baseline.telnet_enabled = Observation[bool].found(False, raw, line_num, note=note)

            # Timeout: console timeout <minutes>
            elif line_strip.startswith("console timeout "):
                val = line_strip.split(" ", 2)[2].strip()
                try:
                    minutes = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.vty_exec_timeout_seconds = Observation[int].found(minutes * 60, raw, line_num, note=note)
                except ValueError:
                    pass

            # Timeout: ssh timeout <minutes>
            elif line_strip.startswith("ssh timeout "):
                # Can be used to set timeout if console timeout is not found, or as auxiliary evidence
                pass

            # DNS Server: ip name-server <IP>
            elif line_strip.startswith("ip name-server "):
                srv = line_strip.split(" ", 2)[2].strip()
                raw, _, note = self._evidence(line_num)
                dns_servers.append((srv, line_num))

            # NTP Server: ntp server <IP/domain>
            elif line_strip.startswith("ntp server "):
                srv = line_strip.split(" ", 2)[2].strip()
                raw, _, note = self._evidence(line_num)
                ntp_servers.append((srv, line_num))

            # Syslog: logging syslog <IP> [options]
            elif line_strip.startswith("logging syslog "):
                srv = line_strip.split(" ", 2)[2].strip().split(" ")[0]
                raw, _, note = self._evidence(line_num)
                logging_hosts.append((srv, line_num))

        # Compile lists into observations
        if dns_servers:
            # Take last server configured as representative line or list
            raw, line_num, note = self._evidence(dns_servers[-1][1])
            baseline.dns_servers = Observation[List[str]].found(
                [d[0] for d in dns_servers], raw, line_num, note=note
            )
        else:
            baseline.dns_servers = Observation[List[str]].unknown("DNS configuration is not present.")

        if ntp_servers:
            raw, line_num, note = self._evidence(ntp_servers[-1][1])
            baseline.ntp_servers = Observation[List[str]].found(
                [n[0] for n in ntp_servers], raw, line_num, note=note
            )
        else:
            baseline.ntp_servers = Observation[List[str]].unknown("NTP configuration is not present.")

        if logging_hosts:
            raw, line_num, note = self._evidence(logging_hosts[-1][1])
            baseline.logging_enabled = Observation[bool].found(True, raw, line_num, note=note)
            baseline.logging_hosts = Observation[List[str]].found(
                [lh[0] for lh in logging_hosts], raw, line_num, note=note
            )
        else:
            baseline.logging_enabled = Observation[bool].unknown("Syslog server configuration is not present.")
            baseline.logging_hosts = Observation[List[str]].unknown("Syslog destination hosts are not present.")

        if not baseline.hostname:
            baseline.hostname = Observation[str].unknown("Hostname is not configured in this file.")
