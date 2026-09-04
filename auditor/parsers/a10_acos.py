"""Deterministic A10 Networks ACOS configuration parser.

This parser processes A10 Networks ACOS plain-text CLI configuration dumps,
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
class A10ACOSParser(VendorParser):
    """Configuration parser for A10 Networks ACOS (Advanced Core Operating System)."""

    name = "a10_acos"
    vendor = "a10"
    os_family = "acos"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        
        score = 0.0
        if "acos" in config_text.lower() or "a10 networks" in config_text.lower() or "thunder" in config_text.lower():
            score += 0.4
        if "enable-management service" in config_text:
            score += 0.3
        if "ip dns primary" in config_text or "ip dns secondary" in config_text or "web-service" in config_text:
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
                        "A10 ACOS parser does not evaluate this field."
                    )
                )

        return baseline

    def _evidence(self, line_num: int) -> Tuple[str, int, str]:
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"Line {line_num}: {raw_line}"

    def _parse_config(self, baseline: SecurityBaselineModel) -> None:
        # ACOS Defaults: SSH, HTTP, HTTPS are disabled on data interfaces by default,
        # but enabled on management port. Telnet is disabled by default.
        baseline.telnet_enabled = Observation[bool].absent(
            False, "Telnet is disabled by default in ACOS."
        )
        baseline.http_server_enabled = Observation[bool].absent(
            False, "HTTP Web management is disabled by default on data interfaces in ACOS."
        )
        # HTTPS is enabled on the management port by default
        baseline.https_server_enabled = Observation[bool].absent(
            True, "HTTPS Web management is enabled by default on management interface in ACOS."
        )
        # SSH is enabled on the management port by default
        baseline.ssh_enabled = Observation[bool].absent(
            True, "SSH is enabled by default on management interface in ACOS."
        )
        baseline.vty_transport_input = Observation[List[str]].absent(
            ["ssh"], "SSH is the default transport input on management interface in ACOS."
        )
        baseline.vty_exec_timeout_seconds = Observation[int].absent(
            900, "VTY session timeout defaults to 15 minutes (900 seconds)."
        )

        dns_servers = {}
        ntp_servers = []
        logging_hosts = []

        # We keep track of explicit enable-management service declarations
        # e.g., 'enable-management service http'
        # or global service states like 'web-service server disable'
        http_explicit_disabled = False
        https_explicit_disabled = False

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

            # Web Service Disable states
            elif line_strip == "web-service server disable":
                raw, _, note = self._evidence(line_num)
                baseline.http_server_enabled = Observation[bool].found(False, raw, line_num, note=note)
                http_explicit_disabled = True
            elif line_strip == "web-service secure-server disable":
                raw, _, note = self._evidence(line_num)
                baseline.https_server_enabled = Observation[bool].found(False, raw, line_num, note=note)
                https_explicit_disabled = True

            # Management Service Explicit states (enable)
            elif line_strip.startswith("enable-management service http"):
                if not http_explicit_disabled:
                    raw, _, note = self._evidence(line_num)
                    baseline.http_server_enabled = Observation[bool].found(True, raw, line_num, note=note)
            elif line_strip.startswith("enable-management service https"):
                if not https_explicit_disabled:
                    raw, _, note = self._evidence(line_num)
                    baseline.https_server_enabled = Observation[bool].found(True, raw, line_num, note=note)

            elif line_strip.startswith("enable-management service ssh"):
                raw, _, note = self._evidence(line_num)
                baseline.ssh_enabled = Observation[bool].found(True, raw, line_num, note=note)
                baseline.vty_transport_input = Observation[List[str]].found(["ssh"], raw, line_num, note=note)
            elif line_strip.startswith("enable-management service telnet"):
                raw, _, note = self._evidence(line_num)
                baseline.telnet_enabled = Observation[bool].found(True, raw, line_num, note=note)

            # Management Service Explicit states (disable/no)
            elif line_strip.startswith("no enable-management service http"):
                raw, _, note = self._evidence(line_num)
                baseline.http_server_enabled = Observation[bool].found(False, raw, line_num, note=note)
            elif line_strip.startswith("no enable-management service https"):
                raw, _, note = self._evidence(line_num)
                baseline.https_server_enabled = Observation[bool].found(False, raw, line_num, note=note)
            elif line_strip.startswith("no enable-management service ssh"):
                raw, _, note = self._evidence(line_num)
                baseline.ssh_enabled = Observation[bool].found(False, raw, line_num, note=note)
                baseline.vty_transport_input = Observation[List[str]].found([], raw, line_num, note=note)
            elif line_strip.startswith("no enable-management service telnet"):
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

            # DNS Server: ip dns primary <IP> or ip dns secondary <IP>
            elif line_strip.startswith("ip dns primary "):
                srv = line_strip.split(" ", 3)[3].strip()
                raw, _, note = self._evidence(line_num)
                dns_servers["primary"] = (srv, line_num)
            elif line_strip.startswith("ip dns secondary "):
                srv = line_strip.split(" ", 3)[3].strip()
                raw, _, note = self._evidence(line_num)
                dns_servers["secondary"] = (srv, line_num)

            # NTP Server: ntp server <IP/domain>
            elif line_strip.startswith("ntp server "):
                srv = line_strip.split(" ", 2)[2].strip()
                raw, _, note = self._evidence(line_num)
                ntp_servers.append((srv, line_num))

            # Syslog: logging host <IP>
            elif line_strip.startswith("logging host "):
                srv = line_strip.split(" ", 2)[2].strip()
                raw, _, note = self._evidence(line_num)
                logging_hosts.append((srv, line_num))

        # Compile lists into observations
        if dns_servers:
            # Sort server lines
            ordered_servers = []
            last_line = 1
            if "primary" in dns_servers:
                ordered_servers.append(dns_servers["primary"][0])
                last_line = dns_servers["primary"][1]
            if "secondary" in dns_servers:
                ordered_servers.append(dns_servers["secondary"][0])
                last_line = dns_servers["secondary"][1]

            raw, line_num, note = self._evidence(last_line)
            baseline.dns_servers = Observation[List[str]].found(
                ordered_servers, raw, line_num, note=note
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
