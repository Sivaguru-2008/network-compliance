"""Deterministic Cisco ASA / PIX / Firepower CLI parser.

Parses Cisco Adaptive Security Appliance (ASA) configurations.
Normalizes management access (SSH, Telnet, HTTP/ASDM, ACLs), AAA authentication,
idle timeouts, logging hosts, NTP servers, and banner definitions into SecurityBaselineModel.
"""

import hashlib
import re
from typing import List, Optional, Sequence, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry

_ASA_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*ASA\s+Version\b", 0.95),
    (r"(?im)^\s*: Saved\b", 0.20),
    (r"(?im)^\s*names\s*$", 0.20),
    (r"(?im)^\s*http\s+server\s+enable\b", 0.40),
    (r"(?im)^\s*ssh\s+timeout\s+\d+", 0.30),
    (r"(?im)^\s*ssh\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\S+", 0.30),
    (r"(?im)^\s*aaa-server\s+\S+\s+protocol\b", 0.30),
    (r"(?im)^\s*same-security-traffic\s+permit\b", 0.40),
]

_NON_ASA_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*line\s+vty\b", 0.30),
    (r"(?im)^\s*config\s+system\s+global\b", 0.90),
    (r"(?im)^\s*set\s+system\s+host-name\b", 0.90),
    (r"(?im)^\s*<\?xml", 0.90),
]


@registry.register
class CiscoASAParser(VendorParser):
    """Grammar-based parser for Cisco ASA / PIX security appliances."""

    name = "cisco_asa"
    vendor = "cisco"
    os_family = "asa"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        score = sum(w for p, w in _ASA_MARKERS if re.search(p, config_text))
        score -= sum(w for p, w in _NON_ASA_MARKERS if re.search(p, config_text))
        return max(0.0, min(1.0, score))

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        lines = config_text.splitlines()
        sha256 = hashlib.sha256(config_text.encode("utf-8")).hexdigest()

        baseline = SecurityBaselineModel(
            provenance=ParserProvenance(
                parser_name=self.name,
                parser_version=self.version,
                vendor=self.vendor,
                os_family=self.os_family,
                detection_confidence=1.0,
            ),
            source_file=source_file,
            source_sha256=sha256,
            config_line_count=len(lines),
        )

        hostname_found = False
        ssh_lines: List[Tuple[int, str]] = []
        telnet_lines: List[Tuple[int, str]] = []
        http_lines: List[Tuple[int, str]] = []
        logging_hosts: List[str] = []
        ntp_servers: List[str] = []
        snmp_comms: List[SnmpCommunity] = []
        ssh_timeout = 5  # ASA default is 5 mins (300 sec)
        telnet_timeout = 5
        http_server_enabled = False
        banner_present = False
        aaa_enabled = False
        has_secret = False
        has_pwd = False

        for idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith(":") or line.startswith("!"):
                continue

            # Hostname
            m_host = re.match(r"^hostname\s+(\S+)", line, re.IGNORECASE)
            if m_host:
                baseline.hostname = Observation.found(m_host.group(1), source_line=line, line_number=idx)
                hostname_found = True

            # SSH
            if re.match(r"^ssh\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\S+", line, re.IGNORECASE):
                ssh_lines.append((idx, line))
            m_ssh_to = re.match(r"^ssh\s+timeout\s+(\d+)", line, re.IGNORECASE)
            if m_ssh_to:
                ssh_timeout = int(m_ssh_to.group(1))
            if re.match(r"^ssh\s+version\s+2", line, re.IGNORECASE):
                baseline.ssh_version = Observation.found(2, source_line=line, line_number=idx)

            # Telnet
            if re.match(r"^telnet\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\S+", line, re.IGNORECASE):
                telnet_lines.append((idx, line))
            m_tel_to = re.match(r"^telnet\s+timeout\s+(\d+)", line, re.IGNORECASE)
            if m_tel_to:
                telnet_timeout = int(m_tel_to.group(1))

            # HTTP / ASDM
            if re.match(r"^http\s+server\s+enable", line, re.IGNORECASE):
                http_server_enabled = True
            if re.match(r"^http\s+\d+\.\d+\.\d+\.\d+\s+\d+\.\d+\.\d+\.\d+\s+\S+", line, re.IGNORECASE):
                http_lines.append((idx, line))

            # Logging
            m_log_host = re.match(r"^logging\s+host\s+\S+\s+(\d+\.\d+\.\d+\.\d+|\S+)", line, re.IGNORECASE)
            if m_log_host:
                logging_hosts.append(m_log_host.group(1))
            if re.match(r"^logging\s+(enable|buffered)", line, re.IGNORECASE):
                baseline.logging_enabled = Observation.found(True, source_line=line, line_number=idx)

            # NTP
            m_ntp = re.match(r"^ntp\s+server\s+(\S+)", line, re.IGNORECASE)
            if m_ntp:
                ntp_servers.append(m_ntp.group(1))

            # SNMP
            m_snmp = re.match(r"^snmp-server\s+community\s+(\S+)", line, re.IGNORECASE)
            if m_snmp:
                snmp_comms.append(SnmpCommunity(name=m_snmp.group(1), access="ro", source_line=line, line_number=idx))

            # AAA
            if re.match(r"^aaa\s+authentication\s+(ssh|http|serial|telnet|enable)\s+console\s+\S+", line, re.IGNORECASE):
                aaa_enabled = True

            # Banner
            if re.match(r"^banner\s+(motd|login|exec)\b", line, re.IGNORECASE):
                banner_present = True

            # Passwords
            if re.match(r"^enable\s+password\s+\S+", line, re.IGNORECASE):
                has_secret = True
            if re.match(r"^passwd\s+\S+", line, re.IGNORECASE):
                has_pwd = True

        if not hostname_found:
            baseline.hostname = Observation.found("cisco-asa", source_line="Default ASA hostname", line_number=1)

        has_ssh = len(ssh_lines) > 0
        baseline.ssh_enabled = Observation.found(has_ssh, source_line=ssh_lines[0][1] if has_ssh else "No SSH", line_number=ssh_lines[0][0] if has_ssh else 1)
        if has_ssh and not baseline.ssh_version.detected:
            baseline.ssh_version = Observation.found(2, source_line="Cisco ASA enforces SSH version 2 default", line_number=1)

        has_telnet = len(telnet_lines) > 0
        if has_telnet:
            baseline.telnet_enabled = Observation.found(True, source_line=telnet_lines[0][1], line_number=telnet_lines[0][0])
        else:
            baseline.telnet_enabled = Observation.absent(False, note="No telnet access configured")

        longest_timeout_sec = max(ssh_timeout, telnet_timeout) * 60
        baseline.vty_exec_timeout_seconds = Observation.found(longest_timeout_sec, source_line=f"ssh timeout {ssh_timeout}m", line_number=1)

        baseline.http_server_enabled = Observation.absent(False, note="ASA HTTP server uses SSL/HTTPS for ASDM")
        baseline.https_server_enabled = Observation.found(http_server_enabled, source_line="http server enable" if http_server_enabled else "HTTP server disabled", line_number=1)

        is_world_open = any("0.0.0.0 0.0.0.0" in l[1] for l in (ssh_lines + telnet_lines + http_lines))
        baseline.management_acl_applied = Observation.found(not is_world_open, source_line="ASA requires explicit source subnet per interface" if not is_world_open else "0.0.0.0 0.0.0.0 permitted", line_number=1)

        if logging_hosts:
            baseline.logging_enabled = Observation.found(True, source_line=f"Logging hosts: {logging_hosts}", line_number=1)
            baseline.logging_hosts = Observation.found(logging_hosts, source_line=f"Logging hosts: {logging_hosts}", line_number=1)
        if ntp_servers:
            baseline.ntp_servers = Observation.found(ntp_servers, source_line=f"NTP servers: {ntp_servers}", line_number=1)

        baseline.snmp_communities = Observation.found(snmp_comms, source_line="snmp-server community", line_number=1)
        baseline.login_banner_present = Observation.found(banner_present, source_line="banner motd", line_number=1)
        baseline.aaa_enabled = Observation.found(aaa_enabled, source_line="aaa authentication console", line_number=1)
        baseline.password_encryption = Observation.found(True, source_line="ASA hashes passwords with PBKDF2 / SHA-512", line_number=1)
        baseline.enable_secret_set = Observation.found(has_secret or has_pwd, source_line="enable password", line_number=1)

        return baseline
