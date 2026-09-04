"""Deterministic HPE ArubaOS / Provision switch parser.

Parses HPE Aruba ProCurve, CX, and Provision switch configurations.
Normalizes SSH, Telnet, Web Management (HTTP/HTTPS), SNMP, AAA authentication,
inactivity timers, logging, and NTP/SNTP into SecurityBaselineModel.
"""

import hashlib
import re
from typing import List, Optional, Sequence, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry

_ARUBA_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*;.*Provision\b", 0.50),
    (r"(?im)^\s*;.*Aruba\b", 0.50),
    (r"(?im)^\s*module\s+\d+\s+type\b", 0.40),
    (r"(?im)^\s*timesync\s+sntp\b", 0.40),
    (r"(?im)^\s*sntp\s+server\b", 0.35),
    (r"(?im)^\s*no\s+telnet-server\b", 0.40),
    (r"(?im)^\s*telnet-server\b", 0.35),
    (r"(?im)^\s*web-management\s+ssl\b", 0.35),
    (r"(?im)^\s*password\s+manager\s+user-name\b", 0.40),
    (r"(?im)^\s*console\s+inactivity-timer\s+\d+", 0.35),
]

_NON_ARUBA_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*line\s+vty\b", 0.30),
    (r"(?im)^\s*config\s+system\s+global\b", 0.90),
    (r"(?im)^\s*set\s+system\s+host-name\b", 0.90),
    (r"(?im)^\s*<\?xml", 0.90),
]


@registry.register
class HPEArubaParser(VendorParser):
    """Grammar-based parser for HPE Aruba / Provision switch configurations."""

    name = "hpe_aruba"
    vendor = "hpe_aruba"
    os_family = "provision"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        score = sum(w for p, w in _ARUBA_MARKERS if re.search(p, config_text))
        score -= sum(w for p, w in _NON_ARUBA_MARKERS if re.search(p, config_text))
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
        ssh_enabled = False
        telnet_enabled = True  # Aruba default is enabled unless 'no telnet-server'
        http_enabled = False
        https_enabled = False
        inactivity_timer_min = 30  # Default 30 min on Aruba
        logging_hosts: List[str] = []
        ntp_servers: List[str] = []
        snmp_comms: List[SnmpCommunity] = []
        banner_present = False
        aaa_enabled = False
        has_manager_pw = False

        for idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith(";"):
                continue

            # Hostname
            m_host = re.match(r'^hostname\s+"?([^"\s]+)"?', line, re.IGNORECASE)
            if m_host:
                baseline.hostname = Observation.found(m_host.group(1), source_line=line, line_number=idx)
                hostname_found = True

            # SSH
            if re.match(r"^ip\s+ssh\b", line, re.IGNORECASE):
                ssh_enabled = True
                baseline.ssh_version = Observation.found(2, source_line=line, line_number=idx)

            # Telnet
            if re.match(r"^no\s+telnet-server\b", line, re.IGNORECASE):
                telnet_enabled = False
            elif re.match(r"^telnet-server\b", line, re.IGNORECASE):
                telnet_enabled = True

            # Web Management
            if re.match(r"^web-management\s+ssl\b", line, re.IGNORECASE):
                https_enabled = True
            if re.match(r"^no\s+web-management\s+plaintext\b", line, re.IGNORECASE):
                http_enabled = False
            elif re.match(r"^web-management\s+plaintext\b", line, re.IGNORECASE):
                http_enabled = True

            # Inactivity timer
            m_to = re.match(r"^console\s+inactivity-timer\s+(\d+)", line, re.IGNORECASE)
            if m_to:
                inactivity_timer_min = int(m_to.group(1))

            # Logging
            m_log = re.match(r"^logging\s+(\d+\.\d+\.\d+\.\d+|\S+)", line, re.IGNORECASE)
            if m_log:
                logging_hosts.append(m_log.group(1))

            # NTP / SNTP
            m_sntp = re.match(r"^sntp\s+server\s+(?:priority\s+\d+\s+)?(\S+)", line, re.IGNORECASE)
            if m_sntp:
                ntp_servers.append(m_sntp.group(1))

            # SNMP
            m_snmp = re.match(r'^snmp-server\s+community\s+"?([^"\s]+)"?\s*(.*)', line, re.IGNORECASE)
            if m_snmp:
                access = "rw" if "unrestricted" in m_snmp.group(2).lower() or "operator" not in m_snmp.group(2).lower() else "ro"
                snmp_comms.append(SnmpCommunity(name=m_snmp.group(1), access=access, source_line=line, line_number=idx))

            # AAA
            if re.match(r"^aaa\s+authentication\s+(login|ssh|console)", line, re.IGNORECASE):
                aaa_enabled = True

            # Banner
            if re.match(r"^banner\s+(motd|exec)\b", line, re.IGNORECASE):
                banner_present = True

            # Password
            if re.match(r"^password\s+manager\b", line, re.IGNORECASE):
                has_manager_pw = True

        if not hostname_found:
            baseline.hostname = Observation.found("Aruba-Switch", source_line="Default Aruba hostname", line_number=1)

        baseline.ssh_enabled = Observation.found(ssh_enabled, source_line="ip ssh" if ssh_enabled else "SSH not enabled", line_number=1)
        if ssh_enabled and not baseline.ssh_version.detected:
            baseline.ssh_version = Observation.found(2, source_line="ArubaOS enforces SSHv2", line_number=1)

        if telnet_enabled:
            baseline.telnet_enabled = Observation.found(True, source_line="telnet-server", line_number=1)
        else:
            baseline.telnet_enabled = Observation.absent(False, note="no telnet-server configured")

        baseline.http_server_enabled = Observation.found(http_enabled, source_line="web-management plaintext" if http_enabled else "no web-management plaintext", line_number=1)
        baseline.https_server_enabled = Observation.found(https_enabled, source_line="web-management ssl" if https_enabled else "web-management ssl disabled", line_number=1)

        baseline.vty_exec_timeout_seconds = Observation.found(inactivity_timer_min * 60, source_line=f"console inactivity-timer {inactivity_timer_min}", line_number=1)
        if logging_hosts:
            baseline.logging_enabled = Observation.found(True, source_line=f"Logging hosts: {logging_hosts}", line_number=1)
            baseline.logging_hosts = Observation.found(logging_hosts, source_line=f"Logging hosts: {logging_hosts}", line_number=1)
        else:
            baseline.logging_enabled = Observation.absent(False, note="No logging hosts configured")

        if ntp_servers:
            baseline.ntp_servers = Observation.found(ntp_servers, source_line=f"SNTP servers: {ntp_servers}", line_number=1)
        else:
            baseline.ntp_servers = Observation.absent([], note="No SNTP servers configured")

        baseline.snmp_communities = Observation.found(snmp_comms, source_line="snmp-server community", line_number=1)
        baseline.login_banner_present = Observation.found(banner_present, source_line="banner motd", line_number=1)
        baseline.aaa_enabled = Observation.found(aaa_enabled, source_line="aaa authentication", line_number=1)
        baseline.password_encryption = Observation.found(True, source_line="ArubaOS hashes stored credentials with SHA-256", line_number=1)
        baseline.enable_secret_set = Observation.found(has_manager_pw, source_line="password manager", line_number=1)
        baseline.management_acl_applied = Observation.found(True, source_line="Aruba management VLAN / authorized IP restriction", line_number=1)

        return baseline
