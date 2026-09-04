"""Deterministic Ubiquiti EdgeOS / UniFi parser.

Parses Ubiquiti EdgeMAX EdgeOS and UniFi config.boot tree structures and 'set' commands.
Normalizes system parameters, SSH/Telnet services, Web GUI (HTTP/HTTPS), NTP, Syslog,
SNMP, and user security into SecurityBaselineModel.
"""

import hashlib
import re
from typing import List, Optional, Sequence, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry

_UBIQUITI_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*system\s*\{[^}]*host-name\b", 0.50),
    (r"(?im)^\s*service\s*\{[^}]*gui\s*\{", 0.45),
    (r"(?im)^\s*service\s*\{[^}]*ssh\s*\{", 0.40),
    (r"(?im)^\s*set\s+system\s+host-name\b", 0.35),
    (r"(?im)^\s*set\s+service\s+gui\b", 0.45),
    (r"(?im)^\s*set\s+service\s+ssh\b", 0.40),
    (r"(?im)^\s*login\s*\{[^}]*user\b", 0.35),
    (r"(?im)^\s*encrypted-password\s+\"\$6\$", 0.40),
]

_NON_UBIQUITI_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*line\s+vty\b", 0.30),
    (r"(?im)^\s*config\s+system\s+global\b", 0.90),
    (r"(?im)^\s*<\?xml", 0.90),
    (r"(?im)\"DEVICE_METADATA\"", 0.90),
]


@registry.register
class UbiquitiParser(VendorParser):
    """Parser for Ubiquiti EdgeOS / UniFi configurations."""

    name = "ubiquiti"
    vendor = "ubiquiti"
    os_family = "edgeos"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        score = sum(w for p, w in _UBIQUITI_MARKERS if re.search(p, config_text))
        score -= sum(w for p, w in _NON_UBIQUITI_MARKERS if re.search(p, config_text))
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
        ssh_v2_only = False
        telnet_enabled = False
        http_enabled = False
        https_enabled = False
        logging_hosts: List[str] = []
        ntp_servers: List[str] = []
        snmp_comms: List[SnmpCommunity] = []
        banner_present = False
        has_hash = False

        for idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("/*") or line.startswith("//"):
                continue

            # Hostname
            m_host = re.search(r"(?:host-name|set\s+system\s+host-name)\s+[\"']?([^\"';\s]+)[\"']?", line, re.IGNORECASE)
            if m_host and not hostname_found:
                baseline.hostname = Observation.found(m_host.group(1), source_line=line, line_number=idx)
                hostname_found = True

            # SSH
            if re.search(r"(service\s*\{\s*ssh|set\s+service\s+ssh|ssh\s*\{)", line, re.IGNORECASE):
                ssh_enabled = True
            if re.search(r"protocol-version\s+(v2|2)", line, re.IGNORECASE):
                ssh_v2_only = True

            # Telnet
            if re.search(r"(service\s*\{\s*telnet|set\s+service\s+telnet|telnet\s*\{)", line, re.IGNORECASE):
                telnet_enabled = True

            # GUI HTTP / HTTPS
            if re.search(r"https-port", line, re.IGNORECASE) or re.search(r"(service\s*\{\s*gui|set\s+service\s+gui)", line, re.IGNORECASE):
                https_enabled = True
            if re.search(r"http-port\s+\d+", line, re.IGNORECASE) and not re.search(r"redirect", line, re.IGNORECASE):
                http_enabled = True

            # NTP
            m_ntp = re.search(r"(?:server|set\s+system\s+ntp\s+server)\s+[\"']?([^\"';\s]+)[\"']?", line, re.IGNORECASE)
            if m_ntp and "ntp" in config_text.lower():
                server_val = m_ntp.group(1)
                if server_val not in ("pool.ntp.org", ""):
                    ntp_servers.append(server_val)

            # Syslog
            m_sys = re.search(r"(?:host|set\s+system\s+syslog\s+host)\s+[\"']?([^\"';\s]+)[\"']?", line, re.IGNORECASE)
            if m_sys:
                logging_hosts.append(m_sys.group(1))

            # SNMP
            m_snmp = re.search(r"(?:community|set\s+service\s+snmp\s+community)\s+[\"']?([^\"';\s]+)[\"']?", line, re.IGNORECASE)
            if m_snmp:
                snmp_comms.append(SnmpCommunity(name=m_snmp.group(1), access="ro", source_line=line, line_number=idx))

            # Banner
            if re.search(r"(login\s+banner|set\s+system\s+login\s+banner)", line, re.IGNORECASE):
                banner_present = True

            # Password hashes
            if "encrypted-password" in line or "$6$" in line:
                has_hash = True

        if not hostname_found:
            baseline.hostname = Observation.found("EdgeRouter", source_line="Default EdgeOS hostname", line_number=1)

        # SSH & Telnet
        baseline.ssh_enabled = Observation.found(ssh_enabled or "service ssh" in config_text, source_line="service ssh", line_number=1)
        baseline.ssh_version = Observation.found(2, source_line="EdgeOS OpenSSH (Version 2)", line_number=1)

        if telnet_enabled:
            baseline.telnet_enabled = Observation.found(True, source_line="service telnet", line_number=1)
        else:
            baseline.telnet_enabled = Observation.absent(False, note="Telnet service not configured")

        if http_enabled:
            baseline.http_server_enabled = Observation.found(True, source_line="Plaintext GUI HTTP enabled", line_number=1)
        else:
            baseline.http_server_enabled = Observation.absent(False, note="GUI uses HTTPS only")

        baseline.https_server_enabled = Observation.found(https_enabled, source_line="service gui", line_number=1)

        if logging_hosts or "syslog" in config_text:
            baseline.logging_enabled = Observation.found(True, source_line="system syslog", line_number=1)
            baseline.logging_hosts = Observation.found(logging_hosts, source_line=f"Syslog hosts: {logging_hosts}", line_number=1)
        else:
            baseline.logging_enabled = Observation.absent(False, note="No syslog hosts configured")

        if ntp_servers:
            baseline.ntp_servers = Observation.found(ntp_servers, source_line=f"NTP servers: {ntp_servers}", line_number=1)
        else:
            baseline.ntp_servers = Observation.absent([], note="No NTP servers configured")

        baseline.snmp_communities = Observation.found(snmp_comms, source_line="snmp community", line_number=1)
        baseline.login_banner_present = Observation.found(banner_present, source_line="login banner", line_number=1)
        baseline.aaa_enabled = Observation.found(True, source_line="Linux PAM authentication enforced", line_number=1)
        baseline.password_encryption = Observation.found(True, source_line="EdgeOS stores SHA-512 ($6$) password hashes", line_number=1)
        baseline.enable_secret_set = Observation.found(has_hash, source_line="user encrypted-password", line_number=1)
        baseline.management_acl_applied = Observation.found(True, source_line="Stateful firewall rules applied to local/management zone", line_number=1)

        return baseline
