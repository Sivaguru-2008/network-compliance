"""Deterministic SONiC / Linux-style parser.

Processes SONiC config_db.json configurations and extracts normalized values
into the SecurityBaselineModel.
"""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class SonicParser(VendorParser):
    """Grammar-based parser for SONiC config_db.json configs."""

    name = "sonic"
    vendor = "sonic"
    os_family = "linux"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        text = config_text.strip()
        if text.startswith("{") and text.endswith("}"):
            if "DEVICE_METADATA" in text or "SONIC" in text or "sonic" in text.lower():
                return 0.95
            return 0.4
        return 0.0

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if config_text is None or not config_text.strip():
            raise ParserError("Configuration is empty.")

        try:
            db = json.loads(config_text)
        except Exception as exc:
            raise ParserError(f"Failed to parse SONiC JSON config: {exc}") from exc

        raw_lines = config_text.splitlines()
        self._warnings: List[str] = []

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
            config_line_count=len(raw_lines),
        )

        # -- helpers for evidence line matching --
        def find_line(search_key: str, default_line: int = 1) -> Tuple[str, int]:
            for idx, line in enumerate(raw_lines, 1):
                if f'"{search_key}"' in line or f"'{search_key}'" in line:
                    return line, idx
            # Fallback to simple matching if quotes aren't exact
            for idx, line in enumerate(raw_lines, 1):
                if search_key in line:
                    return line, idx
            return f"JSON config entry: {search_key}", default_line

        # 1. Hostname
        metadata = db.get("DEVICE_METADATA", {})
        localhost = metadata.get("localhost", {})
        hostname_val = localhost.get("hostname")
        if hostname_val:
            line_text, line_num = find_line("hostname")
            baseline.hostname = Observation[str].found(hostname_val, line_text, line_num)
        else:
            baseline.hostname = Observation[str].unknown("No hostname configured in DEVICE_METADATA.")

        # 2. Telnet (usually disabled on SONiC)
        telnet_cfg = db.get("TELNET", {}) or db.get("telnet", {})
        if telnet_cfg:
            status = str(telnet_cfg.get("status", "disable")).lower()
            enabled = status in ("enable", "enabled", "true", "on")
            line_text, line_num = find_line("TELNET")
            baseline.telnet_enabled = Observation[bool].found(enabled, line_text, line_num)
        else:
            baseline.telnet_enabled = Observation[bool].absent(False, "Telnet server is disabled by default on SONiC.")

        baseline.vty_transport_input = Observation[List[str]].absent(["ssh"], "SONiC manages access via containerized services; SSH is standard.")
        baseline.vty_exec_timeout_seconds = Observation[int].absent(600, "VTY/CLI idle timeout default is 600 seconds.")

        # 3. SSH (enabled by default)
        ssh_cfg = db.get("SSH_SERVER", {}) or db.get("ssh_server", {})
        if ssh_cfg:
            # Check if ssh has any status
            status = str(ssh_cfg.get("status", "enable")).lower()
            enabled = status in ("enable", "enabled", "true", "on")
            line_text, line_num = find_line("SSH_SERVER")
            baseline.ssh_enabled = Observation[bool].found(enabled, line_text, line_num)
        else:
            baseline.ssh_enabled = Observation[bool].absent(True, "SSH service is active by default.")

        baseline.ssh_version = Observation[int].absent(2, "SSH protocol version 2 is default on SONiC/Linux.")

        # 4. HTTP / HTTPS (HTTP disabled, HTTPS active by default)
        http_cfg = db.get("HTTP_SERVER", {}) or db.get("http_server", {})
        if http_cfg:
            status = str(http_cfg.get("status", "disable")).lower()
            enabled = status in ("enable", "enabled", "true", "on")
            line_text, line_num = find_line("HTTP_SERVER")
            baseline.http_server_enabled = Observation[bool].found(enabled, line_text, line_num)
        else:
            baseline.http_server_enabled = Observation[bool].absent(False, "HTTP server is disabled by default.")

        https_cfg = db.get("HTTPS_SERVER", {}) or db.get("https_server", {})
        if https_cfg:
            status = str(https_cfg.get("status", "enable")).lower()
            enabled = status in ("enable", "enabled", "true", "on")
            line_text, line_num = find_line("HTTPS_SERVER")
            baseline.https_server_enabled = Observation[bool].found(enabled, line_text, line_num)
        else:
            baseline.https_server_enabled = Observation[bool].absent(True, "HTTPS server is active by default.")

        # 5. Management ACL
        mgmt_acl = db.get("MGMT_INTERFACE", {}) or db.get("ACL_RULE", {})
        if mgmt_acl:
            line_text, line_num = find_line("MGMT_INTERFACE") if db.get("MGMT_INTERFACE") else find_line("ACL_RULE")
            baseline.management_acl_applied = Observation[bool].found(True, line_text, line_num)
        else:
            baseline.management_acl_applied = Observation[bool].absent(False, "No administrative ACL applied to management plane.")

        # 6. Banner
        banner_val = localhost.get("login_banner") or localhost.get("banner")
        if banner_val:
            line_text, line_num = find_line("login_banner") if localhost.get("login_banner") else find_line("banner")
            baseline.login_banner_present = Observation[bool].found(True, line_text, line_num)
        else:
            baseline.login_banner_present = Observation[bool].absent(False, "No login banner is defined in metadata.")

        # 7. Credentials
        users = db.get("USER", {}) or db.get("user", {})
        if users:
            admin_user = users.get("admin") or users.get("root") or list(users.values())[0]
            password_hash = admin_user.get("password") or admin_user.get("hashed_password")
            if password_hash:
                line_text, line_num = find_line("password")
                baseline.enable_secret_set = Observation[bool].found(True, line_text, line_num, note="Admin password hash exists.")
            else:
                baseline.enable_secret_set = Observation[bool].absent(False, "No admin password hash found.")
        else:
            baseline.enable_secret_set = Observation[bool].absent(False, "No local user accounts configured.")

        baseline.enable_password_present = Observation[bool].absent(False, "Linux shadow passwords do not store plain-text values.")
        baseline.password_encryption = Observation[bool].absent(True, "Linux password hashes are encrypted at rest by default.")
        baseline.password_min_length = Observation[int].absent(8, "Minimum password length is enforced locally via pam_pwquality (default 8).")

        # 8. AAA (TACACS+ / RADIUS)
        tacacs = db.get("TACACS_SERVER", {}) or db.get("tacacs_server", {})
        radius = db.get("RADIUS_SERVER", {}) or db.get("radius_server", {})
        if tacacs or radius:
            key = "TACACS_SERVER" if tacacs else "RADIUS_SERVER"
            line_text, line_num = find_line(key)
            baseline.aaa_enabled = Observation[bool].found(True, line_text, line_num, note="External AAA authentication server configured.")
        else:
            baseline.aaa_enabled = Observation[bool].absent(False, "No external TACACS+ or RADIUS servers configured.")

        # 9. SNMP Communities
        snmp_communities_val = db.get("SNMP_COMMUNITY", {}) or db.get("snmp_community", {})
        if snmp_communities_val:
            communities = []
            for name, details in snmp_communities_val.items():
                line_text, line_num = find_line(name)
                access = details.get("access", "ro")
                communities.append(SnmpCommunity(name=name, access=access, source_line=line_text.strip(), line_number=line_num))
            line_text, line_num = find_line("SNMP_COMMUNITY")
            baseline.snmp_communities = Observation[List[SnmpCommunity]].found(communities, line_text, line_num)
        else:
            baseline.snmp_communities = Observation[List[SnmpCommunity]].absent([], "No SNMP communities configured.")

        # 10. Logging
        syslog = db.get("SYSLOG_SERVER", {}) or db.get("syslog_server", {})
        if syslog:
            hosts = list(syslog.keys())
            line_text, line_num = find_line(hosts[0])
            baseline.logging_hosts = Observation[List[str]].found(hosts, line_text, line_num)
            baseline.logging_buffered = Observation[bool].found(True, line_text, line_num, note="Local syslog buffering is active on Linux.")
            baseline.logging_enabled = Observation[bool].found(True, line_text, line_num, note="External logging hosts configured.")
        else:
            baseline.logging_hosts = Observation[List[str]].absent([], "No syslog servers configured.")
            baseline.logging_buffered = Observation[bool].absent(True, "On-box syslog file logs (journald/rsyslog) are active by default.")
            baseline.logging_enabled = Observation[bool].absent(True, "On-box local logging is active by default.")

        # 11. NTP
        ntp_cfg = db.get("NTP_SERVER", {}) or db.get("ntp_server", {})
        if ntp_cfg:
            hosts = list(ntp_cfg.keys())
            line_text, line_num = find_line(hosts[0])
            baseline.ntp_servers = Observation[List[str]].found(hosts, line_text, line_num)
        else:
            baseline.ntp_servers = Observation[List[str]].absent([], "No NTP servers configured.")

        baseline.provenance.warnings = self._warnings
        return baseline
