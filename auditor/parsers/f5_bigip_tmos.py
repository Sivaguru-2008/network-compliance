"""Deterministic F5 Networks BIG-IP TMOS configuration parser.

This parser processes F5 TMOS configuration files (bigip.conf / bigip_base.conf),
normalizes settings into the SecurityBaselineModel, and preserves
configuration lines and line numbers for compliance audit evidence.
"""

import hashlib
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class F5BigIPTMOSParser(VendorParser):
    """Configuration parser for F5 Networks BIG-IP TMOS configurations."""

    name = "f5_bigip_tmos"
    vendor = "f5"
    os_family = "tmos"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0

        text_lower = config_text.lower()
        keywords = [
            "sys global-settings {",
            "sys sshd {",
            "sys httpd {",
            "sys syslog {",
            "auth password-policy {",
            "sys ntp {",
            "sys dns {",
        ]
        for kw in keywords:
            if kw in text_lower:
                return 1.0
        import re
        if re.search(r"(?im)^#TMSH-VERSION:", config_text):
            return 0.95
        tmsh_blocks = [
            "ltm virtual ", "ltm pool ", "ltm node ", "ltm monitor ",
            "net vlan ", "net self ", "net route ",
            "apm ", "analytics ",
        ]
        hits = sum(1 for kw in tmsh_blocks if kw in text_lower)
        if hits >= 2:
            return 0.85
        return 0.0

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        self._raw_lines = config_text.splitlines()

        if self.detect(config_text) == 0.0:
            raise ParserError("Not an F5 Networks BIG-IP TMOS configuration.")

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
                        "F5 Networks BIG-IP TMOS parser does not evaluate this field."
                    )
                )

        return baseline

    def _evidence(self, line_num: int) -> Tuple[str, int, str]:
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"Line {line_num}: {raw_line}"

    def _parse_config(self, baseline: SecurityBaselineModel) -> None:
        # F5 TMOS default fallback values
        baseline.telnet_enabled = Observation[bool].absent(
            False, "Telnet daemon is not supported or disabled by default on BIG-IP TMOS."
        )
        baseline.http_server_enabled = Observation[bool].absent(
            False, "Insecure HTTP web server management is disabled by default on BIG-IP TMOS."
        )
        baseline.https_server_enabled = Observation[bool].absent(
            True, "Secure HTTPS Configuration Utility (httpd) is enabled by default on BIG-IP TMOS."
        )
        baseline.ssh_enabled = Observation[bool].absent(
            True, "SSH remote console server (sshd) is enabled by default on BIG-IP TMOS."
        )
        baseline.vty_transport_input = Observation[List[str]].absent(
            ["ssh"], "Remote administrative console access is restricted to SSH only."
        )
        baseline.vty_exec_timeout_seconds = Observation[int].absent(
            1200, "VTY / HTTPS GUI timeout defaults to 20 minutes (1200 seconds) on BIG-IP TMOS."
        )
        baseline.login_banner_present = Observation[bool].absent(
            False, "Pre-login security banner is not configured by default."
        )
        baseline.password_encryption = Observation[bool].absent(
            True, "BIG-IP TMOS automatically hashes/encrypts all user administrative passwords."
        )
        baseline.password_min_length = Observation[int].absent(
            12, "Minimum password length defaults to 12 characters on BIG-IP TMOS."
        )
        baseline.aaa_enabled = Observation[bool].absent(
            False, "Centralized AAA authentication is not configured by default."
        )
        baseline.snmp_agent_enabled = Observation[bool].absent(
            False, "SNMP agent is disabled by default on BIG-IP TMOS."
        )
        baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
            [], "SNMP communities are not configured by default."
        )
        baseline.management_acl_applied = Observation[bool].absent(
            False, "sshd and httpd access restrictions default to allow-all."
        )
        baseline.enable_secret_set = Observation[bool].absent(
            True, "BIG-IP TMOS uses role-based administrative accounts (enable secrets are not used)."
        )
        baseline.enable_password_present = Observation[bool].absent(
            False, "BIG-IP TMOS does not support legacy enable passwords."
        )

        context_stack = []
        dns_servers = []
        ntp_servers = []
        logging_hosts = []
        snmp_communities = []

        temp_communities = {}
        sshd_allow = []
        httpd_allow = []
        sshd_line_num = 1
        httpd_line_num = 1
        sshd_timeout = None
        httpd_timeout = None
        global_timeout = None
        sshd_timeout_line = 1
        httpd_timeout_line = 1
        global_timeout_line = 1

        for idx, line in enumerate(self._raw_lines):
            line_num = idx + 1
            line_strip = line.strip()

            if not line_strip or line_strip.startswith("#") or line_strip.startswith("//"):
                continue

            # Context tracking using open/close curly braces
            if line_strip.endswith("{"):
                # E.g. sys global-settings {
                block_head = line_strip[:-1].strip()
                # Extract block type
                context_stack.append((block_head, line_num))
                continue
            elif line_strip == "}":
                if context_stack:
                    context_stack.pop()
                continue

            # Check active context
            active_contexts = [c[0] for c in context_stack]

            # Hostname / System Name
            if active_contexts == ["sys global-settings"] and line_strip.startswith("hostname "):
                val = line_strip.split(" ", 1)[1].strip().strip('"')
                raw, _, note = self._evidence(line_num)
                baseline.hostname = Observation[str].found(val, raw, line_num, note=note)

            # Global console timeout
            elif active_contexts == ["sys global-settings"] and line_strip.startswith("console-inactivity-timeout "):
                val = line_strip.split(" ", 1)[1].strip()
                try:
                    global_timeout = int(val)
                    global_timeout_line = line_num
                except ValueError:
                    pass

            # SSH timeout
            elif active_contexts == ["sys sshd"] and line_strip.startswith("inactivity-timeout "):
                val = line_strip.split(" ", 1)[1].strip()
                try:
                    sshd_timeout = int(val)
                    sshd_timeout_line = line_num
                except ValueError:
                    pass

            # SSH Banner
            elif active_contexts == ["sys sshd"] and line_strip.startswith("banner-text "):
                val = line_strip.split(" ", 1)[1].strip().strip('"')
                if val and val != "none":
                    raw, _, note = self._evidence(line_num)
                    baseline.login_banner_present = Observation[bool].found(True, raw, line_num, note=note)
            elif active_contexts == ["sys sshd"] and line_strip.startswith("banner ") and "enabled" in line_strip:
                raw, _, note = self._evidence(line_num)
                baseline.login_banner_present = Observation[bool].found(True, raw, line_num, note=note)
            elif active_contexts == ["sys sshd"] and line_strip.startswith("include "):
                val = line_strip.split(" ", 1)[1].strip().strip('"')
                if "Banner " in val or "banner " in val:
                    raw, _, note = self._evidence(line_num)
                    baseline.login_banner_present = Observation[bool].found(True, raw, line_num, note=note)

            # SSH ACL
            elif "allow" in active_contexts and "sys sshd" in active_contexts:
                if line_strip not in ("{", "}", "all"):
                    sshd_allow.append(line_strip)
                    sshd_line_num = line_num

            # HTTP timeout (PAM auth idle timeout)
            elif active_contexts == ["sys httpd"] and line_strip.startswith("auth-pam-idle-timeout "):
                val = line_strip.split(" ", 1)[1].strip()
                try:
                    httpd_timeout = int(val)
                    httpd_timeout_line = line_num
                except ValueError:
                    pass

            # HTTP ACL
            elif "allow" in active_contexts and "sys httpd" in active_contexts:
                if line_strip not in ("{", "}", "all"):
                    httpd_allow.append(line_strip)
                    httpd_line_num = line_num

            # AAA sources
            elif line_strip.startswith("auth tacacs ") or line_strip.startswith("auth ldap ") or line_strip.startswith("auth radius "):
                raw, _, note = self._evidence(line_num)
                baseline.aaa_enabled = Observation[bool].found(True, raw, line_num, note=note)
            elif active_contexts == ["auth source"] and line_strip.startswith("type "):
                val = line_strip.split(" ", 1)[1].strip()
                if val not in ("local", "none"):
                    raw, _, note = self._evidence(line_num)
                    baseline.aaa_enabled = Observation[bool].found(True, raw, line_num, note=note)

            # Password policy
            elif active_contexts == ["auth password-policy"] and line_strip.startswith("minimum-length "):
                val = line_strip.split(" ", 1)[1].strip()
                try:
                    num = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.password_min_length = Observation[int].found(num, raw, line_num, note=note)
                except ValueError:
                    pass
            elif active_contexts == ["auth password-policy"] and line_strip.startswith("required-uppercase "):
                val = line_strip.split(" ", 1)[1].strip()
                try:
                    num = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.password_min_uppercase = Observation[int].found(num, raw, line_num, note=note)
                except ValueError:
                    pass
            elif active_contexts == ["auth password-policy"] and line_strip.startswith("required-lowercase "):
                val = line_strip.split(" ", 1)[1].strip()
                try:
                    num = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.password_min_lowercase = Observation[int].found(num, raw, line_num, note=note)
                except ValueError:
                    pass
            elif active_contexts == ["auth password-policy"] and line_strip.startswith("required-numeric "):
                val = line_strip.split(" ", 1)[1].strip()
                try:
                    num = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.password_min_numeric = Observation[int].found(num, raw, line_num, note=note)
                except ValueError:
                    pass
            elif active_contexts == ["auth password-policy"] and line_strip.startswith("required-special "):
                val = line_strip.split(" ", 1)[1].strip()
                try:
                    num = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.password_min_special = Observation[int].found(num, raw, line_num, note=note)
                except ValueError:
                    pass
            elif active_contexts == ["auth password-policy"] and line_strip.startswith("max-duration "):
                val = line_strip.split(" ", 1)[1].strip()
                try:
                    num = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.password_max_age_days = Observation[int].found(num, raw, line_num, note=note)
                except ValueError:
                    pass

            # Syslog Remote server
            elif "remote-servers" in active_contexts and "sys syslog" in active_contexts:
                # E.g. server_1 { host 192.168.1.10 }
                if line_strip.startswith("host "):
                    val = line_strip.split(" ", 1)[1].strip()
                    logging_hosts.append((val, line_num))

            # NTP Servers
            elif "servers" in active_contexts and "sys ntp" in active_contexts:
                if line_strip not in ("{", "}"):
                    val = line_strip.strip('"')
                    ntp_servers.append((val, line_num))

            # DNS Servers
            elif "name-servers" in active_contexts and "sys dns" in active_contexts:
                if line_strip not in ("{", "}"):
                    val = line_strip.strip('"')
                    dns_servers.append((val, line_num))

            # SNMP Community Configuration
            elif "communities" in active_contexts and "sys snmp" in active_contexts:
                # Inside Communities block:
                # public { community-name public }
                # Track community block header
                comm_block = ""
                for ctx in context_stack:
                    if ctx[0] not in ("sys snmp", "communities"):
                        comm_block = ctx[0]
                        break
                if comm_block:
                    if comm_block not in temp_communities:
                        temp_communities[comm_block] = {"name": comm_block, "line": line_num}
                    if line_strip.startswith("community-name "):
                        val = line_strip.split(" ", 1)[1].strip().strip('"')
                        temp_communities[comm_block]["name"] = val

        # ----------------------------------------------------------------------
        # Post-processing evaluations based on collected context states
        # ----------------------------------------------------------------------

        # Session Timeout (SSHD or HTTPD or Global settings)
        if sshd_timeout is not None:
            raw, _, note = self._evidence(sshd_timeout_line)
            baseline.vty_exec_timeout_seconds = Observation[int].found(sshd_timeout, raw, sshd_timeout_line, note=note)
        elif httpd_timeout is not None:
            raw, _, note = self._evidence(httpd_timeout_line)
            baseline.vty_exec_timeout_seconds = Observation[int].found(httpd_timeout, raw, httpd_timeout_line, note=note)
        elif global_timeout is not None:
            raw, _, note = self._evidence(global_timeout_line)
            baseline.vty_exec_timeout_seconds = Observation[int].found(global_timeout, raw, global_timeout_line, note=note)

        # Management ACL Applied
        if sshd_allow:
            raw, _, note = self._evidence(sshd_line_num)
            baseline.management_acl_applied = Observation[bool].found(True, raw, sshd_line_num, note=note)
        elif httpd_allow:
            raw, _, note = self._evidence(httpd_line_num)
            baseline.management_acl_applied = Observation[bool].found(True, raw, httpd_line_num, note=note)

        # DNS Servers
        if dns_servers:
            last_ip, last_line = dns_servers[-1]
            raw, _, note = self._evidence(last_line)
            baseline.dns_servers = Observation[List[str]].found(
                [d[0] for d in dns_servers], raw, last_line, note=note
            )
        else:
            baseline.dns_servers = Observation[List[str]].unknown("DNS configuration is not present.")

        # NTP Servers
        if ntp_servers:
            last_ip, last_line = ntp_servers[-1]
            raw, _, note = self._evidence(last_line)
            baseline.ntp_servers = Observation[List[str]].found(
                [n[0] for n in ntp_servers], raw, last_line, note=note
            )
        else:
            baseline.ntp_servers = Observation[List[str]].unknown("NTP configuration is not present.")

        # Remote Syslog Logging
        if logging_hosts:
            last_ip, last_line = logging_hosts[-1]
            raw, _, note = self._evidence(last_line)
            baseline.logging_enabled = Observation[bool].found(True, raw, last_line, note=note)
            baseline.logging_hosts = Observation[List[str]].found(
                [h[0] for h in logging_hosts], raw, last_line, note=note
            )
        else:
            baseline.logging_enabled = Observation[bool].unknown("Syslog remote server is not configured.")
            baseline.logging_hosts = Observation[List[str]].unknown("Syslog remote server is not configured.")

        # SNMP Communities
        if temp_communities:
            communities_objs = []
            last_snmp_line = 1
            for k, c in temp_communities.items():
                raw, _, _ = self._evidence(c["line"])
                communities_objs.append(
                    SnmpCommunity(
                        name=c["name"],
                        access="ro", # Default is read-only in BIG-IP standard SNMP configuration
                        source_line=raw,
                        line_number=c["line"],
                    )
                )
                last_snmp_line = c["line"]
            
            raw, _, note = self._evidence(last_snmp_line)
            baseline.snmp_agent_enabled = Observation[bool].found(True, raw, last_snmp_line, note=note)
            baseline.snmp_communities = Observation[List[SnmpCommunity]].found(
                communities_objs, raw, last_snmp_line, note=note
            )
