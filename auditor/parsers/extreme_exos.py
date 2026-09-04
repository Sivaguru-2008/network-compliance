"""Deterministic Extreme Networks EXOS parser.

Extreme EXOS configurations are CLI-command scripts (often saved as XML or ASCII scripts).
This parser extracts management settings, accounts, SNMP, DNS, NTP, and logging options
from CLI configurations.
"""

import hashlib
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciscoconfparse2 import CiscoConfParse

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation, Origin
from .base import ParserError, VendorParser, registry

_EXOS_MARKERS: Sequence[Tuple[str, float]] = (
    (r"(?im)^\s*configure switch sysname\b", 0.40),
    (r"(?im)^\s*configure snmp sysName\b", 0.35),
    (r"(?im)^\s*enable ssh2\b", 0.30),
    (r"(?im)^\s*disable ssh2\b", 0.30),
    (r"(?im)^\s*disable telnet\b", 0.30),
    (r"(?im)^\s*enable telnet\b", 0.25),
    (r"(?im)^\s*enable cli idle-timeout\b", 0.30),
    (r"(?im)^\s*configure dns-client add\b", 0.20),
    (r"(?im)^\s*configure ntp server add\b", 0.20),
    (r"(?im)^\s*configure account \S+ password-policy\b", 0.20),
    (r"(?im)^\s*<xos-configuration\b", 0.80),
    (r"(?im)^#\s*ExtremeXOS\s+version\b", 0.50),
    (r"(?im)^\s*enable web\b", 0.15),
    (r"(?im)^\s*disable web\b", 0.15),
)

_NON_EXOS_MARKERS: Sequence[Tuple[str, float]] = (
    (r"(?im)^\s*line vty\b", 0.40),
    (r"(?im)^\s*ip http server\s*$", 0.30),
    (r"(?im)^\s*set system host-name\b", 0.90),
    (r"(?im)^\s*system \{", 0.90),
    (r"(?im)^\s*config system global\b", 0.90),
    (r"(?im)^\s*sysname \S+", 0.90),
    (r"(?im)^\s*management ssh\s*$", 0.40),
    (r"(?im)^\s*session-timeout\b", 0.40),
)


@registry.register
class ExtremeEXOSParser(VendorParser):
    """Grammar-based parser for Extreme Networks EXOS configurations."""

    name = "extreme_exos"
    vendor = "extreme"
    os_family = "exos"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        score = sum(w for p, w in _EXOS_MARKERS if re.search(p, config_text))
        score -= sum(w for p, w in _NON_EXOS_MARKERS if re.search(p, config_text))
        return max(0.0, min(1.0, score))

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if config_text is None or not config_text.strip():
            raise ParserError("Configuration is empty.")

        raw_lines = config_text.splitlines()
        self._warnings: List[str] = []
        try:
            self._parse = CiscoConfParse(config=raw_lines, syntax="ios")
        except Exception as exc:
            raise ParserError(f"Could not parse this configuration: {exc}") from exc

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

        baseline.hostname = self._hostname()
        self._normalize_ssh(baseline)
        self._normalize_telnet(baseline)
        self._derive_vty_transport(baseline)
        self._normalize_http_https(baseline)
        self._normalize_session_timeout(baseline)
        self._normalize_banner(baseline)
        self._normalize_credentials(baseline)
        self._normalize_aaa(baseline)
        self._normalize_snmp(baseline)
        self._normalize_logging(baseline)
        self._normalize_ntp(baseline)
        self._normalize_dns(baseline)
        self._normalize_password_complexity(baseline)

        # Ensure all baseline fields are answered
        for field in baseline.observable_fields():
            observation = getattr(baseline, field)
            if observation.note == "Parser did not evaluate this field.":
                setattr(
                    baseline,
                    field,
                    type(observation).unknown(
                        "Extreme EXOS parser does not evaluate this field."
                    )
                )

        baseline.provenance.warnings = self._warnings
        return baseline

    # -- helpers -----------------------------------------------------------

    def _find(self, pattern: str) -> List[Any]:
        return self._parse.find_objects(pattern)

    def _first(self, pattern: str) -> Optional[Any]:
        objs = self._find(pattern)
        return objs[0] if objs else None

    @staticmethod
    def _lineno(obj) -> int:
        return obj.linenum + 1

    @staticmethod
    def _has_child(block, pattern: str) -> Optional[Any]:
        for child in block.children:
            if re.search(pattern, child.text, re.IGNORECASE):
                return child
        return None

    def _warn(self, message: str) -> None:
        self._warnings.append(message)

    # -- fields normalization ----------------------------------------------

    def _hostname(self) -> Observation[str]:
        obj = self._first(r"^\s*configure\s+switch\s+sysname\s+[\"']?([^\"'\s]+)[\"']?")
        if obj is not None:
            match = re.match(r"^\s*configure\s+switch\s+sysname\s+[\"']?([^\"'\s]+)[\"']?", obj.text)
            if match:
                return Observation[str].found(match.group(1), obj.text, self._lineno(obj))
        return Observation[str].absent(
            "switch", "No sysname configured. The switch defaults to 'switch' hostname."
        )

    def _normalize_ssh(self, baseline: SecurityBaselineModel) -> None:
        enable_ssh = self._first(r"^\s*enable\s+ssh2\b")
        disable_ssh = self._first(r"^\s*disable\s+ssh2\b")

        if enable_ssh is not None:
            # Check if disable is later in config
            if disable_ssh is not None and self._lineno(disable_ssh) > self._lineno(enable_ssh):
                baseline.ssh_enabled = Observation[bool].found(
                    False, disable_ssh.text, self._lineno(disable_ssh),
                    note="SSH2 server is explicitly disabled."
                )
            else:
                baseline.ssh_enabled = Observation[bool].found(
                    True, enable_ssh.text, self._lineno(enable_ssh),
                    note="SSH2 server is explicitly enabled."
                )
        elif disable_ssh is not None:
            baseline.ssh_enabled = Observation[bool].found(
                False, disable_ssh.text, self._lineno(disable_ssh),
                note="SSH2 server is explicitly disabled."
            )
        else:
            baseline.ssh_enabled = Observation[bool].absent(
                False, "SSH2 server is disabled by default."
            )

        baseline.ssh_version = Observation[int].absent(
            2, "SSH v2 is enforced by default in EXOS; no version statement is present in config."
        )

        # Restricting management access via access-profile
        ssh_acl = self._first(r"^\s*configure\s+ssh2\s+access-profile\s+(\S+)")
        telnet_acl = self._first(r"^\s*configure\s+telnet\s+access-profile\s+(\S+)")
        web_acl = self._first(r"^\s*configure\s+web\s+access-profile\s+(\S+)")

        if ssh_acl is not None:
            baseline.management_acl_applied = Observation[bool].found(
                True, ssh_acl.text, self._lineno(ssh_acl),
                note=f"SSH2 access profile applied: {ssh_acl.text.strip()}"
            )
        elif telnet_acl is not None:
            baseline.management_acl_applied = Observation[bool].found(
                True, telnet_acl.text, self._lineno(telnet_acl),
                note=f"Telnet access profile applied: {telnet_acl.text.strip()}"
            )
        elif web_acl is not None:
            baseline.management_acl_applied = Observation[bool].found(
                True, web_acl.text, self._lineno(web_acl),
                note=f"Web access profile applied: {web_acl.text.strip()}"
            )
        else:
            baseline.management_acl_applied = Observation[bool].absent(
                False, "No access profile is applied to SSH2, Telnet, or Web management services."
            )

    def _normalize_telnet(self, baseline: SecurityBaselineModel) -> None:
        enable_telnet = self._first(r"^\s*enable\s+telnet\b")
        disable_telnet = self._first(r"^\s*disable\s+telnet\b")

        if disable_telnet is not None:
            if enable_telnet is not None and self._lineno(enable_telnet) > self._lineno(disable_telnet):
                baseline.telnet_enabled = Observation[bool].found(
                    True, enable_telnet.text, self._lineno(enable_telnet),
                    note="Telnet server is explicitly enabled."
                )
            else:
                baseline.telnet_enabled = Observation[bool].found(
                    False, disable_telnet.text, self._lineno(disable_telnet),
                    note="Telnet server is explicitly disabled."
                )
        elif enable_telnet is not None:
            baseline.telnet_enabled = Observation[bool].found(
                True, enable_telnet.text, self._lineno(enable_telnet),
                note="Telnet server is explicitly enabled."
            )
        else:
            baseline.telnet_enabled = Observation[bool].absent(
                True, "Telnet server is enabled by default on EXOS."
            )

    def _derive_vty_transport(self, baseline: SecurityBaselineModel) -> None:
        transports: List[str] = []
        evidence_line = None
        evidence_lineno = None

        if baseline.ssh_enabled.value:
            transports.append("ssh")
            evidence_line = baseline.ssh_enabled.source_line
            evidence_lineno = baseline.ssh_enabled.line_number
        if baseline.telnet_enabled.value:
            transports.append("telnet")
            if not evidence_line:
                evidence_line = baseline.telnet_enabled.source_line
                evidence_lineno = baseline.telnet_enabled.line_number

        if evidence_line:
            baseline.vty_transport_input = Observation[List[str]].found(
                sorted(transports), evidence_line, evidence_lineno,
                note="Determined from enabled remote access servers."
            )
        else:
            baseline.vty_transport_input = Observation[List[str]].absent(
                [], "Neither SSH nor Telnet management servers are enabled."
            )

    def _normalize_http_https(self, baseline: SecurityBaselineModel) -> None:
        enable_web = self._first(r"^\s*enable\s+web\b")
        enable_web_http = self._first(r"^\s*enable\s+web\s+http\b")
        disable_web = self._first(r"^\s*disable\s+web\b")
        disable_web_http = self._first(r"^\s*disable\s+web\s+http\b")

        # Determine HTTP status
        if disable_web is not None:
            baseline.http_server_enabled = Observation[bool].found(
                False, disable_web.text, self._lineno(disable_web),
                note="Web HTTP server is explicitly disabled."
            )
        elif disable_web_http is not None:
            baseline.http_server_enabled = Observation[bool].found(
                False, disable_web_http.text, self._lineno(disable_web_http),
                note="Web HTTP server is explicitly disabled."
            )
        elif enable_web is not None:
            baseline.http_server_enabled = Observation[bool].found(
                True, enable_web.text, self._lineno(enable_web),
                note="Web HTTP server is explicitly enabled."
            )
        elif enable_web_http is not None:
            baseline.http_server_enabled = Observation[bool].found(
                True, enable_web_http.text, self._lineno(enable_web_http),
                note="Web HTTP server is explicitly enabled."
            )
        else:
            baseline.http_server_enabled = Observation[bool].absent(
                False, "Web HTTP server is disabled by default on EXOS."
            )

        # Determine HTTPS status
        enable_https = self._first(r"^\s*enable\s+web\s+https\b")
        if enable_https is not None:
            baseline.https_server_enabled = Observation[bool].found(
                True, enable_https.text, self._lineno(enable_https),
                note="Web HTTPS server is explicitly enabled."
            )
        else:
            baseline.https_server_enabled = Observation[bool].absent(
                False, "Web HTTPS server is disabled by default on EXOS."
            )

    def _normalize_session_timeout(self, baseline: SecurityBaselineModel) -> None:
        disable_timeout = self._first(r"^\s*disable\s+cli\s+idle-timeout\b")
        timeout_val = self._first(r"^\s*configure\s+cli\s+idle-timeout\s+(\d+)")

        if disable_timeout is not None:
            # Check if there is an enable/configure later
            if timeout_val is not None and self._lineno(timeout_val) > self._lineno(disable_timeout):
                match = re.match(r"^\s*configure\s+cli\s+idle-timeout\s+(\d+)", timeout_val.text)
                if match:
                    minutes = int(match.group(1))
                    baseline.vty_exec_timeout_seconds = Observation[int].found(
                        minutes * 60, timeout_val.text, self._lineno(timeout_val),
                        note=f"CLI idle timeout configured: {minutes} minutes."
                    )
                    return
            baseline.vty_exec_timeout_seconds = Observation[int].found(
                0, disable_timeout.text, self._lineno(disable_timeout),
                note="CLI idle timeout is explicitly disabled."
            )
        elif timeout_val is not None:
            match = re.match(r"^\s*configure\s+cli\s+idle-timeout\s+(\d+)", timeout_val.text)
            if match:
                minutes = int(match.group(1))
                baseline.vty_exec_timeout_seconds = Observation[int].found(
                    minutes * 60, timeout_val.text, self._lineno(timeout_val),
                    note=f"CLI idle timeout configured: {minutes} minutes."
                )
        else:
            # Default idle timeout is 20 minutes (1200 seconds)
            baseline.vty_exec_timeout_seconds = Observation[int].absent(
                1200, "No CLI idle-timeout configured. Defaults to 20 minutes."
            )

    def _normalize_banner(self, baseline: SecurityBaselineModel) -> None:
        obj = self._first(r"^\s*configure\s+banner\b")
        if obj is not None:
            baseline.login_banner_present = Observation[bool].found(
                True, obj.text, self._lineno(obj),
                note="Pre-login banner is configured."
            )
        else:
            baseline.login_banner_present = Observation[bool].absent(
                False, "No pre-login banner is configured."
            )

    def _normalize_credentials(self, baseline: SecurityBaselineModel) -> None:
        # Accounts with encrypted passwords in running configuration
        admin_account = self._first(r"^\s*(?:create|configure)\s+account\s+\S+(?:\s+\S+)?\s+encrypted\b")
        if admin_account is not None:
            baseline.enable_secret_set = Observation[bool].found(
                True, admin_account.text, self._lineno(admin_account),
                note="Local user accounts configured with encrypted passwords."
            )
        else:
            baseline.enable_secret_set = Observation[bool].absent(
                False, "No accounts configured with encrypted passwords found."
            )

        baseline.enable_password_present = Observation[bool].absent(
            False, "Legacy cleartext enable passwords are not supported on EXOS."
        )

        baseline.password_encryption = Observation[bool].absent(
            True, "EXOS automatically hashes and encrypts account passwords in config storage."
        )

    def _normalize_aaa(self, baseline: SecurityBaselineModel) -> None:
        radius = self._first(r"^\s*enable\s+radius\b")
        tacacs = self._first(r"^\s*enable\s+tacacs\b")

        if radius is not None:
            baseline.aaa_enabled = Observation[bool].found(
                True, radius.text, self._lineno(radius),
                note="RADIUS management authentication client is enabled."
            )
        elif tacacs is not None:
            baseline.aaa_enabled = Observation[bool].found(
                True, tacacs.text, self._lineno(tacacs),
                note="TACACS+ management authentication client is enabled."
            )
        else:
            baseline.aaa_enabled = Observation[bool].absent(
                False, "AAA authentication is not enabled (no remote RADIUS or TACACS+ enabled)."
            )

    def _normalize_snmp(self, baseline: SecurityBaselineModel) -> None:
        communities: List[SnmpCommunity] = []
        lines = self._find(r"^\s*configure\s+snmp\s+add\s+community\b")
        for obj in lines:
            # configure snmp add community <string> [readonly | readwrite]
            match = re.match(r"^\s*configure\s+snmp\s+add\s+community\s+(\S+)(?:\s+(readonly|readwrite))?", obj.text)
            if match:
                name = match.group(1)
                privilege = match.group(2) or "readonly"
                access = "rw" if privilege == "readwrite" else "ro"

                communities.append(
                    SnmpCommunity(
                        name=name,
                        access=access,
                        acl=None,
                        source_line=obj.text.strip(),
                        line_number=self._lineno(obj),
                    )
                )

        if communities:
            lines_str = "\n".join(c.source_line for c in communities)
            baseline.snmp_communities = Observation[List[SnmpCommunity]].found(
                communities, lines_str, self._lineno(lines[0])
            )
        else:
            # SNMP is enabled by default with public/private strings on some EXOS unless deleted,
            # but in config absence means none configured.
            baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
                [], "No SNMP communities are configured."
            )

    def _normalize_logging(self, baseline: SecurityBaselineModel) -> None:
        hosts: List[str] = []
        # configure syslog add <ip> ...
        logging_lines = self._find(r"^\s*configure\s+syslog\s+add\s+(\S+)")
        for obj in logging_lines:
            match = re.match(r"^\s*configure\s+syslog\s+add\s+(\S+)", obj.text)
            if match:
                hosts.append(match.group(1).split(":")[0])

        # enable log target syslog <ip> ...
        enable_logging_lines = self._find(r"^\s*enable\s+log\s+target\s+syslog\s+(\S+)")
        for obj in enable_logging_lines:
            match = re.match(r"^\s*enable\s+log\s+target\s+syslog\s+(\S+)", obj.text)
            if match:
                hosts.append(match.group(1).split(":")[0])

        # local event log is on by default
        baseline.logging_buffered = Observation[bool].absent(
            True, "Local log buffer is enabled by default on EXOS."
        )

        unique_hosts = sorted(list(set(hosts)))
        if unique_hosts:
            first_obj = logging_lines[0] if logging_lines else enable_logging_lines[0]
            lines_str = "\n".join(obj.text for obj in logging_lines + enable_logging_lines)
            baseline.logging_enabled = Observation[bool].found(
                True, lines_str, self._lineno(first_obj)
            )
            baseline.logging_hosts = Observation[List[str]].found(
                unique_hosts, lines_str, self._lineno(first_obj)
            )
        else:
            baseline.logging_enabled = Observation[bool].found(
                True, "Local buffer enabled by default", None,
                note="Logging is enabled locally via default event log targets."
            )
            baseline.logging_hosts = Observation[List[str]].absent(
                [], "No remote syslog host configured."
            )

    def _normalize_ntp(self, baseline: SecurityBaselineModel) -> None:
        ntp_lines = self._find(r"^\s*configure\s+ntp\s+server\s+add\s+(\S+)")
        ntp_enabled = self._first(r"^\s*enable\s+ntp\b")

        servers: List[str] = []
        for obj in ntp_lines:
            match = re.match(r"^\s*configure\s+ntp\s+server\s+add\s+(\S+)", obj.text)
            if match:
                servers.append(match.group(1))

        if servers and ntp_enabled is not None:
            lines_str = "\n".join(obj.text for obj in ntp_lines) + f"\n{ntp_enabled.text}"
            baseline.ntp_servers = Observation[List[str]].found(
                servers, lines_str, self._lineno(ntp_lines[0])
            )
        elif servers:
            baseline.ntp_servers = Observation[List[str]].absent(
                [], "NTP servers are configured, but NTP client process is not enabled."
            )
        else:
            baseline.ntp_servers = Observation[List[str]].absent(
                [], "No NTP servers configured."
            )

    def _normalize_dns(self, baseline: SecurityBaselineModel) -> None:
        dns_lines = self._find(r"^\s*configure\s+dns-client\s+add\s+name-server\s+(\S+)")
        servers: List[str] = []
        for obj in dns_lines:
            match = re.match(r"^\s*configure\s+dns-client\s+add\s+name-server\s+(\S+)", obj.text)
            if match:
                servers.append(match.group(1))

        if servers:
            lines_str = "\n".join(obj.text for obj in dns_lines)
            baseline.dns_servers = Observation[List[str]].found(
                servers, lines_str, self._lineno(dns_lines[0])
            )
        else:
            baseline.dns_servers = Observation[List[str]].absent(
                [], "No DNS servers configured."
            )

    def _normalize_password_complexity(self, baseline: SecurityBaselineModel) -> None:
        pwd_policy = self._first(r"^\s*configure\s+account\s+(?:all|\S+)\s+password-policy\b")
        
        if pwd_policy is not None:
            # Check if all-char-groups validation is enabled
            val_lines = self._find(r"^\s*configure\s+account\s+(?:all|\S+)\s+password-policy\s+char-validation\s+all-char-groups\b")
            
            # Check for min-length configuration
            min_len_line = self._first(r"^\s*configure\s+account\s+(?:all|\S+)\s+password-policy\s+min-length\s+(\d+)")
            
            if val_lines:
                # Complexity character validation is active
                min_len = 8  # EXOS defaults min-length to 8 if char-validation is enabled
                if min_len_line is not None:
                    match = re.search(r"min-length\s+(\d+)", min_len_line.text)
                    if match:
                        min_len = int(match.group(1))
                
                lines_str = "\n".join(obj.text for obj in val_lines)
                if min_len_line:
                    lines_str += f"\n{min_len_line.text}"

                baseline.password_min_length = Observation[int].found(
                    min_len, lines_str, self._lineno(val_lines[0])
                )
                return

            if min_len_line is not None:
                match = re.search(r"min-length\s+(\d+)", min_len_line.text)
                if match:
                    min_len = int(match.group(1))
                    baseline.password_min_length = Observation[int].found(
                        min_len, min_len_line.text, self._lineno(min_len_line),
                        note="Password policy min-length set without validation."
                    )
                    return

        baseline.password_min_length = Observation[int].absent(
            0, "Password policy/complexity is disabled."
        )
