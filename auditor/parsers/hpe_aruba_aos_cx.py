"""Deterministic HPE Aruba AOS-CX parser.

AOS-CX shares configuration structure elements with Cisco IOS but manages
services like SSH, Telnet, and HTTPS using VRF-based server commands.
It enforces SSHv2 by default, uses a global 'session-timeout' timer, and
configures password complexity in a nested 'password-complexity' block.
"""

import hashlib
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ciscoconfparse2 import CiscoConfParse

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation, Origin
from .base import ParserError, VendorParser, registry

_AOS_CX_MARKERS: Sequence[Tuple[str, float]] = (
    (r"(?im)^\s*ssh server vrf\s+\S+", 0.40),
    (r"(?im)^\s*https-server vrf\s+\S+", 0.40),
    (r"(?im)^\s*telnet server vrf\s+\S+", 0.30),
    (r"(?im)^\s*password-complexity\b", 0.30),
    (r"(?im)^\s*session-timeout\s+\d+", 0.20),
    (r"(?im)^\s*ip dns server-address\b", 0.15),
    (r"(?im)^\s*hostname \S+", 0.10),
    (r"(?im)^\s*snmp-server community\b", 0.10),
)

_NON_AOS_CX_MARKERS: Sequence[Tuple[str, float]] = (
    (r"(?im)^\s*line vty\b", 0.40),
    (r"(?im)^\s*ip http server\s*$", 0.30),
    (r"(?im)^\s*set system host-name\b", 0.90),
    (r"(?im)^\s*system \{", 0.90),
    (r"(?im)^\s*config system global\b", 0.90),
    (r"(?im)^\s*sysname \S+", 0.90),
    (r"(?im)^\s*<\?xml", 0.90),
    (r"(?im)^\s*management ssh\s*$", 0.40),
    (r"(?im)^\s*management api http-commands\s*$", 0.40),
)


@registry.register
class HPEArubaAosCxParser(VendorParser):
    """Grammar-based parser for HPE Aruba AOS-CX configurations."""

    name = "hpe_aruba_aos_cx"
    vendor = "hpe_aruba"
    os_family = "aos_cx"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        score = sum(w for p, w in _AOS_CX_MARKERS if re.search(p, config_text))
        score -= sum(w for p, w in _NON_AOS_CX_MARKERS if re.search(p, config_text))
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
                        "HPE Aruba AOS-CX parser does not evaluate this field."
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
        obj = self._first(r"^\s*hostname\s+(\S+)")
        if obj is not None:
            match = re.match(r"^\s*hostname\s+(\S+)", obj.text)
            if match:
                return Observation[str].found(match.group(1), obj.text, self._lineno(obj))
        return Observation[str].absent(
            "switch", "No 'hostname' configured. The switch defaults to 'switch' hostname."
        )

    def _normalize_ssh(self, baseline: SecurityBaselineModel) -> None:
        ssh_lines = self._find(r"^\s*ssh server vrf\s+\S+")
        if ssh_lines:
            # Reconstruct evidence
            lines_str = "\n".join(obj.text for obj in ssh_lines)
            lineno = self._lineno(ssh_lines[0])
            baseline.ssh_enabled = Observation[bool].found(
                True, lines_str, lineno,
                note="SSH server is explicitly enabled on VRFs."
            )
            # SSH v2 is default on AOS-CX and cannot be changed/disabled in configuration text
            baseline.ssh_version = Observation[int].absent(
                2, "SSH v2 is enforced by default in AOS-CX; no version statement is present in config."
            )
        else:
            baseline.ssh_enabled = Observation[bool].absent(
                False, "No 'ssh server vrf ...' command found. SSH server is disabled by default."
            )
            baseline.ssh_version = Observation[int].absent(
                2, "SSH server is disabled."
            )

        # Restricting management access via allow-list or Control Plane ACL
        allow_list = self._first(r"^\s*ssh server allow-list\s*$")
        acl_control = self._first(r"^\s*apply access-list ip\s+\S+\s+control-plane\b")

        if allow_list is not None and self._has_child(allow_list, r"^\s*enable\s*$") is not None:
            baseline.management_acl_applied = Observation[bool].found(
                True, allow_list.text, self._lineno(allow_list),
                note="SSH allow-list is enabled."
            )
        elif acl_control is not None:
            baseline.management_acl_applied = Observation[bool].found(
                True, acl_control.text, self._lineno(acl_control),
                note=f"Control Plane ACL is applied: {acl_control.text.strip()}"
            )
        else:
            baseline.management_acl_applied = Observation[bool].absent(
                False, "No control plane ACL or SSH allow-list is applied."
            )

    def _normalize_telnet(self, baseline: SecurityBaselineModel) -> None:
        telnet_lines = self._find(r"^\s*telnet server vrf\s+\S+")
        if telnet_lines:
            lines_str = "\n".join(obj.text for obj in telnet_lines)
            lineno = self._lineno(telnet_lines[0])
            baseline.telnet_enabled = Observation[bool].found(
                True, lines_str, lineno,
                note="Telnet server is explicitly enabled on VRFs."
            )
        else:
            baseline.telnet_enabled = Observation[bool].absent(
                False, "No 'telnet server vrf ...' command found. Telnet server is disabled by default."
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
        # HTTP is unsupported on AOS-CX, so always absent (False)
        baseline.http_server_enabled = Observation[bool].absent(
            False, "HTTP management server is not supported or present in AOS-CX configuration."
        )

        https_lines = self._find(r"^\s*https-server vrf\s+\S+")
        if https_lines:
            lines_str = "\n".join(obj.text for obj in https_lines)
            lineno = self._lineno(https_lines[0])
            baseline.https_server_enabled = Observation[bool].found(
                True, lines_str, lineno,
                note="HTTPS server is explicitly enabled on VRFs."
            )
        else:
            baseline.https_server_enabled = Observation[bool].absent(
                False, "No 'https-server vrf ...' command found. HTTPS server is disabled by default."
            )

    def _normalize_session_timeout(self, baseline: SecurityBaselineModel) -> None:
        obj = self._first(r"^\s*session-timeout\s+(\d+)")
        if obj is not None:
            match = re.match(r"^\s*session-timeout\s+(\d+)", obj.text)
            if match:
                minutes = int(match.group(1))
                baseline.vty_exec_timeout_seconds = Observation[int].found(
                    minutes * 60, obj.text, self._lineno(obj),
                    note=f"Idle VTY/Console timeout configured: {minutes} minutes."
                )
                return

        # Default VTY idle timeout is 30 minutes (1800 seconds)
        baseline.vty_exec_timeout_seconds = Observation[int].absent(
            1800, "No 'session-timeout' configured. The switch defaults to a 30-minute idle timeout."
        )

    def _normalize_banner(self, baseline: SecurityBaselineModel) -> None:
        # AOS-CX supports 'banner motd <delim>' and 'banner exec <delim>'
        obj = self._first(r"^\s*banner\s+(motd|exec)\b")
        if obj is not None:
            baseline.login_banner_present = Observation[bool].found(
                True, obj.text, self._lineno(obj),
                note=f"Banner configured: {obj.text.strip()}"
            )
            return

        baseline.login_banner_present = Observation[bool].absent(
            False, "No 'banner motd' or 'banner exec' statements found in the configuration."
        )

    def _normalize_credentials(self, baseline: SecurityBaselineModel) -> None:
        # Local user administration role
        admin_user = self._first(r"^\s*user\s+\S+(?:\s+group\s+administrators)?\s+password\b")
        if admin_user is not None:
            baseline.enable_secret_set = Observation[bool].found(
                True, admin_user.text, self._lineno(admin_user),
                note="Local administrator user with hashed password is configured."
            )
        else:
            baseline.enable_secret_set = Observation[bool].absent(
                False, "No local administrator user password found."
            )

        # AOS-CX doesn't support legacy cleartext enable password
        baseline.enable_password_present = Observation[bool].absent(
            False, "Legacy unencrypted enable password is not supported on AOS-CX."
        )

        # Stored passwords are encrypted by default
        baseline.password_encryption = Observation[bool].absent(
            True, "AOS-CX automatically encrypts/hashes all stored passwords by default."
        )

    def _normalize_aaa(self, baseline: SecurityBaselineModel) -> None:
        obj = self._first(r"^\s*aaa\s+authentication\s+login\b")
        if obj is not None:
            baseline.aaa_enabled = Observation[bool].found(
                True, obj.text, self._lineno(obj),
                note=f"AAA authentication is configured: {obj.text.strip()}"
            )
        else:
            baseline.aaa_enabled = Observation[bool].absent(
                False, "No 'aaa authentication login' statements found."
            )

    def _normalize_snmp(self, baseline: SecurityBaselineModel) -> None:
        communities: List[SnmpCommunity] = []
        lines = self._find(r"^\s*snmp-server\s+community\b")
        for obj in lines:
            match = re.match(r"^\s*snmp-server\s+community\s+(\S+)(?:\s+acl\s+(\S+))?", obj.text)
            if match:
                name = match.group(1)
                acl = match.group(2)
                
                access = "ro"
                rw_child = obj.has_child_with(r"^\s*access-level\s+rw\b")
                if rw_child:
                    access = "rw"

                communities.append(
                    SnmpCommunity(
                        name=name,
                        access=access,
                        acl=acl,
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
            baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
                [], "No SNMP communities are configured. SNMP is disabled by default."
            )

    def _normalize_logging(self, baseline: SecurityBaselineModel) -> None:
        hosts: List[str] = []
        logging_lines = self._find(r"^\s*logging\s+(?!threshold|filter|facility|severity|disable)\S+")
        for obj in logging_lines:
            match = re.match(r"^\s*logging\s+(\S+)", obj.text)
            if match:
                hosts.append(match.group(1))

        baseline.logging_buffered = Observation[bool].absent(
            True, "Local event log buffer is enabled by default in AOS-CX."
        )

        if hosts:
            lines_str = "\n".join(obj.text for obj in logging_lines)
            baseline.logging_enabled = Observation[bool].found(
                True, lines_str, self._lineno(logging_lines[0])
            )
            baseline.logging_hosts = Observation[List[str]].found(
                hosts, lines_str, self._lineno(logging_lines[0])
            )
        else:
            baseline.logging_enabled = Observation[bool].found(
                True, "Local buffer enabled by default", None,
                note="Logging is enabled locally via rotating buffer."
            )
            baseline.logging_hosts = Observation[List[str]].absent(
                [], "No remote syslog host configured."
            )

    def _normalize_ntp(self, baseline: SecurityBaselineModel) -> None:
        ntp_lines = self._find(r"^\s*ntp\s+server\s+\S+")
        ntp_enabled = self._first(r"^\s*ntp\s+enable\b")

        servers: List[str] = []
        for obj in ntp_lines:
            match = re.match(r"^\s*ntp\s+server\s+(\S+)", obj.text)
            if match:
                servers.append(match.group(1))

        if servers and ntp_enabled is not None:
            lines_str = "\n".join(obj.text for obj in ntp_lines) + f"\n{ntp_enabled.text}"
            baseline.ntp_servers = Observation[List[str]].found(
                servers, lines_str, self._lineno(ntp_lines[0])
            )
        elif servers:
            baseline.ntp_servers = Observation[List[str]].absent(
                [], "NTP servers are configured, but NTP is not enabled (missing 'ntp enable')."
            )
        else:
            baseline.ntp_servers = Observation[List[str]].absent(
                [], "No NTP servers configured."
            )

    def _normalize_dns(self, baseline: SecurityBaselineModel) -> None:
        dns_lines = self._find(r"^\s*ip\s+dns\s+server-address\s+\S+")
        servers: List[str] = []
        for obj in dns_lines:
            match = re.match(r"^\s*ip\s+dns\s+server-address\s+(\S+)", obj.text)
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
        pwd_block = self._first(r"^\s*password-complexity\s*$")
        if pwd_block is not None and self._has_child(pwd_block, r"^\s*enable\s*$") is not None:
            min_len = 8
            len_child = self._has_child(pwd_block, r"^\s*min-length\s+(\d+)")
            if len_child is not None:
                match = re.search(r"min-length\s+(\d+)", len_child.text)
                if match:
                    min_len = int(match.group(1))
            baseline.password_min_length = Observation[int].found(
                min_len, pwd_block.text + f"\n{len_child.text if len_child is not None else ''}", self._lineno(pwd_block)
            )
        else:
            baseline.password_min_length = Observation[int].absent(
                0, "Password complexity is disabled."
            )
