"""Deterministic Huawei VRP parser.

Huawei VRP (Versatile Routing Platform) uses a space-indented configuration structure
similar to Cisco IOS, but employs different command keywords (e.g. `sysname`,
`stelnet`, `info-center`, `ntp-service`).
"""

import hashlib
import re
from typing import Dict, List, Optional, Sequence, Tuple

from ciscoconfparse2 import CiscoConfParse

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation, Origin
from .base import ParserError, VendorParser, registry

_VRP_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*sysname\s+\S+", 0.25),
    (r"(?im)^\s*stelnet\s+server\s+enable\b", 0.35),
    (r"(?im)^\s*info-center\s+loghost\b", 0.20),
    (r"(?im)^\s*ntp-service\s+(?:unicast-server|server)\b", 0.15),
    (r"(?im)^\s*!Software\s+Version\s+\S+", 0.15),
    (r"(?im)^\s*user-interface\s+vty\b", 0.10),
    (r"(?im)^\s*firewall\s+defend\s+\w+\s+enable\b", 0.15),
    (r"(?im)^;REGION\b", 0.10),
]

_NON_VRP_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*line vty\b", 0.40),
    (r"(?im)^\s*ip http server\s*$", 0.30),
    (r"(?im)^\s*set system host-name\b", 0.90),
    (r"(?im)^\s*system \{", 0.90),
    (r"(?im)^\s*config system global\b", 0.90),
    (r"(?im)^\s*ASA Version\b", 0.80),
    (r"(?im)^\s*<\?xml", 0.90),
]


@registry.register
class HuaweiVRPParser(VendorParser):
    """Grammar-based parser for Huawei VRP configurations."""

    name = "huawei_vrp"
    vendor = "huawei"
    os_family = "vrp"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        score = sum(w for p, w in _VRP_MARKERS if re.search(p, config_text))
        score -= sum(w for p, w in _NON_VRP_MARKERS if re.search(p, config_text))
        return max(0.0, min(1.0, score))

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if config_text is None or not config_text.strip():
            raise ParserError("Configuration is empty.")

        raw_lines = config_text.splitlines()
        self._warnings: List[str] = []
        try:
            self._parse = CiscoConfParse(config=raw_lines, syntax="ios")
        except Exception as exc:
            raise ParserError(f"Could not parse VRP configuration: {exc}") from exc

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
        self._normalize_management(baseline)
        self._normalize_banner(baseline)
        self._normalize_credentials(baseline)
        self._normalize_snmp(baseline)
        self._normalize_logging(baseline)
        self._normalize_ntp(baseline)

        # Fill all non-evaluated baseline fields as unknown
        for field in baseline.observable_fields():
            observation = getattr(baseline, field)
            if observation.note == "Parser did not evaluate this field.":
                setattr(
                    baseline,
                    field,
                    type(observation).unknown(
                        "Huawei VRP parser does not evaluate this field."
                    )
                )

        baseline.provenance.warnings = self._warnings
        return baseline

    @staticmethod
    def _lineno(obj) -> int:
        return obj.linenum + 1

    def _find(self, pattern: str) -> List:
        return list(self._parse.find_objects(pattern))

    def _first(self, pattern: str):
        found = self._find(pattern)
        return found[0] if found else None

    def _warn(self, message: str) -> None:
        if message not in self._warnings:
            self._warnings.append(message)

    # -- hostname ----------------------------------------------------------

    def _hostname(self) -> Observation[str]:
        obj = self._first(r"(?i)^\s*sysname\s+\S+")
        if obj is None:
            return Observation[str].unknown("No 'sysname' statement found.")
        # e.g., "sysname BRANCH-SW-03"
        match = re.match(r"(?i)^\s*sysname\s+(\S+)", obj.text)
        if match:
            return Observation[str].found(match.group(1), obj.text, self._lineno(obj))
        return Observation[str].unknown("Malformed 'sysname' statement.")

    # -- management (SSH / Telnet / HTTP / VTY / ACL) -----------------------

    def _normalize_management(self, baseline: SecurityBaselineModel) -> None:
        # Check telnet server status
        telnet_enable_obj = self._first(r"(?i)^\s*telnet\s+server\s+enable\b")
        telnet_undo_obj = self._first(r"(?i)^\s*undo\s+telnet\s+server\s+enable\b")

        # Check ssh server status (stelnet in VRP)
        stelnet_enable_obj = self._first(r"(?i)^\s*stelnet\s+server\s+enable\b")
        stelnet_undo_obj = self._first(r"(?i)^\s*undo\s+stelnet\s+server\s+enable\b")

        vty_blocks = self._find(r"(?i)^\s*user-interface\s+vty\b")

        # HTTP/HTTPS server status
        http_enable = self._first(r"(?i)^\s*http\s+server\s+enable\b")
        https_enable = self._first(r"(?i)^\s*http\s+secure-server\s+enable\b")

        baseline.http_server_enabled = Observation[bool].found(
            True if http_enable else False,
            http_enable.text if http_enable else "http server enable",
            self._lineno(http_enable) if http_enable else None,
            note="HTTP server status."
        )
        baseline.https_server_enabled = Observation[bool].found(
            True if https_enable else False,
            https_enable.text if https_enable else "http secure-server enable",
            self._lineno(https_enable) if https_enable else None,
            note="HTTPS server status."
        )

        if not vty_blocks:
            # Conclusive absence of vty settings means SSH/Telnet access is not defined in config
            baseline.telnet_enabled = Observation[bool].unknown("No user-interface vty blocks found.")
            baseline.ssh_enabled = Observation[bool].unknown("No user-interface vty blocks found.")
            baseline.vty_transport_input = Observation[List[str]].unknown("No user-interface vty blocks found.")
            baseline.vty_exec_timeout_seconds = Observation[int].unknown("No user-interface vty blocks found.")
            baseline.management_acl_applied = Observation[bool].unknown("No user-interface vty blocks found.")
            return

        # Let's inspect SSH and Telnet
        # SSH (stelnet)
        if stelnet_undo_obj:
            baseline.ssh_enabled = Observation[bool].found(False, stelnet_undo_obj.text, self._lineno(stelnet_undo_obj))
        elif stelnet_enable_obj:
            baseline.ssh_enabled = Observation[bool].found(True, stelnet_enable_obj.text, self._lineno(stelnet_enable_obj))
        else:
            # Default state: disabled
            baseline.ssh_enabled = Observation[bool].absent(False, "Stelnet (SSH) server is not explicitly enabled.")

        # Telnet
        if telnet_undo_obj:
            baseline.telnet_enabled = Observation[bool].found(False, telnet_undo_obj.text, self._lineno(telnet_undo_obj))
        elif telnet_enable_obj:
            baseline.telnet_enabled = Observation[bool].found(True, telnet_enable_obj.text, self._lineno(telnet_enable_obj))
        else:
            # Default state: disabled on modern VRP
            baseline.telnet_enabled = Observation[bool].absent(False, "Telnet server is not explicitly enabled.")

        # Protocols and Timeouts across VTY blocks
        vty_transports = set()
        vty_timeouts = []
        blocks_without_timeout = 0
        blocks_without_acl = 0
        acls = []

        for block in vty_blocks:
            protocol_line = None
            timeout_line = None
            acl_line = None

            for child in block.children:
                if re.match(r"(?i)^\s*protocol\s+inbound\b", child.text):
                    protocol_line = child
                elif re.match(r"(?i)^\s*idle-timeout\b", child.text):
                    timeout_line = child
                elif re.match(r"(?i)^\s*acl\s+\S+\s+inbound\b", child.text):
                    acl_line = child

            # Protocol inbound
            if protocol_line:
                # e.g., "protocol inbound ssh" or "protocol inbound stelnet" or "protocol inbound all"
                tokens = protocol_line.text.lower().split()[2:]
                for t in tokens:
                    if t in ("ssh", "stelnet"):
                        vty_transports.add("ssh")
                    elif t == "telnet":
                        vty_transports.add("telnet")
                    elif t == "all":
                        vty_transports.update({"ssh", "telnet"})
            else:
                # If unspecified, default inbound protocols include both telnet and ssh (or all)
                vty_transports.update({"ssh", "telnet"})

            # Idle timeout
            if timeout_line:
                match = re.match(r"(?i)^\s*idle-timeout\s+(\d+)(?:\s+(\d+))?", timeout_line.text)
                if match:
                    mins = int(match.group(1))
                    secs = int(match.group(2) or 0)
                    vty_timeouts.append((mins * 60 + secs, timeout_line.text, self._lineno(timeout_line)))
            else:
                blocks_without_timeout += 1

            # ACL inbound
            if acl_line:
                acls.append((acl_line.text, self._lineno(acl_line)))
            else:
                blocks_without_acl += 1

        # Resolve transport inputs
        # If the stelnet/telnet server daemon is disabled, that overrides the VTY inbound protocols
        actual_transports = []
        if baseline.ssh_enabled.value and "ssh" in vty_transports:
            actual_transports.append("ssh")
        if baseline.telnet_enabled.value and "telnet" in vty_transports:
            actual_transports.append("telnet")

        # Let's assign vty_transport_input based on active daemons and VTY configs
        vty_line_evidence = vty_blocks[0]
        baseline.vty_transport_input = Observation[List[str]].found(
            sorted(actual_transports),
            vty_line_evidence.text,
            self._lineno(vty_line_evidence),
            note="Active protocols allowed across configured VTY lines."
        )

        # If VTY allows telnet but server is disabled globally, the effective state is disabled.
        # But if the telnet daemon is enabled, and at least one VTY allows telnet, telnet_enabled is True.
        if "telnet" in actual_transports:
            baseline.telnet_enabled = Observation[bool].found(
                True,
                vty_line_evidence.text,
                self._lineno(vty_line_evidence),
                note="Telnet daemon is enabled and permitted on VTY lines."
            )

        # Resolve timeouts
        if blocks_without_timeout > 0:
            baseline.vty_exec_timeout_seconds = Observation[int].unknown(
                "One or more user-interface VTY blocks are missing an explicit idle-timeout configuration."
            )
        elif vty_timeouts:
            # worst case is the maximum (longest) timeout, 0 is infinite (worst)
            has_infinite = any(t[0] == 0 for t in vty_timeouts)
            if has_infinite:
                worst_t = next(t for t in vty_timeouts if t[0] == 0)
                baseline.vty_exec_timeout_seconds = Observation[int].found(
                    0, worst_t[1], worst_t[2], note="Worst-case (infinite) VTY session timeout."
                )
            else:
                worst_t = max(vty_timeouts, key=lambda t: t[0])
                baseline.vty_exec_timeout_seconds = Observation[int].found(
                    worst_t[0], worst_t[1], worst_t[2], note="Worst-case VTY session timeout in seconds."
                )
        else:
            baseline.vty_exec_timeout_seconds = Observation[int].unknown("No VTY session timeouts configured.")

        # Resolve ACLs
        if blocks_without_acl > 0:
            baseline.management_acl_applied = Observation[bool].absent(
                False, "No ACL applied inbound to restrict VTY access on one or more VTY blocks."
            )
        elif acls:
            acl_text, acl_line_num = acls[0]
            baseline.management_acl_applied = Observation[bool].found(
                True, acl_text, acl_line_num, note="All VTY lines have inbound ACLs configured."
            )
        else:
            baseline.management_acl_applied = Observation[bool].absent(
                False, "No inbound VTY access restriction ACL found."
            )

        # SSH Version: Check for compatible-ssh1x disable or similar
        ssh_compat_obj = self._first(r"(?i)^\s*ssh\s+server\s+compatible-ssh1x\s+disable\b")
        ssh_version_obj = self._first(r"(?i)^\s*ssh\s+server\s+version\s+(\d+)\b")
        if ssh_version_obj:
            match = re.search(r"\bversion\s+(\d+)\b", ssh_version_obj.text, re.IGNORECASE)
            version_val = int(match.group(1)) if match else 2
            baseline.ssh_version = Observation[int].found(
                version_val, ssh_version_obj.text, self._lineno(ssh_version_obj)
            )
        elif ssh_compat_obj:
            baseline.ssh_version = Observation[int].found(
                2, ssh_compat_obj.text, self._lineno(ssh_compat_obj),
                note="SSH v1 compatibility is explicitly disabled."
            )
        else:
            # VRP default is version-dependent, we don't assume.
            baseline.ssh_version = Observation[int].unknown("SSH version is not explicitly defined in config.")

    # -- banner ------------------------------------------------------------

    def _normalize_banner(self, baseline: SecurityBaselineModel) -> None:
        login_banner = self._first(r"(?i)^\s*header\s+login\b")
        shell_banner = self._first(r"(?i)^\s*header\s+shell\b")

        if login_banner:
            baseline.login_banner_present = Observation[bool].found(
                True, login_banner.text, self._lineno(login_banner)
            )
            baseline.pre_login_banner_present = Observation[bool].found(
                True, login_banner.text, self._lineno(login_banner)
            )
        else:
            baseline.login_banner_present = Observation[bool].absent(
                False, "No login header (login banner) configured."
            )
            baseline.pre_login_banner_present = Observation[bool].absent(
                False, "No login header (login banner) configured."
            )

        if shell_banner:
            baseline.post_login_banner_present = Observation[bool].found(
                True, shell_banner.text, self._lineno(shell_banner)
            )
        else:
            baseline.post_login_banner_present = Observation[bool].absent(
                False, "No shell header (post-login banner) configured."
            )

    # -- credentials (AAA / Enable secret) ----------------------------------

    def _normalize_credentials(self, baseline: SecurityBaselineModel) -> None:
        aaa_block = self._first(r"(?i)^\s*aaa\s*$")
        vty_blocks = self._find(r"(?i)^\s*user-interface\s+vty\b")

        # Check if AAA is enabled and applied to VTY lines
        vty_aaa_applied = False
        vty_aaa_line = None
        for block in vty_blocks:
            for child in block.children:
                if re.match(r"(?i)^\s*authentication-mode\s+aaa\b", child.text):
                    vty_aaa_applied = True
                    vty_aaa_line = child
                    break

        if aaa_block and vty_aaa_applied:
            baseline.aaa_enabled = Observation[bool].found(
                True, vty_aaa_line.text, self._lineno(vty_aaa_line),
                note="AAA is configured and applied to VTY interfaces."
            )
        else:
            baseline.aaa_enabled = Observation[bool].absent(
                False, "AAA is not configured or not applied to VTY interfaces."
            )

        # Super password (enable secret equivalent in VRP)
        super_pw = self._first(r"(?i)^\s*super\s+password\b")
        if super_pw:
            # If it uses irreversible-cipher, it's hashed securely (enable secret)
            is_hashed = "irreversible-cipher" in super_pw.text.lower()
            baseline.enable_secret_set = Observation[bool].found(
                is_hashed, super_pw.text, self._lineno(super_pw)
            )
            baseline.enable_password_present = Observation[bool].found(
                not is_hashed, super_pw.text, self._lineno(super_pw)
            )
        else:
            baseline.enable_secret_set = Observation[bool].absent(False, "No 'super password' configured.")
            baseline.enable_password_present = Observation[bool].absent(False, "No 'super password' configured.")

        # Password encryption checking
        # In VRP, passwords are encrypted when using "cipher" or "irreversible-cipher".
        # If any user or super password uses "simple" (plaintext), then encryption is False.
        # Find all occurrences of password keyword in local-user or super password settings
        all_pws = self._find(r"(?i)password\s+")
        has_plain = False
        plain_line = None
        has_secure = False

        for p in all_pws:
            text = p.text.lower()
            if "simple" in text:
                has_plain = True
                plain_line = p
            elif "cipher" in text or "irreversible-cipher" in text:
                has_secure = True

        if has_plain:
            baseline.password_encryption = Observation[bool].found(
                False, plain_line.text, self._lineno(plain_line),
                note="Plaintext password setting was found in configuration."
            )
        elif has_secure:
            baseline.password_encryption = Observation[bool].found(
                True, all_pws[0].text, self._lineno(all_pws[0]),
                note="All passwords configured are ciphered/hashed."
            )
        else:
            baseline.password_encryption = Observation[bool].absent(
                False, "No passwords configured to verify encryption status."
            )

    # -- SNMP communities --------------------------------------------------

    def _normalize_snmp(self, baseline: SecurityBaselineModel) -> None:
        snmp_agent = self._first(r"(?i)^\s*snmp-agent\b")
        if not snmp_agent:
            baseline.snmp_agent_enabled = Observation[bool].absent(False, "SNMP agent is not enabled.")
            baseline.snmp_communities = Observation[List[SnmpCommunity]].absent([], "No SNMP communities are configured.")
            return

        baseline.snmp_agent_enabled = Observation[bool].found(True, snmp_agent.text, self._lineno(snmp_agent))

        community_lines = self._find(r"(?i)^\s*snmp-agent\s+community\b")
        communities = []
        for line in community_lines:
            match = re.match(
                r"(?i)^\s*snmp-agent\s+community\s+(read|write)\s+(?:cipher\s+|simple\s+)?(\S+)(?:\s+acl\s+(\S+))?",
                line.text
            )
            if match:
                access = match.group(1).lower()
                name = match.group(2)
                acl = match.group(3)
                communities.append(
                    SnmpCommunity(
                        name=name,
                        access="ro" if access == "read" else "rw",
                        acl=acl,
                        source_line=line.text,
                        line_number=self._lineno(line)
                    )
                )

        if communities:
            baseline.snmp_communities = Observation[List[SnmpCommunity]].found(
                communities, community_lines[0].text, self._lineno(community_lines[0])
            )
        else:
            baseline.snmp_communities = Observation[List[SnmpCommunity]].absent([], "No SNMP communities found.")

    # -- syslog logging ----------------------------------------------------

    def _normalize_logging(self, baseline: SecurityBaselineModel) -> None:
        info_center = self._first(r"(?i)^\s*info-center\s+enable\b")
        loghosts = self._find(r"(?i)^\s*info-center\s+loghost\b")

        hosts = []
        for lh in loghosts:
            match = re.match(r"(?i)^\s*info-center\s+loghost\s+(\S+)", lh.text)
            if match:
                hosts.append(match.group(1))

        if info_center and hosts:
            baseline.logging_enabled = Observation[bool].found(
                True, info_center.text, self._lineno(info_center)
            )
            baseline.logging_hosts = Observation[List[str]].found(
                hosts, loghosts[0].text, self._lineno(loghosts[0])
            )
        else:
            baseline.logging_enabled = Observation[bool].absent(
                False, "Logging center is disabled or no loghosts are configured."
            )
            baseline.logging_hosts = Observation[List[str]].absent([], "No logging hosts are configured.")

    # -- ntp servers -------------------------------------------------------

    def _normalize_ntp(self, baseline: SecurityBaselineModel) -> None:
        ntp_lines = self._find(r"(?i)^\s*ntp-service\s+(?:unicast-server|server)\b")
        servers = []
        for line in ntp_lines:
            match = re.match(r"(?i)^\s*ntp-service\s+(?:unicast-server|server)\s+(\S+)", line.text)
            if match:
                servers.append(match.group(1))

        if servers:
            baseline.ntp_servers = Observation[List[str]].found(
                servers, ntp_lines[0].text, self._lineno(ntp_lines[0])
            )
        else:
            baseline.ntp_servers = Observation[List[str]].absent([], "No NTP servers configured.")
