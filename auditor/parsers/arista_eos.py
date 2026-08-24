"""Deterministic Arista EOS parser.

Arista EOS shares its CLI heritage with Cisco IOS but diverges in how
management access is organised.  The ``management ssh`` / ``management
telnet`` / ``management api http-commands`` block structure replaces
IOS's ``line vty`` + ``ip http server`` model.

Detection relies on EOS-specific constructs: ``management ssh`` and
``management api http-commands`` blocks, the ``! device:`` comment
header, and ``vrf instance``.

Normalization policy
--------------------
CONCLUSIVE ABSENCE -- the command is off by default and always written
    when configured.
        management telnet (default shutdown)
        management api http-commands (default shutdown)
        snmp-server community / logging host / ntp server / banner
        enable secret / enable password / service password-encryption

AMBIGUOUS ABSENCE -- the effective value comes from a platform default
    that varies by EOS release.
        management ssh block absent (SSH on by default but settings unknown)
        idle-timeout absent (default varies by release)
        SSH protocol version (EOS 4.x enforces v2 but the config does not
        state it; older releases may differ)
"""

import hashlib
import re
from typing import Dict, List, Optional, Sequence, Tuple

from ciscoconfparse2 import CiscoConfParse

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry

_LOGGING_NON_HOST_KEYWORDS = (
    "on|buffered|trap|console|monitor|facility|source-interface|"
    "synchronous|enable|level|event|policy|vrf|format"
)

_EOS_MARKERS: Sequence[Tuple[str, float]] = (
    (r"(?im)^\s*!\s*device:\s*\S+", 0.40),
    (r"(?im)^\s*management ssh\s*$", 0.25),
    (r"(?im)^\s*management api http-commands\s*$", 0.25),
    (r"(?im)^\s*management telnet\s*$", 0.15),
    (r"(?im)^\s*management console\s*$", 0.10),
    (r"(?im)^\s*vrf instance\s+\S+", 0.15),
    (r"(?im)^\s*hostname \S+", 0.10),
    (r"(?im)^\s*daemon \S+", 0.10),
    (r"(?im)^\s*enable secret\b", 0.05),
    (r"(?im)^\s*snmp-server\b", 0.05),
    # EOS (and NX-OS) carry interface addresses in prefix-length form; an IOS
    # running-config always expands them to a dotted mask. This is the strongest
    # "not classic IOS" signal that also fires on minimal routed EOS configs that
    # lack any management-plane marker -- exactly the ones that used to be lost to
    # the IOS parser (both share hostname/interface/router-bgp syntax).
    (r"(?im)^\s*ip address \d+\.\d+\.\d+\.\d+/\d+", 0.35),
    # Bare "Ethernet<n>" naming is EOS; IOS uses GigabitEthernet/FastEthernet or
    # the slash-bearing Ethernet0/0 of older platforms.
    (r"(?im)^\s*interface Ethernet\d+\s*$", 0.15),
)

_NON_EOS_MARKERS: Sequence[Tuple[str, float]] = (
    (r"(?im)^\s*line vty\b", 0.40),
    (r"(?im)^\s*ip http server\s*$", 0.30),
    (r"(?im)^\s*set system host-name\b", 0.90),
    (r"(?im)^\s*system \{", 0.90),
    (r"(?im)^\s*config system global\b", 0.90),
    (r"(?im)^\s*sysname \S+", 0.90),
    (r"(?im)^\s*ASA Version\b", 0.80),
    (r"(?im)^\s*<\?xml", 0.90),
)


@registry.register
class AristaEOSParser(VendorParser):
    """Grammar-based parser for Arista EOS running-configs."""

    name = "arista_eos"
    vendor = "arista"
    os_family = "eos"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        score = sum(w for p, w in _EOS_MARKERS if re.search(p, config_text))
        score -= sum(w for p, w in _NON_EOS_MARKERS if re.search(p, config_text))
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
        self._normalize_management_ssh(baseline)
        self._normalize_management_telnet(baseline)
        self._derive_vty_transport(baseline)
        self._normalize_management_api(baseline)
        self._normalize_idle_timeout(baseline)
        self._normalize_banner(baseline)
        self._normalize_credentials(baseline)
        self._normalize_aaa(baseline)
        self._normalize_snmp(baseline)
        self._normalize_logging(baseline)
        self._normalize_ntp(baseline)

        baseline.provenance.warnings = self._warnings
        return baseline

    # -- helpers -----------------------------------------------------------

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

    @staticmethod
    def _has_child(block, pattern: str) -> Optional[object]:
        for child in block.children:
            if re.match(pattern, child.text, re.IGNORECASE):
                return child
        return None

    @staticmethod
    def _block_shutdown(block) -> Optional[bool]:
        """Return True if the block has 'shutdown', False if 'no shutdown', None if unstated."""
        for child in block.children:
            stripped = child.text.strip().lower()
            if stripped == "no shutdown":
                return False
            if stripped == "shutdown":
                return True
        return None

    # -- hostname ----------------------------------------------------------

    def _hostname(self) -> Observation[str]:
        obj = self._first(r"(?i)^\s*hostname\s+\S+")
        if obj is None:
            return Observation[str].unknown("No 'hostname' statement found.")
        return Observation[str].found(obj.text.split()[1], obj.text, self._lineno(obj))

    # -- management ssh ----------------------------------------------------

    def _normalize_management_ssh(self, baseline: SecurityBaselineModel) -> None:
        blocks = self._find(r"(?i)^\s*management ssh\s*$")
        if not blocks:
            note = (
                "No 'management ssh' block found. EOS enables SSH by default, "
                "but the exact configuration cannot be determined from this excerpt."
            )
            self._warn(note)
            baseline.ssh_enabled = Observation[bool].unknown(note)
            baseline.ssh_version = Observation[int].unknown(note)
            baseline.management_acl_applied = Observation[bool].unknown(
                "No 'management ssh' block found; management ACL state cannot be determined."
            )
            return

        block = blocks[0]
        is_shutdown = self._block_shutdown(block)

        if is_shutdown is True:
            baseline.ssh_enabled = Observation[bool].found(
                False, block.text, self._lineno(block),
                note="SSH is explicitly disabled with 'shutdown' under 'management ssh'.",
            )
        else:
            baseline.ssh_enabled = Observation[bool].found(
                True, block.text, self._lineno(block),
                note="SSH is enabled under 'management ssh'.",
            )

        note = (
            "EOS does not expose the SSH protocol version in the configuration text. "
            "Modern EOS releases (4.x) enforce SSHv2 exclusively, but this cannot be "
            "confirmed from the running-config alone."
        )
        self._warn(note)
        baseline.ssh_version = Observation[int].unknown(note)

        acl_child = self._has_child(block, r"(?i)^\s*ip access-group\s+\S+\s+in\b")
        if acl_child is not None:
            baseline.management_acl_applied = Observation[bool].found(
                True, acl_child.text, self._lineno(acl_child),
                note="An inbound ACL is applied to SSH management access.",
            )
        else:
            baseline.management_acl_applied = Observation[bool].absent(
                False,
                "No 'ip access-group ... in' under 'management ssh'. EOS writes this "
                "statement when an ACL is applied, so its absence means SSH management "
                "is reachable from any source address.",
            )

    # -- management telnet -------------------------------------------------

    def _normalize_management_telnet(self, baseline: SecurityBaselineModel) -> None:
        blocks = self._find(r"(?i)^\s*management telnet\s*$")
        if not blocks:
            baseline.telnet_enabled = Observation[bool].unknown(
                "No 'management telnet' block found. EOS disables telnet by default, "
                "but the state cannot be confirmed from this excerpt."
            )
            return

        block = blocks[0]
        is_shutdown = self._block_shutdown(block)

        if is_shutdown is False:
            baseline.telnet_enabled = Observation[bool].found(
                True, block.text, self._lineno(block),
                note="Telnet is enabled with 'no shutdown' under 'management telnet'.",
            )
        else:
            baseline.telnet_enabled = Observation[bool].found(
                False, block.text, self._lineno(block),
                note="Telnet is disabled under 'management telnet' (default or explicit shutdown).",
            )

    # -- VTY transport (derived) -------------------------------------------

    def _derive_vty_transport(self, baseline: SecurityBaselineModel) -> None:
        transports: List[str] = []
        evidence_line = None
        evidence_lineno = None

        if baseline.ssh_enabled.detected and baseline.ssh_enabled.value:
            transports.append("ssh")
            evidence_line = baseline.ssh_enabled.source_line
            evidence_lineno = baseline.ssh_enabled.line_number
        if baseline.telnet_enabled.detected and baseline.telnet_enabled.value:
            transports.append("telnet")
            if not evidence_line:
                evidence_line = baseline.telnet_enabled.source_line
                evidence_lineno = baseline.telnet_enabled.line_number

        if not baseline.ssh_enabled.detected or not baseline.telnet_enabled.detected:
            baseline.vty_transport_input = Observation[List[str]].unknown(
                "Cannot determine full management transport list because SSH or telnet "
                "configuration is incomplete."
            )
            return

        if evidence_line:
            baseline.vty_transport_input = Observation[List[str]].found(
                sorted(transports), evidence_line or "", evidence_lineno,
            )
        else:
            baseline.vty_transport_input = Observation[List[str]].absent(
                [], "No management transport is enabled.",
            )

    # -- management api http-commands --------------------------------------

    def _normalize_management_api(self, baseline: SecurityBaselineModel) -> None:
        blocks = self._find(r"(?i)^\s*management api http-commands\s*$")
        if not blocks:
            baseline.http_server_enabled = Observation[bool].absent(
                False,
                "No 'management api http-commands' block present. EOS does not serve the "
                "HTTP/HTTPS management API unless configured, so absence means disabled.",
            )
            baseline.https_server_enabled = Observation[bool].absent(
                False,
                "No 'management api http-commands' block present. EOS does not serve the "
                "HTTP/HTTPS management API unless configured, so absence means disabled.",
            )
            return

        block = blocks[0]
        is_shutdown = self._block_shutdown(block)

        if is_shutdown is True:
            baseline.http_server_enabled = Observation[bool].found(
                False, block.text, self._lineno(block),
                note="The management API is disabled ('shutdown').",
            )
            baseline.https_server_enabled = Observation[bool].found(
                False, block.text, self._lineno(block),
                note="The management API is disabled ('shutdown').",
            )
            return

        no_http = self._has_child(block, r"(?i)^\s*no protocol http\s*$")
        yes_http = self._has_child(block, r"(?i)^\s*protocol http\s*$")
        no_https = self._has_child(block, r"(?i)^\s*no protocol https\s*$")
        yes_https = self._has_child(block, r"(?i)^\s*protocol https\s*$")

        if no_http:
            baseline.http_server_enabled = Observation[bool].found(
                False, no_http.text, self._lineno(no_http),
                note="HTTP protocol explicitly disabled under management API.",
            )
        elif yes_http:
            baseline.http_server_enabled = Observation[bool].found(
                True, yes_http.text, self._lineno(yes_http),
                note="HTTP protocol explicitly enabled under management API.",
            )
        else:
            baseline.http_server_enabled = Observation[bool].unknown(
                "The management API is enabled but no explicit 'protocol http' or "
                "'no protocol http' statement is present; the default varies by EOS release."
            )

        if no_https:
            baseline.https_server_enabled = Observation[bool].found(
                False, no_https.text, self._lineno(no_https),
                note="HTTPS protocol explicitly disabled under management API.",
            )
        elif yes_https:
            baseline.https_server_enabled = Observation[bool].found(
                True, yes_https.text, self._lineno(yes_https),
                note="HTTPS protocol explicitly enabled under management API.",
            )
        else:
            baseline.https_server_enabled = Observation[bool].unknown(
                "The management API is enabled but no explicit 'protocol https' or "
                "'no protocol https' statement is present; the default varies by EOS release."
            )

    # -- idle timeout ------------------------------------------------------

    def _normalize_idle_timeout(self, baseline: SecurityBaselineModel) -> None:
        timeouts: List[Tuple[int, str, int]] = []

        for block_pattern in (r"(?i)^\s*management ssh\s*$", r"(?i)^\s*management console\s*$"):
            for block in self._find(block_pattern):
                child = self._has_child(block, r"(?i)^\s*idle-timeout\s+\d+")
                if child:
                    match = re.search(r"(\d+)", child.text)
                    if match:
                        minutes = int(match.group(1))
                        timeouts.append((minutes * 60, child.text, self._lineno(child)))

        if not timeouts:
            note = (
                "No 'idle-timeout' found under 'management ssh' or 'management console'. "
                "The effective idle timeout is a platform default and cannot be determined "
                "from the configuration text."
            )
            self._warn(note)
            baseline.vty_exec_timeout_seconds = Observation[int].unknown(note)
            return

        never = [t for t in timeouts if t[0] == 0]
        if never:
            seconds, line, lineno = never[0]
            baseline.vty_exec_timeout_seconds = Observation[int].found(
                0, line, lineno,
                note="'idle-timeout 0' disables the idle timeout entirely.",
            )
            return

        seconds, line, lineno = max(timeouts, key=lambda t: t[0])
        baseline.vty_exec_timeout_seconds = Observation[int].found(
            seconds, line, lineno,
            note="Longest idle timeout configured across management sessions.",
        )

    # -- banner ------------------------------------------------------------

    def _normalize_banner(self, baseline: SecurityBaselineModel) -> None:
        obj = self._first(r"(?i)^\s*banner\s+(login|motd)\b")
        if obj is not None:
            baseline.login_banner_present = Observation[bool].found(
                True, obj.text, self._lineno(obj),
            )
            return
        baseline.login_banner_present = Observation[bool].absent(
            False,
            "No 'banner login' or 'banner motd' statement present. EOS writes "
            "banner configuration to the running-config, so absence means no "
            "banner is shown.",
        )

    # -- credentials -------------------------------------------------------

    def _normalize_credentials(self, baseline: SecurityBaselineModel) -> None:
        secret = self._first(r"(?i)^\s*enable secret\b")
        if secret is not None:
            baseline.enable_secret_set = Observation[bool].found(
                True, secret.text, self._lineno(secret),
            )
        else:
            baseline.enable_secret_set = Observation[bool].absent(
                False,
                "No 'enable secret' statement present. EOS writes this command to "
                "the running-config when configured, so its absence means no "
                "enable secret is set.",
            )

        legacy = self._first(r"(?i)^\s*enable password\b")
        if legacy is not None:
            baseline.enable_password_present = Observation[bool].found(
                True, legacy.text, self._lineno(legacy),
                note="Legacy 'enable password' in use.",
            )
        else:
            baseline.enable_password_present = Observation[bool].absent(
                False, "No 'enable password' statement present.",
            )

        encryption = self._first(r"(?i)^\s*(no\s+)?service password-encryption\s*$")
        if encryption is not None:
            enabled = not encryption.text.strip().lower().startswith("no ")
            baseline.password_encryption = Observation[bool].found(
                enabled, encryption.text, self._lineno(encryption),
            )
        else:
            baseline.password_encryption = Observation[bool].absent(
                False,
                "No 'service password-encryption' statement present. The feature is "
                "disabled by default and is written to the running-config when enabled, "
                "so absence means disabled.",
            )

        min_len = self._first(r"(?i)^\s*security password minimum-length\s+\d+")
        if min_len is not None:
            baseline.password_min_length = Observation[int].found(
                int(re.search(r"(\d+)\s*$", min_len.text).group(1)),
                min_len.text,
                self._lineno(min_len),
            )
        else:
            baseline.password_min_length = Observation[int].absent(
                0,
                "No 'security password minimum-length' statement present. EOS enforces "
                "no minimum password length unless this is configured.",
            )

    # -- AAA ---------------------------------------------------------------

    def _normalize_aaa(self, baseline: SecurityBaselineModel) -> None:
        obj = self._first(r"(?i)^\s*aaa authentication\b")
        if obj is not None:
            baseline.aaa_enabled = Observation[bool].found(
                True, obj.text, self._lineno(obj),
                note="AAA authentication is configured.",
            )
            return

        baseline.aaa_enabled = Observation[bool].absent(
            False,
            "No 'aaa authentication' statement present. EOS writes AAA configuration "
            "to the running-config when configured, so its absence means AAA is not enabled.",
        )

    # -- SNMP --------------------------------------------------------------

    def _normalize_snmp(self, baseline: SecurityBaselineModel) -> None:
        community_objs = self._find(r"(?i)^\s*snmp-server community\b")
        if community_objs:
            communities = [self._parse_community(obj) for obj in community_objs]
            first = community_objs[0]
            baseline.snmp_communities = Observation[List[SnmpCommunity]].found(
                communities, first.text, self._lineno(first),
                note=f"{len(communities)} SNMP v1/v2c community string(s) configured.",
            )
            return

        if self._find(r"(?i)^\s*snmp-server\b"):
            baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
                [],
                "SNMP is configured but no 'snmp-server community' statements are present "
                "(consistent with an SNMPv3-only deployment).",
            )
            return

        baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
            [],
            "No 'snmp-server' configuration present. EOS writes SNMP configuration to "
            "the running-config, so absence means no community strings are defined.",
        )

    def _parse_community(self, obj) -> SnmpCommunity:
        tokens = obj.text.split()[2:]
        name = tokens[0] if tokens else ""
        access: Optional[str] = None
        acl: Optional[str] = None
        view: Optional[str] = None

        index = 1
        while index < len(tokens):
            token = tokens[index]
            lowered = token.lower()
            if lowered == "view" and index + 1 < len(tokens):
                view = tokens[index + 1]
                index += 2
                continue
            if lowered in ("ro", "rw"):
                access = lowered
            elif lowered == "ipv6" and index + 1 < len(tokens):
                acl = tokens[index + 1]
                index += 2
                continue
            else:
                acl = token
            index += 1

        return SnmpCommunity(
            name=name, access=access, acl=acl, view=view,
            source_line=obj.text.strip(), line_number=self._lineno(obj),
        )

    # -- logging -----------------------------------------------------------

    def _normalize_logging(self, baseline: SecurityBaselineModel) -> None:
        disabled = self._first(r"(?i)^\s*no logging on\s*$")

        candidates = self._find(r"(?i)^\s*logging\s+\S+")
        host_objs = [
            obj for obj in candidates
            if not re.match(
                rf"(?i)^\s*logging\s+(?:{_LOGGING_NON_HOST_KEYWORDS})\b", obj.text
            )
        ]
        buffered = self._first(r"(?i)^\s*logging buffered\b")

        hosts = []
        for obj in host_objs:
            tokens = obj.text.split()
            host = tokens[2] if len(tokens) > 2 and tokens[1].lower() == "host" else tokens[1]
            if host not in hosts:
                hosts.append(host)

        if hosts:
            first = host_objs[0]
            baseline.logging_hosts = Observation[List[str]].found(
                hosts, first.text, self._lineno(first),
            )
        else:
            baseline.logging_hosts = Observation[List[str]].absent(
                [], "No 'logging host' statement present; no remote syslog destination.",
            )

        if buffered is not None:
            baseline.logging_buffered = Observation[bool].found(
                True, buffered.text, self._lineno(buffered),
            )
        else:
            baseline.logging_buffered = Observation[bool].absent(
                False, "No 'logging buffered' statement present.",
            )

        if disabled is not None:
            baseline.logging_enabled = Observation[bool].found(
                False, disabled.text, self._lineno(disabled),
                note="Logging explicitly disabled with 'no logging on'.",
            )
        elif hosts or buffered is not None:
            evidence = host_objs[0] if hosts else buffered
            baseline.logging_enabled = Observation[bool].found(
                True, evidence.text, self._lineno(evidence),
                note="At least one log destination is configured.",
            )
        else:
            baseline.logging_enabled = Observation[bool].absent(
                False,
                "No 'logging host' or 'logging buffered' statement present. Both are "
                "written to the running-config when configured, so absence means no "
                "log destination exists.",
            )

    # -- NTP ---------------------------------------------------------------

    def _normalize_ntp(self, baseline: SecurityBaselineModel) -> None:
        servers = self._find(r"(?i)^\s*ntp server\b")
        if not servers:
            baseline.ntp_servers = Observation[List[str]].absent(
                [],
                "No 'ntp server' statement present. EOS writes NTP configuration to "
                "the running-config, so absence means the clock is not synchronised.",
            )
            return

        addresses: List[str] = []
        for obj in servers:
            tokens = obj.text.split()[2:]
            if tokens[:1] == ["vrf"]:
                tokens = tokens[2:]
            if tokens:
                addresses.append(tokens[0])
        first = servers[0]
        baseline.ntp_servers = Observation[List[str]].found(
            sorted(set(addresses)), first.text, self._lineno(first),
            note=f"{len(set(addresses))} NTP time source(s) configured.",
        )
