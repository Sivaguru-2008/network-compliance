"""Deterministic Arista EOS parser.

Arista EOS uses a configuration format extremely similar to Cisco IOS.
We leverage CiscoConfParse to normalize Arista EOS configurations.
"""

import hashlib
import re
from typing import Dict, List, Optional, Sequence, Tuple

from ciscoconfparse2 import CiscoConfParse

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry

_EOS_MARKERS: Sequence[Tuple[str, float]] = (
    (r"(?im)^\s*management api http-commands\b", 0.45),
    (r"(?im)^\s*management ssh\b", 0.40),
    (r"(?im)^\s*peer-link\b", 0.40),
    (r"(?im)\barista\b", 0.30),
    (r"(?im)\beos\b", 0.30),
    (r"(?im)^\s*hostname\s+\S+", 0.05),
)

_NON_EOS_MARKERS: Sequence[Tuple[str, float]] = (
    (r"(?im)^\s*config system global\b", 0.90),  # FortiOS
    (r"(?im)^\s*set system host-name\b", 0.90),  # Junos set-format
    (r"(?im)^\s*system \{", 0.90),               # Junos curly-brace format
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
        score = sum(weight for pattern, weight in _EOS_MARKERS if re.search(pattern, config_text))
        score -= sum(weight for pattern, weight in _NON_EOS_MARKERS if re.search(pattern, config_text))
        return max(0.0, min(1.0, score))

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if config_text is None or not config_text.strip():
            raise ParserError("Configuration is empty.")

        raw_lines = config_text.splitlines()
        self._warnings: List[str] = []
        try:
            parse = CiscoConfParse(config=raw_lines, syntax="ios")
        except Exception as exc:
            raise ParserError(f"ciscoconfparse2 could not parse this configuration: {exc}") from exc

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

        baseline.hostname = self._hostname(parse)
        self._normalize_vty(parse, baseline)
        self._normalize_ssh(parse, baseline)
        self._normalize_http(parse, baseline)
        self._normalize_banner(parse, baseline)
        self._normalize_credentials(parse, baseline)
        self._normalize_aaa(parse, baseline)
        self._normalize_snmp(parse, baseline)
        self._normalize_logging(parse, baseline)
        self._normalize_ntp(parse, baseline)

        baseline.provenance.warnings = self._warnings
        return baseline

    @staticmethod
    def _lineno(obj) -> int:
        return obj.linenum + 1

    @staticmethod
    def _find(parse: CiscoConfParse, pattern: str) -> List:
        return list(parse.find_objects(pattern))

    @classmethod
    def _first(cls, parse: CiscoConfParse, pattern: str):
        found = cls._find(parse, pattern)
        return found[0] if found else None

    def _warn(self, message: str) -> None:
        if message not in self._warnings:
            self._warnings.append(message)

    def _hostname(self, parse: CiscoConfParse) -> Observation[str]:
        obj = self._first(parse, r"(?i)^\s*hostname\s+\S+")
        if obj is None:
            return Observation[str].unknown("No 'hostname' statement found.")
        return Observation[str].found(obj.text.split()[1], obj.text, self._lineno(obj))

    def _normalize_vty(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        vty_blocks = self._find(parse, r"(?i)^\s*line vty\b")
        if not vty_blocks:
            note = "No 'line vty' blocks found."
            baseline.telnet_enabled = Observation[bool].absent(False, note)
            baseline.vty_transport_input = Observation[List[str]].absent([], note)
            baseline.vty_exec_timeout_seconds = Observation[int].absent(0, note)
            baseline.management_acl_applied = Observation[bool].absent(False, note)
            return

        transports: Dict[str, Tuple[str, int]] = {}
        blocks_without_transport = 0
        blocks_without_timeout = 0
        blocks_without_access_class = 0
        access_classes: List[Tuple[str, int]] = []
        timeouts: List[Tuple[int, str, int]] = []

        for block in vty_blocks:
            transport_lines = [c for c in block.children if re.match(r"(?i)^\s*transport input\b", c.text)]
            if not transport_lines:
                blocks_without_transport += 1
            for child in transport_lines:
                for token in child.text.split()[2:]:
                    token = token.lower()
                    if token == "none":
                        continue
                    elif token == "all":
                        expanded = {"telnet", "ssh"}
                    else:
                        expanded = {token}
                    for transport in expanded:
                        transports.setdefault(transport, (child.text, self._lineno(child)))

            timeout_lines = [c for c in block.children if re.match(r"(?i)^\s*exec-timeout\b", c.text)]
            if not timeout_lines:
                blocks_without_timeout += 1
            for child in timeout_lines:
                seconds = self._exec_timeout_seconds(child.text)
                if seconds is not None:
                    timeouts.append((seconds, child.text, self._lineno(child)))

            inbound_acl = [
                c for c in block.children if re.match(r"(?i)^\s*access-class\s+\S+\s+in\b", c.text)
            ]
            if not inbound_acl:
                blocks_without_access_class += 1
            for child in inbound_acl:
                access_classes.append((child.text, self._lineno(child)))

        self._resolve_transports(baseline, transports, blocks_without_transport)
        self._resolve_exec_timeout(baseline, timeouts, blocks_without_timeout)
        self._resolve_management_acl(baseline, access_classes, blocks_without_access_class)

    @staticmethod
    def _exec_timeout_seconds(text: str) -> Optional[int]:
        match = re.match(r"(?i)^\s*exec-timeout\s+(\d+)(?:\s+(\d+))?\s*$", text)
        if not match:
            return None
        minutes = int(match.group(1))
        seconds = int(match.group(2) or 0)
        return minutes * 60 + seconds

    def _resolve_transports(
        self,
        baseline: SecurityBaselineModel,
        transports: Dict[str, Tuple[str, int]],
        blocks_without_transport: int,
    ) -> None:
        plaintext = sorted(t for t in transports if t == "telnet")
        found = sorted(transports)

        if plaintext:
            worst = plaintext[0]
            line, lineno = transports[worst]
            baseline.telnet_enabled = Observation[bool].found(
                True, line, lineno, note="Plaintext transport(s) permitted on VTY."
            )
            baseline.vty_transport_input = Observation[List[str]].found(found, line, lineno)
            return

        if blocks_without_transport:
            note = "Some 'line vty' blocks have no 'transport input' statement."
            baseline.telnet_enabled = Observation[bool].unknown(note)
            baseline.vty_transport_input = Observation[List[str]].unknown(note)
            return

        line, lineno = transports[found[0]] if found else ("", None)
        baseline.telnet_enabled = Observation[bool].found(
            False, line, lineno, note="No plaintext transport permitted on VTY."
        )
        baseline.vty_transport_input = Observation[List[str]].found(found, line, lineno)

    def _resolve_exec_timeout(
        self,
        baseline: SecurityBaselineModel,
        timeouts: List[Tuple[int, str, int]],
        blocks_without_timeout: int,
    ) -> None:
        never = [t for t in timeouts if t[0] == 0]
        if never:
            seconds, line, lineno = never[0]
            baseline.vty_exec_timeout_seconds = Observation[int].found(
                seconds, line, lineno, note="Idle timeout disabled."
            )
            return

        if blocks_without_timeout or not timeouts:
            note = "Some 'line vty' blocks have no 'exec-timeout' statement."
            baseline.vty_exec_timeout_seconds = Observation[int].unknown(note)
            return

        seconds, line, lineno = max(timeouts, key=lambda item: item[0])
        baseline.vty_exec_timeout_seconds = Observation[int].found(
            seconds, line, lineno, note="Worst-case VTY idle timeout."
        )

    def _resolve_management_acl(
        self,
        baseline: SecurityBaselineModel,
        access_classes: List[Tuple[str, int]],
        blocks_without_access_class: int,
    ) -> None:
        if blocks_without_access_class:
            line, lineno = access_classes[0] if access_classes else (None, None)
            note = "Some VTY lines are missing access-class."
            baseline.management_acl_applied = (
                Observation[bool].found(False, line, lineno, note=note)
                if line
                else Observation[bool].absent(False, note)
            )
            return

        line, lineno = access_classes[0]
        baseline.management_acl_applied = Observation[bool].found(
            True, line, lineno, note="Access-class applied to all VTY lines."
        )

    def _normalize_banner(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        obj = self._first(parse, r"(?i)^\s*banner\s+(login|motd)\b")
        if obj is not None:
            baseline.login_banner_present = Observation[bool].found(
                True, obj.text, self._lineno(obj)
            )
            return
        baseline.login_banner_present = Observation[bool].absent(
            False, "No login banner configured."
        )

    def _normalize_ntp(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        servers = self._find(parse, r"(?i)^\s*ntp server\b")
        if not servers:
            baseline.ntp_servers = Observation[List[str]].absent(
                [], "No NTP servers configured."
            )
            return

        addresses = [obj.text.split()[2] for obj in servers if len(obj.text.split()) > 2]
        first = servers[0]
        baseline.ntp_servers = Observation[List[str]].found(
            sorted(set(addresses)), first.text, self._lineno(first)
        )

    def _normalize_ssh(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        version_obj = self._first(parse, r"(?i)^\s*ip ssh version\s+\d")
        if version_obj is not None:
            value = int(re.search(r"(\d+)\s*$", version_obj.text).group(1))
            baseline.ssh_version = Observation[int].found(value, version_obj.text, self._lineno(version_obj))
        else:
            baseline.ssh_version = Observation[int].absent(2, "Default SSH version on EOS is 2.")

        ssh_obj = self._first(parse, r"(?i)^\s*management ssh\b")
        if ssh_obj is not None:
            baseline.ssh_enabled = Observation[bool].found(True, ssh_obj.text, self._lineno(ssh_obj))
        else:
            baseline.ssh_enabled = Observation[bool].absent(True, "SSH is enabled by default.")

    def _normalize_http(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        http_obj = self._first(parse, r"(?i)^\s*(no\s+)?management api http-commands\b")
        if http_obj is not None:
            enabled = not http_obj.text.strip().lower().startswith("no ")
            baseline.http_server_enabled = Observation[bool].found(enabled, http_obj.text, self._lineno(http_obj))
            baseline.https_server_enabled = Observation[bool].found(enabled, http_obj.text, self._lineno(http_obj))
        else:
            baseline.http_server_enabled = Observation[bool].absent(False, "HTTP server disabled by default.")
            baseline.https_server_enabled = Observation[bool].absent(False, "HTTPS server disabled by default.")

    def _normalize_credentials(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        secret = self._first(parse, r"(?i)^\s*enable secret\b")
        if secret is not None:
            baseline.enable_secret_set = Observation[bool].found(True, secret.text, self._lineno(secret))
        else:
            baseline.enable_secret_set = Observation[bool].absent(False, "No enable secret configured.")

        baseline.enable_password_present = Observation[bool].absent(False, "No legacy enable password configured.")

        encryption = self._first(parse, r"(?i)^\s*(no\s+)?service password-encryption\s*$")
        if encryption is not None:
            enabled = not encryption.text.strip().lower().startswith("no ")
            baseline.password_encryption = Observation[bool].found(enabled, encryption.text, self._lineno(encryption))
        else:
            baseline.password_encryption = Observation[bool].absent(True, "Password encryption enabled by default on EOS.")

        min_length = self._first(parse, r"(?i)^\s*security passwords min-length\s+\d+")
        if min_length is not None:
            baseline.password_min_length = Observation[int].found(
                int(re.search(r"(\d+)\s*$", min_length.text).group(1)),
                min_length.text,
                self._lineno(min_length),
            )
        else:
            baseline.password_min_length = Observation[int].absent(0, "No minimum password length enforced.")

    def _normalize_aaa(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        obj = self._first(parse, r"(?i)^\s*aaa new-model\s*$")
        if obj is not None:
            baseline.aaa_enabled = Observation[bool].found(True, obj.text, self._lineno(obj))
        else:
            baseline.aaa_enabled = Observation[bool].absent(False, "AAA not enabled.")

    def _normalize_snmp(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        community_objs = self._find(parse, r"(?i)^\s*snmp-server community\b")
        if community_objs:
            communities = []
            for obj in community_objs:
                tokens = obj.text.split()[2:]
                name = tokens[0] if tokens else ""
                access = "rw" if "rw" in [t.lower() for t in tokens] else "ro"
                communities.append(SnmpCommunity(name=name, access=access, source_line=obj.text.strip(), line_number=self._lineno(obj)))
            first = community_objs[0]
            baseline.snmp_communities = Observation[List[SnmpCommunity]].found(
                communities, first.text, self._lineno(first)
            )
        else:
            baseline.snmp_communities = Observation[List[SnmpCommunity]].absent([], "No SNMP communities configured.")

    def _normalize_logging(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        disabled = self._first(parse, r"(?i)^\s*no logging on\s*$")
        host_objs = self._find(parse, r"(?i)^\s*logging host\s+\S+")
        buffered = self._first(parse, r"(?i)^\s*logging buffered\b")

        hosts = [obj.text.split()[2] for obj in host_objs if len(obj.text.split()) > 2]
        if hosts:
            first = host_objs[0]
            baseline.logging_hosts = Observation[List[str]].found(hosts, first.text, self._lineno(first))
        else:
            baseline.logging_hosts = Observation[List[str]].absent([], "No remote logging hosts.")

        if buffered is not None:
            baseline.logging_buffered = Observation[bool].found(True, buffered.text, self._lineno(buffered))
        else:
            baseline.logging_buffered = Observation[bool].absent(False, "No logging buffer configured.")

        if disabled is not None:
            baseline.logging_enabled = Observation[bool].found(False, disabled.text, self._lineno(disabled))
        elif hosts or buffered is not None:
            evidence = host_objs[0] if hosts else buffered
            baseline.logging_enabled = Observation[bool].found(True, evidence.text, self._lineno(evidence))
        else:
            baseline.logging_enabled = Observation[bool].absent(False, "Logging disabled.")
