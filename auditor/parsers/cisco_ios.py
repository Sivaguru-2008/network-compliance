"""Deterministic Cisco IOS parser.

Normalization policy: when is "no line" evidence?
------------------------------------------------
The single most important decision in this parser is what to do when a setting
simply does not appear in the configuration.  We use two, and only two,
policies, chosen per setting from IOS semantics:

CONCLUSIVE ABSENCE -- the command is off by default *and* always written back
    into the running-config when configured, so "not present" provably means
    "not configured".  We record ``detected=True`` with the insecure value and
    a note naming the absence as the evidence.
        enable secret / enable password / service password-encryption /
        aaa new-model / logging host / logging buffered / snmp-server community

AMBIGUOUS ABSENCE -- the effective value comes from a platform default that
    varies by IOS train, or the section may be missing from an excerpt while
    the device still has a non-default state.  We record ``detected=False``,
    which the engine reports as NEEDS_REVIEW.  We never guess in this case.
        ip http server (default on in older trains, off in newer)
        ip ssh version (1.99 fallback depends on train and crypto key)
        transport input (default `all` on 12.x, `none` on 15.x+)
        exec-timeout   (effective default cannot be confirmed from text)

Aggregation across multiple lines is always *worst-case*: if any VTY line
permits telnet, telnet is enabled; if any VTY line never times out, the
device's VTY timeout is "never".  A device is only as strong as its weakest
management path.
"""

import hashlib
import re
from typing import Dict, List, Optional, Sequence, Tuple

from ciscoconfparse2 import CiscoConfParse

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation, Origin
from .base import ParserError, VendorParser, registry

# Transports that carry credentials and session data in cleartext.
PLAINTEXT_TRANSPORTS = {"telnet", "rlogin", "lat", "pad", "udptn", "acercon"}
# `transport input all` is shorthand for "every transport", plaintext included.
TRANSPORT_ALL_EXPANSION = {"telnet", "ssh", "rlogin", "lat", "pad", "udptn", "acercon"}

# Keywords that follow `logging` but are settings, not destinations.
_LOGGING_NON_HOST_KEYWORDS = (
    "on|buffered|trap|console|monitor|facility|source-interface|origin-id|rate-limit|"
    "persistent|discriminator|userinfo|message-counter|history|count|queue-limit|"
    "server-arp|snmp-trap|synchronous|enable|delimiter|esm|exception|filter|"
    "immediate|policy-firewall|reload|dmvpn|event-log|purge"
)

_IOS_MARKERS: Sequence[Tuple[str, float]] = (
    # Management-plane markers (present in hardened/configured devices)
    (r"(?im)^\s*line vty\b", 0.30),
    (r"(?im)^\s*interface (?:Gigabit|Fast|Ten|Forty|Hundred)?Ethernet\S*", 0.20),
    (r"(?im)^\s*service password-encryption\b", 0.15),
    (r"(?im)^\s*ip (?:ssh|http|domain|route)\b", 0.15),
    (r"(?im)^\s*enable (?:secret|password)\b", 0.15),
    (r"(?im)^\s*hostname \S+", 0.10),
    (r"(?im)^\s*version \d+\.\d+", 0.10),
    (r"(?im)^\s*snmp-server\b", 0.10),
    (r"(?im)^\s*spanning-tree\b", 0.05),
    # Data-plane markers (present in real production configs that lack
    # management-plane commands, e.g. Stanford backbone routers)
    (r"(?im)^\s*access-list \d+\s+(?:permit|deny)\b", 0.20),
    (r"(?im)^\s*interface (?:Vlan|Loopback|Port-channel|Tunnel)\d", 0.15),
    (r"(?im)^\s*(?:ip|ipv6) access-group\b", 0.10),
    (r"(?im)^\s*redundancy\s*$", 0.10),
    (r"(?im)^\s*(?:switchport|channel-group)\b", 0.10),
)

# Syntax that positively identifies some *other* vendor/OS. Each future parser
# owns its own markers; these penalties just stop IOS from claiming them.
_NON_IOS_MARKERS: Sequence[Tuple[str, float]] = (
    (r"(?im)^\s*ASA Version\b", 0.80),           # Cisco ASA - different grammar
    (r"(?im)^\s*set system host-name\b", 0.90),  # Junos set-format
    (r"(?im)^\s*system \{", 0.90),               # Junos curly-brace format
    (r"(?im)^\s*sysname \S+", 0.90),             # Huawei VRP / H3C
    (r"(?im)^\s*config system global\b", 0.90),  # FortiOS
    (r"(?im)^\s*<\?xml", 0.90),                  # NETCONF / XML dumps
    (r"(?im)^\s*management ssh\s*$", 0.40),      # Arista EOS
    (r"(?im)^\s*management api http-commands\s*$", 0.40),  # Arista EOS
)


@registry.register
class CiscoIOSParser(VendorParser):
    """Grammar-based parser for Cisco IOS / IOS-XE running-configs."""

    name = "cisco_ios"
    vendor = "cisco"
    os_family = "ios"
    version = "1.0.0"
    base_confidence = 1.0

    # -- detection ---------------------------------------------------------

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        score = sum(weight for pattern, weight in _IOS_MARKERS if re.search(pattern, config_text))
        score -= sum(weight for pattern, weight in _NON_IOS_MARKERS if re.search(pattern, config_text))
        return max(0.0, min(1.0, score))

    # -- entry point -------------------------------------------------------

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if config_text is None or not config_text.strip():
            raise ParserError("Configuration is empty.")

        raw_lines = config_text.splitlines()
        self._warnings: List[str] = []
        try:
            parse = CiscoConfParse(config=raw_lines, syntax="ios")
        except Exception as exc:  # pragma: no cover - defensive
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

        # Ensure all baseline fields are answered
        for field in baseline.observable_fields():
            observation = getattr(baseline, field)
            if observation.note == "Parser did not evaluate this field." or getattr(observation, "is_unsupported", False):
                setattr(
                    baseline,
                    field,
                    type(observation).unsupported(
                        "Cisco IOS parser does not evaluate this field."
                    )
                )

        baseline.provenance.warnings = self._warnings
        return baseline

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _lineno(obj) -> int:
        """ciscoconfparse2 line numbers are 0-based; reports are 1-based."""
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

    # -- individual settings ----------------------------------------------

    def _hostname(self, parse: CiscoConfParse) -> Observation[str]:
        obj = self._first(parse, r"(?i)^\s*hostname\s+\S+")
        if obj is None:
            return Observation[str].unknown("No 'hostname' statement found.")
        return Observation[str].found(obj.text.split()[1], obj.text, self._lineno(obj))

    def _normalize_vty(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        """Worst-case view of remote-admin access across every `line vty` block."""
        vty_blocks = self._find(parse, r"(?i)^\s*line vty\b")
        if not vty_blocks:
            note = "No 'line vty' blocks found; remote administration posture cannot be determined."
            self._warn(note)
            baseline.telnet_enabled = Observation[bool].unknown(note)
            baseline.vty_transport_input = Observation[List[str]].unknown(note)
            baseline.vty_exec_timeout_seconds = Observation[int].unknown(note)
            baseline.management_acl_applied = Observation[bool].unknown(note)
            return

        transports: Dict[str, Tuple[str, int]] = {}  # transport -> (source_line, line_number)
        blocks_without_transport = 0
        blocks_without_timeout = 0
        blocks_without_access_class = 0
        access_classes: List[Tuple[str, int]] = []  # (source_line, line_number)
        timeouts: List[Tuple[int, str, int]] = []  # (seconds, source_line, line_number)

        for block in vty_blocks:
            transport_lines = [c for c in block.children if re.match(r"(?i)^\s*transport input\b", c.text)]
            if not transport_lines:
                blocks_without_transport += 1
            for child in transport_lines:
                for token in child.text.split()[2:]:
                    token = token.lower()
                    if token == "none":
                        expanded = set()
                    elif token == "all":
                        expanded = TRANSPORT_ALL_EXPANSION
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

            # `access-class <acl> in` is what restricts *who* may open a session.
            # An outbound-only access-class does not, so the direction matters.
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
        plaintext = sorted(t for t in transports if t in PLAINTEXT_TRANSPORTS)
        found = sorted(transports)

        if plaintext:
            # Positive evidence of a violation is conclusive even if other VTY
            # blocks are unspecified - the device already accepts cleartext.
            # Cite the earliest offending line so the operator reads the config
            # top-down, preferring the explicitly named transport on a tie.
            worst = min(plaintext, key=lambda t: (transports[t][1], t != "telnet"))
            line, lineno = transports[worst]
            baseline.telnet_enabled = Observation[bool].found(
                True, line, lineno, note=f"Plaintext transport(s) permitted on VTY: {', '.join(plaintext)}."
            )
            baseline.vty_transport_input = Observation[List[str]].found(found, line, lineno)
            return

        if blocks_without_transport:
            # Everything we can see is clean, but not every VTY block declares a
            # transport, and the IOS default differs across trains. Not provable.
            note = (
                f"{blocks_without_transport} 'line vty' block(s) have no 'transport input' statement; "
                "the effective default varies by IOS release (12.x defaults to 'all')."
            )
            self._warn(note)
            baseline.telnet_enabled = Observation[bool].unknown(note)
            baseline.vty_transport_input = Observation[List[str]].unknown(note)
            return

        line, lineno = transports[found[0]] if found else ("", None)
        baseline.telnet_enabled = Observation[bool].found(
            False, line, lineno, note="No plaintext transport permitted on any VTY line."
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
                seconds, line, lineno, note="'exec-timeout 0' disables the idle timeout entirely."
            )
            return

        if blocks_without_timeout or not timeouts:
            note = (
                f"{blocks_without_timeout} 'line vty' block(s) have no 'exec-timeout' statement; "
                "the effective idle timeout is a platform default and cannot be confirmed from the config."
            )
            self._warn(note)
            baseline.vty_exec_timeout_seconds = Observation[int].unknown(note)
            return

        seconds, line, lineno = max(timeouts, key=lambda item: item[0])
        baseline.vty_exec_timeout_seconds = Observation[int].found(
            seconds, line, lineno, note="Longest idle timeout configured across VTY lines."
        )

    def _resolve_management_acl(
        self,
        baseline: SecurityBaselineModel,
        access_classes: List[Tuple[str, int]],
        blocks_without_access_class: int,
    ) -> None:
        """Worst case: one unrestricted VTY block leaves the device reachable.

        Unlike `transport input`, absence is conclusive here. There is no
        platform default that silently restricts a VTY line — an `access-class`
        that is not written is an `access-class` that is not applied — so a
        block without one proves the management plane is open to any source.
        """
        if blocks_without_access_class:
            note = (
                f"{blocks_without_access_class} 'line vty' block(s) have no inbound "
                "'access-class', so remote management is reachable from any source address."
            )
            self._warn(note)
            baseline.management_acl_applied = Observation[bool].absent(False, note)
            return

        line, lineno = access_classes[0]
        baseline.management_acl_applied = Observation[bool].found(
            True,
            line,
            lineno,
            note="Every 'line vty' block restricts inbound access with an access-class.",
        )

    def _normalize_banner(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        """`banner login|motd|exec` — the notice shown before or at login."""
        obj = self._first(parse, r"(?i)^\s*banner\s+(login|motd|exec)\b")
        if obj is not None:
            baseline.login_banner_present = Observation[bool].found(
                True, obj.text, self._lineno(obj)
            )
            return
        baseline.login_banner_present = Observation[bool].absent(
            False,
            "No 'banner login', 'banner motd' or 'banner exec' statement present. IOS writes "
            "banner configuration to the running-config, so absence means no banner is shown.",
        )

    def _normalize_ntp(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        """`ntp server <host>` — peers are excluded; a peer is not an authority."""
        servers = self._find(parse, r"(?i)^\s*ntp server\b")
        if not servers:
            baseline.ntp_servers = Observation[List[str]].absent(
                [],
                "No 'ntp server' statement present. IOS writes NTP configuration to the "
                "running-config, so absence means the clock is not synchronised.",
            )
            return

        addresses: List[str] = []
        for obj in servers:
            tokens = obj.text.split()[2:]
            # `ntp server [vrf NAME] <host> [key N] [prefer] ...`
            if tokens[:1] == ["vrf"]:
                tokens = tokens[2:]
            if tokens:
                addresses.append(tokens[0])
        first = servers[0]
        baseline.ntp_servers = Observation[List[str]].found(
            sorted(set(addresses)),
            first.text,
            self._lineno(first),
            note=f"{len(set(addresses))} NTP time source(s) configured.",
        )

    def _normalize_ssh(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        version_obj = self._first(parse, r"(?i)^\s*ip ssh version\s+\d")
        if version_obj is not None:
            value = int(re.search(r"(\d+)\s*$", version_obj.text).group(1))
            baseline.ssh_version = Observation[int].found(value, version_obj.text, self._lineno(version_obj))
        else:
            note = (
                "No 'ip ssh version' statement found; IOS may fall back to version 1.99 "
                "(v1 compatibility) depending on release and RSA key state."
            )
            self._warn(note)
            baseline.ssh_version = Observation[int].unknown(note)

        ssh_obj = self._first(parse, r"(?i)^\s*ip ssh\b")
        if ssh_obj is not None:
            baseline.ssh_enabled = Observation[bool].found(True, ssh_obj.text, self._lineno(ssh_obj))
        elif baseline.vty_transport_input.detected and "ssh" in (baseline.vty_transport_input.value or []):
            obs = baseline.vty_transport_input
            baseline.ssh_enabled = Observation[bool].found(
                True, obs.source_line or "", obs.line_number, note="Inferred from VTY transport configuration."
            )
        else:
            baseline.ssh_enabled = Observation[bool].unknown("No 'ip ssh' configuration found.")

    def _normalize_http(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        baseline.http_server_enabled = self._toggle(
            parse,
            r"(?i)^\s*(no\s+)?ip http server\s*$",
            ambiguous_note=(
                "Neither 'ip http server' nor 'no ip http server' is present; the HTTP server "
                "default differs across IOS releases, so its state cannot be inferred."
            ),
        )
        baseline.https_server_enabled = self._toggle(
            parse,
            r"(?i)^\s*(no\s+)?ip http secure-server\s*$",
            ambiguous_note=(
                "Neither 'ip http secure-server' nor its negation is present; the HTTPS server "
                "default differs across IOS releases."
            ),
        )

    def _toggle(self, parse: CiscoConfParse, pattern: str, ambiguous_note: str) -> Observation[bool]:
        """Read an explicit `foo` / `no foo` pair; absence is AMBIGUOUS."""
        obj = self._first(parse, pattern)
        if obj is None:
            self._warn(ambiguous_note)
            return Observation[bool].unknown(ambiguous_note)
        enabled = not obj.text.strip().lower().startswith("no ")
        return Observation[bool].found(enabled, obj.text, self._lineno(obj))

    def _normalize_credentials(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        secret = self._first(parse, r"(?i)^\s*enable secret\b")
        if secret is not None:
            baseline.enable_secret_set = Observation[bool].found(True, secret.text, self._lineno(secret))
        else:
            baseline.enable_secret_set = Observation[bool].absent(
                False,
                "No 'enable secret' statement present. IOS always writes this command to the "
                "running-config when configured, so its absence means no enable secret is set.",
            )

        legacy = self._first(parse, r"(?i)^\s*enable password\b")
        if legacy is not None:
            baseline.enable_password_present = Observation[bool].found(
                True,
                legacy.text,
                self._lineno(legacy),
                note="Legacy reversible 'enable password' in use.",
            )
        else:
            baseline.enable_password_present = Observation[bool].absent(
                False, "No 'enable password' statement present."
            )

        encryption = self._first(parse, r"(?i)^\s*(no\s+)?service password-encryption\s*$")
        if encryption is not None:
            enabled = not encryption.text.strip().lower().startswith("no ")
            baseline.password_encryption = Observation[bool].found(
                enabled, encryption.text, self._lineno(encryption)
            )
        else:
            baseline.password_encryption = Observation[bool].absent(
                False,
                "No 'service password-encryption' statement present. The feature is disabled by "
                "default and is written to the running-config when enabled, so absence means disabled.",
            )

        min_length = self._first(parse, r"(?i)^\s*security passwords min-length\s+\d+")
        if min_length is not None:
            baseline.password_min_length = Observation[int].found(
                int(re.search(r"(\d+)\s*$", min_length.text).group(1)),
                min_length.text,
                self._lineno(min_length),
            )
        else:
            baseline.password_min_length = Observation[int].absent(
                0,
                "No 'security passwords min-length' statement present. IOS enforces no minimum "
                "password length unless this is configured, and writes it when it is.",
            )

    def _normalize_aaa(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        obj = self._first(parse, r"(?i)^\s*aaa new-model\s*$")
        if obj is not None:
            baseline.aaa_enabled = Observation[bool].found(True, obj.text, self._lineno(obj))
        else:
            baseline.aaa_enabled = Observation[bool].absent(
                False,
                "No 'aaa new-model' statement present. IOS writes this command to the running-config "
                "when enabled, so its absence means AAA is not enabled.",
            )

    def _normalize_snmp(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        community_objs = self._find(parse, r"(?i)^\s*snmp-server community\b")
        if community_objs:
            communities = [self._parse_community(obj) for obj in community_objs]
            first = community_objs[0]
            baseline.snmp_communities = Observation[List[SnmpCommunity]].found(
                communities,
                first.text,
                self._lineno(first),
                note=f"{len(communities)} SNMP v1/v2c community string(s) configured.",
            )
            return

        if self._find(parse, r"(?i)^\s*snmp-server\b"):
            baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
                [],
                "SNMP is configured but no 'snmp-server community' statements are present "
                "(consistent with an SNMPv3-only deployment).",
            )
            return

        baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
            [],
            "No 'snmp-server' configuration present. IOS writes SNMP configuration to the "
            "running-config, so absence means no community strings are defined.",
        )

    def _parse_community(self, obj) -> SnmpCommunity:
        """`snmp-server community <string> [view <v>] [RO|RW] [<acl>]`."""
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
            name=name,
            access=access,
            acl=acl,
            view=view,
            source_line=obj.text.strip(),
            line_number=self._lineno(obj),
        )

    def _normalize_logging(self, parse: CiscoConfParse, baseline: SecurityBaselineModel) -> None:
        disabled = self._first(parse, r"(?i)^\s*no logging on\s*$")

        candidates = self._find(parse, r"(?i)^\s*logging\s+\S+")
        host_objs = [
            obj
            for obj in candidates
            if not re.match(rf"(?i)^\s*logging\s+(?:{_LOGGING_NON_HOST_KEYWORDS})\b", obj.text)
        ]
        buffered = self._first(parse, r"(?i)^\s*logging buffered\b")

        hosts = []
        for obj in host_objs:
            tokens = obj.text.split()
            host = tokens[2] if len(tokens) > 2 and tokens[1].lower() == "host" else tokens[1]
            if host not in hosts:
                hosts.append(host)

        if hosts:
            first = host_objs[0]
            baseline.logging_hosts = Observation[List[str]].found(hosts, first.text, self._lineno(first))
        else:
            baseline.logging_hosts = Observation[List[str]].absent(
                [], "No 'logging host' statement present; no remote syslog destination is configured."
            )

        if buffered is not None:
            baseline.logging_buffered = Observation[bool].found(True, buffered.text, self._lineno(buffered))
        else:
            baseline.logging_buffered = Observation[bool].absent(
                False, "No 'logging buffered' statement present; local log buffering is not configured."
            )

        if disabled is not None:
            baseline.logging_enabled = Observation[bool].found(
                False, disabled.text, self._lineno(disabled), note="Logging explicitly disabled with 'no logging on'."
            )
        elif hosts or buffered is not None:
            evidence = host_objs[0] if hosts else buffered
            baseline.logging_enabled = Observation[bool].found(
                True,
                evidence.text,
                self._lineno(evidence),
                note="At least one log destination (syslog host or local buffer) is configured.",
            )
        else:
            baseline.logging_enabled = Observation[bool].absent(
                False,
                "No 'logging host' or 'logging buffered' statement present. Both are written to the "
                "running-config when configured, so absence means no log destination exists.",
            )
