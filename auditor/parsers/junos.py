"""Deterministic Juniper Junos parser.

The second deterministic vendor, and the one that tests whether the baseline is
genuinely vendor-neutral or merely Cisco-shaped. It reads both formats an
operator will actually paste:

* **set format** — ``show configuration | display set``
* **braces format** — ``show configuration``

Both are reduced to the same list of statements before any field is read, so
the extraction logic is written once. The conversion is done here rather than
with ``ciscoconfparse2``'s Junos support because that converter renumbers the
lines, and a report that cites line 7 must mean line 7 *of the file the
operator handed us*. Every statement therefore carries the verbatim source line
and its original 1-based number, whichever format it came from.

Two Junos details a naive grep gets wrong, and this parser does not:

* ``deactivate system services telnet`` (set format) and ``inactive: telnet``
  (braces format) mean the statement is present but **not in effect**. Treating
  it as configured would fail a device that is actually compliant.
* A statement's meaning is its full path, not the last word. ``ssh`` under
  ``system services`` enables the SSH server; ``ssh`` under ``system services
  netconf`` does not.

Normalization policy: when is "no statement" evidence?
-----------------------------------------------------
Junos makes this easier than IOS. The candidate configuration is a complete
document — a service that is not written is not offered — so most absences are
conclusive rather than ambiguous:

CONCLUSIVE ABSENCE -- the feature is off unless configured, and Junos writes
    every configured statement back into the configuration.
        system services telnet / ftp / finger / ssh / web-management,
        snmp community, system syslog, system root-authentication,
        system authentication-order + radius-server / tacplus-server,
        system login idle-timeout

AMBIGUOUS ABSENCE -- the effective value is a release-dependent default.
        system services ssh protocol-version (v1 was accepted by releases
        before 15.1; the enforced version cannot be read from the text alone)

Vendor-neutral mappings, stated explicitly because the training loop diffs this
parser against the LLM's reading of the same device and both must mean the same
thing by a field:

    vty_transport_input      the interactive management transports the device
                             offers under `system services` (telnet, ssh, ftp,
                             finger, xnm-clear-text). NETCONF is excluded: it
                             rides on SSH and is an API, not a login shell.
    vty_exec_timeout_seconds `system login idle-timeout`, in minutes on the
                             device, converted to seconds here; worst case
                             (longest) across login classes, 0 meaning never.
    enable_secret_set        `system root-authentication encrypted-password` —
                             the hashed credential guarding privileged access.
    enable_password_present  `system root-authentication plain-text-password`,
                             the reversible form.
    password_encryption      Junos hashes stored credentials by default and
                             offers no toggle, so this is a platform property
                             rather than a setting (see `_normalize_credentials`).
    logging_buffered         `system syslog file …` — on-box log retention,
                             the analogue of the IOS buffer.

Aggregation is worst-case, exactly as in the IOS parser: if any login class
never times out, the device's idle timeout is "never".
"""

import hashlib
import re
import shlex
from typing import Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry

#: Management transports that carry credentials in cleartext.
PLAINTEXT_SERVICES = ("telnet", "ftp", "finger", "xnm-clear-text")
#: Every `system services` child treated as an interactive management transport.
MANAGEMENT_SERVICES = PLAINTEXT_SERVICES + ("ssh",)

_JUNOS_MARKERS: Sequence[Tuple[str, float]] = (
    (r"(?im)^\s*set system host-name\b", 0.35),
    (r"(?im)^\s*(set\s+)?system\s*\{?\s*$", 0.15),
    (r"(?im)^\s*set system services\b", 0.20),
    (r"(?im)^\s*set interfaces \S+ unit \d+", 0.20),
    (r"(?im)^\s*set (?:routing-options|security|protocols|policy-options)\b", 0.15),
    (r"(?im)^\s*set version \d", 0.10),
    (r"(?im)^\s*host-name \S+;", 0.25),
    (r"(?im)^\s*services\s*\{", 0.20),
    (r"(?im)^\s*root-authentication\s*\{", 0.20),
    (r"(?im)^\s*unit \d+\s*\{", 0.10),
)

# Syntax that positively identifies another vendor, so Junos never claims it.
_NON_JUNOS_MARKERS: Sequence[Tuple[str, float]] = (
    (r"(?im)^\s*hostname \S+\s*$", 0.90),        # Cisco IOS
    (r"(?im)^\s*line vty\b", 0.90),              # Cisco IOS
    (r"(?im)^\s*config system global\b", 0.90),  # FortiOS
    (r"(?im)^\s*sysname \S+", 0.90),             # Huawei VRP / H3C
    (r"(?im)^\s*ASA Version\b", 0.90),           # Cisco ASA
    (r"(?im)^\s*<\?xml", 0.90),                  # NETCONF / XML dumps
)


class JunosStatement(BaseModel):
    """One configuration statement, normalized to its set-format path.

    ``path`` is what the parser matches on; ``source_line`` and ``line_number``
    are what a report cites, and they always refer to the original file.
    """

    model_config = ConfigDict(frozen=True)

    path: Tuple[str, ...]
    source_line: str
    line_number: int
    active: bool = True

    @property
    def text(self) -> str:
        return " ".join(self.path)

    def starts_with(self, *prefix: str) -> bool:
        return self.path[: len(prefix)] == tuple(prefix)


@registry.register
class JunosParser(VendorParser):
    """Grammar-based parser for Juniper Junos configurations, either format."""

    name = "juniper_junos"
    vendor = "juniper"
    os_family = "junos"
    version = "1.0.0"
    base_confidence = 1.0

    # -- detection ---------------------------------------------------------

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        score = sum(weight for pattern, weight in _JUNOS_MARKERS if re.search(pattern, config_text))
        score -= sum(weight for pattern, weight in _NON_JUNOS_MARKERS if re.search(pattern, config_text))
        return max(0.0, min(1.0, score))

    # -- entry point -------------------------------------------------------

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if config_text is None or not config_text.strip():
            raise ParserError("Configuration is empty.")

        raw_lines = config_text.splitlines()
        self._warnings: List[str] = []
        self.statements = self._read_statements(raw_lines)
        if not self.statements:
            raise ParserError(
                "No Junos statements found. Expected either 'set' format "
                "(show configuration | display set) or braces format (show configuration)."
            )

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
        self._normalize_services(baseline)
        self._normalize_idle_timeout(baseline)
        self._normalize_credentials(baseline)
        self._normalize_aaa(baseline)
        self._normalize_snmp(baseline)
        self._normalize_logging(baseline)

        baseline.provenance.warnings = self._warnings
        return baseline

    # -- reading the two formats ------------------------------------------

    @classmethod
    def _read_statements(cls, raw_lines: List[str]) -> List[JunosStatement]:
        """Reduce either format to statements, preserving original line numbers."""
        if any(re.match(r"^\s*(set|deactivate)\s+\S", line) for line in raw_lines):
            return cls._read_set_format(raw_lines)
        return cls._read_braces_format(raw_lines)

    @staticmethod
    def _tokenize(text: str) -> Tuple[str, ...]:
        """Split a statement, keeping a quoted value (a password hash) whole."""
        try:
            return tuple(shlex.split(text))
        except ValueError:  # unbalanced quote in a truncated paste
            return tuple(text.replace('"', "").split())

    @classmethod
    def _read_set_format(cls, raw_lines: List[str]) -> List[JunosStatement]:
        statements: List[JunosStatement] = []
        deactivated: List[Tuple[str, ...]] = []

        for index, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            match = re.match(r"^(set|deactivate)\s+(.*)$", stripped)
            if not match:
                continue
            keyword, remainder = match.group(1), match.group(2).rstrip(";")
            path = cls._tokenize(remainder)
            if not path:
                continue
            if keyword == "deactivate":
                deactivated.append(path)
                continue
            statements.append(JunosStatement(path=path, source_line=stripped, line_number=index))

        if not deactivated:
            return statements
        return [
            statement.model_copy(
                update={"active": not any(statement.path[: len(p)] == p for p in deactivated)}
            )
            for statement in statements
        ]

    @classmethod
    def _read_braces_format(cls, raw_lines: List[str]) -> List[JunosStatement]:
        """Walk the brace hierarchy, emitting one statement per leaf.

        Each emitted statement keeps the line number of the leaf itself, not of
        the block that contains it, so evidence points at the specific setting.
        """
        statements: List[JunosStatement] = []
        stack: List[Tuple[str, ...]] = []
        inactive_depth: Optional[int] = None

        for index, line in enumerate(raw_lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("/*"):
                continue

            if stripped in ("}", "};"):
                if stack:
                    stack.pop()
                if inactive_depth is not None and len(stack) < inactive_depth:
                    inactive_depth = None
                continue

            if stripped.endswith("{"):
                body, is_block = stripped[:-1].strip(), True
            elif stripped.endswith(";"):
                body, is_block = stripped, False
            else:
                # Junos terminates every leaf statement with ';' and opens every
                # block with '{'. A line that does neither is not configuration,
                # so it is skipped rather than guessed at - which is what stops
                # prose from parsing into a confident, entirely fictional baseline.
                continue

            marked_inactive = body.startswith("inactive:")
            if marked_inactive:
                body = body[len("inactive:") :].strip()
            body = body.rstrip(";").strip()
            if not body:
                continue

            tokens = cls._tokenize(body)
            if not tokens:
                continue

            if is_block:
                if marked_inactive and inactive_depth is None:
                    inactive_depth = len(stack)
                stack.append(tokens)
                # A block header is itself a statement: `services { ssh { … } }`
                # must record that `system services ssh` exists at all.
                statements.append(
                    JunosStatement(
                        path=tuple(token for group in stack for token in group),
                        source_line=stripped,
                        line_number=index,
                        active=inactive_depth is None,
                    )
                )
                continue

            statements.append(
                JunosStatement(
                    path=tuple(token for group in stack for token in group) + tokens,
                    source_line=stripped,
                    line_number=index,
                    active=inactive_depth is None and not marked_inactive,
                )
            )

        return statements

    # -- helpers -----------------------------------------------------------

    def find(self, *prefix: str) -> List[JunosStatement]:
        """Active statements whose path starts with ``prefix``."""
        return [s for s in self.statements if s.active and s.starts_with(*prefix)]

    def first(self, *prefix: str) -> Optional[JunosStatement]:
        found = self.find(*prefix)
        return found[0] if found else None

    def inactive(self, *prefix: str) -> List[JunosStatement]:
        return [s for s in self.statements if not s.active and s.starts_with(*prefix)]

    def _warn(self, message: str) -> None:
        if message not in self._warnings:
            self._warnings.append(message)

    @staticmethod
    def _evidence(statement: JunosStatement) -> Tuple[str, int]:
        return statement.source_line, statement.line_number

    # -- individual settings ----------------------------------------------

    def _hostname(self) -> Observation[str]:
        statement = self.first("system", "host-name")
        if statement is None:
            return Observation[str].unknown("No 'system host-name' statement found.")
        return Observation[str].found(statement.path[-1], *self._evidence(statement))

    def _normalize_services(self, baseline: SecurityBaselineModel) -> None:
        """`system services` is the whole remote-access surface on Junos."""
        offered: Dict[str, JunosStatement] = {}
        for service in MANAGEMENT_SERVICES:
            statement = self.first("system", "services", service)
            if statement is not None:
                offered[service] = statement

        plaintext = [s for s in PLAINTEXT_SERVICES if s in offered]
        transports = sorted(offered)

        if plaintext:
            worst = offered[plaintext[0]]
            baseline.telnet_enabled = Observation[bool].found(
                True,
                *self._evidence(worst),
                note=f"Cleartext management service(s) enabled: {', '.join(plaintext)}.",
            )
            baseline.vty_transport_input = Observation[List[str]].found(
                transports, *self._evidence(worst)
            )
        elif offered:
            statement = offered[transports[0]]
            baseline.telnet_enabled = Observation[bool].found(
                False,
                *self._evidence(statement),
                note="No cleartext management service is enabled under 'system services'.",
            )
            baseline.vty_transport_input = Observation[List[str]].found(
                transports, *self._evidence(statement)
            )
        else:
            note = (
                "No management services are configured under 'system services'. Junos offers "
                "no remote-access service that is not configured, so none is reachable."
            )
            baseline.telnet_enabled = Observation[bool].absent(False, note)
            baseline.vty_transport_input = Observation[List[str]].absent([], note)

        deactivated = [
            s.path[2] for s in self.inactive("system", "services") if len(s.path) > 2
        ]
        if deactivated:
            self._warn(
                "Deactivated (configured but not in effect) service(s) ignored: "
                f"{', '.join(sorted(set(deactivated)))}."
            )

        self._normalize_ssh(baseline, offered.get("ssh"))
        self._normalize_web_management(baseline)

    def _normalize_ssh(
        self, baseline: SecurityBaselineModel, ssh_statement: Optional[JunosStatement]
    ) -> None:
        if ssh_statement is not None:
            baseline.ssh_enabled = Observation[bool].found(True, *self._evidence(ssh_statement))
        else:
            baseline.ssh_enabled = Observation[bool].absent(
                False,
                "No 'system services ssh' statement present. The SSH server is not enabled "
                "unless configured, so its absence means SSH is not offered.",
            )

        version = self.first("system", "services", "ssh", "protocol-version")
        if version is not None:
            value = re.sub(r"(?i)^v", "", version.path[-1])
            if value.isdigit():
                baseline.ssh_version = Observation[int].found(
                    int(value), *self._evidence(version)
                )
                return
            note = f"Unrecognised SSH protocol-version value {version.path[-1]!r}."
            self._warn(note)
            baseline.ssh_version = Observation[int].unknown(note)
            return

        if ssh_statement is None:
            baseline.ssh_version = Observation[int].unknown(
                "SSH is not enabled, so no protocol version is enforced."
            )
            return

        note = (
            "No 'protocol-version' under 'system services ssh'; the enforced version is a "
            "release default (v1 was still accepted before Junos 15.1) and cannot be "
            "determined from the configuration text."
        )
        self._warn(note)
        baseline.ssh_version = Observation[int].unknown(note)

    def _normalize_web_management(self, baseline: SecurityBaselineModel) -> None:
        for field, protocol in (("http_server_enabled", "http"), ("https_server_enabled", "https")):
            statement = self.first("system", "services", "web-management", protocol)
            if statement is not None:
                setattr(
                    baseline,
                    field,
                    Observation[bool].found(True, *self._evidence(statement)),
                )
            else:
                setattr(
                    baseline,
                    field,
                    Observation[bool].absent(
                        False,
                        f"No 'system services web-management {protocol}' statement present. "
                        "J-Web is not served unless configured.",
                    ),
                )

    def _normalize_idle_timeout(self, baseline: SecurityBaselineModel) -> None:
        """Worst case across the global setting and every login class.

        Absence is conclusive here: Junos applies no idle timeout unless one is
        configured, so an unconfigured device holds sessions open indefinitely.
        That is recorded as the insecure value with the absence as its stated
        evidence, not as an unknown — the same treatment IOS gets for `aaa
        new-model`.
        """
        candidates: List[Tuple[int, JunosStatement]] = []
        for statement in self.find("system", "login"):
            if "idle-timeout" not in statement.path:
                continue
            index = statement.path.index("idle-timeout")
            value = statement.path[index + 1] if index + 1 < len(statement.path) else ""
            if value.isdigit():
                candidates.append((int(value) * 60, statement))

        if not candidates:
            baseline.vty_exec_timeout_seconds = Observation[int].absent(
                0,
                "No 'idle-timeout' is configured under 'system login' or any login class. "
                "Junos does not time out an idle session unless a timeout is configured, "
                "so sessions remain open indefinitely.",
            )
            return

        never = [pair for pair in candidates if pair[0] == 0]
        seconds, statement = never[0] if never else max(candidates, key=lambda pair: pair[0])
        note = (
            "'idle-timeout 0' disables the idle timeout entirely."
            if seconds == 0
            else "Longest idle timeout configured across login classes."
        )
        baseline.vty_exec_timeout_seconds = Observation[int].found(
            seconds, *self._evidence(statement), note=note
        )

    def _normalize_credentials(self, baseline: SecurityBaselineModel) -> None:
        encrypted = self.first("system", "root-authentication", "encrypted-password")
        plaintext = self.first("system", "root-authentication", "plain-text-password")

        if encrypted is not None:
            baseline.enable_secret_set = Observation[bool].found(
                True,
                *self._evidence(encrypted),
                note="Root authentication is protected by a hashed password.",
            )
        else:
            baseline.enable_secret_set = Observation[bool].absent(
                False,
                "No 'system root-authentication encrypted-password' statement present. Junos "
                "writes the hashed root credential into the configuration, so its absence "
                "means no hashed root password is set.",
            )

        if plaintext is not None:
            baseline.enable_password_present = Observation[bool].found(
                True,
                *self._evidence(plaintext),
                note="Root authentication carries a reversible plain-text password.",
            )
        else:
            baseline.enable_password_present = Observation[bool].absent(
                False, "No 'plain-text-password' statement present under root-authentication."
            )

        # Junos hashes every stored credential and exposes no equivalent of
        # `service password-encryption`, so this is a platform property. It is
        # still recorded as an observation with its reasoning, because the rule
        # engine must be able to read it the same way for every vendor.
        if plaintext is not None:
            baseline.password_encryption = Observation[bool].found(
                False,
                *self._evidence(plaintext),
                note="A plain-text password is stored in the configuration.",
            )
            return

        hashed = self.first("system", "root-authentication", "encrypted-password") or next(
            (s for s in self.find("system", "login") if "encrypted-password" in s.path), None
        )
        if hashed is not None:
            baseline.password_encryption = Observation[bool].found(
                True,
                *self._evidence(hashed),
                note="Junos stores credentials hashed; the configuration contains no "
                "plain-text password statement.",
            )
            return

        baseline.password_encryption = Observation[bool].absent(
            True,
            "Junos hashes stored credentials by default and offers no equivalent of "
            "'service password-encryption'; no plain-text password statement is present.",
        )

    def _normalize_aaa(self, baseline: SecurityBaselineModel) -> None:
        """Centralised authentication: an order naming a remote method, and a server."""
        order = [
            s
            for s in self.find("system", "authentication-order")
            if any(method in s.path for method in ("radius", "tacplus"))
        ]
        servers = self.find("system", "radius-server") + self.find("system", "tacplus-server")

        if order:
            baseline.aaa_enabled = Observation[bool].found(
                True,
                *self._evidence(order[0]),
                note="Authentication order names a centralised method.",
            )
            if not servers:
                self._warn(
                    "'system authentication-order' names a remote method but no radius-server "
                    "or tacplus-server is configured; authentication will fall back to local."
                )
            return

        if servers:
            baseline.aaa_enabled = Observation[bool].found(
                True,
                *self._evidence(servers[0]),
                note="A centralised authentication server is configured.",
            )
            self._warn(
                "A RADIUS/TACACS+ server is configured but 'system authentication-order' does "
                "not name it, so local authentication may still be used first."
            )
            return

        baseline.aaa_enabled = Observation[bool].absent(
            False,
            "No 'system authentication-order' naming radius/tacplus and no radius-server or "
            "tacplus-server statement present. Junos writes these when configured, so their "
            "absence means authentication is local only.",
        )

    def _normalize_snmp(self, baseline: SecurityBaselineModel) -> None:
        """`snmp community <name> …` may span several statements; group by name."""
        community_statements = self.find("snmp", "community")
        if community_statements:
            baseline.snmp_communities = Observation[List[SnmpCommunity]].found(
                self._collect_communities(community_statements),
                *self._evidence(community_statements[0]),
                note=f"{len(self._collect_communities(community_statements))} SNMP v1/v2c "
                "community string(s) configured.",
            )
            return

        if self.find("snmp"):
            baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
                [],
                "SNMP is configured but no 'snmp community' statements are present "
                "(consistent with an SNMPv3-only deployment).",
            )
            return

        baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
            [],
            "No 'snmp' configuration present. Junos writes SNMP configuration into the "
            "configuration file, so absence means no community strings are defined.",
        )

    @staticmethod
    def _collect_communities(statements: List[JunosStatement]) -> List[SnmpCommunity]:
        ordered: List[str] = []
        attributes: Dict[str, Dict[str, object]] = {}

        for statement in statements:
            if len(statement.path) < 3:
                continue
            name = statement.path[2]
            if name not in attributes:
                ordered.append(name)
                attributes[name] = {
                    "source_line": statement.source_line,
                    "line_number": statement.line_number,
                }
            tail = statement.path[3:]
            if not tail:
                continue
            if tail[0] == "authorization" and len(tail) > 1:
                attributes[name]["access"] = "rw" if "write" in tail[1] else "ro"
            elif tail[0] == "clients" and len(tail) > 1:
                attributes[name]["acl"] = tail[1]
            elif tail[0] == "view" and len(tail) > 1:
                attributes[name]["view"] = tail[1]

        return [SnmpCommunity(name=name, **attributes[name]) for name in ordered]

    def _normalize_logging(self, baseline: SecurityBaselineModel) -> None:
        host_statements = self.find("system", "syslog", "host")
        files = self.find("system", "syslog", "file")

        hosts = sorted({s.path[3] for s in host_statements if len(s.path) > 3})
        if host_statements:
            baseline.logging_hosts = Observation[List[str]].found(
                hosts, *self._evidence(host_statements[0])
            )
        else:
            baseline.logging_hosts = Observation[List[str]].absent(
                [], "No 'system syslog host' statement present, so no remote log destination."
            )

        if files:
            baseline.logging_buffered = Observation[bool].found(
                True,
                *self._evidence(files[0]),
                note="On-box syslog file retention is configured.",
            )
        else:
            baseline.logging_buffered = Observation[bool].absent(
                False, "No 'system syslog file' statement present, so no on-box log retention."
            )

        evidence = host_statements[0] if host_statements else (files[0] if files else None)
        if evidence is not None:
            baseline.logging_enabled = Observation[bool].found(
                True,
                *self._evidence(evidence),
                note="At least one syslog destination is configured.",
            )
        else:
            baseline.logging_enabled = Observation[bool].absent(
                False,
                "No 'system syslog' configuration present. Junos writes syslog configuration "
                "into the configuration file, so absence means nothing is being logged.",
            )
