"""Deterministic Fortinet FortiOS parser.

The third deterministic vendor. Cisco proved the pipeline; Junos proved the
baseline was not secretly Cisco-shaped. FortiOS tests something narrower and
more specific: whether a *setting* in this tool means the effective state of
the device, or merely a line that appears in a file.

FortiOS is unusually good at making that distinction matter, because its
grammar has four separate ways for a statement to be present and not in force:

* ``unset allowaccess``      clears an attribute set earlier in the same block
* ``delete port3``           removes a table entry, and everything under it
* ``set status disable``     configures an object and switches it off — an SNMP
                             community, a syslog server, a password policy
* an ``edit`` context        scopes an attribute to one table entry, so
                             ``allowaccess`` under ``port1`` says nothing at
                             all about ``port2``

A parser that greps for ``set allowaccess`` and looks for ``telnet`` gets every
one of those wrong. So this parser does not grep. It walks the block structure,
resolves each attribute to its effective value within its own scope, and
records the semantic path it was found at::

    system interface -> port1 -> allowaccess

Line numbers survive that walk. The configuration is never rewritten,
flattened, or renumbered into an intermediate form: every setting keeps the
verbatim text of the line it came from and that line's original 1-based number,
so a report citing line 24 means line 24 of the file the operator handed us.

Vendor semantics, stated because they are *not* the Cisco or Junos ones
---------------------------------------------------------------------
``set allowaccess ping https ssh`` is the whole administrative-access surface
on FortiOS, and it is per interface. It is not a transport list on a login
line, and reading it as one would be wrong in both directions: ``ping`` and
``snmp`` are on it and are not logins, while the same interface keyword governs
the web GUI, which on IOS is a global ``ip http server``. So one statement
feeds five baseline fields, each read from its own keyword and aggregated
worst-case across every interface:

    telnet         -> telnet_enabled, vty_transport_input
    ssh            -> ssh_enabled, vty_transport_input
    http / https   -> http_server_enabled / https_server_enabled

``unset allowaccess`` is therefore not "deny everything": it returns the
attribute to a factory default that depends on the interface's role and the
hardware model, which the text does not state. It is read as *no longer
configured*, which escalates rather than passing.

    management_acl_applied   `config system admin` -> `set trusthostN`. FortiOS
                             has no `access-class` and no loopback filter: an
                             administrator account is reachable from any source
                             until a trusthost narrows it, and `0.0.0.0
                             0.0.0.0` is the factory trusthost, which restricts
                             nothing. Worst case across accounts.
    enable_secret_set        `config system admin` -> `set password ENC <hash>`.
    enable_password_present  the same statement *without* the `ENC` keyword —
                             a credential written in the clear.
    password_encryption      a platform property, as on Junos: FortiOS hashes
                             stored administrator passwords and offers no
                             equivalent of `service password-encryption`.
    vty_exec_timeout_seconds `config system global` -> `set admintimeout`, in
                             minutes on the device and seconds here.
    logging_buffered         `config log memory setting` / `config log disk
                             setting` — on-box retention, gated on its own
                             `set status`.

Normalization policy: when is "no line" evidence?
-------------------------------------------------
FortiOS complicates the question that IOS and Junos each answered one way,
because ``show`` prints only what differs from the factory default while ``show
full-configuration`` prints everything. The same device yields two files, and
absence means different things in each. Each field is therefore decided on
whether its factory default is *stable and known*, not on a blanket rule:

CONCLUSIVE ABSENCE -- the feature is off in every release unless configured,
    and configuring it writes the block.
        pre-login-banner / post-login-banner (both default `disable`)
        config system password-policy        (absent means nothing enforced)
        config user radius / tacacs+, set remote-auth
        config log syslogd setting server
        trusthost on an administrator account (factory trusthost is 0.0.0.0/0)
        an interface whose `allowaccess` is written and omits a protocol

AMBIGUOUS ABSENCE -- the effective value is a factory default that varies by
    model, interface role, or release, or the section may be missing from a
    ``show`` excerpt while the device still has a non-default state. Recorded
    as undetected, which the engine reports as NEEDS_REVIEW.
        allowaccess not written on an interface (default varies by role/model)
        no `config system interface` block at all
        set admintimeout absent  (a default the text does not state)
        set admin-ssh-v1 absent  (the knob exists in 6.x and is gone in 7.x)
        config log memory setting absent (default differs across models)
        config system ntp with FortiGuard's servers (synchronised, but the
            configuration names no address to report)

Aggregation is worst-case, exactly as for the other two vendors: one interface
offering telnet means the device offers telnet, and one administrator account
without a trusthost means the management plane is reachable from anywhere.
"""

import hashlib
import re
import shlex
from typing import Dict, List, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry

#: `allowaccess` keywords that carry an interactive login session.
SSH_ACCESS = "ssh"
TELNET_ACCESS = "telnet"
#: Login transports, in the sense `vty_transport_input` means for every vendor.
MANAGEMENT_ACCESS = (SSH_ACCESS, TELNET_ACCESS)
#: ...of which these carry credentials in cleartext.
PLAINTEXT_ACCESS = (TELNET_ACCESS,)
#: The factory trusthost, which permits every source address.
ANY_SOURCE = ("0.0.0.0", "0.0.0.0")

#: Blocks whose contents belong to the device, not to a VDOM. `config global`
#: exists only to scope them in multi-VDOM mode, so it is walked through rather
#: than becoming part of a setting's path.
_TRANSPARENT_BLOCKS = {("global",)}

_FORTIOS_MARKERS: Sequence[Tuple[str, float]] = (
    (r"(?im)^\s*config system global\b", 0.35),
    (r"(?im)^#config-version=", 0.30),
    (r"(?im)^\s*config system interface\b", 0.20),
    (r"(?im)^\s*set allowaccess\b", 0.20),
    (r"(?im)^\s*config system (?:admin|snmp|password-policy|ntp)\b", 0.15),
    (r"(?im)^\s*next\s*$", 0.15),
    (r"(?im)^\s*config \S+", 0.10),
    (r"(?im)^\s*edit \S+", 0.10),
    (r"(?im)^\s*set (?:vdom|admintimeout|hostname|accprofile)\b", 0.10),
)

# Syntax that positively identifies another vendor, so FortiOS never claims it.
_NON_FORTIOS_MARKERS: Sequence[Tuple[str, float]] = (
    (r"(?im)^\s*line vty\b", 0.90),              # Cisco IOS
    (r"(?im)^\s*hostname \S+\s*$", 0.90),        # Cisco IOS
    (r"(?im)^\s*set system host-name\b", 0.90),  # Junos set format
    (r"(?im)^\s*system \{", 0.90),               # Junos braces format
    (r"(?im)^\s*sysname \S+", 0.90),             # Huawei VRP / H3C
    (r"(?im)^\s*ASA Version\b", 0.90),           # Cisco ASA
    (r"(?im)^\s*<\?xml", 0.90),                  # NETCONF / XML dumps
)


class FortiosScope(BaseModel):
    """One ``config`` or ``edit`` block header.

    ``path`` is the semantic location of the block, so the ``port1`` entry of
    ``config system interface`` is ``("system", "interface", "port1")`` and
    cannot be confused with the ``port1`` entry of anything else.
    """

    model_config = ConfigDict(frozen=True)

    path: Tuple[str, ...]
    kind: str  # "config" | "edit"
    source_line: str
    line_number: int
    active: bool = True

    @property
    def name(self) -> str:
        return self.path[-1] if self.path else ""


class FortiosSetting(BaseModel):
    """One ``set`` statement, resolved to its effective state.

    ``active`` is False when a later ``unset`` in the same block cleared the
    attribute, or when the table entry containing it was deleted. The line is
    still carried, because "configured and then cleared" is a thing an operator
    may need to see.
    """

    model_config = ConfigDict(frozen=True)

    path: Tuple[str, ...]
    values: Tuple[str, ...]
    source_line: str
    line_number: int
    active: bool = True

    @property
    def attribute(self) -> str:
        return self.path[-1] if self.path else ""

    @property
    def value(self) -> str:
        """The single-token value, or "" — the common `set status enable` case."""
        return self.values[0] if self.values else ""

    def starts_with(self, *prefix: str) -> bool:
        return self.path[: len(prefix)] == tuple(prefix)


@registry.register
class FortiosParser(VendorParser):
    """Grammar-based parser for Fortinet FortiOS configurations."""

    name = "fortinet_fortios"
    vendor = "fortinet"
    os_family = "fortios"
    version = "1.0.0"
    base_confidence = 1.0

    # -- detection ---------------------------------------------------------

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        score = sum(weight for pattern, weight in _FORTIOS_MARKERS if re.search(pattern, config_text))
        score -= sum(
            weight for pattern, weight in _NON_FORTIOS_MARKERS if re.search(pattern, config_text)
        )
        return max(0.0, min(1.0, score))

    # -- entry point -------------------------------------------------------

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if config_text is None or not config_text.strip():
            raise ParserError("Configuration is empty.")

        raw_lines = config_text.splitlines()
        self._warnings: List[str] = []
        self.scopes, self.settings = self._read(raw_lines)
        if not self.scopes and not self.settings:
            raise ParserError(
                "No FortiOS statements found. Expected 'config' / 'edit' / 'set' blocks "
                "as produced by 'show' or 'show full-configuration'."
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
        self._normalize_admin_access(baseline)
        self._normalize_ssh_version(baseline)
        self._normalize_idle_timeout(baseline)
        self._normalize_trusthosts(baseline)
        self._normalize_banner(baseline)
        self._normalize_credentials(baseline)
        self._normalize_password_policy(baseline)
        self._normalize_aaa(baseline)
        self._normalize_snmp(baseline)
        self._normalize_logging(baseline)
        self._normalize_ntp(baseline)

        baseline.provenance.warnings = self._warnings
        return baseline

    # -- reading the block structure ---------------------------------------

    @staticmethod
    def _tokenize(text: str) -> Tuple[str, ...]:
        """Split a statement, keeping a quoted value (a hostname, a hash) whole."""
        try:
            return tuple(shlex.split(text))
        except ValueError:  # unbalanced quote in a truncated paste
            return tuple(text.replace('"', "").split())

    def _read(self, raw_lines: List[str]) -> Tuple[List[FortiosScope], List[FortiosSetting]]:
        """Walk config/edit blocks, resolving set/unset/delete within each scope.

        The walk is the whole point. Nothing is matched by keyword alone: an
        attribute belongs to the block that contains it, so two interfaces
        cannot contaminate each other's reading, and a `config` nested inside an
        `edit` (SNMP hosts, NTP servers) nests in the path too.
        """
        scopes: List[FortiosScope] = []
        settings: List[FortiosSetting] = []
        stack: List[FortiosScope] = []
        # A value may run over several lines (a certificate, a replacement
        # message). Consume it whole rather than letting its body parse as
        # configuration - a stray `end` inside a blob would close a real block.
        open_quote = False

        for index, line in enumerate(raw_lines, start=1):
            stripped = line.strip()

            if open_quote:
                open_quote = stripped.count('"') % 2 == 0
                continue
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.count('"') % 2 == 1:
                open_quote = True
                continue

            tokens = self._tokenize(stripped)
            if not tokens:
                continue
            keyword, operands = tokens[0].lower(), tokens[1:]
            here = stack[-1].path if stack else ()

            if keyword == "config" and operands:
                path = here + tuple(operands)
                transparent = not stack and tuple(operands) in _TRANSPARENT_BLOCKS
                if transparent:
                    self._warn(
                        "Multi-VDOM configuration: settings inside 'config global' are read as "
                        "device-wide, and any 'config vdom' block is reported under its VDOM path."
                    )
                    path = here
                scope = FortiosScope(
                    path=path, kind="config", source_line=stripped, line_number=index
                )
                stack.append(scope)
                if not transparent:
                    scopes.append(scope)
                continue

            if keyword == "edit" and operands:
                scope = FortiosScope(
                    path=here + (operands[0],),
                    kind="edit",
                    source_line=stripped,
                    line_number=index,
                )
                stack.append(scope)
                scopes.append(scope)
                continue

            if keyword in ("end", "next"):
                wanted = "config" if keyword == "end" else "edit"
                if not self._close(stack, wanted):
                    self._warn(f"Unmatched '{keyword}' at line {index}; the block structure is incomplete.")
                continue

            if keyword == "set" and operands:
                settings.append(
                    FortiosSetting(
                        path=here + (operands[0],),
                        values=tuple(operands[1:]),
                        source_line=stripped,
                        line_number=index,
                    )
                )
                continue

            if keyword == "unset" and operands:
                # Not "deny everything": the attribute returns to a factory
                # default the configuration text does not state.
                self._deactivate(settings, scopes, here + (operands[0],), exact=True)
                continue

            if keyword == "delete" and operands:
                self._deactivate(settings, scopes, here + (operands[0],), exact=False)
                continue

            self._warn(
                f"Line {index} is not a FortiOS statement and was ignored: {stripped[:60]!r}."
            )

        if stack:
            self._warn(
                f"{len(stack)} block(s) were never closed with 'end' or 'next'; "
                "the configuration appears truncated."
            )
        return scopes, settings

    @staticmethod
    def _close(stack: List[FortiosScope], kind: str) -> bool:
        """Pop back to the innermost block of ``kind``, discarding any left open."""
        for depth in range(len(stack) - 1, -1, -1):
            if stack[depth].kind == kind:
                del stack[depth:]
                return True
        return False

    @staticmethod
    def _deactivate(
        settings: List[FortiosSetting],
        scopes: List[FortiosScope],
        path: Tuple[str, ...],
        *,
        exact: bool,
    ) -> None:
        """`unset` clears one attribute; `delete` removes an entry and its contents."""
        for index, setting in enumerate(settings):
            hit = setting.path == path if exact else setting.path[: len(path)] == path
            if hit and setting.active:
                settings[index] = setting.model_copy(update={"active": False})
        if exact:
            return
        for index, scope in enumerate(scopes):
            if scope.path[: len(path)] == path and scope.active:
                scopes[index] = scope.model_copy(update={"active": False})

    # -- helpers -----------------------------------------------------------

    def find(self, *prefix: str) -> List[FortiosSetting]:
        """Effective settings whose path starts with ``prefix``."""
        return [s for s in self.settings if s.active and s.starts_with(*prefix)]

    def first(self, *prefix: str) -> Optional[FortiosSetting]:
        found = self.find(*prefix)
        return found[0] if found else None

    def cleared(self, *prefix: str) -> List[FortiosSetting]:
        """Settings written and then unset or deleted — present, not in effect."""
        return [s for s in self.settings if not s.active and s.starts_with(*prefix)]

    def entries(self, *path: str) -> List[FortiosScope]:
        """Every `edit` entry directly inside the `config` block at ``path``."""
        return [
            scope
            for scope in self.scopes
            if scope.active
            and scope.kind == "edit"
            and len(scope.path) == len(path) + 1
            and scope.path[: len(path)] == tuple(path)
        ]

    def block(self, *path: str) -> Optional[FortiosScope]:
        """The `config` block at exactly ``path``, if the configuration has one."""
        return next(
            (s for s in self.scopes if s.active and s.kind == "config" and s.path == tuple(path)),
            None,
        )

    def status_of(self, *path: str) -> Optional[bool]:
        """`set status enable|disable` inside a block; None when it is not stated."""
        setting = self.first(*path, "status")
        if setting is None or not setting.values:
            return None
        return setting.value.lower() == "enable"

    def _warn(self, message: str) -> None:
        if message not in self._warnings:
            self._warnings.append(message)

    @staticmethod
    def _evidence(item) -> Tuple[str, int]:
        return item.source_line, item.line_number

    @staticmethod
    def _is_enabled(setting: Optional[FortiosSetting]) -> bool:
        return setting is not None and setting.value.lower() == "enable"

    # -- individual settings ----------------------------------------------

    def _hostname(self) -> Observation[str]:
        setting = self.first("system", "global", "hostname")
        if setting is None:
            return Observation[str].unknown("No 'set hostname' under 'config system global'.")
        return Observation[str].found(setting.value, *self._evidence(setting))

    def _normalize_admin_access(self, baseline: SecurityBaselineModel) -> None:
        """`set allowaccess` is the entire administrative-access surface.

        One statement per interface, five baseline fields, and each protocol
        read from its own keyword rather than from the presence of the line.
        """
        interfaces = self.entries("system", "interface")
        if not interfaces:
            note = (
                "No 'config system interface' block is present, so the administrative access "
                "permitted on each interface cannot be determined. FortiOS interfaces carry a "
                "factory 'allowaccess' that a 'show' excerpt omits, so absence is not proof "
                "that no access is offered."
            )
            self._warn(note)
            for field in (
                "telnet_enabled",
                "ssh_enabled",
                "http_server_enabled",
                "https_server_enabled",
            ):
                setattr(baseline, field, Observation[bool].unknown(note))
            baseline.vty_transport_input = Observation[List[str]].unknown(note)
            return

        # protocol -> earliest (line_number, setting) that permits it
        permitted: Dict[str, FortiosSetting] = {}
        unstated: List[str] = []
        for interface in interfaces:
            setting = self.first(*interface.path, "allowaccess")
            if setting is None:
                unstated.append(interface.name)
                continue
            for token in setting.values:
                permitted.setdefault(token.lower(), setting)

        if unstated:
            self._warn(
                f"{len(unstated)} interface(s) have no 'set allowaccess' statement "
                f"({', '.join(sorted(unstated))}); FortiOS applies a factory default that "
                "depends on the interface role and hardware model."
            )
        cleared = [s for s in self.cleared("system", "interface") if s.attribute == "allowaccess"]
        if cleared:
            self._warn(
                f"{len(cleared)} 'allowaccess' statement(s) were unset or deleted and are not "
                "in effect; the attribute returns to a factory default the configuration "
                "does not state."
            )

        self._resolve_protocol(baseline, "telnet_enabled", TELNET_ACCESS, permitted, unstated)
        self._resolve_protocol(baseline, "ssh_enabled", SSH_ACCESS, permitted, unstated)
        self._resolve_protocol(baseline, "http_server_enabled", "http", permitted, unstated)
        self._resolve_protocol(baseline, "https_server_enabled", "https", permitted, unstated)
        self._resolve_transports(baseline, permitted, unstated)

    def _resolve_protocol(
        self,
        baseline: SecurityBaselineModel,
        field: str,
        protocol: str,
        permitted: Dict[str, FortiosSetting],
        unstated: List[str],
    ) -> None:
        """Worst case across interfaces, and incomplete evidence is not a pass."""
        setting = permitted.get(protocol)
        if setting is not None:
            setattr(
                baseline,
                field,
                Observation[bool].found(
                    True,
                    *self._evidence(setting),
                    note=f"'{protocol}' is permitted by 'set allowaccess' on this interface.",
                ),
            )
            return

        if unstated:
            setattr(
                baseline,
                field,
                Observation[bool].unknown(
                    f"No interface permits '{protocol}' in a written 'set allowaccess', but "
                    f"{len(unstated)} interface(s) state none at all, so the factory default "
                    "for those interfaces is unknown."
                ),
            )
            return

        setattr(
            baseline,
            field,
            Observation[bool].absent(
                False,
                f"Every interface states its 'set allowaccess' and none includes '{protocol}'.",
            ),
        )

    def _resolve_transports(
        self,
        baseline: SecurityBaselineModel,
        permitted: Dict[str, FortiosSetting],
        unstated: List[str],
    ) -> None:
        """Only the login transports: `ping` and `snmp` are on allowaccess too."""
        offered = sorted(p for p in MANAGEMENT_ACCESS if p in permitted)
        plaintext = [p for p in offered if p in PLAINTEXT_ACCESS]

        if plaintext:
            worst = min(
                (permitted[p] for p in plaintext), key=lambda s: (s.line_number, s.source_line)
            )
            baseline.vty_transport_input = Observation[List[str]].found(
                offered,
                *self._evidence(worst),
                note=f"Cleartext administrative access permitted: {', '.join(plaintext)}.",
            )
            return

        if unstated:
            baseline.vty_transport_input = Observation[List[str]].unknown(
                f"{len(unstated)} interface(s) state no 'set allowaccess', so the full set of "
                "administrative transports cannot be established."
            )
            return

        if offered:
            setting = permitted[offered[0]]
            baseline.vty_transport_input = Observation[List[str]].found(
                offered,
                *self._evidence(setting),
                note="No cleartext administrative transport is permitted on any interface.",
            )
            return

        baseline.vty_transport_input = Observation[List[str]].absent(
            [],
            "Every interface states its 'set allowaccess' and none permits an interactive "
            "administrative transport.",
        )

    def _normalize_ssh_version(self, baseline: SecurityBaselineModel) -> None:
        """`set admin-ssh-v1` is the only statement that settles this.

        The knob exists in FortiOS 6.x, where it defaults to `disable`, and was
        removed in 7.x, which speaks v2 only. Both of those end at v2 — but a
        `show` prints neither, so an unwritten setting is a default this parser
        will not read a version out of.
        """
        setting = self.first("system", "global", "admin-ssh-v1")
        if setting is not None:
            enabled = setting.value.lower() == "enable"
            baseline.ssh_version = Observation[int].found(
                1 if enabled else 2,
                *self._evidence(setting),
                note=(
                    "SSHv1 compatibility is enabled, so the device accepts protocol version 1."
                    if enabled
                    else "SSHv1 compatibility is explicitly disabled, leaving protocol version 2."
                ),
            )
            return

        if baseline.ssh_enabled.detected and baseline.ssh_enabled.value is False:
            baseline.ssh_version = Observation[int].unknown(
                "No interface permits SSH, so no protocol version is enforced."
            )
            return

        note = (
            "No 'set admin-ssh-v1' under 'config system global'. The enforced SSH version is a "
            "release default - the setting exists in FortiOS 6.x and was removed in 7.x - and "
            "cannot be read from the configuration text."
        )
        self._warn(note)
        baseline.ssh_version = Observation[int].unknown(note)

    def _normalize_idle_timeout(self, baseline: SecurityBaselineModel) -> None:
        """`set admintimeout` is in minutes on the device and seconds here."""
        setting = self.first("system", "global", "admintimeout")
        if setting is not None and setting.value.isdigit():
            minutes = int(setting.value)
            baseline.vty_exec_timeout_seconds = Observation[int].found(
                minutes * 60,
                *self._evidence(setting),
                note=(
                    "'set admintimeout 0' disables the administrative idle timeout entirely."
                    if minutes == 0
                    else f"Administrative sessions idle out after {minutes} minute(s)."
                ),
            )
            return

        if setting is not None:
            note = f"Unrecognised 'admintimeout' value {setting.value!r}."
            self._warn(note)
            baseline.vty_exec_timeout_seconds = Observation[int].unknown(note)
            return

        note = (
            "No 'set admintimeout' under 'config system global'. FortiOS applies a factory "
            "idle timeout rather than none, and a 'show' omits a setting left at its default, "
            "so the effective timeout cannot be read from the configuration."
        )
        self._warn(note)
        baseline.vty_exec_timeout_seconds = Observation[int].unknown(note)

    def _normalize_trusthosts(self, baseline: SecurityBaselineModel) -> None:
        """`set trusthostN` is what restricts *who* may reach an admin account.

        Absence is conclusive: the factory trusthost is `0.0.0.0 0.0.0.0`,
        which permits every source, so an account with no trusthost written is
        an account reachable from anywhere. Worst case across accounts — one
        unrestricted administrator leaves the management plane open.
        """
        accounts = self.entries("system", "admin")
        if not accounts:
            note = (
                "No 'config system admin' block is present, so the source addresses permitted "
                "to reach an administrator account cannot be determined."
            )
            self._warn(note)
            baseline.management_acl_applied = Observation[bool].unknown(note)
            return

        restricted: List[Tuple[FortiosScope, FortiosSetting]] = []
        unrestricted: List[FortiosScope] = []
        for account in accounts:
            hosts = [s for s in self.find(*account.path) if s.attribute.startswith("trusthost")]
            narrowing = [s for s in hosts if tuple(s.values[:2]) != ANY_SOURCE]
            if narrowing:
                restricted.append((account, narrowing[0]))
            else:
                unrestricted.append(account)

        if unrestricted:
            worst = unrestricted[0]
            note = (
                f"{len(unrestricted)} administrator account(s) have no trusthost narrower than "
                f"0.0.0.0/0 ({', '.join(a.name for a in unrestricted)}), so they can be reached "
                "from any source address."
            )
            self._warn(note)
            baseline.management_acl_applied = Observation[bool].found(
                False, *self._evidence(worst), note=note
            )
            return

        _, setting = restricted[0]
        baseline.management_acl_applied = Observation[bool].found(
            True,
            *self._evidence(setting),
            note="Every administrator account is restricted to specific source addresses.",
        )

    def _normalize_banner(self, baseline: SecurityBaselineModel) -> None:
        """`set pre-login-banner` / `post-login-banner`, both `disable` by default."""
        for attribute in ("pre-login-banner", "post-login-banner"):
            setting = self.first("system", "global", attribute)
            if self._is_enabled(setting):
                baseline.login_banner_present = Observation[bool].found(
                    True, *self._evidence(setting)
                )
                return

        baseline.login_banner_present = Observation[bool].absent(
            False,
            "Neither 'set pre-login-banner enable' nor 'set post-login-banner enable' is "
            "present. Both default to disable in every FortiOS release and are written when "
            "turned on, so absence means no banner is shown.",
        )

    def _normalize_credentials(self, baseline: SecurityBaselineModel) -> None:
        """`set password ENC <hash>` versus `set password <cleartext>`.

        The `ENC` keyword is the whole distinction: FortiOS writes it in front
        of every stored hash, and a password statement without it is a
        credential someone typed in the clear.
        """
        accounts = self.entries("system", "admin")
        passwords = [
            setting
            for account in accounts
            for setting in self.find(*account.path, "password")
        ]
        hashed = [s for s in passwords if s.value.upper() == "ENC"]
        cleartext = [s for s in passwords if s.value.upper() != "ENC"]

        if not accounts:
            note = (
                "No 'config system admin' block is present, so the administrator credentials "
                "cannot be examined."
            )
            baseline.enable_secret_set = Observation[bool].unknown(note)
            baseline.enable_password_present = Observation[bool].unknown(note)
            baseline.password_encryption = Observation[bool].unknown(note)
            return

        if hashed:
            baseline.enable_secret_set = Observation[bool].found(
                True,
                *self._evidence(hashed[0]),
                note="An administrator password is stored as a hash ('ENC').",
            )
        else:
            baseline.enable_secret_set = Observation[bool].absent(
                False,
                "No administrator account under 'config system admin' carries a hashed "
                "'set password ENC' statement. FortiOS writes the stored hash into the "
                "configuration, so its absence means no hashed credential is set.",
            )

        if cleartext:
            baseline.enable_password_present = Observation[bool].found(
                True,
                *self._evidence(cleartext[0]),
                note="An administrator password is written without the 'ENC' keyword, so it "
                "is stored in recoverable form.",
            )
        else:
            baseline.enable_password_present = Observation[bool].absent(
                False, "No administrator password is written without the 'ENC' keyword."
            )

        # As on Junos, this is a platform property rather than a setting:
        # FortiOS hashes stored administrator passwords and has no equivalent
        # of `service password-encryption` to turn on or off. It is still
        # recorded as an observation so every vendor reads the same way.
        if cleartext:
            baseline.password_encryption = Observation[bool].found(
                False,
                *self._evidence(cleartext[0]),
                note="A password is stored in the configuration without the 'ENC' keyword.",
            )
        elif hashed:
            baseline.password_encryption = Observation[bool].found(
                True,
                *self._evidence(hashed[0]),
                note="FortiOS stores administrator passwords hashed; every password statement "
                "in this configuration carries the 'ENC' keyword.",
            )
        else:
            baseline.password_encryption = Observation[bool].absent(
                True,
                "FortiOS hashes stored administrator passwords and offers no equivalent of "
                "'service password-encryption'; no cleartext password statement is present.",
            )

    def _normalize_password_policy(self, baseline: SecurityBaselineModel) -> None:
        """A minimum length that is configured is not necessarily enforced.

        `config system password-policy` carries its own `set status`, and a
        policy with `status disable` enforces nothing however long its
        `minimum-length` says. This is the clearest case in the vendor of a
        setting being present in the text and absent from the device.
        """
        if self.block("system", "password-policy") is None:
            baseline.password_min_length = Observation[int].absent(
                0,
                "No 'config system password-policy' block is present. FortiOS enforces no "
                "minimum password length until a policy is configured, and configuring one "
                "writes the block.",
            )
            return

        status = self.status_of("system", "password-policy")
        minimum = self.first("system", "password-policy", "minimum-length")

        if status is False:
            evidence = self.first("system", "password-policy", "status")
            baseline.password_min_length = Observation[int].found(
                0,
                *self._evidence(evidence),
                note="The password policy is configured but 'set status disable' switches it "
                "off, so no minimum length is enforced.",
            )
            return

        if status is None:
            note = (
                "'config system password-policy' is present but states no 'set status', so "
                "whether the policy is enforced depends on a factory default the configuration "
                "does not state."
            )
            self._warn(note)
            baseline.password_min_length = Observation[int].unknown(note)
            return

        if minimum is not None and minimum.value.isdigit():
            baseline.password_min_length = Observation[int].found(
                int(minimum.value), *self._evidence(minimum)
            )
            return

        note = (
            "The password policy is enabled but states no 'minimum-length', so the enforced "
            "minimum is a FortiOS default rather than a configured value."
        )
        self._warn(note)
        baseline.password_min_length = Observation[int].unknown(note)

    def _normalize_aaa(self, baseline: SecurityBaselineModel) -> None:
        """Centralised authentication: a server, and an administrator using it."""
        servers = [
            setting
            for family in ("radius", "tacacs+")
            for entry in self.entries("user", family)
            for setting in self.find(*entry.path, "server")
        ]
        remote_admins = [
            setting
            for account in self.entries("system", "admin")
            for setting in self.find(*account.path, "remote-auth")
            if setting.value.lower() == "enable"
        ]

        if remote_admins:
            baseline.aaa_enabled = Observation[bool].found(
                True,
                *self._evidence(remote_admins[0]),
                note="An administrator account authenticates against a remote server.",
            )
            if not servers:
                self._warn(
                    "An administrator has 'set remote-auth enable' but no RADIUS or TACACS+ "
                    "server is configured under 'config user'; authentication will fall back "
                    "to the local account."
                )
            return

        if servers:
            baseline.aaa_enabled = Observation[bool].found(
                True,
                *self._evidence(servers[0]),
                note="A centralised authentication server is configured.",
            )
            self._warn(
                "A RADIUS/TACACS+ server is configured but no administrator account has "
                "'set remote-auth enable', so administrative logins are still local."
            )
            return

        baseline.aaa_enabled = Observation[bool].absent(
            False,
            "No 'config user radius' or 'config user tacacs+' server and no administrator "
            "with 'set remote-auth enable'. FortiOS writes both when configured, so their "
            "absence means administrative authentication is local only.",
        )

    def _normalize_snmp(self, baseline: SecurityBaselineModel) -> None:
        """Communities that are actually reachable, not merely written down.

        Two switches gate them: the agent's own `config system snmp sysinfo`
        status, and each community's `set status`. A community behind either
        one turned off cannot be queried, so it is not reported as a finding.
        """
        agent_enabled = self.status_of("system", "snmp", "sysinfo")
        entries = self.entries("system", "snmp", "community")

        if agent_enabled is False:
            evidence = self.first("system", "snmp", "sysinfo", "status")
            baseline.snmp_communities = Observation[List[SnmpCommunity]].found(
                [],
                *self._evidence(evidence),
                note="The SNMP agent is switched off with 'set status disable', so no "
                f"community is reachable ({len(entries)} configured).",
            )
            return

        if not entries:
            baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
                [],
                "No 'config system snmp community' entries are present. FortiOS writes SNMP "
                "communities into the configuration, so absence means none is defined.",
            )
            return

        communities: List[SnmpCommunity] = []
        disabled: List[str] = []
        for entry in entries:
            name = self.first(*entry.path, "name")
            if self.status_of(*entry.path) is False:
                disabled.append(name.value if name else entry.name)
                continue
            communities.append(self._community(entry, name))

        if disabled:
            self._warn(
                f"{len(disabled)} SNMP community/communities are configured but disabled with "
                f"'set status disable' and are not reachable: {', '.join(sorted(disabled))}."
            )

        if not communities:
            evidence = entries[0]
            baseline.snmp_communities = Observation[List[SnmpCommunity]].found(
                [],
                *self._evidence(evidence),
                note="Every configured SNMP community is disabled with 'set status disable'.",
            )
            return

        first = self.first(*entries[0].path, "name") or entries[0]
        baseline.snmp_communities = Observation[List[SnmpCommunity]].found(
            communities,
            *self._evidence(first),
            note=f"{len(communities)} reachable SNMP v1/v2c community string(s) configured.",
        )

    def _community(
        self, entry: FortiosScope, name: Optional[FortiosSetting]
    ) -> SnmpCommunity:
        """One community entry, with the hosts allowed to query it.

        ``access`` is always read-only, and that is a statement about the
        platform rather than about this configuration: the FortiOS SNMP agent
        serves v1/v2c queries and sends traps, and supports no community-scoped
        write. There is no `set` that would make one read-write.
        """
        hosts = [
            setting.values[0]
            for host in self.entries(*entry.path, "hosts")
            for setting in self.find(*host.path, "ip")
            if setting.values
        ]
        evidence = name or entry
        return SnmpCommunity(
            name=name.value if name else entry.name,
            access="ro",
            acl=", ".join(hosts) if hosts else None,
            source_line=evidence.source_line,
            line_number=evidence.line_number,
        )

    def _normalize_logging(self, baseline: SecurityBaselineModel) -> None:
        """Remote syslog, and on-box retention, each gated on its own status."""
        hosts: List[Tuple[str, FortiosSetting]] = []
        configured_but_off = 0
        for suffix in ("", "2", "3", "4"):
            path = ("log", f"syslogd{suffix}", "setting")
            server = self.first(*path, "server")
            if server is None or not server.values:
                continue
            if self.status_of(*path) is False:
                configured_but_off += 1
                continue
            hosts.append((server.value, server))

        if configured_but_off:
            self._warn(
                f"{configured_but_off} syslog server(s) are configured but disabled with "
                "'set status disable', so nothing is shipped to them."
            )

        if hosts:
            baseline.logging_hosts = Observation[List[str]].found(
                sorted({address for address, _ in hosts}), *self._evidence(hosts[0][1])
            )
        else:
            baseline.logging_hosts = Observation[List[str]].absent(
                [],
                "No enabled 'config log syslogd setting' server is present, so no remote "
                "syslog destination is configured.",
            )

        buffered = self._normalize_local_logging(baseline)

        if hosts or buffered:
            evidence = hosts[0][1] if hosts else buffered
            baseline.logging_enabled = Observation[bool].found(
                True,
                *self._evidence(evidence),
                note="At least one log destination (syslog server or on-box log) is enabled.",
            )
        elif baseline.logging_buffered.detected:
            baseline.logging_enabled = Observation[bool].absent(
                False,
                "No syslog server and no on-box log store is enabled, so nothing is retained.",
            )
        else:
            baseline.logging_enabled = Observation[bool].unknown(
                "No syslog server is configured, and whether the device retains logs locally "
                "could not be established, so it cannot be said that nothing is logged."
            )

    def _normalize_local_logging(
        self, baseline: SecurityBaselineModel
    ) -> Optional[FortiosSetting]:
        """`config log memory setting` / `config log disk setting`.

        Absence is *not* conclusive here: which store a FortiGate enables out of
        the box depends on whether the model has a disk, so a configuration that
        mentions neither has not proven that neither is running.
        """
        for store in ("memory", "disk"):
            path = ("log", store, "setting")
            if self.status_of(*path) is True:
                setting = self.first(*path, "status")
                baseline.logging_buffered = Observation[bool].found(
                    True,
                    *self._evidence(setting),
                    note=f"On-box {store} logging is enabled.",
                )
                return setting

        explicit = [
            self.first("log", store, "setting", "status")
            for store in ("memory", "disk")
            if self.status_of("log", store, "setting") is False
        ]
        if explicit and len(explicit) == len(
            [s for s in ("memory", "disk") if self.block("log", s, "setting")]
        ):
            baseline.logging_buffered = Observation[bool].found(
                False,
                *self._evidence(explicit[0]),
                note="Every on-box log store present in the configuration is disabled.",
            )
            return None

        note = (
            "No enabled 'config log memory setting' or 'config log disk setting' is present. "
            "Which on-box log store a FortiGate runs by default depends on the hardware model, "
            "so absence does not prove that logs are not retained."
        )
        self._warn(note)
        baseline.logging_buffered = Observation[bool].unknown(note)
        return None

    def _normalize_ntp(self, baseline: SecurityBaselineModel) -> None:
        """`config system ntp`: custom servers are named, FortiGuard's are not."""
        if self.block("system", "ntp") is None:
            note = (
                "No 'config system ntp' block is present. FortiOS synchronises against "
                "FortiGuard's servers out of the box and a 'show' omits settings left at "
                "their default, so absence does not prove the clock is unsynchronised."
            )
            self._warn(note)
            baseline.ntp_servers = Observation[List[str]].unknown(note)
            return

        ntpsync = self.first("system", "ntp", "ntpsync")
        if ntpsync is not None and ntpsync.value.lower() == "disable":
            baseline.ntp_servers = Observation[List[str]].found(
                [],
                *self._evidence(ntpsync),
                note="'set ntpsync disable' switches time synchronisation off entirely.",
            )
            return

        addresses: List[Tuple[str, FortiosSetting]] = []
        for entry in self.entries("system", "ntp", "ntpserver"):
            server = self.first(*entry.path, "server")
            if server is not None and server.values:
                addresses.append((server.value, server))

        if addresses:
            baseline.ntp_servers = Observation[List[str]].found(
                sorted({address for address, _ in addresses}),
                *self._evidence(addresses[0][1]),
                note=f"{len({a for a, _ in addresses})} NTP time source(s) configured.",
            )
            return

        note = (
            "'config system ntp' names no server under 'config ntpserver', which means the "
            "device is synchronising against FortiGuard's default servers. Time synchronisation "
            "is configured, but the configuration states no address to report."
        )
        self._warn(note)
        baseline.ntp_servers = Observation[List[str]].unknown(note)
