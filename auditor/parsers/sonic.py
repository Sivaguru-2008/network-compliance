"""Deterministic SONiC parser.

SONiC configurations are stored as JSON (config_db.json), which is a
fundamentally different format from the CLI-based configs of every other
vendor this tool supports.  The parser reads the canonical config_db
structure and extracts security-relevant settings from well-known tables.

Many security-relevant settings in a SONiC deployment live at the Linux
level (sshd_config, PAM, /etc/motd) rather than in config_db.json.  For
those settings the parser reports NEEDS_REVIEW, not PASS — because the
absence of a setting from config_db does not prove the device is
insecure, only that the configuration database does not describe it.

Detection relies on SONiC-specific JSON keys: ``DEVICE_METADATA``,
``NTP_SERVER``, ``SNMP_COMMUNITY``, ``SYSLOG_SERVER``, ``ACL_TABLE``,
``FEATURE``, and others.  A valid JSON document whose top-level keys
match the SONiC config_db schema is claimed; CLI-format configs never are.
"""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry

_SONIC_KEYS = frozenset({
    "DEVICE_METADATA", "NTP_SERVER", "SYSLOG_SERVER", "SNMP_COMMUNITY",
    "TACACS_SERVER", "RADIUS_SERVER", "AAA", "ACL_TABLE", "ACL_RULE",
    "FEATURE", "LOOPBACK_INTERFACE", "MGMT_INTERFACE", "MGMT_VRF_CONFIG",
    "SNMP", "SSH_SERVER", "TACACS", "INTERFACE", "PORTCHANNEL",
    "BGP_NEIGHBOR", "ROUTE_TABLE", "VLAN", "CRM", "KDUMP",
})


@registry.register
class SonicParser(VendorParser):
    """Parser for SONiC config_db.json configurations."""

    name = "sonic"
    vendor = "sonic"
    os_family = "sonic"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        try:
            data = json.loads(config_text)
        except (json.JSONDecodeError, ValueError):
            return 0.0
        if not isinstance(data, dict):
            return 0.0

        score = 0.0
        if "DEVICE_METADATA" in data:
            score += 0.40
        matches = len(_SONIC_KEYS & set(data.keys()))
        score += min(0.40, matches * 0.08)
        return max(0.0, min(1.0, score))

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if config_text is None or not config_text.strip():
            raise ParserError("Configuration is empty.")

        try:
            self._data: Dict[str, Any] = json.loads(config_text)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ParserError(f"Configuration is not valid JSON: {exc}") from exc

        if not isinstance(self._data, dict):
            raise ParserError("Configuration JSON must be a top-level object.")

        if not (set(self._data.keys()) & _SONIC_KEYS):
            raise ParserError(
                "No SONiC config_db tables found. Expected keys like "
                "DEVICE_METADATA, NTP_SERVER, SNMP_COMMUNITY, etc."
            )

        self._raw_lines = config_text.splitlines()
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
            config_line_count=len(self._raw_lines),
        )

        baseline.hostname = self._hostname()
        self._normalize_ssh(baseline)
        self._normalize_telnet(baseline)
        self._normalize_http(baseline)
        self._normalize_idle_timeout(baseline)
        self._normalize_banner(baseline)
        self._normalize_credentials(baseline)
        self._normalize_aaa(baseline)
        self._normalize_snmp(baseline)
        self._normalize_logging(baseline)
        self._normalize_ntp(baseline)
        self._normalize_management_acl(baseline)

        baseline.provenance.warnings = self._warnings
        return baseline

    # -- helpers -----------------------------------------------------------

    def _find_line(self, needle: str) -> Tuple[Optional[str], Optional[int]]:
        for idx, line in enumerate(self._raw_lines, 1):
            if needle in line:
                return line.strip(), idx
        return None, None

    def _table(self, *keys: str) -> Any:
        current = self._data
        for key in keys:
            if not isinstance(current, dict) or key not in current:
                return None
            current = current[key]
        return current

    def _warn(self, message: str) -> None:
        if message not in self._warnings:
            self._warnings.append(message)

    _LINUX_NOTE = (
        "This setting is managed at the Linux level (sshd_config, PAM, or system "
        "configuration) and is not represented in the SONiC config_db. Its state "
        "cannot be determined from config_db.json alone."
    )

    # -- hostname ----------------------------------------------------------

    def _hostname(self) -> Observation[str]:
        meta = self._table("DEVICE_METADATA", "localhost")
        if isinstance(meta, dict) and "hostname" in meta:
            line, lineno = self._find_line('"hostname"')
            return Observation[str].found(
                meta["hostname"], line or '"hostname"', lineno,
            )
        return Observation[str].unknown("No hostname in DEVICE_METADATA.")

    # -- SSH ---------------------------------------------------------------

    def _normalize_ssh(self, baseline: SecurityBaselineModel) -> None:
        feature = self._table("FEATURE", "sshd")
        if isinstance(feature, dict) and "state" in feature:
            enabled = feature["state"].lower() == "enabled"
            line, lineno = self._find_line('"sshd"')
            baseline.ssh_enabled = Observation[bool].found(
                enabled, line or '"sshd"', lineno,
                note=f"SSH daemon feature is {'enabled' if enabled else 'disabled'}.",
            )
        else:
            note = (
                "No FEATURE.sshd entry in config_db. The SSH daemon is typically "
                "enabled by default on SONiC but its state cannot be confirmed from "
                "config_db.json alone."
            )
            self._warn(note)
            baseline.ssh_enabled = Observation[bool].unknown(note)

        baseline.ssh_version = Observation[int].unknown(
            "SSH protocol version is configured in sshd_config, not in config_db.json. "
            "Modern SONiC deployments enforce SSHv2 but this cannot be confirmed from "
            "config_db alone."
        )

    # -- telnet ------------------------------------------------------------

    def _normalize_telnet(self, baseline: SecurityBaselineModel) -> None:
        feature = self._table("FEATURE", "telnet")
        if isinstance(feature, dict) and "state" in feature:
            enabled = feature["state"].lower() == "enabled"
            line, lineno = self._find_line('"telnet"')
            baseline.telnet_enabled = Observation[bool].found(
                enabled, line or '"telnet"', lineno,
                note=f"Telnet feature is {'enabled' if enabled else 'disabled'}.",
            )
            if enabled:
                baseline.vty_transport_input = Observation[List[str]].found(
                    sorted({"telnet", "ssh"}), line or '"telnet"', lineno,
                )
        else:
            baseline.telnet_enabled = Observation[bool].unknown(
                "No FEATURE.telnet entry in config_db. SONiC does not typically "
                "run a telnet daemon, but its state cannot be confirmed."
            )

        if not baseline.vty_transport_input.detected:
            if baseline.ssh_enabled.detected and baseline.ssh_enabled.value:
                baseline.vty_transport_input = Observation[List[str]].found(
                    ["ssh"],
                    baseline.ssh_enabled.source_line or "",
                    baseline.ssh_enabled.line_number,
                )
            else:
                baseline.vty_transport_input = Observation[List[str]].unknown(
                    "Management transport list cannot be fully determined from config_db."
                )

    # -- HTTP/HTTPS --------------------------------------------------------

    def _normalize_http(self, baseline: SecurityBaselineModel) -> None:
        rest = self._table("FEATURE", "rest_api") or self._table("RESTAPI")
        if isinstance(rest, dict):
            state = rest.get("state", rest.get("STATUS", "")).lower()
            if state:
                enabled = state == "enabled"
                line, lineno = self._find_line("rest_api") or self._find_line("RESTAPI")
                baseline.http_server_enabled = Observation[bool].unknown(
                    "SONiC REST API state is known but whether it serves HTTP "
                    "(vs HTTPS only) cannot be determined from config_db."
                )
                baseline.https_server_enabled = Observation[bool].found(
                    enabled, line or "RESTAPI", lineno,
                    note=f"REST API is {'enabled' if enabled else 'disabled'}.",
                )
                return

        note = (
            "HTTP/HTTPS management API status is not represented in config_db.json. "
            "SONiC may or may not serve a REST API depending on the image build."
        )
        baseline.http_server_enabled = Observation[bool].unknown(note)
        baseline.https_server_enabled = Observation[bool].unknown(note)

    # -- idle timeout ------------------------------------------------------

    def _normalize_idle_timeout(self, baseline: SecurityBaselineModel) -> None:
        baseline.vty_exec_timeout_seconds = Observation[int].unknown(self._LINUX_NOTE)

    # -- banner ------------------------------------------------------------

    def _normalize_banner(self, baseline: SecurityBaselineModel) -> None:
        baseline.login_banner_present = Observation[bool].unknown(
            "Login banners are configured via /etc/motd or sshd_config, "
            "not in config_db.json."
        )

    # -- credentials -------------------------------------------------------

    def _normalize_credentials(self, baseline: SecurityBaselineModel) -> None:
        note = (
            "User credentials and privileged access are managed at the Linux level "
            "(passwd/shadow) and are not stored in config_db.json."
        )
        baseline.enable_secret_set = Observation[bool].unknown(note)
        baseline.enable_password_present = Observation[bool].unknown(note)
        baseline.password_encryption = Observation[bool].unknown(note)
        baseline.password_min_length = Observation[int].unknown(
            "Password policy is managed via PAM and is not in config_db.json."
        )

    # -- AAA ---------------------------------------------------------------

    def _normalize_aaa(self, baseline: SecurityBaselineModel) -> None:
        aaa = self._table("AAA")
        tacacs = self._table("TACACS_SERVER")
        radius = self._table("RADIUS_SERVER")

        if isinstance(aaa, dict):
            auth = aaa.get("authentication", {})
            login = auth.get("login", "") if isinstance(auth, dict) else ""
            if isinstance(login, str) and any(
                m in login.lower() for m in ("tacacs", "radius")
            ):
                line, lineno = self._find_line('"login"')
                baseline.aaa_enabled = Observation[bool].found(
                    True, line or '"AAA"', lineno,
                    note=f"AAA authentication login method: {login}.",
                )
                return

        if isinstance(tacacs, dict) and tacacs:
            line, lineno = self._find_line("TACACS_SERVER")
            baseline.aaa_enabled = Observation[bool].found(
                True, line or '"TACACS_SERVER"', lineno,
                note="TACACS+ server(s) configured.",
            )
            return

        if isinstance(radius, dict) and radius:
            line, lineno = self._find_line("RADIUS_SERVER")
            baseline.aaa_enabled = Observation[bool].found(
                True, line or '"RADIUS_SERVER"', lineno,
                note="RADIUS server(s) configured.",
            )
            return

        baseline.aaa_enabled = Observation[bool].absent(
            False,
            "No AAA authentication, TACACS_SERVER, or RADIUS_SERVER entries in "
            "config_db. Authentication is local only.",
        )

    # -- SNMP --------------------------------------------------------------

    def _normalize_snmp(self, baseline: SecurityBaselineModel) -> None:
        snmp = self._table("SNMP_COMMUNITY")
        if isinstance(snmp, dict) and snmp:
            communities = []
            for name, attrs in snmp.items():
                access = None
                if isinstance(attrs, dict):
                    raw_type = attrs.get("TYPE", "").lower()
                    if raw_type in ("ro", "rw"):
                        access = raw_type
                communities.append(SnmpCommunity(
                    name=name,
                    access=access,
                    acl=None,
                    source_line=f"SNMP_COMMUNITY.{name}",
                    line_number=self._find_line(f'"{name}"')[1],
                ))
            line, lineno = self._find_line("SNMP_COMMUNITY")
            baseline.snmp_communities = Observation[List[SnmpCommunity]].found(
                communities, line or "SNMP_COMMUNITY", lineno,
                note=f"{len(communities)} SNMP community string(s) configured.",
            )
            return

        snmp_table = self._table("SNMP")
        if isinstance(snmp_table, dict):
            baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
                [],
                "SNMP is configured but no SNMP_COMMUNITY entries are present "
                "(consistent with an SNMPv3-only deployment).",
            )
            return

        baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
            [],
            "No SNMP_COMMUNITY or SNMP configuration in config_db.",
        )

    # -- logging -----------------------------------------------------------

    def _normalize_logging(self, baseline: SecurityBaselineModel) -> None:
        syslog = self._table("SYSLOG_SERVER")
        if isinstance(syslog, dict) and syslog:
            hosts = sorted(syslog.keys())
            line, lineno = self._find_line("SYSLOG_SERVER")
            baseline.logging_hosts = Observation[List[str]].found(
                hosts, line or "SYSLOG_SERVER", lineno,
            )
            baseline.logging_enabled = Observation[bool].found(
                True, line or "SYSLOG_SERVER", lineno,
                note="At least one syslog server is configured.",
            )
        else:
            baseline.logging_hosts = Observation[List[str]].absent(
                [], "No SYSLOG_SERVER entries in config_db.",
            )
            baseline.logging_enabled = Observation[bool].unknown(
                "No SYSLOG_SERVER entries. SONiC may still log locally via rsyslog "
                "but this cannot be confirmed from config_db."
            )

        baseline.logging_buffered = Observation[bool].unknown(
            "Local log buffering is managed by rsyslog at the Linux level, "
            "not in config_db.json."
        )

    # -- NTP ---------------------------------------------------------------

    def _normalize_ntp(self, baseline: SecurityBaselineModel) -> None:
        ntp = self._table("NTP_SERVER")
        if isinstance(ntp, dict) and ntp:
            addresses = sorted(ntp.keys())
            line, lineno = self._find_line("NTP_SERVER")
            baseline.ntp_servers = Observation[List[str]].found(
                addresses, line or "NTP_SERVER", lineno,
                note=f"{len(addresses)} NTP time source(s) configured.",
            )
            return

        baseline.ntp_servers = Observation[List[str]].absent(
            [],
            "No NTP_SERVER entries in config_db. The clock is not synchronised "
            "via config_db configuration.",
        )

    # -- management ACL ----------------------------------------------------

    def _normalize_management_acl(self, baseline: SecurityBaselineModel) -> None:
        acl_table = self._table("ACL_TABLE")
        if not isinstance(acl_table, dict):
            baseline.management_acl_applied = Observation[bool].unknown(
                "No ACL_TABLE in config_db; management access restrictions "
                "cannot be determined."
            )
            return

        def _services(attrs: dict) -> set:
            svc = attrs.get("services")
            if isinstance(svc, list):
                return {str(s).upper() for s in svc}
            if isinstance(svc, str):
                return {svc.upper()}
            return set()

        ctrl_plane = {
            name: attrs for name, attrs in acl_table.items()
            if isinstance(attrs, dict) and attrs.get("type", "").upper() == "CTRLPLANE"
        }
        # A control-plane ACL restricts *management* access only if it actually
        # governs the SSH management plane. A CTRLPLANE ACL scoped to NTP, SNMP or
        # BGP says nothing about who may open a management session, so its mere
        # presence must not pass this control.
        ssh_acls = [name for name, attrs in ctrl_plane.items() if "SSH" in _services(attrs)]

        if ssh_acls:
            line, lineno = self._find_line(ssh_acls[0])
            baseline.management_acl_applied = Observation[bool].found(
                True, line or f"ACL_TABLE.{ssh_acls[0]}", lineno,
                note=f"Control-plane ACL(s) restrict SSH management access: {', '.join(ssh_acls)}.",
            )
            return

        if ctrl_plane:
            other = sorted({s for attrs in ctrl_plane.values() for s in _services(attrs)})
            svc_note = f" (services: {', '.join(other)})" if other else ""
            baseline.management_acl_applied = Observation[bool].unknown(
                f"Control-plane ACL(s) present but none govern the SSH management "
                f"service{svc_note}; SSH source restriction cannot be confirmed from "
                "config_db and may be enforced outside it (e.g. iptables)."
            )
            return

        baseline.management_acl_applied = Observation[bool].absent(
            False,
            "No control-plane ACL (type CTRLPLANE) in ACL_TABLE. Management "
            "services are not restricted by source address in config_db.",
        )
