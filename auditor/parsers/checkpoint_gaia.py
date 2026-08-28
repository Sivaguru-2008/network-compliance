"""Deterministic Check Point Gaia OS parser.

Check Point Gaia is the operating system for Check Point Security Gateways and
Management Servers. Configuration is exported via ``show configuration`` in clish,
which produces a flat list of ``set`` and ``add`` commands -- one per line, no
block nesting.

CLI reference verified against the R81 Gaia Administration Guide at
sc1.checkpoint.com/documents/R81/WebAdminGuides/EN/CP_R81_Gaia_AdminGuide/.
"""

import hashlib
import re
from typing import List, Optional, Sequence, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry

_GAIA_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*set\s+password-controls\s+", 0.30),
    (r"(?im)^\s*set\s+ntp\s+active\s+", 0.25),
    (r"(?im)^\s*set\s+snmp\s+agent\s+", 0.15),
    (r"(?im)^\s*set\s+inactivity-timeout\s+", 0.15),
    (r"(?im)^\s*set\s+message\s+banner\s+", 0.10),
    (r"(?im)^\s*add\s+syslog\s+log-remote-address\s+", 0.15),
    (r"(?im)^\s*set\s+web\s+ssl-port\s+", 0.10),
    (r"(?im)^\s*set\s+domainname\s+", 0.10),
]

_NON_GAIA_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*line\s+vty\b", 0.40),
    (r"(?im)^\s*ip\s+http\s+server\b", 0.30),
    (r"(?im)^\s*config\s+system\s+global\b", 0.90),
    (r"(?im)^\s*set\s+system\s+host-name\b", 0.80),
    (r"(?im)^\s*sysname\s+\S+", 0.50),
    (r"(?im)^\s*<\?xml", 0.90),
    (r"(?im)\"DEVICE_METADATA\"", 0.90),
    (r"(?im)^\s*user-interface\s+vty\b", 0.50),
]


@registry.register
class CheckPointGaiaParser(VendorParser):
    """Grammar-based parser for Check Point Gaia OS configurations."""

    name = "checkpoint_gaia"
    vendor = "checkpoint"
    os_family = "gaia"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        score = sum(w for p, w in _GAIA_MARKERS if re.search(p, config_text))
        score -= sum(w for p, w in _NON_GAIA_MARKERS if re.search(p, config_text))
        return max(0.0, min(1.0, score))

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if config_text is None or not config_text.strip():
            raise ParserError("Configuration is empty.")

        self._lines = config_text.splitlines()
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
            source_sha256=hashlib.sha256(
                config_text.encode("utf-8", errors="replace")
            ).hexdigest(),
            config_line_count=len(self._lines),
        )

        self._normalize_hostname(baseline)
        self._normalize_ntp(baseline)
        self._normalize_dns(baseline)
        self._normalize_snmp(baseline)
        self._normalize_syslog(baseline)
        self._normalize_password_controls(baseline)
        self._normalize_inactivity_timeout(baseline)
        self._normalize_banner(baseline)
        self._normalize_web(baseline)
        self._normalize_aaa(baseline)

        for field in baseline.observable_fields():
            observation = getattr(baseline, field)
            if observation.note == "Parser did not evaluate this field.":
                setattr(
                    baseline,
                    field,
                    type(observation).unknown(
                        "Check Point Gaia parser does not evaluate this field."
                    ),
                )

        baseline.provenance.warnings = self._warnings
        return baseline

    # -- helpers --------------------------------------------------------------

    def _scan(self, pattern: str) -> List[Tuple[re.Match, str, int]]:
        results = []
        for idx, line in enumerate(self._lines, start=1):
            m = re.match(pattern, line, re.IGNORECASE)
            if m:
                results.append((m, line.strip(), idx))
        return results

    def _first(self, pattern: str) -> Optional[Tuple[re.Match, str, int]]:
        hits = self._scan(pattern)
        return hits[0] if hits else None

    # -- hostname -------------------------------------------------------------

    def _normalize_hostname(self, baseline: SecurityBaselineModel) -> None:
        hit = self._first(r"^\s*set\s+hostname\s+(\S+)")
        if hit:
            m, raw, line = hit
            baseline.hostname = Observation[str].found(m.group(1), raw, line)
        else:
            baseline.hostname = Observation[str].unknown("No 'set hostname' statement found.")

    # -- NTP ------------------------------------------------------------------

    def _normalize_ntp(self, baseline: SecurityBaselineModel) -> None:
        servers: List[str] = []
        evidence_line: Optional[str] = None
        evidence_num: Optional[int] = None

        for m, raw, line in self._scan(
            r"^\s*set\s+ntp\s+server\s+(?:primary|secondary)\s+(\S+)"
        ):
            servers.append(m.group(1))
            if evidence_line is None:
                evidence_line, evidence_num = raw, line

        if servers:
            baseline.ntp_servers = Observation[List[str]].found(
                servers, evidence_line, evidence_num
            )
            baseline.ntp_redundant = Observation[bool].found(
                len(servers) >= 2, evidence_line, evidence_num
            )
        else:
            baseline.ntp_servers = Observation[List[str]].absent(
                [], "No NTP servers configured."
            )
            baseline.ntp_redundant = Observation[bool].absent(
                False, "No redundant NTP servers configured."
            )

    # -- DNS ------------------------------------------------------------------

    def _normalize_dns(self, baseline: SecurityBaselineModel) -> None:
        servers: List[str] = []
        evidence_line: Optional[str] = None
        evidence_num: Optional[int] = None

        for pattern in [
            r"^\s*set\s+dns\s+primary\s+(\S+)",
            r"^\s*set\s+dns\s+secondary\s+(\S+)",
            r"^\s*set\s+dns\s+tertiary\s+(\S+)",
        ]:
            hit = self._first(pattern)
            if hit:
                m, raw, line = hit
                servers.append(m.group(1))
                if evidence_line is None:
                    evidence_line, evidence_num = raw, line

        if servers:
            baseline.dns_servers = Observation[List[str]].found(
                servers, evidence_line, evidence_num
            )
        else:
            baseline.dns_servers = Observation[List[str]].absent(
                [], "No DNS servers configured."
            )

    # -- SNMP -----------------------------------------------------------------

    def _normalize_snmp(self, baseline: SecurityBaselineModel) -> None:
        agent_hit = self._first(r"^\s*set\s+snmp\s+agent\s+(on|off)\b")

        if agent_hit:
            m, raw, line = agent_hit
            enabled = m.group(1).lower() == "on"
            baseline.snmp_agent_enabled = Observation[bool].found(enabled, raw, line)
        else:
            baseline.snmp_agent_enabled = Observation[bool].absent(
                False, "SNMP agent is not configured."
            )

        communities: List[SnmpCommunity] = []
        for m, raw, line in self._scan(
            r"^\s*set\s+snmp\s+community\s+(\S+)\s+(read-only|read-write)"
        ):
            name = m.group(1)
            access = "ro" if m.group(2) == "read-only" else "rw"
            communities.append(
                SnmpCommunity(
                    name=name,
                    access=access,
                    acl=None,
                    source_line=raw,
                    line_number=line,
                )
            )

        if communities:
            baseline.snmp_communities = Observation[List[SnmpCommunity]].found(
                communities,
                communities[0].source_line,
                communities[0].line_number,
            )
        else:
            baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
                [], "No SNMP community strings configured."
            )

        # SNMPv3 check: agent-version v3-Only means v3 users should be present
        version_hit = self._first(r"^\s*set\s+snmp\s+agent-version\s+(\S+)")
        if version_hit:
            m, raw, line = version_hit
            is_v3_only = m.group(1).lower() == "v3-only"
            baseline.snmp_v3_users_present = Observation[bool].found(
                is_v3_only, raw, line,
                note="SNMPv3-Only mode implies v3 users are configured."
                if is_v3_only
                else "SNMP agent accepts any version, not restricted to v3.",
            )
        else:
            baseline.snmp_v3_users_present = Observation[bool].unknown(
                "SNMP agent version preference is not configured."
            )

    # -- syslog ---------------------------------------------------------------

    def _normalize_syslog(self, baseline: SecurityBaselineModel) -> None:
        hosts: List[str] = []
        evidence_line: Optional[str] = None
        evidence_num: Optional[int] = None

        for m, raw, line in self._scan(
            r"^\s*add\s+syslog\s+log-remote-address\s+(\S+)"
        ):
            hosts.append(m.group(1))
            if evidence_line is None:
                evidence_line, evidence_num = raw, line

        if hosts:
            baseline.logging_enabled = Observation[bool].found(
                True, evidence_line, evidence_num,
                note="Remote syslog servers are configured.",
            )
            baseline.logging_hosts = Observation[List[str]].found(
                hosts, evidence_line, evidence_num
            )
        else:
            baseline.logging_enabled = Observation[bool].absent(
                False, "No remote syslog servers configured."
            )
            baseline.logging_hosts = Observation[List[str]].absent(
                [], "No syslog hosts configured."
            )

        # Check audit logging
        audit_hit = self._first(r"^\s*set\s+syslog\s+auditlog\s+(\S+)")
        cplogs_hit = self._first(r"^\s*set\s+syslog\s+cplogs\s+(on|off)")
        mgmt_hit = self._first(r"^\s*set\s+syslog\s+mgmtauditlogs\s+(on|off)")

        audit_on = audit_hit and audit_hit[0].group(1).lower() == "permanent"
        cp_on = cplogs_hit and cplogs_hit[0].group(1).lower() == "on"
        mgmt_on = mgmt_hit and mgmt_hit[0].group(1).lower() == "on"

        if audit_on or cp_on or mgmt_on:
            evidence = audit_hit or cplogs_hit or mgmt_hit
            baseline.event_logging_enabled = Observation[bool].found(
                True, evidence[1], evidence[2],
                note="Audit or CP logs are enabled.",
            )
        else:
            baseline.event_logging_enabled = Observation[bool].absent(
                False, "No audit or CP logging explicitly enabled."
            )

        # Logging buffered: Gaia logs locally by default via syslog
        baseline.logging_buffered = Observation[bool].found(
            True, "Gaia syslog", None,
            note="Gaia OS logs locally to /var/log by default.",
        )

    # -- password controls ----------------------------------------------------

    def _normalize_password_controls(self, baseline: SecurityBaselineModel) -> None:
        # Min length
        hit = self._first(r"^\s*set\s+password-controls\s+min-password-length\s+(\d+)")
        if hit:
            m, raw, line = hit
            baseline.password_min_length = Observation[int].found(
                int(m.group(1)), raw, line
            )
        else:
            baseline.password_min_length = Observation[int].absent(
                0, "Minimum password length is not configured."
            )

        # Complexity (Gaia uses a 1-4 scale, not individual character classes)
        complexity_hit = self._first(
            r"^\s*set\s+password-controls\s+complexity\s+(\d+)"
        )
        if complexity_hit:
            m, raw, line = complexity_hit
            level = int(m.group(1))
            # Gaia complexity levels (from official docs):
            # 1 = no restriction, 2 = at least one from two categories,
            # 3 = at least one from three categories, 4 = at least one from all four
            baseline.password_min_uppercase = Observation[int].found(
                1 if level >= 2 else 0, raw, line,
                note=f"Gaia complexity level {level}: "
                + ("requires characters from multiple categories."
                   if level >= 2 else "no category requirement."),
            )
            baseline.password_min_lowercase = Observation[int].found(
                1 if level >= 2 else 0, raw, line,
                note=f"Derived from Gaia complexity level {level}.",
            )
            baseline.password_min_numeric = Observation[int].found(
                1 if level >= 3 else 0, raw, line,
                note=f"Derived from Gaia complexity level {level}.",
            )
            baseline.password_min_special = Observation[int].found(
                1 if level >= 4 else 0, raw, line,
                note=f"Derived from Gaia complexity level {level}.",
            )
        else:
            note = "Password complexity level is not configured."
            baseline.password_min_uppercase = Observation[int].absent(0, note)
            baseline.password_min_lowercase = Observation[int].absent(0, note)
            baseline.password_min_numeric = Observation[int].absent(0, note)
            baseline.password_min_special = Observation[int].absent(0, note)

        # Password expiration
        exp_hit = self._first(
            r"^\s*set\s+password-controls\s+password-expiration\s+(\S+)"
        )
        if exp_hit:
            m, raw, line = exp_hit
            val = m.group(1).lower()
            days = 0 if val == "never" else int(val)
            baseline.password_max_age_days = Observation[int].found(days, raw, line)
        else:
            baseline.password_max_age_days = Observation[int].absent(
                0, "Password expiration is not configured."
            )

        # History
        hist_check = self._first(
            r"^\s*set\s+password-controls\s+history-checking\s+(on|off)"
        )
        hist_len = self._first(
            r"^\s*set\s+password-controls\s+history-length\s+(\d+)"
        )
        if hist_check and hist_check[0].group(1).lower() == "on" and hist_len:
            m, raw, line = hist_len
            baseline.password_history_reuse_limit = Observation[int].found(
                int(m.group(1)), raw, line
            )
        elif hist_check and hist_check[0].group(1).lower() == "off":
            m, raw, line = hist_check
            baseline.password_history_reuse_limit = Observation[int].found(
                0, raw, line, note="History checking is disabled."
            )
        else:
            baseline.password_history_reuse_limit = Observation[int].absent(
                0, "Password history is not configured."
            )

        # Lockout (deny-on-fail)
        lockout_enable = self._first(
            r"^\s*set\s+password-controls\s+deny-on-fail\s+enable\s+(on|off)"
        )
        lockout_attempts = self._first(
            r"^\s*set\s+password-controls\s+deny-on-fail\s+failures-allowed\s+(\d+)"
        )
        lockout_duration = self._first(
            r"^\s*set\s+password-controls\s+deny-on-fail\s+allow-after\s+(\d+)"
        )

        if lockout_enable and lockout_enable[0].group(1).lower() == "on":
            if lockout_attempts:
                m, raw, line = lockout_attempts
                baseline.admin_lockout_threshold = Observation[int].found(
                    int(m.group(1)), raw, line
                )
            else:
                m_e, raw_e, line_e = lockout_enable
                baseline.admin_lockout_threshold = Observation[int].found(
                    0, raw_e, line_e, note="Lockout enabled but threshold not set."
                )

            if lockout_duration:
                m, raw, line = lockout_duration
                baseline.admin_lockout_duration = Observation[int].found(
                    int(m.group(1)), raw, line,
                    note="Lockout duration in seconds.",
                )
            else:
                m_e, raw_e, line_e = lockout_enable
                baseline.admin_lockout_duration = Observation[int].found(
                    0, raw_e, line_e, note="Lockout enabled but duration not set."
                )
        elif lockout_enable:
            m, raw, line = lockout_enable
            baseline.admin_lockout_threshold = Observation[int].found(0, raw, line,
                note="Account lockout is disabled.")
            baseline.admin_lockout_duration = Observation[int].found(0, raw, line,
                note="Account lockout is disabled.")
        else:
            baseline.admin_lockout_threshold = Observation[int].absent(
                0, "Account lockout (deny-on-fail) is not configured."
            )
            baseline.admin_lockout_duration = Observation[int].absent(
                0, "Account lockout (deny-on-fail) is not configured."
            )

        # Password hash type (for password_encryption)
        hash_hit = self._first(
            r"^\s*set\s+password-controls\s+password-hash-type\s+(\S+)"
        )
        if hash_hit:
            m, raw, line = hash_hit
            ht = m.group(1).upper()
            strong = ht in ("SHA256", "SHA512")
            baseline.password_encryption = Observation[bool].found(
                strong, raw, line,
                note=f"Password hash type: {ht}.",
            )
        else:
            baseline.password_encryption = Observation[bool].unknown(
                "Password hash type is not configured."
            )

    # -- inactivity timeout ---------------------------------------------------

    def _normalize_inactivity_timeout(self, baseline: SecurityBaselineModel) -> None:
        hit = self._first(r"^\s*set\s+inactivity-timeout\s+(\d+)")
        if hit:
            m, raw, line = hit
            minutes = int(m.group(1))
            baseline.vty_exec_timeout_seconds = Observation[int].found(
                minutes * 60, raw, line,
                note=f"Inactivity timeout is {minutes} minutes ({minutes * 60}s).",
            )
        else:
            # Gaia default is 10 minutes
            baseline.vty_exec_timeout_seconds = Observation[int].absent(
                600, "Inactivity timeout not configured; Gaia default is 10 minutes."
            )

    # -- banner ---------------------------------------------------------------

    def _normalize_banner(self, baseline: SecurityBaselineModel) -> None:
        banner_hit = self._first(r"^\s*set\s+message\s+banner\s+(on|off)\b")

        if banner_hit:
            m, raw, line = banner_hit
            is_on = m.group(1).lower() == "on"
            baseline.login_banner_present = Observation[bool].found(is_on, raw, line)
            baseline.pre_login_banner_present = Observation[bool].found(
                is_on, raw, line
            )
        else:
            baseline.login_banner_present = Observation[bool].absent(
                False, "No banner message configured."
            )
            baseline.pre_login_banner_present = Observation[bool].absent(
                False, "No banner message configured."
            )

        motd_hit = self._first(r"^\s*set\s+message\s+motd\s+(on|off)\b")
        if motd_hit:
            m, raw, line = motd_hit
            is_on = m.group(1).lower() == "on"
            baseline.post_login_banner_present = Observation[bool].found(
                is_on, raw, line
            )
        else:
            baseline.post_login_banner_present = Observation[bool].absent(
                False, "No MOTD message configured."
            )

    # -- web management -------------------------------------------------------

    def _normalize_web(self, baseline: SecurityBaselineModel) -> None:
        # HTTPS is always enabled on Gaia (web management portal).
        # HTTP is not available on Gaia management by default.
        baseline.https_server_enabled = Observation[bool].found(
            True, "Gaia Portal", None,
            note="Gaia web management (HTTPS) is always available.",
        )
        baseline.http_server_enabled = Observation[bool].absent(
            False, "Gaia does not serve HTTP management; only HTTPS."
        )

        # Check whether default SSL port has been changed
        ssl_port_hit = self._first(r"^\s*set\s+web\s+ssl-port\s+(\d+)")
        if ssl_port_hit:
            m, raw, line = ssl_port_hit
            port = int(m.group(1))
            changed = port != 443
            baseline.admin_default_ports_changed = Observation[bool].found(
                changed, raw, line,
                note=f"Web SSL port is {port} ({'non-default' if changed else 'default 443'}).",
            )
        else:
            baseline.admin_default_ports_changed = Observation[bool].absent(
                False, "Web SSL port not configured; using default 443."
            )

        # Telnet: Gaia does not have a telnet server by default
        baseline.telnet_enabled = Observation[bool].absent(
            False, "Gaia OS does not provide a telnet management service."
        )
        # SSH is always available on Gaia
        baseline.ssh_enabled = Observation[bool].found(
            True, "Gaia SSH", None,
            note="SSH is always enabled on Gaia OS.",
        )
        baseline.ssh_version = Observation[int].found(
            2, "Gaia SSH", None,
            note="Gaia OS supports SSHv2 only.",
        )
        baseline.vty_transport_input = Observation[List[str]].found(
            ["ssh"], "Gaia SSH", None,
            note="Gaia management access is via SSH and HTTPS only.",
        )

    # -- AAA ------------------------------------------------------------------

    def _normalize_aaa(self, baseline: SecurityBaselineModel) -> None:
        radius_hits = self._scan(
            r"^\s*(?:add|set)\s+aaa\s+radius-servers\s+"
        )
        tacacs_hits = self._scan(
            r"^\s*(?:add|set)\s+aaa\s+tacacs-servers\s+"
        )

        if radius_hits or tacacs_hits:
            evidence = (radius_hits or tacacs_hits)[0]
            baseline.aaa_enabled = Observation[bool].found(
                True, evidence[1], evidence[2],
                note="External AAA servers (RADIUS/TACACS+) are configured.",
            )
        else:
            baseline.aaa_enabled = Observation[bool].absent(
                False, "No external AAA servers are configured."
            )

        # Management ACL: if AAA is configured, we consider management restricted
        if radius_hits or tacacs_hits:
            evidence = (radius_hits or tacacs_hits)[0]
            baseline.management_acl_applied = Observation[bool].found(
                True, evidence[1], evidence[2],
                note="AAA server configuration restricts management authentication.",
            )
        else:
            baseline.management_acl_applied = Observation[bool].unknown(
                "No AAA configuration to imply management access restriction."
            )
