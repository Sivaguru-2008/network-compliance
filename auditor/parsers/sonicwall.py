"""Deterministic SonicWall SonicOS parser.

SonicWall firewalls run SonicOS and export configuration via the Enterprise
Command Line Interface (E-CLI).  The ``show current-config`` output (or
``export current-config cli``) produces hierarchical CLI commands with
``configure`` mode and submodes (``administration``, ``interface``, ``snmp``,
``log``, ``ntp``, etc.).

CLI reference verified against official SonicWall documentation:
- SonicOS/X 7 CLI Reference Guide
  (sonicwall.com/techdocs/pdf/sonicosx-7-command-line-interface-reference-guide.pdf)
- SonicOS 6.5 E-CLI Reference Guide
  (sonicwall.com/techdocs/pdf/sonicos-6-5-enterprise-command-line-reference-guide.pdf)
- SonicWall KB: Admin Best Practices (kA1VN0000000Jyv0AE)
- SonicWall KB: High Security Setup (kA1VN0000000IRi0AM)
- SonicWall KB: Password Constraints (kA1VN0000000FvC0AU)
- SonicWall KB: Web Management CLI (170504284559119)
- SonicWall KB: Admin Idle Timeout CLI (kA1VN0000000FOx0AM)
- SonicWall KB: SNMP Configuration (170505617080053)
- SonicWall KB: Login Banner (kA1VN0000000Ogg0AE)
- SonicWall KB: Enhanced Audit Logging (170505386294195)

Platform invariants documented by SonicWall:
- Telnet is NOT supported in SonicOS.  Management access is via SSH and HTTPS.
  (Verified: SonicOS CLI reference does not document telnet as a management
  protocol.  The ``management`` per-interface command supports only: https,
  http, ssh, snmp, ping.)
- SSH is always protocol version 2.
  (SonicOS SSH implementation is SSHv2-only.)

CIS / STIG status:
- NO official CIS Benchmark exists for SonicWall.
- NO official DISA STIG exists for SonicWall.
- Security controls mapped below are generic best-practice controls from the
  13 vendor-neutral rules in security_controls.json, NOT fabricated CIS IDs.
- The Tenable TNS Best Practices SonicWALL v5.9 audit provides ~101 checks
  but is a Tenable product, not a CIS or DISA publication.
"""

import hashlib
import re
from typing import List, Optional, Sequence, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry

_SONICWALL_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*firmware-version\s+SonicOS\b", 0.50),
    (r"(?im)^\s*web-management\s+(allow-http|https-port)\b", 0.20),
    (r"(?im)^\s*management\s+(https|http|ssh|snmp|ping)\b", 0.10),
    (r"(?im)^\s*admin\s+idle-timeout\b", 0.10),
    (r"(?im)^\s*security-services\b", 0.05),
    (r"(?im)^\s*gateway-anti-virus\s+enable\b", 0.05),
    (r"(?im)^\s*intrusion-prevention\s+enable\b", 0.05),
    (r"(?im)^\s*snmp\s+community-name\b", 0.05),
    (r"(?im)^\s*syslog-server\s+\S+\s+port\b", 0.05),
    (r"(?im)^\s*ntp-server\s+\S+", 0.05),
    (r"(?im)^\s*one-time-password\s+totp\b", 0.05),
    (r"(?im)^\s*enhanced-audit-logging\s+enable\b", 0.05),
]

_NON_SONICWALL_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*line\s+vty\b", 0.40),
    (r"(?im)^\s*ip\s+http\s+server\s*$", 0.30),
    (r"(?im)^\s*config\s+system\s+global\b", 0.90),
    (r"(?im)^\s*set\s+system\s+host-name\b", 0.80),
    (r"(?im)^\s*sysname\s+\S+", 0.50),
    (r"(?im)^\s*<\?xml", 0.90),
    (r"(?im)\"DEVICE_METADATA\"", 0.90),
    (r"(?im)^\s*user-interface\s+vty\b", 0.50),
    (r"(?im)^\s*set\s+password-controls\s+", 0.50),
    (r"(?im)^\s*management\s+api\s+http-commands\b", 0.50),
    (r"(?im)^/ip\s+service\b", 0.50),
    (r"(?im)^\s*#.*by RouterOS\b", 0.50),
    (r"(?im)^\s*set\s+protocols\s+", 0.40),
    (r"(?im)^\s*set\s+interfaces\s+", 0.40),
]


@registry.register
class SonicWallParser(VendorParser):
    """Grammar-based parser for SonicWall SonicOS configurations."""

    name = "sonicwall"
    vendor = "sonicwall"
    os_family = "sonicos"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        score = sum(w for p, w in _SONICWALL_MARKERS if re.search(p, config_text))
        score -= sum(w for p, w in _NON_SONICWALL_MARKERS if re.search(p, config_text))
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
        self._normalize_firmware_version(baseline)
        self._normalize_management_access(baseline)
        self._normalize_administration(baseline)
        self._normalize_snmp(baseline)
        self._normalize_syslog(baseline)
        self._normalize_ntp(baseline)
        self._normalize_banner(baseline)
        self._normalize_platform_invariants(baseline)

        for field in baseline.observable_fields():
            observation = getattr(baseline, field)
            if observation.note == "Parser did not evaluate this field.":
                setattr(
                    baseline,
                    field,
                    type(observation).unknown(
                        "SonicWall SonicOS parser does not evaluate this field."
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
        hit = self._first(r"^\s*hostname\s+(\S+.*)")
        if hit:
            m, raw, line = hit
            name = m.group(1).strip()
            if name:
                baseline.hostname = Observation[str].found(name, raw, line)
                return
        baseline.hostname = Observation[str].unknown(
            "No 'hostname' statement found in SonicWall configuration."
        )

    # -- firmware version (stored as warning, not a baseline field) -----------

    def _normalize_firmware_version(self, baseline: SecurityBaselineModel) -> None:
        hit = self._first(r"^\s*firmware-version\s+SonicOS\s+(.+)")
        if hit:
            m, raw, line = hit
            ver = m.group(1).strip()
            if ver and ver.lower() != "unknown":
                self._warnings.append(
                    f"SonicOS version detected: {ver}"
                )
            else:
                self._warnings.append(
                    "SonicOS version not established by available evidence."
                )
        else:
            self._warnings.append(
                "No firmware-version statement found; SonicOS version unknown."
            )

    # -- management access (SSH, HTTP, HTTPS per interface) -------------------

    def _normalize_management_access(self, baseline: SecurityBaselineModel) -> None:
        """Extract per-interface management settings.

        SonicWall enables/disables management protocols per-interface via:
            management https|http|ssh|snmp|ping
            no management https|http|ssh|snmp|ping

        We aggregate worst-case across all interfaces.
        """
        any_ssh = False
        any_http = False
        any_https = False
        any_snmp_if = False
        ssh_evidence: Optional[Tuple[str, int]] = None
        http_evidence: Optional[Tuple[str, int]] = None
        https_evidence: Optional[Tuple[str, int]] = None

        wan_has_mgmt_restriction = True
        has_interface = False
        current_iface = None
        current_iface_is_wan = False
        current_iface_services: List[str] = []

        for idx, line_raw in enumerate(self._lines, start=1):
            line = line_raw.strip()

            iface_m = re.match(r"^\s*interface\s+(X\d+|[A-Za-z]\w*)", line, re.IGNORECASE)
            if iface_m:
                if current_iface is not None and current_iface_is_wan:
                    if current_iface_services:
                        wan_has_mgmt_restriction = False
                current_iface = iface_m.group(1)
                has_interface = True
                current_iface_is_wan = current_iface.upper() == "X1"
                current_iface_services = []
                continue

            mgmt_m = re.match(
                r"^\s*(no\s+)?management\s+(https|http|ssh|snmp|ping)\s*$",
                line, re.IGNORECASE,
            )
            if mgmt_m:
                negated = mgmt_m.group(1) is not None
                proto = mgmt_m.group(2).lower()

                if not negated:
                    if current_iface_is_wan:
                        current_iface_services.append(proto)

                    if proto == "ssh":
                        any_ssh = True
                        if ssh_evidence is None:
                            ssh_evidence = (line, idx)
                    elif proto == "http":
                        any_http = True
                        if http_evidence is None:
                            http_evidence = (line, idx)
                    elif proto == "https":
                        any_https = True
                        if https_evidence is None:
                            https_evidence = (line, idx)

        if current_iface is not None and current_iface_is_wan:
            if current_iface_services:
                wan_has_mgmt_restriction = False

        if ssh_evidence:
            baseline.ssh_enabled = Observation[bool].found(
                True, ssh_evidence[0], ssh_evidence[1],
                note="SSH management is enabled on at least one interface.",
            )
        elif has_interface:
            baseline.ssh_enabled = Observation[bool].absent(
                False, "SSH management not enabled on any interface."
            )
        else:
            baseline.ssh_enabled = Observation[bool].unknown(
                "No interface configuration found to determine SSH status."
            )

        if http_evidence:
            baseline.http_server_enabled = Observation[bool].found(
                True, http_evidence[0], http_evidence[1],
                note="HTTP management is enabled on at least one interface.",
            )
        elif has_interface:
            baseline.http_server_enabled = Observation[bool].absent(
                False, "HTTP management not enabled on any interface."
            )
        else:
            baseline.http_server_enabled = Observation[bool].unknown(
                "No interface configuration found to determine HTTP status."
            )

        web_http_hit = self._first(r"^\s*web-management\s+allow-http\b")
        no_web_http_hit = self._first(r"^\s*no\s+web-management\s+allow-http\b")

        if web_http_hit and not no_web_http_hit:
            m, raw, line_num = web_http_hit
            baseline.http_server_enabled = Observation[bool].found(
                True, raw, line_num,
                note="HTTP management globally enabled via web-management allow-http.",
            )
        elif no_web_http_hit:
            m, raw, line_num = no_web_http_hit
            if not (http_evidence and baseline.http_server_enabled.value is True):
                baseline.http_server_enabled = Observation[bool].found(
                    False, raw, line_num,
                    note="HTTP management globally disabled via no web-management allow-http.",
                )

        if https_evidence:
            baseline.https_server_enabled = Observation[bool].found(
                True, https_evidence[0], https_evidence[1],
                note="HTTPS management is enabled on at least one interface.",
            )
        elif has_interface:
            baseline.https_server_enabled = Observation[bool].absent(
                False, "HTTPS management not enabled on any interface."
            )
        else:
            baseline.https_server_enabled = Observation[bool].unknown(
                "No interface configuration found to determine HTTPS status."
            )

        transports: List[str] = []
        transport_evidence_raw = None
        transport_evidence_line = None
        if any_ssh:
            transports.append("ssh")
            if ssh_evidence:
                transport_evidence_raw = ssh_evidence[0]
                transport_evidence_line = ssh_evidence[1]
        if any_http:
            transports.append("http")

        if transports or has_interface:
            baseline.vty_transport_input = Observation[List[str]].found(
                transports if transports else ["ssh"],
                transport_evidence_raw or (ssh_evidence[0] if ssh_evidence else "SonicOS default"),
                transport_evidence_line,
                note="Derived from enabled management protocols across interfaces.",
            )
        else:
            baseline.vty_transport_input = Observation[List[str]].unknown(
                "No interface management configuration found."
            )

        if has_interface and wan_has_mgmt_restriction:
            first_iface = self._first(r"^\s*interface\s+")
            evidence = first_iface[1] if first_iface else "SonicOS interface config"
            evidence_line = first_iface[2] if first_iface else None
            baseline.management_acl_applied = Observation[bool].found(
                True, evidence, evidence_line,
                note="WAN interface (X1) has management services restricted.",
            )
        elif has_interface:
            first_iface = self._first(r"^\s*interface\s+")
            evidence = first_iface[1] if first_iface else "SonicOS interface config"
            evidence_line = first_iface[2] if first_iface else None
            baseline.management_acl_applied = Observation[bool].found(
                False, evidence, evidence_line,
                note="WAN interface (X1) has management services enabled — not restricted.",
            )
        else:
            baseline.management_acl_applied = Observation[bool].unknown(
                "No interface configuration found to assess management ACL."
            )

    # -- administration settings -----------------------------------------------

    def _normalize_administration(self, baseline: SecurityBaselineModel) -> None:
        # idle timeout
        hit = self._first(r"^\s*admin\s+idle-timeout\s+(\S+)")
        if hit:
            m, raw, line = hit
            try:
                minutes = int(m.group(1))
                if minutes > 0:
                    baseline.vty_exec_timeout_seconds = Observation[int].found(
                        minutes * 60, raw, line,
                        note=f"Admin idle timeout is {minutes} minutes ({minutes * 60}s).",
                    )
                else:
                    self._warnings.append(
                        f"Invalid admin idle-timeout value: {m.group(1)}"
                    )
                    baseline.vty_exec_timeout_seconds = Observation[int].unknown(
                        f"Invalid admin idle-timeout value: {m.group(1)}."
                    )
            except ValueError:
                self._warnings.append(
                    f"Non-numeric admin idle-timeout: {m.group(1)}"
                )
                baseline.vty_exec_timeout_seconds = Observation[int].unknown(
                    f"Non-numeric admin idle-timeout value: {m.group(1)}."
                )
        else:
            baseline.vty_exec_timeout_seconds = Observation[int].absent(
                300, "Admin idle timeout not configured; SonicOS default is 5 minutes."
            )

        # password minimum length
        hit = self._first(r"^\s*password-min-length\s+(\S+)")
        if hit:
            m, raw, line = hit
            try:
                length = int(m.group(1))
                baseline.password_min_length = Observation[int].found(
                    length, raw, line,
                )
            except ValueError:
                self._warnings.append(
                    f"Non-numeric password-min-length: {m.group(1)}"
                )
                baseline.password_min_length = Observation[int].unknown(
                    f"Non-numeric password-min-length value: {m.group(1)}."
                )
        else:
            baseline.password_min_length = Observation[int].absent(
                8, "Password min length not configured; SonicOS default is 8."
            )

        # password complexity
        hit = self._first(r"^\s*password-complexity\s+(\S+)")
        if hit:
            m, raw, line = hit
            complexity = m.group(1).lower()
            if complexity == "alphanumeric-symbolic":
                baseline.password_min_uppercase = Observation[int].found(1, raw, line,
                    note="SonicOS alphanumeric-symbolic complexity requires uppercase.")
                baseline.password_min_lowercase = Observation[int].found(1, raw, line,
                    note="SonicOS alphanumeric-symbolic complexity requires lowercase.")
                baseline.password_min_numeric = Observation[int].found(1, raw, line,
                    note="SonicOS alphanumeric-symbolic complexity requires numeric.")
                baseline.password_min_special = Observation[int].found(1, raw, line,
                    note="SonicOS alphanumeric-symbolic complexity requires symbolic.")
            elif complexity == "alphanumeric":
                baseline.password_min_uppercase = Observation[int].found(1, raw, line,
                    note="SonicOS alphanumeric complexity requires uppercase.")
                baseline.password_min_lowercase = Observation[int].found(1, raw, line,
                    note="SonicOS alphanumeric complexity requires lowercase.")
                baseline.password_min_numeric = Observation[int].found(1, raw, line,
                    note="SonicOS alphanumeric complexity requires numeric.")
                baseline.password_min_special = Observation[int].found(0, raw, line,
                    note="SonicOS alphanumeric complexity does not require symbolic.")
            else:
                note = f"SonicOS password complexity: {complexity} (no character class requirements)."
                baseline.password_min_uppercase = Observation[int].found(0, raw, line, note=note)
                baseline.password_min_lowercase = Observation[int].found(0, raw, line, note=note)
                baseline.password_min_numeric = Observation[int].found(0, raw, line, note=note)
                baseline.password_min_special = Observation[int].found(0, raw, line, note=note)
        else:
            note = "Password complexity not configured; SonicOS default is none."
            baseline.password_min_uppercase = Observation[int].absent(0, note)
            baseline.password_min_lowercase = Observation[int].absent(0, note)
            baseline.password_min_numeric = Observation[int].absent(0, note)
            baseline.password_min_special = Observation[int].absent(0, note)

        # lockout
        lockout_attempts = self._first(r"^\s*login-attempts-per-minute\s+(\d+)")
        lockout_period = self._first(r"^\s*lockout-period\s+(\d+)")

        if lockout_attempts:
            m, raw, line = lockout_attempts
            baseline.admin_lockout_threshold = Observation[int].found(
                int(m.group(1)), raw, line,
                note=f"Login lockout after {m.group(1)} failed attempts per minute.",
            )
        else:
            baseline.admin_lockout_threshold = Observation[int].absent(
                0, "Login lockout not configured; SonicOS default is disabled."
            )

        if lockout_period:
            m, raw, line = lockout_period
            minutes = int(m.group(1))
            baseline.admin_lockout_duration = Observation[int].found(
                minutes * 60, raw, line,
                note=f"Lockout period is {minutes} minutes ({minutes * 60}s).",
            )
        else:
            baseline.admin_lockout_duration = Observation[int].absent(
                0, "Lockout period not configured; SonicOS default is disabled."
            )

        # password encryption: SonicOS stores passwords hashed
        baseline.password_encryption = Observation[bool].found(
            True, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="SonicOS stores admin passwords in hashed form by default.",
        )
        baseline.enable_secret_set = Observation[bool].found(
            True, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="SonicOS does not use a separate enable secret; admin authentication is user/password based and passwords are always hashed.",
        )
        baseline.enable_password_present = Observation[bool].found(
            False, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="SonicOS does not have a reversible enable password concept.",
        )

        # HTTPS port change
        hit = self._first(r"^\s*web-management\s+https-port\s+(\d+)")
        if hit:
            m, raw, line = hit
            port = int(m.group(1))
            changed = port != 443
            baseline.admin_default_ports_changed = Observation[bool].found(
                changed, raw, line,
                note=f"HTTPS management port is {port} ({'non-default' if changed else 'default 443'}).",
            )
        else:
            baseline.admin_default_ports_changed = Observation[bool].absent(
                False, "HTTPS port not configured; using default 443."
            )

        # AAA: check for external auth references
        aaa_hit = self._first(r"(?i)^\s*(radius|tacacs|ldap)\b")
        if aaa_hit:
            m, raw, line = aaa_hit
            baseline.aaa_enabled = Observation[bool].found(
                True, raw, line,
                note=f"External authentication ({m.group(1)}) is configured.",
            )
        else:
            baseline.aaa_enabled = Observation[bool].absent(
                False, "No external AAA (RADIUS/TACACS/LDAP) configuration found."
            )

        # Enhanced audit logging
        audit_hit = self._first(r"^\s*enhanced-audit-logging\s+enable\b")
        if audit_hit:
            m, raw, line = audit_hit
            baseline.event_logging_enabled = Observation[bool].found(
                True, raw, line,
                note="Enhanced audit logging is enabled.",
            )
        else:
            baseline.event_logging_enabled = Observation[bool].unknown(
                "Enhanced audit logging status not found in configuration."
            )

    # -- SNMP -----------------------------------------------------------------

    def _normalize_snmp(self, baseline: SecurityBaselineModel) -> None:
        snmp_enable = self._first(r"^\s*snmp\s+enable\b")
        no_snmp_enable = self._first(r"^\s*no\s+snmp\s+enable\b")

        if snmp_enable and not no_snmp_enable:
            m, raw, line = snmp_enable
            baseline.snmp_agent_enabled = Observation[bool].found(True, raw, line)
        elif no_snmp_enable:
            m, raw, line = no_snmp_enable
            baseline.snmp_agent_enabled = Observation[bool].found(False, raw, line)
        else:
            baseline.snmp_agent_enabled = Observation[bool].unknown(
                "SNMP enabled/disabled status not found in configuration."
            )

        communities: List[SnmpCommunity] = []

        for m, raw, line in self._scan(
            r"^\s*snmp\s+(?:get-)?community-name\s+(\S+)"
        ):
            name = m.group(1)
            if not name:
                continue
            access = "ro"
            communities.append(
                SnmpCommunity(
                    name=name,
                    access=access,
                    acl=None,
                    source_line=raw,
                    line_number=line,
                )
            )

        for m, raw, line in self._scan(
            r"^\s*snmp\s+trap-community-name\s+(\S+)"
        ):
            name = m.group(1)
            if not name:
                continue
            communities.append(
                SnmpCommunity(
                    name=name,
                    access="ro",
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

        # SNMPv3 check
        v3_hit = self._first(r"(?i)^\s*snmp\s+.*v3\b")
        if v3_hit:
            m, raw, line = v3_hit
            baseline.snmp_v3_users_present = Observation[bool].found(
                True, raw, line,
                note="SNMPv3 configuration detected.",
            )
        else:
            baseline.snmp_v3_users_present = Observation[bool].unknown(
                "SNMPv3 configuration not found."
            )

    # -- syslog ---------------------------------------------------------------

    def _normalize_syslog(self, baseline: SecurityBaselineModel) -> None:
        hosts: List[str] = []
        evidence_raw: Optional[str] = None
        evidence_line: Optional[int] = None

        for m, raw, line in self._scan(
            r"^\s*syslog-server\s+(\S+)\s+port\s+\d+"
        ):
            host = m.group(1)
            if host:
                hosts.append(host)
                if evidence_raw is None:
                    evidence_raw = raw
                    evidence_line = line

        if hosts:
            baseline.logging_enabled = Observation[bool].found(
                True, evidence_raw, evidence_line,
                note="Remote syslog servers are configured.",
            )
            baseline.logging_hosts = Observation[List[str]].found(
                hosts, evidence_raw, evidence_line,
            )
        else:
            baseline.logging_enabled = Observation[bool].absent(
                False, "No remote syslog servers configured."
            )
            baseline.logging_hosts = Observation[List[str]].absent(
                [], "No syslog hosts configured."
            )

        baseline.logging_buffered = Observation[bool].found(
            True, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="SonicOS logs to internal buffer by default.",
        )

    # -- NTP ------------------------------------------------------------------

    def _normalize_ntp(self, baseline: SecurityBaselineModel) -> None:
        servers: List[str] = []
        evidence_raw: Optional[str] = None
        evidence_line: Optional[int] = None

        for m, raw, line in self._scan(r"^\s*ntp-server\s+(\S+)"):
            server = m.group(1)
            if server:
                servers.append(server)
                if evidence_raw is None:
                    evidence_raw = raw
                    evidence_line = line

        if servers:
            baseline.ntp_servers = Observation[List[str]].found(
                servers, evidence_raw, evidence_line,
            )
            baseline.ntp_redundant = Observation[bool].found(
                len(servers) >= 2, evidence_raw, evidence_line,
            )
        else:
            baseline.ntp_servers = Observation[List[str]].absent(
                [], "No NTP servers configured."
            )
            baseline.ntp_redundant = Observation[bool].absent(
                False, "No NTP servers configured."
            )

    # -- banner ---------------------------------------------------------------

    def _normalize_banner(self, baseline: SecurityBaselineModel) -> None:
        hit = self._first(r'^\s*pre-login-banner\s+"(.+)"')
        if not hit:
            hit = self._first(r"^\s*pre-login-banner\s+(\S+.*)")

        if hit:
            m, raw, line = hit
            text = m.group(1).strip().strip('"')
            has_banner = bool(text)
            baseline.login_banner_present = Observation[bool].found(
                has_banner, raw, line,
            )
            baseline.pre_login_banner_present = Observation[bool].found(
                has_banner, raw, line,
            )
        else:
            baseline.login_banner_present = Observation[bool].absent(
                False, "No pre-login banner configured."
            )
            baseline.pre_login_banner_present = Observation[bool].absent(
                False, "No pre-login banner configured."
            )

        baseline.post_login_banner_present = Observation[bool].unknown(
            "SonicOS post-login banner cannot be determined from CLI export."
        )

    # -- platform invariants --------------------------------------------------

    def _normalize_platform_invariants(self, baseline: SecurityBaselineModel) -> None:
        baseline.telnet_enabled = Observation[bool].absent(
            False,
            "SonicOS does not support telnet management. "
            "Management protocols are limited to HTTPS, HTTP, SSH, SNMP, and Ping. "
            "(Verified: SonicOS/X 7 CLI Reference Guide, per-interface management command.)"
        )
        baseline.ssh_version = Observation[int].found(
            2, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="SonicOS SSH is always protocol version 2.",
        )
