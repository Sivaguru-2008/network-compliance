"""Deterministic MikroTik RouterOS parser.

MikroTik RouterOS configuration is exported via ``/export`` which produces a
CLI script file (``.rsc``).  The format uses forward-slash menu paths followed
by ``set``/``add`` commands with ``key=value`` properties.

CLI reference verified against the official MikroTik documentation at
help.mikrotik.com (RouterOS 7.x) and manual.mikrotik.com.

Key documentation pages consulted:
- IP Services: help.mikrotik.com/docs/spaces/ROS/pages/328229/IP+Services
- SSH: help.mikrotik.com/docs/spaces/ROS/pages/132350014/SSH
- SNMP: help.mikrotik.com/docs/spaces/ROS/pages/8978519/SNMP
- User: help.mikrotik.com/docs/spaces/ROS/pages/8978504/User
- NTP: help.mikrotik.com/docs/spaces/ROS/pages/40992869/NTP
- Log: help.mikrotik.com/docs/spaces/ROS/pages/328094/Log
- System Note: help.mikrotik.com/docs/spaces/ROS/pages/40992863/Note
- Identity: help.mikrotik.com/docs/display/ROS/Identity
- Securing: help.mikrotik.com/docs/spaces/ROS/pages/328353/Securing+your+router
"""

import hashlib
import re
from typing import Dict, List, Optional, Sequence, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry

_ROS_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*#.*by RouterOS\b", 0.45),
    (r"(?im)^/ip service\b", 0.20),
    (r"(?im)^/system identity\b", 0.15),
    (r"(?im)^/tool mac-server\b", 0.15),
    (r"(?im)winbox", 0.10),
    (r"(?im)^/snmp community\b", 0.10),
    (r"(?im)^/ip ssh\b", 0.10),
    (r"(?im)^/system ntp client\b", 0.10),
    (r"(?im)^/tool bandwidth-server\b", 0.05),
]

_NON_ROS_MARKERS: Sequence[Tuple[str, float]] = [
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
]

_PROP_RE = re.compile(r'([\w][\w-]*)=("(?:[^"\\]|\\.)*"|[^\s]+)')


def _parse_props(line: str) -> Dict[str, str]:
    """Parse key=value pairs from a RouterOS command line."""
    props: Dict[str, str] = {}
    for m in _PROP_RE.finditer(line):
        key = m.group(1)
        val = m.group(2)
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        props[key] = val
    return props


def _parse_ros_time(time_str: str) -> Optional[int]:
    """Parse RouterOS time format (e.g. '10m', '1h', '5m30s') to seconds."""
    total = 0
    m = re.match(
        r"(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s?)?$",
        time_str.strip(),
    )
    if not m:
        return None
    weeks, days, hours, mins, secs = m.groups()
    if weeks:
        total += int(weeks) * 604800
    if days:
        total += int(days) * 86400
    if hours:
        total += int(hours) * 3600
    if mins:
        total += int(mins) * 60
    if secs:
        total += int(secs)
    if total == 0 and not any([weeks, days, hours, mins, secs]):
        return None
    return total


@registry.register
class MikroTikROSParser(VendorParser):
    """Grammar-based parser for MikroTik RouterOS configurations."""

    name = "mikrotik_routeros"
    vendor = "mikrotik"
    os_family = "routeros"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        score = sum(w for p, w in _ROS_MARKERS if re.search(p, config_text))
        score -= sum(w for p, w in _NON_ROS_MARKERS if re.search(p, config_text))
        return max(0.0, min(1.0, score))

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if config_text is None or not config_text.strip():
            raise ParserError("Configuration is empty.")

        self._lines = config_text.splitlines()
        self._warnings: List[str] = []
        self._context = ""

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

        self._build_sections()

        self._normalize_hostname(baseline)
        self._normalize_services(baseline)
        self._normalize_ssh(baseline)
        self._normalize_snmp(baseline)
        self._normalize_ntp(baseline)
        self._normalize_dns(baseline)
        self._normalize_logging(baseline)
        self._normalize_banner(baseline)
        self._normalize_users(baseline)
        self._normalize_passwords(baseline)

        for field in baseline.observable_fields():
            observation = getattr(baseline, field)
            if observation.note == "Parser did not evaluate this field.":
                setattr(
                    baseline,
                    field,
                    type(observation).unknown(
                        "MikroTik RouterOS parser does not evaluate this field."
                    ),
                )

        baseline.provenance.warnings = self._warnings
        return baseline

    _CMD_VERBS = frozenset({"set", "add", "remove", "enable", "disable"})

    def _build_sections(self) -> None:
        """Index lines by their menu context for efficient lookup."""
        self._sections: Dict[str, List[Tuple[str, str, int]]] = {}
        context = ""
        for idx, line in enumerate(self._lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("/"):
                parts = stripped.split()
                verb_idx = None
                for i, part in enumerate(parts):
                    if part.lower() in self._CMD_VERBS:
                        verb_idx = i
                        break
                if verb_idx is not None and verb_idx > 0:
                    context = " ".join(parts[:verb_idx])
                    rest = " ".join(parts[verb_idx:])
                    self._sections.setdefault(context, []).append(
                        (rest, stripped, idx)
                    )
                else:
                    context = stripped
            else:
                self._sections.setdefault(context, []).append(
                    (stripped, stripped, idx)
                )

    def _get_section(self, path: str) -> List[Tuple[str, str, int]]:
        return self._sections.get(path, [])

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
        for cmd, raw, line in self._get_section("/system identity"):
            props = _parse_props(cmd)
            if "name" in props:
                baseline.hostname = Observation[str].found(
                    props["name"], raw, line
                )
                return
        hit = self._first(r"^\s*/system\s+identity\s+set\s+.*name=(\S+)")
        if hit:
            m, raw, line = hit
            baseline.hostname = Observation[str].found(m.group(1), raw, line)
            return
        baseline.hostname = Observation[str].unknown(
            "No '/system identity set name=' found."
        )

    # -- IP services ----------------------------------------------------------

    def _normalize_services(self, baseline: SecurityBaselineModel) -> None:
        services: Dict[str, Dict] = {}

        for cmd, raw, line in self._get_section("/ip service"):
            clean = re.sub(r"\[.*?\]", "", cmd).strip()
            parts = clean.split()
            if len(parts) < 2 or parts[0] != "set":
                continue
            svc_name = parts[1]
            props = _parse_props(clean)
            services[svc_name] = {
                "props": props,
                "raw": raw,
                "line": line,
            }

        telnet_info = services.get("telnet")
        if telnet_info and telnet_info["props"].get("disabled") == "yes":
            baseline.telnet_enabled = Observation[bool].found(
                False, telnet_info["raw"], telnet_info["line"],
                note="Telnet service is disabled.",
            )
        elif telnet_info:
            baseline.telnet_enabled = Observation[bool].found(
                True, telnet_info["raw"], telnet_info["line"],
                note="Telnet service is enabled.",
            )
        else:
            baseline.telnet_enabled = Observation[bool].found(
                True, "RouterOS default", None,
                note="Telnet service is enabled by default in RouterOS.",
            )

        ssh_info = services.get("ssh")
        if ssh_info and ssh_info["props"].get("disabled") == "yes":
            baseline.ssh_enabled = Observation[bool].found(
                False, ssh_info["raw"], ssh_info["line"],
                note="SSH service is disabled.",
            )
        elif ssh_info:
            baseline.ssh_enabled = Observation[bool].found(
                True, ssh_info["raw"], ssh_info["line"],
                note="SSH service is enabled.",
            )
        else:
            baseline.ssh_enabled = Observation[bool].found(
                True, "RouterOS default", None,
                note="SSH service is enabled by default in RouterOS.",
            )

        baseline.ssh_version = Observation[int].found(
            2, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="RouterOS SSH is always protocol version 2.",
        )

        www_info = services.get("www")
        if www_info and www_info["props"].get("disabled") == "yes":
            baseline.http_server_enabled = Observation[bool].found(
                False, www_info["raw"], www_info["line"],
                note="HTTP (www) service is disabled.",
            )
        elif www_info:
            baseline.http_server_enabled = Observation[bool].found(
                True, www_info["raw"], www_info["line"],
                note="HTTP (www) service is enabled.",
            )
        else:
            baseline.http_server_enabled = Observation[bool].found(
                True, "RouterOS default", None,
                note="HTTP (www) service is enabled by default in RouterOS.",
            )

        www_ssl_info = services.get("www-ssl")
        if www_ssl_info and www_ssl_info["props"].get("disabled") == "yes":
            baseline.https_server_enabled = Observation[bool].found(
                False, www_ssl_info["raw"], www_ssl_info["line"],
            )
        elif www_ssl_info:
            baseline.https_server_enabled = Observation[bool].found(
                True, www_ssl_info["raw"], www_ssl_info["line"],
            )
        else:
            baseline.https_server_enabled = Observation[bool].unknown(
                "HTTPS (www-ssl) service not in export; requires a certificate to activate.",
            )

        enabled_transports: List[str] = []
        if baseline.telnet_enabled.value is True:
            enabled_transports.append("telnet")
        if baseline.ssh_enabled.value is True:
            enabled_transports.append("ssh")
        first_svc = next(
            (s for s in services.values()), None
        )
        evidence_raw = first_svc["raw"] if first_svc else "RouterOS defaults"
        evidence_line = first_svc["line"] if first_svc else None
        baseline.vty_transport_input = Observation[List[str]].found(
            enabled_transports, evidence_raw, evidence_line,
            note="Derived from enabled IP services.",
        )

        has_acl = False
        acl_evidence_raw = None
        acl_evidence_line = None
        for svc_name in ("ssh", "winbox", "www", "www-ssl", "api", "api-ssl"):
            info = services.get(svc_name)
            if not info:
                continue
            addr = info["props"].get("address", "0.0.0.0/0")
            if addr != "0.0.0.0/0" and info["props"].get("disabled") != "yes":
                has_acl = True
                if acl_evidence_raw is None:
                    acl_evidence_raw = info["raw"]
                    acl_evidence_line = info["line"]

        if has_acl:
            baseline.management_acl_applied = Observation[bool].found(
                True, acl_evidence_raw, acl_evidence_line,
                note="IP service address restrictions are applied.",
            )
        elif services:
            first = next(iter(services.values()))
            baseline.management_acl_applied = Observation[bool].found(
                False, first["raw"], first["line"],
                note="No IP service address restrictions configured.",
            )
        else:
            baseline.management_acl_applied = Observation[bool].unknown(
                "No /ip service configuration found to assess management ACL.",
            )

        port_changed = False
        port_evidence_raw = None
        port_evidence_line = None
        default_ports = {
            "telnet": "23", "ftp": "21", "www": "80", "ssh": "22",
            "www-ssl": "443", "api": "8728", "winbox": "8291", "api-ssl": "8729",
        }
        for svc_name, info in services.items():
            if "port" in info["props"]:
                default = default_ports.get(svc_name)
                if default and info["props"]["port"] != default:
                    port_changed = True
                    port_evidence_raw = info["raw"]
                    port_evidence_line = info["line"]
                    break

        if port_changed:
            baseline.admin_default_ports_changed = Observation[bool].found(
                True, port_evidence_raw, port_evidence_line,
                note="Service port changed from default.",
            )
        elif services:
            first = next(iter(services.values()))
            baseline.admin_default_ports_changed = Observation[bool].found(
                False, first["raw"], first["line"],
                note="All services use default ports.",
            )
        else:
            baseline.admin_default_ports_changed = Observation[bool].unknown(
                "No /ip service configuration found.",
            )

    # -- SSH ------------------------------------------------------------------

    def _normalize_ssh(self, baseline: SecurityBaselineModel) -> None:
        for cmd, raw, line in self._get_section("/ip ssh"):
            props = _parse_props(cmd)
            if "strong-crypto" in props:
                is_strong = props["strong-crypto"] == "yes"
                baseline.strong_crypto_enabled = Observation[bool].found(
                    is_strong, raw, line,
                    note="SSH strong-crypto is " + ("enabled" if is_strong else "disabled") + ".",
                )
                return

        hit = self._first(r"^\s*/ip\s+ssh\s+set\s+.*strong-crypto=(\S+)")
        if hit:
            m, raw, line = hit
            is_strong = m.group(1) == "yes"
            baseline.strong_crypto_enabled = Observation[bool].found(
                is_strong, raw, line,
            )
            return

        baseline.strong_crypto_enabled = Observation[bool].absent(
            False,
            "SSH strong-crypto not configured; default is disabled.",
        )

    # -- SNMP -----------------------------------------------------------------

    def _normalize_snmp(self, baseline: SecurityBaselineModel) -> None:
        snmp_enabled = False
        snmp_evidence_raw = None
        snmp_evidence_line = None

        for cmd, raw, line in self._get_section("/snmp"):
            props = _parse_props(cmd)
            if "enabled" in props:
                snmp_enabled = props["enabled"] == "yes"
                snmp_evidence_raw = raw
                snmp_evidence_line = line

        if snmp_evidence_raw:
            baseline.snmp_agent_enabled = Observation[bool].found(
                snmp_enabled, snmp_evidence_raw, snmp_evidence_line,
            )
        else:
            baseline.snmp_agent_enabled = Observation[bool].absent(
                False, "SNMP is not enabled (disabled by default in RouterOS).",
            )

        communities: List[SnmpCommunity] = []
        for cmd, raw, line in self._get_section("/snmp community"):
            clean = re.sub(r"\[.*?\]", "", cmd).strip()
            props = _parse_props(clean)
            name = props.get("name")
            if not name:
                continue
            access_str = props.get("write-access", "no")
            access = "rw" if access_str == "yes" else "ro"
            acl = props.get("addresses")
            if acl == "0.0.0.0/0":
                acl = None
            communities.append(
                SnmpCommunity(
                    name=name,
                    access=access,
                    acl=acl,
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
                [], "No SNMP community strings configured.",
            )

        has_v3 = False
        v3_evidence_raw = None
        v3_evidence_line = None
        for cmd, raw, line in self._get_section("/snmp community"):
            clean = re.sub(r"\[.*?\]", "", cmd).strip()
            props = _parse_props(clean)
            security = props.get("security", "none")
            if security in ("authorized", "private"):
                has_v3 = True
                v3_evidence_raw = raw
                v3_evidence_line = line
                break

        if has_v3:
            baseline.snmp_v3_users_present = Observation[bool].found(
                True, v3_evidence_raw, v3_evidence_line,
                note="SNMPv3 security configured (security=authorized or private).",
            )
        elif communities:
            baseline.snmp_v3_users_present = Observation[bool].found(
                False, communities[0].source_line, communities[0].line_number,
                note="SNMP communities use security=none (SNMPv1/v2c only).",
            )
        else:
            baseline.snmp_v3_users_present = Observation[bool].unknown(
                "No SNMP community configuration found.",
            )

    # -- NTP ------------------------------------------------------------------

    def _normalize_ntp(self, baseline: SecurityBaselineModel) -> None:
        ntp_enabled = False
        ntp_evidence_raw = None
        ntp_evidence_line = None

        for cmd, raw, line in self._get_section("/system ntp client"):
            props = _parse_props(cmd)
            if "enabled" in props:
                ntp_enabled = props["enabled"] == "yes"
                ntp_evidence_raw = raw
                ntp_evidence_line = line

        servers: List[str] = []
        server_evidence_raw = None
        server_evidence_line = None

        for cmd, raw, line in self._get_section("/system ntp client servers"):
            props = _parse_props(cmd)
            addr = props.get("address")
            if addr:
                servers.append(addr)
                if server_evidence_raw is None:
                    server_evidence_raw = raw
                    server_evidence_line = line

        if servers and ntp_enabled:
            baseline.ntp_servers = Observation[List[str]].found(
                servers, server_evidence_raw, server_evidence_line,
            )
            baseline.ntp_redundant = Observation[bool].found(
                len(servers) >= 2, server_evidence_raw, server_evidence_line,
            )
        elif ntp_enabled:
            baseline.ntp_servers = Observation[List[str]].found(
                [], ntp_evidence_raw, ntp_evidence_line,
                note="NTP client enabled but no servers configured.",
            )
            baseline.ntp_redundant = Observation[bool].found(
                False, ntp_evidence_raw, ntp_evidence_line,
            )
        else:
            note = "NTP client is not enabled."
            baseline.ntp_servers = Observation[List[str]].absent([], note)
            baseline.ntp_redundant = Observation[bool].absent(False, note)

    # -- DNS ------------------------------------------------------------------

    def _normalize_dns(self, baseline: SecurityBaselineModel) -> None:
        for cmd, raw, line in self._get_section("/ip dns"):
            props = _parse_props(cmd)
            if "servers" in props:
                servers = [s.strip() for s in props["servers"].split(",") if s.strip()]
                baseline.dns_servers = Observation[List[str]].found(
                    servers, raw, line,
                )
                return

        hit = self._first(r"^\s*/ip\s+dns\s+set\s+.*servers=(\S+)")
        if hit:
            m, raw, line = hit
            servers = [s.strip() for s in m.group(1).split(",") if s.strip()]
            baseline.dns_servers = Observation[List[str]].found(
                servers, raw, line,
            )
            return

        baseline.dns_servers = Observation[List[str]].absent(
            [], "No DNS servers configured.",
        )

    # -- logging --------------------------------------------------------------

    def _normalize_logging(self, baseline: SecurityBaselineModel) -> None:
        remote_hosts: List[str] = []
        evidence_raw = None
        evidence_line = None

        for cmd, raw, line in self._get_section("/system logging action"):
            props = _parse_props(cmd)
            remote = props.get("remote")
            if remote and remote != "0.0.0.0":
                remote_hosts.append(remote)
                if evidence_raw is None:
                    evidence_raw = raw
                    evidence_line = line

        has_remote_topics = False
        topic_evidence_raw = None
        topic_evidence_line = None
        for cmd, raw, line in self._get_section("/system logging"):
            props = _parse_props(cmd)
            action = props.get("action", "")
            if "remote" in action or "syslog" in action:
                has_remote_topics = True
                if topic_evidence_raw is None:
                    topic_evidence_raw = raw
                    topic_evidence_line = line

        if remote_hosts:
            baseline.logging_enabled = Observation[bool].found(
                True, evidence_raw, evidence_line,
                note="Remote syslog servers are configured.",
            )
            baseline.logging_hosts = Observation[List[str]].found(
                remote_hosts, evidence_raw, evidence_line,
            )
        elif has_remote_topics:
            baseline.logging_enabled = Observation[bool].found(
                True, topic_evidence_raw, topic_evidence_line,
                note="Remote logging topics configured.",
            )
            baseline.logging_hosts = Observation[List[str]].found(
                [], topic_evidence_raw, topic_evidence_line,
                note="Remote action referenced but no remote host in export.",
            )
        else:
            baseline.logging_enabled = Observation[bool].absent(
                False, "No remote logging configured.",
            )
            baseline.logging_hosts = Observation[List[str]].absent(
                [], "No remote syslog hosts configured.",
            )

        baseline.logging_buffered = Observation[bool].found(
            True, "RouterOS default", None,
            note="RouterOS logs to memory by default.",
        )
        baseline.event_logging_enabled = Observation[bool].found(
            True, "RouterOS default", None,
            note="RouterOS logs system events to memory by default.",
        )

    # -- banner ---------------------------------------------------------------

    def _normalize_banner(self, baseline: SecurityBaselineModel) -> None:
        for cmd, raw, line in self._get_section("/system note"):
            props = _parse_props(cmd)
            show = props.get("show-at-login", "yes")
            note_text = props.get("note", "")

            if show == "yes" and note_text:
                baseline.login_banner_present = Observation[bool].found(
                    True, raw, line,
                )
                baseline.pre_login_banner_present = Observation[bool].found(
                    True, raw, line,
                )
                baseline.post_login_banner_present = Observation[bool].found(
                    True, raw, line,
                    note="System note displayed after login.",
                )
                return
            elif show == "no" or not note_text:
                baseline.login_banner_present = Observation[bool].found(
                    False, raw, line,
                    note="System note is disabled or empty.",
                )
                baseline.pre_login_banner_present = Observation[bool].found(
                    False, raw, line,
                    note="System note is disabled or empty.",
                )
                baseline.post_login_banner_present = Observation[bool].found(
                    False, raw, line,
                    note="System note is disabled or empty.",
                )
                return

        baseline.login_banner_present = Observation[bool].absent(
            False, "No system note configured.",
        )
        baseline.pre_login_banner_present = Observation[bool].absent(
            False, "No system note configured.",
        )
        baseline.post_login_banner_present = Observation[bool].absent(
            False, "No system note configured.",
        )

    # -- user management & AAA ------------------------------------------------

    def _normalize_users(self, baseline: SecurityBaselineModel) -> None:
        use_radius = False
        aaa_evidence_raw = None
        aaa_evidence_line = None

        for cmd, raw, line in self._get_section("/user aaa"):
            props = _parse_props(cmd)
            if "use-radius" in props:
                use_radius = props["use-radius"] == "yes"
                aaa_evidence_raw = raw
                aaa_evidence_line = line

        if aaa_evidence_raw:
            baseline.aaa_enabled = Observation[bool].found(
                use_radius, aaa_evidence_raw, aaa_evidence_line,
                note="RADIUS authentication is " + ("enabled" if use_radius else "disabled") + ".",
            )
        else:
            baseline.aaa_enabled = Observation[bool].absent(
                False, "No /user aaa configuration found; RADIUS is off by default.",
            )

        # default user admin configuration:
        # inactivity-policy defaults to "none"
        # inactivity-timeout defaults to "10m"
        # disabled defaults to False
        users = {
            "admin": {
                "policy": "none",
                "timeout": "10m",
                "disabled": False,
                "raw": "RouterOS default",
                "line": None
            }
        }

        for cmd, raw, line in self._get_section("/user"):
            clean = re.sub(r"\[.*?\]", "", cmd).strip()
            parts = clean.split()
            if not parts:
                continue
            verb = parts[0]
            props = _parse_props(clean)

            if verb == "add":
                name = props.get("name")
                if name:
                    users[name] = {
                        "policy": props.get("inactivity-policy", "none"),
                        "timeout": props.get("inactivity-timeout", "10m"),
                        "disabled": props.get("disabled") == "yes",
                        "raw": raw,
                        "line": line
                    }
            elif verb == "set":
                is_default_find = "find default=yes" in cmd or "default=yes" in cmd
                target_user = None
                
                if is_default_find:
                    target_user = "admin"
                    if "name" in props:
                        new_name = props["name"]
                        if "admin" in users:
                            users[new_name] = users.pop("admin")
                        target_user = new_name
                else:
                    m_name = re.search(r"find name=([\w-]+)", cmd)
                    if m_name:
                        target_user = m_name.group(1)
                    elif len(parts) >= 2:
                        if "=" not in parts[1]:
                            target_user = parts[1]
                
                if target_user:
                    if target_user not in users:
                        users[target_user] = {
                            "policy": "none",
                            "timeout": "10m",
                            "disabled": False,
                            "raw": raw,
                            "line": line
                        }
                    if "inactivity-policy" in props:
                        users[target_user]["policy"] = props["inactivity-policy"]
                    if "inactivity-timeout" in props:
                        users[target_user]["timeout"] = props["inactivity-timeout"]
                    if "disabled" in props:
                        users[target_user]["disabled"] = props["disabled"] == "yes"
                    if "name" in props:
                        new_name = props["name"]
                        if target_user != new_name:
                            users[new_name] = users.pop(target_user)
                            target_user = new_name
                    users[target_user]["raw"] = raw
                    users[target_user]["line"] = line

        active_users = {name: info for name, info in users.items() if not info["disabled"]}

        if not active_users:
            baseline.vty_exec_timeout_seconds = Observation[int].absent(
                0,
                note="All local users are disabled."
            )
        else:
            effective_timeouts = []
            user_notes = []
            has_explicit_config = False
            explicit_raw = None
            explicit_line = None

            for name, info in active_users.items():
                policy = info["policy"]
                timeout_str = info["timeout"]
                
                if info["raw"] != "RouterOS default":
                    has_explicit_config = True
                    if explicit_raw is None:
                        explicit_raw = info["raw"]
                        explicit_line = info["line"]

                eff_t = 0
                if policy == "logout":
                    parsed = _parse_ros_time(timeout_str) if timeout_str else None
                    eff_t = parsed if parsed is not None else 600
                
                effective_timeouts.append(eff_t)
                user_notes.append(f"user '{name}': policy={policy}, timeout={timeout_str} (effective={eff_t}s)")

            if 0 in effective_timeouts:
                overall_timeout = 0
            else:
                overall_timeout = max(effective_timeouts)

            notes_str = "; ".join(user_notes)
            if overall_timeout > 0:
                baseline.vty_exec_timeout_seconds = Observation[int].found(
                    overall_timeout,
                    explicit_raw or "RouterOS defaults",
                    explicit_line,
                    note=f"Effective session timeout: {overall_timeout}s. Details: {notes_str}"
                )
            else:
                if has_explicit_config:
                    baseline.vty_exec_timeout_seconds = Observation[int].found(
                        0,
                        explicit_raw,
                        explicit_line,
                        note=f"No effective session logout timeout enforced (policy is none or lockscreen). Details: {notes_str}"
                    )
                else:
                    baseline.vty_exec_timeout_seconds = Observation[int].absent(
                        0,
                        note=f"No inactivity timeout or policy configured. RouterOS default policy is none (no timeout). Details: {notes_str}"
                    )

    # -- password controls ----------------------------------------------------

    def _normalize_passwords(self, baseline: SecurityBaselineModel) -> None:
        baseline.enable_secret_set = Observation[bool].unknown(
            "RouterOS does not support an enable secret; administrative privileges are user-group based."
        )
        baseline.password_encryption = Observation[bool].found(
            True, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="RouterOS always stores passwords in hashed form.",
        )
        baseline.enable_password_present = Observation[bool].found(
            False, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="RouterOS does not have a reversible enable password.",
        )

        note_no_policy = (
            "RouterOS does not have built-in password policy enforcement "
            "(min-length, complexity, expiration, history). "
            "Password strength is the administrator's responsibility."
        )
        baseline.password_min_length = Observation[int].unknown(note_no_policy)
        baseline.password_min_uppercase = Observation[int].unknown(note_no_policy)
        baseline.password_min_lowercase = Observation[int].unknown(note_no_policy)
        baseline.password_min_numeric = Observation[int].unknown(note_no_policy)
        baseline.password_min_special = Observation[int].unknown(note_no_policy)
        baseline.password_max_age_days = Observation[int].unknown(note_no_policy)
        baseline.password_history_reuse_limit = Observation[int].unknown(note_no_policy)

        baseline.admin_lockout_threshold = Observation[int].unknown(
            "RouterOS does not have built-in account lockout. "
            "Brute-force protection requires firewall rules.",
        )
        baseline.admin_lockout_duration = Observation[int].unknown(
            "RouterOS does not have built-in account lockout duration.",
        )
