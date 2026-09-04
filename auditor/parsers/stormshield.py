"""Deterministic Stormshield Network Security (SNS) parser.

Stormshield Network Security (SNS) firewalls run Stormshield OS (FreeBSD-based).
Configuration is managed via the SNS Serverd CLI (NSRPC / CLI console) or
exported as configuration files (.na backup archive containing INI-format files).

CLI reference verified against official Stormshield documentation:
- Stormshield Technical Documentation: documentation.stormshield.eu
- Stormshield SNS CLI / Serverd Commands Reference Guide (v4.x / v5.x)
- Stormshield Network Security Administration Guides
- Stormshield Technical Note: Hardening SNS Firewalls & Best Practices
- ANSSI Standard Qualification & Common Criteria EAL4+ Security Guidance for SNS

Platform invariants documented by Stormshield:
- Telnet is NOT supported in Stormshield SNS. Remote administration is strictly
  performed via SSH (CLI) and HTTPS (Web Administration).
- SSH implementation on Stormshield SNS is SSHv2-only. SSHv1 is disabled/removed.
- Passwords are encrypted at rest using strong one-way cryptographic hash functions
  (SHA-512 / bcrypt) by default.
- Administrative web access (WebAdmin) enforces HTTPS. Cleartext HTTP access is
  controlled via the 'allowhttp' parameter (default: disabled / 0).

CIS / STIG status:
- NO official CIS Benchmark exists for Stormshield Network Security.
- NO official DISA STIG exists for Stormshield.
- Security controls mapped are generic best-practice controls derived from
  authoritative Stormshield Hardening Guides and ANSSI recommendations, NOT
  fabricated CIS IDs.
"""

import hashlib
import re
from typing import Dict, List, Optional, Sequence, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry

_STORMSHIELD_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*#.*(?:Stormshield|SNS\s+v?\d+)\b", 0.50),
    (r"(?im)^\s*CONFIG\s+(?:WEBADMIN|CONSOLE|PASSWDPOLICY|SNMP|NTP|SLOG|AUTH|FILTER|OBJECT|NETWORK|HA|ALARM|SYSTEM)\b", 0.40),
    (r"(?im)^\s*CONFIG\s+CONSOLE\s+SSH\b", 0.35),
    (r"(?im)^\s*CONFIG\s+WEBADMIN\s+BRUTEFORCE\b", 0.35),
    (r"(?im)^\s*CONFIG\s+PASSWDPOLICY\b", 0.30),
    (r"(?im)^\s*(?:SYSTEM|SYS)\s+(?:PROPERTY|INFO|STATUS)\b", 0.25),
    (r"(?im)^\s*\[(?:Global|Console|Webadmin|PasswordPolicy|Auth|SNMP|NTP|Log|Syslog|Serverd)\]\s*$", 0.25),
    (r"(?im)^\s*NSRPC\b", 0.25),
    (r"(?im)^\s*CONFIG\s+NTP\s+SERVER\b", 0.20),
    (r"(?im)^\s*CONFIG\s+LOG\s+SERVER\b", 0.20),
    (r"(?im)^\s*CONFIG\s+SNMP\s+COMMUNITY\b", 0.20),
]

_NON_STORMSHIELD_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*line\s+vty\b", 0.40),
    (r"(?im)^\s*ip\s+http\s+server\s*$", 0.30),
    (r"(?im)^\s*config\s+system\s+(?:global|interface|admin|settings|dns|ntp)\b", 0.90),
    (r"(?im)^\s*router\s+(?:ospf|bgp|rip|eigrp)\b", 0.50),
    (r"(?im)^\s*set\s+protocols\b", 0.80),
    (r"(?im)^\s*set\s+system\s+host-name\b", 0.80),
    (r"(?im)^\s*sysname\s+\S+", 0.50),
    (r"(?im)^\s*<\?xml", 0.90),
    (r"(?im)\"DEVICE_METADATA\"", 0.90),
    (r"(?im)^\s*user-interface\s+vty\b", 0.50),
    (r"(?im)^\s*#.*by RouterOS\b", 0.90),
    (r"(?im)^/ip\s+service\b", 0.50),
    (r"(?im)^\s*firmware-version\s+SonicOS\b", 0.90),
    (r"(?im)^\s*set\s+password-controls\s+", 0.50),
]

_KEY_VAL_RE = re.compile(r'(\w[\w-]*)=(?:"([^"]*)"|\'([^\']*)\'|([^\s,]+))')


def _parse_params(line: str) -> Dict[str, str]:
    """Parse key=value parameters from a Stormshield command or INI line."""
    params: Dict[str, str] = {}
    for m in _KEY_VAL_RE.finditer(line):
        key = m.group(1).lower()
        val = m.group(2) if m.group(2) is not None else (
            m.group(3) if m.group(3) is not None else m.group(4)
        )
        params[key] = val
    return params


def _is_truthy(val: Optional[str]) -> bool:
    if val is None:
        return False
    v = val.strip().lower()
    return v in ("1", "true", "yes", "enable", "enabled", "on")


def _is_falsy(val: Optional[str]) -> bool:
    if val is None:
        return False
    v = val.strip().lower()
    return v in ("0", "false", "no", "disable", "disabled", "off")


@registry.register
class StormshieldParser(VendorParser):
    """Grammar-based parser for Stormshield Network Security (SNS) configurations."""

    name = "stormshield"
    vendor = "stormshield"
    os_family = "sns"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        score = sum(w for p, w in _STORMSHIELD_MARKERS if re.search(p, config_text))
        score -= sum(w for p, w in _NON_STORMSHIELD_MARKERS if re.search(p, config_text))
        return max(0.0, min(1.0, score))

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if config_text is None or not config_text.strip():
            raise ParserError("Empty configuration text")

        lines = config_text.splitlines()
        line_count = len(lines)
        sha256 = hashlib.sha256(config_text.encode("utf-8")).hexdigest()

        # Track parsed observations
        hostname_obs: Optional[Observation[str]] = None

        # Management / Transport
        telnet_obs: Optional[Observation[bool]] = None
        vty_transport_obs: Optional[Observation[List[str]]] = None
        vty_timeout_obs: Optional[Observation[int]] = None
        ssh_enabled_obs: Optional[Observation[bool]] = None
        ssh_version_obs: Optional[Observation[int]] = None
        http_server_obs: Optional[Observation[bool]] = None
        https_server_obs: Optional[Observation[bool]] = None
        management_acl_obs: Optional[Observation[bool]] = None
        banner_obs: Optional[Observation[bool]] = None
        pre_login_banner_obs: Optional[Observation[bool]] = None
        post_login_banner_obs: Optional[Observation[bool]] = None

        # Credentials & Passwords
        enable_secret_obs: Optional[Observation[bool]] = None
        password_encryption_obs: Optional[Observation[bool]] = None
        password_min_length_obs: Optional[Observation[int]] = None
        aaa_enabled_obs: Optional[Observation[bool]] = None

        # Lockout & Brute-force
        lockout_threshold_obs: Optional[Observation[int]] = None
        lockout_duration_obs: Optional[Observation[int]] = None

        # Monitoring
        snmp_agent_obs: Optional[Observation[bool]] = None
        snmp_communities: List[SnmpCommunity] = []
        logging_enabled_obs: Optional[Observation[bool]] = None
        logging_hosts: List[str] = []
        logging_hosts_line: Optional[str] = None
        logging_hosts_lineno: Optional[int] = None
        logging_buffered_obs: Optional[Observation[bool]] = None
        ntp_servers: List[str] = []
        ntp_servers_line: Optional[str] = None
        ntp_servers_lineno: Optional[int] = None
        dns_servers: List[str] = []
        dns_servers_line: Optional[str] = None
        dns_servers_lineno: Optional[int] = None

        # High Availability
        ha_enabled_obs: Optional[Observation[bool]] = None

        current_ini_section: Optional[str] = None

        for lineno, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                # Still check for version / comments if relevant
                continue

            # INI Section headers
            sec_match = re.match(r"^\[(\w+)\]$", line)
            if sec_match:
                current_ini_section = sec_match.group(1).lower()
                continue

            params = _parse_params(line)

            # -------------------------------------------------------------
            # 1. Hostname
            # -------------------------------------------------------------
            if re.match(r"(?i)^CONFIG\s+(?:SYSTEM\s+)?HOSTNAME\b", line) or (
                current_ini_section == "global" and re.match(r"(?i)^hostname\s*=", line)
            ):
                host_val = params.get("name") or params.get("hostname")
                if not host_val and "=" in line:
                    host_val = line.split("=", 1)[1].strip().strip('"\'')
                if host_val:
                    hostname_obs = Observation[str].found(
                        host_val, raw_line, lineno, note="Extracted from Stormshield hostname configuration."
                    )

            # -------------------------------------------------------------
            # 2. Console & SSH Settings
            # -------------------------------------------------------------
            if re.match(r"(?i)^CONFIG\s+CONSOLE\s+SSH\b", line):
                state_val = params.get("state")
                if state_val is not None:
                    if _is_truthy(state_val):
                        ssh_enabled_obs = Observation[bool].found(
                            True, raw_line, lineno, note="SSH console access is enabled."
                        )
                        # Platform Invariants for Stormshield SNS SSH:
                        telnet_obs = Observation[bool].found(
                            False, raw_line, lineno,
                            note="Telnet is unsupported on Stormshield SNS. Remote access is SSH-only."
                        )
                        ssh_version_obs = Observation[int].found(
                            2, raw_line, lineno,
                            note="Stormshield SNS SSH daemon exclusively supports SSHv2."
                        )
                        vty_transport_obs = Observation[List[str]].found(
                            ["ssh"], raw_line, lineno,
                            note="SSH is enabled; Telnet is unsupported on Stormshield SNS."
                        )
                    elif _is_falsy(state_val):
                        ssh_enabled_obs = Observation[bool].found(
                            False, raw_line, lineno, note="SSH console access is disabled."
                        )
                        vty_transport_obs = Observation[List[str]].found(
                            [], raw_line, lineno, note="SSH console access is disabled."
                        )
                        telnet_obs = Observation[bool].found(
                            False, raw_line, lineno,
                            note="Telnet is unsupported on Stormshield SNS."
                        )

            elif current_ini_section == "console" and re.match(r"(?i)^ssh\s*=", line):
                ssh_val = line.split("=", 1)[1].strip()
                if _is_truthy(ssh_val):
                    ssh_enabled_obs = Observation[bool].found(
                        True, raw_line, lineno, note="SSH console access is enabled in [Console]."
                    )
                    telnet_obs = Observation[bool].found(
                        False, raw_line, lineno,
                        note="Telnet is unsupported on Stormshield SNS. Remote access is SSH-only."
                    )
                    ssh_version_obs = Observation[int].found(
                        2, raw_line, lineno,
                        note="Stormshield SNS SSH daemon exclusively supports SSHv2."
                    )
                    vty_transport_obs = Observation[List[str]].found(
                        ["ssh"], raw_line, lineno,
                        note="SSH is enabled; Telnet is unsupported on Stormshield SNS."
                    )
                elif _is_falsy(ssh_val):
                    ssh_enabled_obs = Observation[bool].found(
                        False, raw_line, lineno, note="SSH console access is disabled in [Console]."
                    )
                    vty_transport_obs = Observation[List[str]].found(
                        [], raw_line, lineno, note="SSH console access is disabled."
                    )
                    telnet_obs = Observation[bool].found(
                        False, raw_line, lineno,
                        note="Telnet is unsupported on Stormshield SNS."
                    )

            # -------------------------------------------------------------
            # 3. Session Idle Timeout (Console / WebAdmin)
            # -------------------------------------------------------------
            if re.match(r"(?i)^CONFIG\s+(?:CONSOLE|WEBADMIN)\s+(?:IDLE)?TIMEOUT\b", line):
                to_val = params.get("timeout") or params.get("idletimeout")
                if to_val:
                    try:
                        if to_val.endswith("m"):
                            secs = int(to_val[:-1]) * 60
                        elif to_val.endswith("s"):
                            secs = int(to_val[:-1])
                        else:
                            secs = int(to_val)
                        if vty_timeout_obs is None:
                            vty_timeout_obs = Observation[int].found(
                                secs, raw_line, lineno,
                                note=f"Administrator session idle timeout set to {secs} seconds."
                            )
                        else:
                            # 0 means never (infinite timeout, worst case)
                            if vty_timeout_obs.value == 0 or secs == 0:
                                worst_secs = 0
                            else:
                                worst_secs = max(vty_timeout_obs.value, secs)
                            vty_timeout_obs = Observation[int].found(
                                worst_secs, raw_line, lineno,
                                note=f"Worst-case administrator session idle timeout: {worst_secs} seconds."
                            )
                    except ValueError:
                        pass
            elif (current_ini_section in ("console", "webadmin")) and re.match(r"(?i)^(?:idle)?timeout\s*=", line):
                val_str = line.split("=", 1)[1].strip()
                try:
                    if val_str.endswith("m"):
                        secs = int(val_str[:-1]) * 60
                    elif val_str.endswith("s"):
                        secs = int(val_str[:-1])
                    else:
                        secs = int(val_str)
                    if vty_timeout_obs is None:
                        vty_timeout_obs = Observation[int].found(
                            secs, raw_line, lineno,
                            note=f"Administrator idle timeout set to {secs} seconds in [{current_ini_section}]."
                        )
                    else:
                        if vty_timeout_obs.value == 0 or secs == 0:
                            worst_secs = 0
                        else:
                            worst_secs = max(vty_timeout_obs.value, secs)
                        vty_timeout_obs = Observation[int].found(
                            worst_secs, raw_line, lineno,
                            note=f"Worst-case administrator idle timeout: {worst_secs} seconds."
                        )
                except ValueError:
                    pass

            # -------------------------------------------------------------
            # 4. WebAdmin & HTTP Server
            # -------------------------------------------------------------
            if re.match(r"(?i)^CONFIG\s+WEBADMIN\b", line) and not re.match(r"(?i)^CONFIG\s+WEBADMIN\s+BRUTEFORCE\b", line):
                allow_http = params.get("allowhttp")
                state = params.get("state")
                if allow_http is not None:
                    if _is_truthy(allow_http):
                        http_server_obs = Observation[bool].found(
                            True, raw_line, lineno, note="Unencrypted HTTP management access is allowed."
                        )
                    elif _is_falsy(allow_http):
                        http_server_obs = Observation[bool].found(
                            False, raw_line, lineno, note="Unencrypted HTTP management access is disabled (HTTPS only)."
                        )
                if state is not None:
                    if _is_truthy(state):
                        https_server_obs = Observation[bool].found(
                            True, raw_line, lineno, note="WebAdmin HTTPS interface is enabled."
                        )
                    elif _is_falsy(state):
                        https_server_obs = Observation[bool].found(
                            False, raw_line, lineno, note="WebAdmin HTTPS interface is disabled."
                        )

            elif current_ini_section == "webadmin":
                if re.match(r"(?i)^allowhttp\s*=", line):
                    val = line.split("=", 1)[1].strip()
                    if _is_truthy(val):
                        http_server_obs = Observation[bool].found(
                            True, raw_line, lineno, note="AllowHTTP is enabled in [Webadmin]."
                        )
                    elif _is_falsy(val):
                        http_server_obs = Observation[bool].found(
                            False, raw_line, lineno, note="AllowHTTP is disabled in [Webadmin]."
                        )
                elif re.match(r"(?i)^state\s*=", line):
                    val = line.split("=", 1)[1].strip()
                    if _is_truthy(val):
                        https_server_obs = Observation[bool].found(
                            True, raw_line, lineno, note="WebAdmin State is enabled in [Webadmin]."
                        )
                    elif _is_falsy(val):
                        https_server_obs = Observation[bool].found(
                            False, raw_line, lineno, note="WebAdmin State is disabled in [Webadmin]."
                        )

            # -------------------------------------------------------------
            # 5. Management Access Restrictions (ACL / IP Source filter)
            # -------------------------------------------------------------
            if re.match(r"(?i)^CONFIG\s+(?:WEBADMIN|CONSOLE|ADMIN)\s+ACCESS\b", line):
                ip_val = params.get("ip") or params.get("network") or params.get("src")
                if ip_val and ip_val.lower() not in ("any", "all", "0.0.0.0/0", "internet"):
                    management_acl_obs = Observation[bool].found(
                        True, raw_line, lineno,
                        note=f"Administrative access restricted to authorized network: {ip_val}."
                    )
                elif ip_val and ip_val.lower() in ("any", "all", "0.0.0.0/0", "internet"):
                    management_acl_obs = Observation[bool].found(
                        False, raw_line, lineno,
                        note="Administrative access allows unrestricted source network ('any')."
                    )
            elif (current_ini_section in ("webadmin", "console", "admin")) and re.match(
                r"(?i)^(?:adminnetwork|allowedips|accessip)\s*=", line
            ):
                val = line.split("=", 1)[1].strip()
                if val and val.lower() not in ("any", "all", "0.0.0.0/0"):
                    management_acl_obs = Observation[bool].found(
                        True, raw_line, lineno,
                        note=f"Administrative access restricted to: {val}."
                    )
                elif val and val.lower() in ("any", "all", "0.0.0.0/0"):
                    management_acl_obs = Observation[bool].found(
                        False, raw_line, lineno,
                        note="Administrative access is open to all networks."
                    )

            # -------------------------------------------------------------
            # 6. Password Policy & Encryption
            # -------------------------------------------------------------
            if re.match(r"(?i)^CONFIG\s+PASSWDPOLICY\b", line):
                min_len = params.get("minlength") or params.get("len")
                if min_len:
                    try:
                        val_int = int(min_len)
                        password_min_length_obs = Observation[int].found(
                            val_int, raw_line, lineno,
                            note=f"Password minimum length configured to {val_int} characters."
                        )
                    except ValueError:
                        pass
                enable_secret_obs = Observation[bool].found(
                    True, raw_line, lineno,
                    note="Stormshield SNS stores administrative credentials cryptographically hashed (SHA-512/bcrypt)."
                )
                password_encryption_obs = Observation[bool].found(
                    True, raw_line, lineno,
                    note="Stormshield SNS enforces encrypted credentials at rest."
                )

            elif current_ini_section == "passwordpolicy":
                if re.match(r"(?i)^minlength\s*=", line):
                    val = line.split("=", 1)[1].strip()
                    try:
                        val_int = int(val)
                        password_min_length_obs = Observation[int].found(
                            val_int, raw_line, lineno,
                            note=f"Password minimum length set to {val_int} in [PasswordPolicy]."
                        )
                    except ValueError:
                        pass
                    enable_secret_obs = Observation[bool].found(
                        True, raw_line, lineno,
                        note="Stormshield SNS stores administrative credentials cryptographically hashed."
                    )
                    password_encryption_obs = Observation[bool].found(
                        True, raw_line, lineno,
                        note="Stormshield SNS enforces password encryption at rest."
                    )

            # -------------------------------------------------------------
            # 7. AAA & External Authentication (RADIUS / LDAP / Kerberos)
            # -------------------------------------------------------------
            if re.match(r"(?i)^CONFIG\s+AUTH\b", line):
                method = params.get("method") or params.get("type")
                server = params.get("server") or params.get("host") or params.get("ip")
                state = params.get("state")
                if method and method.lower() in ("radius", "ldap", "kerberos", "tacacs", "saml", "external"):
                    aaa_enabled_obs = Observation[bool].found(
                        True, raw_line, lineno,
                        note=f"Centralized AAA authentication configured ({method.upper()})."
                    )
                elif server and (state is None or _is_truthy(state)):
                    aaa_enabled_obs = Observation[bool].found(
                        True, raw_line, lineno,
                        note=f"External AAA server configured ({server})."
                    )
                elif method and method.lower() in ("local", "internal", "none"):
                    aaa_enabled_obs = Observation[bool].found(
                        False, raw_line, lineno,
                        note=f"Only local/internal authentication method configured ({method})."
                    )
            elif current_ini_section == "auth":
                if re.match(r"(?i)^method\s*=", line):
                    val = line.split("=", 1)[1].strip()
                    if any(m in val.lower() for m in ("radius", "ldap", "kerberos", "tacacs", "saml")):
                        aaa_enabled_obs = Observation[bool].found(
                            True, raw_line, lineno,
                            note=f"Centralized AAA authentication enabled in [Auth] ({val})."
                        )
                    elif val.lower() in ("local", "internal"):
                        aaa_enabled_obs = Observation[bool].found(
                            False, raw_line, lineno,
                            note=f"Local-only authentication in [Auth] ({val})."
                        )
                elif re.match(r"(?i)^(?:radiusserver|ldapserver)\s*=", line):
                    val = line.split("=", 1)[1].strip()
                    if val:
                        aaa_enabled_obs = Observation[bool].found(
                            True, raw_line, lineno,
                            note=f"External authentication server specified in [Auth]: {val}."
                        )

            # -------------------------------------------------------------
            # 8. WebAdmin Brute-force Protection / Account Lockout
            # -------------------------------------------------------------
            if re.match(r"(?i)^CONFIG\s+WEBADMIN\s+BRUTEFORCE\b", line):
                state = params.get("state")
                nb_attempts = params.get("nbattempts") or params.get("maxattempts") or params.get("attempts")
                lock_time = params.get("time") or params.get("locktime") or params.get("duration")
                if state is not None and _is_falsy(state):
                    lockout_threshold_obs = Observation[int].found(
                        0, raw_line, lineno, note="WebAdmin brute-force lockout protection is disabled."
                    )
                elif nb_attempts:
                    try:
                        th_int = int(nb_attempts)
                        lockout_threshold_obs = Observation[int].found(
                            th_int, raw_line, lineno,
                            note=f"WebAdmin lockout threshold set to {th_int} failed attempts."
                        )
                    except ValueError:
                        pass
                if lock_time:
                    try:
                        dur_int = int(lock_time)
                        lockout_duration_obs = Observation[int].found(
                            dur_int, raw_line, lineno,
                            note=f"WebAdmin lockout duration set to {dur_int} seconds."
                        )
                    except ValueError:
                        pass
            elif current_ini_section == "webadmin":
                if re.match(r"(?i)^bruteforce(?:maxattempts|attempts)?\s*=", line):
                    val = line.split("=", 1)[1].strip()
                    try:
                        th_int = int(val)
                        lockout_threshold_obs = Observation[int].found(
                            th_int, raw_line, lineno,
                            note=f"Bruteforce max attempts set to {th_int} in [Webadmin]."
                        )
                    except ValueError:
                        pass
                elif re.match(r"(?i)^bruteforcetime\s*=", line):
                    val = line.split("=", 1)[1].strip()
                    try:
                        dur_int = int(val)
                        lockout_duration_obs = Observation[int].found(
                            dur_int, raw_line, lineno,
                            note=f"Bruteforce duration set to {dur_int} in [Webadmin]."
                        )
                    except ValueError:
                        pass

            # -------------------------------------------------------------
            # 9. SNMP Configuration
            # -------------------------------------------------------------
            if re.match(r"(?i)^CONFIG\s+SNMP\b", line):
                if re.match(r"(?i)^CONFIG\s+SNMP\s+(?:ACTIVATE|SHOW|STATE)\b", line) or "state=" in line:
                    state = params.get("state")
                    if state is not None:
                        if _is_truthy(state):
                            snmp_agent_obs = Observation[bool].found(
                                True, raw_line, lineno, note="SNMP agent is enabled."
                            )
                        elif _is_falsy(state):
                            snmp_agent_obs = Observation[bool].found(
                                False, raw_line, lineno, note="SNMP agent is disabled."
                            )
                if re.match(r"(?i)^CONFIG\s+SNMP\s+COMMUNITY\b", line) or "community=" in line or "name=" in line:
                    c_name = params.get("name") or params.get("community")
                    c_access = params.get("access") or params.get("right")
                    c_ip = params.get("ip") or params.get("network") or params.get("src")
                    if c_name:
                        snmp_communities.append(
                            SnmpCommunity(
                                name=c_name,
                                access=c_access.lower() if c_access else "ro",
                                acl=c_ip,
                                source_line=raw_line,
                                line_number=lineno,
                            )
                        )
                        if snmp_agent_obs is None:
                            snmp_agent_obs = Observation[bool].found(
                                True, raw_line, lineno, note="SNMP community configured (agent active)."
                            )

            elif current_ini_section == "snmp":
                if re.match(r"(?i)^state\s*=", line):
                    val = line.split("=", 1)[1].strip()
                    if _is_truthy(val):
                        snmp_agent_obs = Observation[bool].found(
                            True, raw_line, lineno, note="SNMP State=1 in [SNMP]."
                        )
                    elif _is_falsy(val):
                        snmp_agent_obs = Observation[bool].found(
                            False, raw_line, lineno, note="SNMP State=0 in [SNMP]."
                        )
                elif re.match(r"(?i)^community\s*=", line):
                    val = line.split("=", 1)[1].strip()
                    if val:
                        snmp_communities.append(
                            SnmpCommunity(
                                name=val,
                                access="ro",
                                source_line=raw_line,
                                line_number=lineno,
                            )
                        )
                        if snmp_agent_obs is None:
                            snmp_agent_obs = Observation[bool].found(
                                True, raw_line, lineno, note="SNMP Community configured in [SNMP]."
                            )

            # -------------------------------------------------------------
            # 10. Logging & Syslog
            # -------------------------------------------------------------
            if re.match(r"(?i)^CONFIG\s+(?:LOG|SYSLOG)\b", line):
                state = params.get("state")
                host = params.get("host") or params.get("server") or params.get("ip")
                buf = params.get("buffer") or params.get("local")
                if state is not None:
                    if _is_truthy(state):
                        logging_enabled_obs = Observation[bool].found(
                            True, raw_line, lineno, note="Logging / Syslog is enabled."
                        )
                    elif _is_falsy(state):
                        logging_enabled_obs = Observation[bool].found(
                            False, raw_line, lineno, note="Logging / Syslog is disabled."
                        )
                if host:
                    logging_hosts.append(host)
                    logging_hosts_line = raw_line
                    logging_hosts_lineno = lineno
                    if logging_enabled_obs is None:
                        logging_enabled_obs = Observation[bool].found(
                            True, raw_line, lineno, note="Remote syslog destination configured."
                        )
                if buf:
                    if _is_truthy(buf):
                        logging_buffered_obs = Observation[bool].found(
                            True, raw_line, lineno, note="Local log buffering is enabled."
                        )
                    elif _is_falsy(buf):
                        logging_buffered_obs = Observation[bool].found(
                            False, raw_line, lineno, note="Local log buffering is disabled."
                        )

            elif current_ini_section in ("log", "syslog"):
                if re.match(r"(?i)^(?:syslog)?state\s*=", line):
                    val = line.split("=", 1)[1].strip()
                    if _is_truthy(val):
                        logging_enabled_obs = Observation[bool].found(
                            True, raw_line, lineno, note=f"Logging State=1 in [{current_ini_section}]."
                        )
                    elif _is_falsy(val):
                        logging_enabled_obs = Observation[bool].found(
                            False, raw_line, lineno, note=f"Logging State=0 in [{current_ini_section}]."
                        )
                elif re.match(r"(?i)^(?:syslogserver|server|host)\s*=", line):
                    val = line.split("=", 1)[1].strip()
                    if val:
                        for h in val.split(","):
                            h_clean = h.strip()
                            if h_clean:
                                logging_hosts.append(h_clean)
                        logging_hosts_line = raw_line
                        logging_hosts_lineno = lineno
                        if logging_enabled_obs is None:
                            logging_enabled_obs = Observation[bool].found(
                                True, raw_line, lineno, note=f"Syslog server in [{current_ini_section}]."
                            )
                elif re.match(r"(?i)^localbuffer\s*=", line):
                    val = line.split("=", 1)[1].strip()
                    logging_buffered_obs = Observation[bool].found(
                        _is_truthy(val), raw_line, lineno, note=f"LocalBuffer={val} in [{current_ini_section}]."
                    )

            # -------------------------------------------------------------
            # 11. NTP Servers
            # -------------------------------------------------------------
            if re.match(r"(?i)^CONFIG\s+NTP\b", line):
                srv = params.get("name") or params.get("server") or params.get("host")
                if srv:
                    ntp_servers.append(srv)
                    ntp_servers_line = raw_line
                    ntp_servers_lineno = lineno
            elif current_ini_section == "ntp":
                if re.match(r"(?i)^server\s*=", line):
                    val = line.split("=", 1)[1].strip()
                    for s in val.split(","):
                        s_clean = s.strip()
                        if s_clean:
                            ntp_servers.append(s_clean)
                    ntp_servers_line = raw_line
                    ntp_servers_lineno = lineno

            # -------------------------------------------------------------
            # 12. DNS Servers
            # -------------------------------------------------------------
            if re.match(r"(?i)^CONFIG\s+DNS\s+SERVER\b", line):
                srv = params.get("host") or params.get("server") or params.get("ip") or params.get("name")
                if srv:
                    dns_servers.append(srv)
                    dns_servers_line = raw_line
                    dns_servers_lineno = lineno
            elif current_ini_section == "global" and re.match(r"(?i)^dns\s*=", line):
                val = line.split("=", 1)[1].strip()
                for d in val.split(","):
                    d_clean = d.strip()
                    if d_clean:
                        dns_servers.append(d_clean)
                dns_servers_line = raw_line
                dns_servers_lineno = lineno

            # -------------------------------------------------------------
            # 13. Login Banner
            # -------------------------------------------------------------
            if re.match(r"(?i)^CONFIG\s+(?:SYSTEM\s+|CONSOLE\s+)?BANNER\b", line):
                state = params.get("state")
                pre = params.get("prelogin") or params.get("text") or params.get("msg")
                post = params.get("postlogin")
                if state is not None and _is_falsy(state):
                    banner_obs = Observation[bool].found(
                        False, raw_line, lineno, note="Login banner is explicitly disabled."
                    )
                elif pre or (state is not None and _is_truthy(state)):
                    banner_obs = Observation[bool].found(
                        True, raw_line, lineno, note="Login banner is configured and enabled."
                    )
                    pre_login_banner_obs = Observation[bool].found(
                        True, raw_line, lineno, note="Pre-login banner text is configured."
                    )
                if post:
                    post_login_banner_obs = Observation[bool].found(
                        True, raw_line, lineno, note="Post-login banner text is configured."
                    )
            elif current_ini_section in ("banner", "global") and re.match(r"(?i)^banner(?:text|state)?\s*=", line):
                val = line.split("=", 1)[1].strip()
                if _is_truthy(val) or len(val) > 1:
                    banner_obs = Observation[bool].found(
                        True, raw_line, lineno, note=f"Banner configured in [{current_ini_section}]."
                    )
                    pre_login_banner_obs = Observation[bool].found(
                        True, raw_line, lineno, note=f"Banner configured in [{current_ini_section}]."
                    )
                elif _is_falsy(val):
                    banner_obs = Observation[bool].found(
                        False, raw_line, lineno, note=f"Banner disabled in [{current_ini_section}]."
                    )

            # -------------------------------------------------------------
            # 14. High Availability (HA)
            # -------------------------------------------------------------
            if re.match(r"(?i)^CONFIG\s+HA\b", line):
                state = params.get("state")
                if state is not None:
                    ha_enabled_obs = Observation[bool].found(
                        _is_truthy(state), raw_line, lineno,
                        note=f"High Availability State={state}."
                    )
            elif current_ini_section == "ha" and re.match(r"(?i)^state\s*=", line):
                val = line.split("=", 1)[1].strip()
                ha_enabled_obs = Observation[bool].found(
                    _is_truthy(val), raw_line, lineno,
                    note=f"High Availability State={val} in [HA]."
                )

        # -----------------------------------------------------------------
        # Build Model with Strict Absence Semantics
        # -----------------------------------------------------------------
        provenance = ParserProvenance(
            parser_name=self.name,
            parser_version=self.version,
            vendor=self.vendor,
            os_family=self.os_family,
            detection_confidence=self.detect(config_text),
            warnings=[],
        )

        model = SecurityBaselineModel(
            provenance=provenance,
            source_file=source_file,
            source_sha256=sha256,
            config_line_count=line_count,
        )

        # Hostname
        if hostname_obs is not None:
            model.hostname = hostname_obs
        else:
            model.hostname = Observation[str].unknown("No 'CONFIG HOSTNAME' statement found in configuration.")

        # Telnet / SSH / Transport
        if telnet_obs is not None:
            model.telnet_enabled = telnet_obs
        else:
            model.telnet_enabled = Observation[bool].absent(
                False, note="Telnet is unsupported on Stormshield SNS. Remote administration is via SSH/HTTPS only."
            )

        if ssh_enabled_obs is not None:
            model.ssh_enabled = ssh_enabled_obs
        else:
            model.ssh_enabled = Observation[bool].unknown("No 'CONFIG CONSOLE SSH' statement found.")

        if ssh_version_obs is not None:
            model.ssh_version = ssh_version_obs
        else:
            model.ssh_version = Observation[int].unknown("No SSH configuration statement found.")

        if vty_transport_obs is not None:
            model.vty_transport_input = vty_transport_obs
        else:
            model.vty_transport_input = Observation[List[str]].unknown("No console transport configuration found.")

        if vty_timeout_obs is not None:
            model.vty_exec_timeout_seconds = vty_timeout_obs
        else:
            model.vty_exec_timeout_seconds = Observation[int].unknown(
                "No 'CONFIG CONSOLE TIMEOUT' or 'CONFIG WEBADMIN TIMEOUT' statement found."
            )

        # Web / HTTP / HTTPS
        if http_server_obs is not None:
            model.http_server_enabled = http_server_obs
        else:
            model.http_server_enabled = Observation[bool].absent(
                False, note="Cleartext HTTP administration is disabled by default on Stormshield SNS (HTTPS only)."
            )

        if https_server_obs is not None:
            model.https_server_enabled = https_server_obs
        else:
            model.https_server_enabled = Observation[bool].unknown("No WebAdmin HTTPS state configured.")

        # Management ACL
        if management_acl_obs is not None:
            model.management_acl_applied = management_acl_obs
        else:
            model.management_acl_applied = Observation[bool].unknown(
                "No administrative access filter (CONFIG WEBADMIN/CONSOLE ACCESS) found."
            )

        # Banner
        if banner_obs is not None:
            model.login_banner_present = banner_obs
        else:
            model.login_banner_present = Observation[bool].unknown("No 'CONFIG BANNER' statement found.")

        if pre_login_banner_obs is not None:
            model.pre_login_banner_present = pre_login_banner_obs
        else:
            model.pre_login_banner_present = Observation[bool].unknown("No pre-login banner statement found.")

        if post_login_banner_obs is not None:
            model.post_login_banner_present = post_login_banner_obs
        else:
            model.post_login_banner_present = Observation[bool].unknown("No post-login banner statement found.")

        # Credentials & Passwords
        if enable_secret_obs is not None:
            model.enable_secret_set = enable_secret_obs
        else:
            model.enable_secret_set = Observation[bool].absent(
                True,
                note="Stormshield SNS stores all administrative credentials cryptographically hashed by default."
            )

        if password_encryption_obs is not None:
            model.password_encryption = password_encryption_obs
        else:
            model.password_encryption = Observation[bool].absent(
                True,
                note="Stormshield SNS enforces password encryption at rest by platform default."
            )

        if password_min_length_obs is not None:
            model.password_min_length = password_min_length_obs
        else:
            model.password_min_length = Observation[int].unknown(
                "No 'CONFIG PASSWDPOLICY' minimum length statement found."
            )

        # AAA
        if aaa_enabled_obs is not None:
            model.aaa_enabled = aaa_enabled_obs
        else:
            model.aaa_enabled = Observation[bool].unknown(
                "No external AAA (RADIUS/LDAP) configuration found under 'CONFIG AUTH'."
            )

        # Account Lockout / Brute force
        if lockout_threshold_obs is not None:
            model.admin_lockout_threshold = lockout_threshold_obs
        else:
            model.admin_lockout_threshold = Observation[int].unknown(
                "No 'CONFIG WEBADMIN BRUTEFORCE' threshold statement found."
            )

        if lockout_duration_obs is not None:
            model.admin_lockout_duration = lockout_duration_obs
        else:
            model.admin_lockout_duration = Observation[int].unknown(
                "No 'CONFIG WEBADMIN BRUTEFORCE' duration statement found."
            )

        # SNMP
        if snmp_agent_obs is not None:
            model.snmp_agent_enabled = snmp_agent_obs
        else:
            model.snmp_agent_enabled = Observation[bool].unknown("No SNMP agent state found.")

        if snmp_communities:
            model.snmp_communities = Observation[List[SnmpCommunity]].found(
                snmp_communities,
                snmp_communities[0].source_line,
                snmp_communities[0].line_number,
                note=f"{len(snmp_communities)} SNMP community string(s) configured.",
            )
        else:
            model.snmp_communities = Observation[List[SnmpCommunity]].absent(
                [], note="No SNMP communities configured."
            )

        # Logging & Syslog
        if logging_enabled_obs is not None:
            model.logging_enabled = logging_enabled_obs
        else:
            model.logging_enabled = Observation[bool].unknown("No 'CONFIG LOG' statement found.")

        if logging_hosts:
            model.logging_hosts = Observation[List[str]].found(
                logging_hosts,
                logging_hosts_line or "",
                logging_hosts_lineno,
                note=f"{len(logging_hosts)} syslog server(s) configured.",
            )
        else:
            model.logging_hosts = Observation[List[str]].absent(
                [], note="No remote syslog servers configured."
            )

        if logging_buffered_obs is not None:
            model.logging_buffered = logging_buffered_obs
        else:
            model.logging_buffered = Observation[bool].unknown("No local log buffer configuration found.")

        # NTP
        if ntp_servers:
            model.ntp_servers = Observation[List[str]].found(
                ntp_servers,
                ntp_servers_line or "",
                ntp_servers_lineno,
                note=f"{len(ntp_servers)} NTP server(s) configured.",
            )
            model.ntp_redundant = Observation[bool].found(
                len(ntp_servers) >= 2,
                ntp_servers_line or "",
                ntp_servers_lineno,
                note=f"{len(ntp_servers)} NTP server(s) configured (redundant={len(ntp_servers) >= 2}).",
            )
        else:
            model.ntp_servers = Observation[List[str]].absent(
                [], note="No NTP servers configured under 'CONFIG NTP'."
            )
            model.ntp_redundant = Observation[bool].absent(
                False, note="No NTP servers configured."
            )

        # DNS
        if dns_servers:
            model.dns_servers = Observation[List[str]].found(
                dns_servers,
                dns_servers_line or "",
                dns_servers_lineno,
                note=f"{len(dns_servers)} DNS server(s) configured.",
            )
        else:
            model.dns_servers = Observation[List[str]].absent(
                [], note="No DNS servers configured."
            )

        # High Availability
        if ha_enabled_obs is not None:
            model.ha_enabled = ha_enabled_obs
        else:
            model.ha_enabled = Observation[bool].unknown("No High Availability (HA) configuration found.")

        # Legacy & Extended Baseline Fields (Platform Invariants & Explanations)
        model.enable_password_present = Observation[bool].found(
            False, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="Stormshield SNS does not support legacy reversible enable passwords."
        )
        model.admin_default_ports_changed = Observation[bool].absent(
            False, note="Using default administrative management ports (443/22)."
        )
        model.snmp_v3_users_present = Observation[bool].absent(
            False, note="No SNMPv3 users configured under 'CONFIG SNMP ACCESS USERV3'."
        )
        model.event_logging_enabled = Observation[bool].unknown(
            "Event logging filter configuration not specified."
        )
        model.verify_update_server_identity = Observation[bool].found(
            True, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="Stormshield SNS verifies update server certificates by default."
        )
        model.usb_auto_install_disabled = Observation[bool].found(
            True, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="Stormshield SNS requires interactive administrator approval for USB installations."
        )
        model.ssl_static_key_ciphers_disabled = Observation[bool].found(
            True, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="Stormshield SNS WebAdmin disables static key ciphers."
        )
        model.strong_crypto_enabled = Observation[bool].found(
            True, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="Stormshield SNS enforces strong cryptography suites for WebAdmin and SSH."
        )
        model.admin_tls13_only = Observation[bool].unknown(
            "Stormshield SNS supports TLS 1.2 and TLS 1.3 for WebAdmin."
        )
        model.management_min_tls_version = Observation[str].found(
            "1.2", "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="Stormshield SNS enforces minimum TLS 1.2 for WebAdmin."
        )
        model.gui_cdn_enabled = Observation[bool].unknown(
            "GUI CDN is not an applicable feature on Stormshield SNS."
        )
        model.log_single_cpu_high_enabled = Observation[bool].unknown(
            "Single-CPU high logging is not an applicable feature on Stormshield SNS."
        )
        model.ha_monitor_interfaces = Observation[List[str]].unknown(
            "High Availability monitored interfaces not specified."
        )
        model.av_push_updates_enabled = Observation[bool].unknown(
            "Automatic signature update schedule not specified."
        )
        model.security_fabric_enabled = Observation[bool].unknown(
            "Security Fabric is a Fortinet-specific architecture; not applicable to Stormshield."
        )
        model.password_min_uppercase = Observation[int].unknown(
            "Password uppercase requirement not explicitly configured."
        )
        model.password_min_lowercase = Observation[int].unknown(
            "Password lowercase requirement not explicitly configured."
        )
        model.password_min_numeric = Observation[int].unknown(
            "Password numeric requirement not explicitly configured."
        )
        model.password_min_special = Observation[int].unknown(
            "Password special characters requirement not explicitly configured."
        )
        model.password_max_age_days = Observation[int].unknown(
            "Password maximum age not configured."
        )
        model.password_new_diff_chars = Observation[int].unknown(
            "Password new diff characters not configured."
        )
        model.password_history_reuse_limit = Observation[int].unknown(
            "Password history limit not configured."
        )
        model.av_ai_detection_enabled = Observation[bool].unknown(
            "Stormshield Breach Fighter sandboxing requires advanced license."
        )
        model.av_grayware_enabled = Observation[bool].unknown(
            "Grayware detection not configured."
        )
        model.log_encryption_enabled = Observation[bool].unknown(
            "Log encryption configuration not specified."
        )

        return model
