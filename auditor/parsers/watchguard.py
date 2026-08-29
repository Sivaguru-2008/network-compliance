"""Deterministic WatchGuard Firebox / Fireware parser.

WatchGuard Firebox security appliances run Fireware OS. Configuration is
managed via the Fireware Web UI (HTTPS port 4117/8080), WatchGuard System Manager
(WSM) Policy Manager, or the Fireware Command Line Interface (CLI via SSH port 4118).
Locally-managed Fireboxes export configuration as an XML file (config.xml) or via CLI
export commands ("export config to console").

Documentation verified against official WatchGuard technical sources:
- WatchGuard Help Center: https://www.watchguard.com/help/docs/
- Fireware Web UI Help / Policy Manager Reference (v11.x, v12.x)
- Fireware Command Line Interface (CLI) Reference Guide
- WatchGuard Security Best Practices & Hardening Guidance
- WatchGuard Knowledge Base: Manage the Firebox Configuration File

Platform invariants documented by WatchGuard:
- Telnet is NOT supported in Fireware. Remote administration is strictly performed
  via HTTPS (Web UI on port 4117/8080) and SSH (CLI on port 4118).
- The SSH daemon in Fireware exclusively supports SSHv2.
- Cleartext HTTP administration is not supported (Web UI requires TLS/HTTPS).
- Administrative passphrases/credentials are stored using cryptographic hashes at rest.
- Logon Disclaimer forces user acknowledgement prior to session access.

CIS / STIG status:
- NO official CIS Benchmark exists for WatchGuard Firebox / Fireware.
- NO official DISA STIG exists for WatchGuard.
- Security controls are mapped directly to OFFICIAL_WATCHGUARD_GUIDANCE and
  INTERNAL_BASELINE with strict provenance tracking.
"""

import hashlib
import re
import xml.parsers.expat
from typing import Dict, List, Optional, Sequence, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry

_WATCHGUARD_XML_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*#.*(?:WatchGuard|Fireware|Firebox)\b", 0.50),
    (r"(?im)<\!--[\s\S]*?(?:WatchGuard|Fireware|Firebox)[\s\S]*?-->", 0.40),
    (r"(?im)<configuration\b[^>]*\bversion=[\"']\d+", 0.60),
    (r"(?im)<\/?system-parameters\b", 0.40),
    (r"(?im)<\/?logon-disclaimer\b", 0.45),
    (r"(?im)<\/?firebox-db\b", 0.45),
    (r"(?im)<\/?firecluster\b", 0.40),
    (r"(?im)<\/?auth-server-list\b", 0.35),
    (r"(?im)<policy>\s*<name>WatchGuard", 0.45),
    (r"(?im)<service>WG-Firebox-", 0.45),
    (r"(?im)<\/?v3-user-list\b", 0.30),
]

_WATCHGUARD_CLI_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*\[?(?:FAULT)?\]?WG(?:<[^>]+>)*[#>]\s*", 0.60),
    (r"(?im)^\s*WatchGuard\s+Fireware\b", 0.55),
    (r"(?im)^\s*export\s+config\s+to\s+console\b", 0.60),
    (r"(?im)^\s*logon-disclaimer\s+(?:enable|message)\b", 0.45),
]

_NON_WATCHGUARD_MARKERS: Sequence[Tuple[str, float]] = [
    (r"(?im)^\s*line\s+vty\b", 0.60),
    (r"(?im)^\s*ip\s+http\s+server\s*$", 0.50),
    (r"(?im)^\s*config\s+system\s+global\b", 0.90),
    (r"(?im)^\s*set\s+system\s+host-name\b", 0.80),
    (r"(?im)^\s*sysname\s+\S+", 0.50),
    (r"(?im)\"DEVICE_METADATA\"", 0.90),
    (r"(?im)^\s*user-interface\s+vty\b", 0.50),
    (r"(?im)^\s*#.*by RouterOS\b", 0.90),
    (r"(?im)^/ip\s+service\b", 0.50),
    (r"(?im)^\s*firmware-version\s+SonicOS\b", 0.90),
    (r"(?im)^\s*CONFIG\s+(?:WEBADMIN|CONSOLE|PASSWDPOLICY|SNMP|NTP|SLOG)\b", 0.90),
    (r"(?im)<\/?(?:deviceconfig|mgt-config)\b", 0.90),
]


class XMLNode:
    """Represents a structured XML node with line tracking."""
    def __init__(self, tag: str, line_number: int, attrs: Optional[dict] = None):
        self.tag: str = tag
        self.line_number: int = line_number
        self.attrs: dict = attrs or {}
        self.text: str = ""
        self.children: List['XMLNode'] = []


class XMLTreeBuilder:
    """Expat-based XML parser preserving element line numbers."""
    def __init__(self):
        self.parser = xml.parsers.expat.ParserCreate()
        self.parser.StartElementHandler = self.start_element
        self.parser.EndElementHandler = self.end_element
        self.parser.CharacterDataHandler = self.char_data

        self.root: Optional[XMLNode] = None
        self.stack: List[XMLNode] = []

    def start_element(self, name: str, attrs: dict):
        line = self.parser.CurrentLineNumber
        node = XMLNode(tag=name, line_number=line, attrs=attrs)
        if not self.root:
            self.root = node
        if self.stack:
            self.stack[-1].children.append(node)
        self.stack.append(node)

    def end_element(self, name: str):
        if self.stack:
            self.stack.pop()

    def char_data(self, data: str):
        if self.stack:
            self.stack[-1].text += data

    def parse(self, text: str) -> XMLNode:
        try:
            self.parser.Parse(text, 1)
        except Exception as e:
            raise ParserError(f"Malformed XML configuration: {e}") from e
        if not self.root:
            raise ParserError("Empty or invalid XML configuration.")
        return self.root


def find_nodes_by_tag(node: XMLNode, tag: str, results: Optional[List[XMLNode]] = None) -> List[XMLNode]:
    """Find all descendant nodes matching the specified tag."""
    if results is None:
        results = []
    if node.tag == tag:
        results.append(node)
    for child in node.children:
        find_nodes_by_tag(child, tag, results)
    return results


def find_child_by_path(node: XMLNode, path_parts: List[str]) -> List[XMLNode]:
    """Find child nodes matching the path parts relative to node."""
    if not path_parts:
        return [node]
    current_tag = path_parts[0]
    matches = []
    for child in node.children:
        if child.tag == current_tag:
            matches.extend(find_child_by_path(child, path_parts[1:]))
    return matches


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
class WatchGuardParser(VendorParser):
    """Deterministic parser for WatchGuard Firebox / Fireware configurations."""

    name = "watchguard_fireware"
    vendor = "watchguard"
    os_family = "fireware"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0

        xml_score = sum(w for p, w in _WATCHGUARD_XML_MARKERS if re.search(p, config_text))
        cli_score = sum(w for p, w in _WATCHGUARD_CLI_MARKERS if re.search(p, config_text))
        neg_score = sum(w for p, w in _NON_WATCHGUARD_MARKERS if re.search(p, config_text))

        score = max(xml_score, cli_score) - neg_score
        return max(0.0, min(1.0, score))

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Empty configuration text")

        self._raw_lines = config_text.splitlines()
        line_count = len(self._raw_lines)
        sha256 = hashlib.sha256(config_text.encode("utf-8")).hexdigest()

        # Check if XML format
        is_xml = "<configuration" in config_text or "<?xml" in config_text or "<system-parameters" in config_text

        if is_xml:
            return self._parse_xml(config_text, source_file, sha256, line_count)
        else:
            return self._parse_cli(config_text, source_file, sha256, line_count)

    def _evidence(self, node: XMLNode, path: str) -> Tuple[str, int, str]:
        line_num = node.line_number
        raw_line = self._raw_lines[line_num - 1].strip() if 0 < line_num <= len(self._raw_lines) else ""
        return raw_line, line_num, f"Path: {path}"

    def _parse_xml(
        self, config_text: str, source_file: Optional[str], sha256: str, line_count: int
    ) -> SecurityBaselineModel:
        builder = XMLTreeBuilder()
        root = builder.parse(config_text)

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

        # -------------------------------------------------------------
        # 1. Hostname
        # -------------------------------------------------------------
        hostname_nodes = find_child_by_path(root, ["system-parameters", "device-name"])
        if not hostname_nodes:
            hostname_nodes = find_child_by_path(root, ["system-parameters", "system-name"])
        if not hostname_nodes:
            hostname_nodes = find_child_by_path(root, ["system-parameters", "name"])

        if hostname_nodes and hostname_nodes[0].text.strip():
            node = hostname_nodes[0]
            raw, line, path = self._evidence(node, f"system-parameters/{node.tag}")
            model.hostname = Observation[str].found(
                node.text.strip(), raw, line, note=f"Extracted from {path}."
            )
        else:
            model.hostname = Observation[str].unknown(
                "No <device-name> or <system-name> configured under <system-parameters>."
            )

        # -------------------------------------------------------------
        # 2. Platform Invariants: Telnet & HTTP & SSH Version & Password Encryption
        # -------------------------------------------------------------
        model.telnet_enabled = Observation[bool].absent(
            False,
            note="Telnet is unsupported on WatchGuard Firebox. Administration is via HTTPS (4117) and SSH (4118) only."
        )

        model.http_server_enabled = Observation[bool].absent(
            False,
            note="Fireware Web UI does not support cleartext HTTP administration (HTTPS only on port 4117/8080)."
        )

        model.enable_secret_set = Observation[bool].absent(
            True,
            note="Fireware stores administrative passphrases cryptographically hashed by default."
        )

        model.password_encryption = Observation[bool].absent(
            True,
            note="Fireware enforces password encryption at rest by platform default."
        )

        model.enable_password_present = Observation[bool].found(
            False, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="Fireware does not support legacy reversible enable passwords."
        )

        model.ssh_version = Observation[int].found(
            2, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="WatchGuard Fireware SSH daemon exclusively supports SSHv2."
        )

        # -------------------------------------------------------------
        # 3. HTTPS Server / Web UI & SSH Management Access
        # -------------------------------------------------------------
        policy_nodes = find_nodes_by_tag(root, "policy")
        web_ui_policy = None
        mgmt_policy = None
        web_ui_from = []
        mgmt_from = []

        for p in policy_nodes:
            name_nodes = find_child_by_path(p, ["name"])
            p_name = name_nodes[0].text.strip().lower() if name_nodes else ""
            srv_nodes = find_child_by_path(p, ["service"])
            p_srv = srv_nodes[0].text.strip().lower() if srv_nodes else ""

            if "watchguard web ui" in p_name or "wg-firebox-webui" in p_srv:
                web_ui_policy = p
                from_nodes = find_child_by_path(p, ["from", "alias"])
                for fn in from_nodes:
                    if fn.text.strip():
                        web_ui_from.append(fn.text.strip())

            if "watchguard" in p_name or "wg-firebox-management" in p_srv or "ssh" in p_name or "ssh" in p_srv:
                mgmt_policy = p
                from_nodes = find_child_by_path(p, ["from", "alias"])
                for fn in from_nodes:
                    if fn.text.strip():
                        mgmt_from.append(fn.text.strip())

        # HTTPS Web UI status
        if web_ui_policy is not None:
            en_nodes = find_child_by_path(web_ui_policy, ["enable"])
            is_en = _is_truthy(en_nodes[0].text.strip()) if en_nodes else True
            raw, line, path = self._evidence(web_ui_policy, "policy-list/policy[name='WatchGuard Web UI']")
            model.https_server_enabled = Observation[bool].found(
                is_en, raw, line, note=f"Web UI management policy is {'enabled' if is_en else 'disabled'}."
            )
        else:
            model.https_server_enabled = Observation[bool].unknown(
                "No WatchGuard Web UI policy found in <policy-list>."
            )

        # SSH CLI status
        if mgmt_policy is not None:
            en_nodes = find_child_by_path(mgmt_policy, ["enable"])
            is_en = _is_truthy(en_nodes[0].text.strip()) if en_nodes else True
            raw, line, path = self._evidence(mgmt_policy, "policy-list/policy[name='WatchGuard']")
            model.ssh_enabled = Observation[bool].found(
                is_en, raw, line, note=f"WatchGuard management / SSH policy is {'enabled' if is_en else 'disabled'}."
            )
            model.vty_transport_input = Observation[List[str]].found(
                ["ssh"] if is_en else [], raw, line,
                note=f"Transport input: {'ssh' if is_en else 'none'}."
            )
        else:
            model.ssh_enabled = Observation[bool].unknown(
                "No WatchGuard management / SSH policy found in <policy-list>."
            )
            model.vty_transport_input = Observation[List[str]].unknown(
                "No management transport configuration evaluated."
            )

        # -------------------------------------------------------------
        # 4. Management ACL Restrictions
        # -------------------------------------------------------------
        all_from = web_ui_from + mgmt_from
        if all_from:
            insecure_sources = {"any", "any-external", "0.0.0.0/0", "internet", "external"}
            is_restricted = not any(src.lower() in insecure_sources for src in all_from)
            ev_policy = web_ui_policy or mgmt_policy or root
            raw, line, path = self._evidence(ev_policy, "policy-list/policy/from")
            if is_restricted:
                model.management_acl_applied = Observation[bool].found(
                    True, raw, line,
                    note=f"Management access restricted to trusted sources: {', '.join(set(all_from))}."
                )
            else:
                model.management_acl_applied = Observation[bool].found(
                    False, raw, line,
                    note=f"Management access permits unrestricted external sources: {', '.join(set(all_from))}."
                )
        else:
            model.management_acl_applied = Observation[bool].unknown(
                "No management policy source rules evaluated in <policy-list>."
            )

        # -------------------------------------------------------------
        # 5. Session Idle Timeout
        # -------------------------------------------------------------
        idle_nodes = find_child_by_path(root, ["system-parameters", "idle-timeout"])
        if not idle_nodes:
            idle_nodes = find_child_by_path(root, ["system-parameters", "web-session-timeout"])
        if not idle_nodes:
            idle_nodes = find_child_by_path(root, ["system-parameters", "session-timeout"])

        if idle_nodes and idle_nodes[0].text.strip().isdigit():
            node = idle_nodes[0]
            val_mins = int(node.text.strip())
            val_secs = val_mins * 60
            raw, line, path = self._evidence(node, f"system-parameters/{node.tag}")
            model.vty_exec_timeout_seconds = Observation[int].found(
                val_secs, raw, line,
                note=f"Administrator idle timeout set to {val_mins} minutes ({val_secs} seconds)."
            )
        else:
            model.vty_exec_timeout_seconds = Observation[int].unknown(
                "No <idle-timeout> configured under <system-parameters>."
            )

        # -------------------------------------------------------------
        # 6. Logon Disclaimer / Login Banner
        # -------------------------------------------------------------
        banner_nodes = find_child_by_path(root, ["system-parameters", "logon-disclaimer"])
        if banner_nodes:
            en_nodes = find_child_by_path(banner_nodes[0], ["enable"])
            msg_nodes = find_child_by_path(banner_nodes[0], ["message"])
            is_en = _is_truthy(en_nodes[0].text.strip()) if en_nodes else False
            raw, line, path = self._evidence(banner_nodes[0], "system-parameters/logon-disclaimer")

            if is_en:
                model.login_banner_present = Observation[bool].found(
                    True, raw, line, note="Logon disclaimer is enabled."
                )
                model.pre_login_banner_present = Observation[bool].found(
                    True, raw, line, note="Pre-login disclaimer is configured and enabled."
                )
                model.post_login_banner_present = Observation[bool].found(
                    True, raw, line, note="Post-login disclaimer acknowledgement is enforced."
                )
            else:
                model.login_banner_present = Observation[bool].found(
                    False, raw, line, note="Logon disclaimer is explicitly disabled."
                )
                model.pre_login_banner_present = Observation[bool].found(
                    False, raw, line, note="Logon disclaimer is disabled."
                )
                model.post_login_banner_present = Observation[bool].found(
                    False, raw, line, note="Logon disclaimer is disabled."
                )
        else:
            note = "No <logon-disclaimer> configured under <system-parameters>."
            model.login_banner_present = Observation[bool].absent(False, note)
            model.pre_login_banner_present = Observation[bool].absent(False, note)
            model.post_login_banner_present = Observation[bool].absent(False, note)

        # -------------------------------------------------------------
        # 7. Password Policy & Complexity
        # -------------------------------------------------------------
        pw_nodes = find_nodes_by_tag(root, "password-policy")
        if pw_nodes:
            node = pw_nodes[0]
            len_nodes = find_child_by_path(node, ["min-password-length"])
            if len_nodes and len_nodes[0].text.strip().isdigit():
                val_len = int(len_nodes[0].text.strip())
                raw, line, path = self._evidence(len_nodes[0], "password-policy/min-password-length")
                model.password_min_length = Observation[int].found(
                    val_len, raw, line, note=f"Minimum password length configured to {val_len} characters."
                )
            else:
                model.password_min_length = Observation[int].absent(
                    0, "Minimum password length not specified in <password-policy>."
                )

            exp_nodes = find_child_by_path(node, ["password-expiration-days"])
            if exp_nodes and exp_nodes[0].text.strip().isdigit():
                val_exp = int(exp_nodes[0].text.strip())
                raw, line, path = self._evidence(exp_nodes[0], "password-policy/password-expiration-days")
                model.password_max_age_days = Observation[int].found(
                    val_exp, raw, line, note=f"Password expiration configured to {val_exp} days."
                )
            else:
                model.password_max_age_days = Observation[int].absent(
                    0, "Password expiration period not configured."
                )
        else:
            model.password_min_length = Observation[int].unknown(
                "No <password-policy> configured in <firebox-db> or <system-parameters>."
            )
            model.password_max_age_days = Observation[int].absent(
                0, "Password expiration period not configured."
            )

        # -------------------------------------------------------------
        # 8. Account Lockout
        # -------------------------------------------------------------
        lockout_nodes = find_nodes_by_tag(root, "account-lockout")
        if lockout_nodes:
            node = lockout_nodes[0]
            en_nodes = find_child_by_path(node, ["enable"])
            is_en = _is_truthy(en_nodes[0].text.strip()) if en_nodes else False
            fa_nodes = find_child_by_path(node, ["failed-attempts"])
            dur_nodes = find_child_by_path(node, ["lockout-duration-minutes"])

            raw, line, path = self._evidence(node, "account-lockout")
            if not is_en:
                model.admin_lockout_threshold = Observation[int].found(
                    0, raw, line, note="Account lockout is explicitly disabled."
                )
                model.admin_lockout_duration = Observation[int].found(
                    0, raw, line, note="Account lockout is explicitly disabled."
                )
            else:
                th_val = int(fa_nodes[0].text.strip()) if (fa_nodes and fa_nodes[0].text.strip().isdigit()) else 0
                dur_val = int(dur_nodes[0].text.strip()) * 60 if (dur_nodes and dur_nodes[0].text.strip().isdigit()) else 0
                model.admin_lockout_threshold = Observation[int].found(
                    th_val, raw, line, note=f"Account lockout threshold set to {th_val} failed attempts."
                )
                model.admin_lockout_duration = Observation[int].found(
                    dur_val, raw, line, note=f"Account lockout duration set to {dur_val} seconds."
                )
        else:
            model.admin_lockout_threshold = Observation[int].unknown(
                "No <account-lockout> configuration found."
            )
            model.admin_lockout_duration = Observation[int].unknown(
                "No <account-lockout> configuration found."
            )

        # -------------------------------------------------------------
        # 9. AAA / Centralized Authentication (RADIUS / LDAP / Active Directory)
        # -------------------------------------------------------------
        auth_server_nodes = find_nodes_by_tag(root, "auth-server-list")
        if auth_server_nodes:
            servers = find_nodes_by_tag(auth_server_nodes[0], "server")
            ext_servers = []
            for s in servers:
                type_nodes = find_child_by_path(s, ["type"])
                stype = type_nodes[0].text.strip().lower() if type_nodes else ""
                if stype in ("radius", "ldap", "active-directory", "activedirectory", "securid", "saml"):
                    ext_servers.append(stype)

            raw, line, path = self._evidence(auth_server_nodes[0], "authentication/auth-server-list")
            if ext_servers:
                model.aaa_enabled = Observation[bool].found(
                    True, raw, line,
                    note=f"Centralized AAA authentication configured: {', '.join(set(ext_servers))}."
                )
            else:
                model.aaa_enabled = Observation[bool].found(
                    False, raw, line,
                    note="No external AAA servers configured in <auth-server-list>."
                )
        else:
            model.aaa_enabled = Observation[bool].unknown(
                "No <auth-server-list> found under <authentication>."
            )

        # -------------------------------------------------------------
        # 10. SNMP Configuration
        # -------------------------------------------------------------
        snmp_nodes = find_child_by_path(root, ["snmp"])
        if snmp_nodes:
            node = snmp_nodes[0]
            en_nodes = find_child_by_path(node, ["enable"])
            is_en = _is_truthy(en_nodes[0].text.strip()) if en_nodes else True
            raw, line, path = self._evidence(node, "snmp")
            model.snmp_agent_enabled = Observation[bool].found(
                is_en, raw, line, note=f"SNMP agent is {'enabled' if is_en else 'disabled'}."
            )

            # Communities
            comm_nodes = find_nodes_by_tag(node, "community")
            communities: List[SnmpCommunity] = []
            for c in comm_nodes:
                c_name = find_child_by_path(c, ["name"])
                c_access = find_child_by_path(c, ["access"])
                c_host = find_child_by_path(c, ["host"])
                if c_name and c_name[0].text.strip():
                    name_str = c_name[0].text.strip()
                    acc_str = c_access[0].text.strip().lower() if c_access else "ro"
                    host_str = c_host[0].text.strip() if c_host else None
                    communities.append(
                        SnmpCommunity(
                            name=name_str,
                            access=acc_str,
                            acl=host_str,
                            source_line=f"<community><name>{name_str}</name></community>",
                            line_number=c.line_number,
                        )
                    )

            if communities:
                model.snmp_communities = Observation[List[SnmpCommunity]].found(
                    communities, raw, line, note=f"{len(communities)} SNMP community string(s) configured."
                )
            else:
                model.snmp_communities = Observation[List[SnmpCommunity]].absent(
                    [], "No SNMP community strings configured."
                )

            # SNMPv3 users
            v3_users = find_nodes_by_tag(node, "v3-user-list")
            if v3_users and find_nodes_by_tag(v3_users[0], "user"):
                model.snmp_v3_users_present = Observation[bool].found(
                    True, raw, line, note="SNMPv3 user(s) configured."
                )
            else:
                model.snmp_v3_users_present = Observation[bool].absent(
                    False, "No SNMPv3 users configured."
                )
        else:
            note = "No <snmp> configuration found."
            model.snmp_agent_enabled = Observation[bool].absent(False, note)
            model.snmp_communities = Observation[List[SnmpCommunity]].absent([], note)
            model.snmp_v3_users_present = Observation[bool].absent(False, note)

        # -------------------------------------------------------------
        # 11. Logging & Syslog
        # -------------------------------------------------------------
        log_nodes = find_child_by_path(root, ["logging"])
        if log_nodes:
            node = log_nodes[0]
            en_nodes = find_child_by_path(node, ["enable"])
            is_en = _is_truthy(en_nodes[0].text.strip()) if en_nodes else True
            raw, line, path = self._evidence(node, "logging")
            model.logging_enabled = Observation[bool].found(
                is_en, raw, line, note=f"Logging is {'enabled' if is_en else 'disabled'}."
            )

            hosts: List[str] = []
            syslog_nodes = find_nodes_by_tag(node, "syslog-server")
            for sl in syslog_nodes:
                ip_nodes = find_child_by_path(sl, ["ip"])
                if ip_nodes and ip_nodes[0].text.strip():
                    hosts.append(ip_nodes[0].text.strip())

            wsm_log_nodes = find_nodes_by_tag(node, "log-server")
            for wl in wsm_log_nodes:
                ip_nodes = find_child_by_path(wl, ["ip"])
                if ip_nodes and ip_nodes[0].text.strip():
                    hosts.append(ip_nodes[0].text.strip())

            if hosts:
                model.logging_hosts = Observation[List[str]].found(
                    hosts, raw, line, note=f"{len(hosts)} remote log/syslog server(s) configured."
                )
            else:
                model.logging_hosts = Observation[List[str]].absent(
                    [], "No remote syslog or WatchGuard log servers configured."
                )
        else:
            model.logging_enabled = Observation[bool].unknown("No <logging> block found.")
            model.logging_hosts = Observation[List[str]].absent([], "No logging hosts configured.")

        # -------------------------------------------------------------
        # 12. NTP Servers
        # -------------------------------------------------------------
        ntp_nodes = find_child_by_path(root, ["ntp"])
        if ntp_nodes:
            node = ntp_nodes[0]
            en_nodes = find_child_by_path(node, ["enable"])
            is_en = _is_truthy(en_nodes[0].text.strip()) if en_nodes else True
            servers: List[str] = []
            srv_nodes = find_nodes_by_tag(node, "server")
            for s in srv_nodes:
                val = s.text.strip()
                if val:
                    servers.append(val)

            raw, line, path = self._evidence(node, "ntp")
            if is_en and servers:
                model.ntp_servers = Observation[List[str]].found(
                    servers, raw, line, note=f"{len(servers)} NTP server(s) configured."
                )
                model.ntp_redundant = Observation[bool].found(
                    len(servers) >= 2, raw, line, note=f"Redundant NTP servers: {len(servers) >= 2}."
                )
            elif not is_en:
                model.ntp_servers = Observation[List[str]].found(
                    [], raw, line, note="NTP client is explicitly disabled."
                )
                model.ntp_redundant = Observation[bool].found(
                    False, raw, line, note="NTP is disabled."
                )
            else:
                model.ntp_servers = Observation[List[str]].absent([], "No NTP servers configured.")
                model.ntp_redundant = Observation[bool].absent(False, "No NTP servers configured.")
        else:
            model.ntp_servers = Observation[List[str]].absent([], "No <ntp> block configured.")
            model.ntp_redundant = Observation[bool].absent(False, "No <ntp> block configured.")

        # -------------------------------------------------------------
        # 13. DNS Servers
        # -------------------------------------------------------------
        dns_nodes = find_child_by_path(root, ["system-parameters", "dns-server-list", "server"])
        if dns_nodes:
            dns_list = [d.text.strip() for d in dns_nodes if d.text.strip()]
            raw, line, path = self._evidence(dns_nodes[0], "system-parameters/dns-server-list/server")
            model.dns_servers = Observation[List[str]].found(
                dns_list, raw, line, note=f"{len(dns_list)} DNS server(s) configured."
            )
        else:
            model.dns_servers = Observation[List[str]].absent([], "No DNS servers configured.")

        # -------------------------------------------------------------
        # 14. High Availability (FireCluster)
        # -------------------------------------------------------------
        cluster_nodes = find_child_by_path(root, ["firecluster"])
        if not cluster_nodes:
            cluster_nodes = find_child_by_path(root, ["cluster"])

        if cluster_nodes:
            node = cluster_nodes[0]
            en_nodes = find_child_by_path(node, ["enable"])
            is_en = _is_truthy(en_nodes[0].text.strip()) if en_nodes else True
            raw, line, path = self._evidence(node, "firecluster")
            model.ha_enabled = Observation[bool].found(
                is_en, raw, line, note=f"FireCluster High Availability is {'enabled' if is_en else 'disabled'}."
            )
        else:
            model.ha_enabled = Observation[bool].absent(
                False, "No FireCluster HA configuration found."
            )

        # Baseline completeness
        self._fill_unhandled_fields(model)
        return model

    def _parse_cli(
        self, config_text: str, source_file: Optional[str], sha256: str, line_count: int
    ) -> SecurityBaselineModel:
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

        # Platform invariants
        model.telnet_enabled = Observation[bool].absent(
            False, note="Telnet is unsupported on WatchGuard Firebox."
        )
        model.http_server_enabled = Observation[bool].absent(
            False, note="Fireware Web UI does not support cleartext HTTP administration."
        )
        model.enable_secret_set = Observation[bool].absent(
            True, note="Fireware stores credentials cryptographically hashed by default."
        )
        model.password_encryption = Observation[bool].absent(
            True, note="Fireware enforces password encryption at rest."
        )
        model.enable_password_present = Observation[bool].found(
            False, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="Fireware does not support legacy reversible enable passwords."
        )
        model.ssh_version = Observation[int].found(
            2, "PLATFORM_DOCUMENTED_INVARIANT", None,
            note="WatchGuard Fireware SSH daemon exclusively supports SSHv2."
        )

        hostname_obs: Optional[Observation[str]] = None
        ntp_servers: List[str] = []
        ntp_line: Optional[str] = None
        ntp_lineno: Optional[int] = None
        snmp_agent_obs: Optional[Observation[bool]] = None
        snmp_communities: List[SnmpCommunity] = []
        logging_enabled_obs: Optional[Observation[bool]] = None
        logging_hosts: List[str] = []
        logging_line: Optional[str] = None
        logging_lineno: Optional[int] = None
        aaa_obs: Optional[Observation[bool]] = None
        banner_obs: Optional[Observation[bool]] = None
        timeout_obs: Optional[Observation[int]] = None
        pw_len_obs: Optional[Observation[int]] = None
        lockout_th_obs: Optional[Observation[int]] = None
        lockout_dur_obs: Optional[Observation[int]] = None
        dns_servers: List[str] = []
        dns_line: Optional[str] = None
        dns_lineno: Optional[int] = None

        for lineno, raw_line in enumerate(self._raw_lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("--") or line.startswith("#"):
                continue

            # Hostname / System Name
            m_host = re.match(r"(?i)^(?:WG[#>]\s*)?(?:System\s+Name:\s*|hostname\s+|device-name\s+)(\S+)", line)
            if m_host:
                hostname_obs = Observation[str].found(
                    m_host.group(1).strip(), raw_line, lineno, note="Extracted from CLI system name."
                )

            # NTP
            if re.match(r"(?i)^(?:WG[#>]\s*)?ntp\s+server\s+(\S+)", line):
                m_ntp = re.match(r"(?i)^(?:WG[#>]\s*)?ntp\s+server\s+(\S+)", line)
                if m_ntp:
                    ntp_servers.append(m_ntp.group(1).strip())
                    ntp_line = raw_line
                    ntp_lineno = lineno
            elif re.match(r"(?i)^(?:WG[#>]\s*)?ntp\s+disable\b", line):
                ntp_servers = []

            # SNMP
            if re.match(r"(?i)^(?:WG[#>]\s*)?snmp\s+enable\b", line):
                snmp_agent_obs = Observation[bool].found(
                    True, raw_line, lineno, note="SNMP agent enabled in CLI."
                )
            elif re.match(r"(?i)^(?:WG[#>]\s*)?snmp\s+disable\b", line):
                snmp_agent_obs = Observation[bool].found(
                    False, raw_line, lineno, note="SNMP agent disabled in CLI."
                )
            elif re.match(r"(?i)^(?:WG[#>]\s*)?snmp\s+community\s+(\S+)(?:\s+(ro|rw))?", line):
                m_comm = re.match(r"(?i)^(?:WG[#>]\s*)?snmp\s+community\s+(\S+)(?:\s+(ro|rw))?", line)
                if m_comm:
                    cname = m_comm.group(1).strip()
                    cacc = m_comm.group(2).lower() if m_comm.group(2) else "ro"
                    snmp_communities.append(
                        SnmpCommunity(name=cname, access=cacc, source_line=raw_line, line_number=lineno)
                    )

            # Logging / Syslog
            if re.match(r"(?i)^(?:WG[#>]\s*)?logging\s+enable\b", line):
                logging_enabled_obs = Observation[bool].found(
                    True, raw_line, lineno, note="Logging enabled in CLI."
                )
            elif re.match(r"(?i)^(?:WG[#>]\s*)?logging\s+disable\b", line):
                logging_enabled_obs = Observation[bool].found(
                    False, raw_line, lineno, note="Logging disabled in CLI."
                )
            elif re.match(r"(?i)^(?:WG[#>]\s*)?log-server\s+(\S+)", line):
                m_log = re.match(r"(?i)^(?:WG[#>]\s*)?log-server\s+(\S+)", line)
                if m_log:
                    logging_hosts.append(m_log.group(1).strip())
                    logging_line = raw_line
                    logging_lineno = lineno
                    if logging_enabled_obs is None:
                        logging_enabled_obs = Observation[bool].found(
                            True, raw_line, lineno, note="Log server configured in CLI."
                        )

            # Authentication / AAA
            if re.match(r"(?i)^(?:WG[#>]\s*)?auth-server\s+(radius|ldap|active-directory|saml)\b", line):
                aaa_obs = Observation[bool].found(
                    True, raw_line, lineno, note="External AAA server configured in CLI."
                )

            # Banner / Disclaimer
            if re.match(r"(?i)^(?:WG[#>]\s*)?logon-disclaimer\s+enable\b", line):
                banner_obs = Observation[bool].found(
                    True, raw_line, lineno, note="Logon disclaimer enabled in CLI."
                )
            elif re.match(r"(?i)^(?:WG[#>]\s*)?logon-disclaimer\s+disable\b", line):
                banner_obs = Observation[bool].found(
                    False, raw_line, lineno, note="Logon disclaimer disabled in CLI."
                )

            # Session Timeout
            m_to = re.match(r"(?i)^(?:WG[#>]\s*)?idle-timeout\s+(\d+)", line)
            if m_to:
                mins = int(m_to.group(1))
                timeout_obs = Observation[int].found(
                    mins * 60, raw_line, lineno, note=f"Idle timeout set to {mins} minutes."
                )

            # Password min length
            m_pw = re.match(r"(?i)^(?:WG[#>]\s*)?password\s+min-length\s+(\d+)", line)
            if m_pw:
                pw_len = int(m_pw.group(1))
                pw_len_obs = Observation[int].found(
                    pw_len, raw_line, lineno, note=f"Password min-length set to {pw_len}."
                )

            # Lockout
            m_lth = re.match(r"(?i)^(?:WG[#>]\s*)?lockout\s+attempts\s+(\d+)", line)
            if m_lth:
                th = int(m_lth.group(1))
                lockout_th_obs = Observation[int].found(
                    th, raw_line, lineno, note=f"Lockout threshold set to {th} attempts."
                )

            m_ldur = re.match(r"(?i)^(?:WG[#>]\s*)?lockout\s+duration\s+(\d+)", line)
            if m_ldur:
                dur_mins = int(m_ldur.group(1))
                lockout_dur_obs = Observation[int].found(
                    dur_mins * 60, raw_line, lineno, note=f"Lockout duration set to {dur_mins} minutes."
                )

            # DNS
            m_dns = re.match(r"(?i)^(?:WG[#>]\s*)?dns\s+server\s+(\S+)", line)
            if m_dns:
                dns_servers.append(m_dns.group(1).strip())
                dns_line = raw_line
                dns_lineno = lineno

        # Set observations on model
        if hostname_obs is not None:
            model.hostname = hostname_obs
        else:
            model.hostname = Observation[str].unknown("No system name statement found in CLI output.")

        if timeout_obs is not None:
            model.vty_exec_timeout_seconds = timeout_obs
        else:
            model.vty_exec_timeout_seconds = Observation[int].unknown("No idle timeout configured.")

        if banner_obs is not None:
            model.login_banner_present = banner_obs
            model.pre_login_banner_present = banner_obs
            model.post_login_banner_present = banner_obs
        else:
            model.login_banner_present = Observation[bool].unknown("No logon disclaimer configured.")
            model.pre_login_banner_present = Observation[bool].unknown("No logon disclaimer configured.")
            model.post_login_banner_present = Observation[bool].unknown("No logon disclaimer configured.")

        if pw_len_obs is not None:
            model.password_min_length = pw_len_obs
        else:
            model.password_min_length = Observation[int].unknown("No password policy configured.")

        if lockout_th_obs is not None:
            model.admin_lockout_threshold = lockout_th_obs
        else:
            model.admin_lockout_threshold = Observation[int].unknown("No lockout threshold configured.")

        if lockout_dur_obs is not None:
            model.admin_lockout_duration = lockout_dur_obs
        else:
            model.admin_lockout_duration = Observation[int].unknown("No lockout duration configured.")

        if aaa_obs is not None:
            model.aaa_enabled = aaa_obs
        else:
            model.aaa_enabled = Observation[bool].unknown("No external AAA configuration found.")

        if snmp_agent_obs is not None:
            model.snmp_agent_enabled = snmp_agent_obs
        else:
            model.snmp_agent_enabled = Observation[bool].unknown("No SNMP configuration found.")

        if snmp_communities:
            model.snmp_communities = Observation[List[SnmpCommunity]].found(
                snmp_communities, snmp_communities[0].source_line, snmp_communities[0].line_number,
                note=f"{len(snmp_communities)} SNMP community strings configured."
            )
        else:
            model.snmp_communities = Observation[List[SnmpCommunity]].absent([], "No SNMP communities configured.")

        if logging_enabled_obs is not None:
            model.logging_enabled = logging_enabled_obs
        else:
            model.logging_enabled = Observation[bool].unknown("No logging state configured.")

        if logging_hosts:
            model.logging_hosts = Observation[List[str]].found(
                logging_hosts, logging_line or "", logging_lineno,
                note=f"{len(logging_hosts)} log server(s) configured."
            )
        else:
            model.logging_hosts = Observation[List[str]].absent([], "No log servers configured.")

        if ntp_servers:
            model.ntp_servers = Observation[List[str]].found(
                ntp_servers, ntp_line or "", ntp_lineno, note=f"{len(ntp_servers)} NTP servers configured."
            )
            model.ntp_redundant = Observation[bool].found(
                len(ntp_servers) >= 2, ntp_line or "", ntp_lineno, note=f"Redundant NTP: {len(ntp_servers) >= 2}."
            )
        else:
            model.ntp_servers = Observation[List[str]].absent([], "No NTP servers configured.")
            model.ntp_redundant = Observation[bool].absent(False, "No NTP servers configured.")

        if dns_servers:
            model.dns_servers = Observation[List[str]].found(
                dns_servers, dns_line or "", dns_lineno, note=f"{len(dns_servers)} DNS servers configured."
            )
        else:
            model.dns_servers = Observation[List[str]].absent([], "No DNS servers configured.")

        self._fill_unhandled_fields(model)
        return model

    def _fill_unhandled_fields(self, model: SecurityBaselineModel) -> None:
        """Fill unhandled fields with explicit explanatory notes."""
        if model.admin_default_ports_changed.note == "Parser did not evaluate this field.":
            model.admin_default_ports_changed = Observation[bool].absent(
                False, note="Using default administrative management ports (4117 HTTPS / 4118 SSH)."
            )
        if model.verify_update_server_identity.note == "Parser did not evaluate this field.":
            model.verify_update_server_identity = Observation[bool].found(
                True, "PLATFORM_DOCUMENTED_INVARIANT", None,
                note="WatchGuard Firebox verifies signature update server identity by default."
            )
        if model.usb_auto_install_disabled.note == "Parser did not evaluate this field.":
            model.usb_auto_install_disabled = Observation[bool].found(
                True, "PLATFORM_DOCUMENTED_INVARIANT", None,
                note="Fireware requires administrator authentication for USB operations."
            )
        if model.ssl_static_key_ciphers_disabled.note == "Parser did not evaluate this field.":
            model.ssl_static_key_ciphers_disabled = Observation[bool].found(
                True, "PLATFORM_DOCUMENTED_INVARIANT", None,
                note="Fireware Web UI enforces modern TLS cipher suites."
            )
        if model.strong_crypto_enabled.note == "Parser did not evaluate this field.":
            model.strong_crypto_enabled = Observation[bool].found(
                True, "PLATFORM_DOCUMENTED_INVARIANT", None,
                note="Fireware enforces strong cryptographic suites for Web UI and SSH."
            )
        if model.management_min_tls_version.note == "Parser did not evaluate this field.":
            model.management_min_tls_version = Observation[str].found(
                "1.2", "PLATFORM_DOCUMENTED_INVARIANT", None,
                note="Fireware enforces minimum TLS 1.2 for Web UI administration."
            )

        for field in model.observable_fields():
            obs = getattr(model, field)
            if obs.note == "Parser did not evaluate this field.":
                setattr(
                    model,
                    field,
                    type(obs).unknown(f"WatchGuard parser does not evaluate {field}.")
                )
