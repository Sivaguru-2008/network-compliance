"""Deterministic Palo Alto Networks / PAN-OS XML parser.

This parser processes standard PAN-OS XML configuration files, normalizes key settings
into the vendor-neutral SecurityBaselineModel, and preserves exact XML paths and line numbers
for compliance audit provenance.
"""

import xml.parsers.expat
import hashlib
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


class XMLNode:
    """Represents a simplified XML node parsed from configuration."""
    def __init__(self, tag: str, line_number: int):
        self.tag: str = tag
        self.line_number: int = line_number
        self.text: str = ""
        self.children: List['XMLNode'] = []


class XMLTreeBuilder:
    """Custom Expat-based XML parser to preserve exact line numbers."""
    def __init__(self):
        self.parser = xml.parsers.expat.ParserCreate()
        self.parser.StartElementHandler = self.start_element
        self.parser.EndElementHandler = self.end_element
        self.parser.CharacterDataHandler = self.char_data

        self.root: Optional[XMLNode] = None
        self.stack: List[XMLNode] = []

    def start_element(self, name: str, attrs: dict):
        line = self.parser.CurrentLineNumber
        node = XMLNode(tag=name, line_number=line)
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


def find_nodes_by_path(node: XMLNode, path_parts: List[str]) -> List[XMLNode]:
    """Recursively find all nodes matching the specified path parts."""
    if not path_parts:
        return [node]
    if node.tag == path_parts[0]:
        return find_nodes_by_path(node, path_parts[1:])
    current_tag = path_parts[0]
    matches = []
    for child in node.children:
        if child.tag == current_tag:
            matches.extend(find_nodes_by_path(child, path_parts[1:]))
    return matches


def find_nodes_by_tag(node: XMLNode, tag: str, results: Optional[List[XMLNode]] = None) -> List[XMLNode]:
    """Find all descendant nodes matching the specified tag."""
    if results is None:
        results = []
    if node.tag == tag:
        results.append(node)
    for child in node.children:
        find_nodes_by_tag(child, tag, results)
    return results


@registry.register
class PaloAltoParser(VendorParser):
    """Grammar-based XML parser for Palo Alto Networks PAN-OS configurations."""

    name = "paloalto_panos"
    vendor = "paloalto"
    os_family = "panos"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        # Palo Alto configs are XML files containing <configuration> and <deviceconfig> or <mgt-config>
        score = 0.0
        if "<configuration" in config_text:
            score += 0.5
        if "<deviceconfig" in config_text:
            score += 0.2
        if "<mgt-config" in config_text:
            score += 0.2
        if "<shared" in config_text:
            score += 0.1
        return min(1.0, score)

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        self._raw_lines = config_text.splitlines()
        builder = XMLTreeBuilder()
        root = builder.parse(config_text)

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

        self._normalize_syslog(root, baseline)
        self._normalize_login_banner(root, baseline)
        self._normalize_log_high_dp(root, baseline)
        self._normalize_services(root, baseline)
        self._normalize_password_complexity(root, baseline)
        self._normalize_idle_timeout(root, baseline)
        self._normalize_lockout_settings(root, baseline)
        self._normalize_snmp(root, baseline)
        self._normalize_update_server(root, baseline)
        self._normalize_ntp(root, baseline)
        self._normalize_hostname(root, baseline)

        # Ensure all baseline fields are answered
        for field in baseline.observable_fields():
            observation = getattr(baseline, field)
            if observation.note == "Parser did not evaluate this field.":
                setattr(
                    baseline,
                    field,
                    type(observation).unknown(
                        "Palo Alto parser does not evaluate this field."
                    )
                )

        return baseline

    def _normalize_hostname(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        nodes = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "hostname"])
        if nodes and nodes[0].text.strip():
            node = nodes[0]
            raw, line, path = self._evidence(node, "/configuration/deviceconfig/system/hostname")
            baseline.hostname = Observation[str].found(node.text.strip(), raw, line, note=path)
        else:
            baseline.hostname = Observation[str].absent("localhost.localdomain", "Hostname is not configured.")

    def _evidence(self, node: XMLNode, path: str) -> Tuple[str, int, str]:
        line_num = node.line_number
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"Path: {path}"

    def _normalize_syslog(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        # Search recursively for all <syslog> nodes
        syslog_nodes = find_nodes_by_tag(root, "syslog")
        hosts = []
        evidence_node = None

        for s_node in syslog_nodes:
            # Under syslog we expect <entry name="..."> <server>ip</server> </entry>
            servers = find_nodes_by_tag(s_node, "server")
            for s in servers:
                val = s.text.strip()
                if val:
                    hosts.append(val)
                    if not evidence_node:
                        evidence_node = s

        if hosts:
            raw, line, path = self._evidence(evidence_node, "shared/log-settings/syslog/entry/server")
            baseline.logging_enabled = Observation[bool].found(True, raw, line, note=path)
            baseline.logging_hosts = Observation[List[str]].found(hosts, raw, line, note=path)
        else:
            baseline.logging_enabled = Observation[bool].absent(False, "No syslog servers are configured in log-settings.")
            baseline.logging_hosts = Observation[List[str]].absent([], "No syslog hosts are configured.")

    def _normalize_login_banner(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        nodes = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "login-banner"])
        if nodes and nodes[0].text.strip():
            node = nodes[0]
            raw, line, path = self._evidence(node, "/configuration/deviceconfig/system/login-banner")
            baseline.login_banner_present = Observation[bool].found(True, raw, line, note=path)
            baseline.pre_login_banner_present = Observation[bool].found(True, raw, line, note=path)
            baseline.post_login_banner_present = Observation[bool].found(True, raw, line, note=path)
        else:
            note = "No logon banner is configured under system settings."
            baseline.login_banner_present = Observation[bool].absent(False, note)
            baseline.pre_login_banner_present = Observation[bool].absent(False, note)
            baseline.post_login_banner_present = Observation[bool].absent(False, note)

    def _normalize_log_high_dp(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        nodes = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "log-high-dp-load"])
        if nodes:
            node = nodes[0]
            enabled = node.text.strip().lower() == "yes"
            raw, line, path = self._evidence(node, "/configuration/deviceconfig/system/log-high-dp-load")
            baseline.log_single_cpu_high_enabled = Observation[bool].found(enabled, raw, line, note=path)
        else:
            baseline.log_single_cpu_high_enabled = Observation[bool].absent(
                False, "log-high-dp-load is not configured (defaults to False)."
            )

    def _normalize_services(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        telnet_nodes = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "service", "telnet"])
        http_nodes = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "service", "http"])

        if telnet_nodes:
            node = telnet_nodes[0]
            enabled = node.text.strip().lower() == "yes"
            raw, line, path = self._evidence(node, "/configuration/deviceconfig/system/service/telnet")
            baseline.telnet_enabled = Observation[bool].found(enabled, raw, line, note=path)
        else:
            baseline.telnet_enabled = Observation[bool].absent(False, "Telnet service is disabled by default.")

        if http_nodes:
            node = http_nodes[0]
            enabled = node.text.strip().lower() == "yes"
            raw, line, path = self._evidence(node, "/configuration/deviceconfig/system/service/http")
            baseline.http_server_enabled = Observation[bool].found(enabled, raw, line, note=path)
        else:
            baseline.http_server_enabled = Observation[bool].absent(False, "HTTP server is disabled by default.")

    def _normalize_password_complexity(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        nodes = find_nodes_by_path(root, ["configuration", "mgt-config", "password-complexity", "minimum-length"])
        if nodes and nodes[0].text.strip().isdigit():
            node = nodes[0]
            val = int(node.text.strip())
            raw, line, path = self._evidence(node, "/configuration/mgt-config/password-complexity/minimum-length")
            baseline.password_min_length = Observation[int].found(val, raw, line, note=path)
        else:
            baseline.password_min_length = Observation[int].absent(0, "Minimum password length is not enforced by default.")

    def _normalize_idle_timeout(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        nodes = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "login-timeout"])
        if nodes and nodes[0].text.strip().isdigit():
            node = nodes[0]
            val_mins = int(node.text.strip())
            val_secs = val_mins * 60
            raw, line, path = self._evidence(node, "/configuration/deviceconfig/system/login-timeout")
            baseline.vty_exec_timeout_seconds = Observation[int].found(val_secs, raw, line, note=path)
        else:
            baseline.vty_exec_timeout_seconds = Observation[int].absent(0, "Management idle timeout is not configured.")

    def _normalize_lockout_settings(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        prevent_nodes = find_nodes_by_path(root, ["configuration", "mgt-config", "password-complexity", "block-prevent"])
        time_nodes = find_nodes_by_path(root, ["configuration", "mgt-config", "password-complexity", "block-time"])

        threshold = 0
        duration = 0
        evidence_node = None
        evidence_path = ""

        if prevent_nodes and prevent_nodes[0].text.strip().isdigit():
            evidence_node = prevent_nodes[0]
            threshold = int(evidence_node.text.strip())
            evidence_path = "/configuration/mgt-config/password-complexity/block-prevent"

        if time_nodes and time_nodes[0].text.strip().isdigit():
            if not evidence_node:
                evidence_node = time_nodes[0]
                evidence_path = "/configuration/mgt-config/password-complexity/block-time"
            duration = int(time_nodes[0].text.strip()) * 60  # convert minutes to seconds

        if evidence_node:
            raw, line, path = self._evidence(evidence_node, evidence_path)
            baseline.admin_lockout_threshold = Observation[int].found(threshold, raw, line, note=path)
            baseline.admin_lockout_duration = Observation[int].found(duration, raw, line, note=path)
        else:
            note = "Account lockout settings are not configured."
            baseline.admin_lockout_threshold = Observation[int].absent(0, note)
            baseline.admin_lockout_duration = Observation[int].absent(0, note)

    def _normalize_snmp(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        snmp_node = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "snmp-setting"])
        if snmp_node:
            node = snmp_node[0]
            raw, line, path = self._evidence(node, "/configuration/deviceconfig/system/snmp-setting")
            baseline.snmp_agent_enabled = Observation[bool].found(True, raw, line, note=path)

            # Search for any community strings under the snmp-setting
            comm_nodes = find_nodes_by_tag(node, "community")
            communities = []
            for c in comm_nodes:
                val = c.text.strip()
                if val:
                    communities.append(SnmpCommunity(
                        name=val,
                        access="ro", # default access in PAN-OS for v2c communities
                        acl=None,
                        source_line=f"<community>{val}</community>",
                        line_number=c.line_number
                    ))
            baseline.snmp_communities = Observation[List[SnmpCommunity]].found(communities, raw, line, note=path)
        else:
            baseline.snmp_agent_enabled = Observation[bool].absent(False, "SNMP agent is not enabled.")
            baseline.snmp_communities = Observation[List[SnmpCommunity]].absent([], "SNMP community strings are not present.")

    def _normalize_update_server(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        nodes = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "verify-update-server-identity"])
        if nodes:
            node = nodes[0]
            enabled = node.text.strip().lower() == "yes"
            raw, line, path = self._evidence(node, "/configuration/deviceconfig/system/verify-update-server-identity")
            baseline.verify_update_server_identity = Observation[bool].found(enabled, raw, line, note=path)
        else:
            # Default is enabled in PAN-OS
            baseline.verify_update_server_identity = Observation[bool].absent(
                True, "verify-update-server-identity is not configured, defaults to True."
            )

    def _normalize_ntp(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        servers = []
        evidence_node = None
        evidence_path = ""

        # Find primary and secondary NTP server configurations
        primary = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "ntp-servers", "primary-ntp", "ntp-server-address"])
        secondary = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "ntp-servers", "secondary-ntp", "ntp-server-address"])

        if primary and primary[0].text.strip():
            evidence_node = primary[0]
            servers.append(evidence_node.text.strip())
            evidence_path = "/configuration/deviceconfig/system/ntp-servers/primary-ntp/ntp-server-address"

        if secondary and secondary[0].text.strip():
            if not evidence_node:
                evidence_node = secondary[0]
                evidence_path = "/configuration/deviceconfig/system/ntp-servers/secondary-ntp/ntp-server-address"
            servers.append(secondary[0].text.strip())

        if servers:
            raw, line, path = self._evidence(evidence_node, evidence_path)
            baseline.ntp_servers = Observation[List[str]].found(servers, raw, line, note=path)
            baseline.ntp_redundant = Observation[bool].found(len(servers) >= 2, raw, line, note=path)
        else:
            baseline.ntp_servers = Observation[List[str]].absent([], "NTP servers are not configured.")
            baseline.ntp_redundant = Observation[bool].absent(False, "No redundant NTP servers are configured.")
