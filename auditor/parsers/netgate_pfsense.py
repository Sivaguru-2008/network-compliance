"""Deterministic Netgate pfSense configuration parser.

This parser processes Netgate pfSense XML configuration exports (config.xml),
normalizes settings into the SecurityBaselineModel, and preserves
configuration lines and line numbers for compliance audit evidence.
"""

import hashlib
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class NetgatePfSenseParser(VendorParser):
    """Configuration parser for Netgate pfSense XML configuration backups."""

    name = "netgate_pfsense"
    vendor = "netgate"
    os_family = "pfsense"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        
        # Must be XML with <pfsense> root tag
        text_lower = config_text.lower()
        if "<?xml" in text_lower and "<pfsense" in text_lower:
            return 1.0
        return 0.0

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        self._raw_lines = config_text.splitlines()
        
        try:
            root = ET.fromstring(config_text)
        except ET.ParseError as e:
            raise ParserError(f"Malformed XML configuration: {e}")

        if root.tag != "pfsense":
            raise ParserError("Root element is not <pfsense>.")

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

        self._parse_xml_config(root, baseline)

        # Set all remaining unparsed fields to unknown
        for field in baseline.observable_fields():
            observation = getattr(baseline, field)
            if observation.note == "Parser did not evaluate this field.":
                setattr(
                    baseline,
                    field,
                    type(observation).unknown(
                        "Netgate pfSense parser does not evaluate this field."
                    )
                )

        return baseline

    def _evidence(self, line_num: int) -> Tuple[str, int, str]:
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"Line {line_num}: {raw_line}"

    def _find_line_number(self, tag: str, value: Optional[str] = None) -> int:
        for idx, line in enumerate(self._raw_lines):
            line_strip = line.strip()
            if f"<{tag}>" in line_strip or f"<{tag}/" in line_strip:
                if value is None or value in line_strip:
                    return idx + 1
        return 1

    def _parse_xml_config(self, root: ET.Element, baseline: SecurityBaselineModel) -> None:
        # pfSense Defaults
        baseline.telnet_enabled = Observation[bool].absent(
            False, "Telnet is not supported/enabled in pfSense."
        )
        baseline.http_server_enabled = Observation[bool].absent(
            False, "HTTP Web management is disabled by default in pfSense (HTTPS is default)."
        )
        baseline.https_server_enabled = Observation[bool].absent(
            True, "HTTPS Web management is enabled by default in pfSense."
        )
        baseline.ssh_enabled = Observation[bool].absent(
            False, "SSH access is disabled by default in pfSense."
        )
        baseline.vty_transport_input = Observation[List[str]].absent(
            [], "VTY remote access transport is disabled by default."
        )
        baseline.vty_exec_timeout_seconds = Observation[int].absent(
            14400, "WebGUI session timeout defaults to 240 minutes (14400 seconds)."
        )

        system = root.find("system")

        # Hostname
        if system is not None:
            hn_el = system.find("hostname")
            if hn_el is not None and hn_el.text:
                line_num = self._find_line_number("hostname", hn_el.text)
                raw, _, note = self._evidence(line_num)
                baseline.hostname = Observation[str].found(hn_el.text, raw, line_num, note=note)
            else:
                baseline.hostname = Observation[str].unknown("Hostname is not configured in this file.")
        else:
            baseline.hostname = Observation[str].unknown("System block is not configured in this file.")

        # WebGUI config
        if system is not None:
            webgui = system.find("webgui")
            if webgui is not None:
                proto_el = webgui.find("protocol")
                if proto_el is not None and proto_el.text:
                    proto = proto_el.text.lower()
                    line_num = self._find_line_number("protocol", proto_el.text)
                    raw, _, note = self._evidence(line_num)
                    if proto == "http":
                        baseline.http_server_enabled = Observation[bool].found(True, raw, line_num, note=note)
                        baseline.https_server_enabled = Observation[bool].found(False, raw, line_num, note=note)
                    elif proto == "https":
                        baseline.http_server_enabled = Observation[bool].found(False, raw, line_num, note=note)
                        baseline.https_server_enabled = Observation[bool].found(True, raw, line_num, note=note)

                timeout_el = webgui.find("session_timeout")
                if timeout_el is not None and timeout_el.text:
                    try:
                        minutes = int(timeout_el.text)
                        line_num = self._find_line_number("session_timeout", timeout_el.text)
                        raw, _, note = self._evidence(line_num)
                        baseline.vty_exec_timeout_seconds = Observation[int].found(minutes * 60, raw, line_num, note=note)
                    except ValueError:
                        pass

        # SSH
        if system is not None:
            ssh = system.find("ssh")
            if ssh is not None:
                enable_el = ssh.find("enable")
                if enable_el is not None and enable_el.text == "enabled":
                    line_num = self._find_line_number("enable", "enabled")
                    raw, _, note = self._evidence(line_num)
                    baseline.ssh_enabled = Observation[bool].found(True, raw, line_num, note=note)
                    baseline.vty_transport_input = Observation[List[str]].found(["ssh"], raw, line_num, note=note)
                else:
                    line_num = self._find_line_number("ssh")
                    raw, _, note = self._evidence(line_num)
                    baseline.ssh_enabled = Observation[bool].found(False, raw, line_num, note=note)
                    baseline.vty_transport_input = Observation[List[str]].found([], raw, line_num, note=note)

        # Centralized AAA / authservers
        if system is not None:
            authservers = system.find("authservers")
            if authservers is not None and len(authservers.findall("authserver")) > 0:
                line_num = self._find_line_number("authserver")
                raw, _, note = self._evidence(line_num)
                baseline.aaa_enabled = Observation[bool].found(True, raw, line_num, note=note)
            else:
                baseline.aaa_enabled = Observation[bool].absent(
                    False, "No remote authentication servers are configured in pfSense."
                )

        # DNS Servers
        if system is not None:
            dns_servers = []
            for dnsserver in system.findall("dnsserver"):
                if dnsserver.text:
                    line_num = self._find_line_number("dnsserver", dnsserver.text)
                    dns_servers.append((dnsserver.text, line_num))
            if dns_servers:
                raw, line_num, note = self._evidence(dns_servers[-1][1])
                baseline.dns_servers = Observation[List[str]].found(
                    [d[0] for d in dns_servers], raw, line_num, note=note
                )
            else:
                baseline.dns_servers = Observation[List[str]].unknown("DNS configuration is not present.")

        # NTP Servers (timeservers)
        if system is not None:
            timeservers_el = system.find("timeservers")
            if timeservers_el is not None and timeservers_el.text:
                servers = timeservers_el.text.strip().split()
                line_num = self._find_line_number("timeservers", timeservers_el.text)
                raw, _, note = self._evidence(line_num)
                baseline.ntp_servers = Observation[List[str]].found(
                    servers, raw, line_num, note=note
                )
            else:
                baseline.ntp_servers = Observation[List[str]].unknown("NTP configuration is not present.")

        # Syslog Remote Logging
        syslog = root.find("syslog")
        if syslog is not None:
            rem_el = syslog.find("remoteserverenable")
            servers_el = syslog.find("remote-log-servers")
            if rem_el is not None and rem_el.text == "1" and servers_el is not None and servers_el.text:
                servers = [s.split(":")[0] for s in servers_el.text.strip().split(",")]
                line_num = self._find_line_number("remote-log-servers", servers_el.text)
                raw, _, note = self._evidence(line_num)
                baseline.logging_enabled = Observation[bool].found(True, raw, line_num, note=note)
                baseline.logging_hosts = Observation[List[str]].found(
                    servers, raw, line_num, note=note
                )
            else:
                line_num = self._find_line_number("syslog")
                raw, _, note = self._evidence(line_num)
                baseline.logging_enabled = Observation[bool].found(False, raw, line_num, note=note)
                baseline.logging_hosts = Observation[List[str]].unknown("Syslog destination hosts are not configured.")
        else:
            baseline.logging_enabled = Observation[bool].unknown("Syslog configuration is not present.")
            baseline.logging_hosts = Observation[List[str]].unknown("Syslog destination hosts are not present.")

        # SNMP
        snmpd = root.find("snmpd")
        if snmpd is not None:
            enable_el = snmpd.find("enable")
            ro_el = snmpd.find("rocommunity")
            if enable_el is not None and enable_el.text == "enabled":
                line_num = self._find_line_number("enable", "enabled")
                raw, _, note = self._evidence(line_num)
                baseline.snmp_agent_enabled = Observation[bool].found(True, raw, line_num, note=note)
                ro_comm = ro_el.text if (ro_el is not None and ro_el.text) else ""
                comm_line_num = self._find_line_number("rocommunity", ro_comm) if ro_comm else line_num
                comm_raw, _, _ = self._evidence(comm_line_num)
                communities = [
                    SnmpCommunity(
                        name=ro_comm,
                        access="ro",
                        source_line=comm_raw,
                        line_number=comm_line_num,
                    )
                ]
                baseline.snmp_communities = Observation[List[SnmpCommunity]].found(
                    communities, raw, line_num, note=f"Configured SNMP RO community: {ro_comm}"
                )
            else:
                line_num = self._find_line_number("snmpd")
                raw, _, note = self._evidence(line_num)
                baseline.snmp_agent_enabled = Observation[bool].found(False, raw, line_num, note=note)
                baseline.snmp_communities = Observation[List[SnmpCommunity]].found(
                    [], raw, line_num, note="SNMP agent is disabled."
                )
        else:
            baseline.snmp_agent_enabled = Observation[bool].absent(
                False, "SNMP service is disabled by default in pfSense."
            )
            baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
                [], "SNMP service is disabled by default in pfSense."
            )
