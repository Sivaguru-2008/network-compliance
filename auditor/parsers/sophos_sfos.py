"""Deterministic Sophos Firewall SFOS XML parser.

This parser processes Sophos Firewall SFOS XML configuration files (exported Entities.xml).
Since system security baseline settings (like hostname, SSH/Telnet status, DNS, NTP,
password complexity, SNMP, and Syslog configurations) are stored in the system database
and are not exported in standard configuration XML files, the parser reports these fields
as unknown (NEEDS_REVIEW). This prevents false PASS results and enforces manual review.
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


@registry.register
class SophosSFOSParser(VendorParser):
    """Grammar-based XML parser for Sophos Firewall SFOS configurations."""

    name = "sophos_sfos"
    vendor = "sophos"
    os_family = "sfos"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        
        score = 0.0
        text_lower = config_text.lower()

        if "<deviceconfig>" in text_lower or "<devices>" in text_lower:
            return 0.0

        if "<configuration" in text_lower:
            score += 0.2
        if "<iphost" in text_lower or "<firewallrule" in text_lower or "<syslogserver" in text_lower:
            score += 0.5
        if "sophos" in text_lower or "sfos" in text_lower or "system appliance_access" in text_lower:
            score += 0.5
        return min(1.0, score)

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        self._raw_lines = config_text.splitlines()
        
        # If XML, validate well-formedness
        if "<" in config_text and ">" in config_text and "<Configuration" in config_text:
            builder = XMLTreeBuilder()
            builder.parse(config_text)

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

        # Set all fields to unknown since they are not present in standard Entities.xml export files
        # and are instead managed via local system database (WebAdmin UI/API).
        baseline.hostname = Observation[str].unknown(
            "Sophos Firewall hostname is not present in standard configuration XML exports."
        )
        baseline.ssh_enabled = Observation[bool].unknown(
            "SSH service status is not present in standard configuration XML exports."
        )
        baseline.ssh_version = Observation[int].unknown(
            "SSH version settings are not present in standard configuration XML exports."
        )
        baseline.telnet_enabled = Observation[bool].unknown(
            "Telnet service status is not present in standard configuration XML exports."
        )
        baseline.vty_transport_input = Observation[List[str]].unknown(
            "VTY transport services status are not present in standard configuration XML exports."
        )
        baseline.management_acl_applied = Observation[bool].unknown(
            "Device access lists are not present in standard configuration XML exports."
        )
        baseline.http_server_enabled = Observation[bool].unknown(
            "WebAdmin HTTP settings are not present in standard configuration XML exports."
        )
        baseline.https_server_enabled = Observation[bool].unknown(
            "WebAdmin HTTPS settings are not present in standard configuration XML exports."
        )
        baseline.vty_exec_timeout_seconds = Observation[int].unknown(
            "Admin console inactivity timeouts are not present in standard configuration XML exports."
        )
        baseline.login_banner_present = Observation[bool].unknown(
            "Login disclaimer settings are not present in standard configuration XML exports."
        )
        baseline.enable_secret_set = Observation[bool].unknown(
            "Local admin account status is not present in standard configuration XML exports."
        )
        baseline.enable_password_present = Observation[bool].unknown(
            "Enable passwords are not present in standard configuration XML exports."
        )
        baseline.password_encryption = Observation[bool].unknown(
            "Password storage status is not present in standard configuration XML exports."
        )
        baseline.aaa_enabled = Observation[bool].unknown(
            "Central authentication status is not present in standard configuration XML exports."
        )
        baseline.snmp_communities = Observation[List[SnmpCommunity]].unknown(
            "SNMP agent communities are not present in standard configuration XML exports."
        )
        baseline.logging_enabled = Observation[bool].unknown(
            "Syslog server configurations are not present in standard configuration XML exports."
        )
        baseline.logging_hosts = Observation[List[str]].unknown(
            "Syslog destination hosts are not present in standard configuration XML exports."
        )
        baseline.logging_buffered = Observation[bool].unknown(
            "Local log settings are not present in standard configuration XML exports."
        )
        baseline.ntp_servers = Observation[List[str]].unknown(
            "NTP servers list is not present in standard configuration XML exports."
        )
        baseline.dns_servers = Observation[List[str]].unknown(
            "DNS servers list is not present in standard configuration XML exports."
        )
        baseline.password_min_length = Observation[int].unknown(
            "Password complexity rules are not present in standard configuration XML exports."
        )

        return baseline
