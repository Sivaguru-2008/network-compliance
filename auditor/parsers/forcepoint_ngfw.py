"""Deterministic Forcepoint NGFW XML configuration parser.

Validation Status: SYNTHETIC / UNSUPPORTED CLI FORMAT.
Forcepoint NGFW is managed primarily via Forcepoint Security Management Center (SMC)
export or REST API. This parser processes simplified XML export fixtures and must not
be claimed as verified real-world production grammar.
"""

import xml.parsers.expat
import hashlib
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


class XMLNode:
    """Represents a simplified XML node parsed from Forcepoint configuration."""
    def __init__(self, tag: str, attrs: dict, line_number: int):
        self.tag: str = tag
        self.attrs: dict = attrs
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
        node = XMLNode(tag=name, attrs=attrs, line_number=line)
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
class ForcepointNGFWParser(VendorParser):
    """SMC XML configuration parser for Forcepoint NGFW."""

    name = "forcepoint_ngfw"
    vendor = "forcepoint"
    os_family = "forcepoint_ngfw"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        
        score = 0.0
        if "<firewall_node" in config_text or "<single_fw" in config_text or "<fw_cluster" in config_text:
            score += 0.5
        if "engine_version=" in config_text or "db_key=" in config_text:
            score += 0.5
            
        return min(1.0, score)

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        self._raw_lines = config_text.splitlines()
        builder = XMLTreeBuilder()
        root_node = builder.parse(config_text)

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

        self._normalize_hostname(root_node, baseline)
        self._normalize_http_https(root_node, baseline)
        self._normalize_ssh_telnet(root_node, baseline)

        # Set all remaining unparsed fields to unknown
        for field in baseline.observable_fields():
            observation = getattr(baseline, field)
            if observation.note == "Parser did not evaluate this field.":
                setattr(
                    baseline,
                    field,
                    type(observation).unknown(
                        "Forcepoint NGFW parser does not evaluate this field."
                    )
                )

        return baseline

    def _evidence(self, node: XMLNode, key: str, value: str) -> Tuple[str, int, str]:
        raw_line = self._raw_lines[node.line_number - 1].strip()
        return raw_line, node.line_number, f"Line {node.line_number}: <{node.tag} {key}=\"{value}\">"

    def _normalize_hostname(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        # Check 'name' attribute in root node
        if "name" in root.attrs:
            val = root.attrs["name"]
            raw, line, note = self._evidence(root, "name", val)
            baseline.hostname = Observation[str].found(val, raw, line, note=note)
        else:
            baseline.hostname = Observation[str].unknown("Hostname is not configured in this file.")

    def _normalize_http_https(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        # Check HTTP service status in XML attributes
        if "web_server_http" in root.attrs:
            val = root.attrs["web_server_http"]
            raw, line, note = self._evidence(root, "web_server_http", val)
            is_enabled = val.lower() in ("true", "1", "yes")
            baseline.http_server_enabled = Observation[bool].found(is_enabled, raw, line, note=note)
        else:
            # Default HTTP access is disabled
            baseline.http_server_enabled = Observation[bool].absent(
                False, "WebAdmin HTTP is disabled by default in Forcepoint NGFW."
            )

        if "web_server_https" in root.attrs:
            val = root.attrs["web_server_https"]
            raw, line, note = self._evidence(root, "web_server_https", val)
            is_enabled = val.lower() in ("true", "1", "yes")
            baseline.https_server_enabled = Observation[bool].found(is_enabled, raw, line, note=note)
        else:
            # Default HTTPS access is enabled
            baseline.https_server_enabled = Observation[bool].absent(
                True, "WebAdmin HTTPS is enabled by default in Forcepoint NGFW."
            )

    def _normalize_ssh_telnet(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        # Telnet is disabled/unsupported on Forcepoint NGFW
        baseline.telnet_enabled = Observation[bool].absent(
            False, "Telnet is unsupported on Forcepoint NGFW."
        )

        # SSH Console status
        if "ssh_service" in root.attrs:
            val = root.attrs["ssh_service"]
            raw, line, note = self._evidence(root, "ssh_service", val)
            is_enabled = val.lower() in ("true", "1", "yes")
            baseline.ssh_enabled = Observation[bool].found(is_enabled, raw, line, note=note)
            baseline.vty_transport_input = Observation[List[str]].found(
                ["ssh"] if is_enabled else [], raw, line, note=note
            )
        else:
            baseline.ssh_enabled = Observation[bool].unknown("SSH service status is not configured in this element.")
            baseline.vty_transport_input = Observation[List[str]].unknown("SSH console transport configuration is absent.")

        baseline.ssh_version = Observation[int].unknown("SSH version is not configured in this file.")
