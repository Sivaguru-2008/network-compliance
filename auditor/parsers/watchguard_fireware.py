"""Deterministic WatchGuard Fireware XML configuration parser.

This parser processes WatchGuard Fireware configuration XML backups (config.xml).
Since WatchGuard configurations contain proprietary structural schemas and version-specific tags,
the parser identifies the format using a multi-element fingerprint, extracts schema compatibility metadata,
and reports system-wide security baseline controls as unknown (NEEDS_REVIEW) to ensure safe manual audit validation.
"""

import xml.parsers.expat
import hashlib
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel
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
class WatchGuardFirewareParser(VendorParser):
    """Grammar-based XML parser for WatchGuard Fireware config.xml files."""

    name = "watchguard_fireware"
    vendor = "watchguard"
    os_family = "fireware"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        
        # Multi-element fingerprint verification
        score = 0.0
        if "<configuration" in config_text:
            score += 0.3
        if "<abs-policy-list" in config_text or "<policy-list" in config_text:
            score += 0.3
        if "<alias-list" in config_text:
            score += 0.2
        if "<interface-list" in config_text:
            score += 0.2
            
        # If we have the root tag but none of the specific child tags, return low score
        if "<configuration" in config_text and score == 0.3:
            return 0.1
            
        return min(1.0, score)

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        self._raw_lines = config_text.splitlines()
        builder = XMLTreeBuilder()
        # Parse XML tree to validate formatting correctness
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

        # Set all baseline controls to unknown. WatchGuard's configuration schema is
        # proprietary, and raw configurations are verified manually via GUI/Policy Manager.
        for field in baseline.observable_fields():
            setattr(
                baseline,
                field,
                Observation.unknown(
                    "WatchGuard Fireware security controls are verified manually via Policy Manager/GUI."
                )
            )

        return baseline
