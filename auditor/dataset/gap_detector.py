"""Automated comparison engine between authoritative vendor reference knowledge and deterministic parsers."""

import inspect
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..parsers import registry
from .nlp_extractor import ExtractedCommand

logger = logging.getLogger(__name__)


VENDOR_PARSER_MAP = {
    "cisco_ios": "cisco_ios",
    "juniper_junos": "junos",
    "fortinet_fortios": "fortios",
    "arista_eos": "arista_eos",
    "sonic": "sonic",
    "paloalto_panos": "paloalto",
    "huawei_vrp": "huawei_vrp",
    "checkpoint_gaia": "checkpoint_gaia",
    "mikrotik_routeros": "mikrotik_routeros",
    "sonicwall": "sonicwall",
    "stormshield": "stormshield",
    "watchguard_fireware": "watchguard",
}


@dataclass
class GapReport:
    vendor_key: str
    parser_class_name: str
    total_authoritative_commands: int
    supported_commands: List[str]
    unsupported_commands: List[str]
    coverage_percentage: float
    blind_spots: List[Dict[str, Any]]
    recommendations: List[str]


class ParserGapDetector:
    """Detects gaps between authoritative vendor documentation commands and current deterministic parsers."""

    def __init__(self, dataset_base: Path = Path("dataset")):
        self.dataset_base = Path(dataset_base)
        self.vendor_ref_base = self.dataset_base / "vendor_references"

    def _get_parser_source_code(self, parser_cls) -> str:
        try:
            return inspect.getsource(parser_cls)
        except Exception:
            return ""

    def analyze_vendor(self, vendor_key: str) -> Optional[GapReport]:
        """Analyze gaps for a single vendor."""
        # Find parser
        parser_name = VENDOR_PARSER_MAP.get(vendor_key, vendor_key)
        try:
            parser_cls = registry.get(parser_name)
        except Exception:
            parser_cls = None
            for name in registry.names():
                p_cls = registry.get(name)
                if name == vendor_key or p_cls.vendor.lower() in vendor_key.lower():
                    parser_cls = p_cls
                    break

        if not parser_cls:
            logger.warning("No registered parser found for vendor key: %s", vendor_key)
            return None

        # Load authoritative extracted commands
        cmd_file = self.vendor_ref_base / vendor_key / "commands" / "commands.json"
        commands: List[ExtractedCommand] = []
        if cmd_file.exists():
            try:
                with open(cmd_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data:
                        commands.append(ExtractedCommand(**item))
            except Exception as e:
                logger.error("Failed to load command database for %s: %s", vendor_key, e)

        # If no commands file yet, return empty analysis
        if not commands:
            return GapReport(
                vendor_key=vendor_key,
                parser_class_name=parser_cls.__name__,
                total_authoritative_commands=0,
                supported_commands=[],
                unsupported_commands=[],
                coverage_percentage=0.0,
                blind_spots=[],
                recommendations=["Acquire and extract vendor reference documentation to perform gap analysis."],
            )

        parser_src = self._get_parser_source_code(parser_cls).lower()

        supported: List[str] = []
        unsupported: List[str] = []
        blind_spots: List[Dict[str, Any]] = []

        for cmd_entry in commands:
            cmd = cmd_entry.command.strip()
            # Extract first 2-3 key tokens
            tokens = [t.lower() for t in cmd.split() if not t.startswith("<") and not t.startswith("[")]
            key_phrase = " ".join(tokens[:2]) if len(tokens) >= 2 else (tokens[0] if tokens else "")

            if not key_phrase:
                continue

            # Check if keyword / pattern is handled in parser source
            if key_phrase in parser_src or (len(tokens) >= 3 and " ".join(tokens[:3]) in parser_src):
                supported.append(cmd)
            else:
                unsupported.append(cmd)
                if cmd_entry.security_relevance:
                    blind_spots.append({
                        "command": cmd,
                        "security_domain": cmd_entry.security_relevance,
                        "mode": cmd_entry.mode,
                        "source_document": cmd_entry.source_document,
                        "page_or_section": cmd_entry.page_or_section,
                    })

        total = len(supported) + len(unsupported)
        cov = (len(supported) / total * 100.0) if total > 0 else 100.0

        recs = []
        if blind_spots:
            recs.append(f"Add support for {len(blind_spots)} security-relevant commands found in official docs.")
        if cov < 80.0:
            recs.append(f"Improve parser regex and grammar coverage (current coverage: {cov:.1f}%).")
        else:
            recs.append("Core parser covers primary baseline commands documented in official references.")

        return GapReport(
            vendor_key=vendor_key,
            parser_class_name=parser_cls.__name__,
            total_authoritative_commands=total,
            supported_commands=supported,
            unsupported_commands=unsupported,
            coverage_percentage=round(cov, 2),
            blind_spots=blind_spots,
            recommendations=recs,
        )

    def analyze_all(self) -> Dict[str, GapReport]:
        """Analyze gaps across all core vendors."""
        from .sources import get_all_vendor_keys
        results = {}
        for vk in get_all_vendor_keys():
            rep = self.analyze_vendor(vk)
            if rep:
                results[vk] = rep
        return results
