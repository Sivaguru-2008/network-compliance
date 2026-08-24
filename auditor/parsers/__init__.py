"""Vendor parsers. Importing this package registers every built-in parser."""

from .base import ParserError, ParserRegistry, VendorParser, registry
from .arista_eos import AristaEOSParser
from .cisco_ios import CiscoIOSParser
from .fortios import FortiosParser
from .hybrid import HybridParser
from .junos import JunosParser
from .llm import LLMClient, LLMParser, LLMResponseError, LLMUnavailableError
from .sonic import SonicParser

__all__ = [
    "AristaEOSParser",
    "CiscoIOSParser",
    "FortiosParser",
    "HybridParser",
    "JunosParser",
    "LLMClient",
    "LLMParser",
    "LLMResponseError",
    "LLMUnavailableError",
    "ParserError",
    "ParserRegistry",
    "SonicParser",
    "VendorParser",
    "registry",
]
