"""Vendor parsers. Importing this package registers every built-in parser."""

from .base import ParserError, ParserRegistry, VendorParser, registry
from .arista_eos import AristaEOSParser
from .cisco_ios import CiscoIOSParser
from .fortios import FortiosParser
from .hybrid import HybridParser
from .junos import JunosParser
from .sonic import SonicParser
from .paloalto import PaloAltoParser
from .llm import LLMClient, LLMParser, LLMResponseError, LLMUnavailableError

__all__ = [
    "AristaEOSParser",
    "CiscoIOSParser",
    "FortiosParser",
    "HybridParser",
    "JunosParser",
    "SonicParser",
    "PaloAltoParser",
    "LLMClient",
    "LLMParser",
    "LLMResponseError",
    "LLMUnavailableError",
    "ParserError",
    "ParserRegistry",
    "VendorParser",
    "registry",
]
