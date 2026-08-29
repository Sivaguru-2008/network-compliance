"""Vendor parsers. Importing this package registers every built-in parser."""

from .base import ParserError, ParserRegistry, VendorParser, registry
from .arista_eos import AristaEOSParser
from .cisco_ios import CiscoIOSParser
from .fortios import FortiosParser
from .hybrid import HybridParser
from .junos import JunosParser
from .sonic import SonicParser
from .paloalto import PaloAltoParser
from .huawei_vrp import HuaweiVRPParser
from .checkpoint_gaia import CheckPointGaiaParser
from .mikrotik_routeros import MikroTikROSParser
from .sonicwall import SonicWallParser
from .stormshield import StormshieldParser
from .watchguard import WatchGuardParser
from .llm import LLMClient, LLMParser, LLMResponseError, LLMUnavailableError

__all__ = [
    "AristaEOSParser",
    "CheckPointGaiaParser",
    "CiscoIOSParser",
    "FortiosParser",
    "HybridParser",
    "JunosParser",
    "SonicParser",
    "PaloAltoParser",
    "HuaweiVRPParser",
    "MikroTikROSParser",
    "SonicWallParser",
    "StormshieldParser",
    "WatchGuardParser",
    "LLMClient",
    "LLMParser",
    "LLMResponseError",
    "LLMUnavailableError",
    "ParserError",
    "ParserRegistry",
    "VendorParser",
    "registry",
]
