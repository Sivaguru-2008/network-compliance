"""Vendor parsers. Importing this package registers every built-in parser."""

from .base import ParserError, ParserRegistry, VendorParser, registry
from .a10_acos import A10ACOSParser
from .alcatel_aos import AlcatelAOSParser
from .arista_eos import AristaEOSParser
from .aws_security_group import AWSSecurityGroupParser
from .azure_nsg import AzureNSGParser
from .barracuda_cloudgen import BarracudaCloudGenParser
from .cato_networks import CatoNetworksParser
from .checkpoint_gaia import CheckPointGaiaParser
from .cisco_asa import CiscoASAParser
from .cisco_ios import CiscoIOSParser
from .extreme_exos import ExtremeEXOSParser
from .f5_bigip_tmos import F5BigIPTMOSParser
from .forcepoint_ngfw import ForcepointNGFWParser
from .fortios import FortiosParser
from .hillstone_stoneos import HillstoneStoneOSParser
from .hpe_aruba import HPEArubaParser
from .hpe_aruba_aos_cx import HPEArubaAosCxParser
from .huawei_vrp import HuaweiVRPParser
from .hybrid import HybridParser
from .junos import JunosParser
from .mikrotik_routeros import MikroTikROSParser
from .netgate_pfsense import NetgatePfSenseParser
from .nokia_sros import NokiaSROSParser
from .paloalto import PaloAltoParser
from .pfsense import PfSenseParser
from .ruckus_fastiron import RuckusFastIronParser
from .sangfor_ngaf import SangforNGAFParser
from .sonic import SonicParser
from .sonicwall import SonicWallParser
from .sonicwall_sonicos import SonicWallSonicOSParser
from .sophos_sfos import SophosSFOSParser
from .stormshield import StormshieldParser
from .stormshield_sns import StormshieldSNSParser
from .ubiquiti import UbiquitiParser
from .ubiquiti_edgeos import UbiquitiEdgeOSParser
from .versa_versos import VersaVersaOSParser
from .watchguard import WatchGuardParser
from .watchguard_fireware import WatchGuardFirewareParser
from .zscaler_zia import ZscalerZIAParser
from .zscaler_zpa import ZscalerZPAParser
from .llm import LLMClient, LLMParser, LLMResponseError, LLMUnavailableError

__all__ = [
    "A10ACOSParser",
    "AlcatelAOSParser",
    "AristaEOSParser",
    "AWSSecurityGroupParser",
    "AzureNSGParser",
    "BarracudaCloudGenParser",
    "CatoNetworksParser",
    "CheckPointGaiaParser",
    "CiscoASAParser",
    "CiscoIOSParser",
    "ExtremeEXOSParser",
    "F5BigIPTMOSParser",
    "ForcepointNGFWParser",
    "FortiosParser",
    "HillstoneStoneOSParser",
    "HPEArubaParser",
    "HPEArubaAosCxParser",
    "HuaweiVRPParser",
    "HybridParser",
    "JunosParser",
    "MikroTikROSParser",
    "NetgatePfSenseParser",
    "NokiaSROSParser",
    "PaloAltoParser",
    "PfSenseParser",
    "RuckusFastIronParser",
    "SangforNGAFParser",
    "SonicParser",
    "SonicWallParser",
    "SonicWallSonicOSParser",
    "SophosSFOSParser",
    "StormshieldParser",
    "StormshieldSNSParser",
    "UbiquitiParser",
    "UbiquitiEdgeOSParser",
    "VersaVersaOSParser",
    "WatchGuardParser",
    "WatchGuardFirewareParser",
    "ZscalerZIAParser",
    "ZscalerZPAParser",
    "LLMClient",
    "LLMParser",
    "LLMResponseError",
    "LLMUnavailableError",
    "ParserError",
    "ParserRegistry",
    "VendorParser",
    "registry",
]

