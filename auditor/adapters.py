import re
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple, Type

from auditor.models.baseline import SecurityBaselineModel
from auditor.parsers import (
    A10ACOSParser, AlcatelAOSParser, AristaEOSParser, AWSSecurityGroupParser,
    AzureNSGParser, BarracudaCloudGenParser, CatoNetworksParser, CheckPointGaiaParser,
    CiscoASAParser, CiscoIOSParser, ExtremeEXOSParser, F5BigIPTMOSParser,
    ForcepointNGFWParser, FortiosParser, HillstoneStoneOSParser, HPEArubaParser,
    HPEArubaAosCxParser, HuaweiVRPParser, JunosParser, MikroTikROSParser,
    NetgatePfSenseParser, NokiaSROSParser, PaloAltoParser, PfSenseParser,
    RuckusFastIronParser, SangforNGAFParser, SonicParser, SonicWallParser,
    SonicWallSonicOSParser, SophosSFOSParser, StormshieldParser, StormshieldSNSParser,
    UbiquitiParser, UbiquitiEdgeOSParser, VersaVersaOSParser, WatchGuardParser,
    WatchGuardFirewareParser, ZscalerZIAParser, ZscalerZPAParser, VendorParser
)

IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
SUBNET_RE = re.compile(r'\b(?:255\.(?:255|0|128|192|224|240|248|252|254)\.(?:255|0|128|192|224|240|248|252|254)\.(?:255|0|128|192|224|240|248|252|254))\b')

class VendorAdapter(ABC):
    vendor_slug = 'unknown'
    platform = 'unknown'
    parser_class = None
    corpus_status = 'SUPPORTED'

    @classmethod
    def identify(cls, config_text: str) -> float:
        if cls.parser_class:
            return cls.parser_class.detect(config_text)
        return 0.0

    def parse(self, config_text: str, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if self.parser_class:
            return self.parser_class().parse(config_text, source_file=source_file)
        return SecurityBaselineModel()

    def extract_sections(self, config_text: str) -> Dict[str, List[Tuple[int, int, str]]]:
        lines = config_text.splitlines()
        sections = {'INTERFACE': [], 'ROUTING': [], 'FIREWALL': [], 'ACL': [], 'AAA': [], 'MANAGEMENT': [], 'LOGGING': [], 'NTP': [], 'SNMP': [], 'VPN': [], 'SYSTEM': []}
        curr, chunk, start = 'SYSTEM', [], 1
        for i, line in enumerate(lines, 1):
            s = line.strip()
            if not s or s.startswith(('!', '#', '//')):
                continue
            up = s.upper()
            nxt = None
            if up.startswith(('INTERFACE', 'PORT ', 'EDIT PORT', 'SET INTERFACES')):
                nxt = 'INTERFACE'
            elif any(k in up for k in ['ROUTER ', 'BGP', 'OSPF', 'IP ROUTE', 'STATIC-ROUTE', 'ROUTING-OPTIONS']):
                nxt = 'ROUTING'
            elif any(k in up for k in ['FIREWALL', 'SECURITY POLICY', 'ACCESS-LIST', 'ACL', 'RULEBASE', 'SECURITY RULES']):
                nxt = 'FIREWALL'
            elif any(k in up for k in ['AAA ', 'AUTHENTICATION', 'AUTHORIZATION', 'ACCOUNTING', 'USER ', 'USERNAME']):
                nxt = 'AAA'
            elif any(k in up for k in ['LINE VTY', 'SSH', 'TELNET', 'HTTP SERVER', 'WEB-MANAGEMENT']):
                nxt = 'MANAGEMENT'
            elif any(k in up for k in ['LOGGING ', 'SYSLOG', 'INFO-CENTER']):
                nxt = 'LOGGING'
            elif any(k in up for k in ['NTP ', 'NTP-SERVICE', 'TIME-SERVER']):
                nxt = 'NTP'
            elif any(k in up for k in ['SNMP', 'SNMP-SERVER', 'SNMP-AGENT']):
                nxt = 'SNMP'
            elif any(k in up for k in ['CRYPTO ', 'IPSEC', 'IKE', 'VPN']):
                nxt = 'VPN'
            if nxt and nxt != curr:
                if chunk:
                    sections[curr].append((start, i - 1, '\n'.join(chunk)))
                    chunk = []
                curr, start = nxt, i
            chunk.append(line)
        if chunk:
            sections[curr].append((start, len(lines), '\n'.join(chunk)))
        return sections

    def extract_security_features(self, config_text: str) -> Dict[str, Any]:
        features = {}
        for i, line in enumerate(config_text.splitlines(), 1):
            s = line.strip().lower()
            if not s or s.startswith(('!', '#')):
                continue
            if 'transport input' in s:
                features['telnet_enabled'] = {'value': 'telnet' in s, 'line': i, 'evidence': line.strip(), 'confidence': 1.0, 'vendor': self.vendor_slug}
                features['ssh_enabled'] = {'value': 'ssh' in s, 'line': i, 'evidence': line.strip(), 'confidence': 1.0, 'vendor': self.vendor_slug}
            elif 'service telnet' in s or 'telnet server enable' in s:
                features['telnet_enabled'] = {'value': not ('delete' in s or 'undo' in s or 'no ' in s), 'line': i, 'evidence': line.strip(), 'confidence': 1.0, 'vendor': self.vendor_slug}
            elif 'logging host' in s or 'syslog host' in s or 'info-center loghost' in s:
                features['logging_configured'] = {'value': True, 'line': i, 'evidence': line.strip(), 'confidence': 1.0, 'vendor': self.vendor_slug}
            elif 'ntp server' in s or 'ntp-service' in s or 'ntpserver' in s:
                features['ntp_configured'] = {'value': True, 'line': i, 'evidence': line.strip(), 'confidence': 1.0, 'vendor': self.vendor_slug}
            elif 'snmp-server community public' in s or 'community public' in s:
                features['default_snmp_community'] = {'value': True, 'line': i, 'evidence': line.strip(), 'confidence': 1.0, 'vendor': self.vendor_slug}
            elif any(c in s for c in ['des', '3des', 'md5', 'rc4', 'sha-1']):
                if not any(k in s for k in ['no ', 'delete', 'undo']):
                    features['weak_crypto'] = {'value': True, 'line': i, 'evidence': line.strip(), 'confidence': 0.98, 'vendor': self.vendor_slug}
        return features

    def extract_entities(self, config_text: str) -> List[Dict[str, Any]]:
        entities = []
        char_off = 0
        for lnum, line in enumerate(config_text.splitlines(), 1):
            for m in IP_RE.finditer(line):
                val = m.group(0)
                if not SUBNET_RE.match(val):
                    entities.append({'type': 'IP_ADDRESS', 'value': val, 'start': char_off + m.start(), 'end': char_off + m.end(), 'line_number': lnum, 'evidence': line.strip()})
            for m in SUBNET_RE.finditer(line):
                entities.append({'type': 'SUBNET', 'value': m.group(0), 'start': char_off + m.start(), 'end': char_off + m.end(), 'line_number': lnum, 'evidence': line.strip()})
            im = re.search(r'\b(?:interface|edit|port)\s+([a-zA-Z0-9/_.:-]+)', line, re.I)
            if im:
                entities.append({'type': 'INTERFACE', 'value': im.group(1), 'start': char_off + im.start(1), 'end': char_off + im.end(1), 'line_number': lnum, 'evidence': line.strip()})
            vm = re.search(r'\bvlan\s+(\d+)\b', line, re.I)
            if vm:
                entities.append({'type': 'VLAN', 'value': vm.group(1), 'start': char_off + vm.start(1), 'end': char_off + vm.end(1), 'line_number': lnum, 'evidence': line.strip()})
            cm = re.search(r'\b(aes-128|aes-256|3des|des|sha256|sha512|md5|sha1)\b', line, re.I)
            if cm:
                entities.append({'type': 'CRYPTO_ALGORITHM', 'value': cm.group(1), 'start': char_off + cm.start(1), 'end': char_off + cm.end(1), 'line_number': lnum, 'evidence': line.strip()})
            pm = re.search(r'\b(tcp|udp|icmp|ospf|bgp|ssh|telnet|https|http|snmp|ntp)\b', line, re.I)
            if pm:
                entities.append({'type': 'PROTOCOL', 'value': pm.group(1), 'start': char_off + pm.start(1), 'end': char_off + pm.end(1), 'line_number': lnum, 'evidence': line.strip()})
            char_off += len(line) + 1
        return entities

    def generate_remediation(self, finding: str) -> Dict[str, Any]:
        from auditor.rules.loader import get_remediation_for_control
        remed = get_remediation_for_control(finding, self.platform)
        if remed:
            return {'summary': remed.get('summary', f'Remediate {finding}'), 'commands': remed.get('commands', []), 'risk': remed.get('risk', 'Medium'), 'rationale': remed.get('rationale', 'Ensure security compliance')}
        return {'summary': f'Review and remediate {finding} according to security policy.', 'commands': [], 'risk': 'Medium', 'rationale': 'Ensure compliance with security baseline.'}

class CiscoIOSAdapter(VendorAdapter): vendor_slug = 'cisco'; platform = 'cisco_ios'; parser_class = CiscoIOSParser
class CiscoASAAdapter(VendorAdapter): vendor_slug = 'cisco'; platform = 'cisco_asa'; parser_class = CiscoASAParser
class JuniperJunosAdapter(VendorAdapter): vendor_slug = 'juniper'; platform = 'juniper_junos'; parser_class = JunosParser
class AristaEOSAdapter(VendorAdapter): vendor_slug = 'arista'; platform = 'arista_eos'; parser_class = AristaEOSParser
class FortiOSAdapter(VendorAdapter): vendor_slug = 'fortinet'; platform = 'fortinet_fortios'; parser_class = FortiosParser
class PaloAltoPANOSAdapter(VendorAdapter): vendor_slug = 'paloalto'; platform = 'paloalto_panos'; parser_class = PaloAltoParser
class HuaweiVRPAdapter(VendorAdapter): vendor_slug = 'huawei'; platform = 'huawei_vrp'; parser_class = HuaweiVRPParser
class NokiaSROSAdapter(VendorAdapter): vendor_slug = 'nokia'; platform = 'nokia_sros'; parser_class = NokiaSROSParser
class MikroTikRouterOSAdapter(VendorAdapter): vendor_slug = 'mikrotik'; platform = 'mikrotik_routeros'; parser_class = MikroTikROSParser
class F5BIGIPAdapter(VendorAdapter): vendor_slug = 'f5'; platform = 'f5_bigip_tmos'; parser_class = F5BigIPTMOSParser
class SONiCAdapter(VendorAdapter): vendor_slug = 'sonic'; platform = 'sonic'; parser_class = SonicParser
class pfSenseAdapter(VendorAdapter): vendor_slug = 'netgate'; platform = 'netgate_pfsense'; parser_class = NetgatePfSenseParser
class CheckPointGaiaAdapter(VendorAdapter): vendor_slug = 'checkpoint'; platform = 'checkpoint_gaia'; parser_class = CheckPointGaiaParser
class SonicWallAdapter(VendorAdapter): vendor_slug = 'sonicwall'; platform = 'sonicwall_sonicos'; parser_class = SonicWallParser
class StormshieldAdapter(VendorAdapter): vendor_slug = 'stormshield'; platform = 'stormshield_sns'; parser_class = StormshieldParser
class UbiquitiAdapter(VendorAdapter): vendor_slug = 'ubiquiti'; platform = 'ubiquiti_edgeos'; parser_class = UbiquitiEdgeOSParser
class VersaAdapter(VendorAdapter): vendor_slug = 'versa'; platform = 'versa_versos'; parser_class = VersaVersaOSParser
class WatchGuardAdapter(VendorAdapter): vendor_slug = 'watchguard'; platform = 'watchguard_fireware'; parser_class = WatchGuardParser
class HPEArubaAdapter(VendorAdapter): vendor_slug = 'hpe'; platform = 'hpe_aruba_aos_cx'; parser_class = HPEArubaAosCxParser
class ExtremeEXOSAdapter(VendorAdapter): vendor_slug = 'extreme'; platform = 'extreme_exos'; parser_class = ExtremeEXOSParser
class AlcatelAOSAdapter(VendorAdapter): vendor_slug = 'alcatel'; platform = 'alcatel_aos'; parser_class = AlcatelAOSParser
class A10ACOSAdapter(VendorAdapter): vendor_slug = 'a10'; platform = 'a10_acos'; parser_class = A10ACOSParser
class SophosSFOSAdapter(VendorAdapter): vendor_slug = 'sophos'; platform = 'sophos_sfos'; parser_class = SophosSFOSParser
class RuckusFastIronAdapter(VendorAdapter): vendor_slug = 'ruckus'; platform = 'ruckus_fastiron'; parser_class = RuckusFastIronParser
class SangforNGAFAdapter(VendorAdapter): vendor_slug = 'sangfor'; platform = 'sangfor_ngaf'; parser_class = SangforNGAFParser
class HillstoneStoneOSAdapter(VendorAdapter): vendor_slug = 'hillstone'; platform = 'hillstone_stoneos'; parser_class = HillstoneStoneOSParser

class AWSSecurityGroupAdapter(VendorAdapter): vendor_slug = 'aws'; platform = 'aws_security_group'; parser_class = AWSSecurityGroupParser
class AzureNSGAdapter(VendorAdapter): vendor_slug = 'azure'; platform = 'azure_nsg'; parser_class = AzureNSGParser
class HPEArubaAOSAdapter(VendorAdapter): vendor_slug = 'hpe'; platform = 'hpe_aruba'; parser_class = HPEArubaParser
class BarracudaCloudGenAdapter(VendorAdapter): vendor_slug = 'barracuda'; platform = 'barracuda_cloudgen'; parser_class = BarracudaCloudGenParser; corpus_status = 'SUPPORTED_WITH_LIMITED_CORPUS'
class CatoNetworksAdapter(VendorAdapter): vendor_slug = 'cato'; platform = 'cato_networks'; parser_class = CatoNetworksParser; corpus_status = 'SUPPORTED_WITH_LIMITED_CORPUS'
class ForcepointNGFWAdapter(VendorAdapter): vendor_slug = 'forcepoint'; platform = 'forcepoint_ngfw'; parser_class = ForcepointNGFWParser; corpus_status = 'SUPPORTED_WITH_LIMITED_CORPUS'
class ZscalerZIAAdapter(VendorAdapter): vendor_slug = 'zscaler'; platform = 'zscaler_zia'; parser_class = ZscalerZIAParser; corpus_status = 'SUPPORTED_WITH_LIMITED_CORPUS'
class ZscalerZPAAdapter(VendorAdapter): vendor_slug = 'zscaler'; platform = 'zscaler_zpa'; parser_class = ZscalerZPAParser; corpus_status = 'SUPPORTED_WITH_LIMITED_CORPUS'

class AdapterRegistry:
    def __init__(self):
        self._adapters = {
            'a10_acos': A10ACOSAdapter,
            'alcatel_aos': AlcatelAOSAdapter,
            'arista_eos': AristaEOSAdapter,
            'aws_security_group': AWSSecurityGroupAdapter,
            'azure_nsg': AzureNSGAdapter,
            'barracuda_cloudgen': BarracudaCloudGenAdapter,
            'cato_networks': CatoNetworksAdapter,
            'checkpoint_gaia': CheckPointGaiaAdapter,
            'cisco_asa': CiscoASAAdapter,
            'cisco_ios': CiscoIOSAdapter,
            'extreme_exos': ExtremeEXOSAdapter,
            'f5_bigip_tmos': F5BIGIPAdapter,
            'forcepoint_ngfw': ForcepointNGFWAdapter,
            'fortinet_fortios': FortiOSAdapter,
            'hillstone_stoneos': HillstoneStoneOSAdapter,
            'hpe_aruba': HPEArubaAOSAdapter,
            'hpe_aruba_aos_cx': HPEArubaAdapter,
            'huawei_vrp': HuaweiVRPAdapter,
            'juniper_junos': JuniperJunosAdapter,
            'mikrotik_routeros': MikroTikRouterOSAdapter,
            'netgate_pfsense': pfSenseAdapter,
            'nokia_sros': NokiaSROSAdapter,
            'paloalto_panos': PaloAltoPANOSAdapter,
            'ruckus_fastiron': RuckusFastIronAdapter,
            'sangfor_ngaf': SangforNGAFAdapter,
            'sonic': SONiCAdapter,
            'sonicwall_sonicos': SonicWallAdapter,
            'sophos_sfos': SophosSFOSAdapter,
            'stormshield_sns': StormshieldAdapter,
            'ubiquiti_edgeos': UbiquitiAdapter,
            'versa_versos': VersaAdapter,
            'watchguard_fireware': WatchGuardAdapter,
            'zscaler_zia': ZscalerZIAAdapter,
            'zscaler_zpa': ZscalerZPAAdapter,
        }

    def get(self, platform: str) -> Optional[VendorAdapter]:
        cls = self._adapters.get(platform.lower())
        return cls() if cls else None

    def rank(self, config_text: str) -> List[Tuple[float, VendorAdapter]]:
        scored = []
        for cls in self._adapters.values():
            s = cls.identify(config_text)
            if s > 0.0:
                scored.append((s, cls()))
        return sorted(scored, key=lambda x: -x[0])

adapter_registry = AdapterRegistry()
