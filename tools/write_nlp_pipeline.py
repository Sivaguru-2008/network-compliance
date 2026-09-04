# Python generator for NLP pipeline modules
import os
import sys
from pathlib import Path

def write_extractor():
    code = '''"""Comprehensive Security & Network Semantic Extractor for Multi-Vendor Configurations.

Extracts canonical structured semantics across Device, Interfaces, Routing,
Firewall/ACL, NAT, AAA, Management Security, Cryptography, and Security Controls.
"""

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Core regex patterns
IP_PATTERN = re.compile(r'\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\b')
IPV6_PATTERN = re.compile(r'(?i)\\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\\b')
CIDR_PATTERN = re.compile(r'\\b(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)/(?:[0-9]|[12][0-9]|3[0-2])\\b')

@dataclass
class DeviceInfo:
    hostname: Optional[str] = None
    vendor: str = "unknown"
    platform: str = "unknown"
    os_version: Optional[str] = None
    device_role: str = "network_device"
    line_number: Optional[int] = None
    evidence: Optional[str] = None

@dataclass
class InterfaceInfo:
    name: str
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    vlan: Optional[int] = None
    vrf: Optional[str] = None
    admin_state: str = "up"
    description: Optional[str] = None
    security_zone: Optional[str] = None
    applied_acls: List[str] = field(default_factory=list)
    line_number: Optional[int] = None
    evidence: Optional[str] = None

@dataclass
class RouteRule:
    prefix: str
    next_hop: Optional[str] = None
    interface: Optional[str] = None
    protocol: str = "static"
    distance: Optional[int] = None
    is_default: bool = False
    line_number: Optional[int] = None
    evidence: Optional[str] = None

@dataclass
class RoutingInfo:
    protocols: List[str] = field(default_factory=list)
    default_route_configured: bool = False
    routes: List[RouteRule] = field(default_factory=list)
    bgp_asns: List[int] = field(default_factory=list)
    ospf_areas: List[str] = field(default_factory=list)
    route_policies: List[str] = field(default_factory=list)

@dataclass
class FirewallRule:
    acl_name: str
    rule_id: Optional[str] = None
    action: str = "permit"
    protocol: str = "ip"
    source: str = "any"
    destination: str = "any"
    source_port: Optional[str] = None
    destination_port: Optional[str] = None
    direction: Optional[str] = None
    interface: Optional[str] = None
    logging: bool = False
    is_unrestricted: bool = False
    line_number: Optional[int] = None
    evidence: Optional[str] = None

@dataclass
class FirewallInfo:
    acl_count: int = 0
    rules: List[FirewallRule] = field(default_factory=list)
    has_any_to_any_rule: bool = False
    unrestricted_acls: List[str] = field(default_factory=list)
    security_policies: List[str] = field(default_factory=list)

@dataclass
class NatRule:
    nat_type: str = "dynamic"
    original_source: Optional[str] = None
    translated_source: Optional[str] = None
    original_destination: Optional[str] = None
    translated_destination: Optional[str] = None
    pool_name: Optional[str] = None
    interface: Optional[str] = None
    line_number: Optional[int] = None
    evidence: Optional[str] = None

@dataclass
class NatInfo:
    enabled: bool = False
    rules: List[NatRule] = field(default_factory=list)
    nat_pools: List[str] = field(default_factory=list)

@dataclass
class UserInfo:
    username: str
    privilege_level: Optional[int] = None
    role: Optional[str] = None
    has_secret: bool = False
    has_weak_password: bool = False
    line_number: Optional[int] = None
    evidence: Optional[str] = None

@dataclass
class AuthenticationInfo:
    aaa_enabled: bool = False
    radius_servers: List[str] = field(default_factory=list)
    tacacs_servers: List[str] = field(default_factory=list)
    local_users: List[UserInfo] = field(default_factory=list)
    auth_methods: List[str] = field(default_factory=list)
    password_encryption_enabled: bool = False
    enable_secret_configured: bool = False
    enable_password_plaintext: bool = False
    min_password_length: Optional[int] = None
    account_lockout_enabled: bool = False
    lockout_threshold: Optional[int] = None

@dataclass
class SnmpCommunityInfo:
    name: str
    access: str = "ro"
    acl: Optional[str] = None
    is_default: bool = False
    line_number: Optional[int] = None
    evidence: Optional[str] = None

@dataclass
class ManagementSecurityInfo:
    ssh_enabled: bool = False
    ssh_version: Optional[int] = None
    telnet_enabled: bool = False
    http_server_enabled: bool = False
    https_server_enabled: bool = False
    snmp_enabled: bool = False
    snmp_version: Optional[str] = None
    snmp_v3_users: List[str] = field(default_factory=list)
    snmp_communities: List[SnmpCommunityInfo] = field(default_factory=list)
    logging_enabled: bool = False
    syslog_servers: List[str] = field(default_factory=list)
    logging_buffered: bool = False
    ntp_enabled: bool = False
    ntp_servers: List[str] = field(default_factory=list)
    login_banner_configured: bool = False
    management_acl_applied: bool = False
    exec_timeout_seconds: Optional[int] = None

@dataclass
class CryptoInfo:
    ipsec_configured: bool = False
    ike_configured: bool = False
    vpn_profiles: List[str] = field(default_factory=list)
    tls_min_version: Optional[str] = None
    weak_algorithms_used: List[str] = field(default_factory=list)
    strong_crypto_enforced: bool = False

@dataclass
class CanonicalSecurityConfig:
    file_id: str
    vendor: str
    platform: str
    source_path: str
    sha256: str
    line_count: int
    quality_score: float
    parse_status: str
    device: DeviceInfo
    interfaces: List[InterfaceInfo] = field(default_factory=list)
    routing: RoutingInfo = field(default_factory=RoutingInfo)
    firewall: FirewallInfo = field(default_factory=FirewallInfo)
    nat: NatInfo = field(default_factory=NatInfo)
    authentication: AuthenticationInfo = field(default_factory=AuthenticationInfo)
    management: ManagementSecurityInfo = field(default_factory=ManagementSecurityInfo)
    cryptography: CryptoInfo = field(default_factory=CryptoInfo)
    raw_sections: Dict[str, List[str]] = field(default_factory=dict)
    security_features: Dict[str, bool] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecuritySemanticExtractor:
    """Extracts structured network and security semantics across 24+ network vendors."""

    def __init__(self):
        pass

    def extract(self, config_text: str, file_id: str, vendor_slug: str, source_path: str = "") -> CanonicalSecurityConfig:
        lines = config_text.splitlines()
        line_count = len(lines)
        sha256 = hashlib.sha256(config_text.encode('utf-8')).hexdigest()

        quality_score = self._compute_quality_score(lines, vendor_slug)
        device = self._extract_device_info(lines, vendor_slug)
        interfaces = self._extract_interfaces(lines, vendor_slug)
        routing = self._extract_routing(lines, vendor_slug)
        firewall = self._extract_firewall(lines, vendor_slug)
        nat = self._extract_nat(lines, vendor_slug)
        auth = self._extract_authentication(lines, vendor_slug)
        mgmt = self._extract_management(lines, vendor_slug)
        crypto = self._extract_cryptography(lines, vendor_slug)
        sections = self._extract_sections(lines, vendor_slug)

        features = self._extract_security_features(device, interfaces, routing, firewall, nat, auth, mgmt, crypto)
        findings = self._detect_security_findings(device, interfaces, routing, firewall, nat, auth, mgmt, crypto, features)

        parse_status = 'success' if quality_score >= 0.25 and (device.hostname or interfaces or features) else 'partial'

        return CanonicalSecurityConfig(
            file_id=file_id,
            vendor=device.vendor,
            platform=device.platform,
            source_path=source_path,
            sha256=sha256,
            line_count=line_count,
            quality_score=round(quality_score, 3),
            parse_status=parse_status,
            device=device,
            interfaces=interfaces,
            routing=routing,
            firewall=firewall,
            nat=nat,
            authentication=auth,
            management=mgmt,
            cryptography=crypto,
            raw_sections=sections,
            security_features=features,
            findings=findings,
        )

    def _compute_quality_score(self, lines: List[str], vendor_slug: str) -> float:
        if not lines:
            return 0.0
        non_empty = [l.strip() for l in lines if l.strip() and not l.strip().startswith(('!', '#', '//', '/*'))]
        if not non_empty:
            return 0.1
        ratio = len(non_empty) / max(len(lines), 1)
        base_score = min(1.0, 0.4 + (ratio * 0.4) + min(0.2, len(non_empty) / 100.0))
        return base_score

    def _extract_device_info(self, lines: List[str], vendor_slug: str) -> DeviceInfo:
        hostname = None
        ev = None
        ln = None

        vendor_name = vendor_slug.split('_')[0] if '_' in vendor_slug else vendor_slug
        platform = vendor_slug

        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            m = re.match(r'^(?:hostname|sysname|set\\s+system\\s+host-name|host-name)\\s+[\"\\x27]?([a-zA-Z0-9_.-]+)', clean, re.I)
            if m:
                hostname = m.group(1).rstrip(';')
                ev = clean
                ln = idx
                break
            if clean.startswith('set hostname'):
                parts = clean.split()
                if len(parts) >= 3:
                    hostname = parts[2].strip('\"\\x27')
                    ev = clean
                    ln = idx
                    break
            m_junos = re.match(r'^host-name\\s+([a-zA-Z0-9_.-]+);', clean, re.I)
            if m_junos:
                hostname = m_junos.group(1)
                ev = clean
                ln = idx
                break
            m_pan = re.match(r'set\\s+deviceconfig\\s+system\\s+hostname\\s+([a-zA-Z0-9_.-]+)', clean, re.I)
            if m_pan:
                hostname = m_pan.group(1)
                ev = clean
                ln = idx
                break
            if '\"DEVICE_METADATA\"' in clean or '\"hostname\"' in clean:
                m_json = re.search(r'\"hostname\"\\s*:\\s*\"([^\"]+)\"', clean)
                if m_json:
                    hostname = m_json.group(1)
                    ev = clean
                    ln = idx
                    break

        return DeviceInfo(
            hostname=hostname,
            vendor=vendor_name,
            platform=platform,
            os_version=None,
            device_role='router_switch' if any('interface' in l.lower() for l in lines[:50]) else 'security_device',
            line_number=ln,
            evidence=ev,
        )

    def _extract_interfaces(self, lines: List[str], vendor_slug: str) -> List[InterfaceInfo]:
        interfaces = []
        curr_iface = None
        curr_lines = []
        curr_start = 0

        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            m_if = re.match(r'^(?:interface|set\\s+interfaces|edit)\\s+([a-zA-Z0-9_./-]+)', clean, re.I)
            if m_if and not clean.startswith('interface-range') and not 'tunnel' in clean.lower() and not clean.startswith('set interfaces interface-range'):
                if curr_iface:
                    self._finalize_interface(curr_iface, curr_lines, interfaces, curr_start)
                curr_iface = InterfaceInfo(name=m_if.group(1).rstrip(';'), line_number=idx, evidence=clean)
                curr_lines = []
                curr_start = idx
                continue

            m_junos_if = re.match(r'^set\\s+interfaces\\s+([a-zA-Z0-9_./-]+)', clean, re.I)
            if m_junos_if:
                iface_name = m_junos_if.group(1)
                existing = next((i for i in interfaces if i.name == iface_name), None)
                if not existing:
                    existing = InterfaceInfo(name=iface_name, line_number=idx, evidence=clean)
                    interfaces.append(existing)
                ip_match = IP_PATTERN.search(clean)
                if ip_match and 'address' in clean:
                    existing.ip_address = ip_match.group(0)

            if curr_iface:
                curr_lines.append(clean)
                if clean == '!' or clean == 'exit' or clean == 'next' or clean.startswith('interface ') or clean.startswith('router '):
                    self._finalize_interface(curr_iface, curr_lines, interfaces, curr_start)
                    curr_iface = None
                    curr_lines = []

        if curr_iface:
            self._finalize_interface(curr_iface, curr_lines, interfaces, curr_start)

        return interfaces

    def _finalize_interface(self, iface: InterfaceInfo, lines: List[str], iface_list: List[InterfaceInfo], start_ln: int):
        for line in lines:
            m_ip = re.search(r'ip(?:v4)?\\s+address\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)(?:\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)|/(\\d+))?', line, re.I)
            if m_ip:
                iface.ip_address = m_ip.group(1)
                iface.subnet_mask = m_ip.group(2) or m_ip.group(3)
            if 'shutdown' in line.lower() and not 'no shutdown' in line.lower():
                iface.admin_state = 'down'
            m_desc = re.search(r'description\\s+(.*)', line, re.I)
            if m_desc:
                iface.description = m_desc.group(1).strip('\"\\x27')
            m_acl = re.search(r'(?:ip\\s+access-group|access-class|traffic-filter)\\s+([a-zA-Z0-9_.-]+)', line, re.I)
            if m_acl:
                iface.applied_acls.append(m_acl.group(1))
            m_zone = re.search(r'(?:zone-member\\s+security|security-zone|zone)\\s+([a-zA-Z0-9_.-]+)', line, re.I)
            if m_zone:
                iface.security_zone = m_zone.group(1)
            m_vlan = re.search(r'(?:vlan|access\\s+vlan)\\s+(\\d+)', line, re.I)
            if m_vlan:
                try:
                    iface.vlan = int(m_vlan.group(1))
                except ValueError:
                    pass

        iface_list.append(iface)

    def _extract_routing(self, lines: List[str], vendor_slug: str) -> RoutingInfo:
        info = RoutingInfo()
        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            if re.match(r'^(?:ip\\s+route|set\\s+routing-options\\s+static\\s+route|route\\s+add|ip\\s+route-static)', clean, re.I):
                m_def = re.search(r'(?:0\\.0\\.0\\.0\\s+0\\.0\\.0\\.0|0\\.0\\.0\\.0/0|default)', clean, re.I)
                is_def = bool(m_def)
                if is_def:
                    info.default_route_configured = True
                ip_matches = IP_PATTERN.findall(clean)
                prefix = ip_matches[0] if ip_matches else "0.0.0.0/0"
                next_hop = ip_matches[1] if len(ip_matches) > 1 else None
                info.routes.append(RouteRule(prefix=prefix, next_hop=next_hop, is_default=is_def, line_number=idx, evidence=clean))
                if "static" not in info.protocols:
                    info.protocols.append("static")

            if re.search(r'\\b(?:router\\s+ospf|set\\s+protocols\\s+ospf|ospf\\b)', clean, re.I):
                if "OSPF" not in info.protocols:
                    info.protocols.append("OSPF")
                m_area = re.search(r'area\\s+([a-zA-Z0-9_.-]+)', clean, re.I)
                if m_area and m_area.group(1) not in info.ospf_areas:
                    info.ospf_areas.append(m_area.group(1))

            if re.search(r'\\b(?:router\\s+bgp|set\\s+protocols\\s+bgp|bgp\\b)', clean, re.I):
                if "BGP" not in info.protocols:
                    info.protocols.append("BGP")
                m_asn = re.search(r'(?:router\\s+bgp|autonomous-system|as)\\s+(\\d+)', clean, re.I)
                if m_asn:
                    try:
                        asn = int(m_asn.group(1))
                        if asn not in info.bgp_asns:
                            info.bgp_asns.append(asn)
                    except ValueError:
                        pass

            if re.search(r'\\brouter\\s+eigrp\\b', clean, re.I) and "EIGRP" not in info.protocols:
                info.protocols.append("EIGRP")
            if re.search(r'\\brouter\\s+rip\\b', clean, re.I) and "RIP" not in info.protocols:
                info.protocols.append("RIP")
            if re.search(r'\\brouter\\s+isis\\b', clean, re.I) and "ISIS" not in info.protocols:
                info.protocols.append("ISIS")

        return info

    def _extract_firewall(self, lines: List[str], vendor_slug: str) -> FirewallInfo:
        info = FirewallInfo()
        acl_names = set()

        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            m_cisco_acl = re.match(r'^(?:access-list\\s+(\\S+)|ip\\s+access-list\\s+(?:extended|standard)\\s+(\\S+))\\s+(permit|deny)\\s+(.*)', clean, re.I)
            if m_cisco_acl:
                acl_name = m_cisco_acl.group(1) or m_cisco_acl.group(2)
                action = m_cisco_acl.group(3).lower()
                rest = m_cisco_acl.group(4)
                acl_names.add(acl_name)

                is_any_any = bool(re.search(r'\\bany\\s+any\\b', rest, re.I))
                if is_any_any and action == 'permit':
                    info.has_any_to_any_rule = True
                    if acl_name not in info.unrestricted_acls:
                        info.unrestricted_acls.append(acl_name)

                proto_match = re.search(r'^(ip|tcp|udp|icmp|gre|esp|ah)\\b', rest, re.I)
                proto = proto_match.group(1).lower() if proto_match else 'ip'

                info.rules.append(FirewallRule(
                    acl_name=acl_name,
                    action=action,
                    protocol=proto,
                    is_unrestricted=is_any_any and action == 'permit',
                    line_number=idx,
                    evidence=clean,
                ))

            if re.search(r'\\b(?:security\\s+policies|config\\s+firewall\\s+policy|set\\s+security\\s+rules)\\b', clean, re.I):
                info.security_policies.append(clean)
            if re.search(r'\\b(?:action\\s+accept|action\\s+permit|then\\s+permit|action\\s+allow)\\b', clean, re.I) and ('any' in clean.lower() or 'all' in clean.lower()):
                info.has_any_to_any_rule = True

        info.acl_count = len(acl_names) or len(info.rules)
        return info

    def _extract_nat(self, lines: List[str], vendor_slug: str) -> NatInfo:
        info = NatInfo()
        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            if re.match(r'^(?:ip\\s+nat|set\\s+security\\s+nat|config\\s+firewall\\s+vip|config\\s+firewall\\s+ippool)', clean, re.I):
                info.enabled = True
                nat_type = "dynamic"
                if "static" in clean.lower() or "vip" in clean.lower():
                    nat_type = "static"
                elif "overload" in clean.lower() or "pat" in clean.lower() or "masquerade" in clean.lower():
                    nat_type = "pat"
                elif "pool" in clean.lower():
                    nat_type = "pool"
                    m_pool = re.search(r'pool\\s+([a-zA-Z0-9_.-]+)', clean, re.I)
                    if m_pool and m_pool.group(1) not in info.nat_pools:
                        info.nat_pools.append(m_pool.group(1))

                info.rules.append(NatRule(nat_type=nat_type, line_number=idx, evidence=clean))
        return info

    def _extract_authentication(self, lines: List[str], vendor_slug: str) -> AuthenticationInfo:
        info = AuthenticationInfo()
        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            if re.search(r'\\b(?:aaa\\s+new-model|aaa\\s+authentication|set\\s+system\\s+authentication-order)\\b', clean, re.I):
                info.aaa_enabled = True
            if re.search(r'\\b(?:radius-server|radius\\s+host|config\\s+user\\s+radius)\\b', clean, re.I):
                ip_match = IP_PATTERN.search(clean)
                if ip_match and ip_match.group(0) not in info.radius_servers:
                    info.radius_servers.append(ip_match.group(0))
            if re.search(r'\\b(?:tacacs-server|tacacs\\s+host|config\\s+user\\s+tacacs)\\b', clean, re.I):
                ip_match = IP_PATTERN.search(clean)
                if ip_match and ip_match.group(0) not in info.tacacs_servers:
                    info.tacacs_servers.append(ip_match.group(0))
            m_user = re.match(r'^(?:username|local-user|set\\s+system\\s+login\\s+user|set\\s+user)\\s+([a-zA-Z0-9_.-]+)', clean, re.I)
            if m_user:
                uname = m_user.group(1)
                has_secret = 'secret' in clean.lower() or 'encrypted-password' in clean.lower()
                has_weak = 'password 0' in clean.lower() or 'plain-text-password' in clean.lower() or 'password 7' in clean.lower()
                priv_match = re.search(r'privilege\\s+(\\d+)', clean, re.I)
                priv = int(priv_match.group(1)) if priv_match else None
                info.local_users.append(UserInfo(username=uname, privilege_level=priv, has_secret=has_secret, has_weak_password=has_weak, line_number=idx, evidence=clean))

            if re.search(r'\\bservice\\s+password-encryption\\b', clean, re.I):
                info.password_encryption_enabled = True
            if re.match(r'^enable\\s+secret\\b', clean, re.I):
                info.enable_secret_configured = True
            if re.match(r'^enable\\s+password\\b', clean, re.I):
                info.enable_password_plaintext = True
            m_len = re.search(r'(?:min-length|min-password-length|password\\s+min-len)\\s+(\\d+)', clean, re.I)
            if m_len:
                try:
                    info.min_password_length = int(m_len.group(1))
                except ValueError:
                    pass
            if re.search(r'\\b(?:admin-lockout|lockout-duration|login\\s+block-for|login\\s+delay)\\b', clean, re.I):
                info.account_lockout_enabled = True
                m_thresh = re.search(r'(?:attempts|threshold|within)\\s+(\\d+)', clean, re.I)
                if m_thresh:
                    try:
                        info.lockout_threshold = int(m_thresh.group(1))
                    except ValueError:
                        pass

        return info

    def _extract_management(self, lines: List[str], vendor_slug: str) -> ManagementSecurityInfo:
        info = ManagementSecurityInfo()

        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            if re.search(r'\\b(?:ip\\s+ssh|set\\s+system\\s+services\\s+ssh|ssh\\s+server|stelnet\\s+server\\s+enable)\\b', clean, re.I):
                info.ssh_enabled = True
                m_v = re.search(r'(?:version\\s+(\\d+)|v(\\d+))', clean, re.I)
                if m_v:
                    v_str = m_v.group(1) or m_v.group(2)
                    try:
                        info.ssh_version = int(v_str)
                    except ValueError:
                        pass
            if re.search(r'\\b(?:transport\\s+input.*\\btelnet\\b|telnet\\s+server\\s+enable|set\\s+system\\s+services\\s+telnet)\\b', clean, re.I):
                info.telnet_enabled = True
            if re.match(r'^ip\\s+http\\s+server\\b', clean, re.I) or re.search(r'\\bset\\s+system\\s+services\\s+web-management\\s+http\\b', clean, re.I):
                info.http_server_enabled = True
            if re.match(r'^ip\\s+http\\s+secure-server\\b', clean, re.I) or re.search(r'\\bset\\s+system\\s+services\\s+web-management\\s+https\\b', clean, re.I):
                info.https_server_enabled = True
            if re.match(r'^no\\s+ip\\s+http\\s+server\\b', clean, re.I):
                info.http_server_enabled = False

            if re.search(r'\\b(?:snmp-server|snmp-agent|set\\s+snmp|config\\s+system\\s+snmp)\\b', clean, re.I):
                info.snmp_enabled = True
                m_comm = re.search(r'(?:community|snmp-agent\\s+community\\s+\\w+)\\s+([a-zA-Z0-9_.-]+)(?:\\s+(ro|rw))?', clean, re.I)
                if m_comm:
                    comm_name = m_comm.group(1)
                    access = (m_comm.group(2) or "ro").lower()
                    is_def = comm_name.lower() in ("public", "private")
                    info.snmp_communities.append(SnmpCommunityInfo(name=comm_name, access=access, is_default=is_def, line_number=idx, evidence=clean))
                if "v3" in clean.lower() or "user" in clean.lower():
                    m_u = re.search(r'user\\s+([a-zA-Z0-9_.-]+)', clean, re.I)
                    if m_u and m_u.group(1) not in info.snmp_v3_users:
                        info.snmp_v3_users.append(m_u.group(1))

            if re.search(r'\\b(?:logging\\s+host|logging\\s+server|set\\s+system\\s+syslog|info-center\\s+loghost)\\b', clean, re.I):
                info.logging_enabled = True
                ip_match = IP_PATTERN.search(clean)
                if ip_match and ip_match.group(0) not in info.syslog_servers:
                    info.syslog_servers.append(ip_match.group(0))
            if re.search(r'\\blogging\\s+buffered\\b', clean, re.I):
                info.logging_enabled = True
                info.logging_buffered = True

            if re.search(r'\\b(?:ntp\\s+server|set\\s+system\\s+ntp|ntp-service\\s+unicast-server)\\b', clean, re.I):
                info.ntp_enabled = True
                ip_match = IP_PATTERN.search(clean)
                if ip_match and ip_match.group(0) not in info.ntp_servers:
                    info.ntp_servers.append(ip_match.group(0))

            if re.search(r'\\b(?:banner\\s+(?:login|motd|exec)|set\\s+system\\s+login\\s+message|header\\s+login)\\b', clean, re.I):
                info.login_banner_configured = True

            if re.search(r'\\b(?:access-class|management-access|ssh\\s+access-group|admin-access)\\b', clean, re.I):
                info.management_acl_applied = True

            m_to = re.search(r'\\bexec-timeout\\s+(\\d+)(?:\\s+(\\d+))?', clean, re.I)
            if m_to:
                mins = int(m_to.group(1))
                secs = int(m_to.group(2) or 0)
                info.exec_timeout_seconds = (mins * 60) + secs

        return info

    def _extract_cryptography(self, lines: List[str], vendor_slug: str) -> CryptoInfo:
        info = CryptoInfo()
        weak_algos = ['des', '3des', 'md5', 'rc4', 'diffie-hellman-group-1', 'group1', 'null', 'export']

        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            lower = clean.lower()
            if re.search(r'\\b(?:crypto\\s+ipsec|crypto\\s+map|set\\s+security\\s+ipsec|config\\s+vpn\\s+ipsec)\\b', clean, re.I):
                info.ipsec_configured = True
            if re.search(r'\\b(?:crypto\\s+ike|crypto\\s+isakmp|set\\s+security\\s+ike)\\b', clean, re.I):
                info.ike_configured = True
            for w in weak_algos:
                if re.search(r'\\b' + re.escape(w) + r'\\b', lower):
                    if w not in info.weak_algorithms_used:
                        info.weak_algorithms_used.append(w)
            if 'aes-256' in lower or 'sha256' in lower or 'group14' in lower or 'group19' in lower:
                info.strong_crypto_enforced = True

        return info

    def _extract_sections(self, lines: List[str], vendor_slug: str) -> Dict[str, List[str]]:
        sections = {}
        curr_section = "SYSTEM"
        curr_lines = []

        for line in lines:
            clean = line.strip()
            if not clean or clean.startswith('!'):
                continue

            sec = self._classify_line_section(clean)
            if sec != curr_section and curr_lines:
                sections.setdefault(curr_section, []).extend(curr_lines)
                curr_lines = []
                curr_section = sec
            curr_lines.append(clean)

        if curr_lines:
            sections.setdefault(curr_section, []).extend(curr_lines)

        return sections

    def _classify_line_section(self, line: str) -> str:
        lower = line.lower()
        if lower.startswith(('interface', 'set interfaces', 'edit interface', 'port-channel')):
            return "INTERFACE"
        if lower.startswith(('router ospf', 'router bgp', 'router eigrp', 'router rip', 'router isis', 'ip route', 'set protocols', 'set routing-options')):
            return "ROUTING"
        if lower.startswith(('access-list', 'ip access-list', 'firewall', 'security policies', 'config firewall policy', 'set security rules')):
            return "FIREWALL"
        if lower.startswith(('ip nat', 'config firewall vip', 'set security nat')):
            return "NAT"
        if lower.startswith(('crypto', 'set security ipsec', 'set security ike', 'config vpn')):
            return "VPN"
        if lower.startswith(('aaa', 'tacacs', 'radius', 'set system authentication-order')):
            return "AAA"
        if lower.startswith(('username', 'local-user', 'set system login user', 'set user', 'user')):
            return "USER_MANAGEMENT"
        if lower.startswith(('snmp', 'snmp-server', 'snmp-agent', 'set snmp')):
            return "SNMP"
        if lower.startswith(('logging', 'syslog', 'info-center', 'set system syslog')):
            return "LOGGING"
        if lower.startswith(('ntp', 'ntp-server', 'ntp-service', 'set system ntp')):
            return "NTP"
        if lower.startswith(('line vty', 'line con', 'line aux', 'transport input', 'exec-timeout', 'ssh', 'ip ssh', 'ip http', 'web-management')):
            return "MANAGEMENT"
        if lower.startswith(('vlan', 'set vlans')):
            return "VLAN"
        return "SYSTEM"

    def _extract_security_features(self, device: DeviceInfo, ifaces: List[InterfaceInfo], routing: RoutingInfo,
                                  firewall: FirewallInfo, nat: NatInfo, auth: AuthenticationInfo,
                                  mgmt: ManagementSecurityInfo, crypto: CryptoInfo) -> Dict[str, bool]:
        features = {
            "SSH_ENABLED": mgmt.ssh_enabled,
            "TELNET_ENABLED": mgmt.telnet_enabled,
            "AAA_ENABLED": auth.aaa_enabled,
            "TACACS_ENABLED": bool(auth.tacacs_servers),
            "RADIUS_ENABLED": bool(auth.radius_servers),
            "SNMP_ENABLED": mgmt.snmp_enabled,
            "SNMPV2": any(not c.is_default for c in mgmt.snmp_communities),
            "SNMPV3": bool(mgmt.snmp_v3_users),
            "WEAK_CRYPTO": bool(crypto.weak_algorithms_used),
            "DEFAULT_CREDENTIAL": any(c.is_default for c in mgmt.snmp_communities),
            "INSECURE_MANAGEMENT": mgmt.telnet_enabled or mgmt.http_server_enabled,
            "UNRESTRICTED_ACL": firewall.has_any_to_any_rule,
            "ANY_TO_ANY_RULE": firewall.has_any_to_any_rule,
            "LOGGING_DISABLED": not mgmt.logging_enabled,
            "NTP_DISABLED": not mgmt.ntp_enabled,
            "UNUSED_INTERFACE_ACTIVE": any(i.admin_state == 'up' and not i.ip_address and not i.vlan for i in ifaces),
            "WEAK_PASSWORD_POLICY": not auth.password_encryption_enabled or (auth.min_password_length is not None and auth.min_password_length < 8),
            "HTTP_MANAGEMENT_ENABLED": mgmt.http_server_enabled,
            "MANAGEMENT_ACL_APPLIED": mgmt.management_acl_applied,
            "LOGIN_BANNER_PRESENT": mgmt.login_banner_configured,
            "PASSWORD_ENCRYPTION_ENABLED": auth.password_encryption_enabled,
            "ENABLE_SECRET_SET": auth.enable_secret_configured,
            "ENABLE_PASSWORD_PLAINTEXT": auth.enable_password_plaintext,
            "DEFAULT_ROUTE_PRESENT": routing.default_route_configured,
            "IPSEC_CONFIGURED": crypto.ipsec_configured,
            "NAT_CONFIGURED": nat.enabled,
        }
        return features

    def _detect_security_findings(self, device: DeviceInfo, ifaces: List[InterfaceInfo], routing: RoutingInfo,
                                 firewall: FirewallInfo, nat: NatInfo, auth: AuthenticationInfo,
                                 mgmt: ManagementSecurityInfo, crypto: CryptoInfo,
                                 features: Dict[str, bool]) -> List[Dict[str, Any]]:
        findings = []

        if features.get("TELNET_ENABLED"):
            findings.append({
                "finding": "TELNET_ENABLED",
                "severity": "HIGH",
                "evidence": "transport input telnet",
                "explanation": "Telnet transmits administrative credentials and traffic in plaintext across the network.",
                "control_ref": "CIS-2.1.1",
            })

        if features.get("HTTP_MANAGEMENT_ENABLED"):
            findings.append({
                "finding": "HTTP_MANAGEMENT_ENABLED",
                "severity": "HIGH",
                "evidence": "ip http server",
                "explanation": "Unencrypted HTTP web management exposes administrative session cookies and credentials.",
                "control_ref": "CIS-2.2.1",
            })

        if features.get("DEFAULT_CREDENTIAL"):
            findings.append({
                "finding": "DEFAULT_CREDENTIAL",
                "severity": "CRITICAL",
                "evidence": next((c.evidence for c in mgmt.snmp_communities if c.is_default), "snmp-server community public"),
                "explanation": "Default SNMP community strings ('public'/'private') allow unauthorized reconnaissance or reconfiguration.",
                "control_ref": "CIS-1.3.1",
            })

        if features.get("WEAK_CRYPTO"):
            findings.append({
                "finding": "WEAK_CRYPTO",
                "severity": "HIGH",
                "evidence": f"weak algorithms: {', '.join(crypto.weak_algorithms_used)}",
                "explanation": "Legacy encryption/hashing ciphers (DES/3DES/MD5) are susceptible to cryptanalytic collision and decryption attacks.",
                "control_ref": "CIS-4.1.2",
            })

        if features.get("ANY_TO_ANY_RULE"):
            findings.append({
                "finding": "ANY_TO_ANY_RULE",
                "severity": "HIGH",
                "evidence": next((r.evidence for r in firewall.rules if r.is_unrestricted), "permit any any"),
                "explanation": "Unrestricted any-to-any firewall rules permit all network traffic bypassing security perimeter controls.",
                "control_ref": "CIS-3.1.4",
            })

        if features.get("LOGGING_DISABLED"):
            findings.append({
                "finding": "LOGGING_DISABLED",
                "severity": "MEDIUM",
                "evidence": "<absent> no logging destination configured",
                "explanation": "Security events and access logs are not forwarded to centralized SIEM/syslog repositories.",
                "control_ref": "CIS-1.4.1",
            })

        if features.get("NTP_DISABLED"):
            findings.append({
                "finding": "NTP_DISABLED",
                "severity": "MEDIUM",
                "evidence": "<absent> no ntp server configured",
                "explanation": "Device lacks authoritative time synchronization needed for accurate forensic log correlation.",
                "control_ref": "CIS-1.4.2",
            })

        if features.get("ENABLE_PASSWORD_PLAINTEXT"):
            findings.append({
                "finding": "ENABLE_PASSWORD_PLAINTEXT",
                "severity": "HIGH",
                "evidence": "enable password <REDACTED>",
                "explanation": "Legacy enable password uses reversible or cleartext encoding instead of cryptographic hash.",
                "control_ref": "CIS-1.1.2",
            })

        if not features.get("MANAGEMENT_ACL_APPLIED") and (mgmt.ssh_enabled or mgmt.telnet_enabled):
            findings.append({
                "finding": "UNRESTRICTED_MANAGEMENT",
                "severity": "HIGH",
                "evidence": "<absent> access-class not applied on remote admin lines",
                "explanation": "Administrative access is not filtered by source IP address filter/ACL.",
                "control_ref": "CIS-2.3.1",
            })

        return findings
'''
    Path('nlp_pipeline/extractor.py').write_text(code, encoding='utf-8')
    print('Generated nlp_pipeline/extractor.py')

if __name__ == '__main__':
    write_extractor()

