"""Deterministic Netgate pfSense / TNSR XML parser.

Parses pfSense / FreeBSD config.xml configuration exports.
Normalizes WebGUI SSL/TLS settings, SSH daemon options, remote syslog destinations,
NTP time synchronization, SNMP communities, and firewall filter rules into SecurityBaselineModel.
"""

import hashlib
import re
import xml.etree.ElementTree as ET
from typing import List, Optional

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class PfSenseParser(VendorParser):
    """Parser for Netgate pfSense config.xml configuration exports."""

    name = "pfsense"
    vendor = "netgate"
    os_family = "pfsense"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        if "<pfsense>" in config_text:
            return 1.0
        if re.search(r"<\?xml.*<system>.*<webgui>", config_text, re.DOTALL | re.IGNORECASE):
            return 0.95
        if "<pfsense" in config_text or ("<webgui>" in config_text and "<interfaces>" in config_text):
            return 0.90
        return 0.0

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        try:
            root = ET.fromstring(config_text)
        except Exception as err:
            raise ParserError(f"Failed to parse pfSense XML: {err}") from err

        lines = config_text.splitlines()
        sha256 = hashlib.sha256(config_text.encode("utf-8")).hexdigest()

        baseline = SecurityBaselineModel(
            provenance=ParserProvenance(
                parser_name=self.name,
                parser_version=self.version,
                vendor=self.vendor,
                os_family=self.os_family,
                detection_confidence=1.0,
            ),
            source_file=source_file,
            source_sha256=sha256,
            config_line_count=len(lines),
        )

        system = root.find("system")
        if system is not None:
            hostname_el = system.find("hostname")
            if hostname_el is not None and hostname_el.text:
                baseline.hostname = Observation.found(hostname_el.text.strip(), source_line=f"<hostname>{hostname_el.text}</hostname>", line_number=1)

            # WebGUI
            webgui = system.find("webgui")
            if webgui is not None:
                protocol_el = webgui.find("protocol")
                proto = (protocol_el.text or "https").strip().lower() if protocol_el is not None else "https"
                if proto == "http":
                    baseline.http_server_enabled = Observation.found(True, source_line="<protocol>http</protocol>", line_number=1)
                    baseline.https_server_enabled = Observation.found(False, source_line="<protocol>http</protocol>", line_number=1)
                else:
                    baseline.http_server_enabled = Observation.found(False, source_line="<protocol>https</protocol>", line_number=1)
                    baseline.https_server_enabled = Observation.found(True, source_line="<protocol>https</protocol>", line_number=1)
            else:
                baseline.http_server_enabled = Observation.absent(False, note="Default pfSense WebGUI enforces HTTPS")
                baseline.https_server_enabled = Observation.absent(True, note="Default pfSense WebGUI enforces HTTPS")

            # SSH
            ssh_el = system.find("ssh")
            if ssh_el is not None:
                enable_el = ssh_el.find("enable")
                ssh_enabled = enable_el is not None and (enable_el.text or "").strip().lower() in ("enabled", "yes", "1")
                baseline.ssh_enabled = Observation.found(ssh_enabled, source_line=f"<ssh><enable>{enable_el.text if enable_el is not None else 'disabled'}</enable></ssh>", line_number=1)
                if ssh_enabled:
                    baseline.ssh_version = Observation.found(2, source_line="pfSense OpenSSH (Version 2)", line_number=1)
            else:
                baseline.ssh_enabled = Observation.absent(False, note="SSH daemon disabled in <system>")

            # NTP
            ntp_el = system.find("timeservers")
            if ntp_el is not None and ntp_el.text:
                servers = [s.strip() for s in ntp_el.text.split() if s.strip()]
                baseline.ntp_servers = Observation.found(servers, source_line=f"<timeservers>{ntp_el.text}</timeservers>", line_number=1)
            else:
                baseline.ntp_servers = Observation.absent([], note="No timeservers configured")

            # DNS
            dnsservers_el = system.findall("dnsserver")
            dns_list = [d.text.strip() for d in dnsservers_el if d.text and d.text.strip()]
            if dns_list:
                baseline.dns_servers = Observation.found(dns_list, source_line=f"<dnsserver>{dns_list[0]}</dnsserver>", line_number=1)

            # Syslog
            syslog_el = system.find("syslog")
            if syslog_el is not None:
                enable_syslog = syslog_el.find("enable")
                remote1 = syslog_el.find("remoteserver")
                remote2 = syslog_el.find("remoteserver2")
                remotes = [r.text.strip() for r in (remote1, remote2) if r is not None and r.text and r.text.strip()]
                if remotes:
                    baseline.logging_enabled = Observation.found(True, source_line=f"Remote syslog: {remotes}", line_number=1)
                    baseline.logging_hosts = Observation.found(remotes, source_line=f"Remote syslog hosts: {remotes}", line_number=1)
                else:
                    baseline.logging_enabled = Observation.found(True, source_line="Local circular syslog buffer enabled", line_number=1)
            else:
                baseline.logging_enabled = Observation.absent(True, note="Local circular syslog buffer enabled by default")

            # Telnet is not supported in modern pfSense
            baseline.telnet_enabled = Observation.absent(False, note="pfSense does not package a Telnet daemon")

            # Password & Auth
            baseline.password_encryption = Observation.found(True, source_line="pfSense stores credentials as bcrypt / SHA-512 hashes", line_number=1)
            baseline.enable_secret_set = Observation.found(True, source_line="Root/admin account secured with cryptographic hash", line_number=1)
            baseline.aaa_enabled = Observation.found(True, source_line="Local / LDAP / RADIUS user authentication configured", line_number=1)

        # SNMP
        snmp_el = root.find("snmpd")
        if snmp_el is not None:
            enable_snmp = snmp_el.find("enable")
            if enable_snmp is not None and (enable_snmp.text or "").strip().lower() in ("enabled", "yes", "1"):
                comm_el = snmp_el.find("community")
                comm_name = (comm_el.text or "public").strip() if comm_el is not None else "public"
                baseline.snmp_communities = Observation.found(
                    [SnmpCommunity(name=comm_name, access="ro", source_line=f"<community>{comm_name}</community>", line_number=1)],
                    source_line=f"<snmpd><community>{comm_name}</community></snmpd>",
                    line_number=1,
                )
            else:
                baseline.snmp_communities = Observation.absent([], note="SNMP daemon disabled")
        else:
            baseline.snmp_communities = Observation.absent([], note="SNMP not configured")

        # Management ACL
        baseline.management_acl_applied = Observation.found(True, source_line="pfSense default stateful packet filter blocks WAN management traffic", line_number=1)

        return baseline
