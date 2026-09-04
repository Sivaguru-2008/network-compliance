"""Deterministic Ruckus Networks ICX FastIron configuration parser.

This parser processes Ruckus FastIron configuration files (show running-config exports),
normalizes settings into the SecurityBaselineModel, and preserves
configuration lines and line numbers for compliance audit evidence.
"""

import hashlib
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class RuckusFastIronParser(VendorParser):
    """Configuration parser for Ruckus Networks ICX FastIron configurations."""

    name = "ruckus_fastiron"
    vendor = "ruckus"
    os_family = "fastiron"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0

        # Look for distinctive Ruckus FastIron CLI configuration elements
        text_lower = config_text.lower()
        
        # Unique FastIron indicators
        indicators = [
            "web-management http",
            "web-management https",
            "enable super-user-password",
            "enable strict-password-enforcement",
            "fdp run",
            "fdp enable",
            "telnet client-acl",
            "ip ssh client-acl",
            "fastiron",
            "ruckus",
        ]
        
        score = 0
        for ind in indicators:
            if ind in text_lower:
                score += 1

        # Must have at least two indicators or one very specific one (like enable super-user-password or strict password)
        if "sonicos" in text_lower or "sonicwall" in text_lower:
            return 0.0

        if (score >= 2 or 
            "enable super-user-password" in text_lower or 
            "enable strict-password-enforcement" in text_lower or 
            "web-management client-acl" in text_lower):
            # Exclude Cisco IOS false positives
            if "ip http server" not in text_lower or "web-management" in text_lower:
                return 1.0
        return 0.0

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        self._raw_lines = config_text.splitlines()

        if self.detect(config_text) == 0.0:
            raise ParserError("Not a Ruckus Networks FastIron configuration.")

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

        self._parse_config(baseline)

        # Set all remaining unparsed fields to unknown
        for field in baseline.observable_fields():
            observation = getattr(baseline, field)
            if observation.note == "Parser did not evaluate this field.":
                setattr(
                    baseline,
                    field,
                    type(observation).unknown(
                        "Ruckus FastIron parser does not evaluate this field."
                    )
                )

        return baseline

    def _evidence(self, line_num: int) -> Tuple[str, int, str]:
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"Line {line_num}: {raw_line}"

    def _parse_config(self, baseline: SecurityBaselineModel) -> None:
        # FastIron default values
        baseline.telnet_enabled = Observation[bool].absent(
            True, "Telnet server daemon is enabled by default on Ruckus FastIron."
        )
        baseline.http_server_enabled = Observation[bool].absent(
            False, "HTTP web management is disabled by default on Ruckus FastIron."
        )
        baseline.https_server_enabled = Observation[bool].absent(
            False, "HTTPS web management is disabled by default on Ruckus FastIron."
        )
        baseline.ssh_enabled = Observation[bool].absent(
            False, "SSH server daemon is disabled by default on Ruckus FastIron."
        )
        baseline.vty_transport_input = Observation[List[str]].absent(
            ["telnet"], "Console/remote access defaults to Telnet on Ruckus FastIron."
        )
        baseline.vty_exec_timeout_seconds = Observation[int].absent(
            0, "CLI session timeout defaults to 0 (no timeout) on Ruckus FastIron."
        )
        baseline.login_banner_present = Observation[bool].absent(
            False, "Pre-login security banner is not configured by default."
        )
        baseline.password_encryption = Observation[bool].absent(
            True, "Ruckus FastIron automatically encrypts all passwords in the configuration file."
        )
        baseline.password_min_length = Observation[int].absent(
            0, "Password minimum length is not enforced by default."
        )
        baseline.aaa_enabled = Observation[bool].absent(
            False, "Centralized AAA authentication is not configured by default."
        )
        baseline.snmp_agent_enabled = Observation[bool].absent(
            False, "SNMP agent is disabled by default on Ruckus FastIron."
        )
        baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
            [], "SNMP communities are not configured by default."
        )
        baseline.management_acl_applied = Observation[bool].absent(
            False, "Management client access lists (ACLs) are not configured by default."
        )
        baseline.enable_secret_set = Observation[bool].absent(
            False, "Super-user privilege password (enable secret) is not configured by default."
        )
        baseline.enable_password_present = Observation[bool].absent(
            False, "FastIron does not support legacy privilege enable passwords."
        )

        dns_servers = []
        ntp_servers = []
        logging_hosts = []
        snmp_communities = []

        ssh_configured = False
        ssh_line = 1
        telnet_disabled = False
        telnet_line = 1
        http_enabled = False
        http_line = 1
        https_enabled = False
        https_line = 1

        active_banner = False
        banner_lines = []
        banner_start_line = 1

        for idx, line in enumerate(self._raw_lines):
            line_num = idx + 1
            line_strip = line.strip()

            if active_banner:
                banner_lines.append(line_strip)
                if line_strip.endswith("^") or line_strip == "^":
                    active_banner = False
                    raw, _, note = self._evidence(banner_start_line)
                    baseline.login_banner_present = Observation[bool].found(True, raw, banner_start_line, note=note)
                continue

            # Skip comments
            if not line_strip or line_strip.startswith("!"):
                continue

            # Hostname
            if line_strip.startswith("hostname "):
                val = line_strip.split(" ", 1)[1].strip().strip('"')
                raw, _, note = self._evidence(line_num)
                baseline.hostname = Observation[str].found(val, raw, line_num, note=note)

            # SSH
            elif line_strip == "ip ssh server":
                ssh_configured = True
                ssh_line = line_num
            elif line_strip == "no ip ssh server":
                ssh_configured = False
                ssh_line = line_num

            # Telnet
            elif line_strip == "no telnet server":
                telnet_disabled = True
                telnet_line = line_num
            elif line_strip == "telnet server":
                telnet_disabled = False
                telnet_line = line_num

            # HTTP / HTTPS web-management
            elif line_strip == "web-management http":
                http_enabled = True
                http_line = line_num
            elif line_strip == "no web-management http":
                http_enabled = False
                http_line = line_num
            elif line_strip == "web-management https":
                https_enabled = True
                https_line = line_num
            elif line_strip == "no web-management https":
                https_enabled = False
                https_line = line_num

            # Session Timeout
            elif line_strip.startswith("console timeout ") or line_strip.startswith("telnet timeout ") or line_strip.startswith("cli timeout "):
                parts = line_strip.split()
                try:
                    minutes = int(parts[-1])
                    raw, _, note = self._evidence(line_num)
                    baseline.vty_exec_timeout_seconds = Observation[int].found(minutes * 60, raw, line_num, note=note)
                except ValueError:
                    pass

            # Login Banner
            elif line_strip.startswith("banner motd "):
                active_banner = True
                banner_start_line = line_num
                banner_lines.append(line_strip)

            # Password policy
            elif line_strip == "enable strict-password-enforcement":
                raw, _, note = self._evidence(line_num)
                baseline.password_min_length = Observation[int].found(8, raw, line_num, note=note)

            # Enable Secret (enable super-user-password)
            elif line_strip.startswith("enable super-user-password"):
                raw, _, note = self._evidence(line_num)
                baseline.enable_secret_set = Observation[bool].found(True, raw, line_num, note=note)

            # AAA
            elif line_strip.startswith("aaa authentication login "):
                raw, _, note = self._evidence(line_num)
                # Check if it uses local only or remote AAA (tacacs+/radius)
                is_aaa = "tacacs+" in line_strip or "radius" in line_strip
                baseline.aaa_enabled = Observation[bool].found(is_aaa, raw, line_num, note=note)

            # SNMP Community
            elif line_strip.startswith("snmp-server community "):
                # E.g. snmp-server community public ro
                parts = line_strip.split()
                try:
                    comm_name = parts[2]
                    priv = "ro"
                    if len(parts) > 3:
                        priv = parts[3].lower()
                    snmp_communities.append({
                        "name": comm_name,
                        "access": priv,
                        "line": line_num,
                    })
                except IndexError:
                    pass

            # NTP Server
            elif line_strip.startswith("ntp server "):
                parts = line_strip.split()
                try:
                    val = parts[2]
                    ntp_servers.append((val, line_num))
                except IndexError:
                    pass

            # DNS Server
            elif line_strip.startswith("ip dns server-address "):
                parts = line_strip.split()
                try:
                    val = parts[3]
                    dns_servers.append((val, line_num))
                except IndexError:
                    pass

            # Logging syslog destination host
            elif line_strip.startswith("logging host ") or line_strip.startswith("logging server "):
                parts = line_strip.split()
                try:
                    val = parts[2]
                    logging_hosts.append((val, line_num))
                except IndexError:
                    pass

            # Management ACL (client-acl on ssh, telnet, or web-management)
            elif "client-acl" in line_strip:
                raw, _, note = self._evidence(line_num)
                baseline.management_acl_applied = Observation[bool].found(True, raw, line_num, note=note)

        # ----------------------------------------------------------------------
        # Post-processing evaluations based on collected context states
        # ----------------------------------------------------------------------

        # SSH
        if ssh_configured:
            raw, _, note = self._evidence(ssh_line)
            baseline.ssh_enabled = Observation[bool].found(True, raw, ssh_line, note=note)

        # Telnet
        if telnet_disabled:
            raw, _, note = self._evidence(telnet_line)
            baseline.telnet_enabled = Observation[bool].found(False, raw, telnet_line, note=note)

        # Transports Allowed
        allowed_transports = []
        if ssh_configured:
            allowed_transports.append("ssh")
        if not telnet_disabled:
            allowed_transports.append("telnet")
        if allowed_transports:
            # Pick whichever command set or modified VTY transport
            ref_line = ssh_line if ssh_configured else telnet_line
            raw, _, note = self._evidence(ref_line)
            baseline.vty_transport_input = Observation[List[str]].found(allowed_transports, raw, ref_line, note=note)

        # HTTP / HTTPS
        if http_enabled:
            raw, _, note = self._evidence(http_line)
            baseline.http_server_enabled = Observation[bool].found(True, raw, http_line, note=note)
        elif http_line > 1: # if we saw no web-management http
            raw, _, note = self._evidence(http_line)
            baseline.http_server_enabled = Observation[bool].found(False, raw, http_line, note=note)

        if https_enabled:
            raw, _, note = self._evidence(https_line)
            baseline.https_server_enabled = Observation[bool].found(True, raw, https_line, note=note)
        elif https_line > 1:
            raw, _, note = self._evidence(https_line)
            baseline.https_server_enabled = Observation[bool].found(False, raw, https_line, note=note)

        # DNS Servers
        if dns_servers:
            last_ip, last_line = dns_servers[-1]
            raw, _, note = self._evidence(last_line)
            baseline.dns_servers = Observation[List[str]].found(
                [d[0] for d in dns_servers], raw, last_line, note=note
            )
        else:
            baseline.dns_servers = Observation[List[str]].unknown("DNS configuration is not present.")

        # NTP Servers
        if ntp_servers:
            last_ip, last_line = ntp_servers[-1]
            raw, _, note = self._evidence(last_line)
            baseline.ntp_servers = Observation[List[str]].found(
                [n[0] for n in ntp_servers], raw, last_line, note=note
            )
        else:
            baseline.ntp_servers = Observation[List[str]].unknown("NTP configuration is not present.")

        # Logging / Syslog remote hosts
        if logging_hosts:
            last_ip, last_line = logging_hosts[-1]
            raw, _, note = self._evidence(last_line)
            baseline.logging_enabled = Observation[bool].found(True, raw, last_line, note=note)
            baseline.logging_hosts = Observation[List[str]].found(
                [h[0] for h in logging_hosts], raw, last_line, note=note
            )
        else:
            baseline.logging_enabled = Observation[bool].unknown("Syslog remote server is not configured.")
            baseline.logging_hosts = Observation[List[str]].unknown("Syslog remote server is not configured.")

        # SNMP Communities
        if snmp_communities:
            communities_list = []
            last_snmp_line = 1
            for c in snmp_communities:
                raw, _, _ = self._evidence(c["line"])
                communities_list.append(
                    SnmpCommunity(
                        name=c["name"],
                        access=c["access"],
                        source_line=raw,
                        line_number=c["line"],
                    )
                )
                last_snmp_line = c["line"]
            
            raw, _, note = self._evidence(last_snmp_line)
            baseline.snmp_agent_enabled = Observation[bool].found(True, raw, last_snmp_line, note=note)
            baseline.snmp_communities = Observation[List[SnmpCommunity]].found(
                communities_list, raw, last_snmp_line, note=note
            )
