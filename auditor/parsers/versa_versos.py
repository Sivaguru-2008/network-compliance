"""Deterministic Versa Networks VersaOS configuration parser.

This parser processes Versa Networks VOS/VersaOS configurations (both Junos-like
curly-brace hierarchy and flat set-command formats), normalizes settings
into the SecurityBaselineModel, and preserves configuration lines and line numbers.
"""

import hashlib
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class VersaVersaOSParser(VendorParser):
    """Configuration parser for Versa Networks VersaOS configurations."""

    name = "versa_versos"
    vendor = "versa_networks"
    os_family = "versos"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0

        # Look for distinctive Versa VOS CLI configuration elements
        text_lower = config_text.lower()
        
        # Unique VersaOS fingerprints
        indicators = [
            "versaos",
            "versa",
            "system services access-list",
            "system syslog server",
            "system password-policy",
            "set system services ssh",
            "set system services telnet",
            "set system login idle-timeout",
        ]
        
        score = 0
        for ind in indicators:
            if ind in text_lower:
                score += 1

        if score >= 1:
            return 1.0
        return 0.0

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        self._raw_lines = config_text.splitlines()

        if self.detect(config_text) == 0.0:
            raise ParserError("Not a Versa Networks VersaOS configuration.")

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
                        "VersaOS parser does not evaluate this field."
                    )
                )

        return baseline

    def _evidence(self, line_num: int) -> Tuple[str, int, str]:
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"Line {line_num}: {raw_line}"

    def _parse_config(self, baseline: SecurityBaselineModel) -> None:
        # VersaOS default fallback values
        baseline.telnet_enabled = Observation[bool].absent(
            False, "Telnet daemon is not enabled/supported by default in VersaOS."
        )
        baseline.http_server_enabled = Observation[bool].absent(
            False, "HTTP clear-text web server is disabled by default in VersaOS."
        )
        baseline.https_server_enabled = Observation[bool].absent(
            True, "HTTPS secure management portal is enabled by default in VersaOS."
        )
        baseline.ssh_enabled = Observation[bool].absent(
            True, "SSH remote console access is enabled by default in VersaOS."
        )
        baseline.vty_transport_input = Observation[List[str]].absent(
            ["ssh"], "Administrative console access is restricted to SSH only by default."
        )
        baseline.vty_exec_timeout_seconds = Observation[int].absent(
            600, "CLI session timeout defaults to 10 minutes (600 seconds) in VersaOS."
        )
        baseline.login_banner_present = Observation[bool].absent(
            False, "Pre-login security banner is not configured by default."
        )
        baseline.password_encryption = Observation[bool].absent(
            True, "VersaOS automatically hashes/encrypts all user administrative passwords."
        )
        baseline.password_min_length = Observation[int].absent(
            8, "Minimum password length defaults to 8 characters in VersaOS."
        )
        baseline.aaa_enabled = Observation[bool].absent(
            False, "Centralized AAA authentication is not configured by default."
        )
        baseline.snmp_agent_enabled = Observation[bool].absent(
            False, "SNMP agent is disabled by default in VersaOS."
        )
        baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
            [], "SNMP communities are not configured by default."
        )
        baseline.management_acl_applied = Observation[bool].absent(
            False, "sshd and httpd access list restrictions default to allow-all."
        )
        baseline.enable_secret_set = Observation[bool].absent(
            True, "VersaOS uses user-profile-based administrative privileges (enable secrets are not used)."
        )
        baseline.enable_password_present = Observation[bool].absent(
            False, "VersaOS does not support legacy enable passwords."
        )

        context_stack = []
        dns_servers = []
        ntp_servers = []
        logging_hosts = []
        snmp_communities = []

        ssh_disabled = False
        ssh_line = 1
        telnet_enabled_flag = False
        telnet_line = 1

        for idx, line in enumerate(self._raw_lines):
            line_num = idx + 1
            line_strip = line.strip()

            if not line_strip or line_strip.startswith("#") or line_strip.startswith("/*") or line_strip.startswith("*") or line_strip.startswith("!"):
                continue

            # Context tracking using open/close curly braces (Junos-like)
            if line_strip.endswith("{"):
                block_head = line_strip[:-1].strip()
                context_stack.append((block_head, line_num))
                continue
            elif line_strip == "}":
                if context_stack:
                    context_stack.pop()
                continue

            active_contexts = [c[0] for c in context_stack]

            # Hostname / System Name
            if (active_contexts == ["system"] and line_strip.startswith("host-name ")) or line_strip.startswith("set system host-name "):
                val = line_strip.replace("set system host-name ", "").replace("host-name ", "").strip().strip('";')
                raw, _, note = self._evidence(line_num)
                baseline.hostname = Observation[str].found(val, raw, line_num, note=note)

            # SSH status
            elif (active_contexts == ["system", "services", "ssh"] and line_strip == "disable;") or line_strip.startswith("set system services ssh disable"):
                ssh_disabled = True
                ssh_line = line_num

            # Telnet status
            elif (active_contexts == ["system", "services", "telnet"] and line_strip == "enable;") or line_strip.startswith("set system services telnet enable"):
                telnet_enabled_flag = True
                telnet_line = line_num

            # Session Timeout
            elif (active_contexts == ["system", "login"] and line_strip.startswith("idle-timeout ")) or line_strip.startswith("set system login idle-timeout "):
                val = line_strip.replace("set system login idle-timeout ", "").replace("idle-timeout ", "").strip().strip('";')
                try:
                    minutes = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.vty_exec_timeout_seconds = Observation[int].found(minutes * 60, raw, line_num, note=note)
                except ValueError:
                    pass

            # Login Banner / Announcement
            elif (active_contexts == ["system", "login"] and line_strip.startswith("announcement ")) or line_strip.startswith("set system login announcement "):
                raw, _, note = self._evidence(line_num)
                baseline.login_banner_present = Observation[bool].found(True, raw, line_num, note=note)
            elif (active_contexts == ["system", "login"] and line_strip.startswith("message ")) or line_strip.startswith("set system login message "):
                raw, _, note = self._evidence(line_num)
                baseline.login_banner_present = Observation[bool].found(True, raw, line_num, note=note)

            # AAA authentication-order
            elif (active_contexts == ["system"] and line_strip.startswith("authentication-order ")) or line_strip.startswith("set system authentication-order "):
                methods = line_strip.replace("set system authentication-order ", "").replace("authentication-order ", "")
                is_aaa = "tacplus" in methods or "radius" in methods or "ldap" in methods
                raw, _, note = self._evidence(line_num)
                baseline.aaa_enabled = Observation[bool].found(is_aaa, raw, line_num, note=note)

            # Password min length
            elif (active_contexts == ["system", "password-policy"] and line_strip.startswith("minimum-length ")) or line_strip.startswith("set system password-policy minimum-length "):
                val = line_strip.replace("set system password-policy minimum-length ", "").replace("minimum-length ", "").strip().strip('";')
                try:
                    num = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.password_min_length = Observation[int].found(num, raw, line_num, note=note)
                except ValueError:
                    pass

            # Logging syslog destination host
            elif (active_contexts == ["system", "syslog"] and line_strip.startswith("server ")) or line_strip.startswith("set system syslog server "):
                # E.g. set system syslog server 192.168.1.100 ...
                parts = line_strip.split()
                # Find the token after "server"
                try:
                    idx_srv = parts.index("server")
                    val = parts[idx_srv + 1].strip().strip('";')
                    logging_hosts.append((val, line_num))
                except (ValueError, IndexError):
                    pass

            # NTP Server
            elif (active_contexts == ["system", "ntp"] and line_strip.startswith("server ")) or line_strip.startswith("set system ntp server "):
                parts = line_strip.split()
                try:
                    idx_srv = parts.index("server")
                    val = parts[idx_srv + 1].strip().strip('";')
                    ntp_servers.append((val, line_num))
                except (ValueError, IndexError):
                    pass

            # DNS Server (name-server)
            elif (active_contexts == ["system"] and line_strip.startswith("name-server ")) or line_strip.startswith("set system name-server "):
                # E.g. set system name-server 8.8.8.8
                parts = line_strip.split()
                try:
                    idx_srv = parts.index("name-server")
                    val = parts[idx_srv + 1].strip().strip('";')
                    dns_servers.append((val, line_num))
                except (ValueError, IndexError):
                    pass

            # SNMP Community mapping
            elif (active_contexts == ["system", "snmp"] and line_strip.startswith("community ")) or line_strip.startswith("set system snmp community "):
                # E.g. set system snmp community public authorization read-only
                parts = line_strip.split()
                try:
                    idx_comm = parts.index("community")
                    comm_name = parts[idx_comm + 1].strip().strip('";')
                    priv = "ro"
                    if "read-write" in line_strip:
                        priv = "rw"
                    snmp_communities.append({
                        "name": comm_name,
                        "access": priv,
                        "line": line_num,
                    })
                except (ValueError, IndexError):
                    pass

            # Management ACL (system services access-list ssh/http allow)
            elif "access-list" in line_strip or (active_contexts and "access-list" in active_contexts[-1]):
                if "allow" in line_strip:
                    raw, _, note = self._evidence(line_num)
                    baseline.management_acl_applied = Observation[bool].found(True, raw, line_num, note=note)

        # ----------------------------------------------------------------------
        # Post-processing evaluations based on collected context states
        # ----------------------------------------------------------------------

        # SSH & Transport Input
        if ssh_disabled:
            raw, _, note = self._evidence(ssh_line)
            baseline.ssh_enabled = Observation[bool].found(False, raw, ssh_line, note=note)
            transports = []
            if telnet_enabled_flag:
                transports.append("telnet")
            baseline.vty_transport_input = Observation[List[str]].found(transports, raw, ssh_line, note=note)
        else:
            transports = ["ssh"]
            if telnet_enabled_flag:
                transports.append("telnet")
            raw, _, note = self._evidence(ssh_line)
            baseline.vty_transport_input = Observation[List[str]].found(transports, raw, ssh_line, note=note)

        # Telnet
        if telnet_enabled_flag:
            raw, _, note = self._evidence(telnet_line)
            baseline.telnet_enabled = Observation[bool].found(True, raw, telnet_line, note=note)

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
