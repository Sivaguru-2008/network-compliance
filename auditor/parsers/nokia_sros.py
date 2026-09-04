"""Deterministic Nokia SR OS configuration parser.

This parser processes Nokia SR OS classic CLI configurations (e.g., config.cfg or admin save output),
normalizes settings into the SecurityBaselineModel, and preserves
configuration lines and line numbers for compliance audit evidence.
"""

import hashlib
import re
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class NokiaSROSParser(VendorParser):
    """Configuration parser for Nokia SR OS configurations."""

    name = "nokia_sros"
    vendor = "nokia"
    os_family = "sros"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0

        # Look for TiMOS version header comments, echo messages, or Nokia classic CLI configuration
        text_lower = config_text.lower()
        if (
            "timos" in text_lower
            or 'echo "system configuration"' in text_lower
            or "configure system name" in text_lower
            or "configure system security" in text_lower
            or "nokia" in text_lower
        ):
            return 1.0
        return 0.0

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        self._raw_lines = config_text.splitlines()

        # Simple verification of Nokia SR OS identity
        if self.detect(config_text) == 0.0:
            raise ParserError("Not a Nokia SR OS configuration.")

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
                        "Nokia SR OS parser does not evaluate this field."
                    )
                )

        return baseline

    def _evidence(self, line_num: int) -> Tuple[str, int, str]:
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"Line {line_num}: {raw_line}"

    def _parse_config(self, baseline: SecurityBaselineModel) -> None:
        # Default fallback values for Nokia SR OS
        baseline.telnet_enabled = Observation[bool].absent(
            False, "Telnet server is shutdown/disabled by default in Nokia SR OS."
        )
        baseline.http_server_enabled = Observation[bool].absent(
            False, "HTTP management server is not supported/disabled by default in Nokia SR OS."
        )
        baseline.https_server_enabled = Observation[bool].absent(
            False, "HTTPS management server is not supported/disabled by default in Nokia SR OS."
        )
        baseline.ssh_enabled = Observation[bool].absent(
            True, "SSH server is enabled by default in Nokia SR OS."
        )
        baseline.vty_transport_input = Observation[List[str]].absent(
            ["ssh"], "VTY remote access default transport is SSH only."
        )
        baseline.vty_exec_timeout_seconds = Observation[int].absent(
            1800, "VTY idle timeout defaults to 30 minutes (1800 seconds) in Nokia SR OS."
        )
        baseline.ssh_version = Observation[int].absent(
            2, "SSH protocol version defaults to SSHv2 in Nokia SR OS."
        )
        baseline.login_banner_present = Observation[bool].absent(
            True, "Nokia SR OS login banner is enabled by default."
        )
        baseline.password_encryption = Observation[bool].absent(
            True, "Nokia SR OS automatically hashes user administrative passwords."
        )
        baseline.password_min_length = Observation[int].absent(
            8, "Minimum password length defaults to 8 characters in Nokia SR OS."
        )
        baseline.aaa_enabled = Observation[bool].absent(
            False, "Centralized AAA authentication is not configured by default."
        )
        baseline.snmp_agent_enabled = Observation[bool].absent(
            False, "SNMP agent is disabled by default in Nokia SR OS."
        )
        baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
            [], "SNMP communities are not configured by default."
        )
        baseline.management_acl_applied = Observation[bool].absent(
            False, "Management access filters are not configured by default."
        )
        baseline.enable_secret_set = Observation[bool].absent(
            True, "Nokia SR OS uses role-based user management (enable secrets are not used)."
        )
        baseline.enable_password_present = Observation[bool].absent(
            False, "Nokia SR OS does not support legacy enable passwords."
        )

        # Context tracker
        context_stack = []
        
        # Local lists to collect parsed servers / hosts
        dns_servers = []
        ntp_servers = []
        logging_hosts = []
        snmp_communities_list = []

        # Temp trackers for multiline block contexts
        telnet_shutdown = True
        telnet_line_num = 1
        ssh_shutdown = False
        ssh_line_num = 1
        ssh_version_val = 2
        ssh_version_line = 1
        no_login_banner = False
        no_login_banner_line = 1
        pre_login_msg = False
        pre_login_line = 1
        motd_msg = False
        motd_line = 1

        syslog_hosts_map = {}
        syslog_shutdown_map = {}

        for idx, line in enumerate(self._raw_lines):
            line_num = idx + 1
            line_strip = line.strip()

            if not line_strip or line_strip.startswith("#") or line_strip.startswith("echo "):
                continue

            # Update context stack based on indentation or exit keywords
            # For classic CLI, context exits with 'exit' statement
            if line_strip == "exit":
                if context_stack:
                    context_stack.pop()
                continue

            # Check if this line starts a block context
            # We look for lines containing block entry names
            block_entry = None
            if line_strip in ("system", "security", "ssh", "telnet-server", "telnet6-server", "snmp", "log", "time", "ntp", "login-control"):
                block_entry = line_strip
            elif line_strip.startswith("syslog "):
                block_entry = "syslog"
                parts = line_strip.split()
                if len(parts) > 1:
                    syslog_id = parts[1]
                    syslog_shutdown_map[syslog_id] = False  # defaults to active
            elif line_strip.startswith("community "):
                block_entry = "community"
            elif line_strip.startswith("mgmt-access-filter"):
                block_entry = "mgmt-access-filter"
            elif line_strip.startswith("password"):
                block_entry = "password"

            if block_entry:
                context_stack.append((block_entry, line_num))
                continue

            # Get current active contexts list
            active_contexts = [c[0] for c in context_stack]

            # System Name / Hostname
            if active_contexts == ["system"] and line_strip.startswith("name "):
                val = line_strip.split(" ", 1)[1].strip().strip('"')
                raw, _, note = self._evidence(line_num)
                baseline.hostname = Observation[str].found(val, raw, line_num, note=note)

            # Telnet
            elif active_contexts == ["system", "security", "telnet-server"] or active_contexts == ["system", "security", "telnet6-server"]:
                telnet_line_num = line_num
                if line_strip == "no shutdown":
                    telnet_shutdown = False
                elif line_strip == "shutdown":
                    telnet_shutdown = True

            # SSH Shutdown
            elif active_contexts == ["system", "security", "ssh"] and line_strip == "server-shutdown":
                ssh_shutdown = True
                ssh_line_num = line_num
            elif active_contexts == ["system", "security", "ssh"] and line_strip == "no server-shutdown":
                ssh_shutdown = False
                ssh_line_num = line_num

            # SSH Version
            elif active_contexts == ["system", "security", "ssh"] and line_strip.startswith("version "):
                ver_val = line_strip.split(" ", 1)[1].strip()
                ssh_version_line = line_num
                if ver_val == "1":
                    ssh_version_val = 1
                elif "1-2" in ver_val:
                    ssh_version_val = 1
                else:
                    ssh_version_val = 2

            # Session timeout
            elif active_contexts == ["system", "login-control"] and line_strip.startswith("idle-timeout "):
                val = line_strip.split(" ", 1)[1].strip()
                raw, _, note = self._evidence(line_num)
                if val == "disable":
                    baseline.vty_exec_timeout_seconds = Observation[int].found(0, raw, line_num, note=note)
                else:
                    try:
                        minutes = int(val)
                        baseline.vty_exec_timeout_seconds = Observation[int].found(minutes * 60, raw, line_num, note=note)
                    except ValueError:
                        pass

            # Pre-login message & MOTD
            elif active_contexts == ["system", "login-control"] and line_strip.startswith("pre-login-message "):
                pre_login_msg = True
                pre_login_line = line_num
            elif active_contexts == ["system", "login-control"] and line_strip.startswith("motd "):
                motd_msg = True
                motd_line = line_num
            elif active_contexts == ["system", "login-control"] and line_strip == "no login-banner":
                no_login_banner = True
                no_login_banner_line = line_num

            # AAA authentication-order
            elif active_contexts == ["system", "security"] and line_strip.startswith("authentication-order "):
                methods = line_strip.split(" ", 1)[1].strip()
                raw, _, note = self._evidence(line_num)
                is_aaa = "tacplus" in methods or "radius" in methods
                baseline.aaa_enabled = Observation[bool].found(is_aaa, raw, line_num, note=note)

            # Password min length
            elif active_contexts == ["system", "security", "password"] and line_strip.startswith("minimum-length "):
                val = line_strip.split(" ", 1)[1].strip()
                try:
                    num = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.password_min_length = Observation[int].found(num, raw, line_num, note=note)
                except ValueError:
                    pass

            # SNMP Community
            elif "community" in active_contexts and active_contexts[:3] == ["system", "security", "snmp"]:
                # The community block header contains the name
                # E.g. community "public" hash2
                comm_name = ""
                # Find the line that entered the community context
                for ctx in context_stack:
                    if ctx[0] == "community":
                        ctx_line = self._raw_lines[ctx[1] - 1].strip()
                        parts = ctx_line.split()
                        if len(parts) > 1:
                            comm_name = parts[1].strip('"')
                        break
                
                if comm_name:
                    perm = "ro"
                    if line_strip.startswith("access-permissions "):
                        val = line_strip.split(" ", 1)[1].strip()
                        if "rwa" in val:
                            perm = "rw"
                    
                    # Update or add community
                    found = False
                    for c in snmp_communities_list:
                        if c["name"] == comm_name:
                            if line_strip.startswith("access-permissions "):
                                c["access"] = perm
                            found = True
                            break
                    if not found:
                        snmp_communities_list.append({
                            "name": comm_name,
                            "access": perm,
                            "line": line_num,
                        })

            # Logging syslog destination host
            elif "syslog" in active_contexts and active_contexts[0] == "log":
                syslog_id = None
                for ctx in context_stack:
                    if ctx[0] == "syslog":
                        ctx_line = self._raw_lines[ctx[1] - 1].strip()
                        parts = ctx_line.split()
                        if len(parts) > 1:
                            syslog_id = parts[1]
                        break
                if syslog_id:
                    if line_strip.startswith("address "):
                        val = line_strip.split(" ", 1)[1].strip().strip('"')
                        syslog_hosts_map[syslog_id] = (val, line_num)
                    elif line_strip == "shutdown":
                        syslog_shutdown_map[syslog_id] = True
                    elif line_strip == "no shutdown":
                        syslog_shutdown_map[syslog_id] = False

            # NTP Server
            elif active_contexts == ["system", "time", "ntp"] and line_strip.startswith("server "):
                val = line_strip.split(" ", 1)[1].strip().split()[0].strip('"')
                ntp_servers.append((val, line_num))
            elif active_contexts == ["system", "time", "ntp"] and line_strip.startswith("peer "):
                val = line_strip.split(" ", 1)[1].strip().split()[0].strip('"')
                ntp_servers.append((val, line_num))

            # DNS Server (BOF or System context)
            elif line_strip.startswith("primary-dns ") or line_strip.startswith("secondary-dns ") or line_strip.startswith("tertiary-dns "):
                val = line_strip.split(" ", 1)[1].strip().split()[0].strip('"')
                dns_servers.append((val, line_num))
            elif active_contexts == ["system", "dns"] and line_strip.startswith("server-list "):
                val = line_strip.split(" ", 1)[1].strip().split()[0].strip('"')
                dns_servers.append((val, line_num))
            elif active_contexts == ["system", "dns"] and line_strip.startswith("server "):
                val = line_strip.split(" ", 1)[1].strip().split()[0].strip('"')
                dns_servers.append((val, line_num))

            # Management ACL (mgmt-access-filter)
            elif "mgmt-access-filter" in active_contexts:
                raw, _, note = self._evidence(line_num)
                baseline.management_acl_applied = Observation[bool].found(True, raw, line_num, note=note)

        # ----------------------------------------------------------------------
        # Post-processing evaluations based on collected context states
        # ----------------------------------------------------------------------

        # Telnet Evaluation
        if not telnet_shutdown:
            raw, _, note = self._evidence(telnet_line_num)
            baseline.telnet_enabled = Observation[bool].found(True, raw, telnet_line_num, note=note)

        # SSH & Transport Input Evaluation
        transports = []
        if not ssh_shutdown:
            transports.append("ssh")
        if not telnet_shutdown:
            transports.append("telnet")

        evidence_line = telnet_line_num if not telnet_shutdown else ssh_line_num
        raw, _, note = self._evidence(evidence_line)
        baseline.vty_transport_input = Observation[List[str]].found(transports, raw, evidence_line, note=note)

        if ssh_shutdown:
            raw, _, note = self._evidence(ssh_line_num)
            baseline.ssh_enabled = Observation[bool].found(False, raw, ssh_line_num, note=note)
        else:
            raw, _, note = self._evidence(ssh_line_num)
            baseline.ssh_enabled = Observation[bool].found(True, raw, ssh_line_num, note=note)

        # SSH Version
        if ssh_version_line > 1:
            raw, _, note = self._evidence(ssh_version_line)
            baseline.ssh_version = Observation[int].found(ssh_version_val, raw, ssh_version_line, note=note)

        # Login Banner
        if pre_login_msg:
            raw, _, note = self._evidence(pre_login_line)
            baseline.login_banner_present = Observation[bool].found(True, raw, pre_login_line, note=note)
        elif motd_msg:
            raw, _, note = self._evidence(motd_line)
            baseline.login_banner_present = Observation[bool].found(True, raw, motd_line, note=note)
        elif no_login_banner:
            raw, _, note = self._evidence(no_login_banner_line)
            baseline.login_banner_present = Observation[bool].found(False, raw, no_login_banner_line, note=note)

        # DNS Servers
        if dns_servers:
            # Take last server for baseline note evidence
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

        # Remote Syslog Logging
        active_syslogs = []
        last_log_line = 1
        for sid, (addr, ln) in syslog_hosts_map.items():
            if not syslog_shutdown_map.get(sid, False):
                active_syslogs.append(addr)
                last_log_line = ln
        
        if active_syslogs:
            raw, _, note = self._evidence(last_log_line)
            baseline.logging_enabled = Observation[bool].found(True, raw, last_log_line, note=note)
            baseline.logging_hosts = Observation[List[str]].found(active_syslogs, raw, last_log_line, note=note)
        else:
            baseline.logging_enabled = Observation[bool].unknown("Remote syslog is not configured or shutdown.")
            baseline.logging_hosts = Observation[List[str]].unknown("Remote syslog is not configured or shutdown.")

        # SNMP Communities
        if snmp_communities_list:
            communities_objs = []
            last_snmp_line = 1
            for c in snmp_communities_list:
                raw, _, _ = self._evidence(c["line"])
                communities_objs.append(
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
                communities_objs, raw, last_snmp_line, note=note
            )
