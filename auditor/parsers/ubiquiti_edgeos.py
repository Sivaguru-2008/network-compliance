"""Deterministic Ubiquiti Networks EdgeOS configuration parser.

This parser processes Ubiquiti EdgeOS configuration files (both flat set-commands
and Vyatta-style hierarchical curly-brace formats), normalizes settings
into the SecurityBaselineModel, and preserves configuration lines and line numbers.
"""

import hashlib
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class UbiquitiEdgeOSParser(VendorParser):
    """Configuration parser for Ubiquiti Networks EdgeOS configurations."""

    name = "ubiquiti_edgeos"
    vendor = "ubiquiti"
    os_family = "edgeos"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0

        text_lower = config_text.lower()

        _edgeos_markers = (
            "service gui",
            "set service gui",
            "gui {",
            "ubiquiti",
            "ubnt",
            "edgeos",
            "edgerouter",
            "delete service",
        )
        has_edgeos = any(marker in text_lower for marker in _edgeos_markers)

        if has_edgeos:
            return 1.0

        _junos_only_markers = (
            "root-authentication",
            "set routing-options",
            "set protocols ",
            "set policy-options",
            "set firewall family",
        )
        if any(marker in text_lower for marker in _junos_only_markers):
            return 0.0

        if "set system host-name" in text_lower or "set interfaces " in text_lower:
            return 0.0

        return 0.0

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        self._raw_lines = config_text.splitlines()

        if self.detect(config_text) == 0.0:
            raise ParserError("Not a Ubiquiti Networks EdgeOS configuration.")

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
                        "EdgeOS parser does not evaluate this field."
                    )
                )

        return baseline

    def _evidence(self, line_num: int) -> Tuple[str, int, str]:
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"Line {line_num}: {raw_line}"

    def _parse_config(self, baseline: SecurityBaselineModel) -> None:
        # EdgeOS default values
        baseline.telnet_enabled = Observation[bool].absent(
            False, "Telnet daemon is disabled by default on Ubiquiti EdgeOS."
        )
        baseline.http_server_enabled = Observation[bool].absent(
            False, "HTTP clear-text web server is disabled by default on Ubiquiti EdgeOS."
        )
        baseline.https_server_enabled = Observation[bool].absent(
            False, "HTTPS secure management portal is not configured by default."
        )
        baseline.ssh_enabled = Observation[bool].absent(
            False, "SSH daemon is disabled by default on Ubiquiti EdgeOS."
        )
        baseline.vty_transport_input = Observation[List[str]].absent(
            [], "No remote access console transport is enabled by default."
        )
        baseline.vty_exec_timeout_seconds = Observation[int].unknown(
            "CLI session inactivity timeout is not configured or hardcoded in EdgeOS."
        )
        baseline.login_banner_present = Observation[bool].absent(
            False, "Pre-login security banner is not configured by default."
        )
        baseline.password_encryption = Observation[bool].absent(
            True, "EdgeOS automatically hashes/encrypts administrative passwords at rest."
        )
        baseline.password_min_length = Observation[int].unknown(
            "Password complexity policy length requirements are not configured or supported in EdgeOS."
        )
        baseline.aaa_enabled = Observation[bool].absent(
            False, "Centralized AAA authentication is not configured by default."
        )
        baseline.snmp_agent_enabled = Observation[bool].absent(
            False, "SNMP agent is disabled by default on Ubiquiti EdgeOS."
        )
        baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
            [], "SNMP communities are not configured by default."
        )
        baseline.management_acl_applied = Observation[bool].absent(
            False, "Management service access restrictions (listen-address) are not applied by default."
        )
        baseline.enable_secret_set = Observation[bool].absent(
            True, "EdgeOS uses role-based administrative accounts directly (enable secrets are not used)."
        )
        baseline.enable_password_present = Observation[bool].absent(
            False, "EdgeOS does not support legacy privilege passwords."
        )

        dns_servers = []
        ntp_servers = []
        logging_hosts = []
        snmp_communities = []

        ssh_configured = False
        ssh_line = 1
        ssh_disabled = False
        telnet_configured = False
        telnet_line = 1
        telnet_disabled = False
        gui_configured = False
        gui_line = 1
        gui_http_port_set = False

        ssh_listen_address = False
        gui_listen_address = False

        context_stack = []

        for idx, line in enumerate(self._raw_lines):
            line_num = idx + 1
            line_strip = line.strip()

            # Skip comments
            if not line_strip or line_strip.startswith("#") or line_strip.startswith("/*") or line_strip.startswith("*") or line_strip.startswith("//"):
                continue

            # Context tracking using open/close curly braces (Junos/Vyatta style)
            if line_strip.endswith("{"):
                block_head = line_strip[:-1].strip()
                context_stack.append((block_head, line_num))
                continue
            elif line_strip == "}":
                if context_stack:
                    context_stack.pop()
                continue

            active_contexts = [c[0] for c in context_stack]

            # Hostname
            if (active_contexts == ["system"] and line_strip.startswith("host-name ")) or line_strip.startswith("set system host-name "):
                val = line_strip.replace("set system host-name ", "").replace("host-name ", "").strip().strip('";')
                raw, _, note = self._evidence(line_num)
                baseline.hostname = Observation[str].found(val, raw, line_num, note=note)

            # SSH Daemon status
            elif active_contexts == ["service", "ssh"] or line_strip == "set service ssh" or line_strip.startswith("set service ssh "):
                ssh_configured = True
                ssh_line = line_num
                if "disable" in line_strip:
                    ssh_disabled = True
                if "listen-address" in line_strip:
                    ssh_listen_address = True

            # Telnet Daemon status
            elif active_contexts == ["service", "telnet"] or line_strip == "set service telnet" or line_strip.startswith("set service telnet "):
                telnet_configured = True
                telnet_line = line_num
                if "disable" in line_strip:
                    telnet_disabled = True

            # GUI Web-Server status
            elif active_contexts == ["service", "gui"] or line_strip == "set service gui" or line_strip.startswith("set service gui "):
                gui_configured = True
                gui_line = line_num
                if "http-port" in line_strip:
                    gui_http_port_set = True
                if "listen-address" in line_strip:
                    gui_listen_address = True

            # Login Banner
            elif (active_contexts == ["system", "login", "banner"] and ("pre-login" in line_strip or "post-login" in line_strip)) or "set system login banner" in line_strip:
                raw, _, note = self._evidence(line_num)
                baseline.login_banner_present = Observation[bool].found(True, raw, line_num, note=note)

            # AAA configurations (radius/tacacs)
            elif "authentication" in active_contexts or "set system login" in line_strip:
                if "radius" in line_strip or "tacacs" in line_strip:
                    raw, _, note = self._evidence(line_num)
                    baseline.aaa_enabled = Observation[bool].found(True, raw, line_num, note=note)

            # DNS Server (name-server)
            elif (active_contexts == ["system"] and line_strip.startswith("name-server ")) or line_strip.startswith("set system name-server "):
                parts = line_strip.split()
                try:
                    idx_srv = parts.index("name-server")
                    val = parts[idx_srv + 1].strip().strip('";')
                    dns_servers.append((val, line_num))
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

            # Syslog Server host
            elif (active_contexts == ["system", "syslog"] and line_strip.startswith("host ")) or "set system syslog host " in line_strip:
                # E.g. set system syslog host 192.168.1.100 ...
                parts = line_strip.split()
                try:
                    idx_srv = parts.index("host")
                    val = parts[idx_srv + 1].strip().strip('";')
                    logging_hosts.append((val, line_num))
                except (ValueError, IndexError):
                    pass

            # SNMP Community
            elif "snmp" in active_contexts or "set service snmp community " in line_strip:
                # E.g. set service snmp community public authorization ro
                parts = line_strip.split()
                try:
                    idx_comm = parts.index("community")
                    comm_name = parts[idx_comm + 1].strip().strip('";')
                    priv = "ro"
                    if "authorization" in parts:
                        idx_auth = parts.index("authorization")
                        priv = parts[idx_auth + 1].strip().strip('";')
                    snmp_communities.append({
                        "name": comm_name,
                        "access": priv,
                        "line": line_num,
                    })
                except (ValueError, IndexError):
                    pass

        # ----------------------------------------------------------------------
        # Post-processing evaluations based on collected context states
        # ----------------------------------------------------------------------

        # SSH
        if ssh_configured and not ssh_disabled:
            raw, _, note = self._evidence(ssh_line)
            baseline.ssh_enabled = Observation[bool].found(True, raw, ssh_line, note=note)

        # Telnet
        if telnet_configured and not telnet_disabled:
            raw, _, note = self._evidence(telnet_line)
            baseline.telnet_enabled = Observation[bool].found(True, raw, telnet_line, note=note)

        # Allowed Transport VTY inputs
        allowed = []
        if ssh_configured and not ssh_disabled:
            allowed.append("ssh")
        if telnet_configured and not telnet_disabled:
            allowed.append("telnet")
        if allowed:
            ref_line = ssh_line if ssh_configured else telnet_line
            raw, _, note = self._evidence(ref_line)
            baseline.vty_transport_input = Observation[List[str]].found(allowed, raw, ref_line, note=note)

        # GUI Web portal
        if gui_configured:
            raw, _, note = self._evidence(gui_line)
            baseline.https_server_enabled = Observation[bool].found(True, raw, gui_line, note=note)
            if gui_http_port_set:
                baseline.http_server_enabled = Observation[bool].found(True, raw, gui_line, note=note)
            else:
                baseline.http_server_enabled = Observation[bool].found(False, raw, gui_line, note=note)

        # Management ACL (listen-address configured)
        if ssh_listen_address or gui_listen_address:
            ref_line = ssh_line if ssh_listen_address else gui_line
            raw, _, note = self._evidence(ref_line)
            baseline.management_acl_applied = Observation[bool].found(True, raw, ref_line, note=note)

        # DNS Servers
        if dns_servers:
            last_ip, last_line = dns_servers[-1]
            raw, _, note = self._evidence(last_line)
            baseline.dns_servers = Observation[List[str]].found(
                [d[0] for d in dns_servers], raw, last_line, note=note
            )
        else:
            baseline.dns_servers = Observation[List[str]].unknown("DNS name-servers are not configured.")

        # NTP Servers
        if ntp_servers:
            last_ip, last_line = ntp_servers[-1]
            raw, _, note = self._evidence(last_line)
            baseline.ntp_servers = Observation[List[str]].found(
                [n[0] for n in ntp_servers], raw, last_line, note=note
            )
        else:
            baseline.ntp_servers = Observation[List[str]].unknown("NTP servers are not configured.")

        # Logging / Syslog remote hosts
        if logging_hosts:
            last_ip, last_line = logging_hosts[-1]
            raw, _, note = self._evidence(last_line)
            baseline.logging_enabled = Observation[bool].found(True, raw, last_line, note=note)
            baseline.logging_hosts = Observation[List[str]].found(
                [h[0] for h in logging_hosts], raw, last_line, note=note
            )
        else:
            baseline.logging_enabled = Observation[bool].unknown("Syslog remote host is not configured.")
            baseline.logging_hosts = Observation[List[str]].unknown("Syslog remote host is not configured.")

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
