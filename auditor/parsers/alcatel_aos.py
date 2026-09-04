"""Deterministic Alcatel-Lucent Enterprise AOS configuration parser.

This parser processes Alcatel-Lucent OmniSwitch AOS configuration files (boot.cfg),
normalizes settings into the SecurityBaselineModel, and preserves
configuration lines and line numbers for compliance audit evidence.
"""

import hashlib
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class AlcatelAOSParser(VendorParser):
    """Configuration parser for Alcatel-Lucent Enterprise AOS configurations."""

    name = "alcatel_aos"
    vendor = "alcatel_lucent_enterprise"
    os_family = "aos"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0

        text_lower = config_text.lower()
        keywords = [
            "aaa authentication default local",
            'aaa authentication default "local"',
            "ip service ssh",
            "ip service secure-http",
            "swlog output socket",
            "session timeout cli",
            "session banner cli",
            "user password-size min",
        ]
        for kw in keywords:
            if kw in text_lower:
                return 1.0
        import re
        score = 0.0
        if re.search(r"(?im)^!\s*AOS\s+\d+\.\d+", config_text):
            score += 0.50
        if re.search(r"(?im)^\s*system\s+name\s+\S+", config_text):
            score += 0.20
        if "no ssh enable" in text_lower or "ssh enable" in text_lower:
            score += 0.15
        return min(1.0, score)

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        self._raw_lines = config_text.splitlines()

        if self.detect(config_text) == 0.0:
            raise ParserError("Not an Alcatel-Lucent Enterprise AOS configuration.")

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
                        "Alcatel-Lucent Enterprise AOS parser does not evaluate this field."
                    )
                )

        return baseline

    def _evidence(self, line_num: int) -> Tuple[str, int, str]:
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"Line {line_num}: {raw_line}"

    def _parse_config(self, baseline: SecurityBaselineModel) -> None:
        # AOS default fallback values
        baseline.telnet_enabled = Observation[bool].absent(
            False, "Telnet service is disabled by default in newer AOS releases."
        )
        baseline.http_server_enabled = Observation[bool].absent(
            False, "HTTP service is disabled by default in newer AOS releases."
        )
        baseline.https_server_enabled = Observation[bool].absent(
            False, "HTTPS service is disabled by default in newer AOS releases."
        )
        baseline.ssh_enabled = Observation[bool].absent(
            False, "SSH service is disabled by default in newer AOS releases."
        )
        baseline.vty_transport_input = Observation[List[str]].unknown(
            "VTY remote access transport state is not configured."
        )
        baseline.vty_exec_timeout_seconds = Observation[int].unknown(
            "Session timeout is not configured."
        )
        baseline.login_banner_present = Observation[bool].absent(
            False, "Login banner is not configured by default."
        )
        baseline.password_encryption = Observation[bool].absent(
            True, "AOS automatically hashes all stored passwords by default."
        )
        baseline.password_min_length = Observation[int].absent(
            8, "Minimum password length defaults to 8 characters in AOS."
        )
        baseline.aaa_enabled = Observation[bool].absent(
            False, "Centralized AAA authentication is not configured by default."
        )
        baseline.snmp_agent_enabled = Observation[bool].absent(
            False, "SNMP agent is disabled by default."
        )
        baseline.snmp_communities = Observation[List[SnmpCommunity]].absent(
            [], "SNMP communities are not configured by default."
        )
        baseline.management_acl_applied = Observation[bool].unknown(
            "Management access QoS policy filters are not configured."
        )
        baseline.enable_secret_set = Observation[bool].absent(
            True, "AOS uses user-profile-based access privilege level security (enable secrets are not used)."
        )
        baseline.enable_password_present = Observation[bool].absent(
            False, "AOS does not support legacy enable passwords."
        )

        ssh_state = None
        ssh_line = 1
        telnet_state = None
        telnet_line = 1
        http_state = None
        http_line = 1
        https_state = None
        https_line = 1

        dns_servers = []
        ntp_servers = []
        logging_hosts = []
        snmp_communities = []
        user_privilege_map = {}
        user_line_map = {}

        for idx, line in enumerate(self._raw_lines):
            line_num = idx + 1
            line_strip = line.strip()

            if not line_strip or line_strip.startswith("!") or line_strip.startswith("#"):
                continue

            # Hostname / System Name
            # AOS syntax: system name <hostname>
            if line_strip.startswith("system name "):
                val = line_strip.split(" ", 2)[2].strip().strip('"')
                raw, _, note = self._evidence(line_num)
                baseline.hostname = Observation[str].found(val, raw, line_num, note=note)

            # HTTP Service
            elif line_strip.startswith("ip service http") or line_strip.startswith("ip service http "):
                http_state = True
                http_line = line_num
            elif line_strip.startswith("no ip service http") or "ip service http disable" in line_strip:
                http_state = False
                http_line = line_num

            # HTTPS Service
            elif line_strip.startswith("ip service secure-http") or line_strip.startswith("ip service secure-http "):
                https_state = True
                https_line = line_num
            elif line_strip.startswith("no ip service secure-http") or "ip service secure-http disable" in line_strip:
                https_state = False
                https_line = line_num

            # Telnet Service
            elif line_strip.startswith("ip service telnet") or line_strip.startswith("ip service telnet "):
                telnet_state = True
                telnet_line = line_num
            elif line_strip.startswith("no ip service telnet") or "ip service telnet disable" in line_strip:
                telnet_state = False
                telnet_line = line_num

            # SSH Service
            elif line_strip.startswith("ip service ssh") or line_strip.startswith("ip service ssh "):
                ssh_state = True
                ssh_line = line_num
            elif line_strip.startswith("no ip service ssh") or "ip service ssh disable" in line_strip:
                ssh_state = False
                ssh_line = line_num

            # Timeout CLI
            elif line_strip.startswith("session timeout cli "):
                val = line_strip.split(" ", 3)[3].strip()
                try:
                    minutes = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.vty_exec_timeout_seconds = Observation[int].found(minutes * 60, raw, line_num, note=note)
                except ValueError:
                    pass

            # Login Banner
            elif line_strip.startswith("session banner cli "):
                raw, _, note = self._evidence(line_num)
                baseline.login_banner_present = Observation[bool].found(True, raw, line_num, note=note)

            # AAA
            elif "aaa radius-server" in line_strip or "aaa tacacs-server" in line_strip:
                raw, _, note = self._evidence(line_num)
                baseline.aaa_enabled = Observation[bool].found(True, raw, line_num, note=note)
            elif line_strip.startswith("aaa authentication "):
                parts = line_strip.split()
                if len(parts) > 3:
                    method = parts[3].strip('"')
                    if method not in ("local", "none"):
                        raw, _, note = self._evidence(line_num)
                        baseline.aaa_enabled = Observation[bool].found(True, raw, line_num, note=note)

            # Password policy
            elif line_strip.startswith("user password-size min "):
                val = line_strip.split(" ", 3)[3].strip()
                try:
                    num = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.password_min_length = Observation[int].found(num, raw, line_num, note=note)
                except ValueError:
                    pass
            elif line_strip.startswith("user password-policy min-uppercase "):
                val = line_strip.split(" ", 3)[3].strip()
                try:
                    num = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.password_min_uppercase = Observation[int].found(num, raw, line_num, note=note)
                except ValueError:
                    pass
            elif line_strip.startswith("user password-policy min-lowercase "):
                val = line_strip.split(" ", 3)[3].strip()
                try:
                    num = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.password_min_lowercase = Observation[int].found(num, raw, line_num, note=note)
                except ValueError:
                    pass
            elif line_strip.startswith("user password-policy min-digit "):
                val = line_strip.split(" ", 3)[3].strip()
                try:
                    num = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.password_min_numeric = Observation[int].found(num, raw, line_num, note=note)
                except ValueError:
                    pass
            elif line_strip.startswith("user password-policy min-nonalpha "):
                val = line_strip.split(" ", 3)[3].strip()
                try:
                    num = int(val)
                    raw, _, note = self._evidence(line_num)
                    baseline.password_min_special = Observation[int].found(num, raw, line_num, note=note)
                except ValueError:
                    pass
            elif line_strip.startswith("user password-expiration "):
                val = line_strip.split(" ", 2)[2].strip()
                raw, _, note = self._evidence(line_num)
                if val == "disable":
                    baseline.password_max_age_days = Observation[int].found(0, raw, line_num, note=note)
                else:
                    try:
                        num = int(val)
                        baseline.password_max_age_days = Observation[int].found(num, raw, line_num, note=note)
                    except ValueError:
                        pass

            # Logging syslog destination host
            elif line_strip.startswith("swlog output socket "):
                val = line_strip.split(" ", 3)[3].strip().split()[0]
                logging_hosts.append((val, line_num))

            # NTP Server
            elif line_strip.startswith("ntp server "):
                val = line_strip.split(" ", 2)[2].strip().split()[0]
                ntp_servers.append((val, line_num))

            # DNS Server (ip name-server)
            elif line_strip.startswith("ip name-server "):
                servers = line_strip.split(" ")[2:]
                for s in servers:
                    s_clean = s.strip().strip('"')
                    if s_clean:
                        dns_servers.append((s_clean, line_num))

            # User level map (for SNMP)
            elif line_strip.startswith("user "):
                parts = line_strip.split()
                if len(parts) > 1:
                    username = parts[1].strip('"')
                    priv = "read-only"
                    if "read-write" in line_strip:
                        priv = "read-write"
                    user_privilege_map[username] = priv
                    user_line_map[username] = line_num

            # SNMP Community mapping
            elif line_strip.startswith("snmp community map "):
                # E.g. snmp community map "public" user "snmp_monitor" on
                parts = line_strip.split()
                if len(parts) > 5:
                    comm_name = parts[3].strip('"')
                    user_ref = parts[5].strip('"')
                    snmp_communities.append({
                        "name": comm_name,
                        "user": user_ref,
                        "line": line_num,
                    })

            # Management ACL (QoS Policy rule targeting Switch)
            elif line_strip.startswith("policy rule ") and "destination network group Switch" in line_strip:
                raw, _, note = self._evidence(line_num)
                baseline.management_acl_applied = Observation[bool].found(True, raw, line_num, note=note)

        # ----------------------------------------------------------------------
        # Post-processing evaluations based on collected context states
        # ----------------------------------------------------------------------

        # HTTP Server
        if http_state is not None:
            raw, _, note = self._evidence(http_line)
            baseline.http_server_enabled = Observation[bool].found(http_state, raw, http_line, note=note)

        # HTTPS Server
        if https_state is not None:
            raw, _, note = self._evidence(https_line)
            baseline.https_server_enabled = Observation[bool].found(https_state, raw, https_line, note=note)

        # Telnet
        if telnet_state is not None:
            raw, _, note = self._evidence(telnet_line)
            baseline.telnet_enabled = Observation[bool].found(telnet_state, raw, telnet_line, note=note)

        # SSH & VTY Transport Input
        if ssh_state is not None:
            raw, _, note = self._evidence(ssh_line)
            baseline.ssh_enabled = Observation[bool].found(ssh_state, raw, ssh_line, note=note)

        # If we have clear SSH and Telnet states, calculate permitted transports
        if ssh_state is not None and telnet_state is not None:
            transports = []
            if ssh_state:
                transports.append("ssh")
            if telnet_state:
                transports.append("telnet")
            evidence_line = ssh_line if ssh_line > telnet_line else telnet_line
            raw, _, note = self._evidence(evidence_line)
            baseline.vty_transport_input = Observation[List[str]].found(transports, raw, evidence_line, note=note)

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
            baseline.logging_enabled = Observation[bool].unknown("Syslog output host is not configured.")
            baseline.logging_hosts = Observation[List[str]].unknown("Syslog output host is not configured.")

        # SNMP Communities mapping
        if snmp_communities:
            communities_list = []
            last_snmp_line = 1
            for c in snmp_communities:
                # Find the mapping user privilege
                priv = user_privilege_map.get(c["user"], "read-only")
                access = "ro" if priv == "read-only" else "rw"
                raw, _, _ = self._evidence(c["line"])
                communities_list.append(
                    SnmpCommunity(
                        name=c["name"],
                        access=access,
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
