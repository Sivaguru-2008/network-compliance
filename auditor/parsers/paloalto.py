"""Deterministic Palo Alto Networks / PAN-OS XML parser.

This parser processes standard PAN-OS XML configuration files, normalizes key settings
into the vendor-neutral SecurityBaselineModel, and preserves exact XML paths and line numbers
for compliance audit provenance.
"""

import xml.parsers.expat
import hashlib
from typing import Dict, List, Optional, Tuple

from ..models.baseline import ParserProvenance, SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


class XMLNode:
    """Represents a simplified XML node parsed from configuration."""
    def __init__(self, tag: str, line_number: int):
        self.tag: str = tag
        self.line_number: int = line_number
        self.text: str = ""
        self.children: List['XMLNode'] = []


class XMLTreeBuilder:
    """Custom Expat-based XML parser to preserve exact line numbers."""
    def __init__(self):
        self.parser = xml.parsers.expat.ParserCreate()
        self.parser.StartElementHandler = self.start_element
        self.parser.EndElementHandler = self.end_element
        self.parser.CharacterDataHandler = self.char_data

        self.root: Optional[XMLNode] = None
        self.stack: List[XMLNode] = []

    def start_element(self, name: str, attrs: dict):
        line = self.parser.CurrentLineNumber
        node = XMLNode(tag=name, line_number=line)
        if not self.root:
            self.root = node
        if self.stack:
            self.stack[-1].children.append(node)
        self.stack.append(node)

    def end_element(self, name: str):
        if self.stack:
            self.stack.pop()

    def char_data(self, data: str):
        if self.stack:
            self.stack[-1].text += data

    def parse(self, text: str) -> XMLNode:
        try:
            self.parser.Parse(text, 1)
        except Exception as e:
            raise ParserError(f"Malformed XML configuration: {e}") from e
        if not self.root:
            raise ParserError("Empty or invalid XML configuration.")
        return self.root


def find_nodes_by_path(node: XMLNode, path_parts: List[str]) -> List[XMLNode]:
    """Recursively find all nodes matching the specified path parts."""
    if not path_parts:
        return [node]
    if node.tag == path_parts[0]:
        return find_nodes_by_path(node, path_parts[1:])
    current_tag = path_parts[0]
    matches = []
    for child in node.children:
        if child.tag == current_tag:
            matches.extend(find_nodes_by_path(child, path_parts[1:]))
    return matches


def find_child_by_path(node: XMLNode, path_parts: List[str]) -> List[XMLNode]:
    """Find child nodes matching the path parts relative to node."""
    if not path_parts:
        return [node]
    current_tag = path_parts[0]
    matches = []
    for child in node.children:
        if child.tag == current_tag:
            matches.extend(find_child_by_path(child, path_parts[1:]))
    return matches


def find_nodes_by_tag(node: XMLNode, tag: str, results: Optional[List[XMLNode]] = None) -> List[XMLNode]:
    """Find all descendant nodes matching the specified tag."""
    if results is None:
        results = []
    if node.tag == tag:
        results.append(node)
    for child in node.children:
        find_nodes_by_tag(child, tag, results)
    return results


@registry.register
class PaloAltoParser(VendorParser):
    """Grammar-based XML parser for Palo Alto Networks PAN-OS configurations."""

    name = "paloalto_panos"
    vendor = "paloalto"
    os_family = "panos"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        # Palo Alto configs are XML files containing <configuration> and <deviceconfig> or <mgt-config>
        score = 0.0
        if "<configuration" in config_text:
            score += 0.5
        if "<deviceconfig" in config_text:
            score += 0.2
        if "<mgt-config" in config_text:
            score += 0.2
        if "<shared" in config_text:
            score += 0.1
        return min(1.0, score)

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        self._raw_lines = config_text.splitlines()
        builder = XMLTreeBuilder()
        root = builder.parse(config_text)

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

        self._normalize_syslog(root, baseline)
        self._normalize_login_banner(root, baseline)
        self._normalize_log_high_dp(root, baseline)
        self._normalize_services(root, baseline)
        self._normalize_password_complexity(root, baseline)
        self._normalize_idle_timeout(root, baseline)
        self._normalize_lockout_settings(root, baseline)
        self._normalize_snmp(root, baseline)
        self._normalize_update_server(root, baseline)
        self._normalize_ntp(root, baseline)
        self._normalize_hostname(root, baseline)
        self._normalize_password_expiration(root, baseline)


        # Ensure all baseline fields are answered
        for field in baseline.observable_fields():
            observation = getattr(baseline, field)
            if observation.note == "Parser did not evaluate this field.":
                setattr(
                    baseline,
                    field,
                    type(observation).unknown(
                        "Palo Alto parser does not evaluate this field."
                    )
                )

        return baseline

    def _normalize_hostname(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        deviceconfig_nodes = find_nodes_by_tag(root, "deviceconfig")
        nodes = []
        is_legacy = False
        if deviceconfig_nodes:
            nodes = find_child_by_path(deviceconfig_nodes[0], ["system", "hostname"])
        if not nodes:
            nodes = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "hostname"])
            is_legacy = True
            
        if nodes and nodes[0].text.strip():
            node = nodes[0]
            path_str = "/configuration/deviceconfig/system/hostname" if (is_legacy or root.tag == "configuration") else "/config/devices/entry/deviceconfig/system/hostname"
            raw, line, path = self._evidence(node, path_str)
            baseline.hostname = Observation[str].found(node.text.strip(), raw, line, note=path)
        else:
            baseline.hostname = Observation[str].absent("localhost.localdomain", "Hostname is not configured.")

    def _evidence(self, node: XMLNode, path: str) -> Tuple[str, int, str]:
        line_num = node.line_number
        raw_line = self._raw_lines[line_num - 1].strip()
        return raw_line, line_num, f"Path: {path}"

    def _normalize_syslog(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        # Search recursively for <syslog> nodes under <log-settings>
        log_settings_nodes = find_nodes_by_tag(root, "log-settings")
        syslog_nodes = []
        for ls in log_settings_nodes:
            syslog_nodes.extend(find_nodes_by_tag(ls, "syslog"))
        
        hosts = []
        evidence_node = None

        for s_node in syslog_nodes:
            # Under syslog we expect <entry name="..."> <server>ip</server> </entry>
            servers = find_nodes_by_tag(s_node, "server")
            for s in servers:
                val = s.text.strip()
                if val:
                    hosts.append(val)
                    if not evidence_node:
                        evidence_node = s

        if hosts:
            raw, line, path = self._evidence(evidence_node, "shared/log-settings/syslog/entry/server")
            baseline.logging_enabled = Observation[bool].found(True, raw, line, note=path)
            baseline.logging_hosts = Observation[List[str]].found(hosts, raw, line, note=path)
        else:
            baseline.logging_enabled = Observation[bool].absent(False, "No syslog servers are configured in log-settings.")
            baseline.logging_hosts = Observation[List[str]].absent([], "No syslog hosts are configured.")

    def _normalize_login_banner(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        deviceconfig_nodes = find_nodes_by_tag(root, "deviceconfig")
        nodes = []
        is_legacy = False
        if deviceconfig_nodes:
            nodes = find_child_by_path(deviceconfig_nodes[0], ["system", "login-banner"])
        if not nodes:
            nodes = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "login-banner"])
            is_legacy = True
            
        if nodes and nodes[0].text.strip():
            node = nodes[0]
            path_str = "/configuration/deviceconfig/system/login-banner" if (is_legacy or root.tag == "configuration") else "/config/devices/entry/deviceconfig/system/login-banner"
            raw, line, path = self._evidence(node, path_str)
            baseline.login_banner_present = Observation[bool].found(True, raw, line, note=path)
            baseline.pre_login_banner_present = Observation[bool].found(True, raw, line, note=path)
            baseline.post_login_banner_present = Observation[bool].found(True, raw, line, note=path)
        else:
            note = "No logon banner is configured under system settings."
            baseline.login_banner_present = Observation[bool].absent(False, note)
            baseline.pre_login_banner_present = Observation[bool].absent(False, note)
            baseline.post_login_banner_present = Observation[bool].absent(False, note)

    def _normalize_log_high_dp(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        deviceconfig_nodes = find_nodes_by_tag(root, "deviceconfig")
        nodes = []
        evidence_path = ""
        
        if deviceconfig_nodes:
            # Real PAN-OS path
            nodes = find_child_by_path(deviceconfig_nodes[0], ["setting", "management", "enable-log-high-dp-load"])
            evidence_path = "deviceconfig/setting/management/enable-log-high-dp-load"
            
            # Legacy/Test path under system
            if not nodes:
                nodes = find_child_by_path(deviceconfig_nodes[0], ["system", "log-high-dp-load"])
                evidence_path = "deviceconfig/system/log-high-dp-load"
                
        if not nodes:
            nodes = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "log-high-dp-load"])
            evidence_path = "configuration/deviceconfig/system/log-high-dp-load"
            
        if nodes:
            node = nodes[0]
            enabled = node.text.strip().lower() == "yes"
            raw, line, path = self._evidence(node, evidence_path)
            baseline.log_single_cpu_high_enabled = Observation[bool].found(enabled, raw, line, note=path)
        else:
            baseline.log_single_cpu_high_enabled = Observation[bool].absent(
                False, "enable-log-high-dp-load is not configured (defaults to False)."
            )

    def _normalize_services(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        deviceconfig_nodes = find_nodes_by_tag(root, "deviceconfig")
        
        disable_telnet_nodes = []
        disable_http_nodes = []
        if deviceconfig_nodes:
            disable_telnet_nodes = find_child_by_path(deviceconfig_nodes[0], ["system", "service", "disable-telnet"])
            disable_http_nodes = find_child_by_path(deviceconfig_nodes[0], ["system", "service", "disable-http"])
            
        telnet_nodes = []
        http_nodes = []
        if deviceconfig_nodes:
            telnet_nodes = find_child_by_path(deviceconfig_nodes[0], ["system", "service", "telnet"])
            http_nodes = find_child_by_path(deviceconfig_nodes[0], ["system", "service", "http"])
            
        if not telnet_nodes:
            telnet_nodes = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "service", "telnet"])
        if not http_nodes:
            http_nodes = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "service", "http"])

        # Telnet service status
        if disable_telnet_nodes:
            node = disable_telnet_nodes[0]
            disabled = node.text.strip().lower() == "yes"
            raw, line, path = self._evidence(node, "deviceconfig/system/service/disable-telnet")
            baseline.telnet_enabled = Observation[bool].found(not disabled, raw, line, note=path)
        elif telnet_nodes:
            node = telnet_nodes[0]
            enabled = node.text.strip().lower() == "yes"
            raw, line, path = self._evidence(node, "deviceconfig/system/service/telnet")
            baseline.telnet_enabled = Observation[bool].found(enabled, raw, line, note=path)
        else:
            baseline.telnet_enabled = Observation[bool].absent(False, "Telnet service is disabled by default.")

        # HTTP service status
        if disable_http_nodes:
            node = disable_http_nodes[0]
            disabled = node.text.strip().lower() == "yes"
            raw, line, path = self._evidence(node, "deviceconfig/system/service/disable-http")
            baseline.http_server_enabled = Observation[bool].found(not disabled, raw, line, note=path)
        elif http_nodes:
            node = http_nodes[0]
            enabled = node.text.strip().lower() == "yes"
            raw, line, path = self._evidence(node, "deviceconfig/system/service/http")
            baseline.http_server_enabled = Observation[bool].found(enabled, raw, line, note=path)
        else:
            baseline.http_server_enabled = Observation[bool].absent(False, "HTTP server is disabled by default.")

    def _normalize_password_complexity(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        mgt_config_nodes = find_nodes_by_tag(root, "mgt-config")
        
        enabled_node = []
        if mgt_config_nodes:
            enabled_node = find_child_by_path(mgt_config_nodes[0], ["password-complexity", "enabled"])
        if not enabled_node:
            enabled_node = find_nodes_by_path(root, ["configuration", "mgt-config", "password-complexity", "enabled"])
            
        is_enabled = enabled_node and enabled_node[0].text.strip().lower() == "yes"

        def get_complex_val(tag: str) -> Tuple[int, Optional[XMLNode]]:
            if not is_enabled:
                return 0, None
            tag_nodes = []
            if mgt_config_nodes:
                tag_nodes = find_child_by_path(mgt_config_nodes[0], ["password-complexity", tag])
            if not tag_nodes:
                tag_nodes = find_nodes_by_path(root, ["configuration", "mgt-config", "password-complexity", tag])
            if tag_nodes and tag_nodes[0].text.strip().isdigit():
                return int(tag_nodes[0].text.strip()), tag_nodes[0]
            return 0, None

        # 1. Minimum password length
        len_nodes = []
        if mgt_config_nodes:
            len_nodes = find_child_by_path(mgt_config_nodes[0], ["password-complexity", "minimum-length"])
        if not len_nodes:
            len_nodes = find_nodes_by_path(root, ["configuration", "mgt-config", "password-complexity", "minimum-length"])
            
        if len_nodes and len_nodes[0].text.strip().isdigit():
            len_val = int(len_nodes[0].text.strip())
            raw, line, path = self._evidence(len_nodes[0], "mgt-config/password-complexity/minimum-length")
            baseline.password_min_length = Observation[int].found(len_val, raw, line, note=path)
        else:
            baseline.password_min_length = Observation[int].absent(0, "Minimum password length is not enforced.")

        # 2. Uppercase letters
        upper_val, upper_node = get_complex_val("minimum-uppercase-letters")
        if upper_node:
            raw, line, path = self._evidence(upper_node, "mgt-config/password-complexity/minimum-uppercase-letters")
            baseline.password_min_uppercase = Observation[int].found(upper_val, raw, line, note=path)
        else:
            baseline.password_min_uppercase = Observation[int].absent(0, "Minimum uppercase letters is not enforced or policy is disabled.")

        # 3. Lowercase letters
        lower_val, lower_node = get_complex_val("minimum-lowercase-letters")
        if lower_node:
            raw, line, path = self._evidence(lower_node, "mgt-config/password-complexity/minimum-lowercase-letters")
            baseline.password_min_lowercase = Observation[int].found(lower_val, raw, line, note=path)
        else:
            baseline.password_min_lowercase = Observation[int].absent(0, "Minimum lowercase letters is not enforced or policy is disabled.")

        # 4. Numeric letters
        numeric_val, numeric_node = get_complex_val("minimum-numeric-letters")
        if numeric_node:
            raw, line, path = self._evidence(numeric_node, "mgt-config/password-complexity/minimum-numeric-letters")
            baseline.password_min_numeric = Observation[int].found(numeric_val, raw, line, note=path)
        else:
            baseline.password_min_numeric = Observation[int].absent(0, "Minimum numeric letters is not enforced or policy is disabled.")

        # 5. Special characters
        special_val, special_node = get_complex_val("minimum-special-characters")
        if special_node:
            raw, line, path = self._evidence(special_node, "mgt-config/password-complexity/minimum-special-characters")
            baseline.password_min_special = Observation[int].found(special_val, raw, line, note=path)
        else:
            baseline.password_min_special = Observation[int].absent(0, "Minimum special characters is not enforced or policy is disabled.")

        # 6. Diff characters
        diff_val, diff_node = get_complex_val("new-password-differs-by-characters")
        if diff_node:
            raw, line, path = self._evidence(diff_node, "mgt-config/password-complexity/new-password-differs-by-characters")
            baseline.password_new_diff_chars = Observation[int].found(diff_val, raw, line, note=path)
        else:
            baseline.password_new_diff_chars = Observation[int].absent(0, "New password differences not enforced or policy is disabled.")

        # 7. Password history reuse limit
        history_val, history_node = get_complex_val("password-history-count")
        if history_node:
            raw, line, path = self._evidence(history_node, "mgt-config/password-complexity/password-history-count")
            baseline.password_history_reuse_limit = Observation[int].found(history_val, raw, line, note=path)
        else:
            baseline.password_history_reuse_limit = Observation[int].absent(0, "Password history reuse limit not enforced or policy is disabled.")

    def _normalize_password_expiration(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        mgt_config_nodes = find_nodes_by_tag(root, "mgt-config")
        
        profile_nodes = []
        if mgt_config_nodes:
            profile_nodes = find_child_by_path(mgt_config_nodes[0], ["password-profile"])
        if not profile_nodes:
            profile_nodes = find_nodes_by_path(root, ["configuration", "mgt-config", "password-profile"])
            
        profile_entries = []
        if profile_nodes:
            for child in profile_nodes[0].children:
                if child.tag == "entry":
                    profile_entries.append(child)

        if not profile_entries:
            baseline.password_max_age_days = Observation[int].absent(
                0, "No password profiles are configured."
            )
            return

        periods = []
        evidence_node = None
        
        for entry in profile_entries:
            exp_nodes = find_child_by_path(entry, ["password-change", "expiration-period"])
            if not exp_nodes:
                exp_nodes = find_nodes_by_path(entry, ["entry", "password-change", "expiration-period"])
                
            if exp_nodes and exp_nodes[0].text.strip().isdigit():
                val = int(exp_nodes[0].text.strip())
                periods.append(val)
                if val == 0 or not evidence_node:
                    evidence_node = exp_nodes[0]
            else:
                periods.append(0)
                pc_nodes = find_child_by_path(entry, ["password-change"])
                if not pc_nodes:
                    pc_nodes = find_nodes_by_path(entry, ["entry", "password-change"])
                if pc_nodes:
                    evidence_node = pc_nodes[0]
                else:
                    evidence_node = entry

        if 0 in periods:
            worst_val = 0
        else:
            worst_val = max(periods)

        if evidence_node:
            raw, line, path = self._evidence(evidence_node, "mgt-config/password-profile/entry/password-change/expiration-period")
            baseline.password_max_age_days = Observation[int].found(
                worst_val, raw, line, note=f"Worst-case password expiration is {worst_val} days (from profile configuration)."
            )
        else:
            baseline.password_max_age_days = Observation[int].absent(
                worst_val, "Password profiles exist but expiration period could not be parsed."
            )

    def _normalize_idle_timeout(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        deviceconfig_nodes = find_nodes_by_tag(root, "deviceconfig")
        nodes = []
        evidence_path = ""
        
        # Real: deviceconfig/setting/management/idle-timeout
        if deviceconfig_nodes:
            nodes = find_child_by_path(deviceconfig_nodes[0], ["setting", "management", "idle-timeout"])
            evidence_path = "deviceconfig/setting/management/idle-timeout"
            
        # Legacy/Test: deviceconfig/system/login-timeout
        if not nodes and deviceconfig_nodes:
            nodes = find_child_by_path(deviceconfig_nodes[0], ["system", "login-timeout"])
            evidence_path = "deviceconfig/system/login-timeout"
            
        if not nodes:
            nodes = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "login-timeout"])
            evidence_path = "configuration/deviceconfig/system/login-timeout"
            
        if nodes and nodes[0].text.strip().isdigit():
            node = nodes[0]
            val_mins = int(node.text.strip())
            val_secs = val_mins * 60
            raw, line, path = self._evidence(node, evidence_path)
            baseline.vty_exec_timeout_seconds = Observation[int].found(val_secs, raw, line, note=path)
        else:
            baseline.vty_exec_timeout_seconds = Observation[int].absent(0, "Management idle timeout is not configured.")

    def _normalize_lockout_settings(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        deviceconfig_nodes = find_nodes_by_tag(root, "deviceconfig")
        mgt_config_nodes = find_nodes_by_tag(root, "mgt-config")
        
        # 1. Check global lockout: deviceconfig/setting/management/admin-lockout/failed-attempts and lockout-time
        global_threshold = 0
        global_duration = 0
        global_evidence_node = None
        global_evidence_path = ""
        
        if deviceconfig_nodes:
            fa_nodes = find_child_by_path(deviceconfig_nodes[0], ["setting", "management", "admin-lockout", "failed-attempts"])
            lt_nodes = find_child_by_path(deviceconfig_nodes[0], ["setting", "management", "admin-lockout", "lockout-time"])
            
            if fa_nodes and fa_nodes[0].text.strip().isdigit():
                global_evidence_node = fa_nodes[0]
                global_threshold = int(global_evidence_node.text.strip())
                global_evidence_path = "deviceconfig/setting/management/admin-lockout/failed-attempts"
                
            if lt_nodes and lt_nodes[0].text.strip().isdigit():
                if not global_evidence_node:
                    global_evidence_node = lt_nodes[0]
                    global_evidence_path = "deviceconfig/setting/management/admin-lockout/lockout-time"
                global_duration = int(lt_nodes[0].text.strip()) * 60  # convert minutes to seconds
                
        # 2. Check local password complexity lockout (legacy/tests)
        prevent_nodes = []
        time_nodes = []
        if mgt_config_nodes:
            prevent_nodes = find_child_by_path(mgt_config_nodes[0], ["password-complexity", "block-prevent"])
            time_nodes = find_child_by_path(mgt_config_nodes[0], ["password-complexity", "block-time"])
        if not prevent_nodes:
            prevent_nodes = find_nodes_by_path(root, ["configuration", "mgt-config", "password-complexity", "block-prevent"])
        if not time_nodes:
            time_nodes = find_nodes_by_path(root, ["configuration", "mgt-config", "password-complexity", "block-time"])

        local_threshold = 0
        local_duration = 0
        local_evidence_node = None
        local_evidence_path = ""

        if prevent_nodes and prevent_nodes[0].text.strip().isdigit():
            local_evidence_node = prevent_nodes[0]
            local_threshold = int(local_evidence_node.text.strip())
            local_evidence_path = "mgt-config/password-complexity/block-prevent"

        if time_nodes and time_nodes[0].text.strip().isdigit():
            if not local_evidence_node:
                local_evidence_node = time_nodes[0]
                local_evidence_path = "mgt-config/password-complexity/block-time"
            local_duration = int(time_nodes[0].text.strip()) * 60  # convert minutes to seconds

        # Use global lockout if configured, otherwise fallback to local/complexity lockout
        base_threshold = global_threshold if global_evidence_node else local_threshold
        base_duration = global_duration if global_evidence_node else local_duration
        base_evidence_node = global_evidence_node or local_evidence_node
        base_evidence_path = global_evidence_path or local_evidence_path

        # 3. Check Authentication Profiles lockout
        auth_profile_nodes = find_nodes_by_tag(root, "authentication-profile")
        profile_entries = []
        for ap_node in auth_profile_nodes:
            for child in ap_node.children:
                if child.tag == "entry":
                    profile_entries.append(child)

        all_profiles_compliant = True
        profile_evidence_node = None
        profile_evidence_path = ""
        profile_thresholds = []
        profile_durations = []

        if profile_entries:
            for entry in profile_entries:
                failed_attempts = 0
                lockout_time = 0
                
                lockout_nodes = [c for c in entry.children if c.tag == "lockout"]
                if lockout_nodes:
                    lockout_node = lockout_nodes[0]
                    fa_nodes = [c for c in lockout_node.children if c.tag == "failed-attempts"]
                    lt_nodes = [c for c in lockout_node.children if c.tag == "lockout-time"]
                    
                    if fa_nodes and fa_nodes[0].text.strip().isdigit():
                        failed_attempts = int(fa_nodes[0].text.strip())
                        if not profile_evidence_node:
                            profile_evidence_node = fa_nodes[0]
                            profile_evidence_path = "authentication-profile/entry/lockout/failed-attempts"
                    if lt_nodes and lt_nodes[0].text.strip().isdigit():
                        lockout_time = int(lt_nodes[0].text.strip()) * 60  # minutes to seconds
                        if not profile_evidence_node:
                            profile_evidence_node = lt_nodes[0]
                            profile_evidence_path = "authentication-profile/entry/lockout/lockout-time"
                
                if failed_attempts == 0 or lockout_time == 0:
                    all_profiles_compliant = False
                else:
                    profile_thresholds.append(failed_attempts)
                    profile_durations.append(lockout_time)

        # Determine overall lockout settings
        if profile_entries:
            if all_profiles_compliant and profile_thresholds and profile_durations:
                threshold = min(profile_thresholds)
                duration = min(profile_durations)
                evidence_node = profile_evidence_node
                evidence_path = profile_evidence_path
            else:
                threshold = 0
                duration = 0
                evidence_node = profile_evidence_node or profile_entries[0]
                evidence_path = "authentication-profile/entry"
        else:
            threshold = base_threshold
            duration = base_duration
            evidence_node = base_evidence_node
            evidence_path = base_evidence_path

        if evidence_node:
            raw, line, path = self._evidence(evidence_node, evidence_path)
            baseline.admin_lockout_threshold = Observation[int].found(threshold, raw, line, note=path)
            baseline.admin_lockout_duration = Observation[int].found(duration, raw, line, note=path)
        else:
            note = "Account lockout settings are not configured."
            baseline.admin_lockout_threshold = Observation[int].absent(0, note)
            baseline.admin_lockout_duration = Observation[int].absent(0, note)

    def _normalize_snmp(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        deviceconfig_nodes = find_nodes_by_tag(root, "deviceconfig")
        
        snmp_node = []
        if deviceconfig_nodes:
            snmp_node = find_child_by_path(deviceconfig_nodes[0], ["system", "snmp-setting"])
        if not snmp_node:
            snmp_node = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "snmp-setting"])
            
        if snmp_node:
            node = snmp_node[0]
            raw, line, path = self._evidence(node, "deviceconfig/system/snmp-setting")
            baseline.snmp_agent_enabled = Observation[bool].found(True, raw, line, note=path)

            # Search recursively for community strings
            comm_nodes = find_nodes_by_tag(node, "community")
            communities = []
            for c in comm_nodes:
                val = c.text.strip()
                if val:
                    communities.append(SnmpCommunity(
                        name=val,
                        access="ro", # default access in PAN-OS for v2c communities
                        acl=None,
                        source_line=f"<community>{val}</community>",
                        line_number=c.line_number
                    ))
            baseline.snmp_communities = Observation[List[SnmpCommunity]].found(communities, raw, line, note=path)
        else:
            baseline.snmp_agent_enabled = Observation[bool].absent(False, "SNMP agent is not enabled.")
            baseline.snmp_communities = Observation[List[SnmpCommunity]].absent([], "SNMP community strings are not present.")

    def _normalize_update_server(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        deviceconfig_nodes = find_nodes_by_tag(root, "deviceconfig")
        nodes = []
        evidence_path = ""
        
        # Real: deviceconfig/system/server-verification
        if deviceconfig_nodes:
            nodes = find_child_by_path(deviceconfig_nodes[0], ["system", "server-verification"])
            evidence_path = "deviceconfig/system/server-verification"
            
        # Legacy/Test: deviceconfig/system/verify-update-server-identity
        if not nodes and deviceconfig_nodes:
            nodes = find_child_by_path(deviceconfig_nodes[0], ["system", "verify-update-server-identity"])
            evidence_path = "deviceconfig/system/verify-update-server-identity"
            
        if not nodes:
            nodes = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "verify-update-server-identity"])
            evidence_path = "configuration/deviceconfig/system/verify-update-server-identity"
            
        if nodes:
            node = nodes[0]
            enabled = node.text.strip().lower() == "yes"
            raw, line, path = self._evidence(node, evidence_path)
            baseline.verify_update_server_identity = Observation[bool].found(enabled, raw, line, note=path)
        else:
            # Default is enabled in PAN-OS
            baseline.verify_update_server_identity = Observation[bool].absent(
                True, "server-verification is not configured, defaults to True."
            )

    def _normalize_ntp(self, root: XMLNode, baseline: SecurityBaselineModel) -> None:
        deviceconfig_nodes = find_nodes_by_tag(root, "deviceconfig")
        servers = []
        evidence_node = None
        evidence_path = ""

        # Real paths
        if deviceconfig_nodes:
            primary = find_child_by_path(deviceconfig_nodes[0], ["system", "ntp-servers", "primary-ntp-server", "ntp-server-address"])
            secondary = find_child_by_path(deviceconfig_nodes[0], ["system", "ntp-servers", "secondary-ntp-server", "ntp-server-address"])
            if primary and primary[0].text.strip():
                evidence_node = primary[0]
                servers.append(evidence_node.text.strip())
                evidence_path = "deviceconfig/system/ntp-servers/primary-ntp-server/ntp-server-address"
            if secondary and secondary[0].text.strip():
                if not evidence_node:
                    evidence_node = secondary[0]
                    evidence_path = "deviceconfig/system/ntp-servers/secondary-ntp-server/ntp-server-address"
                servers.append(secondary[0].text.strip())

        # Legacy/Test paths
        if not servers and deviceconfig_nodes:
            primary_legacy = find_child_by_path(deviceconfig_nodes[0], ["system", "ntp-servers", "primary-ntp", "ntp-server-address"])
            secondary_legacy = find_child_by_path(deviceconfig_nodes[0], ["system", "ntp-servers", "secondary-ntp", "ntp-server-address"])
            
            if not primary_legacy:
                primary_legacy = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "ntp-servers", "primary-ntp", "ntp-server-address"])
            if not secondary_legacy:
                secondary_legacy = find_nodes_by_path(root, ["configuration", "deviceconfig", "system", "ntp-servers", "secondary-ntp", "ntp-server-address"])
                
            if primary_legacy and primary_legacy[0].text.strip():
                evidence_node = primary_legacy[0]
                servers.append(evidence_node.text.strip())
                evidence_path = "deviceconfig/system/ntp-servers/primary-ntp/ntp-server-address"
            if secondary_legacy and secondary_legacy[0].text.strip():
                if not evidence_node:
                    evidence_node = secondary_legacy[0]
                    evidence_path = "deviceconfig/system/ntp-servers/secondary-ntp/ntp-server-address"
                servers.append(secondary_legacy[0].text.strip())

        if servers:
            raw, line, path = self._evidence(evidence_node, evidence_path)
            baseline.ntp_servers = Observation[List[str]].found(servers, raw, line, note=path)
            baseline.ntp_redundant = Observation[bool].found(len(servers) >= 2, raw, line, note=path)
        else:
            baseline.ntp_servers = Observation[List[str]].absent([], "NTP servers are not configured.")
            baseline.ntp_redundant = Observation[bool].absent(False, "No redundant NTP servers are configured.")
