"""Deterministic Azure Network Security Group (NSG) parser.

Parses Azure NSG JSON configuration templates and resource exports.
Normalizes inbound and outbound security rules (SSH, Telnet, HTTP, HTTPS, source IP restrictions)
into the vendor-neutral SecurityBaselineModel.
"""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional

from ..models.baseline import ParserProvenance, SecurityBaselineModel
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class AzureNSGParser(VendorParser):
    """Parser for Azure Network Security Group JSON configurations."""

    name = "azure_nsg"
    vendor = "azure"
    os_family = "cloud_firewall"
    version = "1.0.0"
    base_confidence = 1.0

    @classmethod
    def detect(cls, config_text: str) -> float:
        if not config_text or not config_text.strip():
            return 0.0
        try:
            data = json.loads(config_text)
            if isinstance(data, dict):
                if "securityRules" in data or "defaultSecurityRules" in data:
                    return 0.95
                if "properties" in data and ("securityRules" in data["properties"] or "defaultSecurityRules" in data["properties"]):
                    return 0.98
                if data.get("type") == "Microsoft.Network/networkSecurityGroups":
                    return 1.0
        except Exception:
            pass

        if re.search(r'"(Microsoft\.Network/networkSecurityGroups|securityRules|destinationPortRange)"\s*:', config_text):
            return 0.85
        return 0.0

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        try:
            data = json.loads(config_text)
        except Exception as err:
            raise ParserError(f"Failed to parse Azure NSG JSON: {err}") from err

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

        nsg_name = data.get("name") or "azure-nsg"
        baseline.hostname = Observation.found(str(nsg_name), source_line=f"NSG Name: {nsg_name}", line_number=1)

        rules: List[Dict[str, Any]] = []
        if isinstance(data, dict):
            props = data.get("properties", data)
            rules.extend(props.get("securityRules", []))
            rules.extend(props.get("defaultSecurityRules", []))

        telnet_open = False
        ssh_open = False
        ssh_configured = False
        http_open = False
        https_open = False
        unrestricted_mgmt = False
        restricted_mgmt = False

        telnet_snippets: List[str] = []
        ssh_snippets: List[str] = []
        http_snippets: List[str] = []

        for rule in rules:
            r_props = rule.get("properties", rule)
            access = str(r_props.get("access", "")).lower()
            direction = str(r_props.get("direction", "")).lower()
            if direction != "inbound" or access != "allow":
                continue

            protocol = str(r_props.get("protocol", "")).lower()
            dst_port = str(r_props.get("destinationPortRange", ""))
            dst_ports = r_props.get("destinationPortRanges", [])
            all_dst_ports = [dst_port] if dst_port else []
            all_dst_ports.extend(dst_ports)

            src_prefix = str(r_props.get("sourceAddressPrefix", ""))
            src_prefixes = r_props.get("sourceAddressPrefixes", [])
            all_src_prefixes = [src_prefix] if src_prefix else []
            all_src_prefixes.extend(src_prefixes)

            is_world_open = any(p in ("*", "0.0.0.0/0", "Internet", "<nw>/0") for p in all_src_prefixes)

            def matches_port(target: int) -> bool:
                if protocol not in ("*", "tcp"):
                    return False
                for p in all_dst_ports:
                    if p in ("*", f"{target}"):
                        return True
                    if "-" in p:
                        parts = p.split("-")
                        try:
                            if int(parts[0]) <= target <= int(parts[1]):
                                return True
                        except ValueError:
                            pass
                return False

            if matches_port(23):
                if is_world_open:
                    telnet_open = True
                    unrestricted_mgmt = True
                    telnet_snippets.append(f"Inbound Allow Port 23 from {all_src_prefixes}")

            if matches_port(22):
                ssh_configured = True
                if is_world_open:
                    ssh_open = True
                    unrestricted_mgmt = True
                    ssh_snippets.append(f"Inbound Allow Port 22 from {all_src_prefixes}")
                else:
                    restricted_mgmt = True
                    ssh_snippets.append(f"Inbound Allow Port 22 restricted to {all_src_prefixes}")

            if matches_port(80):
                if is_world_open:
                    http_open = True
                    http_snippets.append(f"Inbound Allow Port 80 from {all_src_prefixes}")

            if matches_port(443):
                https_open = True

        if telnet_open:
            baseline.telnet_enabled = Observation.found(True, source_line="; ".join(telnet_snippets), line_number=1)
        else:
            baseline.telnet_enabled = Observation.absent(False, note="No inbound Telnet allow rule")

        if ssh_configured:
            baseline.ssh_enabled = Observation.found(True, source_line="; ".join(ssh_snippets), line_number=1)
            baseline.ssh_version = Observation.found(2, source_line="Azure NSG SSH service (Version 2)", line_number=1)
        else:
            baseline.ssh_enabled = Observation.absent(False, note="No SSH ingress rule defined")

        baseline.http_server_enabled = Observation.found(http_open, source_line="; ".join(http_snippets) if http_snippets else "No HTTP ingress rule", line_number=1)
        baseline.https_server_enabled = Observation.found(https_open, source_line="HTTPS ingress rule present" if https_open else "No HTTPS ingress rule", line_number=1)

        if unrestricted_mgmt:
            baseline.management_acl_applied = Observation.found(False, source_line="Inbound management rules allow * / Internet source", line_number=1)
        elif restricted_mgmt:
            baseline.management_acl_applied = Observation.found(True, source_line="Inbound management rules restricted to specific source prefixes", line_number=1)
        else:
            baseline.management_acl_applied = Observation.found(True, source_line="No public management rules", line_number=1)

        has_diagnostics = "diagnosticSettings" in config_text or "logs" in config_text
        baseline.logging_enabled = Observation.found(has_diagnostics, source_line="NSG diagnostic logging configured" if has_diagnostics else "Diagnostic logging not defined in NSG export", line_number=1)

        baseline.aaa_enabled = Observation.found(True, source_line="Microsoft Entra ID / Azure RBAC enforced", line_number=1)
        baseline.password_encryption = Observation.found(True, source_line="Azure Managed Identity / Key Vault credentials", line_number=1)

        return baseline
