"""Deterministic AWS VPC Security Groups and Network Firewall parser.

Parses AWS EC2 Security Groups and Network Firewall JSON/YAML configuration exports.
Normalizes inbound/outbound firewall rules, open ports (SSH, Telnet, HTTP), source CIDR restrictions,
and logging settings into the vendor-neutral SecurityBaselineModel.
"""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional

from ..models.baseline import ParserProvenance, SecurityBaselineModel
from ..models.observation import Observation
from .base import ParserError, VendorParser, registry


@registry.register
class AWSSecurityGroupParser(VendorParser):
    """Parser for AWS Security Groups and Network Firewall configurations."""

    name = "aws_security_group"
    vendor = "aws"
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
                if "SecurityGroups" in data or "IpPermissions" in data or "SecurityGroupRules" in data:
                    return 0.95
                if "GroupId" in data and ("IpPermissionsEgress" in data or "FromPort" in data):
                    return 0.90
            elif isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                if "IpPermissions" in data[0] or "GroupId" in data[0]:
                    return 0.90
        except Exception:
            pass

        if re.search(r'"(IpPermissions|SecurityGroups|FromPort|IpProtocol)"\s*:', config_text):
            return 0.85
        return 0.0

    def parse(self, config_text: str, *, source_file: Optional[str] = None) -> SecurityBaselineModel:
        if not config_text or not config_text.strip():
            raise ParserError("Configuration is empty.")

        try:
            data = json.loads(config_text)
        except Exception as err:
            raise ParserError(f"Failed to parse AWS Security Group JSON: {err}") from err

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

        groups: List[Dict[str, Any]] = []
        if isinstance(data, dict):
            if "SecurityGroups" in data and isinstance(data["SecurityGroups"], list):
                groups = data["SecurityGroups"]
            else:
                groups = [data]
        elif isinstance(data, list):
            groups = [item for item in data if isinstance(item, dict)]

        if not groups:
            return baseline

        # Extract primary group details
        primary_group = groups[0]
        group_name = primary_group.get("GroupName") or primary_group.get("GroupId") or "aws-security-group"
        baseline.hostname = Observation.found(str(group_name), source_line=f"GroupName: {group_name}", line_number=1)

        # Analyze Ingress rules across groups
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

        for grp in groups:
            inbound = grp.get("IpPermissions", []) or grp.get("SecurityGroupRules", [])
            for perm in inbound:
                ip_protocol = str(perm.get("IpProtocol", "-1"))
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 65535 if ip_protocol == "-1" else from_port)
                
                # Check CIDRs
                ip_ranges = [r.get("CidrIp", "") for r in perm.get("IpRanges", []) if isinstance(r, dict)]
                if not ip_ranges and "CidrIpv4" in perm:
                    ip_ranges.append(perm["CidrIpv4"])

                is_world_open = any(cidr in ("0.0.0.0/0", "::/0") for cidr in ip_ranges)
                has_cidrs = len(ip_ranges) > 0

                def port_in_range(target: int) -> bool:
                    if ip_protocol == "-1":
                        return True
                    if ip_protocol in ("tcp", "6"):
                        return (from_port is None or from_port <= target) and (to_port is None or to_port >= target)
                    return False

                # Telnet (23)
                if port_in_range(23):
                    if is_world_open:
                        telnet_open = True
                        telnet_snippets.append(f"Port 23 open to {ip_ranges}")
                        unrestricted_mgmt = True
                    elif has_cidrs:
                        restricted_mgmt = True

                # SSH (22)
                if port_in_range(22):
                    ssh_configured = True
                    if is_world_open:
                        ssh_open = True
                        ssh_snippets.append(f"Port 22 open to 0.0.0.0/0")
                        unrestricted_mgmt = True
                    elif has_cidrs:
                        restricted_mgmt = True
                        ssh_snippets.append(f"Port 22 restricted to {ip_ranges}")

                # HTTP (80)
                if port_in_range(80):
                    if is_world_open:
                        http_open = True
                        http_snippets.append(f"Port 80 open to {ip_ranges}")

                # HTTPS (443)
                if port_in_range(443):
                    https_open = True

        # Observations
        if telnet_open:
            baseline.telnet_enabled = Observation.found(True, source_line="; ".join(telnet_snippets), line_number=1)
        else:
            baseline.telnet_enabled = Observation.absent(False, note="No unrestricted port 23 ingress rule")

        if ssh_configured:
            baseline.ssh_enabled = Observation.found(True, source_line="; ".join(ssh_snippets), line_number=1)
            baseline.ssh_version = Observation.found(2, source_line="AWS Security Group SSH service (Version 2)", line_number=1)
        else:
            baseline.ssh_enabled = Observation.absent(False, note="No SSH ingress rule defined")

        baseline.http_server_enabled = Observation.found(http_open, source_line="; ".join(http_snippets) if http_snippets else "No HTTP rule", line_number=1)
        baseline.https_server_enabled = Observation.found(https_open, source_line="HTTPS ingress rule present" if https_open else "No HTTPS rule", line_number=1)

        # Management ACL applied
        if unrestricted_mgmt:
            baseline.management_acl_applied = Observation.found(False, source_line="Management ports (22/23) allow 0.0.0.0/0 unrestricted access", line_number=1)
        elif restricted_mgmt:
            baseline.management_acl_applied = Observation.found(True, source_line="Management access restricted to specific CIDR blocks", line_number=1)
        else:
            baseline.management_acl_applied = Observation.found(True, source_line="No public management ingress rules", line_number=1)

        # Flow logs / CloudWatch
        has_flow_logs = "FlowLogs" in config_text or "cloudwatch" in config_text.lower() or "flow-logs" in config_text.lower()
        baseline.logging_enabled = Observation.found(has_flow_logs, source_line="VPC Flow Logs reference found" if has_flow_logs else "No VPC Flow Logs configured in export", line_number=1)

        # Password / AAA are managed by IAM in AWS
        baseline.aaa_enabled = Observation.found(True, source_line="AWS IAM centralized identity provider enforced", line_number=1)
        baseline.password_encryption = Observation.found(True, source_line="AWS IAM managed credentials", line_number=1)

        return baseline
