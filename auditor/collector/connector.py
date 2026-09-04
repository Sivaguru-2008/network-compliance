"""Live network device connector for running-configuration extraction.

Supports pulling live configurations over SSH / CLI across multi-vendor fleets.
"""

from dataclasses import dataclass, field
import logging
import socket
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Map of vendor/OS family to canonical running-config retrieval commands
VENDOR_CONFIG_COMMANDS: Dict[str, List[str]] = {
    "cisco_ios": ["terminal length 0", "show running-config"],
    "cisco_asa": ["terminal pager 0", "show running-config"],
    "cisco_nxos": ["terminal length 0", "show running-config"],
    "juniper_junos": ["set cli screen-length 0", "show configuration"],
    "fortinet_fortios": ["config system console\nset output standard\nend", "show full-configuration"],
    "arista_eos": ["terminal length 0", "show running-config"],
    "huawei_vrp": ["screen-length 0 temporary", "display current-configuration"],
    "checkpoint_gaia": ["set clienv rows 0", "show configuration"],
    "mikrotik_routeros": ["/export"],
    "sonic": ["show runningconfiguration all"],
    "paloalto": ["set cli pager off", "show config running"],
    "hpe_aruba": ["no page", "show running-config"],
    "hpe_aruba_aos_cx": ["no page", "show running-config"],
    "ubiquiti": ["show configuration"],
    "ubiquiti_edgeos": ["show configuration"],
    "pfsense": ["cat /cf/conf/config.xml"],
    "netgate_pfsense": ["cat /cf/conf/config.xml"],
    "a10_acos": ["terminal length 0", "show running-config"],
    "alcatel_aos": ["session timeout cli 0", "show configuration snapshot"],
    "barracuda_cloudgen": ["cat /opt/phion/config/active/boxnet.conf"],
    "cato_networks": ["api_export_config"],
    "extreme_exos": ["disable clipaging", "show configuration"],
    "f5_bigip_tmos": ["modify cli preference pager disabled", "show running-config"],
    "forcepoint_ngfw": ["sg-admin export"],
    "hillstone_stoneos": ["terminal length 0", "show configuration"],
    "nokia_sros": ["environment no more", "admin display-config"],
    "ruckus_fastiron": ["skip-page-display", "show running-config"],
    "sangfor_ngaf": ["show configuration"],
    "sonicwall": ["no cli-paging", "show current-config"],
    "sonicwall_sonicos": ["no cli-paging", "show current-config"],
    "sophos_sfos": ["console> system diagnostics show version-info"],
    "stormshield": ["CONFIG GET"],
    "stormshield_sns": ["CONFIG GET"],
    "versa_versos": ["set cli screen-length 0", "show configuration"],
    "watchguard": ["show running-config"],
    "watchguard_fireware": ["show running-config"],
    "zscaler_zia": ["cloud_api_export_zia"],
    "zscaler_zpa": ["cloud_api_export_zpa"],
    "aws_security_group": ["aws ec2 describe-security-groups"],
    "azure_nsg": ["az network nsg list"],
    "generic": ["terminal length 0", "show running-config"],
}


@dataclass
class DeviceCredential:
    """Device authentication credentials."""

    username: str
    password: Optional[str] = None
    ssh_key_path: Optional[str] = None
    enable_secret: Optional[str] = None
    port: int = 22
    timeout_seconds: int = 15


@dataclass
class LiveDeviceResult:
    """Result of live configuration collection."""

    host: str
    port: int
    success: bool
    config_text: str = ""
    error_message: Optional[str] = None
    vendor_hint: Optional[str] = None
    execution_time_seconds: float = 0.0
    command_log: List[str] = field(default_factory=list)


class DeviceConnector:
    """Manages live device connection and command execution."""

    def __init__(self, host: str, credential: DeviceCredential, vendor_hint: str = "generic") -> None:
        self.host = host
        self.credential = credential
        self.vendor_hint = vendor_hint.lower()

    def fetch_running_config(self, mock_response: Optional[str] = None) -> LiveDeviceResult:
        """Fetch the live running-configuration from the device.

        If `mock_response` is provided (useful in test/simulation environments),
        returns simulated output immediately.
        """
        start_time = time.time()
        commands = VENDOR_CONFIG_COMMANDS.get(self.vendor_hint, VENDOR_CONFIG_COMMANDS["generic"])

        if mock_response is not None:
            return LiveDeviceResult(
                host=self.host,
                port=self.credential.port,
                success=True,
                config_text=mock_response,
                vendor_hint=self.vendor_hint,
                execution_time_seconds=time.time() - start_time,
                command_log=commands,
            )

        # Live SSH Execution via Paramiko/Netmiko or socket
        try:
            import paramiko  # type: ignore

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            key_file = self.credential.ssh_key_path
            client.connect(
                hostname=self.host,
                port=self.credential.port,
                username=self.credential.username,
                password=self.credential.password,
                key_filename=key_file,
                timeout=self.credential.timeout_seconds,
                banner_timeout=15,
                auth_timeout=15,
            )

            # Interactive Shell or exec_command
            output_parts: List[str] = []
            for cmd in commands:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=self.credential.timeout_seconds)
                out = stdout.read().decode("utf-8", errors="replace")
                err = stderr.read().decode("utf-8", errors="replace")
                if out:
                    output_parts.append(out)

            client.close()
            full_config = "\n".join(output_parts) if output_parts else ""

            if not full_config.strip():
                return LiveDeviceResult(
                    host=self.host,
                    port=self.credential.port,
                    success=False,
                    error_message="Empty configuration returned by device commands.",
                    vendor_hint=self.vendor_hint,
                    execution_time_seconds=time.time() - start_time,
                    command_log=commands,
                )

            return LiveDeviceResult(
                host=self.host,
                port=self.credential.port,
                success=True,
                config_text=full_config,
                vendor_hint=self.vendor_hint,
                execution_time_seconds=time.time() - start_time,
                command_log=commands,
            )

        except ImportError:
            # Fallback when paramiko is not installed: test socket reachability
            try:
                with socket.create_connection((self.host, self.credential.port), timeout=2.0):
                    return LiveDeviceResult(
                        host=self.host,
                        port=self.credential.port,
                        success=False,
                        error_message="Live SSH client library (paramiko/netmiko) not installed. Use mock or install paramiko.",
                        vendor_hint=self.vendor_hint,
                        execution_time_seconds=time.time() - start_time,
                    )
            except Exception as conn_err:
                return LiveDeviceResult(
                    host=self.host,
                    port=self.credential.port,
                    success=False,
                    error_message=f"Connection failed: {conn_err}",
                    vendor_hint=self.vendor_hint,
                    execution_time_seconds=time.time() - start_time,
                )
        except Exception as exc:
            return LiveDeviceResult(
                host=self.host,
                port=self.credential.port,
                success=False,
                error_message=f"SSH collection error: {exc}",
                vendor_hint=self.vendor_hint,
                execution_time_seconds=time.time() - start_time,
                command_log=commands,
            )
