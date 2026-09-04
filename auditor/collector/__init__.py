"""Live Network Device Data Collection and Closed-Loop Remediation Subsystem.

Provides direct network device communication (SSH / CLI / NETCONF / API) for:
1. Pulling live running-configurations directly from network devices without manual export.
2. Fleet-wide automated inventory collection and continuous compliance scanning.
3. Closed-loop remediation execution with pre-change snapshotting, dry-run previews, and safe rollback.
"""

from .connector import DeviceConnector, DeviceCredential, LiveDeviceResult
from .inventory_collector import FleetCollector
from .remediation_pusher import RemediationExecutor, RemediationPlan, RemediationResult

__all__ = [
    "DeviceConnector",
    "DeviceCredential",
    "LiveDeviceResult",
    "FleetCollector",
    "RemediationExecutor",
    "RemediationPlan",
    "RemediationResult",
]
