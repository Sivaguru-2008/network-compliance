"""Fleet Inventory Collector.

Loads a list of device targets from JSON/YAML/CSV inventory files,
polls devices via DeviceConnector, and yields normalized configurations.
"""

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from .connector import DeviceConnector, DeviceCredential, LiveDeviceResult


@dataclass
class TargetDeviceEntry:
    """Entry describing a network device to be audited."""

    host: str
    username: str
    password: Optional[str] = None
    ssh_key_path: Optional[str] = None
    enable_secret: Optional[str] = None
    port: int = 22
    vendor_hint: str = "generic"
    tags: Dict[str, str] = None


class FleetCollector:
    """Scans fleets of network devices and extracts running configurations."""

    @classmethod
    def load_inventory_file(cls, inventory_path: Path) -> List[TargetDeviceEntry]:
        """Load target devices from JSON or CSV file."""
        path = Path(inventory_path)
        if not path.exists():
            raise FileNotFoundError(f"Inventory file not found: {path}")

        entries: List[TargetDeviceEntry] = []
        if path.suffix.lower() == ".json":
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            raw_list = data if isinstance(data, list) else data.get("devices", [])
            for item in raw_list:
                entries.append(
                    TargetDeviceEntry(
                        host=item["host"],
                        username=item.get("username", "admin"),
                        password=item.get("password"),
                        ssh_key_path=item.get("ssh_key_path"),
                        enable_secret=item.get("enable_secret"),
                        port=int(item.get("port", 22)),
                        vendor_hint=item.get("vendor_hint", "generic"),
                        tags=item.get("tags", {}),
                    )
                )
        return entries

    @classmethod
    def collect_fleet(
        cls,
        targets: List[TargetDeviceEntry],
        mock_configs: Optional[Dict[str, str]] = None,
    ) -> Iterator[LiveDeviceResult]:
        """Poll each target device in the inventory."""
        for target in targets:
            cred = DeviceCredential(
                username=target.username,
                password=target.password,
                ssh_key_path=target.ssh_key_path,
                enable_secret=target.enable_secret,
                port=target.port,
            )
            connector = DeviceConnector(host=target.host, credential=cred, vendor_hint=target.vendor_hint)
            mock_conf = mock_configs.get(target.host) if mock_configs else None
            yield connector.fetch_running_config(mock_response=mock_conf)
