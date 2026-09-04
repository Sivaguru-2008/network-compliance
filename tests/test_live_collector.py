"""Tests for Live Device Collector and Closed-Loop Remediation Executor."""

import json
from pathlib import Path
import pytest
from auditor.collector.connector import DeviceConnector, DeviceCredential
from auditor.collector.inventory_collector import FleetCollector, TargetDeviceEntry
from auditor.collector.remediation_pusher import RemediationExecutor, RemediationPlan


def test_device_connector_mock():
    cred = DeviceCredential(username="admin", password="password123", port=22)
    connector = DeviceConnector(host="192.168.1.1", credential=cred, vendor_hint="cisco_ios")
    mock_cfg = "hostname core-rtr\nline vty 0 4\ntransport input ssh\n"
    res = connector.fetch_running_config(mock_response=mock_cfg)

    assert res.success is True
    assert res.host == "192.168.1.1"
    assert "hostname core-rtr" in res.config_text
    assert len(res.command_log) > 0


def test_remediation_executor_dry_run():
    cred = DeviceCredential(username="admin", password="password123")
    connector = DeviceConnector(host="10.0.0.1", credential=cred, vendor_hint="cisco_ios")
    executor = RemediationExecutor(connector)

    plan = RemediationPlan(
        target_host="10.0.0.1",
        control_id="CIS-1.2.9",
        title="Enforce VTY exec timeout",
        commands=["line vty 0 4", "exec-timeout 10 0"],
        rollback_commands=["line vty 0 4", "no exec-timeout"],
    )

    result = executor.preview_dry_run(plan)
    assert result.dry_run is True
    assert result.success is True
    assert len(result.commands_executed) == 2
    assert "[DRY-RUN]" in result.output_log[0]


def test_remediation_executor_mock_execution():
    cred = DeviceCredential(username="admin", password="password123")
    connector = DeviceConnector(host="10.0.0.1", credential=cred, vendor_hint="cisco_ios")
    executor = RemediationExecutor(connector)

    plan = RemediationPlan(
        target_host="10.0.0.1",
        control_id="CIS-1.2.2",
        title="Disable Telnet",
        commands=["line vty 0 4", "transport input ssh"],
    )

    result = executor.execute_plan(plan, dry_run=False, mock_success=True)
    assert result.dry_run is False
    assert result.success is True
    assert result.snapshot_taken is True
    assert len(result.commands_executed) == 2


def test_fleet_collector(tmp_path: Path):
    inventory_data = {
        "devices": [
            {"host": "10.0.0.1", "username": "admin", "vendor_hint": "cisco_ios"},
            {"host": "10.0.0.2", "username": "root", "vendor_hint": "juniper_junos"},
        ]
    }
    inv_file = tmp_path / "inventory.json"
    inv_file.write_text(json.dumps(inventory_data), encoding="utf-8")

    entries = FleetCollector.load_inventory_file(inv_file)
    assert len(entries) == 2
    assert entries[0].host == "10.0.0.1"
    assert entries[1].host == "10.0.0.2"

    mock_configs = {
        "10.0.0.1": "hostname rtr1\n",
        "10.0.0.2": "set system host-name srx1\n",
    }
    results = list(FleetCollector.collect_fleet(entries, mock_configs=mock_configs))
    assert len(results) == 2
    assert results[0].success is True
    assert results[0].config_text == "hostname rtr1\n"
    assert results[1].success is True
    assert results[1].config_text == "set system host-name srx1\n"
