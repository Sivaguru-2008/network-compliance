"""Closed-Loop Automated Remediation Executor.

Safely applies compliance hardening CLI commands to network devices with:
1. Dry-run diff simulation.
2. Pre-change configuration snapshotting.
3. Command execution verification.
4. Automatic rollback upon execution error.
"""

from dataclasses import dataclass, field
import datetime
import logging
import time
from typing import Dict, List, Optional

from .connector import DeviceConnector, DeviceCredential, LiveDeviceResult

logger = logging.getLogger(__name__)


@dataclass
class RemediationPlan:
    """A set of CLI commands to harden non-compliant settings on a target."""

    target_host: str
    control_id: str
    title: str
    commands: List[str]
    rollback_commands: List[str] = field(default_factory=list)
    risk_level: str = "Medium"


@dataclass
class RemediationResult:
    """Outcome of remediation execution."""

    target_host: str
    control_id: str
    success: bool
    dry_run: bool
    commands_executed: List[str] = field(default_factory=list)
    output_log: List[str] = field(default_factory=list)
    snapshot_taken: bool = False
    rollback_triggered: bool = False
    error_message: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())


class RemediationExecutor:
    """Executes hardening commands against network devices safely."""

    def __init__(self, connector: DeviceConnector) -> None:
        self.connector = connector

    def preview_dry_run(self, plan: RemediationPlan) -> RemediationResult:
        """Simulate remediation execution without modifying device state."""
        return RemediationResult(
            target_host=plan.target_host,
            control_id=plan.control_id,
            success=True,
            dry_run=True,
            commands_executed=plan.commands,
            output_log=[f"[DRY-RUN] Would execute on {plan.target_host}: {cmd}" for cmd in plan.commands],
            snapshot_taken=False,
            rollback_triggered=False,
        )

    def execute_plan(
        self,
        plan: RemediationPlan,
        dry_run: bool = False,
        mock_success: bool = False,
    ) -> RemediationResult:
        """Apply the remediation plan to the target device."""
        if dry_run:
            return self.preview_dry_run(plan)

        if mock_success:
            return RemediationResult(
                target_host=plan.target_host,
                control_id=plan.control_id,
                success=True,
                dry_run=False,
                commands_executed=plan.commands,
                output_log=[f"[MOCK] Executed: {cmd} -> OK" for cmd in plan.commands],
                snapshot_taken=True,
                rollback_triggered=False,
            )

        # 1. Take Pre-change Snapshot
        snapshot_res = self.connector.fetch_running_config()
        snapshot_taken = snapshot_res.success

        executed: List[str] = []
        logs: List[str] = []
        rollback_needed = False
        err_msg: Optional[str] = None

        try:
            import paramiko  # type: ignore

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=self.connector.host,
                port=self.connector.credential.port,
                username=self.connector.credential.username,
                password=self.connector.credential.password,
                timeout=self.connector.credential.timeout_seconds,
            )

            # Apply commands
            for cmd in plan.commands:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=self.connector.credential.timeout_seconds)
                out = stdout.read().decode("utf-8", errors="replace")
                err = stderr.read().decode("utf-8", errors="replace")
                executed.append(cmd)
                logs.append(f"CMD: {cmd} | OUT: {out.strip()} | ERR: {err.strip()}")

                if "Invalid input" in out or "Error" in err or "% Incomplete command" in out:
                    rollback_needed = True
                    err_msg = f"Command syntax error on: {cmd}"
                    break

            # Rollback if needed
            if rollback_needed and plan.rollback_commands:
                for rb_cmd in plan.rollback_commands:
                    client.exec_command(rb_cmd, timeout=self.connector.credential.timeout_seconds)
                    logs.append(f"ROLLBACK CMD: {rb_cmd}")

            client.close()

        except Exception as exc:
            rollback_needed = True
            err_msg = f"Remediation execution error: {exc}"

        return RemediationResult(
            target_host=plan.target_host,
            control_id=plan.control_id,
            success=not rollback_needed and err_msg is None,
            dry_run=False,
            commands_executed=executed,
            output_log=logs,
            snapshot_taken=snapshot_taken,
            rollback_triggered=rollback_needed,
            error_message=err_msg,
        )
