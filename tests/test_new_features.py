"""Tests for the secrets redactor, SQLite database, and multi-provider AI framework."""

from pathlib import Path
import tempfile
import sqlite3
import pytest
from datetime import datetime, timezone

from auditor.parsers.llm.client import redact_secrets, MockProvider, LocalProvider
from auditor.training import db
from auditor.models.identity import DeviceIdentity
from auditor.models.inventory import DeviceRecord, DeviceStatus, DeviceKeyTier
from auditor.models.result import ReportSummary, ControlResult, Status, Severity


def test_secrets_redactor():
    """Verify that sensitive elements are redacted locally before sending to AI."""
    ios_config = (
        "hostname SWITCH-A\n"
        "username admin secret 9 $9$Qw8sT2nMzXv5Kd$3pLhBc7YrUeIoAt\n"
        "enable password 7 08311B1E1A\n"
        "snmp-server community secretString RO 99\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0y...\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    redacted = redact_secrets(ios_config)
    assert "$9$" not in redacted
    assert "08311B1E1A" not in redacted
    assert "secretString" not in redacted
    assert "MIIEow" not in redacted
    assert "<REDACTED>" in redacted

    junos_config = (
        "system {\n"
        "    root-authentication {\n"
        "        encrypted-password \"$6$rounds=65536$...\"\n"
        "    }\n"
        "}\n"
        "snmp {\n"
        "    community internal-nms {\n"
        "        authorization read-only;\n"
        "    }\n"
        "}\n"
    )
    redacted_junos = redact_secrets(junos_config)
    assert "$6$" not in redacted_junos
    assert "internal-nms" not in redacted_junos
    assert "<REDACTED>" in redacted_junos


def test_mock_and_local_ai_providers():
    """Verify that MockProvider and LocalProvider are offline-safe and generate schema-compliant results."""
    provider = MockProvider()
    assert "mock" in provider.description
    
    config = "hostname CORE-GATEWAY-01\ninterface Loopback0\n"
    extraction = provider.extract(config)
    assert extraction.vendor == "cisco" or extraction.vendor == "juniper" or extraction.vendor == "sonic"
    assert extraction.hostname.value == "CORE-GATEWAY-01"
    assert extraction.telnet_enabled.value is False
    assert extraction.ssh_enabled.value is True

    local = LocalProvider()
    assert "local" in local.description
    ext_local = local.extract(config)
    assert ext_local.hostname.value == "CORE-GATEWAY-01"


def test_sqlite_database_roundtrip():
    """Verify that SQLite can store, list, and retrieve device audit summaries."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_inventory.sqlite"
        
        # Initialize DB
        db.init_db(db_path)
        
        # Build dummy DeviceRecord
        record = DeviceRecord(
            identity=DeviceIdentity(vendor="arista", os_family="eos"),
            source_file="samples/arista/sample.conf",
            source_hash="ab12cd34ef56gh78ab12cd34ef56gh78ab12cd34ef56gh78ab12cd34ef56gh78",
            ingested_at=datetime.now(timezone.utc),
            status=DeviceStatus.AUDITED,
            error=None,
            device_key="host:arista-sw-01@arista",
            device_key_tier=DeviceKeyTier.HOSTNAME_VENDOR,
            frameworks=["CIS"],
            findings=[
                ControlResult(
                    rule_id="CIS-GENERIC-AAA",
                    control_ref="1.1.1",
                    internal_control_id="aaa_enabled",
                    verified_ref=False,
                    title="Enable AAA",
                    description="AAA must be enabled",
                    framework="CIS",
                    severity=Severity.MEDIUM,
                    status=Status.PASS,
                    message="AAA is enabled",
                    evidence=[],
                    remediation=None,
                    references=[]
                )
            ],
            framework_summaries={
                "CIS": ReportSummary(total=1, passed=1, failed=0, needs_review=0)
            },
            summary=ReportSummary(total=1, passed=1, failed=0, needs_review=0),
            target=None,
            companion_file=None
        )
        
        # Save to DB
        db.save_audit_result(db_path, record, "hostname arista-sw-01")
        
        # Verify Listing
        devices = db.list_devices(db_path)
        assert len(devices) == 1
        assert devices[0]["hostname"] == "arista-sw-01"
        assert devices[0]["vendor"] == "arista"
        assert devices[0]["status"] == "audited"

        # Verify Retrieve
        retrieved = db.get_device(db_path, record.device_key)
        assert retrieved is not None
        assert retrieved["hostname"] == "arista-sw-01"
        assert retrieved["config_text"] == "hostname arista-sw-01"

        # Verify Dashboard stats
        stats = db.get_dashboard_stats(db_path)
        assert stats["total_devices"] == 1
        assert stats["compliant"] == 1
        assert stats["non_compliant"] == 0
