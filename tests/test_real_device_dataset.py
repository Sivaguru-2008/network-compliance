"""Unit and regression tests for real device configuration acquisition, provenance, and partitioning."""

import json
from pathlib import Path
import pytest

from auditor.training.real_device_dataset import (
    ConfigSanitizer,
    DatasetSplit,
    DeviceProvenance,
    RealDeviceConfigRecord,
    RealDeviceDatasetBuilder,
    SecurityConceptExtractor,
)
from auditor.training.acquire_real_device_dataset import run_acquisition


@pytest.fixture(scope="module")
def acquired_dataset():
    builder = run_acquisition()
    return builder


class TestProvenanceIntegrity:
    """Verifies that all acquired configs adhere strictly to provenance standards."""

    def test_provenance_enums_defined(self):
        assert DeviceProvenance.REAL_DEVICE.value == "REAL_DEVICE"
        assert DeviceProvenance.SANITIZED_REAL_DEVICE.value == "SANITIZED_REAL_DEVICE"
        assert DeviceProvenance.PUBLIC_CONFIGURATION.value == "PUBLIC_CONFIGURATION"
        assert DeviceProvenance.PUBLIC_LAB_CONFIGURATION.value == "PUBLIC_LAB_CONFIGURATION"
        assert DeviceProvenance.OFFICIAL_VENDOR_EXAMPLE.value == "OFFICIAL_VENDOR_EXAMPLE"
        assert DeviceProvenance.SYNTHETIC.value == "SYNTHETIC"
        assert DeviceProvenance.UNKNOWN.value == "UNKNOWN"

    def test_real_device_flag_consistency(self, acquired_dataset):
        for rec in acquired_dataset.records:
            if rec.source_type in (DeviceProvenance.REAL_DEVICE, DeviceProvenance.SANITIZED_REAL_DEVICE):
                assert rec.real_device is True
                assert rec.provenance_verified is True
            else:
                assert rec.real_device is False

    def test_manifest_and_audit_files_generated(self):
        assert Path("dataset/provenance_audit.json").is_file()
        assert Path("dataset/research_dataset.json").is_file()

        with open("dataset/provenance_audit.json", "r", encoding="utf-8") as f:
            audit_entries = json.load(f)

        assert len(audit_entries) == 4
        for entry in audit_entries:
            assert entry["real_device"] is False
            assert entry["mock_or_fixture"] is True
            assert entry["verified_classification"] == "PUBLIC_CONFIGURATION"
            assert len(entry["evidence"]) > 0
            assert entry["confidence"] == "HIGH"


class TestSanitizationEngine:
    """Verifies that sensitive data is scrubbed without destroying configuration syntax."""

    def test_cisco_secret_redaction(self):
        raw = "enable secret 9 $9$SanitizedSecret123\nsnmp-server community secretComm RO\nusername admin password secretPass"
        sanitized = ConfigSanitizer.sanitize(raw)
        assert "$9$SanitizedSecret123" not in sanitized
        assert "secretComm" not in sanitized
        assert "secretPass" not in sanitized
        assert "<SANITIZED_SECRET>" in sanitized or "<SANITIZED_COMMUNITY>" in sanitized

    def test_private_key_redaction(self):
        raw = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...SECRET...\n-----END RSA PRIVATE KEY-----"
        sanitized = ConfigSanitizer.sanitize(raw)
        assert "SECRET" not in sanitized
        assert "BEGIN REDACTED PRIVATE KEY" in sanitized

    def test_syntax_preservation(self):
        raw = "interface GigabitEthernet0/1\n ip address 10.0.0.1 255.255.255.0\n no shutdown"
        sanitized = ConfigSanitizer.sanitize(raw)
        assert "interface GigabitEthernet0/1" in sanitized
        assert "no shutdown" in sanitized


class TestSecurityConceptExtraction:
    """Verifies detection and extraction of security dimensions."""

    def test_cisco_concept_extraction(self):
        config = """
        hostname core-rtr
        ip ssh version 2
        aaa new-model
        aaa authentication login default group tacacs+
        service password-encryption
        line vty 0 4
         transport input ssh
         exec-timeout 10 0
        snmp-server community test RO
        ntp server 1.1.1.1
        ip access-list standard 99
         permit 10.0.0.0 0.255.255.255
        """
        ext = SecurityConceptExtractor.extract(config, vendor="Cisco")
        assert ext.ssh_detected is True
        assert ext.ssh_version == 2
        assert ext.telnet_disabled is True
        assert ext.aaa_configured is True
        assert ext.tacacs_configured is True
        assert ext.password_encryption is True
        assert ext.session_timeout_seconds == 600
        assert ext.snmp_configured is True
        assert ext.ntp_configured is True
        assert ext.acls_firewall_rules is True
        assert "SSH_v2" in ext.detected_concepts


class TestPartitioningAndLeakagePrevention:
    """Verifies that real device data is never leaked into training partitions."""

    def test_real_device_never_in_train(self, acquired_dataset):
        for rec in acquired_dataset.records:
            if rec.real_device:
                assert rec.assigned_split == DatasetSplit.REAL_DEVICE_TEST
                assert rec.assigned_split != DatasetSplit.TRAIN

    def test_leave_one_vendor_out_disjointness(self, acquired_dataset):
        splits = acquired_dataset.generate_leave_one_vendor_out_splits("Cisco")
        assert splits["held_out_vendor"] == "Cisco"

        for train_rec in splits["train"]:
            assert train_rec["vendor"].lower() != "cisco"
            assert train_rec["real_device"] is False

        for test_rec in splits["test"]:
            assert test_rec["vendor"].lower() == "cisco"
            assert test_rec["real_device"] is False


class TestHonestProvenanceReporting:
    """Ensures missing vendor real configurations are reported honestly and not fabricated."""

    def test_missing_real_vendors_flagged(self, acquired_dataset):
        report = acquired_dataset.generate_summary_report()
        # All vendors without verified physical/production exports must be in missing real device list
        assert "Stormshield" in report["MISSING_REAL_DEVICE_VENDORS"]
        assert "Sophos" in report["MISSING_REAL_DEVICE_VENDORS"]
        assert "Barracuda" in report["MISSING_REAL_DEVICE_VENDORS"]
        assert "Cisco" in report["MISSING_REAL_DEVICE_VENDORS"]
        assert report["TOTAL_VERIFIED_REAL_DEVICE_CONFIGURATIONS"] == 0
        assert report["TOTAL_SANITIZED_REAL_DEVICE_CONFIGURATIONS"] == 0
        assert report["TOTAL_PUBLIC_CONFIGURATION_EXAMPLES"] == 7
        assert report["TOTAL_OFFICIAL_VENDOR_EXAMPLES"] == 7
        assert report["TOTAL_LAB_CONFIGURATIONS"] == 4
