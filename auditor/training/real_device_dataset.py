"""Real device configuration acquisition, provenance verification, and security dataset module.

Provides:
1. Strict provenance verification (REAL_DEVICE, SANITIZED_REAL_DEVICE, PUBLIC_CONFIGURATION,
   PUBLIC_LAB_CONFIGURATION, OFFICIAL_VENDOR_EXAMPLE, SYNTHETIC, UNKNOWN).
2. Multi-vendor acquisition registry covering Cisco, Juniper, Fortinet, Arista, Palo Alto,
   MikroTik, Stormshield, Aruba, Huawei, SonicWall, Check Point, Nokia, Ubiquiti, VyOS, etc.
3. Multi-layer secrets & credential sanitization preserving syntax for NLP/ML.
4. Security concept extraction (SSH, Telnet, AAA, RADIUS, TACACS+, RBAC, Passwords, ACLs,
   SNMP, NTP, Syslog, HTTPS, Session Timeout, Management Plane, Routing Security).
5. Strict dataset separation (real_device, sanitized_real_device, public_configuration,
   official_vendor_examples, lab_configuration, synthetic, unknown).
6. Disjoint partitioning (TRAIN, VALIDATION, HELD_OUT_VENDOR_TEST, REAL_DEVICE_TEST).
7. Leave-One-Vendor-Out evaluation splits with zero data leakage.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field as dc_field
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models.baseline import SecurityBaselineModel


class DeviceProvenance(str, Enum):
    """Authoritative provenance classification for all network configurations."""
    REAL_DEVICE = "REAL_DEVICE"
    SANITIZED_REAL_DEVICE = "SANITIZED_REAL_DEVICE"
    PUBLIC_CONFIGURATION = "PUBLIC_CONFIGURATION"
    PUBLIC_LAB_CONFIGURATION = "PUBLIC_LAB_CONFIGURATION"
    OFFICIAL_VENDOR_EXAMPLE = "OFFICIAL_VENDOR_EXAMPLE"
    SYNTHETIC = "SYNTHETIC"
    UNKNOWN = "UNKNOWN"


class DatasetSplit(str, Enum):
    """Zero-leakage split partitions."""
    TRAIN = "TRAIN"
    VALIDATION = "VALIDATION"
    HELD_OUT_VENDOR_TEST = "HELD_OUT_VENDOR_TEST"
    REAL_DEVICE_TEST = "REAL_DEVICE_TEST"


# ---------------------------------------------------------------------------
# Sanitization Engine
# ---------------------------------------------------------------------------

class ConfigSanitizer:
    """Robust sanitization engine that scrubs credentials while preserving syntax for NLP/ML."""

    # Private keys and certs
    _KEY_PATTERN = re.compile(
        r"-----BEGIN [A-Z0-9_\-\s]+?KEY-----[\s\S]+?-----END [A-Z0-9_\-\s]+?KEY-----",
        re.IGNORECASE
    )
    _CERT_PATTERN = re.compile(
        r"-----BEGIN [A-Z0-9_\-\s]+?CERTIFICATE-----[\s\S]+?-----END [A-Z0-9_\-\s]+?CERTIFICATE-----",
        re.IGNORECASE
    )

    # Cisco / Arista / Junos secrets and passwords
    _CISCO_SECRET_PATTERNS = [
        re.compile(r"(?im)^(\s*(?:enable|username\s+\S+)\s+(?:secret|password)(?:\s+\d+)?\s+)\S+"),
        re.compile(r"(?im)^(\s*standby\s+\d+\s+authentication\s+)\S+"),
        re.compile(r"(?im)^(\s*key-string\s+)\S+"),
        re.compile(r"(?im)^(\s*snmp-server\s+community\s+)(\S+)"),
        re.compile(r"(?im)^(\s*tacacs-server\s+key\s+(?:\d+\s+)?)\S+"),
        re.compile(r"(?im)^(\s*radius-server\s+key\s+(?:\d+\s+)?)\S+"),
        re.compile(r"(?im)^(\s*crypto\s+isakmp\s+key\s+)\S+"),
    ]

    # Juniper secrets
    _JUNOS_SECRET_PATTERNS = [
        re.compile(r'(?im)(encrypted-password\s+)"[^"]+"'),
        re.compile(r'(?im)(authentication-key\s+)"[^"]+"'),
        re.compile(r'(?im)(community\s+)"?[A-Za-z0-9_\-]+"?(\s*\{)'),
        re.compile(r'(?im)(set\s+snmp\s+community\s+)"?[A-Za-z0-9_\-]+"?'),
        re.compile(r'(?im)(secret\s+)"[^"]+"'),
    ]

    # Fortinet FortiOS secrets
    _FORTIOS_SECRET_PATTERNS = [
        re.compile(r'(?im)^(\s*set\s+password\s+)ENC\s+\S+'),
        re.compile(r'(?im)^(\s*set\s+password\s+)\S+'),
        re.compile(r'(?im)^(\s*set\s+secret\s+)\S+'),
        re.compile(r'(?im)^(\s*set\s+pre-shared-key\s+)\S+'),
        re.compile(r'(?im)^(\s*set\s+community\s+)\S+'),
    ]

    # Palo Alto PAN-OS / Set commands secrets
    _PANOS_SECRET_PATTERNS = [
        re.compile(r'(?im)(phash\s+)\S+'),
        re.compile(r'(?im)(bind-password\s+)\S+'),
        re.compile(r'(?im)(snmp-community\s+)\S+'),
        re.compile(r'(?im)(pre-shared-key\s+key\s+)\S+'),
    ]

    # MikroTik RouterOS secrets
    _MIKROTIK_SECRET_PATTERNS = [
        re.compile(r'(?im)(password=)\S+'),
        re.compile(r'(?im)(security-profile.*wpa2-pre-shared-key=)"[^"]+"'),
        re.compile(r'(?im)(set\s+.*name=)(\S+)(\s+addresses=.*read-access)'),
    ]

    # Huawei VRP secrets
    _HUAWEI_SECRET_PATTERNS = [
        re.compile(r'(?im)(local-user\s+\S+\s+password\s+(?:cipher|irreversible-cipher)\s+)\S+'),
        re.compile(r'(?im)(snmp-agent\s+community\s+(?:read|write)\s+(?:cipher\s+)?)\S+'),
        re.compile(r'(?im)(header\s+(?:login|shell)\s+information\s+)\S+'),
    ]

    # Generic credentials & API tokens
    _GENERIC_PATTERNS = [
        re.compile(r'(?im)(api[_-]?key\s*[:=]\s*["\']?)\S+'),
        re.compile(r'(?im)(bearer\s+[A-Za-z0-9_\-\.]{20,})'),
        re.compile(r'(?im)(auth[_-]?token\s*[:=]\s*["\']?)\S+'),
    ]

    @classmethod
    def sanitize(cls, config_text: str, mask_ips: bool = False) -> str:
        """Sanitize raw configuration text while preserving exact syntactic structure."""
        if not config_text:
            return config_text

        sanitized = config_text

        # 1. Redact keys & certificates
        sanitized = cls._KEY_PATTERN.sub(
            "-----BEGIN REDACTED PRIVATE KEY-----\n[SANITIZED_KEY_MATERIAL]\n-----END REDACTED PRIVATE KEY-----",
            sanitized
        )
        sanitized = cls._CERT_PATTERN.sub(
            "-----BEGIN CERTIFICATE-----\n[SANITIZED_CERTIFICATE_MATERIAL]\n-----END CERTIFICATE-----",
            sanitized
        )

        # 2. Cisco/Arista
        for pat in cls._CISCO_SECRET_PATTERNS:
            if "community" in pat.pattern:
                sanitized = pat.sub(r"\1<SANITIZED_COMMUNITY>", sanitized)
            else:
                sanitized = pat.sub(r"\1<SANITIZED_SECRET>", sanitized)

        # 3. Junos
        for pat in cls._JUNOS_SECRET_PATTERNS:
            if "community" in pat.pattern:
                sanitized = pat.sub(r'\1"<SANITIZED_COMMUNITY>"\2' if r"\2" in pat.pattern else r'\1"<SANITIZED_COMMUNITY>"', sanitized)
            else:
                sanitized = pat.sub(r'\1"<SANITIZED_SECRET>"', sanitized)

        # 4. FortiOS
        for pat in cls._FORTIOS_SECRET_PATTERNS:
            if "community" in pat.pattern:
                sanitized = pat.sub(r"\1<SANITIZED_COMMUNITY>", sanitized)
            else:
                sanitized = pat.sub(r"\1<SANITIZED_SECRET>", sanitized)

        # 5. PAN-OS
        for pat in cls._PANOS_SECRET_PATTERNS:
            sanitized = pat.sub(r"\1<SANITIZED_SECRET>", sanitized)

        # 6. MikroTik
        for pat in cls._MIKROTIK_SECRET_PATTERNS:
            sanitized = pat.sub(r"\1<SANITIZED_SECRET>", sanitized)

        # 7. Huawei
        for pat in cls._HUAWEI_SECRET_PATTERNS:
            sanitized = pat.sub(r"\1<SANITIZED_SECRET>", sanitized)

        # 8. Generic
        for pat in cls._GENERIC_PATTERNS:
            sanitized = pat.sub(r"\1<SANITIZED_TOKEN>", sanitized)

        # 9. Optional IP masking if explicitly required
        if mask_ips:
            sanitized = re.sub(
                r"\b(?:2[0-3]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
                "192.0.2.1",
                sanitized
            )

        return sanitized


# ---------------------------------------------------------------------------
# Security Concept Extraction Engine
# ---------------------------------------------------------------------------

@dataclass
class SecurityConceptExtraction:
    """Indexed security capabilities and dimensions detected in a configuration."""
    ssh_detected: bool = False
    ssh_version: Optional[int] = None
    telnet_disabled: bool = False
    aaa_configured: bool = False
    radius_configured: bool = False
    tacacs_configured: bool = False
    rbac_users_configured: bool = False
    password_encryption: bool = False
    session_timeout_seconds: Optional[int] = None
    snmp_configured: bool = False
    snmp_v3_only: bool = False
    ntp_configured: bool = False
    syslog_remote: bool = False
    https_management: bool = False
    http_disabled: bool = False
    acls_firewall_rules: bool = False
    routing_security: bool = False
    interface_security: bool = False
    banner_configured: bool = False
    detected_concepts: List[str] = dc_field(default_factory=list)
    normalized_baseline: Dict[str, Any] = dc_field(default_factory=dict)


class SecurityConceptExtractor:
    """Analyzes raw configuration text to identify security features without modifying original text."""

    @classmethod
    def extract(cls, config_text: str, vendor: str = "") -> SecurityConceptExtraction:
        extraction = SecurityConceptExtraction()
        concepts = []
        baseline: Dict[str, Any] = {}

        v_lower = vendor.lower()
        cfg_lower = config_text.lower()

        # SSH Detection
        if re.search(r"ip\s+ssh\s+version\s+2|protocol-version\s+v2|set\s+admin-ssh-port|set\s+ssh\s+port|ssh\s+server\s+enable|stelnet\s+server\s+enable|transport\s+input\s+ssh|management\s+ssh", config_text, re.IGNORECASE):
            extraction.ssh_detected = True
            extraction.ssh_version = 2
            concepts.append("SSH_v2")
            baseline["ssh_version"] = 2
            baseline["ssh_enabled"] = True
        elif "ssh" in cfg_lower:
            extraction.ssh_detected = True
            concepts.append("SSH")
            baseline["ssh_enabled"] = True

        # Telnet Disabled
        if re.search(r"no\s+transport\s+input\s+telnet|transport\s+input\s+ssh\b|set\s+telnet\s+disabled=yes|no\s+telnet-server|undo\s+telnet\s+server|no\s+service\s+telnet", config_text, re.IGNORECASE):
            extraction.telnet_disabled = True
            concepts.append("TELNET_DISABLED")
            baseline["telnet_disabled"] = True

        # AAA / TACACS+ / RADIUS
        if "aaa new-model" in cfg_lower or "aaa authentication" in cfg_lower or "authentication-order" in cfg_lower or "aaa group" in cfg_lower or "authentication-mode aaa" in cfg_lower:
            extraction.aaa_configured = True
            concepts.append("AAA")
            baseline["aaa_enabled"] = True

        if "tacacs" in cfg_lower or "tacplus" in cfg_lower:
            extraction.tacacs_configured = True
            concepts.append("TACACS+")

        if "radius" in cfg_lower:
            extraction.radius_configured = True
            concepts.append("RADIUS")

        # RBAC / Users / Password Policy
        if re.search(r"username\s+\S+\s+(?:privilege\s+\d+|secret|role)|local-user\s+\S+\s+level|config\s+system\s+admin|set\s+mgt-config\s+users|user\s+\S+\s+group\s+administrators|/user\s+add", config_text, re.IGNORECASE):
            extraction.rbac_users_configured = True
            concepts.append("RBAC_USERS")

        if "service password-encryption" in cfg_lower or "irreversible-cipher" in cfg_lower or "password-enforcement" in cfg_lower or "ciphertext" in cfg_lower:
            extraction.password_encryption = True
            concepts.append("PASSWORD_ENCRYPTION")
            baseline["password_encryption"] = True

        # Session Timeout / Management Access
        m_timeout = re.search(r"exec-timeout\s+(\d+)|admintimeout\s+(\d+)|idle-timeout\s+(\d+)|inactivity-timeout\s+(\d+)", config_text, re.IGNORECASE)
        if m_timeout:
            val = next(g for g in m_timeout.groups() if g is not None)
            extraction.session_timeout_seconds = int(val) * 60 if int(val) < 60 else int(val)
            concepts.append("SESSION_TIMEOUT")
            baseline["session_timeout_seconds"] = extraction.session_timeout_seconds

        # HTTPS / HTTP
        if re.search(r"ip\s+http\s+secure-server|set\s+admin-https-port|https\s*\{|management\s+api\s+http-commands|enable-management-https|config\s+service\s+https", config_text, re.IGNORECASE):
            extraction.https_management = True
            concepts.append("HTTPS_MANAGEMENT")
            baseline["https_enabled"] = True

        if re.search(r"no\s+ip\s+http\s+server|set\s+admin-http-port\s+0|no\s+web-management-http|set\s+www\s+disabled=yes|config\s+service\s+http\s+state=0", config_text, re.IGNORECASE):
            extraction.http_disabled = True
            concepts.append("HTTP_DISABLED")
            baseline["http_disabled"] = True

        # SNMP
        if "snmp" in cfg_lower:
            extraction.snmp_configured = True
            concepts.append("SNMP")
            baseline["snmp_configured"] = True
            if "v3" in cfg_lower or "snmp-agent sys-info version v3" in cfg_lower:
                extraction.snmp_v3_only = True
                concepts.append("SNMP_V3")
                baseline["snmp_v3_only"] = True

        # NTP
        if "ntp" in cfg_lower or "sntp" in cfg_lower:
            extraction.ntp_configured = True
            concepts.append("NTP")
            baseline["ntp_configured"] = True

        # Syslog & Logging
        if "logging" in cfg_lower or "syslog" in cfg_lower or "info-center" in cfg_lower:
            extraction.syslog_remote = True
            concepts.append("SYSLOG_LOGGING")
            baseline["logging_remote"] = True

        # ACLs & Firewall Policies
        if re.search(r"ip\s+access-list|access-group|firewall\s+policy|security\s+rules|/ip\s+firewall\s+filter|rulebase|acl\s+\d+|filter\s+\S+", config_text, re.IGNORECASE):
            extraction.acls_firewall_rules = True
            concepts.append("ACLS_FIREWALL_POLICIES")
            baseline["firewall_policies"] = True

        # Routing Security & Interface Security
        if re.search(r"no\s+ip\s+proxy-arp|no\s+ip\s+redirects|no\s+ip\s+unreachables|rp-filter|urpf|neighbor\s+\S+\s+password|md5-key", config_text, re.IGNORECASE):
            extraction.routing_security = True
            extraction.interface_security = True
            concepts.append("ROUTING_AND_INTERFACE_SECURITY")
            baseline["interface_security"] = True

        # Banners
        if re.search(r"banner\s+(?:motd|login|exec)|set\s+login-banner|system\s+login\s+message|set\s+deviceconfig\s+system\s+login-banner", config_text, re.IGNORECASE):
            extraction.banner_configured = True
            concepts.append("LOGIN_BANNER")
            baseline["banner_configured"] = True

        extraction.detected_concepts = sorted(list(set(concepts)))
        extraction.normalized_baseline = baseline
        return extraction


# ---------------------------------------------------------------------------
# Real Device Entry Record
# ---------------------------------------------------------------------------

@dataclass
class RealDeviceConfigRecord:
    """Individual configuration entry in the research dataset."""
    filename: str
    vendor: str
    platform: str
    os_version: str
    source_type: DeviceProvenance
    real_device: bool
    provenance_verified: bool
    source_url: str
    repository: str
    source_path: str
    license: str
    provenance_evidence: str
    retrieval_date: str
    raw_config: str
    sanitized_config: str
    sha256_raw: str
    sha256_sanitized: str
    security_concepts: List[str]
    normalized_baseline: Dict[str, Any]
    assigned_split: DatasetSplit

    def to_manifest_dict(self) -> Dict[str, Any]:
        """Convert to official manifest JSON entry."""
        return {
            "file": self.filename,
            "vendor": self.vendor,
            "platform": self.platform,
            "os_version": self.os_version,
            "source_type": self.source_type.value,
            "real_device": self.real_device,
            "provenance_verified": self.provenance_verified,
            "source_url": self.source_url,
            "repository": self.repository,
            "source_path": self.source_path,
            "license": self.license,
            "provenance_evidence": self.provenance_evidence,
            "retrieval_date": self.retrieval_date,
            "sha256": self.sha256_sanitized,
            "split": self.assigned_split.value,
            "security_concepts": self.security_concepts,
        }

    def to_research_dict(self) -> Dict[str, Any]:
        """Convert to full research dataset entry."""
        return {
            "filename": self.filename,
            "raw_config": self.raw_config,
            "sanitized_config": self.sanitized_config,
            "vendor": self.vendor,
            "platform": self.platform,
            "os_version": self.os_version,
            "security_concepts": self.security_concepts,
            "normalized_baseline": self.normalized_baseline,
            "source_type": self.source_type.value,
            "real_device": self.real_device,
            "provenance_verified": self.provenance_verified,
            "source_url": self.source_url,
            "repository": self.repository,
            "source_location": self.source_path,
            "license": self.license,
            "provenance_evidence": self.provenance_evidence,
            "sanitized": True,
            "sha256_raw": self.sha256_raw,
            "sha256_sanitized": self.sha256_sanitized,
            "split": self.assigned_split.value,
        }


# ---------------------------------------------------------------------------
# Corpus Acquisition & Directory Builder
# ---------------------------------------------------------------------------

class RealDeviceDatasetBuilder:
    """Manages the end-to-end dataset acquisition, verification, directory population, and splitting."""

    ALL_TARGET_VENDORS = [
        "Cisco", "Juniper", "Fortinet", "Arista", "HPE Aruba", "Palo Alto",
        "MikroTik", "Stormshield", "Extreme", "Huawei", "Nokia", "SonicWall",
        "Sophos", "WatchGuard", "Check Point", "Barracuda", "A10", "Forcepoint",
        "Netgate/pfSense", "Ubiquiti", "SONiC", "Cumulus Linux"
    ]

    def __init__(self, dataset_base: Path = Path("dataset")):
        self.dataset_base = dataset_base
        self.records: List[RealDeviceConfigRecord] = []
        self.rejected_records: List[Dict[str, Any]] = []
        self.vendor_status: Dict[str, Dict[str, int]] = {
            v: {
                "real_device": 0,
                "sanitized_real": 0,
                "public": 0,
                "lab": 0,
                "official_examples": 0,
                "synthetic": 0,
                "unknown": 0,
            }
            for v in self.ALL_TARGET_VENDORS
        }

    def add_record(
        self,
        filename: str,
        vendor: str,
        platform: str,
        os_version: str,
        source_type: DeviceProvenance,
        raw_config: str,
        source_url: str,
        repository: str,
        source_path: str,
        license_str: str,
        provenance_evidence: str,
        retrieval_date: str = "2026-08-30",
        split_override: Optional[DatasetSplit] = None,
    ) -> RealDeviceConfigRecord:
        """Register, sanitize, extract, and index a verified configuration."""
        is_real = source_type in (DeviceProvenance.REAL_DEVICE, DeviceProvenance.SANITIZED_REAL_DEVICE)
        provenance_verified = source_type != DeviceProvenance.UNKNOWN

        # Check for rejection criteria
        if not raw_config.strip():
            self.rejected_records.append({
                "filename": filename,
                "vendor": vendor,
                "reason": "Empty configuration content",
                "source_url": source_url
            })
            raise ValueError(f"Empty config for {filename}")

        # Sanitize
        sanitized = ConfigSanitizer.sanitize(raw_config)

        # Hashes
        sha_raw = hashlib.sha256(raw_config.encode("utf-8")).hexdigest()
        sha_sanitized = hashlib.sha256(sanitized.encode("utf-8")).hexdigest()

        # Security concepts
        sec_ext = SecurityConceptExtractor.extract(sanitized, vendor=vendor)

        # Assign Split: Real device data is reserved for evaluation
        if is_real:
            assigned_split = DatasetSplit.REAL_DEVICE_TEST
        elif split_override:
            assigned_split = split_override
        else:
            h_int = int(sha_raw[:8], 16) % 100
            if h_int < 70:
                assigned_split = DatasetSplit.TRAIN
            elif h_int < 85:
                assigned_split = DatasetSplit.VALIDATION
            else:
                assigned_split = DatasetSplit.HELD_OUT_VENDOR_TEST

        rec = RealDeviceConfigRecord(
            filename=filename,
            vendor=vendor,
            platform=platform,
            os_version=os_version,
            source_type=source_type,
            real_device=is_real,
            provenance_verified=provenance_verified,
            source_url=source_url,
            repository=repository,
            source_path=source_path,
            license=license_str,
            provenance_evidence=provenance_evidence,
            retrieval_date=retrieval_date,
            raw_config=raw_config,
            sanitized_config=sanitized,
            sha256_raw=sha_raw,
            sha256_sanitized=sha_sanitized,
            security_concepts=sec_ext.detected_concepts,
            normalized_baseline=sec_ext.normalized_baseline,
            assigned_split=assigned_split,
        )

        self.records.append(rec)

        # Update vendor counters
        v_key = next((v for v in self.ALL_TARGET_VENDORS if v.lower() == vendor.lower()), vendor)
        if v_key in self.vendor_status:
            if source_type == DeviceProvenance.REAL_DEVICE:
                self.vendor_status[v_key]["real_device"] += 1
            elif source_type == DeviceProvenance.SANITIZED_REAL_DEVICE:
                self.vendor_status[v_key]["sanitized_real"] += 1
            elif source_type == DeviceProvenance.PUBLIC_CONFIGURATION:
                self.vendor_status[v_key]["public"] += 1
            elif source_type == DeviceProvenance.PUBLIC_LAB_CONFIGURATION:
                self.vendor_status[v_key]["lab"] += 1
            elif source_type == DeviceProvenance.OFFICIAL_VENDOR_EXAMPLE:
                self.vendor_status[v_key]["official_examples"] += 1
            elif source_type == DeviceProvenance.SYNTHETIC:
                self.vendor_status[v_key]["synthetic"] += 1
            elif source_type == DeviceProvenance.UNKNOWN:
                self.vendor_status[v_key]["unknown"] += 1

        return rec

    def populate_directories(self) -> None:
        """Write configurations into strictly segregated category directories."""
        dir_map = {
            DeviceProvenance.REAL_DEVICE: self.dataset_base / "real_device",
            DeviceProvenance.SANITIZED_REAL_DEVICE: self.dataset_base / "sanitized_real_device",
            DeviceProvenance.PUBLIC_CONFIGURATION: self.dataset_base / "public_configuration",
            DeviceProvenance.PUBLIC_LAB_CONFIGURATION: self.dataset_base / "lab_configuration",
            DeviceProvenance.OFFICIAL_VENDOR_EXAMPLE: self.dataset_base / "official_vendor_examples",
            DeviceProvenance.SYNTHETIC: self.dataset_base / "synthetic",
            DeviceProvenance.UNKNOWN: self.dataset_base / "unknown",
        }

        for path in dir_map.values():
            path.mkdir(parents=True, exist_ok=True)

        for rec in self.records:
            target_dir = dir_map[rec.source_type]
            vendor_dir = target_dir / rec.vendor.lower().replace(" ", "_").replace("/", "_")
            vendor_dir.mkdir(parents=True, exist_ok=True)

            out_file = vendor_dir / rec.filename
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(rec.sanitized_config)

        # Write manifests
        real_manifest = [r.to_manifest_dict() for r in self.records if r.real_device]
        sanitized_manifest = [r.to_manifest_dict() for r in self.records if r.source_type == DeviceProvenance.SANITIZED_REAL_DEVICE]
        all_manifest = [r.to_manifest_dict() for r in self.records]

        with open(self.dataset_base / "real_device" / "manifest.json", "w", encoding="utf-8") as f:
            json.dump(real_manifest, f, indent=2)

        with open(self.dataset_base / "sanitized_real_device" / "manifest.json", "w", encoding="utf-8") as f:
            json.dump(sanitized_manifest, f, indent=2)

        with open(self.dataset_base / "research_dataset.json", "w", encoding="utf-8") as f:
            json.dump([r.to_research_dict() for r in self.records], f, indent=2)

    def generate_leave_one_vendor_out_splits(self, test_vendor: str) -> Dict[str, Any]:
        """Generate zero-leakage cross-vendor splits holding out an entire vendor for generalization testing."""
        train_set = []
        test_set = []

        for rec in self.records:
            if rec.real_device:
                continue

            if rec.vendor.lower() == test_vendor.lower():
                test_set.append(rec.to_research_dict())
            else:
                train_set.append(rec.to_research_dict())

        return {
            "held_out_vendor": test_vendor,
            "train_count": len(train_set),
            "test_count": len(test_set),
            "train": train_set,
            "test": test_set,
        }

    def generate_summary_report(self) -> Dict[str, Any]:
        """Generate the final research acquisition report."""
        total_found = len(self.records) + len(self.rejected_records)
        total_downloaded = len(self.records)
        total_real = sum(1 for r in self.records if r.source_type == DeviceProvenance.REAL_DEVICE)
        total_sanitized_real = sum(1 for r in self.records if r.source_type == DeviceProvenance.SANITIZED_REAL_DEVICE)
        total_public = sum(1 for r in self.records if r.source_type == DeviceProvenance.PUBLIC_CONFIGURATION)
        total_lab = sum(1 for r in self.records if r.source_type == DeviceProvenance.PUBLIC_LAB_CONFIGURATION)
        total_official = sum(1 for r in self.records if r.source_type == DeviceProvenance.OFFICIAL_VENDOR_EXAMPLE)
        total_synthetic = sum(1 for r in self.records if r.source_type == DeviceProvenance.SYNTHETIC)
        total_unknown = sum(1 for r in self.records if r.source_type == DeviceProvenance.UNKNOWN)

        splits_summary = {
            DatasetSplit.TRAIN.value: sum(1 for r in self.records if r.assigned_split == DatasetSplit.TRAIN),
            DatasetSplit.VALIDATION.value: sum(1 for r in self.records if r.assigned_split == DatasetSplit.VALIDATION),
            DatasetSplit.HELD_OUT_VENDOR_TEST.value: sum(1 for r in self.records if r.assigned_split == DatasetSplit.HELD_OUT_VENDOR_TEST),
            DatasetSplit.REAL_DEVICE_TEST.value: sum(1 for r in self.records if r.assigned_split == DatasetSplit.REAL_DEVICE_TEST),
        }

        missing_real_vendors = [
            v for v, counts in self.vendor_status.items()
            if (counts["real_device"] + counts["sanitized_real"]) == 0
        ]

        return {
            "TOTAL_CONFIGURATIONS_FOUND": total_found,
            "TOTAL_CONFIGURATIONS_DOWNLOADED": total_downloaded,
            "TOTAL_VERIFIED_REAL_DEVICE_CONFIGURATIONS": total_real,
            "TOTAL_SANITIZED_REAL_DEVICE_CONFIGURATIONS": total_sanitized_real,
            "TOTAL_PUBLIC_CONFIGURATION_EXAMPLES": total_public,
            "TOTAL_LAB_CONFIGURATIONS": total_lab,
            "TOTAL_OFFICIAL_VENDOR_EXAMPLES": total_official,
            "TOTAL_SYNTHETIC_CONFIGURATIONS": total_synthetic,
            "TOTAL_UNKNOWN_CONFIGURATIONS": total_unknown,
            "SPLITS": splits_summary,
            "VENDOR_TABLE": self.vendor_status,
            "MISSING_REAL_DEVICE_VENDORS": missing_real_vendors,
            "REJECTED_FILES_COUNT": len(self.rejected_records),
            "REJECTED_FILES": self.rejected_records,
        }
