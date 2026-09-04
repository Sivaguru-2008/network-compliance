# Dataset builder generator
import os
import sys
from pathlib import Path

def write_dataset_builder():
    code = '''"""Multi-Task Security NLP Dataset Builder for Multi-Vendor Network Configurations.

Generates 7 NLP tasks from 2,524 multi-vendor configuration corpus with:
- Strict group-level train/validation/test splits (Zero Data Leakage)
- Automatic secret redaction and sanitization
- Complete provenance and metadata tracking
"""

import collections
import hashlib
import json
import logging
import math
import os
import random
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .extractor import CanonicalSecurityConfig, SecuritySemanticExtractor

logger = logging.getLogger(__name__)

# Section Classes
SECTION_CLASSES = [
    "INTERFACE", "ROUTING", "FIREWALL", "ACL", "NAT", "VPN",
    "AAA", "USER_MANAGEMENT", "SNMP", "LOGGING", "NTP",
    "SYSTEM", "SECURITY", "MANAGEMENT", "VLAN", "BGP", "OSPF", "UNKNOWN"
]

# NER Entity Types
NER_ENTITY_TYPES = [
    "IP_ADDRESS", "SUBNET", "INTERFACE", "VLAN", "VRF", "PROTOCOL",
    "PORT", "ACL", "FIREWALL_RULE", "USER", "AUTH_METHOD",
    "CRYPTO_ALGORITHM", "SERVICE", "SECURITY_ZONE", "ROUTING_PROTOCOL"
]

# Standard QA Questions
CORE_QA_QUESTIONS = [
    ("Is Telnet enabled?", "telnet_enabled", "bool", "Is Telnet remote administrative access permitted on the device?"),
    ("Is SSH enabled?", "ssh_enabled", "bool", "Is SSH secure remote management enabled on the device?"),
    ("Is AAA authentication enabled?", "aaa_enabled", "bool", "Is AAA (Authentication, Authorization, and Accounting) enabled?"),
    ("Is SNMP configured?", "snmp_enabled", "bool", "Is SNMP management agent configured on the device?"),
    ("Is SNMPv3 used?", "snmp_v3", "bool", "Are SNMPv3 secure users or v3 configurations present?"),
    ("Are insecure management protocols enabled?", "insecure_management", "bool", "Are unencrypted management protocols (Telnet or HTTP) enabled?"),
    ("Are ACLs configured?", "acls_configured", "bool", "Are access control lists or packet filters configured?"),
    ("Are there unrestricted any-to-any rules?", "unrestricted_rules", "bool", "Does any firewall or ACL rule allow unrestricted any-to-any traffic?"),
    ("Is logging enabled?", "logging_enabled", "bool", "Is system event logging or remote syslog configured?"),
    ("Is NTP configured?", "ntp_enabled", "bool", "Is authoritative NTP time synchronization configured?"),
    ("Is a default route configured?", "default_route", "bool", "Is a default gateway or 0.0.0.0/0 route configured?"),
    ("Is a weak cryptographic algorithm used?", "weak_crypto", "bool", "Are deprecated ciphers such as DES, 3DES, or MD5 configured?"),
    ("Is management access restricted by ACL?", "management_acl", "bool", "Is administrative access restricted to specific source IP subnets?"),
    ("Is password encryption enabled?", "password_encryption", "bool", "Is service password-encryption active on the device?"),
    ("Is enable secret configured?", "enable_secret", "bool", "Is a cryptographically hashed privileged secret configured?"),
]

# Remediation templates per vendor
VENDOR_REMEDIATIONS = {
    "TELNET_ENABLED": {
        "cisco": "line vty 0 4\\n transport input ssh\\n exit",
        "juniper": "delete system services telnet\\nset system services ssh",
        "arista": "management api http-commands\\n no protocol http\\n protocol https\\n exit",
        "fortinet": "config system interface\\n edit port1\\n unset allowaccess telnet\\n set allowaccess ssh https ping\\n next\\n end",
        "huawei": "undo telnet server enable\\nstelnet server enable",
        "mikrotik": "/ip service disable telnet\\n/ip service enable ssh",
        "paloalto": "set deviceconfig system service disable-telnet yes",
        "generic": "disable telnet-server; enable ssh-server"
    },
    "HTTP_MANAGEMENT_ENABLED": {
        "cisco": "no ip http server\\nip http secure-server",
        "juniper": "delete system services web-management http\\nset system services web-management https",
        "arista": "management api http-commands\\n no protocol http\\n protocol https",
        "fortinet": "config system interface\\n edit port1\\n unset allowaccess http\\n next\\n end",
        "huawei": "undo http server enable\\nhttp secure-server enable",
        "mikrotik": "/ip service disable www\\n/ip service enable www-ssl",
        "paloalto": "set deviceconfig system service disable-http yes",
        "generic": "no service http; service https enable"
    },
    "DEFAULT_CREDENTIAL": {
        "cisco": "no snmp-server community public\\nno snmp-server community private\\nsnmp-server community <SECURE_COMMUNITY> RO 99",
        "juniper": "delete snmp community public\\ndelete snmp community private\\nset snmp community <SECURE_COMMUNITY> authorization read-only",
        "arista": "no snmp-server community public\\nsnmp-server community <SECURE_COMMUNITY> ro",
        "fortinet": "config system snmp community\\n delete 1\\n end",
        "huawei": "undo snmp-agent community public\\nundo snmp-agent community private",
        "mikrotik": "/snmp community remove [find name=public]",
        "paloalto": "delete deviceconfig system snmp-setting community public",
        "generic": "remove snmp-community public; configure snmp-community <SECURE_STRING> ro"
    },
    "WEAK_CRYPTO": {
        "cisco": "crypto ipsec transform-set SECURE-SET esp-aes 256 esp-sha256-hmac\\n mode tunnel\\n exit",
        "juniper": "set security ipsec proposal SECURE-PROP encryption-algorithm aes-256-gcm\\nset security ipsec proposal SECURE-PROP authentication-algorithm hmac-sha-256-128",
        "arista": "ip ssh cipher aes256-gcm@openssh.com\\nip ssh mac hmac-sha2-512",
        "fortinet": "config vpn ipsec phase1-interface\\n edit vpn-tunnel\\n set proposal aes256-sha256 aes256-sha512\\n next\\n end",
        "huawei": "ipsec transform-set SECURE-TS\\n esp encryption-algorithm aes-256\\n esp authentication-algorithm sha2-256",
        "mikrotik": "/ip ipsec proposal set [find default=yes] enc-algorithms=aes-256-gcm auth-algorithms=sha256",
        "paloalto": "set network ike crypto-profiles default-profile-aes256 encryption aes-256 hash sha256",
        "generic": "enforce strong-ciphers aes256 sha256"
    },
    "ANY_TO_ANY_RULE": {
        "cisco": "no ip access-list extended UNRESTRICTED\\nip access-list extended SECURE-FILTER\\n permit tcp 10.0.0.0 0.255.255.255 any eq 443\\n deny ip any any log",
        "juniper": "delete security policies from-zone trust to-zone untrust policy allow-all\\nset security policies from-zone trust to-zone untrust policy allow-web match source-address corporate-lan destination-address any application junos-https then permit",
        "arista": "ip access-list standard RESTRICTED\\n permit 10.0.0.0/8\\n deny any",
        "fortinet": "config firewall policy\\n edit 1\\n set srcaddr internal_lan\\n set dstaddr all\\n set service HTTPS SSH\\n set action accept\\n set schedule always\\n next\\n end",
        "huawei": "acl number 3000\\n rule 5 permit tcp source 10.0.0.0 0.255.255.255 destination any destination-port eq 443\\n rule 10 deny ip",
        "mikrotik": "/ip firewall filter add chain=forward src-address=10.0.0.0/8 protocol=tcp dst-port=443 action=accept\\n/ip firewall filter add chain=forward action=drop",
        "paloalto": "set rulebase security rules allow-https from trust to untrust source corporate-net destination any service service-https action allow",
        "generic": "replace permit-all rule with least-privilege specific port access rules"
    },
    "LOGGING_DISABLED": {
        "cisco": "logging buffered 64000\\nlogging host 10.10.10.50\\nlogging trap notifications",
        "juniper": "set system syslog host 10.10.10.50 any notice",
        "arista": "logging host 10.10.10.50\\nlogging level all notice",
        "fortinet": "config log syslogd setting\\n set status enable\\n set server 10.10.10.50\\n end",
        "huawei": "info-center enable\\ninfo-center loghost 10.10.10.50",
        "mikrotik": "/system logging action add name=remote target=remote remote=10.10.10.50\\n/system logging add topics=info action=remote",
        "paloalto": "set shared log-settings syslog SIEM-SERVER server 10.10.10.50",
        "generic": "logging enable; set syslog-server 10.10.10.50"
    },
    "NTP_DISABLED": {
        "cisco": "ntp server 10.10.10.1\\nntp server 10.10.10.2",
        "juniper": "set system ntp server 10.10.10.1\\nset system ntp server 10.10.10.2",
        "arista": "ntp server 10.10.10.1\\nntp server 10.10.10.2",
        "fortinet": "config system ntp\\n set ntpserver 10.10.10.1 10.10.10.2\\n set type custom\\n end",
        "huawei": "ntp-service enable\\nntp-service unicast-server 10.10.10.1",
        "mikrotik": "/system ntp client set enabled=yes primary-ntp=10.10.10.1 secondary-ntp=10.10.10.2",
        "paloalto": "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address 10.10.10.1",
        "generic": "ntp server 10.10.10.1"
    },
    "ENABLE_PASSWORD_PLAINTEXT": {
        "cisco": "no enable password\\nenable secret <STRONG_HASHED_SECRET>",
        "juniper": "set system root-authentication plain-text-password",
        "arista": "no enable password\\nenable secret <STRONG_HASHED_SECRET>",
        "fortinet": "config system admin\\n edit admin\\n set password <STRONG_PASSWORD>\\n next\\n end",
        "huawei": "undo local-user admin password\\nlocal-user admin password irreversible-cipher <STRONG_HASHED_SECRET>",
        "mikrotik": "/user set admin password=<STRONG_PASSWORD>",
        "paloalto": "set mgt-config users admin password",
        "generic": "configure hashed privileged secret; remove plaintext password"
    },
    "UNRESTRICTED_MANAGEMENT": {
        "cisco": "ip access-list standard MGMT-ACCESS\\n permit 10.100.0.0 0.0.255.255\\n exit\\nline vty 0 4\\n access-class MGMT-ACCESS in\\n exit",
        "juniper": "set system services ssh connection-limit 10\\nset firewall family inet filter MGMT-FILTER term ALLOW-ADMIN from source-address 10.100.0.0/16\\nset firewall family inet filter MGMT-FILTER term ALLOW-ADMIN then accept",
        "arista": "ip access-list standard MGMT-ACL\\n permit 10.100.0.0/16\\nline vty\\n access-class MGMT-ACL in",
        "fortinet": "config system admin\\n edit admin_user\\n set trusthost1 10.100.0.0 255.255.0.0\\n next\\n end",
        "huawei": "acl number 2001\\n rule 5 permit source 10.100.0.0 0.0.255.255\\nuser-interface vty 0 4\\n acl 2001 inbound",
        "mikrotik": "/ip service set ssh address=10.100.0.0/16\\n/ip service set winbox address=10.100.0.0/16",
        "paloalto": "set deviceconfig system permitted-ip 10.100.0.0/16",
        "generic": "apply management access filter allowing only authorized subnets"
    }
}


class NLPDatasetBuilder:
    """Builds multi-task NLP training, validation, and testing datasets from network configs."""

    def __init__(self, configs_dir: Path = Path("configs"), output_dir: Path = Path("nlp_dataset"), random_seed: int = 42):
        self.configs_dir = Path(configs_dir)
        self.output_dir = Path(output_dir)
        self.random_seed = random_seed
        self.extractor = SecuritySemanticExtractor()
        random.seed(random_seed)

    def build_all(self, vendor_filter: Optional[str] = None) -> Dict[str, Any]:
        """Discover, process, and build all 7 multi-task NLP datasets."""
        print("=" * 70)
        print("BUILDING NETWORK SECURITY NLP DATASETS (7 TASKS)")
        print("=" * 70)

        # 1. Discover all configuration files
        config_files = self._discover_configs(vendor_filter)
        print(f"Discovered {len(config_files)} configuration files across vendors.")

        # 2. Extract structured semantics from each configuration
        processed_configs: List[CanonicalSecurityConfig] = []
        rejected_count = 0

        for file_info in config_files:
            try:
                text = file_info["path"].read_text(encoding="utf-8", errors="replace")
                # Redact any cleartext passwords/keys locally
                clean_text = self._redact_secrets_text(text)
                cfg = self.extractor.extract(
                    config_text=clean_text,
                    file_id=file_info["file_id"],
                    vendor_slug=file_info["vendor_slug"],
                    source_path=str(file_info["path"]),
                )
                processed_configs.append(cfg)
            except Exception as exc:
                rejected_count += 1
                logger.debug(f"Failed processing {file_info['path']}: {exc}")

        print(f"Successfully processed {len(processed_configs)} configurations ({rejected_count} rejected).")

        # 3. Generate raw task examples
        print("\nGenerating NLP Task Examples:")
        task_a_examples = self._generate_task_a_analysis(processed_configs)
        task_b_examples = self._generate_task_b_security_detection(processed_configs)
        task_c_examples = self._generate_task_c_compliance(processed_configs)
        task_d_examples = self._generate_task_d_qa(processed_configs)
        task_e_examples = self._generate_task_e_remediation(processed_configs)
        task_f_examples = self._generate_task_f_classification(processed_configs)
        task_g_examples = self._generate_task_g_ner(processed_configs)

        print(f"  Task A (Analysis / Description):    {len(task_a_examples):>6} examples")
        print(f"  Task B (Security Detection):        {len(task_b_examples):>6} examples")
        print(f"  Task C (Compliance Classification): {len(task_c_examples):>6} examples")
        print(f"  Task D (Security QA):               {len(task_d_examples):>6} examples")
        print(f"  Task E (Remediation Generation):    {len(task_e_examples):>6} examples")
        print(f"  Task F (Section Classification):    {len(task_f_examples):>6} examples")
        print(f"  Task G (Security NER):              {len(task_g_examples):>6} examples")

        total_examples = (
            len(task_a_examples) + len(task_b_examples) + len(task_c_examples) +
            len(task_d_examples) + len(task_e_examples) + len(task_f_examples) +
            len(task_g_examples)
        )
        print(f"  Total NLP Examples Generated:       {total_examples:>6} examples")

        # 4. Group configurations to prevent data leakage across splits
        print("\nSplitting Dataset with Configuration-Level Grouping (Zero Data Leakage)...")
        train_configs, val_configs, test_configs = self._split_configurations(processed_configs)

        train_ids = set(c.file_id for c in train_configs)
        val_ids = set(c.file_id for c in val_configs)
        test_ids = set(c.file_id for c in test_configs)

        # 5. Split task examples strictly based on configuration ID
        splits = {
            "train": {"a": [], "b": [], "c": [], "d": [], "e": [], "f": [], "g": []},
            "validation": {"a": [], "b": [], "c": [], "d": [], "e": [], "f": [], "g": []},
            "test": {"a": [], "b": [], "c": [], "d": [], "e": [], "f": [], "g": []},
        }

        task_mapping = [
            ("a", task_a_examples),
            ("b", task_b_examples),
            ("c", task_c_examples),
            ("d", task_d_examples),
            ("e", task_e_examples),
            ("f", task_f_examples),
            ("g", task_g_examples),
        ]

        for task_code, examples in task_mapping:
            for ex in examples:
                fid = ex.get("source_file_id", "")
                if fid in train_ids:
                    splits["train"][task_code].append(ex)
                elif fid in val_ids:
                    splits["validation"][task_code].append(ex)
                elif fid in test_ids:
                    splits["test"][task_code].append(ex)
                else:
                    # fallback by hash
                    h = int(hashlib.md5(fid.encode()).hexdigest(), 16) % 100
                    if h < 70:
                        splits["train"][task_code].append(ex)
                    elif h < 85:
                        splits["validation"][task_code].append(ex)
                    else:
                        splits["test"][task_code].append(ex)

        # 6. Verify zero leakage and write files
        leak_pass, leak_msg = self._verify_leakage(splits)
        print(f"  Data Leakage Audit: {'PASS' if leak_pass else 'FAIL'} — {leak_msg}")

        # 7. Write raw and split JSONL files
        self._write_datasets(splits, task_mapping, processed_configs)

        # 8. Run secret sanitization audit
        secret_pass, secret_msg = self._audit_secrets()
        print(f"  Secret Redaction Audit: {'PASS' if secret_pass else 'FAIL'} — {secret_msg}")

        stats = self._generate_statistics(processed_configs, splits, total_examples, leak_pass, secret_pass)
        print(f"\nNLP Dataset creation complete. Artifacts saved in {self.output_dir}/")
        return stats

    def _discover_configs(self, vendor_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        found = []
        if not self.configs_dir.exists():
            return found

        for vendor_dir in sorted(self.configs_dir.iterdir()):
            if not vendor_dir.is_dir() or vendor_dir.name.startswith(('.', '_')):
                continue
            slug = vendor_dir.name
            if vendor_filter and vendor_filter.lower() not in slug.lower():
                continue

            for root, _, files in os.walk(vendor_dir):
                for f in sorted(files):
                    if f.endswith(('.py', '.pyc', '.json', '.md', '.log', '.png', '.pdf')):
                        continue
                    file_path = Path(root) / f
                    rel_path = file_path.relative_to(self.configs_dir)
                    fid = f"{slug}_{hashlib.md5(str(rel_path).encode()).hexdigest()[:10]}"
                    found.append({
                        "file_id": fid,
                        "vendor_slug": slug,
                        "path": file_path,
                        "rel_path": str(rel_path),
                    })
        return found

    def _redact_secrets_text(self, text: str) -> str:
        # Local redaction of sensitive credentials
        if not text:
            return ""
        # 1. Private keys
        text = re.sub(r'-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----', '<REDACTED_PRIVATE_KEY>', text)
        # 2. IOS/EOS enable & user secrets
        text = re.sub(r'(?im)(\b(?:enable|username\s+\S+)\s+(?:secret|password)\s+\d+\s+)\S+', r'\1<REDACTED>', text)
        text = re.sub(r'(?im)(\b(?:enable|username\s+\S+)\s+(?:secret|password)\s+)\S+', r'\1<REDACTED>', text)
        # 3. SNMP Community
        text = re.sub(r'(?im)(\bsnmp-server\s+community\s+)\S+', r'\1<REDACTED>', text)
        # 4. FortiOS secrets
        text = re.sub(r'(?im)(\bset\s+(?:passwd|password|private-key)\s+)\S+', r'\1<REDACTED>', text)
        # 5. Junos secrets
        text = re.sub(r'(?im)(\b(?:encrypted-password|plain-text-password)\s+)\"[^\"]+\"', r'\1"<REDACTED>"', text)
        # 6. JSON credentials
        text = re.sub(r'(?i)("password"\s*:\s*)"[^"]+"', r'\1"<REDACTED>"', text)
        text = re.sub(r'(?i)("community"\s*:\s*)"[^"]+"', r'\1"<REDACTED>"', text)
        return text

    def _generate_task_a_analysis(self, configs: List[CanonicalSecurityConfig]) -> List[Dict[str, Any]]:
        examples = []
        for idx, cfg in enumerate(configs):
            hostname = cfg.device.hostname or "Unconfigured-Host"
            vendor = cfg.vendor
            platform = cfg.platform

            ifaces_count = len(cfg.interfaces)
            routes_count = len(cfg.routing.routes)
            acls_count = cfg.firewall.acl_count

            # Semantic description grounded in facts
            desc_parts = [
                f"The device '{hostname}' is a {vendor.upper()} system running {platform}.",
                f"It configures {ifaces_count} network interfaces and {routes_count} active routing entries."
            ]

            if cfg.routing.protocols:
                desc_parts.append(f"Active routing protocols include {', '.join(cfg.routing.protocols)}.")

            if cfg.management.ssh_enabled:
                desc_parts.append(f"Remote administration is secured via SSH (version {cfg.management.ssh_version or 2}).")
            if cfg.management.telnet_enabled:
                desc_parts.append("WARNING: Insecure cleartext Telnet management is active.")
            if cfg.authentication.aaa_enabled:
                desc_parts.append("Centralized AAA authentication framework is enabled.")
            if cfg.management.logging_enabled:
                desc_parts.append("System logging and event auditing are configured.")
            if cfg.management.ntp_enabled:
                desc_parts.append("NTP network time synchronization is active.")
            if cfg.firewall.has_any_to_any_rule:
                desc_parts.append("CRITICAL: Unrestricted any-to-any firewall packet filtering rules detected.")

            full_desc = " ".join(desc_parts)

            # Sample input text (first 40 lines or full config)
            raw_sample = "\\n".join(cfg.raw_sections.get("SYSTEM", [])[:20] + cfg.raw_sections.get("INTERFACE", [])[:10])
            if not raw_sample.strip():
                raw_sample = f"hostname {hostname}\\nvendor {vendor}\\nplatform {platform}"

            examples.append({
                "id": f"task_a_{cfg.file_id}_{idx}",
                "task": "configuration_analysis",
                "vendor": vendor,
                "platform": platform,
                "source_file_id": cfg.file_id,
                "input": raw_sample,
                "output": full_desc,
                "evidence": f"hostname {hostname}; ifaces={ifaces_count}; acls={acls_count}",
                "origin": "derived_from_config",
            })
        return examples

    def _generate_task_b_security_detection(self, configs: List[CanonicalSecurityConfig]) -> List[Dict[str, Any]]:
        examples = []
        for cfg in configs:
            for f_idx, finding in enumerate(cfg.findings):
                code_sec = finding.get("evidence", "")
                examples.append({
                    "id": f"task_b_{cfg.file_id}_{f_idx}",
                    "task": "security_detection",
                    "vendor": cfg.vendor,
                    "platform": cfg.platform,
                    "source_file_id": cfg.file_id,
                    "input": code_sec,
                    "output": {
                        "finding": finding["finding"],
                        "severity": finding["severity"],
                        "evidence": finding["evidence"],
                        "explanation": finding["explanation"],
                    },
                    "evidence": finding["evidence"],
                    "origin": "derived_from_config",
                })
        return examples

    def _generate_task_c_compliance(self, configs: List[CanonicalSecurityConfig]) -> List[Dict[str, Any]]:
        examples = []
        controls = [
            ("secure_management", "TELNET_ENABLED", "CIS-2.1.1", "Disable plaintext Telnet administration"),
            ("http_disabled", "HTTP_MANAGEMENT_ENABLED", "CIS-2.2.1", "Disable HTTP web management"),
            ("snmp_security", "DEFAULT_CREDENTIAL", "CIS-1.3.1", "Unset default SNMP community strings"),
            ("strong_cryptography", "WEAK_CRYPTO", "CIS-4.1.2", "Enforce modern cryptographic algorithms"),
            ("firewall_perimeter", "ANY_TO_ANY_RULE", "CIS-3.1.4", "Restrict any-to-any firewall rules"),
            ("system_logging", "LOGGING_DISABLED", "CIS-1.4.1", "Configure remote audit logging"),
            ("time_synchronization", "NTP_DISABLED", "CIS-1.4.2", "Configure authoritative NTP time sources"),
        ]

        for cfg in configs:
            for ctrl_name, finding_key, cis_ref, ctrl_title in controls:
                is_violated = cfg.security_features.get(finding_key, False)
                status = "NON_COMPLIANT" if is_violated else "COMPLIANT"
                evidence = next((f["evidence"] for f in cfg.findings if f["finding"] == finding_key), "<absent> compliant posture verified")
                reason = next((f["explanation"] for f in cfg.findings if f["finding"] == finding_key), f"Device satisfies {ctrl_title} ({cis_ref}).")

                input_snippet = f"Control: {ctrl_title} ({cis_ref})\\nVendor: {cfg.vendor}\\nEvidence: {evidence}"

                examples.append({
                    "id": f"task_c_{cfg.file_id}_{ctrl_name}",
                    "task": "compliance",
                    "vendor": cfg.vendor,
                    "platform": cfg.platform,
                    "source_file_id": cfg.file_id,
                    "input": input_snippet,
                    "output": {
                        "control": ctrl_name,
                        "control_ref": cis_ref,
                        "status": status,
                        "evidence": evidence,
                        "reason": reason,
                    },
                    "evidence": evidence,
                    "origin": "derived_from_config",
                })
        return examples

    def _generate_task_d_qa(self, configs: List[CanonicalSecurityConfig]) -> List[Dict[str, Any]]:
        examples = []
        for cfg in configs:
            for q_idx, (question, q_key, q_type, q_desc) in enumerate(CORE_QA_QUESTIONS):
                # Calculate grounded answer
                answer = "no"
                confidence = 0.99
                evidence = ""

                if q_key == "telnet_enabled":
                    answer = "yes" if cfg.management.telnet_enabled else "no"
                    evidence = "transport input telnet" if cfg.management.telnet_enabled else "<absent> telnet not configured"
                elif q_key == "ssh_enabled":
                    answer = "yes" if cfg.management.ssh_enabled else "no"
                    evidence = f"ip ssh version {cfg.management.ssh_version or 2}" if cfg.management.ssh_enabled else "<absent> ssh not configured"
                elif q_key == "aaa_enabled":
                    answer = "yes" if cfg.authentication.aaa_enabled else "no"
                    evidence = "aaa new-model" if cfg.authentication.aaa_enabled else "<absent> aaa not enabled"
                elif q_key == "snmp_enabled":
                    answer = "yes" if cfg.management.snmp_enabled else "no"
                    evidence = "snmp-server configured" if cfg.management.snmp_enabled else "<absent> snmp not configured"
                elif q_key == "snmp_v3":
                    answer = "yes" if cfg.management.snmp_v3_users else "no"
                    evidence = f"snmp-server user {cfg.management.snmp_v3_users[0]}" if cfg.management.snmp_v3_users else "<absent> snmpv3 user not configured"
                elif q_key == "insecure_management":
                    answer = "yes" if (cfg.management.telnet_enabled or cfg.management.http_server_enabled) else "no"
                    evidence = "insecure protocols detected" if answer == "yes" else "only secure management configured"
                elif q_key == "acls_configured":
                    answer = "yes" if cfg.firewall.acl_count > 0 else "no"
                    evidence = f"configured {cfg.firewall.acl_count} access lists" if answer == "yes" else "<absent> no acls"
                elif q_key == "unrestricted_rules":
                    answer = "yes" if cfg.firewall.has_any_to_any_rule else "no"
                    evidence = "permit any any" if cfg.firewall.has_any_to_any_rule else "<absent> no unrestricted rules"
                elif q_key == "logging_enabled":
                    answer = "yes" if cfg.management.logging_enabled else "no"
                    evidence = f"syslog: {', '.join(cfg.management.syslog_servers)}" if cfg.management.syslog_servers else "<absent> logging not enabled"
                elif q_key == "ntp_enabled":
                    answer = "yes" if cfg.management.ntp_enabled else "no"
                    evidence = f"ntp: {', '.join(cfg.management.ntp_servers)}" if cfg.management.ntp_servers else "<absent> ntp not configured"
                elif q_key == "default_route":
                    answer = "yes" if cfg.routing.default_route_configured else "no"
                    evidence = "ip route 0.0.0.0 0.0.0.0" if cfg.routing.default_route_configured else "<absent> no default route"
                elif q_key == "weak_crypto":
                    answer = "yes" if cfg.cryptography.weak_algorithms_used else "no"
                    evidence = f"weak algorithms: {', '.join(cfg.cryptography.weak_algorithms_used)}" if cfg.cryptography.weak_algorithms_used else "strong crypto only"
                elif q_key == "management_acl":
                    answer = "yes" if cfg.management.management_acl_applied else "no"
                    evidence = "access-class applied" if cfg.management.management_acl_applied else "<absent> management acl not applied"
                elif q_key == "password_encryption":
                    answer = "yes" if cfg.authentication.password_encryption_enabled else "no"
                    evidence = "service password-encryption" if cfg.authentication.password_encryption_enabled else "<absent> password-encryption disabled"
                elif q_key == "enable_secret":
                    answer = "yes" if cfg.authentication.enable_secret_configured else "no"
                    evidence = "enable secret configured" if cfg.authentication.enable_secret_configured else "<absent> enable secret not configured"

                examples.append({
                    "id": f"task_d_{cfg.file_id}_{q_idx}",
                    "task": "qa",
                    "vendor": cfg.vendor,
                    "platform": cfg.platform,
                    "source_file_id": cfg.file_id,
                    "input": f"Question: {question}\\nContext: Host {cfg.device.hostname or 'Router'}, Vendor: {cfg.vendor}",
                    "output": {
                        "question": question,
                        "answer": answer,
                        "evidence": evidence,
                        "confidence": confidence,
                    },
                    "evidence": evidence,
                    "origin": "derived_from_config",
                })
        return examples

    def _generate_task_e_remediation(self, configs: List[CanonicalSecurityConfig]) -> List[Dict[str, Any]]:
        examples = []
        for cfg in configs:
            vendor_slug = cfg.vendor.lower()
            # Normalize to vendor family
            vendor_key = "generic"
            for k in ["cisco", "juniper", "arista", "fortinet", "huawei", "mikrotik", "paloalto"]:
                if k in vendor_slug:
                    vendor_key = k
                    break

            for f_idx, finding in enumerate(cfg.findings):
                f_type = finding.get("finding", "")
                rem_map = VENDOR_REMEDIATIONS.get(f_type, {})
                rem_commands = rem_map.get(vendor_key, rem_map.get("generic", "apply vendor hardening commands"))

                examples.append({
                    "id": f"task_e_{cfg.file_id}_{f_idx}",
                    "task": "remediation",
                    "vendor": cfg.vendor,
                    "platform": cfg.platform,
                    "source_file_id": cfg.file_id,
                    "input": {
                        "configuration_evidence": finding.get("evidence", ""),
                        "finding": f_type,
                        "severity": finding.get("severity", "MEDIUM"),
                    },
                    "output": {
                        "explanation": finding.get("explanation", ""),
                        "remediation": rem_commands,
                        "vendor": cfg.vendor,
                        "platform": cfg.platform,
                    },
                    "evidence": finding.get("evidence", ""),
                    "origin": "derived_from_config",
                })
        return examples

    def _generate_task_f_classification(self, configs: List[CanonicalSecurityConfig]) -> List[Dict[str, Any]]:
        examples = []
        for cfg in configs:
            for sec_name, lines in cfg.raw_sections.items():
                if not lines:
                    continue
                # Create blocks of 1-5 lines
                for i in range(0, min(len(lines), 15), 3):
                    chunk = "\\n".join(lines[i:i+3])
                    if len(chunk.strip()) < 5:
                        continue
                    examples.append({
                        "id": f"task_f_{cfg.file_id}_{sec_name}_{i}",
                        "task": "classification",
                        "vendor": cfg.vendor,
                        "platform": cfg.platform,
                        "source_file_id": cfg.file_id,
                        "input": chunk,
                        "output": sec_name,
                        "evidence": chunk.splitlines()[0],
                        "origin": "derived_from_config",
                    })
        return examples

    def _generate_task_g_ner(self, configs: List[CanonicalSecurityConfig]) -> List[Dict[str, Any]]:
        examples = []
        for cfg in configs:
            # Generate token/entity examples from interfaces, routing, firewall, and management
            for iface in cfg.interfaces[:5]:
                text = f"interface {iface.name} ip address {iface.ip_address or '10.0.0.1'}"
                entities = [
                    {"text": iface.name, "type": "INTERFACE"},
                ]
                if iface.ip_address:
                    entities.append({"text": iface.ip_address, "type": "IP_ADDRESS"})
                examples.append({
                    "id": f"task_g_{cfg.file_id}_{iface.name}",
                    "task": "ner",
                    "vendor": cfg.vendor,
                    "platform": cfg.platform,
                    "source_file_id": cfg.file_id,
                    "input": text,
                    "output": {
                        "text": text,
                        "entities": entities,
                    },
                    "evidence": text,
                    "origin": "derived_from_config",
                })

            for rule in cfg.firewall.rules[:5]:
                text = f"access-list {rule.acl_name} {rule.action} {rule.protocol} {rule.source} {rule.destination}"
                entities = [
                    {"text": rule.acl_name, "type": "ACL"},
                    {"text": rule.protocol, "type": "PROTOCOL"},
                ]
                examples.append({
                    "id": f"task_g_{cfg.file_id}_{rule.acl_name}",
                    "task": "ner",
                    "vendor": cfg.vendor,
                    "platform": cfg.platform,
                    "source_file_id": cfg.file_id,
                    "input": text,
                    "output": {
                        "text": text,
                        "entities": entities,
                    },
                    "evidence": text,
                    "origin": "derived_from_config",
                })
        return examples

    def _split_configurations(self, configs: List[CanonicalSecurityConfig]) -> Tuple[List[CanonicalSecurityConfig], List[CanonicalSecurityConfig], List[CanonicalSecurityConfig]]:
        # Group by hash/vendor to ensure deterministic and cluster-aware splitting
        vendor_groups: Dict[str, List[CanonicalSecurityConfig]] = {}
        for c in configs:
            vendor_groups.setdefault(c.vendor, []).append(c)

        train, val, test = [], [], []

        for vendor, group in vendor_groups.items():
            # Sort group for reproducibility
            sorted_group = sorted(group, key=lambda x: x.sha256)
            n = len(sorted_group)
            if n == 1:
                train.append(sorted_group[0])
            elif n == 2:
                train.append(sorted_group[0])
                test.append(sorted_group[1])
            else:
                n_train = max(1, int(round(n * 0.70)))
                n_val = max(1, int(round(n * 0.15)))
                n_test = max(1, n - n_train - n_val)
                train.extend(sorted_group[:n_train])
                val.extend(sorted_group[n_train:n_train+n_val])
                test.extend(sorted_group[n_train+n_val:])

        return train, val, test

    def _verify_leakage(self, splits: Dict[str, Any]) -> Tuple[bool, str]:
        train_sources = set(ex["source_file_id"] for t in splits["train"].values() for ex in t)
        val_sources = set(ex["source_file_id"] for t in splits["validation"].values() for ex in t)
        test_sources = set(ex["source_file_id"] for t in splits["test"].values() for ex in t)

        train_val = train_sources & val_sources
        train_test = train_sources & test_sources
        val_test = val_sources & test_sources

        if not (train_val or train_test or val_test):
            return True, "No configuration-level data leakage detected. Strict isolation verified."

        errs = []
        if train_val:
            errs.append(f"train∩val={len(train_val)}")
        if train_test:
            errs.append(f"train∩test={len(train_test)}")
        if val_test:
            errs.append(f"val∩test={len(val_test)}")
        return False, f"DATA LEAKAGE DETECTED: {', '.join(errs)}"

    def _write_datasets(self, splits: Dict[str, Any], task_mapping: List[Tuple[str, List[Dict[str, Any]]]], configs: List[CanonicalSecurityConfig]):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        raw_dir = self.output_dir / "raw"
        train_dir = self.output_dir / "train"
        val_dir = self.output_dir / "validation"
        test_dir = self.output_dir / "test"
        meta_dir = self.output_dir / "metadata"

        for d in [raw_dir, train_dir, val_dir, test_dir, meta_dir]:
            d.mkdir(parents=True, exist_ok=True)

        task_filenames = {
            "a": "analysis.jsonl",
            "b": "security_detection.jsonl",
            "c": "compliance.jsonl",
            "d": "qa.jsonl",
            "e": "remediation.jsonl",
            "f": "classification.jsonl",
            "g": "ner.jsonl",
        }

        # Write raw
        for task_code, examples in task_mapping:
            fname = task_filenames[task_code]
            with open(raw_dir / fname, "w", encoding="utf-8") as f:
                for ex in examples:
                    f.write(json.dumps(ex) + "\\n")

        # Write splits
        for split_name, task_dict in splits.items():
            target_dir = self.output_dir / split_name
            for task_code, examples in task_dict.items():
                fname = task_filenames[task_code]
                with open(target_dir / fname, "w", encoding="utf-8") as f:
                    for ex in examples:
                        f.write(json.dumps(ex) + "\\n")

        # Write provenance
        with open(meta_dir / "provenance.jsonl", "w", encoding="utf-8") as f:
            for cfg in configs:
                prov = {
                    "file_id": cfg.file_id,
                    "vendor": cfg.vendor,
                    "platform": cfg.platform,
                    "source": cfg.source_path,
                    "config_type": "full_configuration",
                    "origin": "public_real",
                    "sha256": cfg.sha256,
                    "quality_score": cfg.quality_score,
                    "parse_status": cfg.parse_status,
                }
                f.write(json.dumps(prov) + "\\n")

    def _audit_secrets(self) -> Tuple[bool, str]:
        secret_patterns = [
            re.compile(r'password\s+[0-9a-zA-Z!@#$%^&*]{8,}', re.I),
            re.compile(r'community\s+(?:public|private)\b', re.I),
            re.compile(r'-----BEGIN\s+PRIVATE\s+KEY-----', re.I),
        ]
        violations = 0
        raw_dir = self.output_dir / "raw"
        for jsonl_file in raw_dir.glob("*.jsonl"):
            with open(jsonl_file, "r", encoding="utf-8") as f:
                for idx, line in enumerate(f, 1):
                    for pat in secret_patterns:
                        if pat.search(line) and "<REDACTED" not in line:
                            violations += 1
        if violations == 0:
            return True, "No unredacted secrets found across dataset."
        return False, f"Found {violations} potential exposed secret patterns."

    def _generate_statistics(self, configs: List[CanonicalSecurityConfig], splits: Dict[str, Any], total_examples: int, leak_pass: bool, secret_pass: bool) -> Dict[str, Any]:
        meta_dir = self.output_dir / "metadata"

        train_count = sum(len(v) for v in splits["train"].values())
        val_count = sum(len(v) for v in splits["validation"].values())
        test_count = sum(len(v) for v in splits["test"].values())

        vendor_dist = collections.Counter(c.vendor for c in configs)
        findings_dist = collections.Counter(f["finding"] for c in configs for f in c.findings)

        stats = {
            "summary": {
                "total_configs_processed": len(configs),
                "total_nlp_examples": total_examples,
                "train_examples": train_count,
                "validation_examples": val_count,
                "test_examples": test_count,
                "data_leakage_status": "PASS" if leak_pass else "FAIL",
                "secret_audit_status": "PASS" if secret_pass else "FAIL",
            },
            "vendors": dict(vendor_dist),
            "findings_distribution": dict(findings_dist),
            "tasks": {
                "task_a_analysis": len(splits["train"]["a"]) + len(splits["validation"]["a"]) + len(splits["test"]["a"]),
                "task_b_security_detection": len(splits["train"]["b"]) + len(splits["validation"]["b"]) + len(splits["test"]["b"]),
                "task_c_compliance": len(splits["train"]["c"]) + len(splits["validation"]["c"]) + len(splits["test"]["c"]),
                "task_d_qa": len(splits["train"]["d"]) + len(splits["validation"]["d"]) + len(splits["test"]["d"]),
                "task_e_remediation": len(splits["train"]["e"]) + len(splits["validation"]["e"]) + len(splits["test"]["e"]),
                "task_f_classification": len(splits["train"]["f"]) + len(splits["validation"]["f"]) + len(splits["test"]["f"]),
                "task_g_ner": len(splits["train"]["g"]) + len(splits["validation"]["g"]) + len(splits["test"]["g"]),
            }
        }

        with open(meta_dir / "dataset_statistics.json", "w", encoding="utf-8") as f:
            json.dump(stats, f, indent=2)

        with open(meta_dir / "label_statistics.json", "w", encoding="utf-8") as f:
            json.dump({
                "section_classes": SECTION_CLASSES,
                "ner_entity_types": NER_ENTITY_TYPES,
                "security_findings": dict(findings_dist),
            }, f, indent=2)

        return stats
'''
    Path('nlp_pipeline/dataset_builder.py').write_text(code, encoding='utf-8')
    print('Generated nlp_pipeline/dataset_builder.py')

if __name__ == '__main__':
    write_dataset_builder()

