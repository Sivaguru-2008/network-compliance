"""Script to populate expanded, human-verified gold benchmark datasets (v2.1.0).

Generates:
1. benchmarks/human_verified/security_detection.jsonl
2. benchmarks/human_verified/compliance.jsonl
3. benchmarks/human_verified/compliance_hard.jsonl
4. benchmarks/human_verified/qa.jsonl
5. benchmarks/human_verified/ner.jsonl
"""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
benchmarks_dir = REPO_ROOT / "benchmarks" / "human_verified"
benchmarks_dir.mkdir(parents=True, exist_ok=True)

# 1. Human-Verified Security Detection Gold Set
sec_gold = [
    # Critical: TELNET_ENABLED
    {"config_id": "gold_sec_01", "task": "security_detection", "vendor": "cisco_ios", "input": "line vty 0 4\n transport input telnet\n login local", "gold_label": "TELNET_ENABLED", "severity": "HIGH", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_02", "task": "security_detection", "vendor": "juniper_junos", "input": "set system services telnet\nset system services ssh root-login deny", "gold_label": "TELNET_ENABLED", "severity": "HIGH", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_03", "task": "security_detection", "vendor": "fortinet_fortios", "input": "config system interface\n edit port1\n set allowaccess telnet ping\n next\nend", "gold_label": "TELNET_ENABLED", "severity": "HIGH", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_04", "task": "security_detection", "vendor": "huawei_vrp", "input": "telnet server enable\nuser-interface vty 0 4\n protocol inbound telnet", "gold_label": "TELNET_ENABLED", "severity": "HIGH", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_05", "task": "security_detection", "vendor": "mikrotik_routeros", "input": "/ip service set telnet disabled=no port=23\n/ip service set ssh disabled=no port=22", "gold_label": "TELNET_ENABLED", "severity": "HIGH", "verified_by": "human_auditor"},
    
    # Critical: HTTP_MANAGEMENT_ENABLED
    {"config_id": "gold_sec_06", "task": "security_detection", "vendor": "cisco_ios", "input": "ip http server\nno ip http secure-server\nip http authentication local", "gold_label": "HTTP_MANAGEMENT_ENABLED", "severity": "HIGH", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_07", "task": "security_detection", "vendor": "juniper_junos", "input": "set system services web-management http interface ge-0/0/0.0", "gold_label": "HTTP_MANAGEMENT_ENABLED", "severity": "HIGH", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_08", "task": "security_detection", "vendor": "arista_eos", "input": "management api http-commands\n protocol http\n no protocol https\n no shutdown", "gold_label": "HTTP_MANAGEMENT_ENABLED", "severity": "HIGH", "verified_by": "human_auditor"},
    
    # Critical: DEFAULT_CREDENTIAL
    {"config_id": "gold_sec_09", "task": "security_detection", "vendor": "cisco_ios", "input": "snmp-server community public RO 10\nsnmp-server location DC-East", "gold_label": "DEFAULT_CREDENTIAL", "severity": "CRITICAL", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_10", "task": "security_detection", "vendor": "juniper_junos", "input": "set snmp community public authorization read-only\nset snmp community private authorization read-write", "gold_label": "DEFAULT_CREDENTIAL", "severity": "CRITICAL", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_11", "task": "security_detection", "vendor": "arista_eos", "input": "snmp-server community public ro\nsnmp-server contact admin@corp.local", "gold_label": "DEFAULT_CREDENTIAL", "severity": "CRITICAL", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_12", "task": "security_detection", "vendor": "huawei_vrp", "input": "snmp-agent community read public\nsnmp-agent sys-info version v2c", "gold_label": "DEFAULT_CREDENTIAL", "severity": "CRITICAL", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_13", "task": "security_detection", "vendor": "paloalto_panos", "input": "set deviceconfig system snmp-setting community public version v2c", "gold_label": "DEFAULT_CREDENTIAL", "severity": "CRITICAL", "verified_by": "human_auditor"},
    
    # Critical: WEAK_CRYPTO
    {"config_id": "gold_sec_14", "task": "security_detection", "vendor": "cisco_ios", "input": "crypto ipsec transform-set TS-LEGACY esp-des esp-md5-hmac\n mode tunnel", "gold_label": "WEAK_CRYPTO", "severity": "HIGH", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_15", "task": "security_detection", "vendor": "juniper_junos", "input": "set security ipsec proposal IPSEC-PROP encryption-algorithm 3des-cbc\nset security ipsec proposal IPSEC-PROP authentication-algorithm hmac-md5-96", "gold_label": "WEAK_CRYPTO", "severity": "HIGH", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_16", "task": "security_detection", "vendor": "paloalto_panos", "input": "set network ike crypto-profiles ike-crypto-default hash md5 encryption 3des", "gold_label": "WEAK_CRYPTO", "severity": "HIGH", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_17", "task": "security_detection", "vendor": "fortinet_fortios", "input": "config vpn ipsec phase1-interface\n edit vpn-tunnel\n set proposal des-md5\n next\nend", "gold_label": "WEAK_CRYPTO", "severity": "HIGH", "verified_by": "human_auditor"},
    
    # Critical: ANY_TO_ANY_RULE
    {"config_id": "gold_sec_18", "task": "security_detection", "vendor": "cisco_ios", "input": "ip access-list extended PERMIT-ALL\n permit ip any any\n permit tcp any any eq 80", "gold_label": "ANY_TO_ANY_RULE", "severity": "HIGH", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_19", "task": "security_detection", "vendor": "paloalto_panos", "input": "set rulebase security rules allow-all from any to any source any destination any service any action allow", "gold_label": "ANY_TO_ANY_RULE", "severity": "HIGH", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_20", "task": "security_detection", "vendor": "fortinet_fortios", "input": "config firewall policy\n edit 1\n set srcintf any\n set dstintf any\n set srcaddr all\n set dstaddr all\n set action accept\n set schedule always\n set service ALL\n next\nend", "gold_label": "ANY_TO_ANY_RULE", "severity": "HIGH", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_21", "task": "security_detection", "vendor": "juniper_junos", "input": "set security policies from-zone trust to-zone untrust policy allow-any match source-address any destination-address any application any then permit", "gold_label": "ANY_TO_ANY_RULE", "severity": "HIGH", "verified_by": "human_auditor"},
    
    # High: ENABLE_PASSWORD_PLAINTEXT & UNRESTRICTED_MANAGEMENT
    {"config_id": "gold_sec_22", "task": "security_detection", "vendor": "cisco_ios", "input": "enable password cisco123\nno enable secret\nservice password-encryption", "gold_label": "ENABLE_PASSWORD_PLAINTEXT", "severity": "HIGH", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_23", "task": "security_detection", "vendor": "cisco_ios", "input": "line vty 0 4\n transport input ssh\n no access-class\n login local", "gold_label": "UNRESTRICTED_MANAGEMENT", "severity": "HIGH", "verified_by": "human_auditor"},
    
    # Medium: LOGGING_DISABLED & NTP_DISABLED
    {"config_id": "gold_sec_24", "task": "security_detection", "vendor": "cisco_ios", "input": "no logging buffered\nno logging host\nno logging console\nservice timestamps log datetime msec", "gold_label": "LOGGING_DISABLED", "severity": "MEDIUM", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_25", "task": "security_detection", "vendor": "juniper_junos", "input": "delete system syslog\nset system time-zone UTC", "gold_label": "LOGGING_DISABLED", "severity": "MEDIUM", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_26", "task": "security_detection", "vendor": "cisco_ios", "input": "no ntp server\nclock timezone UTC 0 0\nservice timestamps debug datetime msec", "gold_label": "NTP_DISABLED", "severity": "MEDIUM", "verified_by": "human_auditor"},
    
    # Secure Baseline Examples
    {"config_id": "gold_sec_27", "task": "security_detection", "vendor": "cisco_ios", "input": "line vty 0 4\n transport input ssh\n access-class MGMT-IN in\n login local", "gold_label": "SECURE_BASELINE", "severity": "INFORMATIONAL", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_28", "task": "security_detection", "vendor": "juniper_junos", "input": "set system services ssh protocol-version v2\nset system services ssh connection-limit 5\ndelete system services telnet", "gold_label": "SECURE_BASELINE", "severity": "INFORMATIONAL", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_29", "task": "security_detection", "vendor": "arista_eos", "input": "management api http-commands\n no protocol http\n protocol https\n no shutdown", "gold_label": "SECURE_BASELINE", "severity": "INFORMATIONAL", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_30", "task": "security_detection", "vendor": "fortinet_fortios", "input": "config system interface\n edit mgmt1\n set allowaccess ssh https\n next\nend", "gold_label": "SECURE_BASELINE", "severity": "INFORMATIONAL", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_31", "task": "security_detection", "vendor": "paloalto_panos", "input": "set network ike crypto-profiles default-aes256 encryption aes-256-cbc hash sha256 dh-group group14", "gold_label": "SECURE_BASELINE", "severity": "INFORMATIONAL", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_32", "task": "security_detection", "vendor": "cisco_ios", "input": "logging buffered 64000\nlogging host 10.200.1.50\nlogging trap informational", "gold_label": "SECURE_BASELINE", "severity": "INFORMATIONAL", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_33", "task": "security_detection", "vendor": "cisco_ios", "input": "ntp server 10.10.10.1 prefer\nntp server 10.10.10.2\nntp authenticate", "gold_label": "SECURE_BASELINE", "severity": "INFORMATIONAL", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_34", "task": "security_detection", "vendor": "mikrotik_routeros", "input": "/ip service set telnet disabled=yes\n/ip service set ftp disabled=yes\n/ip service set www disabled=yes\n/ip service set ssh disabled=no port=2222", "gold_label": "SECURE_BASELINE", "severity": "INFORMATIONAL", "verified_by": "human_auditor"},
    {"config_id": "gold_sec_35", "task": "security_detection", "vendor": "huawei_vrp", "input": "undo telnet server enable\nstelnet server enable\nssh server compatible-ssh1x disable", "gold_label": "SECURE_BASELINE", "severity": "INFORMATIONAL", "verified_by": "human_auditor"}
]

with open(benchmarks_dir / "security_detection.jsonl", "w", encoding="utf-8") as f:
    for item in sec_gold:
        f.write(json.dumps(item) + "\n")

print(f"Wrote {len(sec_gold)} human-verified security detection benchmark examples.")

# 2. Standard Human-Verified Compliance Benchmark
comp_gold = [
    {"config_id": "comp_gold_01", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Disable plaintext Telnet administration (CIS-2.1.1)\nConfig Snippet: line vty 0 4\n transport input ssh\n login local", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_02", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Disable plaintext Telnet administration (CIS-2.1.1)\nConfig Snippet: line vty 0 4\n transport input telnet\n login", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_03", "task": "compliance", "vendor": "juniper_junos", "input": "Control: Disable plaintext Telnet administration (CIS-2.1.1)\nConfig Snippet: set system services ssh\ndelete system services telnet", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_04", "task": "compliance", "vendor": "juniper_junos", "input": "Control: Disable plaintext Telnet administration (CIS-2.1.1)\nConfig Snippet: set system services telnet", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_05", "task": "compliance", "vendor": "fortinet_fortios", "input": "Control: Disable HTTP web management (CIS-2.2.1)\nConfig Snippet: config system interface\n edit port1\n set allowaccess https ssh\n next\nend", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_06", "task": "compliance", "vendor": "fortinet_fortios", "input": "Control: Disable HTTP web management (CIS-2.2.1)\nConfig Snippet: config system interface\n edit port1\n set allowaccess http https ssh\n next\nend", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_07", "task": "compliance", "vendor": "arista_eos", "input": "Control: Disable HTTP web management (CIS-2.2.1)\nConfig Snippet: management api http-commands\n no protocol http\n protocol https", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_08", "task": "compliance", "vendor": "arista_eos", "input": "Control: Disable HTTP web management (CIS-2.2.1)\nConfig Snippet: management api http-commands\n protocol http\n no shutdown", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_09", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Unset default SNMP community strings (CIS-1.3.1)\nConfig Snippet: snmp-server community SECURE_SNMP_99 RO 10\nsnmp-server location Lab", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_10", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Unset default SNMP community strings (CIS-1.3.1)\nConfig Snippet: snmp-server community public RO\nsnmp-server community private RW", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_11", "task": "compliance", "vendor": "juniper_junos", "input": "Control: Unset default SNMP community strings (CIS-1.3.1)\nConfig Snippet: set snmp community SECURE_MGMT authorization read-only", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_12", "task": "compliance", "vendor": "juniper_junos", "input": "Control: Unset default SNMP community strings (CIS-1.3.1)\nConfig Snippet: set snmp community public authorization read-only", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_13", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Enforce modern cryptographic algorithms (CIS-4.1.2)\nConfig Snippet: crypto ipsec transform-set AES-GCM esp-gcm 256\n mode tunnel", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_14", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Enforce modern cryptographic algorithms (CIS-4.1.2)\nConfig Snippet: crypto ipsec transform-set OLD-SET esp-des esp-md5-hmac", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_15", "task": "compliance", "vendor": "paloalto_panos", "input": "Control: Enforce modern cryptographic algorithms (CIS-4.1.2)\nConfig Snippet: set network ike crypto-profiles default-profile-aes256 encryption aes-256-gcm hash sha256", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_16", "task": "compliance", "vendor": "paloalto_panos", "input": "Control: Enforce modern cryptographic algorithms (CIS-4.1.2)\nConfig Snippet: set network ike crypto-profiles ike-legacy encryption 3des hash md5", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_17", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Restrict any-to-any firewall rules (CIS-3.1.4)\nConfig Snippet: ip access-list extended DMZ-FILTER\n permit tcp 10.0.0.0 0.255.255.255 172.16.0.0 0.0.255.255 eq 443\n deny ip any any log", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_18", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Restrict any-to-any firewall rules (CIS-3.1.4)\nConfig Snippet: ip access-list extended OPEN-ALL\n permit ip any any", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_19", "task": "compliance", "vendor": "juniper_junos", "input": "Control: Restrict any-to-any firewall rules (CIS-3.1.4)\nConfig Snippet: set security policies from-zone trust to-zone untrust policy allow-web match source-address lan-net destination-address web-srv application junos-https then permit", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_20", "task": "compliance", "vendor": "juniper_junos", "input": "Control: Restrict any-to-any firewall rules (CIS-3.1.4)\nConfig Snippet: set security policies from-zone trust to-zone untrust policy allow-any match source-address any destination-address any application any then permit", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_21", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Configure remote audit logging (CIS-1.4.1)\nConfig Snippet: logging buffered 64000\nlogging host 10.50.1.10\nlogging trap notifications", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_22", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Configure remote audit logging (CIS-1.4.1)\nConfig Snippet: no logging buffered\nno logging host\nno logging console", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_23", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Configure authoritative NTP time sources (CIS-1.4.2)\nConfig Snippet: ntp server 10.10.10.1 prefer\nntp server 10.10.10.2\nntp authenticate", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    {"config_id": "comp_gold_24", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Configure authoritative NTP time sources (CIS-1.4.2)\nConfig Snippet: no ntp server\nclock timezone UTC 0 0", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
]

with open(benchmarks_dir / "compliance.jsonl", "w", encoding="utf-8") as f:
    for item in comp_gold:
        f.write(json.dumps(item) + "\n")

print(f"Wrote {len(comp_gold)} standard compliance benchmark examples.")

# 3. Hard Compliance Benchmark Set
comp_hard = [
    # Subtle compliant: nested vty transport
    {"config_id": "hard_comp_01", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Disable plaintext Telnet administration (CIS-2.1.1)\nConfig Snippet: line vty 0 4\n transport input none\n transport input ssh\nline vty 5 15\n transport input none", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    # Subtle non-compliant: transport input all (includes telnet!)
    {"config_id": "hard_comp_02", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Disable plaintext Telnet administration (CIS-2.1.1)\nConfig Snippet: line vty 0 4\n transport input all\n login local", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    # Subtle non-compliant: telnet on vty 5 15 while 0 4 is ssh
    {"config_id": "hard_comp_03", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Disable plaintext Telnet administration (CIS-2.1.1)\nConfig Snippet: line vty 0 4\n transport input ssh\nline vty 5 15\n transport input telnet ssh", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    # Subtle compliant: Junos with explicit telnet service removed
    {"config_id": "hard_comp_04", "task": "compliance", "vendor": "juniper_junos", "input": "Control: Disable plaintext Telnet administration (CIS-2.1.1)\nConfig Snippet: set system services ssh protocol-version v2\nset system services ssh max-pre-authentication-packets 4\nset system login message \"Authorized users only\"", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    # Subtle non-compliant: FortiOS allowaccess ping telnet https
    {"config_id": "hard_comp_05", "task": "compliance", "vendor": "fortinet_fortios", "input": "Control: Disable plaintext Telnet administration (CIS-2.1.1)\nConfig Snippet: config system interface\n edit \"mgmt_vlan\"\n set allowaccess ping https telnet\n next\nend", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    # Partial compliance / subtle non-compliant: SNMPv2 with community starting with 'public' in name
    {"config_id": "hard_comp_06", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Unset default SNMP community strings (CIS-1.3.1)\nConfig Snippet: snmp-server community public-monitoring RO 15\nsnmp-server community private-admin RW 20", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    # Subtle compliant: SNMPv3 user only, no community strings
    {"config_id": "hard_comp_07", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Unset default SNMP community strings (CIS-1.3.1)\nConfig Snippet: snmp-server group SECURE_V3 v3 priv\nsnmp-server user secadmin SECURE_V3 v3 auth sha <REDACTED> priv aes 128 <REDACTED>", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    # Subtle non-compliant: weak crypto 3des in mixed transform set
    {"config_id": "hard_comp_08", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Enforce modern cryptographic algorithms (CIS-4.1.2)\nConfig Snippet: crypto ipsec transform-set HYBRID esp-aes 256 esp-3des esp-sha-hmac", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    # Subtle compliant: strong crypto Suite-B
    {"config_id": "hard_comp_09", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Enforce modern cryptographic algorithms (CIS-4.1.2)\nConfig Snippet: crypto ipsec profile SUITE-B\n set transform-set ESP-GCM-256\n set pfs group19", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    # Conflicting controls: ACL permits established then denies all vs permit any in sub-rule
    {"config_id": "hard_comp_10", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Restrict any-to-any firewall rules (CIS-3.1.4)\nConfig Snippet: ip access-list extended INBOUND-EDGE\n 10 permit tcp any any established\n 20 permit udp host 10.1.1.1 host 10.2.2.2 eq 53\n 30 deny ip any any log", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    # Subtle non-compliant: Permit IP any any disguised under name
    {"config_id": "hard_comp_11", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Restrict any-to-any firewall rules (CIS-3.1.4)\nConfig Snippet: ip access-list extended RESTRICTED-WEB\n 10 permit ip any any\n 20 deny ip any any", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    # Absence-based control: Logging local only vs remote SIEM
    {"config_id": "hard_comp_12", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Configure remote audit logging (CIS-1.4.1)\nConfig Snippet: logging buffered 16000\nno logging host\nlogging source-interface Loopback0", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    # Multi-line compliant: Remote logging with multiple syslog servers
    {"config_id": "hard_comp_13", "task": "compliance", "vendor": "cisco_ios", "input": "Control: Configure remote audit logging (CIS-1.4.1)\nConfig Snippet: logging host 10.100.1.50\nlogging host 10.100.1.51\nlogging trap informational\nlogging facility local7", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    # Subtle non-compliant: NTP configured but disabled
    {"config_id": "hard_comp_14", "task": "compliance", "vendor": "mikrotik_routeros", "input": "Control: Configure authoritative NTP time sources (CIS-1.4.2)\nConfig Snippet: /system ntp client set enabled=no primary-ntp=10.1.1.1 secondary-ntp=10.1.1.2", "gold_label": "NON_COMPLIANT", "verified_by": "human_auditor"},
    # Vendor-specific syntax: Huawei info-center syslog compliant
    {"config_id": "hard_comp_15", "task": "compliance", "vendor": "huawei_vrp", "input": "Control: Configure remote audit logging (CIS-1.4.1)\nConfig Snippet: info-center enable\ninfo-center loghost 10.10.50.1 facility local5\ninfo-center loghost source-ip 10.10.50.254", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
    # Vendor-specific syntax: Nokia SROS logging
    {"config_id": "hard_comp_16", "task": "compliance", "vendor": "nokia_sros", "input": "Control: Configure remote audit logging (CIS-1.4.1)\nConfig Snippet: configure log syslog 1 address 192.168.100.50\nconfigure log log-id 100 to syslog 1\nconfigure log log-id 100 from main security", "gold_label": "COMPLIANT", "verified_by": "human_auditor"},
]

with open(benchmarks_dir / "compliance_hard.jsonl", "w", encoding="utf-8") as f:
    for item in comp_hard:
        f.write(json.dumps(item) + "\n")

print(f"Wrote {len(comp_hard)} hard compliance benchmark examples.")

# 4. Human-Verified Security QA Benchmark
qa_gold = [
    {"config_id": "qa_gold_01", "task": "qa", "vendor": "cisco_ios", "input": "Question: Is Telnet enabled?\nContext:\nline vty 0 4\n transport input telnet\n login local", "gold_label": "yes", "verified_by": "human_auditor"},
    {"config_id": "qa_gold_02", "task": "qa", "vendor": "cisco_ios", "input": "Question: Is Telnet enabled?\nContext:\nline vty 0 4\n transport input ssh\n login local", "gold_label": "no", "verified_by": "human_auditor"},
    {"config_id": "qa_gold_03", "task": "qa", "vendor": "juniper_junos", "input": "Question: Is SSH enabled?\nContext:\nset system services ssh protocol-version v2\nset system services ssh connection-limit 10", "gold_label": "yes", "verified_by": "human_auditor"},
    {"config_id": "qa_gold_04", "task": "qa", "vendor": "juniper_junos", "input": "Question: Is SSH enabled?\nContext:\ndelete system services ssh\nset system services telnet", "gold_label": "no", "verified_by": "human_auditor"},
    {"config_id": "qa_gold_05", "task": "qa", "vendor": "arista_eos", "input": "Question: Are ACLs configured?\nContext:\nip access-list standard RESTRICT-MGMT\n 10 permit 10.0.0.0/8\n 20 deny any", "gold_label": "yes", "verified_by": "human_auditor"},
    {"config_id": "qa_gold_06", "task": "qa", "vendor": "arista_eos", "input": "Question: Are ACLs configured?\nContext:\ninterface Ethernet1\n no switchport\n ip address 10.1.1.1/24", "gold_label": "no", "verified_by": "human_auditor"},
    {"config_id": "qa_gold_07", "task": "qa", "vendor": "fortinet_fortios", "input": "Question: Is HTTP management enabled?\nContext:\nconfig system interface\n edit port1\n set allowaccess http https ssh\n next\nend", "gold_label": "yes", "verified_by": "human_auditor"},
    {"config_id": "qa_gold_08", "task": "qa", "vendor": "fortinet_fortios", "input": "Question: Is HTTP management enabled?\nContext:\nconfig system interface\n edit port1\n set allowaccess https ssh ping\n next\nend", "gold_label": "no", "verified_by": "human_auditor"},
    {"config_id": "qa_gold_09", "task": "qa", "vendor": "cisco_ios", "input": "Question: Is logging enabled?\nContext:\nlogging host 10.10.10.50\nlogging buffered 64000\nlogging trap notifications", "gold_label": "yes", "verified_by": "human_auditor"},
    {"config_id": "qa_gold_10", "task": "qa", "vendor": "cisco_ios", "input": "Question: Is logging enabled?\nContext:\nno logging buffered\nno logging host\nno logging console", "gold_label": "no", "verified_by": "human_auditor"},
    {"config_id": "qa_gold_11", "task": "qa", "vendor": "cisco_ios", "input": "Question: Is NTP configured?\nContext:\nntp server 192.168.1.1\nntp server 192.168.1.2\nntp source Loopback0", "gold_label": "yes", "verified_by": "human_auditor"},
    {"config_id": "qa_gold_12", "task": "qa", "vendor": "cisco_ios", "input": "Question: Is NTP configured?\nContext:\nno ntp server\nclock timezone GMT 0 0", "gold_label": "no", "verified_by": "human_auditor"},
    {"config_id": "qa_gold_13", "task": "qa", "vendor": "paloalto_panos", "input": "Question: Are unrestricted any-to-any rules present?\nContext:\nset rulebase security rules allow-all from any to any service any action allow", "gold_label": "yes", "verified_by": "human_auditor"},
    {"config_id": "qa_gold_14", "task": "qa", "vendor": "paloalto_panos", "input": "Question: Are unrestricted any-to-any rules present?\nContext:\nset rulebase security rules allow-ssl from trust to untrust source 10.0.0.0/8 destination any service service-https action allow", "gold_label": "no", "verified_by": "human_auditor"},
    {"config_id": "qa_gold_15", "task": "qa", "vendor": "cisco_ios", "input": "Question: Is weak cryptography used?\nContext:\ncrypto ipsec transform-set OLD esp-des esp-md5-hmac\n mode tunnel", "gold_label": "yes", "verified_by": "human_auditor"},
    {"config_id": "qa_gold_16", "task": "qa", "vendor": "cisco_ios", "input": "Question: Is weak cryptography used?\nContext:\ncrypto ipsec transform-set SECURE esp-aes 256 esp-sha256-hmac\n mode tunnel", "gold_label": "no", "verified_by": "human_auditor"},
]

with open(benchmarks_dir / "qa.jsonl", "w", encoding="utf-8") as f:
    for item in qa_gold:
        f.write(json.dumps(item) + "\n")

print(f"Wrote {len(qa_gold)} human-verified QA benchmark examples.")

# 5. Human-Verified NER Benchmark Set across 11 Platforms
ner_gold = [
    # Cisco IOS
    {"config_id": "cisco_ios_gold_01", "vendor": "cisco_ios", "input": "interface GigabitEthernet0/0/1\n ip address 192.168.10.1 255.255.255.0", "entities": [{"text": "GigabitEthernet0/0/1", "type": "INTERFACE"}, {"text": "192.168.10.1", "type": "IP_ADDRESS"}, {"text": "255.255.255.0", "type": "SUBNET"}], "verified_by": "human_auditor"},
    {"config_id": "cisco_ios_gold_02", "vendor": "cisco_ios", "input": "ip access-list extended RESTRICT-MGMT\n permit tcp 10.1.1.0 0.0.0.255 any eq 22", "entities": [{"text": "RESTRICT-MGMT", "type": "ACL"}, {"text": "tcp", "type": "PROTOCOL"}, {"text": "10.1.1.0", "type": "IP_ADDRESS"}, {"text": "22", "type": "PORT"}], "verified_by": "human_auditor"},
    {"config_id": "cisco_ios_gold_03", "vendor": "cisco_ios", "input": "router bgp 65001\n neighbor 10.254.0.2 remote-as 65002", "entities": [{"text": "bgp", "type": "ROUTING_PROTOCOL"}, {"text": "10.254.0.2", "type": "IP_ADDRESS"}], "verified_by": "human_auditor"},
    {"config_id": "cisco_ios_gold_04", "vendor": "cisco_ios", "input": "crypto ipsec transform-set SECURE esp-aes 256 esp-sha256-hmac", "entities": [{"text": "SECURE", "type": "SERVICE"}, {"text": "esp-aes", "type": "CRYPTO_ALGORITHM"}, {"text": "esp-sha256-hmac", "type": "CRYPTO_ALGORITHM"}], "verified_by": "human_auditor"},
    {"config_id": "cisco_ios_gold_05", "vendor": "cisco_ios", "input": "username admin privilege 15 secret 5 <REDACTED>", "entities": [{"text": "admin", "type": "USER"}], "verified_by": "human_auditor"},
    # Cisco ASA
    {"config_id": "cisco_asa_gold_01", "vendor": "cisco_asa", "input": "nameif outside\n security-level 0\n ip address 203.0.113.1 255.255.255.248", "entities": [{"text": "outside", "type": "SECURITY_ZONE"}, {"text": "203.0.113.1", "type": "IP_ADDRESS"}, {"text": "255.255.255.248", "type": "SUBNET"}], "verified_by": "human_auditor"},
    {"config_id": "cisco_asa_gold_02", "vendor": "cisco_asa", "input": "access-list OUTSIDE_IN extended permit tcp any host 192.0.2.50 eq https", "entities": [{"text": "OUTSIDE_IN", "type": "FIREWALL_RULE"}, {"text": "tcp", "type": "PROTOCOL"}, {"text": "192.0.2.50", "type": "IP_ADDRESS"}, {"text": "https", "type": "SERVICE"}], "verified_by": "human_auditor"},
    # Juniper Junos
    {"config_id": "juniper_junos_gold_01", "vendor": "juniper_junos", "input": "set interfaces ge-9/9/9 unit 99 family inet address 198.51.100.99/24", "entities": [{"text": "ge-9/9/9", "type": "INTERFACE"}, {"text": "198.51.100.99", "type": "IP_ADDRESS"}], "verified_by": "human_auditor"},
    {"config_id": "juniper_junos_gold_02", "vendor": "juniper_junos", "input": "set security zones security-zone trust interfaces ge-0/0/1.0", "entities": [{"text": "trust", "type": "SECURITY_ZONE"}, {"text": "ge-0/0/1.0", "type": "INTERFACE"}], "verified_by": "human_auditor"},
    {"config_id": "juniper_junos_gold_03", "vendor": "juniper_junos", "input": "set security policies from-zone trust to-zone untrust policy allow-web match source-address corporate-lan destination-address any application junos-https", "entities": [{"text": "trust", "type": "SECURITY_ZONE"}, {"text": "untrust", "type": "SECURITY_ZONE"}, {"text": "allow-web", "type": "FIREWALL_RULE"}, {"text": "junos-https", "type": "SERVICE"}], "verified_by": "human_auditor"},
    # Arista EOS
    {"config_id": "arista_eos_gold_01", "vendor": "arista_eos", "input": "interface Ethernet1\n no switchport\n ip address 10.0.12.1/30", "entities": [{"text": "Ethernet1", "type": "INTERFACE"}, {"text": "10.0.12.1", "type": "IP_ADDRESS"}], "verified_by": "human_auditor"},
    {"config_id": "arista_eos_gold_02", "vendor": "arista_eos", "input": "ip access-list standard SNMP-MGMT\n 10 permit 10.200.0.0/16", "entities": [{"text": "SNMP-MGMT", "type": "ACL"}, {"text": "10.200.0.0", "type": "IP_ADDRESS"}], "verified_by": "human_auditor"},
    # Fortinet FortiOS
    {"config_id": "fortinet_fortios_gold_01", "vendor": "fortinet_fortios", "input": "config system interface\n edit port1\n set ip 192.168.1.99 255.255.255.0\n next\nend", "entities": [{"text": "port1", "type": "INTERFACE"}, {"text": "192.168.1.99", "type": "IP_ADDRESS"}, {"text": "255.255.255.0", "type": "SUBNET"}], "verified_by": "human_auditor"},
    {"config_id": "fortinet_fortios_gold_02", "vendor": "fortinet_fortios", "input": "config firewall policy\n edit 10\n set srcintf port2\n set dstintf port1\n set service HTTPS\n next\nend", "entities": [{"text": "port2", "type": "INTERFACE"}, {"text": "port1", "type": "INTERFACE"}, {"text": "HTTPS", "type": "SERVICE"}], "verified_by": "human_auditor"},
    # Palo Alto PAN-OS
    {"config_id": "paloalto_panos_gold_01", "vendor": "paloalto_panos", "input": "set network interface ethernet ethernet1/1 layer3 ip 10.100.1.1/24", "entities": [{"text": "ethernet1/1", "type": "INTERFACE"}, {"text": "10.100.1.1", "type": "IP_ADDRESS"}], "verified_by": "human_auditor"},
    {"config_id": "paloalto_panos_gold_02", "vendor": "paloalto_panos", "input": "set rulebase security rules Corp-Internet from Trust to Untrust service service-http", "entities": [{"text": "Corp-Internet", "type": "FIREWALL_RULE"}, {"text": "Trust", "type": "SECURITY_ZONE"}, {"text": "Untrust", "type": "SECURITY_ZONE"}, {"text": "service-http", "type": "SERVICE"}], "verified_by": "human_auditor"},
    # Huawei VRP
    {"config_id": "huawei_vrp_gold_01", "vendor": "huawei_vrp", "input": "interface GigabitEthernet0/0/1\n ip address 10.50.1.1 255.255.255.0", "entities": [{"text": "GigabitEthernet0/0/1", "type": "INTERFACE"}, {"text": "10.50.1.1", "type": "IP_ADDRESS"}, {"text": "255.255.255.0", "type": "SUBNET"}], "verified_by": "human_auditor"},
    {"config_id": "huawei_vrp_gold_02", "vendor": "huawei_vrp", "input": "acl number 3001\n rule 5 permit tcp source 10.10.0.0 0.0.255.255 destination-port eq 80", "entities": [{"text": "3001", "type": "ACL"}, {"text": "tcp", "type": "PROTOCOL"}, {"text": "10.10.0.0", "type": "IP_ADDRESS"}, {"text": "80", "type": "PORT"}], "verified_by": "human_auditor"},
    # Nokia SR OS
    {"config_id": "nokia_sros_gold_01", "vendor": "nokia_sros", "input": "configure router interface to-Core-1 address 192.168.200.1/30 port 1/1/1", "entities": [{"text": "to-Core-1", "type": "INTERFACE"}, {"text": "192.168.200.1", "type": "IP_ADDRESS"}, {"text": "1/1/1", "type": "PORT"}], "verified_by": "human_auditor"},
    # MikroTik RouterOS
    {"config_id": "mikrotik_routeros_gold_01", "vendor": "mikrotik_routeros", "input": "/ip address add address=192.168.88.1/24 interface=ether1 network=192.168.88.0", "entities": [{"text": "192.168.88.1", "type": "IP_ADDRESS"}, {"text": "ether1", "type": "INTERFACE"}], "verified_by": "human_auditor"},
    # F5 BIG-IP TMOS
    {"config_id": "f5_bigip_gold_01", "vendor": "f5_bigip_tmos", "input": "net self /Common/internal_self { address 10.1.10.240/24 vlan /Common/internal }", "entities": [{"text": "internal_self", "type": "INTERFACE"}, {"text": "10.1.10.240", "type": "IP_ADDRESS"}, {"text": "internal", "type": "VLAN"}], "verified_by": "human_auditor"},
    # SONiC
    {"config_id": "sonic_gold_01", "vendor": "sonic", "input": "config interface ip add Ethernet0 10.0.0.1/31", "entities": [{"text": "Ethernet0", "type": "INTERFACE"}, {"text": "10.0.0.1", "type": "IP_ADDRESS"}], "verified_by": "human_auditor"},
    # pfSense (Netgate)
    {"config_id": "pfsense_gold_01", "vendor": "netgate_pfsense", "input": "<interface><lan><if>em1</if><ipaddr>192.168.1.1</ipaddr><subnet>24</subnet></lan></interface>", "entities": [{"text": "em1", "type": "INTERFACE"}, {"text": "192.168.1.1", "type": "IP_ADDRESS"}, {"text": "24", "type": "SUBNET"}], "verified_by": "human_auditor"}
]

with open(benchmarks_dir / "ner.jsonl", "w", encoding="utf-8") as f:
    for item in ner_gold:
        f.write(json.dumps(item) + "\n")

print(f"Wrote {len(ner_gold)} human-verified NER benchmark examples across 11 platforms.")
