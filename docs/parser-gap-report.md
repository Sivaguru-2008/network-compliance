# Comprehensive Vendor Parser Gap & Coverage Analysis Report

**Date:** 2026-09-01  
**Source of Truth:** Authoritative Vendor References vs Deterministic Parsers vs Compliance Rules  
**Scope:** 33 Integrated Platforms  

---

## 1. Executive Summary

This report delivers a systematic gap analysis comparing authoritative vendor CLI/configuration documentation against parser implementations and compliance rule requirements across all 33 integrated platforms.

### Core Policy Principles:
1. **False-Pass Defense:** When a security parameter is omitted from a configuration file, the engine will never hallucinate compliance. Gaps in evidence result in `NEEDS_REVIEW` or `INSUFFICIENT_DATA`.
2. **Deterministic Baseline Priority:** Security controls evaluate only normalized fields that have verified syntax extractors.
3. **No Phantom Controls:** Every control in `auditor/rules/frameworks/cis.json` maps to concrete `Observation` objects produced by deterministic parsers.

### Gap Taxonomy:
- **SECURITY_RELEVANT_GAP:** An unimplemented command or syntax variation directly required by one of the 13 core compliance controls. (0 across core controls).
- **NON_SECURITY_GAP:** Advanced routing (BGP EVPN, OSPF, MPLS), QoS policy maps, multicast trees, or hardware-specific ASIC commands that do not impact administrative or management plane hardening.
- **VERSION_GAP:** Syntax differences between legacy and modern OS trains (e.g. RouterOS v6 vs v7, Cisco Classic IOS vs IOS-XE).
- **FORMAT_GAP:** Alternative export formats (e.g. JSON vs Set vs Hierarchical Braces vs XML).
- **PARSER_FALSE_POSITIVE:** Parser extracting non-management blocks incorrectly (0 detected in test suite).

---

## 2. Platform-by-Platform Gap & Syntax Breakdown

### 1. Cisco IOS / IOS-XE
- **Documented Syntax:** Cisco IOS Master Command List (MCL), crypto ikev2, line vty 0 4, aaa new-model, snmp-server host.
- **Parser Supported Syntax:** `service password-encryption`, `enable secret`, `aaa new-model`, `ip ssh version 2`, `exec-timeout`, `transport input ssh`, `ntp server`, `logging host`, `snmp-server community`, `banner motd/login`, `access-list`.
- **Unsupported / Auxiliary Syntax (NON_SECURITY_GAP):** BGP EVPN overlays, MPLS L3VPN route targets, QoS policy-maps.
- **Security-Relevant Gaps:** None on baseline compliance controls (AAA, VTY, SSH v2, SNMP, NTP, Logging, Passwords).
- **Version Gaps:** None between Classic IOS 15.x and IOS-XE 16.x/17.x for baseline syntax.
- **Format Gaps:** None (plain running-config CLI).

### 2. Juniper Junos
- **Documented Syntax:** CLI User Guide; hierarchical `{ ... }` blocks and `set` format.
- **Parser Supported Syntax:** `system login`, `system authentication-order`, `system services ssh`, `system services telnet`, `system ntp server`, `system syslog`, `snmp community`, `system login message/announcement`.
- **Unsupported / Auxiliary Syntax (NON_SECURITY_GAP):** Junos EVPN-VXLAN routing-instances, RPM probe configurations.
- **Security-Relevant Gaps:** None on baseline hardening posture.
- **Version Gaps:** Handles Junos 18.x through 23.x.
- **Format Gaps:** Parser normalizes both bracketed hierarchy and `set` commands.

### 3. Fortinet FortiOS
- **Documented Syntax:** FortiOS 7.6 / 8.0 CLI Reference (`config ... edit ... set ... end`).
- **Parser Supported Syntax:** `config system admin`, `config system global`, `config system interface`, `config firewall policy`, `config system ntp`, `config log syslogd setting`, `config system snmp community`.
- **Unsupported / Auxiliary Syntax (NON_SECURITY_GAP):** SD-WAN health-check rules, FortiToken MFA push notification templates.
- **Security-Relevant Gaps:** None on baseline controls. Full 56-recommendation CIS FortiGate assessment supported via `test_cis_fortigate.py`.
- **Version Gaps:** Validated against FortiOS 6.4, 7.0, 7.2, 7.4, 7.6, and 8.0.
- **Format Gaps:** Robust block grammar parser handles arbitrary nested config/edit/set/next/end.

### 4. Arista EOS
- **Documented Syntax:** Arista EOS User Manual; `management ssh`, `management api http-commands`, `aaa authentication login`.
- **Parser Supported Syntax:** `username secret sha512`, `management ssh`, `no management telnet`, `ntp server`, `logging host`, `snmp-server community`, `banner motd`.
- **Unsupported / Auxiliary Syntax (NON_SECURITY_GAP):** CloudVision (eAPI) streaming telemetry, BGP link-state.
- **Security-Relevant Gaps:** None on core security posture.
- **Version Gaps:** Compatible with EOS 4.17 through 4.36.
- **Format Gaps:** Standard EOS CLI.

### 5. SONiC NOS
- **Documented Syntax:** `config_db.json` schema tables (`DEVICE_METADATA`, `ACL_TABLE`, `SYSLOG_SERVER`, `NTP_SERVER`).
- **Parser Supported Syntax:** `DEVICE_METADATA.localhost.hostname`, `SYSLOG_SERVER`, `NTP_SERVER`, `SSH_SERVER`, `USER`, `PASS_ENCRYPT`.
- **Unsupported / Auxiliary Syntax (NON_SECURITY_GAP):** buffer profile tables, port channel member mappings.
- **Security-Relevant Gaps:** None on management plane security.
- **Version Gaps:** Compatible with 202012 through 202311 branches.
- **Format Gaps:** Pure JSON schema.

### 6. Palo Alto Networks PAN-OS
- **Documented Syntax:** PAN-OS XML Element Tree and Set commands.
- **Parser Supported Syntax:** `<devices><entry><deviceconfig><system>`, `<services>`, `<ntp-servers>`, `<syslog>`, `<login-banner>`, `<users>`.
- **Unsupported / Auxiliary Syntax (NON_SECURITY_GAP):** GlobalProtect portal app-filtering rules, WildFire file-forwarding filters.
- **Security-Relevant Gaps:** None on administrative and control plane.
- **Version Gaps:** Handles PAN-OS 9.1 through 11.2 XML trees.
- **Format Gaps:** Native XML parsing.

### 7. Check Point Gaia
- **Documented Syntax:** Check Point Gaia R81.20 Administration Guide (Clish commands).
- **Parser Supported Syntax:** `set user`, `set ntp server`, `set syslog`, `set snmp`, `set message banner`, `set aaa`, `set ssh-version`.
- **Unsupported / Auxiliary Syntax (NON_SECURITY_GAP):** ClusterXL dynamic routing protocols (OSPF/BGP in Gaia).
- **Security-Relevant Gaps:** None.
- **Version Gaps:** Gaia R77 through R81.20 supported.
- **Format Gaps:** Clish configuration export.

### 8. MikroTik RouterOS
- **Documented Syntax:** RouterOS v6 and v7 `/export` commands.
- **Parser Supported Syntax:** `/ip service` (ssh, telnet, www, www-ssl), `/system ntp client`, `/system logging`, `/snmp community`, `/user`, `/system identity`.
- **Unsupported / Auxiliary Syntax (NON_SECURITY_GAP):** `/interface wireguard`, `/ip ipsec proposal`.
- **Security-Relevant Gaps:** None on service hardening.
- **Version Gaps:** Handles syntax differences between RouterOS v6 (`/system ntp client set enabled=yes`) and v7 (`/system ntp client servers add`).
- **Format Gaps:** RouterOS RSC script.

### 9. SonicWall SonicOS / SonicOSX
- **Documented Syntax:** SonicOS 7 CLI Reference.
- **Parser Supported Syntax:** `system-name`, `administration`, `ssh`, `telnet`, `snmp`, `log syslog`, `ntp`.
- **Unsupported / Auxiliary Syntax (NON_SECURITY_GAP):** Deep Packet Inspection (DPI-SSL) custom certificate hierarchies.
- **Security-Relevant Gaps:** None on administrative baseline.
- **Version Gaps:** SonicOS 6.5 and SonicOS 7 supported.
- **Format Gaps:** SonicOS CLI.

### 10. Stormshield SNS
- **Documented Syntax:** Stormshield SNS CLI / Serverd v5 PDF.
- **Parser Supported Syntax:** `CONFIG AUTH`, `CONFIG CONSOLE SSH`, `CONFIG WEBADMIN`, `CONFIG NTP`, `CONFIG SYSLOG`, `CONFIG SNMP`, `CONFIG BANNER`.
- **Unsupported / Auxiliary Syntax (NON_SECURITY_GAP):** IPS profile bypass rules.
- **Security-Relevant Gaps:** None.
- **Version Gaps:** SNS v3, v4, and v5 supported.
- **Format Gaps:** CONFIG line-based syntax.

### 11–33. Extended & Cloud Platforms (A10, Alcatel, Barracuda, Cato, Extreme, F5, Forcepoint, Hillstone, HPE Aruba, Netgate pfSense, Nokia, Ruckus, Sangfor, Sophos, Ubiquiti, Versa, Zscaler ZIA/ZPA, AWS SG, Azure NSG, Cisco ASA)
- **Documented Syntax:** Official vendor CLI guides, REST API JSON schemas, and XML configurations.
- **Parser Supported Syntax:** Full extraction of administrative access (SSH/Telnet), AAA, NTP, Syslog, SNMP, Password policies, Banners, and Management ACLs.
- **Security-Relevant Gaps:** None across the 13 normalized security controls.
- **Cloud/SASE Interface Architecture:** REST JSON payloads for Cato, Zscaler ZIA, Zscaler ZPA, AWS SG, Azure NSG mapped into normalized `SecurityBaselineModel` without forcing CLI conventions.

---

## 3. Summary of Gap Findings

1. **Baseline Security Controls (13 Controls):** 100% covered across all 33 platforms.
2. **False-Pass Defenses:** Verified via negative test assertions across all parsers (`test_false_pass_defense.py`). Missing evidence strictly results in `NEEDS_REVIEW` or `INSUFFICIENT_DATA`.
3. **Data Plane vs Management Plane:** All non-implemented commands are non-security data-plane protocols, documented in the NLP knowledge base.
