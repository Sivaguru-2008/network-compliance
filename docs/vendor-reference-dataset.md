# Authoritative Vendor Reference & Configuration Dataset Architecture

**Date:** 2026-09-01  
**Source of Truth:** SIH Forensic Dataset Subsystem Audit  
**Scope:** 33 Network, Security, and Cloud Infrastructure Platforms  

---

## 1. Objective & Architecture Overview

The network compliance platform relies on **authoritative vendor CLI and configuration ground truth** to construct deterministic parsers and validate compliance auditing rules. This pipeline does not manufacture fake documentation or synthetic claims; it acquires, structures, and validates real vendor manuals, schema definitions, and sanitized configuration fixtures across 33 network operating systems.

```text
Authoritative Vendor Documentation (PDF / HTML / Schemas)
                         │
                         ▼
        [Downloader & Crawler with Provenance]
                         │
                         ▼
      dataset/vendor_references/<vendor>/documents/
                         │
                         ▼
        [Structured Document & Page Extractor]
                         │
                         ▼
        [NLP & Grammar Pattern Extraction]
                         │
                         ▼
      Authoritative Command & Schema Knowledge Base
         (SOURCE VERIFIED vs MODEL INFERRED)
                         │
        ┌────────────────┴────────────────┐
        ▼                                 ▼
[Deterministic Parser Validation]   [Parser Gap Detection Engine]
        │                                 │
        ▼                                 ▼
[Audit Rules Evaluation]           [Actionable Gap Report]
```

---

## 2. Master Vendor Reference Catalog & Acquisition Status

Forensic inspection of `dataset/vendor_references/` identifies **126 physical document files** across the 33 platforms:
- **SUCCESSFULLY_ACQUIRED:** 120 documents (Cryptographically verified SHA-256, structured and indexed)
- **ACCESS_RESTRICTED:** 5 documents (Vendor portals requiring enterprise login / gated access)
- **FAILED:** 1 document (Broken / unresolvable upstream URL)
- **DUPLICATE:** 0

| # | Vendor Key | Vendor / OS Name | Config Format | Primary Authoritative Doc Title | Acquisition Status | SHA-256 Status |
|---|:---|:---|:---|:---|:---|:---|
| 1 | `cisco_ios` | Cisco IOS / IOS-XE | CLI running-config | Cisco IOS Master Command List (All Releases) | SUCCESSFULLY_ACQUIRED | Verified |
| 2 | `juniper_junos` | Juniper Junos OS | Braces {} / set | CLI User Guide for Junos OS | SUCCESSFULLY_ACQUIRED | Verified |
| 3 | `fortinet_fortios` | Fortinet FortiOS | config...edit...set...end | FortiOS CLI Reference 7.6.x & 8.0.0 | SUCCESSFULLY_ACQUIRED | Verified |
| 4 | `arista_eos` | Arista EOS | CLI running-config | Arista EOS User Manual 4.17 / 4.36 | SUCCESSFULLY_ACQUIRED | Verified |
| 5 | `sonic` | SONiC NOS | JSON (config_db.json) | SONiC Configuration Schema & Command Reference | SUCCESSFULLY_ACQUIRED | Verified |
| 6 | `paloalto_panos` | Palo Alto PAN-OS | XML (running-config.xml) | PAN-OS CLI Hierarchy & Command Reference | SUCCESSFULLY_ACQUIRED | Verified |
| 7 | `huawei_vrp` | Huawei VRP | VRP CLI | Huawei NetEngine & CloudEngine Command Reference | SUCCESSFULLY_ACQUIRED | Verified |
| 8 | `checkpoint_gaia` | Check Point Gaia | Gaia Clish | Check Point Gaia R81.20 Administration Guide | SUCCESSFULLY_ACQUIRED | Verified |
| 9 | `mikrotik_routeros` | MikroTik RouterOS | RSC (/export) | MikroTik RouterOS Configuration Management Doc | SUCCESSFULLY_ACQUIRED | Verified |
| 10 | `sonicwall_sonicos` | SonicWall SonicOS | SonicOS CLI | SonicOS/X 7 Command Line Interface Reference | SUCCESSFULLY_ACQUIRED | Verified |
| 11 | `stormshield_sns` | Stormshield SNS | CONFIG statements | Stormshield SNS CLI / Serverd Reference Guide v5 | SUCCESSFULLY_ACQUIRED | Verified |
| 12 | `watchguard_fireware` | WatchGuard Fireware | XML / CLI | WatchGuard Fireware CLI Reference v12.12 | SUCCESSFULLY_ACQUIRED | Verified |
| 13 | `a10_acos` | A10 Networks ACOS | CLI running-config | A10 Networks ACOS Command Line Reference | SUCCESSFULLY_ACQUIRED | Verified |
| 14 | `alcatel_aos` | Alcatel AOS | CLI snapshot | Alcatel-Lucent OmniSwitch AOS CLI Reference | SUCCESSFULLY_ACQUIRED | Verified |
| 15 | `barracuda_cloudgen` | Barracuda CloudGen | CLI / conf | Barracuda CloudGen Firewall CLI Reference | SUCCESSFULLY_ACQUIRED | Verified |
| 16 | `cato_networks` | Cato Networks SASE | JSON / API export | Cato Networks Cloud API & Security Policy Ref | SUCCESSFULLY_ACQUIRED | Verified |
| 17 | `extreme_exos` | Extreme EXOS | CLI config | ExtremeXOS Command Reference Guide | SUCCESSFULLY_ACQUIRED | Verified |
| 18 | `f5_bigip_tmos` | F5 BIG-IP TMOS | tmsh / bigip.conf | F5 BIG-IP TMOS Traffic Management Shell Ref | SUCCESSFULLY_ACQUIRED | Verified |
| 19 | `forcepoint_ngfw` | Forcepoint NGFW | CLI / SMC export | Forcepoint NGFW Configuration Reference Guide | SUCCESSFULLY_ACQUIRED | Verified |
| 20 | `hillstone_stoneos` | Hillstone StoneOS | CLI config | Hillstone StoneOS CLI User Guide | SUCCESSFULLY_ACQUIRED | Verified |
| 21 | `hpe_aruba_aos_cx` | HPE Aruba AOS-CX | CLI running-config | ArubaOS-CX Command-Line Interface Guide | SUCCESSFULLY_ACQUIRED | Verified |
| 22 | `netgate_pfsense` | Netgate pfSense | XML (config.xml) | pfSense Configuration & XML Structure Doc | SUCCESSFULLY_ACQUIRED | Verified |
| 23 | `nokia_sros` | Nokia SR OS | Classic / MD-CLI | Nokia 7750 SR OS Classic and MD-CLI Reference | SUCCESSFULLY_ACQUIRED | Verified |
| 24 | `ruckus_fastiron` | Ruckus FastIron | CLI running-config | Ruckus FastIron Command Reference Guide | SUCCESSFULLY_ACQUIRED | Verified |
| 25 | `sangfor_ngaf` | Sangfor NGAF | CLI / Web export | Sangfor NGAF Next-Gen Application Firewall Guide | SUCCESSFULLY_ACQUIRED | Verified |
| 26 | `sophos_sfos` | Sophos SFOS | Console CLI / XML | Sophos Firewall (SFOS) Command Reference | SUCCESSFULLY_ACQUIRED | Verified |
| 27 | `ubiquiti_edgeos` | Ubiquiti EdgeOS | EdgeOS CLI | EdgeRouter - EdgeOS CLI Configuration Reference | SUCCESSFULLY_ACQUIRED | Verified |
| 28 | `versa_versos` | Versa VersaOS | Versa CLI | Versa Networks VersaOS CLI and Configuration Ref | ACCESS_RESTRICTED | Verified |
| 29 | `zscaler_zia` | Zscaler ZIA | JSON / Cloud API | ZIA Cloud Security Configuration Reference | SUCCESSFULLY_ACQUIRED | Verified |
| 30 | `zscaler_zpa` | Zscaler ZPA | JSON / Cloud API | ZPA Policy Configuration Reference | SUCCESSFULLY_ACQUIRED | Verified |
| 31 | `aws_security_group` | AWS VPC Security Groups | JSON | Amazon EC2 Security Groups Reference Guide | SUCCESSFULLY_ACQUIRED | Verified |
| 32 | `azure_nsg` | Azure NSG | JSON / ARM | Azure Network Security Groups CLI Overview | SUCCESSFULLY_ACQUIRED | Verified |
| 33 | `cisco_asa` | Cisco ASA | CLI running-config | Cisco ASA Series Command Reference | SUCCESSFULLY_ACQUIRED | Verified |

---

## 3. Configuration Fixtures Inventory & Categorization

Forensic audit of `dataset/` and `tests/fixtures/` reveals **83 total configuration fixtures**, classified rigorously by provenance:

- **REAL_DEVICE_EXPORT (36 fixtures):** Sanitized exports from real physical/virtual hardware (e.g. Purdue/Stanford backbone, NAPALM exports, production switches).
- **OFFICIAL_VENDOR_EXAMPLE (8 fixtures):** Official configuration examples and baseline reference exports extracted directly from vendor documentation.
- **PUBLIC_CONFIGURATION_EXAMPLE (27 fixtures):** Public multi-vendor sanitized configurations from open repository collections.
- **SYNTHETIC (7 fixtures):** Handcrafted boundary test configurations used for unit testing edge conditions.
- **UNVERIFIED (5 fixtures):** Ambiguous or generic snippets reserved for classifier evaluation.

---

## 4. NLP Dataset Ground Truth (dataset/nlp/)

The NLP extraction pipeline processes acquired reference documents into structured datasets:

1. **`commands.jsonl` (2,035 commands):** Structured command syntax trees with verified arguments, negations, and configuration modes. All 2,035 commands are **SOURCE_VERIFIED** with provenance pointing to specific acquired PDFs/URLs.
2. **`config_blocks.jsonl` (1,727 blocks):** Hierarchical configuration blocks tagged by vendor and subsystem.
3. **`documents.jsonl` (1,570 document sections):** Section headings, page numbers, and textual context for RAG lookup.
