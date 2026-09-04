# SIH Demo Data Package

This directory provides the standardized evaluation and demonstration datasets for the Smart India Hackathon (SIH) Final Product Demonstration.

---

## Dataset Classification & Provenance

### A. Known Vendor Reference Configuration
- **File**: A_KNOWN_VENDOR_CISCO_IOS.conf
- **Vendor / OS**: Cisco IOS (IOS-XE Hardened Reference)
- **Classification**: Vendor Hardened Reference Standard
- **Purpose**: Demonstrates baseline deterministic parsing, complete normalization, multi-framework compliance evaluation (CIS, NIST, STIG, ISO), evidence extraction, and remediation generation on enterprise network devices.
- **Provenance**: Cisco Systems DevNet Baseline Configuration Standard.

### B. Real-World Evaluation Configuration
- **File**: B_REAL_WORLD_INTERNET2_EVALUATION_JUNIPER.conf
- **Vendor / OS**: Juniper Networks Junos OS (MX480 Edge Router, Atlanta POP)
- **Classification**: **REAL-WORLD EVALUATION DATA** (Evaluation-Only; Strictly Isolated from Training)
- **Purpose**: Demonstrates enterprise-scale real-device auditing (8,000+ lines), SHA-256 integrity verification, deterministic identity extraction, deep rule evaluation across 4 frameworks, and PDF compliance reporting without training leakage or exposed secrets.
- **Provenance**: Internet2 Research & Education Backbone Network (tla.conf, SHA-256 verified, sanitized).

### C. Synthetic Controlled Unknown-Vendor Configuration
- **File**: C_SYNTHETIC_UNKNOWN_VENDOR_APPLIANCE.conf
- **Vendor / OS**: Novel/Custom Appliance (
ovel_vendor / unknown)
- **Classification**: **SYNTHETIC CONTROLLED DEMONSTRATION DATA** (Not Real Device Data)
- **Purpose**: Demonstrates dynamic unknown command detection, initial NEEDS_REVIEW compliance state, automated NLP/heuristic candidate mapping suggestions in the Admin Training Center, human-in-the-loop approval, mapping persistence across restarts, and instant re-evaluation to PASS with Origin.LEARNED provenance.
- **Provenance**: Synthetically generated test fixture for unknown-syntax adaptive learning validation.

---

## Data Integrity & Security Guarantees
1. **Never Represent Synthetic Data as Real**: All synthetic files are explicitly documented and tagged in metadata.
2. **Never Train on Real-World Evaluation Data**: Internet2 configurations are strictly evaluation-only and never processed by the training loop.
3. **Strict Secrets Redaction**: Passwords, pre-shared keys, and SNMP strings are redacted in evidence and reports.
