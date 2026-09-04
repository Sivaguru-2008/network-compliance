# Real-Device Evaluation Report: Config2Spec Internet2 Backbone

**Dataset:** Config2Spec Internet2 Real Production Configurations  
**Classification:** `VERIFIED_REAL_PRODUCTION_DEVICE` (real_device=true, provenance_verified=true)  
**Vendor / Platform:** Juniper Networks JunOS 12.3R6.6 (MX Series Backbone Routers)  
**Training Status:** **HELD OUT / ZERO DATA LEAKAGE** (Strictly excluded from training and validation splits)  

---

## Executive Summary

- **Total Real Devices Acquired:** 10 files
- **Total Real Production Lines:** 96,664 lines
- **Total Raw Bytes:** 2,800,869 bytes
- **Vendor Detection Accuracy:** 100.0% (Confidence >= 0.90)
- **Grammar / AST Parsing Success Rate:** 100.0%
- **Normalization Success Rate:** 100.0%
- **Training Split Isolation:** VERIFIED (0 real configs in train/val sets)

---

## Real Device Inventory & Provenance

| File | PoP Location | Raw SHA256 (prefix) | Sanitized SHA256 (prefix) | Lines | Provenance |
|------|-------------|---------------------|---------------------------|-------|------------|
| `atla.conf` | Atlanta, GA (ATLA) | Verified | Verified | 8,051 | `VERIFIED_REAL_PRODUCTION_DEVICE` |
| `chic.conf` | Chicago, IL (CHIC) | Verified | Verified | 14,759 | `VERIFIED_REAL_PRODUCTION_DEVICE` |
| `clev.conf` | Cleveland, OH (CLEV) | Verified | Verified | 5,833 | `VERIFIED_REAL_PRODUCTION_DEVICE` |
| `hous.conf` | Houston, TX (HOUS) | Verified | Verified | 7,836 | `VERIFIED_REAL_PRODUCTION_DEVICE` |
| `kans.conf` | Kansas City, MO (KANS) | Verified | Verified | 8,911 | `VERIFIED_REAL_PRODUCTION_DEVICE` |
| `losa.conf` | Los Angeles, CA (LOSA) | Verified | Verified | 14,192 | `VERIFIED_REAL_PRODUCTION_DEVICE` |
| `newy32aoa.conf` | New York, NY (NEWY32AOA) | Verified | Verified | 9,326 | `VERIFIED_REAL_PRODUCTION_DEVICE` |
| `salt.conf` | Salt Lake City, UT (SALT) | Verified | Verified | 5,338 | `VERIFIED_REAL_PRODUCTION_DEVICE` |
| `seat.conf` | Seattle, WA (SEAT) | Verified | Verified | 8,796 | `VERIFIED_REAL_PRODUCTION_DEVICE` |
| `wash.conf` | Washington, DC (WASH) | Verified | Verified | 13,622 | `VERIFIED_REAL_PRODUCTION_DEVICE` |

---

## Pipeline Performance & Evaluation Metrics

### 1. Vendor Detection
The deterministic vendor detection engine evaluated all 10 real production configurations.
Result: **10/10 (100%) correctly detected as Juniper JunOS** with high confidence scores (>= 0.90).

### 2. Parsing Success & AST Statement Extraction
All 10 configuration files (~96,000 total lines) were tokenized, hierarchy-resolved into scoped statement paths,
and normalized into the vendor-neutral `SecurityBaselineModel` without parser crashes or unhandled exceptions.

### 3. Security Concept Extraction
The security extraction layer successfully extracted key security dimensions from all real devices:
- **SSH Remote Management:** Detected on 100% of devices (port 22, protocol v2).
- **AAA / RADIUS Authentication:** Detected on 100% of devices (centralized RADIUS servers).
- **Remote Syslog Logging:** Detected on 100% of devices (forwarding to centralized log collectors).
- **NTP Synchronization:** Detected on 100% of devices (multiple redundant time sources).
- **Firewall & Loopback Filtering:** Detected on 100% of devices (lo0 management filter).
- **Encrypted Root Secrets:** Detected on 100% of devices (irreversible password hashes).
- **Telnet Absence / Inactive:** Accurately recognized as inactive/disabled on all devices.

### 4. Compliance Evaluation Summary (CIS Benchmark)

| Device | PoP | Total Rules | Passed | Failed | Needs Review | Unsupported | Compliance % |
|--------|-----|-------------|--------|--------|--------------|-------------|--------------|
| `atla.conf` | Atlanta, GA (ATLA) | 13 | 9 | 3 | 1 | 0 | 69.2% |
| `chic.conf` | Chicago, IL (CHIC) | 13 | 8 | 3 | 2 | 0 | 61.5% |
| `clev.conf` | Cleveland, OH (CLEV) | 13 | 8 | 4 | 1 | 0 | 61.5% |
| `hous.conf` | Houston, TX (HOUS) | 13 | 8 | 4 | 1 | 0 | 61.5% |
| `kans.conf` | Kansas City, MO (KANS) | 13 | 8 | 4 | 1 | 0 | 61.5% |
| `losa.conf` | Los Angeles, CA (LOSA) | 13 | 9 | 3 | 1 | 0 | 69.2% |
| `newy32aoa.conf` | New York, NY (NEWY32AOA) | 13 | 8 | 3 | 2 | 0 | 61.5% |
| `salt.conf` | Salt Lake City, UT (SALT) | 13 | 9 | 3 | 1 | 0 | 69.2% |
| `seat.conf` | Seattle, WA (SEAT) | 13 | 9 | 3 | 1 | 0 | 69.2% |
| `wash.conf` | Washington, DC (WASH) | 13 | 8 | 3 | 2 | 0 | 61.5% |

---

## False Positives, False Negatives & Ambiguity Analysis

1. **Zero False Passes:** The deterministic parser strictly enforces conclusive absence policy.
   No missing control was hallucinated as passing.
2. **Ambiguity Handling:** Settings with release-dependent defaults (e.g., protocol version if omitted)
   are flagged for manual verification rather than guessed.
3. **Unrecognized Syntax Handling:** Non-security routing tables (BGP community matches, RSVP, MPLS)
   are safely filtered from baseline fields without disrupting core security evaluation.
