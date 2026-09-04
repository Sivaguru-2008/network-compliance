# Real Device Evaluation Dataset

**Classification:** `VERIFIED_REAL_PRODUCTION_DEVICE`  
**Real Device Flag:** `true`  
**Provenance Verified:** `true`  
**Split:** `REAL_DEVICE_EVALUATION` (Zero-leakage holdout)  
**Total Real Configurations:** 10  
**Total Production Lines:** 96,664  

## Overview

This directory contains 10 verified real production network configurations from the Internet2
nationwide research backbone network, published as part of the USENIX NSDI '20 Config2Spec
research dataset (ETH Zurich Network Security Group).

### Provenance Details

- **Vendor:** Juniper Networks
- **Platform:** JunOS
- **OS Version:** 12.3R6.6
- **Device Series:** MX series backbone routers
- **License:** Apache-2.0
- **Source Repository:** `https://github.com/nsg-ethz/config2spec/tree/master/scenarios/internet2/configs`
- **Topology:** Real Internet2 PoPs (Atlanta, Chicago, Cleveland, Houston, Kansas City, Los Angeles, New York, Salt Lake City, Seattle, Washington DC)

## Directory Structure

- `raw/`: Verbatim original configuration files exactly as downloaded from the repository.
- `sanitized/`: Syntax-preserving sanitized copies with secrets, passwords, and RADIUS keys redacted.
- `manifest.json`: Full cryptographic provenance manifest including SHA256 hashes, source URLs, and PoP locations.
- `structured_examples.json`: Structured evaluation examples mapping raw snippets to normalized baseline concepts.
- `evaluation_report.json` & `evaluation_report.md`: Detailed evaluation reports from the audit pipeline.

## Safety and Zero-Leakage Policy

These configurations are strictly reserved for **out-of-sample evaluation and validation**.
They are never included in NLP training splits or model fine-tuning corpora.
