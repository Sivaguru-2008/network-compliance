# Purdue University ISL Campus Network Dataset Adapter

**Dataset Name:** Purdue ISL Campus Network Configuration Snapshot  
**Vendor / Platform:** Cisco IOS (Routers and Catalyst Switches)  
**Estimated Devices:** ~1,600 running configurations  
**Target Classification:** `VERIFIED_SANITIZED_REAL_DEVICE` (real_device=true, provenance_verified=true)  
**Assigned Split:** `REAL_DEVICE_EVALUATION` (Zero-leakage out-of-sample evaluation)  

---

## Dataset Acquisition Instructions

1. Submit academic research data request at:  
   `https://engineering.purdue.edu/~isl/network-config/data.html`
2. Provide required researcher details:
   - Full Name
   - University / Institutional Email (.edu / academic domain)
   - Institution Name
   - Academic Homepage URL
   - Research Description & Citation to:  
     *Sung, Y.-W. E., Rao, S. G., Xie, G. G., & Maltz, D. A. (2008). Towards systematic design of enterprise networks. IEEE/ACM Transactions on Networking / ACM CoNEXT '08.*
3. Place received archive contents into:  
   `dataset/purdue_isl/raw/`
4. Run the automated ingestion adapter:
   ```bash
   python -c "from auditor.training.purdue_isl_adapter import PurdueISLDatasetAdapter; adapter = PurdueISLDatasetAdapter(); res = adapter.process_and_sanitize(); print(res)"
   ```

---

## Architectural Preparation

The NetAudit architecture is fully pre-configured to ingest all ~1,600 Cisco configurations without any codebase modifications:
1. `PurdueISLDatasetAdapter` automatically processes, sanitizes, and verifies raw Cisco configs.
2. The `CiscoIOSParser` deterministic parser evaluates all configurations against CIS / NIST / PCI-DSS rule engines.
3. Split isolation guarantees that all 1,600 files are assigned exclusively to `REAL_DEVICE_EVALUATION`, preventing data leakage into any NLP training corpus.
