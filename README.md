# Network Security Compliance Auditor

**SIH 2026 &middot; PS SIH26155**

Reads a network device configuration, normalizes it into a vendor-neutral
security baseline, evaluates it against compliance frameworks (CIS, NIST 800-53,
DISA STIG, ISO 27001), and reports `PASS` / `FAIL` / `NEEDS_REVIEW` per
control -- each verdict backed by the exact configuration line it came from.

Runs fully offline. No API keys, no internet, no cloud dependency.

---

## Vendor support matrix

| Vendor | Parser | Format | Offline |
| --- | --- | --- | --- |
| **Cisco IOS / IOS-XE** | `cisco_ios` | CLI grammar | yes |
| **Juniper Junos** | `juniper_junos` | set format + braces format | yes |
| **Fortinet FortiOS** | `fortinet_fortios` | config/edit block walk | yes |
| **Arista EOS** | `arista_eos` | CLI grammar, management blocks | yes |
| **SONiC** | `sonic` | JSON config_db.json | yes |
| any other vendor | `llm` | LLM fallback (opt-in, `--allow-llm`) | no |
| recognised vendor with gaps | `hybrid` | deterministic + LLM fill | no |

Five configuration languages with nothing in common are normalized by five
vendor-specific parsers into **one** `SecurityBaselineModel`. Everything
downstream is written once: one engine, one condition grammar, one report.
A new vendor is a parser and a rule pack -- no change to the pipeline.

---

## Quick start

### Install

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS
pip install -r requirements.txt
```

### Audit a single config

```bash
python -m auditor samples/insecure_ios.conf --framework CIS --offline
```

Output: a colour-coded compliance table on stdout + `reports/insecure_ios.cis.json`.

The vendor is auto-detected from the configuration text. No flags needed to tell
it which device it is looking at.

### Try every vendor

```bash
python -m auditor samples/insecure_ios.conf   --framework CIS --offline
python -m auditor samples/junos_srx.conf      --framework CIS --offline
python -m auditor samples/fortios_fgt.conf    --framework CIS --offline
python -m auditor samples/arista/insecure.conf --framework CIS --offline
python -m auditor samples/sonic/insecure.conf  --framework CIS --offline
```

### Audit a fleet

```bash
python -m auditor --bulk samples/configs/ \
    --framework CIS --framework NIST_800_53 \
    --inventory-out inventory.json --offline
```

### Generate PDF reports

```bash
pip install -r requirements-pdf.txt
python -m auditor samples/insecure_ios.conf --framework CIS --pdf-out --offline
python -m auditor --bulk samples/configs/ --framework CIS --pdf-dir reports/ --offline
```

### Run the web dashboard

```bash
pip install -r requirements-web.txt
uvicorn auditor.web.app:app --port 8000
```

Open `http://localhost:8000/`. Upload configs, browse findings, download PDFs.

### Run tests

```bash
python -m pytest
```

---

## Offline / air-gapped operation

The `--offline` flag enforces complete network isolation:

1. **Socket guard** -- monkey-patches `socket.socket` to raise `RuntimeError`
   on any connection attempt. No DNS, no HTTP, no API calls can leak.
2. **No LLM dependency** -- deterministic parsers handle all 5 supported
   vendors. The `anthropic` package is not imported.
3. **Local knowledge database** -- compliance rules are seeded into a SQLite
   database from the bundled JSON rule packs on first run. No external fetch.
4. **Unknown vendor fallback** -- configurations from unsupported vendors
   produce `NEEDS_REVIEW` findings (not crashes) by querying the local
   knowledge DB for all controls in the requested framework.

```bash
# Works with no API keys, no internet, no environment variables
python -m auditor samples/insecure_ios.conf --framework CIS --offline
```

### Knowledge base management

```bash
python -m auditor knowledge status           # verify offline readiness
python -m auditor knowledge list             # list loaded controls
python -m auditor knowledge export backup.db # export for transfer
python -m auditor knowledge import backup.db # import on air-gapped host
```

---

## CLI reference

| Flag | Effect |
| --- | --- |
| `--offline` | Strict offline mode: blocks all network calls, uses local knowledge DB. |
| `--framework CIS` | Which rule pack to evaluate (repeatable; default `CIS`). |
| `--bulk` | Ingest a directory/glob/file list as a batch. |
| `--inventory-out PATH` | With `--bulk`, write device inventory JSON. |
| `--pdf-out [PATH]` | Per-device PDF report (needs `requirements-pdf.txt`). |
| `--pdf-dir DIR` | With `--bulk`, one PDF per device into DIR. |
| `--vendor NAME` | Force a parser instead of auto-detecting. |
| `--rules PATH` | Use an explicit rule pack JSON. |
| `--json PATH` | Where to write the JSON report. |
| `--no-json` / `--quiet` | Skip JSON / skip the table. |
| `--strict` | Exit `1` on FAIL, `3` on NEEDS_REVIEW. |
| `--allow-llm` | Permit LLM fallback (sends config to API). |
| `--llm-model` | Model for LLM parsing. |
| `--version` | Print version and exit. |

**Exit codes:** `0` success, `1` findings (with `--strict`), `2` error,
`3` needs review (with `--strict`).

---

## Pipeline

```
config text --> VendorParser --> SecurityBaselineModel --> ComplianceEngine --> AuditReport
             (vendor-specific)   (vendor-neutral)         (framework-neutral)
```

Each stage is ignorant of its neighbours' internals:

- The **parser** knows one vendor's syntax but nothing about CIS.
- The **baseline** is the only thing the engine reads -- it never sees raw config.
- The **engine** knows the condition grammar but nothing about Cisco or CIS specifics.
- **Rules** are JSON data: a framework is a file in `auditor/rules/frameworks/`.

### Design invariants

1. **`NEEDS_REVIEW` is a first-class verdict.** Three-valued Kleene logic:
   missing evidence is never rounded up to PASS.
2. **Absence policy is per-vendor, per-setting.** The same silence means
   different things on IOS vs Junos vs FortiOS; each parser declares what it
   can conclude from what is not written.
3. **Aggregation is worst-case.** If any VTY block permits telnet, the device
   permits telnet.

---

## Multi-framework compliance

The 13 core security controls map across four frameworks:

| Control area | CIS | NIST 800-53 | DISA STIG | ISO 27001 |
| --- | --- | --- | --- | --- |
| AAA / centralized auth | 1.1.1 | AC-2 | CCI-000015 | A.8.2 |
| Cleartext transport | 1.2.2 | AC-17 | CCI-000366 | A.8.20 |
| Idle timeout | 1.2.9 | AC-12 | CCI-000057 | A.8.19 |
| Credential hashing | 1.4.1-1.4.2 | IA-5 | CCI-000200 | -- |
| SNMP defaults | 1.5.2-1.5.3 | -- | -- | -- |
| HTTP management | 2.1 | SC-7 | CCI-000381 | -- |
| SSH version | 2.1.1.6 | SC-13 | CCI-000068 | -- |
| Logging | 2.2.2-2.2.4 | AU-2 | CCI-000130 | A.8.10 |
| Management ACL | 1.2 | AC-3 | -- | -- |
| Login banner | 1.6 | AC-8 | CCI-000048 | -- |
| Password policy | 1.1 | IA-5(1) | CCI-000200 | A.5.17 |
| NTP | 2.3 | AU-8 | CCI-000159 | -- |
| SNMP read-only | 1.5 | -- | -- | -- |

Evaluate multiple frameworks in a single pass:

```bash
python -m auditor samples/insecure_ios.conf \
    --framework CIS --framework NIST_800_53 --framework STIG --framework ISO_27001 \
    --offline
```

---

## Project layout

```
auditor/
  parsers/           vendor-specific parsers (IOS, Junos, FortiOS, EOS, SONiC, LLM, hybrid)
  models/            SecurityBaselineModel, Observation[T], rules, results, identity, inventory
  engine/            ComplianceEngine + three-valued condition evaluator
  rules/frameworks/  JSON rule packs per vendor per framework
  knowledge/         SQLite knowledge DB for offline operation
  pipeline.py        single-file audit stages (shared by CLI and bulk)
  ingest.py          bulk orchestration, dedup, fleet inventory
  cli.py             CLI entry point
  report/            table, JSON, PDF renderers
  training/          LLM training loop (threshold fitting, worked examples)
  web/               FastAPI dashboard (upload, inventory, findings, PDF download)
samples/             test configurations for all 5 vendors
tests/               test suite
```

---

## Requirements

- **Core:** `pip install -r requirements.txt` (deterministic parsing, no network needed)
- **PDF reports:** `pip install -r requirements-pdf.txt` (reportlab)
- **Web dashboard:** `pip install -r requirements-web.txt` (FastAPI + uvicorn)
- **LLM fallback:** `pip install -r requirements-llm.txt` (anthropic SDK + API key)
