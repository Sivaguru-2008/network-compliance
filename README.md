# Network Security Compliance Auditor — deterministic core

SIH 2026 · PS **SIH26155** — AI-driven multi-vendor network security compliance auditor.

This repository is **Step 1**: the deterministic vertical slice. It ingests one Cisco IOS
configuration, normalizes it into a vendor-neutral **Security Baseline Model**, evaluates it
against eight real CIS Benchmark controls, and emits a per-control report with severity,
the exact evidence line, and CIS-sourced remediation CLI.

There is deliberately **no LLM, no NLP, and no training loop yet** — but every seam they will
plug into already exists and is documented at the end of this file.

---

## Quick start

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
```

Audit the deliberately weak sample:

```bash
.venv/Scripts/python -m auditor samples/insecure_ios.conf --framework CIS
```

Audit the hardened sample:

```bash
.venv/Scripts/python -m auditor samples/hardened_ios.conf --framework CIS
```

Both print a report table and write a JSON report to `reports/<config-name>.cis.json`.

### CLI options

| Flag | Purpose |
| --- | --- |
| `--framework CIS` | Benchmark to evaluate against (rule files are discovered by framework + platform). |
| `--vendor auto\|cisco_ios` | Force a parser instead of auto-detecting from the config text. |
| `--rules PATH` | Use an explicit rule file, overriding `--framework`. |
| `-o, --json PATH` | Where to write the JSON report. |
| `--no-json`, `--quiet`, `--no-color`, `--width N` | Output control. |
| `--exit-code` | Exit `1` if any control FAILs, `2` if any is NEEDS_REVIEW. For CI gating. |

Run the tests:

```bash
.venv/Scripts/python -m pytest -q
```

---

## What the output looks like

```
STATUS        SEV    CONTROL         TITLE                              EVIDENCE
FAIL          HIGH   CIS-IOS-1.2.5   Set 'transport input ssh' for '... line vty 0 4 / transport...
FAIL          MEDIUM CIS-IOS-2.1.5   Configure 'no ip http server'      L16: ip http server
NEEDS_REVIEW  HIGH   CIS-IOS-2.1.6   Configure 'ip ssh version 2'       <no evidence>

 Summary    : 0 PASS   7 FAIL   1 NEEDS_REVIEW   of 8 controls
 Score      : 0.0% (NEEDS_REVIEW counts against the score: unverified is not compliant)
```

Every finding is then expanded with its reason, evidence lines, risk rationale, and the exact
remediation commands.

---

## Architecture

Four stages, four contracts. Each stage can be replaced without touching the others.

```
config text
    │
    ▼  VendorParser.parse()                  parsers/
SecurityBaselineModel   ← vendor-neutral, evidence-carrying   models/baseline.py
    │
    ▼  rule engine (three-valued logic)      engine/
ControlResult[]         ← PASS / FAIL / NEEDS_REVIEW + evidence + remediation
    │
    ▼  report renderers                      report/
CLI table  +  JSON report
```

```
auditor/
├── models/
│   ├── observation.py   Observation[T] + Evidence: value, detected, source_line, why
│   ├── baseline.py      SecurityBaselineModel — the parse/evaluate contract
│   └── findings.py      Status, Severity, ControlResult, AuditReport
├── parsers/
│   ├── base.py          VendorParser ABC + ParserRegistry (auto-detect, fallback slot)
│   └── cisco_ios.py     CiscoIOSParser, built on ciscoconfparse2
├── rules/
│   ├── schema.py        ComplianceRule, Condition, Operator — rules are inert data
│   ├── loader.py        discovery + validation of rule files
│   └── frameworks/
│       └── cis_cisco_ios.json     the 8 CIS controls
├── engine/
│   ├── tristate.py      Kleene TRUE / FALSE / UNKNOWN
│   ├── resolver.py      "vty_exec_timeout.total_seconds" → value + evidence
│   ├── operators.py     the only comparisons a rule file may use
│   └── evaluator.py     rule + baseline → ControlResult
├── report/
│   ├── table.py         human-readable CLI rendering
│   └── json_report.py   structured JSON (schema generated from the model)
├── pipeline.py          parse → normalize → evaluate → report
└── cli.py               argparse entry point (python -m auditor)
```

### The Security Baseline Model

Every security-relevant setting is an `Observation`, never a bare value:

```python
Observation(
    value=True,                       # normalized, vendor-neutral
    detected=True,                    # is this backed by evidence?
    evidence_type="explicit",         # explicit | absence | none
    source_line=" transport input telnet",
    evidence=[Evidence(text=..., line_number=..., context="line vty 0 4")],
    note="At least one vty line accepts cleartext telnet.",
)
```

Current fields: `aaa_enabled`, `enable_secret_set`, `password_encryption`, `telnet_enabled`,
`ssh_version`, `http_server_enabled`, `vty_exec_timeout`, `logging_enabled`,
`snmp_communities`, plus `device` provenance and the structural `terminal_lines`.

### Evidence policy — why NEEDS_REVIEW exists

The parser is allowed to reach exactly three conclusions about any setting:

| Evidence type | Meaning | `detected` | Verdict effect |
| --- | --- | --- | --- |
| `explicit` | A config line states the value (`ip ssh version 2`). | `True` | PASS or FAIL |
| `absence` | The directive is one IOS *always* renders when active, so its absence proves the feature is **off** (`aaa new-model`, `service password-encryption`, `enable secret`, `logging host`). | `True` | Fails **closed** |
| `none` | The setting genuinely cannot be read from the text — a platform default applies, or the excerpt is partial. | `False` | **NEEDS_REVIEW** |

The third case is the important one. `ip http server` is on by default on some IOS images and
off on others, so a config with neither `ip http server` nor `no ip http server` is unknowable
from text alone. The tool says so instead of guessing. **A control we could not verify is never
reported as compliant** — and NEEDS_REVIEW counts against the compliance score.

The engine evaluates rules with three-valued (Kleene) logic, so a missing input only decides
the outcome when it actually matters:

* `telnet_disabled AND timeout_ok` → **FAIL** if telnet is proven on, even when the timeout is unknown.
* `sshv2 OR telnet_disabled` → **PASS** if either is proven, even when the other is unknown.
* Only when the unknown input is decisive does the control become NEEDS_REVIEW.

---

## The eight CIS controls

| Rule id | CIS control(s) | Severity | Check (baseline field) |
| --- | --- | --- | --- |
| `CIS-IOS-1.1.1` | 1.1.1 | medium | `aaa_enabled` is true |
| `CIS-IOS-1.2.5` | 1.2.5 | high | `telnet_enabled` is false (no vty accepts telnet/all) |
| `CIS-IOS-1.2.7` | 1.2.7 | medium | `vty_exec_timeout` not disabled **and** ≤ 600 s |
| `CIS-IOS-1.4.1` | 1.4.1, 1.4.2 | high | `enable_secret_set` **and** `password_encryption` |
| `CIS-IOS-1.5.2` | 1.5.2, 1.5.3 | high | no `snmp_communities` named `public` / `private` |
| `CIS-IOS-2.1.5` | 2.1.5 | medium | `http_server_enabled` is false |
| `CIS-IOS-2.1.6` | 2.1.6 | high | `ssh_version` equals 2 |
| `CIS-IOS-2.2.2` | 2.2.2, 2.2.3 | medium | `logging_enabled` is true |

> **On the control numbers:** these follow the published CIS Cisco IOS Benchmark section
> numbering. The check logic and the remediation commands are the substantive part and are
> independent of the numbering — verify the exact section numbers against your licensed copy of
> the benchmark before using the output in a formal audit.

### Adding a control or a framework

Rules are pure JSON — no Python, no vendor syntax:

```json
{
  "id": "CIS-IOS-1.1.1",
  "severity": "medium",
  "check": { "field": "aaa_enabled", "op": "is_true" },
  "remediation": { "summary": "...", "commands": ["configure terminal", " aaa new-model", "end"] }
}
```

Conditions can nest with `all_of` / `any_of` / `not`, and address structured values by path
(`vty_exec_timeout.total_seconds`) or list contents (`item_path: "name"`). A rule file is
validated against `SecurityBaselineModel` at load time, so a typo in a field name fails loudly
instead of silently producing NEEDS_REVIEW for every device.

A new framework is a new file in `auditor/rules/frameworks/` with its own `framework` and
`platform` header — it is discovered automatically. If a rule needs a setting nobody normalizes
yet, add the field to the baseline model **first**, then the rule.

---

## How the LLM parser and the training loop plug in later

The single extension point is `VendorParser` (`auditor/parsers/base.py`): one method,
`parse(config_text) -> SecurityBaselineModel`. Step 2's `LLMParser` implements that same
interface for vendors we have no deterministic grammar for — it prompts the model to emit the
baseline schema as JSON, validates the response with the same pydantic model (so a
hallucinated field is a validation error, not a silent wrong answer), and marks its output with
`DeviceInfo.parser="llm"` and a `confidence` below 1.0. It registers via
`REGISTRY.set_fallback(LLMParser)`, so auto-detection uses the deterministic parser whenever
one claims the config and only falls back to the model otherwise. The rule engine, the rule
files, the report layer and the CLI need **no changes at all** — they only ever see a baseline.
The training/feedback loop then closes on the same contract: because every `Observation`
carries its `source_line` and every `ControlResult` carries the evidence it used, a reviewer
correcting a NEEDS_REVIEW or a wrong value produces a `(config snippet → correct normalized
field)` pair automatically. Those pairs become few-shot examples and fine-tuning data for the
LLM parser, and — where a correction reveals a pattern the deterministic parser could have
matched — a new regex in `CiscoIOSParser`, which is always preferred because it is free,
instant, and reproducible. NEEDS_REVIEW is therefore not just a safety valve: it is the label
queue that the learning loop feeds on.

---

## Samples

| File | Purpose |
| --- | --- |
| `samples/hardened_ios.conf` | Reasonably hardened device — currently 8/8 PASS. |
| `samples/insecure_ios.conf` | Telnet on, HTTP server on, `public`/`private` SNMP, no logging, no AAA, SSHv1, plaintext enable password, `exec-timeout 0 0` — currently 8/8 FAIL. |

The tests also cover a third, *ambiguous* configuration (inline in `tests/conftest.py`) that is
silent about SSH version, HTTP server, and vty transports, and must therefore produce
NEEDS_REVIEW rather than PASS for those three controls.

Nothing is keyed to a file name: `tests/test_engine.py` patches a single line in each sample and
asserts that exactly the affected control flips verdict.
