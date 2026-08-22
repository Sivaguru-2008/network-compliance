# Network Security Compliance Auditor — deterministic core

**SIH 2026 · PS SIH26155 · Step 1 of the multi-vendor compliance auditor.**

Reads a network device configuration, normalizes it into a vendor-neutral
security baseline, evaluates it against a CIS Benchmark rule pack, and reports
`PASS` / `FAIL` / `NEEDS_REVIEW` per control — each verdict backed by the exact
configuration line it came from.

No LLM, no NLP, no training loop yet. This step exists to make those additions
*drop-in* rather than a rewrite: the seams they plug into are described in
[Where the LLM plugs in](#where-the-llm-plugs-in-later).

---

## Quick start

```bash
python -m venv .venv && .venv/Scripts/activate && pip install -r requirements.txt
```

```bash
python -m auditor samples/insecure_ios.conf --framework CIS
```

Prints the report table and writes `reports/insecure_ios.cis.json`.

```bash
python -m pytest
```

### Useful flags

| Flag | Effect |
| --- | --- |
| `--framework CIS` | Which rule pack to evaluate (default `CIS`). |
| `--vendor cisco_ios` | Force a parser instead of auto-detecting the vendor. |
| `--rules path.json` | Use an explicit rule pack, bypassing framework lookup. |
| `--json path.json` | Where to write the JSON report (default `reports/<name>.<framework>.json`). |
| `--no-json` / `--quiet` | Skip the JSON file / skip the table. |
| `--no-baseline` | Omit the full normalized baseline from the JSON. |
| `--strict` | Exit non-zero on findings — `1` if anything FAILED, `3` if anything needs review. |

Without `--strict` the tool exits `0` on any successful run, so it can collect
reports in a pipeline without gating on them. Exit `2` means the config could
not be read, parsed, or evaluated.

---

## What the two samples produce

| Control | Severity | `hardened_ios.conf` | `insecure_ios.conf` |
| --- | --- | --- | --- |
| `CIS-IOS-1.2.2` — VTY accepts SSH only | high | PASS | **FAIL** — `transport input telnet` |
| `CIS-IOS-2.1.1.6` — `ip ssh version 2` | high | PASS | **NEEDS_REVIEW** — no version statement |
| `CIS-IOS-1.4.1-1.4.2` — enable secret + password encryption | high | PASS | **FAIL** — `enable password cisco123` |
| `CIS-IOS-1.5.2-1.5.3` — no default SNMP community | high | PASS | **FAIL** — `public`, `private` |
| `CIS-IOS-2.1-HTTP-SERVER` — `no ip http server` | medium | PASS | **FAIL** — `ip http server` |
| `CIS-IOS-1.2.9` — VTY exec-timeout ≤ 10 min, non-zero | medium | PASS | **FAIL** — `exec-timeout 0 0` |
| `CIS-IOS-2.2.2-2.2.4` — a logging destination exists | medium | PASS | **FAIL** — no logging configured |
| `CIS-IOS-1.1.1` — `aaa new-model` | medium | PASS | **FAIL** — not present |

`8 PASS` versus `7 FAIL + 1 NEEDS_REVIEW`. The `NEEDS_REVIEW` is deliberate and
is explained below.

---

## Pipeline

```
config text ──▶ VendorParser ──▶ SecurityBaselineModel ──▶ ComplianceEngine ──▶ AuditReport ──▶ table + JSON
              (vendor-specific)   (vendor-neutral)          (framework-neutral)
```

Each arrow is a contract, and each stage is ignorant of its neighbours'
internals:

- The **parser** knows Cisco syntax but nothing about CIS.
- The **baseline** is the only thing the engine reads — it never sees raw config text.
- The **engine** knows the baseline field vocabulary and a condition grammar, but nothing about Cisco or CIS specifics.
- **Rules** are JSON data, so a framework is swapped by adding a file to `auditor/rules/frameworks/`.

That is what makes the two planned extensions cheap: a new vendor is a new
parser, a new framework is a new JSON file, and neither touches the other side.

### `SecurityBaselineModel`

Every normalized setting is an `Observation[T]`, which binds a value to the
evidence behind it:

```python
Observation(
    value=True,                              # normalized, vendor-neutral
    detected=True,                           # was this conclusively determined?
    source_line="transport input telnet",    # the raw config line, verbatim
    line_number=41,                          # 1-based, into the source file
    origin=Origin.DETERMINISTIC,             # deterministic | llm | hybrid
    confidence=1.0,                          # 0..1
    note="Plaintext transport(s) permitted on VTY: telnet.",
)
```

Fields: `hostname`, `telnet_enabled`, `vty_transport_input`,
`vty_exec_timeout_seconds`, `ssh_enabled`, `ssh_version`, `http_server_enabled`,
`https_server_enabled`, `enable_secret_set`, `enable_password_present`,
`password_encryption`, `aaa_enabled`, `snmp_communities`, `logging_enabled`,
`logging_hosts`, `logging_buffered`.

---

## Three design decisions worth defending

### 1. `NEEDS_REVIEW` is a first-class verdict

Conditions evaluate in **Kleene three-valued logic**, not boolean:

| Condition | Verdict |
| --- | --- |
| The config proves the control is met | `PASS` |
| The config proves the control is violated | `FAIL` |
| The config proves neither | `NEEDS_REVIEW` |

For `all_of`, one *proven* violation condemns the control even when other
operands are unknown; unknown wins only when nothing is proven false. `any_of`
is the mirror image. The practical effect: **missing evidence is never rounded
up to PASS.** An auditor who cannot see a setting says so, and escalates.

### 2. When "no line" *is* evidence — a stated per-setting policy

Absence is ambiguous in general, so the parser declares a policy per setting
rather than applying one blanket rule (`auditor/parsers/cisco_ios.py`):

- **Conclusive absence** — the command is off by default *and* always written
  back into the running-config when configured, so "not present" provably means
  "not configured". Recorded as `detected=True` with the insecure value and a
  note naming the absence as the evidence.
  → `enable secret`, `enable password`, `service password-encryption`,
  `aaa new-model`, `logging host`, `logging buffered`, `snmp-server community`.

- **Ambiguous absence** — the effective value comes from a platform default that
  varies by IOS train, or the section may simply be missing from an excerpt.
  Recorded as `detected=False` → `NEEDS_REVIEW`. Never guessed.
  → `ip http server` (default differs across trains), `ip ssh version` (1.99
  fallback depends on release and RSA key state), `transport input` (`all` on
  12.x, `none` on 15.x+), `exec-timeout`.

This is why `insecure_ios.conf` yields `NEEDS_REVIEW` on SSH version: the file
has no `ip ssh version` line at all, and the honest answer is "a human must
check the device", not "fail" and not "pass".

### 3. Aggregation is worst-case

A device is only as strong as its weakest management path. If *any* `line vty`
block permits telnet, `telnet_enabled` is true. If *any* block has
`exec-timeout 0`, the device's VTY timeout is "never". And clean-but-incomplete
evidence is not proof: if some VTY blocks specify no transport at all, the
result is `NEEDS_REVIEW` rather than a pass.

---

## Rule packs

`auditor/rules/frameworks/cis_cisco_ios.json` holds the eight controls. A rule
refers only to baseline fields, never to Cisco syntax:

```json
{
  "id": "CIS-IOS-1.2.2",
  "control_ref": "1.2.2",
  "title": "Set 'transport input ssh' for 'line vty' connections",
  "severity": "high",
  "baseline_fields": ["telnet_enabled", "vty_transport_input"],
  "condition": {
    "all_of": [
      { "field": "telnet_enabled", "operator": "is_false" },
      { "field": "vty_transport_input", "operator": "subset_of", "value": ["ssh"] }
    ]
  },
  "remediation": {
    "summary": "Restrict every VTY line to the SSH transport.",
    "cli": ["configure terminal", " line vty 0 15", "  transport input ssh", " end", "copy running-config startup-config"]
  }
}
```

Conditions nest with `all_of` / `any_of` / `not` over leaves using a closed
operator vocabulary (`equals`, `is_true`, `is_false`, `greater_than`,
`less_or_equal`, `in_set`, `subset_of`, `contains_any`, `contains_none`,
`is_empty`, `is_not_empty`, `matches_regex`, …). `select` plucks an attribute
from list-valued fields — that is how the SNMP rule compares community *names*.

Two guards keep hand-edited packs honest:

- `baseline_fields` is validated against the fields the condition actually reads.
- The engine refuses to start if a rule names a field that does not exist on
  `SecurityBaselineModel`, naming the offending rule.

**On CIS clause numbers:** conditions and remediation follow the CIS Cisco IOS
Benchmark. Clause numbers are recorded for traceability and should be
re-confirmed against your licensed copy for the IOS train you audit — the
numbering differs between the IOS 15 and IOS 17 editions. The HTTP server rule
carries a section-level `control_ref` (`2.1`, Global Service Rules) and a note,
because its exact clause could not be pinned with confidence; the other seven
carry specific clause numbers.

---

## Where the LLM plugs in later

The `VendorParser` ABC is the seam. It requires exactly one thing —
`parse(config_text) -> SecurityBaselineModel` — plus a `detect(config_text)`
score that the registry uses to pick a parser. An `LLMParser` for unknown
vendors implements that same interface and registers a low constant `detect()`
floor (say `0.05`), so it wins only when no deterministic parser claims the
config: fallback dispatch with no routing logic to rewrite, and the engine, the
rule packs, and the report layer stay untouched. Its output is
distinguishable rather than blindly trusted, because every `Observation`
already carries `origin` (`deterministic` / `llm` / `hybrid`) and a `confidence`
score — so the report can flag LLM-derived findings, the engine can later be
told to treat sub-threshold confidence as `NEEDS_REVIEW`, and a `HYBRID` parser
can let the LLM fill only the fields the deterministic pass left undetected.
That same structure is what makes the **training loop** possible: run both
parsers over configs the deterministic one already handles, diff the LLM's
`Observation`s against deterministic ground truth field by field, and use the
disagreements as labelled training and calibration data — while the JSON report
(which embeds the full baseline, not just verdicts) supplies human-reviewed
`NEEDS_REVIEW` adjudications as a second, higher-value label source.

---

## Layout

```
auditor/
  models/
    observation.py   Observation[T] — value + evidence + provenance
    baseline.py      SecurityBaselineModel — the vendor-neutral contract
    rule.py          ComplianceRule, conditions, operators, RuleSet
    result.py        Status, Evidence, ControlResult, AuditReport
  parsers/
    base.py          VendorParser ABC + ParserRegistry (LLMParser plugs in here)
    cisco_ios.py     CiscoIOSParser — ciscoconfparse2, absence policy, worst-case aggregation
  rules/
    loader.py        pack discovery + schema validation
    frameworks/cis_cisco_ios.json
  engine/
    conditions.py    three-valued logic + operator implementations
    evaluator.py     ComplianceEngine — rules × baseline → report
  report/
    table.py         dependency-free CLI table
    json_report.py   structured JSON
  cli.py             argument parsing and wiring only
samples/             hardened_ios.conf, insecure_ios.conf
tests/               137 tests
```

## Tests

```bash
python -m pytest
```

Covers the normalized baseline for both samples field by field, the expected
verdict matrix per control, evidence integrity (every cited line number must
actually contain the cited text), the three-valued logic truth tables, the
operator truth table, rule-pack validation, and the CLI end to end.

Two tests specifically pin the "no hardcoded verdicts" constraint: editing one
line of the hardened config must flip exactly one control to `FAIL`, and
remediating the insecure config must turn all eight controls green.
