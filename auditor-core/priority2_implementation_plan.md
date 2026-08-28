# Priority-2 Implementation Plan — Batch 1

**Date:** 2026-08-26
**Baseline:** 1021 tests passing, 41/123 controls automated

---

## Selected Controls

| Control | Title | Config Block | Complexity |
|---|---|---|---|
| 4.2.4 | Enable AI/heuristic based malware detection | `config antivirus settings` | LOW |
| 4.2.5 | Enable grayware detection on antivirus | `config antivirus settings` | LOW |
| 7.2.1 | Encrypt Log Transmission to FortiAnalyzer/FortiManager | `config log fortianalyzer setting` | LOW |

**Expected coverage gain:** 41 → 44 / 123 (3 controls)

---

## Control Details

### 4.2.4 — AI Malware Detection

**Benchmark requirement:** AI/heuristic-based malware detection must be enabled in antivirus settings.

**Audit procedure (CLI):**
```
show antivirus settings | grep machine-learning-detection
```
Validate that `machine-learning-detection` is `enable`.

**Remediation:**
```
config antivirus settings
set machine-learning-detection enable
end
```

**Default value:** Enabled.

**Required parser change:** Add `_normalize_av_ai_detection` method to `FortiosParser`. Parse `config antivirus settings` block, extract `machine-learning-detection` setting.

**Required model field:** `av_ai_detection_enabled: Observation[bool]`

**Mapping change:** Update `fortigate_map.json` entry for `4.2.4`:
- `evaluation_type`: `DETERMINISTIC`
- `baseline_field`: `av_ai_detection_enabled`
- `condition_json`: `{"field": "av_ai_detection_enabled", "operator": "is_true"}`

**Database change:** Rebuild knowledge.db with updated mapping.

**Evidence:** Source line from `set machine-learning-detection enable/disable`.

**False-PASS risk:** LOW — simple boolean, no ambiguity.
**False-FAIL risk:** LOW — default is enabled, so presence of block with no explicit setting could be compliant. Parser treats absent setting within block as non-compliant (conservative).

---

### 4.2.5 — Grayware Detection

**Benchmark requirement:** Grayware detection must be enabled in antivirus settings.

**Audit procedure (CLI):**
```
show antivirus settings | grep grayware
```
Validate that `grayware` is `enable`.

**Remediation:**
```
config antivirus settings
set grayware enable
end
```

**Default value:** Disabled.

**Required parser change:** Extract `grayware` setting from same `config antivirus settings` block as 4.2.4. Combined into single `_normalize_av_settings` method.

**Required model field:** `av_grayware_enabled: Observation[bool]`

**Mapping change:** Update `fortigate_map.json` entry for `4.2.5`:
- `evaluation_type`: `DETERMINISTIC`
- `baseline_field`: `av_grayware_enabled`
- `condition_json`: `{"field": "av_grayware_enabled", "operator": "is_true"}`

**Database change:** Rebuild knowledge.db with updated mapping.

**Evidence:** Source line from `set grayware enable/disable`.

**False-PASS risk:** LOW — simple boolean, default is disabled (so absent = correctly FAIL).
**False-FAIL risk:** LOW — no edge cases.

---

### 7.2.1 — Log Encryption

**Benchmark requirement:** Log transmission to FortiAnalyzer/FortiManager must use encryption. Two settings required: `enc-algorithm high` AND `reliable enable`.

**Audit procedure (CLI):**
```
config log fortianalyzer setting
get
```
Validate `enc-algorithm` is `high`. Validate `reliable` is `enable`.

**Remediation:**
```
config log fortianalyzer setting
set reliable enable
set enc-algorithm high
end
```

**Default value:** Disabled.

**Required parser change:** Add `_normalize_log_encryption` method to `FortiosParser`. Parse `config log fortianalyzer setting` block, extract `enc-algorithm` and `reliable` settings.

**Required model field:** `log_encryption_enabled: Observation[bool]`

**Mapping change:** Update `fortigate_map.json` entry for `7.2.1`:
- `evaluation_type`: `DETERMINISTIC`
- `baseline_field`: `log_encryption_enabled`
- `condition_json`: `{"all_of": [{"field": "log_encryption_enabled", "operator": "is_true"}]}`

**Database change:** Rebuild knowledge.db with updated mapping.

**Evidence:** Source lines from `set enc-algorithm` and `set reliable`.

**False-PASS risk:** LOW — requires both settings to be compliant.
**False-FAIL risk:** LOW — absent block = FAIL (default disabled).

---

## Tests Required

For each control (4.2.4, 4.2.5, 7.2.1):

1. **PASS case** — fully compliant config
2. **FAIL case** — explicitly non-compliant
3. **Absent case** — config block missing
4. **Block-present-no-setting case** — block exists but key setting absent
5. **False-PASS guard** — deliberately non-compliant must not PASS
6. **False-FAIL guard** — deliberately compliant must not FAIL
7. **Evidence case** — verify source_line and line_number

For 4.2.4 + 4.2.5 combined: test both settings in same block.

For 7.2.1: test partial compliance (enc-algorithm without reliable, and vice versa).

---

## Cross-Vendor Reuse

- These fields are FortiOS-specific (`config antivirus settings`, `config log fortianalyzer setting`).
- No Palo Alto equivalent mapping needed at this time.
- The generic `ComplianceEngine` evaluator is unchanged — all conditions use existing operators (`is_true`, `all_of`).

---

## Architectural Impact

- **Parser:** Two new normalization methods added to `FortiosParser`
- **Model:** Two new `Observation[bool]` fields on `SecurityBaselineModel`
- **Mapping:** Three entries updated from PARSER_REQUIRED to DETERMINISTIC
- **Database:** Rebuilt with updated mappings
- **Evaluator:** No changes
- **LLM schema:** Two new `BooleanFinding` fields added

No architectural blockers identified.
