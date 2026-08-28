# Priority-2 Batch 1 — Correctness Audit

**Date:** 2026-08-26
**Auditor:** Automated correctness verification
**Verdict:** ALL CHECKS PASSED

## Methodology

Each control was tested across 4–5 configuration scenarios: compliant, explicitly disabled, absent config block, missing setting within present block, and (for 7.2.1) partial compliance. Every scenario was verified for:

1. **Observation correctness** — `value` and `detected` fields match expected state
2. **Pipeline status** — PASS only when fully compliant, FAIL otherwise
3. **Evidence presence** — at least 1 evidence item with source line or note
4. **False-PASS immunity** — empty/minimal configs never produce PASS
5. **False-FAIL immunity** — fully compliant configs always produce PASS

## 4.2.4 — AI/Heuristic Malware Detection

| Scenario | obs.value | obs.detected | Status | Evidence | Correct |
|----------|-----------|-------------|--------|----------|---------|
| `machine-learning-detection enable` | True | True | PASS | 1 | YES |
| `machine-learning-detection disable` | False | True | FAIL | 1 | YES |
| No `config antivirus settings` block | False | True | FAIL | 1 | YES |
| Block present, no ml setting | False | True | FAIL | 1 | YES |
| Empty config (false-PASS guard) | False | True | FAIL | 1 | YES |

## 4.2.5 — Grayware Detection

| Scenario | obs.value | obs.detected | Status | Evidence | Correct |
|----------|-----------|-------------|--------|----------|---------|
| `grayware enable` | True | True | PASS | 1 | YES |
| `grayware disable` | False | True | FAIL | 1 | YES |
| No `config antivirus settings` block | False | True | FAIL | 1 | YES |
| Block present, no grayware setting | False | True | FAIL | 1 | YES |
| Empty config (false-PASS guard) | False | True | FAIL | 1 | YES |

## 7.2.1 — Log Encryption

| Scenario | obs.value | obs.detected | Status | Evidence | Correct |
|----------|-----------|-------------|--------|----------|---------|
| `enc-algorithm high` + `reliable enable` | True | True | PASS | 1 | YES |
| `enc-algorithm low` + `reliable enable` | False | True | FAIL | 1 | YES |
| `enc-algorithm high` only (no reliable) | False | True | FAIL | 1 | YES |
| `enc-algorithm high` + `reliable disable` | False | True | FAIL | 1 | YES |
| No `config log fortianalyzer setting` | False | True | FAIL | 1 | YES |
| Empty config (false-PASS guard) | False | True | FAIL | 1 | YES |

## Evidence Traceability

All PASS-path evaluations carry evidence items with non-null `source_line` values pointing to the actual config lines that satisfied the condition. All FAIL-path evaluations carry evidence explaining why the control failed (absent block or non-compliant value).

## Multi-Vendor Isolation

- FortiGate → Palo Alto → FortiGate: identical results before and after PA evaluation
- Palo Alto → FortiGate → Palo Alto: identical results before and after FG evaluation
- Controls 4.2.4, 4.2.5, 7.2.1 correctly absent from Palo Alto reports (FortiGate-only)

## Conclusion

All 3 controls pass every correctness check. No false positives, no false negatives, no evidence gaps, no cross-vendor leakage.
