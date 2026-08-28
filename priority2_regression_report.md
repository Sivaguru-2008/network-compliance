# Priority-2 Batch 1 — Regression Report

**Date:** 2026-08-26
**Baseline:** 1025 tests
**Result:** 1025 passed, 0 failed, 0 regressions

## Regression Run

```
platform win32 -- Python 3.12.10, pytest-9.1.1
collected 1025 items
1025 passed, 5 warnings in 69.52s
```

## Failures Encountered and Resolved

During the regression cycle, 6 test failures were identified. All were analyzed for root cause and resolved without modifying test assertions to hide failures.

### Category 1: Expected Count Updates (caused by implementation)

| Test | Old Value | New Value | Reason |
|------|-----------|-----------|--------|
| `test_architecture_refactor::test_rule_loading` rules | 24 | 27 | 3 new DETERMINISTIC rules |
| `test_architecture_refactor::test_rule_loading` non_evaluable | 32 | 29 | 3 moved from PARSER_REQUIRED |
| `test_architecture_refactor::test_fortigate_regression` failed | 13 | 16 | 3 new controls FAIL on sample config |
| `test_architecture_refactor::test_fortigate_regression` unsupported | 8 | 5 | 3 moved to DETERMINISTIC |

**Root cause:** Adding 3 controls as DETERMINISTIC shifts them from the PARSER_REQUIRED/UNSUPPORTED bucket into the evaluable bucket. The sample config (`fortios_fgt.conf`) lacks `config antivirus settings` and `config log fortianalyzer setting` blocks, so all 3 correctly FAIL. This is expected behavior — the count updates reflect the actual new state.

### Category 2: Knowledge DB Rebuild Side Effect

| Test | Symptom | Root Cause |
|------|---------|------------|
| `test_bulk_ingestion::test_bulk_cli_renders_an_inventory_and_writes_json` | Exit code 2 | DB rebuild dropped NIST/STIG/ISO framework rules |
| `test_bulk_ingestion::test_bulk_cli_rejects_an_unknown_framework_once` | "NIST_800_53" not in error | Same — only CIS was available |
| `test_cis_paloalto::test_compliant_configuration` | 67 total, expected 80 | Same — bootstrap framework rules missing |
| `test_cis_paloalto::test_non_compliant_configuration` | 67 total, expected 80 | Same |

**Root cause:** The DB was rebuilt using only `populate_fortigate_kb` and `populate_paloalto_kb`, which populate CIS rules. The framework-level rules (NIST_800_53, STIG, ISO_27001) are populated by `bootstrap_database_if_empty`, which only runs on an empty DB. Since CIS data was already present, bootstrap was skipped.

**Fix:** Rebuilt knowledge.db by:
1. Deleting the DB
2. Running `bootstrap_database_if_empty()` first (populates framework rules)
3. Running `populate_fortigate_kb()` (adds CIS FortiGate rules)
4. Running `populate_paloalto_kb()` (adds CIS Palo Alto rules)

This restored all 4 frameworks (CIS, NIST_800_53, STIG, ISO_27001) and the correct Palo Alto total of 80 (67 CIS + 13 framework-bootstrapped).

## Unmodified Tests

No test was deleted. No test assertion was weakened. No test was modified "merely to make it pass." All changes to test files were count updates that accurately reflect the new system state after adding 3 DETERMINISTIC controls.

## Vendor Isolation

- FortiGate changes did not affect any Palo Alto test
- Palo Alto test suite: 38/38 passed
- Multi-vendor isolation tests: 5/5 passed
- No cross-vendor state leakage detected
