# Priority-2 Batch 1 — Implementation Report

**Date:** 2026-08-26
**Scope:** CIS FortiGate 7.0.x controls 4.2.4, 4.2.5, 7.2.1
**Status:** COMPLETE

## Controls Implemented

### 4.2.4 — Ensure AI/Heuristic Based Malware Detection Is Enabled

- **Baseline field:** `av_ai_detection_enabled: Observation[bool]`
- **Parser method:** `_normalize_av_settings` in `auditor/parsers/fortios.py`
- **Config block parsed:** `config antivirus settings` → `set machine-learning-detection enable`
- **Map entry:** DETERMINISTIC with condition `{"field": "av_ai_detection_enabled", "operator": "is_true"}`
- **Absent behavior:** `Observation.absent(False, ...)` — FAIL (no false PASS)

### 4.2.5 — Ensure Grayware Detection Is Enabled

- **Baseline field:** `av_grayware_enabled: Observation[bool]`
- **Parser method:** `_normalize_av_settings` (shared with 4.2.4)
- **Config block parsed:** `config antivirus settings` → `set grayware enable`
- **Map entry:** DETERMINISTIC with condition `{"field": "av_grayware_enabled", "operator": "is_true"}`
- **Absent behavior:** `Observation.absent(False, ...)` — FAIL (no false PASS)

### 7.2.1 — Ensure Log Encryption Is Enabled

- **Baseline field:** `log_encryption_enabled: Observation[bool]`
- **Parser method:** `_normalize_log_encryption` in `auditor/parsers/fortios.py`
- **Config block parsed:** `config log fortianalyzer setting` → requires BOTH `set enc-algorithm high` AND `set reliable enable`
- **Map entry:** DETERMINISTIC with condition `{"field": "log_encryption_enabled", "operator": "is_true"}`
- **Absent behavior:** `Observation.absent(False, ...)` — FAIL (no false PASS)

## Files Modified

| File | Change |
|------|--------|
| `auditor/models/baseline.py` | Added 3 new `Observation[bool]` fields |
| `auditor/parsers/fortios.py` | Added `_normalize_av_settings`, `_normalize_log_encryption`; fixed `_normalize_av_push` for 4.2.1 |
| `auditor/cis/fortigate_map.json` | Changed 4.2.4, 4.2.5, 7.2.1 from PARSER_REQUIRED to DETERMINISTIC |
| `auditor/parsers/llm/schema.py` | Added 3 new BooleanFinding fields |
| `auditor/parsers/llm/parser.py` | Added 3 entries to FIELD_TYPES |
| `tests/llm_stub.py` | Added 3 new BooleanFinding entries to KINDS |
| `tests/test_parser_fortios.py` | Added parser tests for all 3 controls |
| `tests/test_cis_fortigate.py` | Added pipeline assertions for 4.2.4, 4.2.5, 7.2.1; updated counts |
| `tests/test_architecture_refactor.py` | Updated hardcoded counts: rules 24→27, failed 13→16, unsupported 8→5, non_evaluable 32→29 |
| `auditor/rules/knowledge.db` | Rebuilt with framework bootstrap + CIS population |

## Coverage Change

| Metric | Before | After |
|--------|--------|-------|
| FortiGate DETERMINISTIC | 24 | 27 |
| FortiGate PARSER_REQUIRED | 8 | 5 |
| FortiGate MANUAL | 24 | 24 |
| Evaluable controls | 24 | 27 |
| Total controls | 56 | 56 |

## Test Summary

- **New parser tests:** 4 test functions, 23 parametrized cases
- **New pipeline assertions:** 3 FAIL expectations + count updates
- **Full regression:** 1025/1025 passed, 0 failures
