# FortiGate 4.2.1 Resolution — AV Auto-Update Benchmark Ambiguity

**Date:** 2026-08-26
**Control:** CIS FortiGate 7.0.x Benchmark v1.4.0, Rule 4.2.1
**Status:** RESOLVED — Implementation corrected to match authoritative audit/remediation procedures

---

## 1. Benchmark Evidence

### Title
"Ensure Antivirus Definition Push Updates are Configured"

### Description
"Ensure FortiGate is configured to accept antivirus definition push updates."

### Rationale
"Ensure that the FortiGate will accept push updates from FortiGuard to ensure the most up to date signature databases are present on the device."

### Audit Procedure (verbatim from benchmark)
```
On GUI:
1. Access the FortiGate administrative web access page and go to System >
   FortiGuard.
2. Under "FortiGuard Updates" ensure that the "Scheduled updates" is set to
   "Automatic".

On CLI:
config system autoupdate schedule
show (Validate that there are no output, meaning it is already set as "automatic")
```

### Remediation Procedure (verbatim from benchmark)
```
On GUI:
1. Access the FortiGate administrative web access page and go to System >
   FortiGuard.
2. Under "FortiGuard Updates" ensure that the "Scheduled updates" is set to
   "Automatic".

On CLI:
config system autoupdate schedule
set status enable
set frequency automatic
end
```

### Default Value
"Enabled and set to automatic."

### Source
CIS_Fortigate_7.0.x_Benchmark_v1.4.0.pdf, page 107.

---

## 2. Conflicting Instructions

The benchmark contains an internal inconsistency between its **title/description** and its **audit/remediation procedures**:

| Element | References | FortiOS Config Block |
|---|---|---|
| Title | "Push Updates" | `config system autoupdate push-update` |
| Description | "push updates" | `config system autoupdate push-update` |
| Rationale | "push updates" | `config system autoupdate push-update` |
| GUI audit | "Scheduled updates → Automatic" | `config system autoupdate schedule` |
| CLI audit | `config system autoupdate schedule` | `config system autoupdate schedule` |
| GUI remediation | "Scheduled updates → Automatic" | `config system autoupdate schedule` |
| CLI remediation | `config system autoupdate schedule` | `config system autoupdate schedule` |

In FortiOS, these are **two distinct configuration blocks**:

- **`config system autoupdate push-update`** — Controls whether the FortiGate accepts real-time push notifications from FortiGuard when new signatures are available. This is an event-driven, server-initiated mechanism.
- **`config system autoupdate schedule`** — Controls the device's own scheduled/automatic polling of FortiGuard for signature updates. Settings include `status` (enable/disable) and `frequency` (every/daily/weekly/automatic).

These are complementary but separate features. The title implies the first; the audit/remediation procedures unambiguously specify the second.

---

## 3. Interpretation

The **audit and remediation procedures** are the authoritative, actionable compliance verification steps in a CIS benchmark. They are what an auditor follows to verify compliance and what an administrator follows to remediate non-compliance.

Both the GUI and CLI audit procedures reference "Scheduled updates" / `config system autoupdate schedule` — not push-update. The remediation explicitly sets `status enable` and `frequency automatic` within the `schedule` block.

The CIS Controls mapping (v8 10.2: "Configure Automatic Anti-Malware Signature Updates") aligns with ensuring automatic updates are configured, which is the `schedule` mechanism.

The title's use of "Push Updates" appears to be a misnomer. In FortiOS terminology, enabling `schedule` with `frequency automatic` ensures the device automatically receives the latest signatures — the benchmark likely uses "push" colloquially to mean "automatically delivered" rather than the specific FortiOS `push-update` feature.

---

## 4. Implementation Assessment (Before Fix)

The implementation checked the **wrong configuration block**:

- **Parser** (`fortios.py:_normalize_av_push`): Parsed `config system autoupdate push-update` and checked `status = enable`.
- **Baseline field**: `av_push_updates_enabled`
- **Mapping** (`fortigate_map.json` key `4.2.1`): Condition `av_push_updates_enabled is_true`
- **Tests** (`test_parser_fortios.py:test_av_push_parsing`): Tested against `config system autoupdate push-update` blocks.

This implementation would produce a **false PASS** on a device that has `push-update` enabled but `schedule` disabled, and a **false FAIL** on a device that has `schedule` set to automatic but no explicit `push-update` block.

---

## 5. Decision

**Correct the implementation** to check `config system autoupdate schedule` with:
- `status` = `enable` (or absent within block, since default is enable)
- `frequency` = `automatic` (or absent within block, since default is automatic)

Block-level absence handling:
- If the `config system autoupdate schedule` block is entirely absent from the configuration, the control evaluates as **FAIL** (absent evidence), consistent with the codebase's established "absence is conclusive" policy for FortiOS complete configurations.
- The benchmark's audit note ("Validate that there are no output, meaning it is already set as automatic") refers to FortiOS `show` behavior (which omits defaults). Our parser processes `show full-configuration` output where all blocks appear explicitly.

The baseline field name `av_push_updates_enabled` is retained for backward compatibility and minimal blast radius. Its description is updated to reflect the corrected semantics.

---

## 6. Remaining Ambiguity

The benchmark title says "Push Updates" but the audit/remediation check "Scheduled updates." A fully hardened device should arguably have **both** push-update and schedule enabled. However, the benchmark defines exactly one audit procedure and it checks `schedule`, not `push-update`. Implementing a check for both would exceed the benchmark's stated requirement.

If a future benchmark revision clarifies this, the implementation should be revisited.

---

## 7. Recommended Treatment in Audit Reports

- **Report the control result** based on the `schedule` check (as implemented).
- **Include a note** in the evidence/rationale field: "CIS 4.2.1 audit procedure checks `config system autoupdate schedule` (automatic signature updates). The benchmark title references 'push updates' but the audit/remediation procedures specify the schedule configuration."
- **Do not** suppress or hide the control.
- **Do not** mark as NEEDS_REVIEW — the audit procedure is unambiguous.
