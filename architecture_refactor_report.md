# Pre-Palo-Alto Architecture Refactor Report

## 1. Refactoring Summary
This refactoring generalizes the FortiGate-specific elements of the compliance auditor, preparing the architecture for Palo Alto integration. Mappings are moved from static Python declarations into declarative JSON configuration, and vendor-specific fields are normalized.

## 2. Baseline Model Changes
The following field has been generalized:
- **Old Field**: `admin_tls13_only` (Observation[bool])
- **New Semantic Field**: `management_min_tls_version` (Observation[str])
- **Reasoning**: Minimum TLS versions are configured on most modern network and firewall devices (including Palo Alto). Storing this as a string version (e.g. `'1.3'`) allows vendor-neutral checks.
- **Backward Compatibility**: `admin_tls13_only` is fully retained and populated alongside `management_min_tls_version`.

## 3. Mapping Migration
The mappings embedded in `fortigate_map.py` have been migrated to the declarative file `fortigate_map.json`.
- **Location**: `auditor/cis/fortigate_map.json`
- **Dynamic Loading**: `fortigate_map.py` now reads, parses, and validates the configuration file at runtime.
- **Validation**: Rejects invalid schemas, duplicate rule IDs, and references to nonexistent baseline fields.

## 4. Evidence Preservation
Raw configuration lines, line numbers, and parsed values survive normalization by being packed directly into the `Observation` objects under the `source_line` and `line_number` attributes. The compliance engine uses these to build report evidence, meaning all results remain traceable to the raw input text.

## 5. Compatibility
Existing FortiGate semantics remain entirely unchanged. The parser populates both fields, and evaluation returns identical outcomes.
- **Baseline PASS controls**: `2.1.5`, `7.1.1`, `7.3.1` (unchanged)
- **Baseline FAIL controls**: `2.1.1`, `2.1.2`, `2.2.1`, `2.2.2`, `2.3.1`, `2.4.2`, `2.4.4`, `2.4.5`, `2.4.7` (unchanged)
- **Baseline NEEDS_REVIEW controls**: `1.1`, `2.1.10`, `2.1.11`, `2.1.12`, `2.1.4`, `2.1.7`, `2.1.8`, `2.1.9` (unchanged)

## 6. Database Integrity
Rule definitions are loaded from SQLite `knowledge.db` per the declarative mapping specifications.
- Verified rule ID consistency: all 56 rules have matching DB records.
- Verified version and benchmark provenance: CIS FortiGate 7.0.x Benchmark v1.4.0 is preserved.

## 7. Test Results
- **Before Refactoring**: **957** passed tests
- **After Refactoring**: **965** passed tests (includes 8 new architecture-level validation tests)
- **Status**: All tests passing successfully, 0 failures.

## 8. Remaining Vendor-Specific Fields
The following fields were intentionally retained:
- `gui_cdn_enabled`: CDN integration for administrative GUI performance is a specific FortiOS configuration feature. Retained to avoid forcing a fake abstraction on other vendors.
- `log_single_cpu_high_enabled`: Logging of single-CPU overload events is specific to FortiOS daemon architectures.
- `event_logging_enabled`: FortiOS class-specific system event filter toggle has no direct equivalent in generic syslogs of other vendors.

## 9. Palo Alto Readiness
The codebase is now fully ready to begin the Palo Alto implementation. Mappings are declarative, the model supports semantic TLS versions, and the database loader is vendor-agnostic.
