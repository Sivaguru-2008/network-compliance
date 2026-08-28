"""Analytics computation tests: fleet scoring, vendor distribution, severity
breakdown, per-control pass rates, comparison deltas, CSV generation, and edge
cases.

Every helper tested here mirrors the client-side JS that computes these values
from the inventory JSON.  The tests prove the logic is sound on the same data
contract the API returns.
"""

import csv
import io
from datetime import datetime, timezone
from typing import Dict, List, Optional

import pytest

from auditor.models.identity import DeviceIdentity
from auditor.models.observation import Observation
from auditor.models.inventory import (
    DeviceInventory,
    DeviceRecord,
    DeviceStatus,
    DeviceKeyTier,
    InventoryCounts,
)
from auditor.models.result import (
    ControlResult,
    Evidence,
    ReportSummary,
    Status,
    TargetInfo,
)
from auditor.models.rule import Severity


# ---------------------------------------------------------------------------
# helpers: replicate the analytics computation the JS does client-side
# ---------------------------------------------------------------------------


def fleet_compliance_score(inventory: DeviceInventory) -> float:
    rollup = inventory.framework_rollup
    total_pass = sum(s.passed for s in rollup.values())
    total_fail = sum(s.failed for s in rollup.values())
    total_review = sum(s.needs_review for s in rollup.values())
    total = total_pass + total_fail + total_review
    if total == 0:
        return 0.0
    return round(total_pass / total * 100, 2)


def vendor_distribution(inventory: DeviceInventory) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for d in inventory.devices:
        v = d.identity.vendor or (d.target.vendor if d.target else None) or "unknown"
        counts[v] = counts.get(v, 0) + 1
    return counts


def severity_breakdown(inventory: DeviceInventory) -> Dict[str, Dict[str, int]]:
    data = {
        "high": {"PASS": 0, "FAIL": 0, "NEEDS_REVIEW": 0},
        "medium": {"PASS": 0, "FAIL": 0, "NEEDS_REVIEW": 0},
        "low": {"PASS": 0, "FAIL": 0, "NEEDS_REVIEW": 0},
    }
    for d in inventory.devices:
        for f in d.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else f.severity
            st = f.status.value if hasattr(f.status, "value") else f.status
            if sev in data and st in data[sev]:
                data[sev][st] += 1
    return data


def per_control_pass_rates(inventory: DeviceInventory) -> Dict[str, Dict]:
    audited = [d for d in inventory.devices if d.status == DeviceStatus.AUDITED]
    controls: Dict[str, Dict] = {}
    for d in audited:
        for f in d.findings:
            cid = f.rule_id
            if cid not in controls:
                controls[cid] = {"passed": 0, "total": 0}
            controls[cid]["total"] += 1
            if f.status == Status.PASS:
                controls[cid]["passed"] += 1
    for cid in controls:
        t = controls[cid]["total"]
        controls[cid]["rate"] = controls[cid]["passed"] / t if t else 0
    return controls


def comparison_deltas(
    current: DeviceInventory, previous: DeviceInventory
) -> Dict[str, float]:
    deltas = {}
    curr_rollup = current.framework_rollup
    prev_rollup = previous.framework_rollup
    all_fws = set(curr_rollup) | set(prev_rollup)
    for fw in all_fws:
        curr_score = curr_rollup[fw].compliance_score if fw in curr_rollup else None
        prev_score = prev_rollup[fw].compliance_score if fw in prev_rollup else None
        if curr_score is not None and prev_score is not None:
            deltas[fw] = round(curr_score - prev_score, 2)
    return deltas


def generate_csv(inventory: DeviceInventory) -> str:
    output = io.StringIO()
    output.write("﻿")
    writer = csv.writer(output)
    writer.writerow([
        "hostname", "vendor", "framework", "control_id", "control_title",
        "severity", "status", "evidence_summary", "remediation_summary",
    ])
    for d in inventory.devices:
        hostname = d.hostname or d.source_file
        vendor = d.identity.vendor or (d.target.vendor if d.target else "unknown")
        for f in d.findings:
            ev_summary = "; ".join(
                f"{e.field}: {e.source_line or e.note or ''}" for e in f.evidence
            )
            rem_summary = f.remediation.summary if f.remediation else ""
            sev = f.severity.value if hasattr(f.severity, "value") else f.severity
            st = f.status.value if hasattr(f.status, "value") else f.status
            writer.writerow([
                hostname, vendor, f.framework, f.rule_id, f.title,
                sev, st, ev_summary, rem_summary,
            ])
    return output.getvalue()


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def _identity(vendor: str, hostname: Optional[str] = None) -> DeviceIdentity:
    return DeviceIdentity(
        vendor=vendor,
        hostname=Observation[str](value=hostname, detected=hostname is not None),
    )


def _finding(
    rule_id: str,
    status: Status,
    severity: Severity,
    framework: str = "CIS",
    title: str = "",
) -> ControlResult:
    return ControlResult(
        rule_id=rule_id,
        title=title or rule_id,
        description="test",
        framework=framework,
        severity=severity,
        status=status,
        message="test message",
        evidence=[Evidence(field="test_field", detected=True, source_line="test line", origin="deterministic")],
    )


def _target(vendor: str) -> TargetInfo:
    return TargetInfo(
        vendor=vendor, os_family="test", parser="test_parser", parser_version="1.0",
    )


def _device(
    vendor: str,
    hostname: str,
    findings: List[ControlResult],
    status: DeviceStatus = DeviceStatus.AUDITED,
) -> DeviceRecord:
    passed = sum(1 for f in findings if f.status == Status.PASS)
    failed = sum(1 for f in findings if f.status == Status.FAIL)
    review = sum(1 for f in findings if f.status == Status.NEEDS_REVIEW)
    total = passed + failed + review
    score = round(passed / total * 100, 2) if total else 0
    by_fw: Dict[str, ReportSummary] = {}
    for f in findings:
        fw = f.framework
        if fw not in by_fw:
            by_fw[fw] = ReportSummary()
        s = by_fw[fw]
        s.total += 1
        if f.status == Status.PASS:
            s.passed += 1
        elif f.status == Status.FAIL:
            s.failed += 1
        else:
            s.needs_review += 1
    for s in by_fw.values():
        s.compliance_score = round(s.passed / s.total * 100, 2) if s.total else 0

    return DeviceRecord(
        identity=_identity(vendor, hostname),
        source_file=f"/fake/{hostname}.conf",
        source_hash="abc123",
        ingested_at=datetime.now(timezone.utc),
        status=status,
        device_key=hostname,
        device_key_tier=DeviceKeyTier.HOSTNAME_VENDOR,
        frameworks=list(by_fw.keys()),
        findings=findings,
        framework_summaries=by_fw,
        summary=ReportSummary(
            total=total, passed=passed, failed=failed, needs_review=review,
            compliance_score=score,
        ),
        target=_target(vendor),
    )


def _inventory(
    devices: List[DeviceRecord],
    frameworks: Optional[List[str]] = None,
) -> DeviceInventory:
    fws = frameworks or list({f.framework for d in devices for f in d.findings})
    audited = sum(1 for d in devices if d.status == DeviceStatus.AUDITED)
    parse_error = sum(1 for d in devices if d.status == DeviceStatus.PARSE_ERROR)
    unknown = sum(1 for d in devices if d.status == DeviceStatus.UNKNOWN_VENDOR)

    rollup: Dict[str, ReportSummary] = {}
    for d in devices:
        if d.status != DeviceStatus.AUDITED:
            continue
        for fw, s in d.framework_summaries.items():
            if fw not in rollup:
                rollup[fw] = ReportSummary()
            rollup[fw].passed += s.passed
            rollup[fw].failed += s.failed
            rollup[fw].needs_review += s.needs_review
            rollup[fw].total += s.total
    for s in rollup.values():
        s.compliance_score = round(s.passed / s.total * 100, 2) if s.total else 0

    return DeviceInventory(
        frameworks=fws,
        counts=InventoryCounts(
            total=len(devices), audited=audited,
            parse_error=parse_error, unknown_vendor=unknown,
        ),
        framework_rollup=rollup,
        devices=devices,
    )


# ---------------------------------------------------------------------------
# tests: fleet compliance score
# ---------------------------------------------------------------------------


class TestFleetComplianceScore:
    def test_basic_score(self):
        d = _device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH),
            _finding("R2", Status.FAIL, Severity.HIGH),
            _finding("R3", Status.PASS, Severity.MEDIUM),
            _finding("R4", Status.NEEDS_REVIEW, Severity.LOW),
        ])
        inv = _inventory([d])
        score = fleet_compliance_score(inv)
        assert score == 50.0

    def test_all_pass_fleet(self):
        d1 = _device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH),
            _finding("R2", Status.PASS, Severity.MEDIUM),
        ])
        d2 = _device("juniper_junos", "rtr2", [
            _finding("R1", Status.PASS, Severity.HIGH),
            _finding("R2", Status.PASS, Severity.MEDIUM),
        ])
        inv = _inventory([d1, d2])
        assert fleet_compliance_score(inv) == 100.0

    def test_all_fail_fleet(self):
        d = _device("cisco_ios", "rtr1", [
            _finding("R1", Status.FAIL, Severity.HIGH),
            _finding("R2", Status.FAIL, Severity.MEDIUM),
        ])
        inv = _inventory([d])
        assert fleet_compliance_score(inv) == 0.0

    def test_empty_inventory_returns_zero(self):
        inv = _inventory([])
        assert fleet_compliance_score(inv) == 0.0

    def test_parse_error_devices_excluded_from_score(self):
        good = _device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH),
            _finding("R2", Status.PASS, Severity.MEDIUM),
        ])
        bad = _device("unknown", "bad", [], status=DeviceStatus.PARSE_ERROR)
        inv = _inventory([good, bad])
        assert fleet_compliance_score(inv) == 100.0

    def test_unknown_vendor_excluded_from_score(self):
        good = _device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH),
        ])
        unk = _device("unknown", "unk", [], status=DeviceStatus.UNKNOWN_VENDOR)
        inv = _inventory([good, unk])
        assert fleet_compliance_score(inv) == 100.0

    def test_single_device_fleet(self):
        d = _device("cisco_ios", "solo", [
            _finding("R1", Status.PASS, Severity.LOW),
            _finding("R2", Status.FAIL, Severity.LOW),
            _finding("R3", Status.PASS, Severity.LOW),
        ])
        inv = _inventory([d])
        assert fleet_compliance_score(inv) == pytest.approx(66.67, abs=0.01)

    def test_single_framework_evaluation(self):
        d = _device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH, framework="NIST_SP_800_53"),
            _finding("R2", Status.FAIL, Severity.MEDIUM, framework="NIST_SP_800_53"),
        ])
        inv = _inventory([d], frameworks=["NIST_SP_800_53"])
        assert fleet_compliance_score(inv) == 50.0


# ---------------------------------------------------------------------------
# tests: vendor distribution
# ---------------------------------------------------------------------------


class TestVendorDistribution:
    def test_multiple_vendors(self):
        d1 = _device("cisco_ios", "rtr1", [_finding("R1", Status.PASS, Severity.LOW)])
        d2 = _device("juniper_junos", "rtr2", [_finding("R1", Status.PASS, Severity.LOW)])
        d3 = _device("cisco_ios", "rtr3", [_finding("R1", Status.PASS, Severity.LOW)])
        inv = _inventory([d1, d2, d3])
        dist = vendor_distribution(inv)
        assert dist == {"cisco_ios": 2, "juniper_junos": 1}

    def test_single_vendor(self):
        d = _device("fortinet_fortios", "fw1", [_finding("R1", Status.PASS, Severity.LOW)])
        inv = _inventory([d])
        assert vendor_distribution(inv) == {"fortinet_fortios": 1}

    def test_unknown_vendor_counted(self):
        d = _device("unknown", "unk", [], status=DeviceStatus.UNKNOWN_VENDOR)
        inv = _inventory([d])
        dist = vendor_distribution(inv)
        assert "unknown" in dist


# ---------------------------------------------------------------------------
# tests: severity breakdown
# ---------------------------------------------------------------------------


class TestSeverityBreakdown:
    def test_breakdown_by_status_and_severity(self):
        d = _device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH),
            _finding("R2", Status.FAIL, Severity.HIGH),
            _finding("R3", Status.PASS, Severity.MEDIUM),
            _finding("R4", Status.NEEDS_REVIEW, Severity.LOW),
            _finding("R5", Status.FAIL, Severity.LOW),
        ])
        inv = _inventory([d])
        bd = severity_breakdown(inv)
        assert bd["high"]["PASS"] == 1
        assert bd["high"]["FAIL"] == 1
        assert bd["medium"]["PASS"] == 1
        assert bd["low"]["NEEDS_REVIEW"] == 1
        assert bd["low"]["FAIL"] == 1

    def test_empty_findings(self):
        d = _device("cisco_ios", "rtr1", [])
        inv = _inventory([d])
        bd = severity_breakdown(inv)
        assert all(
            bd[sev][st] == 0
            for sev in ("high", "medium", "low")
            for st in ("PASS", "FAIL", "NEEDS_REVIEW")
        )


# ---------------------------------------------------------------------------
# tests: per-control pass rates
# ---------------------------------------------------------------------------


class TestPerControlPassRates:
    def test_rates_across_devices(self):
        d1 = _device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH),
            _finding("R2", Status.FAIL, Severity.MEDIUM),
        ])
        d2 = _device("cisco_ios", "rtr2", [
            _finding("R1", Status.PASS, Severity.HIGH),
            _finding("R2", Status.PASS, Severity.MEDIUM),
        ])
        inv = _inventory([d1, d2])
        rates = per_control_pass_rates(inv)
        assert rates["R1"]["rate"] == 1.0
        assert rates["R2"]["rate"] == 0.5

    def test_control_only_on_one_device(self):
        d1 = _device("cisco_ios", "rtr1", [
            _finding("R1", Status.FAIL, Severity.HIGH),
        ])
        d2 = _device("cisco_ios", "rtr2", [])
        inv = _inventory([d1, d2])
        rates = per_control_pass_rates(inv)
        assert rates["R1"]["rate"] == 0.0
        assert rates["R1"]["total"] == 1


# ---------------------------------------------------------------------------
# tests: comparison deltas
# ---------------------------------------------------------------------------


class TestComparisonDeltas:
    def test_improvement(self):
        prev = _inventory([_device("cisco_ios", "rtr1", [
            _finding("R1", Status.FAIL, Severity.HIGH),
            _finding("R2", Status.FAIL, Severity.MEDIUM),
        ])])
        curr = _inventory([_device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH),
            _finding("R2", Status.FAIL, Severity.MEDIUM),
        ])])
        deltas = comparison_deltas(curr, prev)
        assert deltas["CIS"] == 50.0

    def test_regression(self):
        prev = _inventory([_device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH),
            _finding("R2", Status.PASS, Severity.MEDIUM),
        ])])
        curr = _inventory([_device("cisco_ios", "rtr1", [
            _finding("R1", Status.FAIL, Severity.HIGH),
            _finding("R2", Status.PASS, Severity.MEDIUM),
        ])])
        deltas = comparison_deltas(curr, prev)
        assert deltas["CIS"] == -50.0

    def test_no_change(self):
        inv = _inventory([_device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH),
        ])])
        deltas = comparison_deltas(inv, inv)
        assert deltas["CIS"] == 0.0

    def test_different_frameworks(self):
        prev = _inventory([_device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH, framework="CIS"),
        ])], frameworks=["CIS"])
        curr = _inventory([_device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH, framework="NIST_SP_800_53"),
        ])], frameworks=["NIST_SP_800_53"])
        deltas = comparison_deltas(curr, prev)
        assert len(deltas) == 0


# ---------------------------------------------------------------------------
# tests: CSV generation
# ---------------------------------------------------------------------------


class TestCSVGeneration:
    def test_csv_has_bom_prefix(self):
        d = _device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH),
        ])
        inv = _inventory([d])
        csv_str = generate_csv(inv)
        assert csv_str.startswith("﻿")

    def test_csv_correct_columns(self):
        d = _device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH, title="AAA Enabled"),
        ])
        inv = _inventory([d])
        csv_str = generate_csv(inv)
        reader = csv.reader(io.StringIO(csv_str.lstrip("﻿")))
        header = next(reader)
        assert header == [
            "hostname", "vendor", "framework", "control_id", "control_title",
            "severity", "status", "evidence_summary", "remediation_summary",
        ]

    def test_csv_data_rows(self):
        d = _device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH, title="AAA Enabled"),
            _finding("R2", Status.FAIL, Severity.MEDIUM, title="SSH Version"),
        ])
        inv = _inventory([d])
        csv_str = generate_csv(inv)
        reader = csv.reader(io.StringIO(csv_str.lstrip("﻿")))
        rows = list(reader)
        assert len(rows) == 3  # header + 2 data rows
        assert rows[1][0] == "rtr1"
        assert rows[1][1] == "cisco_ios"
        assert rows[1][3] == "R1"

    def test_csv_escapes_commas_and_quotes(self):
        finding = _finding("R1", Status.PASS, Severity.HIGH, title='Test, "with" special')
        d = _device("cisco_ios", "rtr1", [finding])
        inv = _inventory([d])
        csv_str = generate_csv(inv)
        reader = csv.reader(io.StringIO(csv_str.lstrip("﻿")))
        rows = list(reader)
        assert rows[1][4] == 'Test, "with" special'

    def test_csv_multiple_devices(self):
        d1 = _device("cisco_ios", "rtr1", [_finding("R1", Status.PASS, Severity.HIGH)])
        d2 = _device("juniper_junos", "rtr2", [_finding("R1", Status.FAIL, Severity.MEDIUM)])
        inv = _inventory([d1, d2])
        csv_str = generate_csv(inv)
        reader = csv.reader(io.StringIO(csv_str.lstrip("﻿")))
        rows = list(reader)
        assert len(rows) == 3
        hostnames = {rows[1][0], rows[2][0]}
        assert hostnames == {"rtr1", "rtr2"}


# ---------------------------------------------------------------------------
# tests: edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_fleet_with_only_parse_errors(self):
        d = _device("unknown", "bad", [], status=DeviceStatus.PARSE_ERROR)
        inv = _inventory([d])
        assert fleet_compliance_score(inv) == 0.0
        assert vendor_distribution(inv) == {"unknown": 1}

    def test_fleet_with_mixed_error_and_audited(self):
        good = _device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH),
        ])
        bad = _device("unknown", "bad", [], status=DeviceStatus.PARSE_ERROR)
        inv = _inventory([good, bad])
        assert fleet_compliance_score(inv) == 100.0
        rates = per_control_pass_rates(inv)
        assert rates["R1"]["total"] == 1

    def test_needs_review_penalises_score(self):
        d = _device("cisco_ios", "rtr1", [
            _finding("R1", Status.PASS, Severity.HIGH),
            _finding("R2", Status.NEEDS_REVIEW, Severity.MEDIUM),
        ])
        inv = _inventory([d])
        assert fleet_compliance_score(inv) == 50.0

    def test_all_needs_review(self):
        d = _device("cisco_ios", "rtr1", [
            _finding("R1", Status.NEEDS_REVIEW, Severity.HIGH),
            _finding("R2", Status.NEEDS_REVIEW, Severity.MEDIUM),
        ])
        inv = _inventory([d])
        assert fleet_compliance_score(inv) == 0.0
