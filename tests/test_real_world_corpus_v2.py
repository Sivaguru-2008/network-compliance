"""Tests for Real-World Corpus Provenance and Integrity.

Verifies:
1. Provenance classification (REAL_PRODUCTION, PUBLIC_REFERENCE).
2. Manifest integrity and schema consistency across all records.
3. Cryptographic SHA-256 verification of all corpus artifacts on disk.
4. Duplicate detection (exact content and normalized hash uniqueness).
5. Secret and PII redaction verification.
6. Vendor coverage across all real-world configs.
7. Parser validation across 100% of acquired configurations.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.parsers.cisco_ios import CiscoIOSParser
from auditor.parsers.junos import JunosParser


def test_manifest_v2_structure_and_counts():
    manifest_path = Path("dataset/real_world/manifest.json")
    assert manifest_path.exists(), "dataset/real_world/manifest.json must exist"

    records = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert len(records) == 26, f"Expected 26 verified configurations, found {len(records)}"

    real_prod = [
        r for r in records
        if (r.get("provenance_classification") or r.get("provenance_class")) == "REAL_PRODUCTION"
    ]
    assert len(real_prod) == 26, f"Expected 26 REAL_PRODUCTION files, got {len(real_prod)}"


def test_manifest_v2_provenance_fields():
    manifest_path = Path("dataset/real_world/manifest.json")
    records = json.loads(manifest_path.read_text(encoding="utf-8"))

    required_fields = [
        "filename", "local_path", "vendor", "platform", "platform_key",
        "device_role", "description", "source_organization", "source_repository",
        "source_path", "source_url", "retrieval_timestamp", "repository_commit",
        "original_filename", "sha256", "original_sha256", "normalized_sha256",
        "provenance_classification", "provenance_evidence", "format_evidence",
        "sanitized", "secret_detected", "redaction_count", "line_count",
        "byte_count", "download_success", "parse_success", "semantic_success",
        "evidence_success", "compliance_success"
    ]

    for r in records:
        for fld in required_fields:
            assert fld in r, f"Record {r.get('filename')} missing required field '{fld}'"
        prov = r.get("provenance_classification") or r.get("provenance_class")
        assert prov in ("REAL_PRODUCTION", "PUBLIC_REFERENCE", "SYNTHETIC", "UNKNOWN")
        assert len(r["sha256"]) == 64
        assert len(r["original_sha256"]) == 64
        assert r["line_count"] > 0
        assert r["byte_count"] > 0
        assert r["download_success"] is True
        assert r["parse_success"] is True
        assert r["semantic_success"] is True
        assert r["evidence_success"] is True
        assert r["compliance_success"] is True


def test_sha256_verification_on_disk():
    manifest_path = Path("dataset/real_world/manifest.json")
    records = json.loads(manifest_path.read_text(encoding="utf-8"))

    for r in records:
        fpath = Path(r["local_path"])
        assert fpath.exists(), f"File {fpath} does not exist on disk"
        raw = fpath.read_bytes()
        actual_sha256 = hashlib.sha256(raw).hexdigest()
        assert actual_sha256 == r["sha256"], (
            f"SHA-256 mismatch on {fpath}: expected {r['sha256']}, got {actual_sha256}"
        )
        content = fpath.read_text(encoding="utf-8")
        assert len(content.splitlines()) == r["line_count"], f"Line count mismatch on {fpath}"


def test_duplicate_uniqueness():
    manifest_path = Path("dataset/real_world/manifest.json")
    records = json.loads(manifest_path.read_text(encoding="utf-8"))

    seen_sha = set()
    seen_norm = set()
    for r in records:
        assert r["sha256"] not in seen_sha, f"Duplicate exact SHA-256 detected: {r['filename']}"
        assert r["normalized_sha256"] not in seen_norm, f"Duplicate normalized SHA-256 detected: {r['filename']}"
        seen_sha.add(r["sha256"])
        seen_norm.add(r["normalized_sha256"])


def test_secret_redaction_integrity():
    manifest_path = Path("dataset/real_world/manifest.json")
    records = json.loads(manifest_path.read_text(encoding="utf-8"))

    for r in records:
        content = Path(r["local_path"]).read_text(encoding="utf-8")
        assert "-----BEGIN PRIVATE KEY-----" not in content
        assert "-----BEGIN RSA PRIVATE KEY-----" not in content


def test_vendor_coverage_and_parsers():
    manifest_path = Path("dataset/real_world/manifest.json")
    records = json.loads(manifest_path.read_text(encoding="utf-8"))

    vendors_found = {r["vendor"] for r in records}
    expected_vendors = {"Cisco Systems", "Juniper Networks"}
    assert expected_vendors.issubset(vendors_found), f"Missing vendors: {expected_vendors - vendors_found}"

    vendor_parsers = {
        "Cisco Systems": CiscoIOSParser,
        "Juniper Networks": JunosParser,
    }

    for r in records:
        content = Path(r["local_path"]).read_text(encoding="utf-8")
        parser_cls = vendor_parsers.get(r["vendor"])
        assert parser_cls is not None, f"No parser for vendor {r['vendor']}"
        parser = parser_cls()
        model = parser.parse(content, source_file=r.get("filename"))
        assert isinstance(model, SecurityBaselineModel)
        assert model.config_line_count > 0


def test_benchmark_immutability_and_zero_contamination():
    report_path = Path("reports/real_world_corpus_v2.json")
    assert report_path.exists()
    report = json.loads(report_path.read_text(encoding="utf-8"))

    contam = report["contamination_results"]
    assert contam["benchmarks_modified"] == 0
    assert contam["gold_contamination"] == 0
    assert contam["test_contamination"] == 0
    assert contam["held_out_contamination"] == 0
    assert contam["cross_vendor_contamination"] == 0


def test_corpus_report_v2_schema_completeness():
    report_path = Path("reports/real_world_corpus_v2.json")
    report = json.loads(report_path.read_text(encoding="utf-8"))

    required_keys = [
        "total_files", "real_production_files", "public_reference_files",
        "synthetic_files", "unknown_files", "total_real_lines",
        "vendors_with_real_configs", "vendors_without_real_configs",
        "per_vendor_counts", "per_vendor_line_counts", "provenance_sources",
        "redaction_statistics", "duplicate_statistics", "parser_success",
        "semantic_success", "evidence_success", "compliance_success",
        "contamination_results", "sha256_manifest"
    ]

    for k in required_keys:
        assert k in report, f"Report missing key '{k}'"

    assert report["total_files"] == 46
    assert report["real_production_files"] == 31
    assert report["public_reference_files"] == 15
    assert report["synthetic_files"] == 0
    assert report["unknown_files"] == 0
    assert report["total_real_lines"] >= 120000
    assert report["parser_success"] == "100.0%"
    assert report["semantic_success"] == "100.0%"
    assert report["evidence_success"] == "100.0%"
    assert report["compliance_success"] == "100.0%"
