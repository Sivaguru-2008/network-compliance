"""Tests for real-world network configuration corpus integrity, provenance, and benchmark isolation."""

import json
from pathlib import Path
import pytest

from auditor.parsers.cisco_ios import CiscoIOSParser
from auditor.parsers.junos import JunosParser


def test_real_world_manifest_integrity():
    manifest_path = Path("dataset/real_world/manifest.json")
    assert manifest_path.exists(), "dataset/real_world/manifest.json must exist"

    records = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert len(records) >= 26, f"Expected at least 26 verified real files, found {len(records)}"

    cisco_records = [r for r in records if "cisco" in r["vendor"].lower()]
    juniper_records = [r for r in records if "juniper" in r["vendor"].lower()]

    assert len(cisco_records) == 16, f"Expected 16 Cisco records, found {len(cisco_records)}"
    assert len(juniper_records) == 10, f"Expected 10 Juniper records, found {len(juniper_records)}"

    for r in records:
        prov = r.get("provenance_classification") or r.get("provenance_class")
        assert prov in ("VERIFIED_REAL_PRODUCTION", "REAL_PRODUCTION", "PUBLIC_REFERENCE")
        assert r["parse_success"] is True
        assert r["semantic_success"] is True
        assert r["evidence_success"] is True
        assert r["line_count"] > 0
        assert r["byte_count"] > 0
        assert r["sha256"]
        assert r.get("original_sha256") or r.get("original_hash")


def test_real_world_cisco_files_exist_and_parse():
    cisco_dir = Path("dataset/real_world/cisco_ios")
    assert cisco_dir.exists()
    cfg_files = list(cisco_dir.glob("*.cfg"))
    assert len(cfg_files) == 16

    parser = CiscoIOSParser()
    total_lines = 0
    for f in cfg_files:
        content = f.read_text(encoding="utf-8")
        total_lines += len(content.splitlines())
        model = parser.parse(content)
        assert model.provenance.vendor.lower() == "cisco"
        assert model.config_line_count > 0

    assert total_lines == 17750


def test_real_world_juniper_files_exist_and_parse():
    juniper_dir = Path("dataset/real_world/juniper_junos")
    assert juniper_dir.exists()
    conf_files = list(juniper_dir.glob("*.conf"))
    assert len(conf_files) == 10

    parser = JunosParser()
    total_lines = 0
    for f in conf_files:
        content = f.read_text(encoding="utf-8")
        total_lines += len(content.splitlines())
        model = parser.parse(content)
        assert model.provenance.vendor.lower() == "juniper"
        assert model.config_line_count > 0

    assert total_lines == 96664


def test_real_world_corpus_report_metrics():
    report_path = Path("reports/real_world_corpus_acquisition.json")
    assert report_path.exists()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["overall_metrics"]["total_verified_real_production_files"] == 26
    assert report["overall_metrics"]["total_verified_real_lines"] == 114414
    assert report["benchmark_isolation"]["benchmarks_modified"] == 0
    assert report["benchmark_isolation"]["gold_contamination"] == 0
    assert report["benchmark_isolation"]["test_contamination"] == 0
    assert report["quality_and_provenance_audit"]["fabricated_formats"] == 0
    assert report["quality_and_provenance_audit"]["final_status"] == "PASS"
