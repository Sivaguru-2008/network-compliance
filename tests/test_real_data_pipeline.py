"""Automated tests for the real-data pipeline, provenance tracking, and zero-leakage partition safety.

Validates:
1. Acquisition of the 10 Config2Spec Internet2 JunOS configuration files.
2. Cryptographic verification (SHA-256) of raw originals and sanitized copies.
3. Provenance metadata completeness (vendor, platform, OS, URL, path, evidence, license, capture info).
4. Verbatim preservation of un-sanitized originals in dataset/real_device_evaluation/raw/.
5. Syntax-preserving multi-layer sanitization on copies.
6. Correct provenance flags (source_type = VERIFIED_REAL_PRODUCTION_DEVICE, real_device = True, provenance_verified = True).
7. Strict zero-leakage isolation: Real device configurations are strictly forbidden from entering training splits.
8. Structured evaluation examples schema validity and SecurityBaselineModel alignment.
9. Pipeline execution, deterministic vendor detection, parsing, and CIS compliance evaluation.
10. Purdue ISL campus dataset adapter architectural readiness.
"""

import hashlib
import json
from pathlib import Path
import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.parsers.base import registry
from auditor.parsers.junos import JunosParser
from auditor.pipeline import evaluate, parse_config, select_parser
from auditor.training.public_dataset import SUPPORTED_BASELINE_FIELDS
from auditor.training.real_device_dataset import (
    ConfigSanitizer,
    DatasetSplit,
    DeviceProvenance,
    SecurityConceptExtractor,
)
from auditor.training.real_device_pipeline import (
    CONFIG2SPEC_FILES,
    RealDeviceProvenanceMetadata,
    execute_real_device_pipeline,
)
from auditor.training.purdue_isl_adapter import PurdueISLDatasetAdapter, PURDUE_ISL_PROVENANCE_METADATA


REAL_EVAL_DIR = Path("dataset/real_device_evaluation")
RAW_DIR = REAL_EVAL_DIR / "raw"
SANITIZED_DIR = REAL_EVAL_DIR / "sanitized"
MANIFEST_FILE = REAL_EVAL_DIR / "manifest.json"
EXAMPLES_FILE = REAL_EVAL_DIR / "structured_examples.json"
REPORT_JSON_FILE = REAL_EVAL_DIR / "evaluation_report.json"
REPORT_MD_FILE = REAL_EVAL_DIR / "evaluation_report.md"


@pytest.fixture(scope="module", autouse=True)
def ensure_real_device_pipeline_executed():
    """Ensure the pipeline has run and files are present before running tests."""
    if not (MANIFEST_FILE.is_file() and REPORT_JSON_FILE.is_file() and len(list(RAW_DIR.glob("*.conf"))) == 10):
        execute_real_device_pipeline()


class TestRealDeviceAcquisitionAndIntegrity:
    """Verifies that all 10 Config2Spec Internet2 files are acquired, verified, and intact."""

    def test_all_10_files_present_in_raw_and_sanitized(self):
        assert RAW_DIR.is_dir()
        assert SANITIZED_DIR.is_dir()

        for fn in CONFIG2SPEC_FILES:
            raw_path = RAW_DIR / fn
            sanitized_path = SANITIZED_DIR / fn
            assert raw_path.is_file(), f"Missing raw file: {fn}"
            assert sanitized_path.is_file(), f"Missing sanitized file: {fn}"
            assert raw_path.stat().st_size > 10000, f"Raw file {fn} unexpectedly small"
            assert sanitized_path.stat().st_size > 10000, f"Sanitized file {fn} unexpectedly small"

    def test_cryptographic_hashes_match_manifest(self):
        with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        assert len(manifest) == 10
        manifest_by_name = {m["filename"]: m for m in manifest}

        for fn in CONFIG2SPEC_FILES:
            assert fn in manifest_by_name
            meta = manifest_by_name[fn]

            # Verify raw hash
            raw_text = (RAW_DIR / fn).read_text(encoding="utf-8")
            computed_raw_sha = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
            assert computed_raw_sha == meta["sha256_raw"]

            # Verify sanitized hash
            sanitized_text = (SANITIZED_DIR / fn).read_text(encoding="utf-8")
            computed_sanitized_sha = hashlib.sha256(sanitized_text.encode("utf-8")).hexdigest()
            assert computed_sanitized_sha == meta["sha256_sanitized"]

    def test_provenance_metadata_completeness(self):
        with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        required_keys = [
            "filename",
            "vendor",
            "platform",
            "os_version",
            "source_type",
            "real_device",
            "provenance_verified",
            "source_url",
            "repository",
            "source_path",
            "license",
            "provenance_evidence",
            "capture_source_info",
            "pop_location",
            "sha256_raw",
            "sha256_sanitized",
            "split",
            "line_count",
            "byte_count",
        ]

        for entry in manifest:
            for k in required_keys:
                assert k in entry, f"Missing key {k} in manifest entry {entry.get('filename')}"

            assert entry["vendor"] == "Juniper"
            assert entry["platform"] == "JunOS"
            assert entry["os_version"] == "12.3R6.6"
            assert entry["source_type"] == "VERIFIED_REAL_PRODUCTION_DEVICE"
            assert entry["real_device"] is True
            assert entry["provenance_verified"] is True
            assert entry["license"] == "Apache-2.0"
            assert "config2spec" in entry["source_url"]
            assert len(entry["provenance_evidence"]) > 20
            assert len(entry["capture_source_info"]) > 20
            assert entry["split"] == "REAL_DEVICE_EVALUATION"


class TestZeroLeakageAndPartitionSafety:
    """Strictly validates that real device configurations NEVER enter training splits."""

    def test_real_devices_have_evaluation_split_only(self):
        with open(MANIFEST_FILE, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        for entry in manifest:
            assert entry["split"] == "REAL_DEVICE_EVALUATION"
            assert entry["split"] != DatasetSplit.TRAIN.value
            assert entry["split"] != DatasetSplit.VALIDATION.value

    def test_training_split_disjointness(self):
        """Verify that no training file or snippet is derived from real device configs."""
        train_snippets_path = Path("dataset/public_config/train/snippets.json")
        if train_snippets_path.is_file():
            with open(train_snippets_path, "r", encoding="utf-8") as f:
                train_snippets = json.load(f)

            for s in train_snippets:
                assert s.get("real_device") is False
                assert s.get("source_file") not in CONFIG2SPEC_FILES

    def test_builder_rejects_real_device_in_training(self):
        """Verify RealDeviceDatasetBuilder assigns REAL_DEVICE_TEST / REAL_DEVICE_EVALUATION to real configs."""
        from auditor.training.real_device_dataset import RealDeviceDatasetBuilder

        builder = RealDeviceDatasetBuilder()
        rec = builder.add_record(
            filename="atla.conf",
            vendor="Juniper",
            platform="JunOS",
            os_version="12.3R6.6",
            source_type=DeviceProvenance.REAL_DEVICE,
            raw_config="set system host-name atla-mx960\n",
            source_url="https://example.com/atla.conf",
            repository="test/repo",
            source_path="atla.conf",
            license_str="Apache-2.0",
            provenance_evidence="Test evidence",
        )
        assert rec.real_device is True
        assert rec.assigned_split == DatasetSplit.REAL_DEVICE_TEST
        assert rec.assigned_split != DatasetSplit.TRAIN


class TestStructuredEvaluationExamples:
    """Verifies that structured evaluation examples are well-formed and adhere to the schema."""

    def test_structured_examples_schema_and_types(self):
        assert EXAMPLES_FILE.is_file()
        with open(EXAMPLES_FILE, "r", encoding="utf-8") as f:
            examples = json.load(f)

        assert len(examples) >= 50, "Expected at least 50 structured evaluation examples across 10 devices"

        valid_fields = SUPPORTED_BASELINE_FIELDS.union({"ssh_enabled", "aaa_enabled", "enable_secret_set", "management_acl_applied", "telnet_enabled"})

        for ex in examples:
            assert "raw_configuration" in ex and len(ex["raw_configuration"]) > 0
            assert ex["vendor"] == "Juniper"
            assert "security_concept" in ex and len(ex["security_concept"]) > 0
            assert "normalized_field" in ex and len(ex["normalized_field"]) > 0
            assert "expected_semantic_meaning" in ex and len(ex["expected_semantic_meaning"]) > 0
            assert ex["source_file"] in CONFIG2SPEC_FILES
            assert ex["normalized_field"] in valid_fields


class TestRealDevicePipelineExecution:
    """Verifies pipeline execution across all 10 real production devices."""

    def test_evaluation_report_completeness(self):
        assert REPORT_JSON_FILE.is_file()
        assert REPORT_MD_FILE.is_file()

        with open(REPORT_JSON_FILE, "r", encoding="utf-8") as f:
            report = json.load(f)

        assert report["total_files"] == 10
        assert report["provenance_classification"] == "VERIFIED_REAL_PRODUCTION_DEVICE"
        assert report["evaluation_summary"]["vendor_detection_accuracy"] == 1.0
        assert report["evaluation_summary"]["parsing_success_rate"] == 1.0
        assert report["evaluation_summary"]["zero_leakage_verified"] is True
        assert len(report["devices"]) == 10

        for dev in report["devices"]:
            assert dev["vendor_detection"]["detected_vendor"] == "juniper"
            assert dev["vendor_detection"]["confidence"] >= 0.85
            assert dev["vendor_detection"]["success"] is True
            assert dev["parsing_success"]["parsed"] is True
            assert dev["compliance_evaluation"]["total_rules"] > 0

    def test_deterministic_parser_on_real_configs_without_training(self):
        """Verify deterministic parsing on a real config file."""
        config_text = (SANITIZED_DIR / "atla.conf").read_text(encoding="utf-8")
        parser_cls, conf = select_parser(config_text)
        assert parser_cls == JunosParser
        assert conf >= 0.85

        parser = parser_cls()
        baseline = parse_config(parser, config_text, source_file="atla.conf")

        assert isinstance(baseline, SecurityBaselineModel)
        assert baseline.ssh_enabled.value is True
        assert baseline.telnet_enabled.value is False
        assert len(baseline.logging_hosts.value or []) > 0
        assert len(baseline.ntp_servers.value or []) > 0

        outcome = evaluate(baseline, ["CIS"])
        assert len(outcome.results) > 0
        assert outcome.summaries["CIS"].passed > 0


class TestPurdueISLAdapterArchitecture:
    """Verifies that the architecture is prepared for the Purdue ISL campus dataset (~1,600 Cisco configs)."""

    def test_adapter_initialization_and_metadata(self):
        adapter = PurdueISLDatasetAdapter()
        assert PURDUE_ISL_PROVENANCE_METADATA["vendor"] == "Cisco"
        assert PURDUE_ISL_PROVENANCE_METADATA["source_type"] == "VERIFIED_SANITIZED_REAL_DEVICE"
        assert PURDUE_ISL_PROVENANCE_METADATA["split"] == "REAL_DEVICE_EVALUATION"
        assert Path("dataset/purdue_isl/README.md").is_file()

    def test_adapter_role_inference(self):
        adapter = PurdueISLDatasetAdapter()
        assert adapter.infer_device_role("core-rtr-01.cfg", "hostname core-rtr-01") == "Core Router / Switch"
        assert adapter.infer_device_role("dist-sw-02.cfg", "hostname dist-sw-02") == "Distribution Switch"
        assert adapter.infer_device_role("border-gw.cfg", "router bgp 65001") == "Border Router"
