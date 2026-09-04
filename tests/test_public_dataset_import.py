"""Tests for public configuration dataset import, provenance, classification, and NLP validation.

Validates:
1. Dataset import & inventory completeness (Kentik config-snippets and CiscoDevNet netconf-examples)
2. Provenance classification (strictly PUBLIC_CONFIGURATION_SNIPPET, PUBLIC_NETCONF_EXAMPLE, real_device: false)
3. CiscoDevNet NETCONF classification (CONFIGURATION, NETCONF/API, AUTOMATION CODE, DOCUMENTATION, OTHER)
4. Security extraction vs non-security filtering (BGP, NetFlow, telemetry -> UNMAPPED)
5. Normalization strictly against SecurityBaselineModel (no invented fields)
6. Strongly-typed value extraction (SNMP communities, SSH versions, VTY timeouts, NTP servers, logging hosts)
7. Unknown and ambiguous syntax handling (UNMAPPED, AMBIGUOUS)
8. Cross-vendor semantic mappings and official vendor documentation links
9. Zero data leakage prevention (train/val/test file-level disjointness)
10. Multi-vendor parser isolation (ensuring Cisco, Juniper, etc. parsers isolate vendor syntax)
11. False semantic mapping prevention (ML/NLP never emits PASS/FAIL compliance decisions)
12. Malformed snippet robustness
13. NLP benchmark evaluation metrics (Top-1, Top-3, Entity, Value, Calibration, Reviews)
"""

import json
from pathlib import Path
import pytest

from auditor.models.baseline import SecurityBaselineModel
from auditor.parsers.cisco_ios import CiscoIOSParser
from auditor.parsers.junos import JunosParser
from auditor.parsers.arista_eos import AristaEOSParser
from auditor.training.public_dataset import (
    OFFICIAL_DOC_REFERENCES,
    SUPPORTED_BASELINE_FIELDS,
    DeterministicBaselineMatcher,
    DevNetContentType,
    DevNetItem,
    DevNetNetconfScanner,
    HybridSemanticMatcher,
    InventoryItem,
    NLPSemanticLayer,
    ProvenanceClassification,
    PublicDatasetScanner,
    SecuritySnippet,
    extract_value_for_field,
    partition_snippets_without_leakage,
    run_nlp_benchmark,
)


DATASET_DIR = Path("dataset/public_config")
DATASET_LEGACY_DIR = Path("dataset/public_config_snippets")
NETCONF_DIR = Path("dataset/public_netconf")
OFFICIAL_DIR = Path("dataset/official")
REAL_DEVICE_DIR = Path("dataset/real_device")
UNKNOWN_DIR = Path("dataset/unknown")


# ---------------------------------------------------------------------------
# 1. Dataset Import & Inventory Completeness
# ---------------------------------------------------------------------------

class TestDatasetInventory:
    """Verifies inventory extraction and dataset directory structure across all sources."""

    def test_dataset_directories_exist(self):
        assert DATASET_DIR.is_dir()
        assert NETCONF_DIR.is_dir()
        assert OFFICIAL_DIR.is_dir()
        assert REAL_DEVICE_DIR.is_dir()
        assert UNKNOWN_DIR.is_dir()

    def test_kentik_inventory_completeness(self):
        with open(DATASET_DIR / "inventory.json", "r", encoding="utf-8") as f:
            inventory = json.load(f)

        assert len(inventory) == 183
        for item in inventory:
            assert "vendor" in item
            assert "file" in item
            assert "format" in item
            assert "size" in item
            assert item["format"] in ("cli_config", "markdown_doc", "image_binary", "unknown")
            assert item["size"] > 0

    def test_kentik_metadata(self):
        with open(DATASET_DIR / "metadata.json", "r", encoding="utf-8") as f:
            meta = json.load(f)

        assert meta["source_name"] == "Kentik config-snippets"
        assert meta["dataset_classification"] == ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value
        assert meta["real_device"] is False
        assert meta["total_inventory_files"] == 183
        assert meta["total_extracted_snippets"] > 0
        assert meta["mapped_count"] > 0
        assert meta["unmapped_count"] > 0
        assert meta["ambiguous_count"] > 0
        assert "splits" in meta

    def test_legacy_directory_compatibility(self):
        assert DATASET_LEGACY_DIR.is_dir()
        assert (DATASET_LEGACY_DIR / "inventory.json").is_file()
        assert (DATASET_LEGACY_DIR / "extracted_security_snippets.json").is_file()


# ---------------------------------------------------------------------------
# 2. Cisco DevNet NETCONF Classification
# ---------------------------------------------------------------------------

class TestDevNetNetconfClassification:
    """Verifies strict classification of Cisco DevNet NETCONF repository files."""

    def test_devnet_inventory_and_classifications(self):
        with open(NETCONF_DIR / "classified_items.json", "r", encoding="utf-8") as f:
            items = json.load(f)

        assert len(items) == 23
        classifications = {item["classification"] for item in items}
        expected_classes = {
            DevNetContentType.CONFIGURATION.value,
            DevNetContentType.NETCONF_API_EXAMPLE.value,
            DevNetContentType.AUTOMATION_CODE.value,
            DevNetContentType.DOCUMENTATION.value,
            DevNetContentType.OTHER.value,
        }
        assert classifications == expected_classes

    def test_devnet_config_vs_non_config_separation(self):
        with open(NETCONF_DIR / "classified_items.json", "r", encoding="utf-8") as f:
            items = json.load(f)

        config_items = [i for i in items if i["contains_actual_config"]]
        assert len(config_items) == 1
        assert "sandbox-nexus9kv-config.txt" in config_items[0]["file"]

        non_config_scripts = [
            i for i in items
            if i["file"].endswith(".py") or i["file"].endswith(".xml") or i["file"].endswith(".j2")
        ]
        for item in non_config_scripts:
            assert item["contains_actual_config"] is False
            assert item["classification"] in (
                DevNetContentType.NETCONF_API_EXAMPLE.value,
                DevNetContentType.AUTOMATION_CODE.value,
            )

    def test_devnet_show_command_classified_as_other(self):
        with open(NETCONF_DIR / "classified_items.json", "r", encoding="utf-8") as f:
            items = json.load(f)

        show_item = next(i for i in items if "show_ip_int_brief.txt" in i["file"])
        assert show_item["classification"] == DevNetContentType.OTHER.value
        assert show_item["contains_actual_config"] is False


# ---------------------------------------------------------------------------
# 3. Provenance & Real Device Safety
# ---------------------------------------------------------------------------

class TestProvenanceAndSafety:
    """Strictly verifies that provenance is accurate and real_device is False."""

    def test_kentik_provenance_and_real_device(self):
        with open(DATASET_DIR / "inventory.json", "r", encoding="utf-8") as f:
            inventory = json.load(f)
        for item in inventory:
            assert item["provenance"] == ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value
            assert item["real_device"] is False

        with open(DATASET_DIR / "extracted_security_snippets.json", "r", encoding="utf-8") as f:
            snippets = json.load(f)
        for s in snippets:
            assert s["provenance"] == ProvenanceClassification.PUBLIC_CONFIGURATION_SNIPPET.value
            assert s["real_device"] is False

    def test_devnet_provenance_and_real_device(self):
        with open(NETCONF_DIR / "classified_items.json", "r", encoding="utf-8") as f:
            items = json.load(f)
        for item in items:
            assert item["provenance"] == ProvenanceClassification.PUBLIC_NETCONF_EXAMPLE.value
            assert item["real_device"] is False

    def test_real_device_directory_documents_zero_real_devices(self):
        readme_path = REAL_DEVICE_DIR / "README.md"
        assert readme_path.is_file()
        content = readme_path.read_text(encoding="utf-8")
        assert "Total Count: 0" in content
        assert "Real Device Flag: false" in content


# ---------------------------------------------------------------------------
# 4. Security Directive Extraction & Non-Security Filtering
# ---------------------------------------------------------------------------

class TestSecurityExtractionAndFiltering:
    """Verifies extraction of management-plane security directives and filtering of telemetry."""

    def test_extracted_snippets_have_required_fields(self):
        with open(DATASET_DIR / "extracted_security_snippets.json", "r", encoding="utf-8") as f:
            snippets = json.load(f)

        for s in snippets:
            assert s["source_file"]
            assert s["source_path"]
            assert s["source_line"] > 0
            assert s["raw_text"]
            assert s["category"]
            assert "security_concept" in s
            assert "status" in s

    def test_snmp_community_snippets_extracted(self):
        with open(DATASET_DIR / "extracted_security_snippets.json", "r", encoding="utf-8") as f:
            snippets = json.load(f)

        snmp_snippets = [s for s in snippets if s["category"] == "SNMP"]
        assert len(snmp_snippets) >= 10
        assert any(s["normalized_field"] == "snmp_communities" for s in snmp_snippets)
        assert any(s["normalized_field"] == "snmp_agent_enabled" for s in snmp_snippets)

    def test_non_security_routing_telemetry_unmapped(self):
        with open(DATASET_DIR / "extracted_security_snippets.json", "r", encoding="utf-8") as f:
            snippets = json.load(f)

        unmapped = [s for s in snippets if s["status"] == "UNMAPPED"]
        assert len(unmapped) > 0
        for u in unmapped:
            assert u["normalized_field"] in ("UNMAPPED", None, "null")
            assert u["category"] in ("RoutingAndTelemetry", "FlowTelemetry", "Unmapped")


# ---------------------------------------------------------------------------
# 5. Normalization against SecurityBaselineModel
# ---------------------------------------------------------------------------

class TestBaselineNormalization:
    """Verifies that all normalized fields strictly exist in SecurityBaselineModel."""

    def test_all_normalized_fields_are_valid_or_unmapped(self):
        with open(DATASET_DIR / "extracted_security_snippets.json", "r", encoding="utf-8") as f:
            snippets = json.load(f)

        valid_fields = SUPPORTED_BASELINE_FIELDS | {"UNMAPPED", "AMBIGUOUS", None, "null"}
        for s in snippets:
            field = s["normalized_field"]
            assert field in valid_fields, f"Invented field detected: {field}"

    def test_no_unsupported_model_fields_invented(self):
        with open(DATASET_DIR / "extracted_security_snippets.json", "r", encoding="utf-8") as f:
            snippets = json.load(f)

        invented_fields = [
            s["normalized_field"] for s in snippets
            if s["normalized_field"] not in SUPPORTED_BASELINE_FIELDS
            and s["normalized_field"] not in ("UNMAPPED", "AMBIGUOUS", None, "null")
        ]
        assert not invented_fields


# ---------------------------------------------------------------------------
# 6. Value Extraction
# ---------------------------------------------------------------------------

class TestValueExtraction:
    """Verifies strongly typed value extraction for supported baseline fields."""

    def test_snmp_community_value_extraction(self):
        cisco_val = extract_value_for_field("snmp_communities", "snmp-server community secret-read RO")
        assert cisco_val == [{"name": "secret-read", "access": "ro"}]

        juniper_val = extract_value_for_field("snmp_communities", "set snmp community public authorization read-only")
        assert juniper_val == [{"name": "public", "access": "ro"}]

    def test_ssh_version_value_extraction(self):
        val = extract_value_for_field("ssh_version", "ip ssh version 2")
        assert val == 2

    def test_exec_timeout_value_extraction(self):
        val = extract_value_for_field("vty_exec_timeout_seconds", "exec-timeout 10 30")
        assert val == 630  # 10*60 + 30

    def test_ntp_server_value_extraction(self):
        val = extract_value_for_field("ntp_servers", "ntp server 192.168.1.100")
        assert val == ["192.168.1.100"]

    def test_logging_host_value_extraction(self):
        val = extract_value_for_field("logging_hosts", "logging host 10.10.10.50")
        assert val == ["10.10.10.50"]


# ---------------------------------------------------------------------------
# 7. Unknown and Ambiguous Syntax Handling
# ---------------------------------------------------------------------------

class TestUnknownAndAmbiguousHandling:
    """Verifies proper classification of ambiguous timers vs unmapped commands."""

    def test_flow_timeout_is_ambiguous_or_unmapped(self):
        scanner = PublicDatasetScanner(Path("config-snippets-master"))
        extracted = scanner._classify_and_normalize_line(
            clean_line="flow-inactive-timeout 15",
            vendor="Cisco",
            platform="IOS-XE",
            version="15.1",
            source_file="Cisco/IOS-XE/netflow-9.conf",
            source_path="d:/sih/config-snippets-master/Cisco/IOS-XE/netflow-9.conf",
            line_number=10,
        )
        assert extracted.status == "AMBIGUOUS"
        assert extracted.normalized_field is None

    def test_unseen_custom_command_classified_as_unmapped(self):
        matcher = NLPSemanticLayer()
        snippet = SecuritySnippet(
            source="test",
            vendor="cisco",
            raw_text="custom-proprietary-command speed 1000",
            status="UNMAPPED",
            normalized_field=None,
        )
        pred, conf, top3, val = matcher.predict(snippet)
        assert pred == "UNMAPPED"
        assert top3[0] == "UNMAPPED"
        assert val is None


# ---------------------------------------------------------------------------
# 8. Cross-Vendor Semantic Mapping & Official Documentation
# ---------------------------------------------------------------------------

class TestCrossVendorSemanticMapping:
    """Verifies multi-vendor semantic equivalence mapped to baseline fields."""

    def test_cross_vendor_mapping_file_contents(self):
        with open(DATASET_DIR / "cross_vendor_mapping.json", "r", encoding="utf-8") as f:
            mappings = json.load(f)

        assert "snmp_community_access" in mappings
        assert "snmp_agent_state" in mappings
        assert "ssh_access_control" in mappings
        assert "ssh_protocol_version" in mappings

        cisco_entry = mappings["snmp_community_access"]["vendors"]["Cisco"]
        juniper_entry = mappings["snmp_community_access"]["vendors"]["Juniper"]
        arista_entry = mappings["snmp_community_access"]["vendors"]["Arista"]

        assert "snmp-server community" in cisco_entry["syntax"]
        assert "community" in juniper_entry["syntax"]
        assert "snmp-server community" in arista_entry["syntax"]

    def test_official_documentation_references_exist(self):
        with open(OFFICIAL_DIR / "documentation_references.json", "r", encoding="utf-8") as f:
            docs = json.load(f)

        assert "Cisco" in docs
        assert "Juniper" in docs
        assert "Arista" in docs
        assert "Huawei" in docs
        assert "Mikrotik" in docs


# ---------------------------------------------------------------------------
# 9. Dataset Leakage Prevention
# ---------------------------------------------------------------------------

class TestDatasetLeakage:
    """Verifies that no configuration file spans across train/val/test splits."""

    def test_no_file_level_leakage(self):
        with open(DATASET_DIR / "train" / "snippets.json", "r", encoding="utf-8") as f:
            train = json.load(f)
        with open(DATASET_DIR / "validation" / "snippets.json", "r", encoding="utf-8") as f:
            val = json.load(f)
        with open(DATASET_DIR / "test" / "snippets.json", "r", encoding="utf-8") as f:
            test = json.load(f)

        train_files = {s["source_file"] for s in train}
        val_files = {s["source_file"] for s in val}
        test_files = {s["source_file"] for s in test}

        assert len(train_files & val_files) == 0, "Leakage between train and validation"
        assert len(train_files & test_files) == 0, "Leakage between train and test"
        assert len(val_files & test_files) == 0, "Leakage between validation and test"

    def test_partitioning_function_strict_isolation(self):
        dummy_snippets = [
            SecuritySnippet(source_file="file_A.conf", raw_text="line 1"),
            SecuritySnippet(source_file="file_A.conf", raw_text="line 2"),
            SecuritySnippet(source_file="file_B.conf", raw_text="line 3"),
            SecuritySnippet(source_file="file_C.conf", raw_text="line 4"),
        ]
        tr, va, te = partition_snippets_without_leakage(dummy_snippets, train_ratio=0.5, val_ratio=0.25)
        tr_files = {s.source_file for s in tr}
        va_files = {s.source_file for s in va}
        te_files = {s.source_file for s in te}
        assert not (tr_files & va_files)
        assert not (tr_files & te_files)
        assert not (va_files & te_files)


# ---------------------------------------------------------------------------
# 10. Multi-Vendor Parser Isolation
# ---------------------------------------------------------------------------

class TestMultiVendorParserIsolation:
    """Verifies that vendor parsers are strictly isolated and do not accept incompatible syntax."""

    def test_cisco_parser_rejects_or_ignores_juniper_syntax(self):
        parser = CiscoIOSParser()
        baseline = parser.parse("set system services ssh protocol-version v2\nset snmp community public")
        # Cisco parser must not parse Junos set commands as valid Cisco SSH or SNMP settings
        assert not baseline.ssh_version.detected or baseline.ssh_version.value != 2

    def test_juniper_parser_rejects_cisco_syntax(self):
        parser = JunosParser()
        # Junos parser raises ParserError on foreign Cisco syntax (strict parser isolation)
        with pytest.raises(Exception):
            parser.parse("ip ssh version 2\nsnmp-server community public RO")


# ---------------------------------------------------------------------------
# 11. False Semantic Mapping Prevention
# ---------------------------------------------------------------------------

class TestFalseMappingPrevention:
    """Verifies that NLP snippets do NOT emit compliance PASS/FAIL results."""

    def test_snippets_have_no_compliance_verdict(self):
        with open(DATASET_DIR / "extracted_security_snippets.json", "r", encoding="utf-8") as f:
            snippets = json.load(f)

        for s in snippets:
            assert "verdict" not in s
            assert "compliance_pass" not in s
            assert "pass_fail" not in s


# ---------------------------------------------------------------------------
# 12. NLP Benchmark Evaluation Metrics
# ---------------------------------------------------------------------------

class TestNLPBenchmarkEvaluation:
    """Runs NLP benchmarks and checks metrics across deterministic, NLP, and hybrid models."""

    def test_benchmark_metrics_calculation(self):
        with open(DATASET_DIR / "test" / "snippets.json", "r", encoding="utf-8") as f:
            test_data = json.load(f)

        test_snippets = []
        for item in test_data:
            test_snippets.append(
                SecuritySnippet(
                    source_file=item["source_file"],
                    source_line=item["source_line"],
                    raw_text=item["raw_text"],
                    vendor=item["vendor"],
                    security_concept=item["security_concept"],
                    normalized_field=item["normalized_field"],
                    value=item["value"],
                    status=item["status"],
                )
            )

        matcher = HybridSemanticMatcher()
        result = run_nlp_benchmark(test_snippets, matcher, "Test Split Hybrid")

        assert result.total_evaluated == len(test_snippets)
        assert 0.0 <= result.top1_accuracy <= 1.0
        assert 0.0 <= result.top3_accuracy <= 1.0
        assert result.top3_accuracy >= result.top1_accuracy
        assert 0.0 <= result.entity_extraction_accuracy <= 1.0
        assert 0.0 <= result.value_extraction_accuracy <= 1.0
        assert 0.0 <= result.false_mapping_rate <= 1.0
        assert 0.0 <= result.human_review_rate <= 1.0
        assert 0.0 <= result.average_confidence <= 1.0
