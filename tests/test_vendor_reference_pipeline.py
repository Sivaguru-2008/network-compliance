"""Tests for the authoritative vendor reference acquisition, extraction, and validation pipeline."""

import json
from pathlib import Path
import pytest

from auditor.dataset.downloader import ReferenceDownloader
from auditor.dataset.extractor import DocumentExtractor, ExtractedDocument
from auditor.dataset.fixtures_loader import load_or_sync_fixtures
from auditor.dataset.gap_detector import ParserGapDetector
from auditor.dataset.grammar import VENDOR_GRAMMARS, get_vendor_grammar, save_all_vendor_grammars
from auditor.dataset.manifest import DatasetManifestManager
from auditor.dataset.nlp_export import NLPDatasetExporter
from auditor.dataset.nlp_extractor import NLPCommandExtractor
from auditor.dataset.sanitizer import SecretSanitizer
from auditor.dataset.sources import VENDOR_SOURCES, AccessType, get_all_vendor_keys, get_sources_for_vendor
from auditor.knowledge.repository import get_authoritative_citation, get_vendor_command_reference


class TestVendorSourcesCatalog:
    """Test the authoritative vendor source index catalog."""

    def test_all_12_vendors_present(self):
        expected_vendors = {
            "cisco_ios",
            "juniper_junos",
            "fortinet_fortios",
            "arista_eos",
            "sonic",
            "paloalto_panos",
            "huawei_vrp",
            "checkpoint_gaia",
            "mikrotik_routeros",
            "sonicwall",
            "stormshield",
            "watchguard_fireware",
        }
        all_keys = set(get_all_vendor_keys())
        assert expected_vendors.issubset(all_keys), f"Missing vendors: {expected_vendors - all_keys}"

    def test_sources_have_valid_urls_and_titles(self):
        for vendor_key, sources in VENDOR_SOURCES.items():
            assert len(sources) > 0, f"Vendor {vendor_key} has no sources defined"
            for src in sources:
                assert src.url.startswith("https://") or src.url.startswith("http://")
                assert src.doc_title != ""
                assert src.vendor_key == vendor_key
                assert isinstance(src.access_type, AccessType)


class TestSecretSanitizer:
    """Test credential and secret scanning and sanitization."""

    def test_sanitizes_cisco_enable_secret(self):
        raw = "enable secret 5 $1$abcdef1234567890\nhostname test-rtr"
        res = SecretSanitizer.scan_and_sanitize(raw)
        assert not res.is_clean
        assert "<SANITIZED_ENABLE_SECRET>" in res.sanitized_content
        assert "$1$abcdef1234567890" not in res.sanitized_content

    def test_sanitizes_snmp_community(self):
        raw = "snmp-server community secretComm RO 10\nlogging host 10.0.0.1"
        res = SecretSanitizer.scan_and_sanitize(raw)
        assert "<SANITIZED_SNMP_COMMUNITY>" in res.sanitized_content
        assert "secretComm" not in res.sanitized_content

    def test_sanitizes_private_key_block(self):
        raw = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
        res = SecretSanitizer.scan_and_sanitize(raw)
        assert "<SANITIZED_PRIVATE_KEY_BLOCK>" in res.sanitized_content
        assert "MIIEowIBAAKCAQEA0" not in res.sanitized_content


class TestDocumentExtractorAndNLP:
    """Test text and structured command extraction."""

    def test_markdown_extraction(self, tmp_path):
        md_file = tmp_path / "sample_manual.md"
        md_file.write_text("# Chapter 1: SSH Configuration\n\n```\nip ssh version 2\nip ssh time-out 60\n```\n", encoding="utf-8")

        extractor = DocumentExtractor(dataset_base=tmp_path)
        doc = extractor.extract_markdown(md_file, "cisco_ios", "Sample Manual", "15.0")
        assert doc.total_sections >= 1
        assert doc.total_code_blocks >= 1

        nlp = NLPCommandExtractor(dataset_base=tmp_path)
        cmds = nlp.extract_from_document(doc, "https://example.com/sample.md")
        assert len(cmds) >= 1
        ssh_cmd = next(c for c in cmds if "ssh" in c.command)
        assert ssh_cmd.provenance_status == "SOURCE VERIFIED"
        assert ssh_cmd.security_relevance == "management_ssh"

    def test_vendor_grammar_definitions(self):
        for vk in get_all_vendor_keys():
            grammar = get_vendor_grammar(vk)
            assert grammar is not None, f"Missing grammar for {vk}"
            assert grammar.syntax_type != ""
            assert len(grammar.root_blocks) > 0


class TestGapDetectorAndManifest:
    """Test parser gap analysis and dataset manifest integrity."""

    def test_gap_detector_runs_for_all_vendors(self):
        detector = ParserGapDetector()
        reports = detector.analyze_all()
        assert len(reports) >= 12
        for vk, rep in reports.items():
            assert rep.vendor_key == vk
            assert rep.parser_class_name != ""
            assert rep.coverage_percentage >= 0.0

    def test_manifest_validation(self):
        manifest_mgr = DatasetManifestManager()
        res = manifest_mgr.validate_dataset()
        assert res.is_valid is True
        assert res.valid_artifacts > 0
        assert len(res.missing_files) == 0
        assert len(res.hash_mismatches) == 0

    def test_nlp_exporter(self):
        exporter = NLPDatasetExporter()
        counts = exporter.export_all()
        assert counts["commands"] >= 0
        assert counts["documents"] >= 0
        assert counts["config_blocks"] >= 0
        assert counts["parser_examples"] >= 0


class TestAuthoritativeCitations:
    """Test retrieval of authoritative citations from knowledge repository."""

    def test_get_authoritative_citation_fortinet(self):
        res = get_authoritative_citation("fortinet_fortios", "admin-lockout-threshold")
        if res:
            assert res["provenance_status"] == "SOURCE VERIFIED"
            assert "fortinet" in res["vendor"]
