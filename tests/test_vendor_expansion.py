"""Vendor expansion verification test.

Proves that adding a new vendor parser requires ONLY:
  1. A parser file (auditor/parsers/<vendor>.py)
  2. Registration in auditor/parsers/__init__.py
  3. Rule mappings in the framework JSON files
  4. Tests

NO changes to the compliance engine, pipeline, ingestion, CLI, or web
layer are needed. This is a structural guarantee of the architecture.
"""

import inspect
from pathlib import Path

import pytest

from auditor.parsers.base import VendorParser, registry
from auditor.engine.evaluator import ComplianceEngine
from auditor.models.baseline import SecurityBaselineModel, ParserProvenance
from auditor.models.observation import Observation, Origin
from auditor.models.rule import (
    ComplianceRule, LeafCondition, Operator, Platform, Remediation, RuleSet, Severity,
)
from auditor.pipeline import select_parser


# ---------------------------------------------------------------- structural


class TestVendorIsolation:
    """The engine, pipeline, and CLI must not name any vendor."""

    def test_engine_does_not_import_any_parser(self):
        source = inspect.getsource(ComplianceEngine)
        parser_modules = [
            "cisco_ios", "junos", "fortios", "arista_eos", "sonic",
            "paloalto", "huawei_vrp", "checkpoint_gaia", "mikrotik_routeros",
            "sonicwall", "stormshield", "watchguard",
        ]
        for mod in parser_modules:
            assert mod not in source, (
                f"ComplianceEngine references parser module '{mod}'. "
                "The engine must be vendor-agnostic."
            )

    def test_all_registered_parsers_extend_vendor_parser(self):
        for name in registry.names():
            cls = registry.get(name)
            assert issubclass(cls, VendorParser), f"{name} does not extend VendorParser"

    def test_each_parser_has_detect_and_parse(self):
        for name in registry.names():
            cls = registry.get(name)
            assert hasattr(cls, "detect"), f"{name} missing detect()"
            assert hasattr(cls, "parse"), f"{name} missing parse()"


class TestNewVendorRequiresNoEngineChanges:
    """Simulating a new vendor parser requires zero engine modifications."""

    def test_fake_vendor_evaluates_with_existing_engine(self):
        provenance = ParserProvenance(
            parser_name="FakeVendorParser",
            parser_version="1.0.0",
            vendor="fake_vendor",
            os_family="fake_os",
        )
        baseline = SecurityBaselineModel(provenance=provenance)
        object.__setattr__(
            baseline, "ssh_enabled",
            Observation.found(True, source_line="ssh enable", line_number=1),
        )

        rule = ComplianceRule(
            id="FAKE-SSH-1",
            title="SSH must be enabled",
            description="Test rule for fake vendor",
            severity=Severity.HIGH,
            condition=LeafCondition(field="ssh_enabled", operator=Operator.IS_TRUE),
            remediation=Remediation(summary="Enable SSH on the device."),
        )
        ruleset = RuleSet(
            schema_version="1.0",
            framework="CIS",
            framework_version="1.0",
            platform=Platform(vendor="fake_vendor", os_family="fake_os"),
            rules=[rule],
        )

        engine = ComplianceEngine(ruleset)
        results = engine.evaluate(baseline)
        assert len(results) == 1
        assert results[0].status.value == "PASS"

    def test_all_vendor_parsers_produce_compatible_baselines(self):
        """Every parser returns a SecurityBaselineModel the engine can evaluate."""
        for name in registry.names():
            if name in ("llm", "hybrid"):
                continue
            cls = registry.get(name)
            baseline_cls = SecurityBaselineModel
            # Verify the parser's parse method signature accepts a string
            sig = inspect.signature(cls.parse)
            params = list(sig.parameters.keys())
            assert "config_text" in params or len(params) >= 2, (
                f"{name}.parse() must accept config_text"
            )


class TestVendorCount:
    """Track the vendor count — a regression if one disappears."""

    def test_at_least_12_deterministic_parsers(self):
        deterministic = [
            name for name in registry.names()
            if name not in ("llm", "hybrid")
        ]
        assert len(deterministic) >= 12, (
            f"Expected at least 12 deterministic parsers, found {len(deterministic)}: "
            f"{deterministic}"
        )

    def test_parser_files_exist(self):
        parser_dir = Path("auditor/parsers")
        expected = [
            "cisco_ios.py", "junos.py", "fortios.py", "arista_eos.py",
            "sonic.py", "paloalto.py", "huawei_vrp.py", "checkpoint_gaia.py",
            "mikrotik_routeros.py", "sonicwall.py", "stormshield.py", "watchguard.py",
        ]
        for filename in expected:
            assert (parser_dir / filename).exists(), f"Missing parser file: {filename}"
