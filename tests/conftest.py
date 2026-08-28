"""Shared fixtures: the two sample configs, parsed once per session."""

from pathlib import Path
from typing import Dict

import pytest

from auditor.engine import ComplianceEngine
from auditor.models.baseline import SecurityBaselineModel
from auditor.models.result import ControlResult
from auditor.parsers import CiscoIOSParser
from auditor.rules import load_framework

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = PROJECT_ROOT / "samples"


@pytest.fixture(scope="session")
def hardened_text() -> str:
    return (SAMPLES / "hardened_ios.conf").read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def insecure_text() -> str:
    return (SAMPLES / "insecure_ios.conf").read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def hardened(hardened_text: str) -> SecurityBaselineModel:
    return CiscoIOSParser().parse(hardened_text, source_file="samples/hardened_ios.conf")


@pytest.fixture(scope="session")
def insecure(insecure_text: str) -> SecurityBaselineModel:
    return CiscoIOSParser().parse(insecure_text, source_file="samples/insecure_ios.conf")


@pytest.fixture(scope="session")
def ruleset():
    return load_framework("CIS", "cisco_ios")


@pytest.fixture(scope="session")
def engine(ruleset) -> ComplianceEngine:
    return ComplianceEngine(ruleset)


def results_by_id(engine: ComplianceEngine, baseline: SecurityBaselineModel) -> Dict[str, ControlResult]:
    return {result.rule_id: result for result in engine.evaluate(baseline)}


@pytest.fixture(scope="session")
def hardened_results(engine, hardened) -> Dict[str, ControlResult]:
    return results_by_id(engine, hardened)


@pytest.fixture(scope="session")
def insecure_results(engine, insecure) -> Dict[str, ControlResult]:
    return results_by_id(engine, insecure)
