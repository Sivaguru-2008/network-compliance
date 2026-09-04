"""Comprehensive tests for the NLP requirement-to-rule mapping pipeline.

Every test uses manually defined ground truth. Tests cover:
  - canonical requirements (one per control)
  - paraphrased requirements
  - synonym handling
  - different sentence structures
  - technical terminology
  - negation (positive and negative requirements)
  - multiple requirements in one sentence
  - vendor-specific terminology (Cisco IOS, Junos CLI)
  - numeric parameters (timeout seconds, password length, SSH version)
  - ambiguous requirements
  - unsupported / unrelated requirements
  - malformed / empty input
  - end-to-end compliance engine integration

Metrics calculated at the end:
  - Intent accuracy
  - Rule-mapping accuracy (exact match)
  - Precision / Recall / F1
  - Unknown/ambiguous detection accuracy
"""

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from auditor.nlp.preprocessor import (
    PreprocessedText,
    extract_numeric_params,
    normalize,
    preprocess,
    split_requirements,
    tokenize,
)
from auditor.nlp.extractor import ExtractionResult, Intent, extract
from auditor.nlp.mapper import MappingResult, MappingStatus, map_requirement
from auditor.nlp.pipeline import NLPPipeline, RequirementResult


# =========================================================================== #
#  Ground truth definitions                                                    #
# =========================================================================== #

@dataclass
class GroundTruth:
    text: str
    expected_intent: str
    expected_rule_ids: List[str]
    expected_status: str
    is_negative: bool = False
    expected_concepts: Optional[List[str]] = None
    expected_params: Optional[Dict[str, Any]] = None
    category: str = "canonical"


CANONICAL_CASES: List[GroundTruth] = [
    GroundTruth(
        text="Enable AAA authentication on the device",
        expected_intent="ENFORCE",
        expected_rule_ids=["aaa_enabled"],
        expected_status="MAPPED",
        expected_concepts=["aaa"],
        category="canonical",
    ),
    GroundTruth(
        text="VTY lines must accept SSH only and telnet must be disabled",
        expected_intent="ENFORCE",
        expected_rule_ids=["secure_vty_transport"],
        expected_status="MAPPED",
        expected_concepts=["vty_transport"],
        category="canonical",
    ),
    GroundTruth(
        text="Set the VTY idle timeout to 600 seconds",
        expected_intent="ENFORCE",
        expected_rule_ids=["vty_idle_timeout"],
        expected_status="MAPPED",
        expected_concepts=["idle_timeout"],
        expected_params={"seconds": 600.0},
        category="canonical",
    ),
    GroundTruth(
        text="The enable secret must be stored as a hash and passwords must be encrypted",
        expected_intent="ENFORCE",
        expected_rule_ids=["enable_secret_encrypted"],
        expected_status="MAPPED",
        expected_concepts=["enable_secret"],
        category="canonical",
    ),
    GroundTruth(
        text="No SNMP community string should use the default value public or private",
        expected_intent="ENFORCE",
        expected_rule_ids=["no_default_snmp_community"],
        expected_status="MAPPED",
        expected_concepts=["snmp_default"],
        category="canonical",
    ),
    GroundTruth(
        text="The HTTP management server must be disabled",
        expected_intent="ENFORCE",
        expected_rule_ids=["http_server_disabled"],
        expected_status="MAPPED",
        expected_concepts=["http_server"],
        category="canonical",
    ),
    GroundTruth(
        text="Enforce SSH protocol version 2",
        expected_intent="ENFORCE",
        expected_rule_ids=["ssh_version_2"],
        expected_status="MAPPED",
        expected_concepts=["ssh_version"],
        category="canonical",
    ),
    GroundTruth(
        text="Configure a syslog destination for remote logging",
        expected_intent="ENFORCE",
        expected_rule_ids=["logging_enabled"],
        expected_status="MAPPED",
        expected_concepts=["logging"],
        category="canonical",
    ),
    GroundTruth(
        text="Restrict management access to authorized source subnets using an ACL",
        expected_intent="ENFORCE",
        expected_rule_ids=["management_acl"],
        expected_status="MAPPED",
        expected_concepts=["management_acl"],
        category="canonical",
    ),
    GroundTruth(
        text="A login banner must be displayed to warn unauthorized users",
        expected_intent="ENFORCE",
        expected_rule_ids=["login_banner"],
        expected_status="MAPPED",
        expected_concepts=["login_banner"],
        category="canonical",
    ),
    GroundTruth(
        text="Passwords must be at least 8 characters long",
        expected_intent="ENFORCE",
        expected_rule_ids=["password_min_length"],
        expected_status="MAPPED",
        expected_concepts=["password_min_length"],
        category="canonical",
    ),
    GroundTruth(
        text="Configure at least one NTP server for time synchronization",
        expected_intent="ENFORCE",
        expected_rule_ids=["ntp_configured"],
        expected_status="MAPPED",
        expected_concepts=["ntp"],
        category="canonical",
    ),
    GroundTruth(
        text="Do not configure read-write SNMP communities",
        expected_intent="PROHIBIT",
        expected_rule_ids=["no_write_snmp_community"],
        expected_status="MAPPED",
        is_negative=True,
        expected_concepts=["snmp_write"],
        category="canonical",
    ),
]


PARAPHRASE_CASES: List[GroundTruth] = [
    GroundTruth(
        text="Centralized authentication must be turned on",
        expected_intent="ENFORCE",
        expected_rule_ids=["aaa_enabled"],
        expected_status="MAPPED",
        category="paraphrase",
    ),
    GroundTruth(
        text="Only encrypted protocols should be used for remote administration",
        expected_intent="ENFORCE",
        expected_rule_ids=["secure_vty_transport"],
        expected_status="MAPPED",
        category="paraphrase",
    ),
    GroundTruth(
        text="Idle sessions on the console must automatically disconnect after 10 minutes",
        expected_intent="ENFORCE",
        expected_rule_ids=["vty_idle_timeout"],
        expected_status="MAPPED",
        expected_params={"seconds": 600.0},
        category="paraphrase",
    ),
    GroundTruth(
        text="The privileged access credential must be hashed, not stored in plaintext",
        expected_intent="ENFORCE",
        expected_rule_ids=["enable_secret_encrypted"],
        expected_status="MAPPED",
        category="paraphrase",
    ),
    GroundTruth(
        text="Well-known community strings such as public must not be used in SNMP configuration",
        expected_intent="PROHIBIT",
        expected_rule_ids=["no_default_snmp_community"],
        expected_status="MAPPED",
        is_negative=True,
        category="paraphrase",
    ),
    GroundTruth(
        text="The unencrypted web management interface must be turned off",
        expected_intent="ENFORCE",
        expected_rule_ids=["http_server_disabled"],
        expected_status="MAPPED",
        category="paraphrase",
    ),
    GroundTruth(
        text="The device should only allow SSH v2 connections",
        expected_intent="ENFORCE",
        expected_rule_ids=["ssh_version_2"],
        expected_status="MAPPED",
        category="paraphrase",
    ),
    GroundTruth(
        text="Event logs must be sent to a remote syslog host",
        expected_intent="ENFORCE",
        expected_rule_ids=["logging_enabled"],
        expected_status="MAPPED",
        category="paraphrase",
    ),
    GroundTruth(
        text="Administrative access should be limited to specific IP addresses via a filter",
        expected_intent="ENFORCE",
        expected_rule_ids=["management_acl"],
        expected_status="MAPPED",
        category="paraphrase",
    ),
    GroundTruth(
        text="A warning message must appear before the login prompt",
        expected_intent="ENFORCE",
        expected_rule_ids=["login_banner"],
        expected_status="MAPPED",
        category="paraphrase",
    ),
    GroundTruth(
        text="The minimum passphrase length must be at least eight characters",
        expected_intent="ENFORCE",
        expected_rule_ids=["password_min_length"],
        expected_status="MAPPED",
        category="paraphrase",
    ),
    GroundTruth(
        text="Clock synchronization must be configured with a time server",
        expected_intent="ENFORCE",
        expected_rule_ids=["ntp_configured"],
        expected_status="MAPPED",
        category="paraphrase",
    ),
    GroundTruth(
        text="SNMP communities must not have write access",
        expected_intent="PROHIBIT",
        expected_rule_ids=["no_write_snmp_community"],
        expected_status="MAPPED",
        is_negative=True,
        category="paraphrase",
    ),
]


NEGATION_CASES: List[GroundTruth] = [
    GroundTruth(
        text="Disable telnet on all management interfaces",
        expected_intent="PROHIBIT",
        expected_rule_ids=["secure_vty_transport"],
        expected_status="MAPPED",
        is_negative=True,
        category="negation",
    ),
    GroundTruth(
        text="The device must not allow HTTP management access",
        expected_intent="PROHIBIT",
        expected_rule_ids=["http_server_disabled"],
        expected_status="MAPPED",
        is_negative=True,
        category="negation",
    ),
    GroundTruth(
        text="Prevent the use of default SNMP community strings",
        expected_intent="PROHIBIT",
        expected_rule_ids=["no_default_snmp_community"],
        expected_status="MAPPED",
        is_negative=True,
        category="negation",
    ),
    GroundTruth(
        text="No read-write SNMP communities should be configured",
        expected_intent="PROHIBIT",
        expected_rule_ids=["no_write_snmp_community"],
        expected_status="MAPPED",
        is_negative=True,
        category="negation",
    ),
]


VENDOR_CASES: List[GroundTruth] = [
    GroundTruth(
        text="aaa new-model must be configured",
        expected_intent="ENFORCE",
        expected_rule_ids=["aaa_enabled"],
        expected_status="MAPPED",
        category="vendor",
    ),
    GroundTruth(
        text="exec-timeout must be set to 10 0 on all VTY lines",
        expected_intent="ENFORCE",
        expected_rule_ids=["vty_idle_timeout"],
        expected_status="MAPPED",
        category="vendor",
    ),
    GroundTruth(
        text="ip ssh version 2 must be configured",
        expected_intent="ENFORCE",
        expected_rule_ids=["ssh_version_2"],
        expected_status="MAPPED",
        category="vendor",
    ),
    GroundTruth(
        text="no ip http server must be applied",
        expected_intent="ENFORCE",
        expected_rule_ids=["http_server_disabled"],
        expected_status="MAPPED",
        category="vendor",
    ),
    GroundTruth(
        text="snmp-server community public RO should be removed",
        expected_intent="ENFORCE",
        expected_rule_ids=["no_default_snmp_community"],
        expected_status="MAPPED",
        category="vendor",
    ),
    GroundTruth(
        text="set system services ssh protocol-version v2",
        expected_intent="UNKNOWN",
        expected_rule_ids=["ssh_version_2"],
        expected_status="MAPPED",
        category="vendor",
    ),
    GroundTruth(
        text="banner motd must be configured with a legal notice",
        expected_intent="ENFORCE",
        expected_rule_ids=["login_banner"],
        expected_status="MAPPED",
        category="vendor",
    ),
    GroundTruth(
        text="logging host 10.0.0.1 must be set",
        expected_intent="ENFORCE",
        expected_rule_ids=["logging_enabled"],
        expected_status="MAPPED",
        category="vendor",
    ),
    GroundTruth(
        text="security passwords min-length 8 must be configured",
        expected_intent="ENFORCE",
        expected_rule_ids=["password_min_length"],
        expected_status="MAPPED",
        category="vendor",
    ),
]


NUMERIC_CASES: List[GroundTruth] = [
    GroundTruth(
        text="The VTY session timeout must be 300 seconds or less",
        expected_intent="ENFORCE",
        expected_rule_ids=["vty_idle_timeout"],
        expected_status="MAPPED",
        expected_params={"seconds": 300.0},
        category="numeric",
    ),
    GroundTruth(
        text="Enforce a minimum password length of 10 characters",
        expected_intent="ENFORCE",
        expected_rule_ids=["password_min_length"],
        expected_status="MAPPED",
        expected_params={"characters": 10.0},
        category="numeric",
    ),
    GroundTruth(
        text="SSH version 2 is required",
        expected_intent="ENFORCE",
        expected_rule_ids=["ssh_version_2"],
        expected_status="MAPPED",
        expected_params={"version": 2.0},
        category="numeric",
    ),
    GroundTruth(
        text="The idle timeout must not exceed 5 minutes",
        expected_intent="PROHIBIT",
        expected_rule_ids=["vty_idle_timeout"],
        expected_status="MAPPED",
        expected_params={"seconds": 300.0},
        is_negative=True,
        category="numeric",
    ),
]


MULTI_REQUIREMENT_CASES: List[GroundTruth] = [
    GroundTruth(
        text="Enable AAA authentication. Configure a login banner. Set NTP time synchronization.",
        expected_intent="ENFORCE",
        expected_rule_ids=["aaa_enabled", "login_banner", "ntp_configured"],
        expected_status="MAPPED",
        category="multi",
    ),
    GroundTruth(
        text="Ensure SSH version 2 is enforced and disable telnet",
        expected_intent="ENFORCE",
        expected_rule_ids=["ssh_version_2", "secure_vty_transport"],
        expected_status="MAPPED",
        category="multi",
    ),
]


UNSUPPORTED_CASES: List[GroundTruth] = [
    GroundTruth(
        text="The weather today is sunny and warm",
        expected_intent="UNKNOWN",
        expected_rule_ids=[],
        expected_status="UNKNOWN",
        category="unsupported",
    ),
    GroundTruth(
        text="Configure BGP routing with AS 65001",
        expected_intent="ENFORCE",
        expected_rule_ids=[],
        expected_status="UNKNOWN",
        category="unsupported",
    ),
    GroundTruth(
        text="Enable OSPF area 0 on all backbone interfaces",
        expected_intent="ENFORCE",
        expected_rule_ids=[],
        expected_status="UNKNOWN",
        category="unsupported",
    ),
]


MALFORMED_CASES: List[GroundTruth] = [
    GroundTruth(
        text="",
        expected_intent="UNKNOWN",
        expected_rule_ids=[],
        expected_status="UNKNOWN",
        category="malformed",
    ),
    GroundTruth(
        text="   ",
        expected_intent="UNKNOWN",
        expected_rule_ids=[],
        expected_status="UNKNOWN",
        category="malformed",
    ),
    GroundTruth(
        text="!!@@##$$%%",
        expected_intent="UNKNOWN",
        expected_rule_ids=[],
        expected_status="UNKNOWN",
        category="malformed",
    ),
    GroundTruth(
        text="a",
        expected_intent="UNKNOWN",
        expected_rule_ids=[],
        expected_status="UNKNOWN",
        category="malformed",
    ),
]


SYNONYM_CASES: List[GroundTruth] = [
    GroundTruth(
        text="Credential verification using RADIUS must be enabled",
        expected_intent="ENFORCE",
        expected_rule_ids=["aaa_enabled"],
        expected_status="MAPPED",
        category="synonym",
    ),
    GroundTruth(
        text="Session inactivity timeout must be configured",
        expected_intent="ENFORCE",
        expected_rule_ids=["vty_idle_timeout"],
        expected_status="MAPPED",
        category="synonym",
    ),
    GroundTruth(
        text="The legal notice must appear at the login prompt",
        expected_intent="ENFORCE",
        expected_rule_ids=["login_banner"],
        expected_status="MAPPED",
        category="synonym",
    ),
    GroundTruth(
        text="Audit logging must have a remote destination",
        expected_intent="ENFORCE",
        expected_rule_ids=["logging_enabled"],
        expected_status="MAPPED",
        category="synonym",
    ),
    GroundTruth(
        text="Clock sync with an NTP time source is required",
        expected_intent="ENFORCE",
        expected_rule_ids=["ntp_configured"],
        expected_status="MAPPED",
        category="synonym",
    ),
]


SENTENCE_STRUCTURE_CASES: List[GroundTruth] = [
    GroundTruth(
        text="Is AAA authentication enabled?",
        expected_intent="VERIFY",
        expected_rule_ids=["aaa_enabled"],
        expected_status="MAPPED",
        category="structure",
    ),
    GroundTruth(
        text="Verify that SSH version 2 is enforced",
        expected_intent="VERIFY",
        expected_rule_ids=["ssh_version_2"],
        expected_status="MAPPED",
        category="structure",
    ),
    GroundTruth(
        text="Check whether an NTP server has been configured",
        expected_intent="VERIFY",
        expected_rule_ids=["ntp_configured"],
        expected_status="MAPPED",
        category="structure",
    ),
    GroundTruth(
        text="All management sessions should have an idle timeout",
        expected_intent="ENFORCE",
        expected_rule_ids=["vty_idle_timeout"],
        expected_status="MAPPED",
        category="structure",
    ),
]


ALL_CASES = (
    CANONICAL_CASES
    + PARAPHRASE_CASES
    + NEGATION_CASES
    + VENDOR_CASES
    + NUMERIC_CASES
    + MULTI_REQUIREMENT_CASES
    + UNSUPPORTED_CASES
    + MALFORMED_CASES
    + SYNONYM_CASES
    + SENTENCE_STRUCTURE_CASES
)


# =========================================================================== #
#  Preprocessing tests                                                         #
# =========================================================================== #


class TestPreprocessing:
    def test_normalize_lowercase(self):
        assert normalize("Enable AAA") == "enable aaa"

    def test_normalize_collapse_whitespace(self):
        assert normalize("  multiple   spaces  ") == "multiple spaces"

    def test_normalize_strip_punctuation(self):
        result = normalize("Enable AAA! Configure NTP?")
        assert "!" not in result
        assert "?" not in result

    def test_normalize_empty(self):
        assert normalize("") == ""
        assert normalize("   ") == ""

    def test_tokenize_produces_tokens(self):
        tokens = tokenize("enable aaa timeout 300")
        assert len(tokens) == 4
        assert tokens[3].is_number
        assert tokens[3].numeric_value == 300.0

    def test_extract_numeric_seconds(self):
        params = extract_numeric_params("timeout 600 seconds")
        assert params["seconds"] == 600.0

    def test_extract_numeric_minutes(self):
        params = extract_numeric_params("timeout of 10 minutes")
        assert params["seconds"] == 600.0

    def test_extract_numeric_version(self):
        params = extract_numeric_params("SSH version 2")
        assert params["version"] == 2.0

    def test_extract_numeric_min_length(self):
        params = extract_numeric_params("minimum length of 8")
        assert params["min_length"] == 8.0

    def test_extract_numeric_characters(self):
        params = extract_numeric_params("at least 12 characters")
        assert params["characters"] == 12.0

    def test_split_requirements_period(self):
        parts = split_requirements("Enable AAA. Configure NTP. Set a banner.")
        assert len(parts) == 3

    def test_split_requirements_semicolon(self):
        parts = split_requirements("Enable AAA; configure NTP")
        assert len(parts) == 2

    def test_split_requirements_and_verb(self):
        parts = split_requirements("Ensure SSH v2 and disable telnet")
        assert len(parts) == 2

    def test_split_requirements_single(self):
        parts = split_requirements("Enable AAA authentication")
        assert len(parts) == 1

    def test_split_requirements_empty(self):
        assert split_requirements("") == []
        assert split_requirements("   ") == []

    def test_preprocess_vendor_terms(self):
        pp = preprocess("no ip http server must be applied")
        assert "disable http management server" in pp.normalized
        assert "no ip http server" in pp.detected_vendor_terms

    def test_preprocess_negation_detection(self):
        pp = preprocess("do not configure telnet")
        assert len(pp.detected_negations) > 0

    def test_preprocess_synonym_expansion(self):
        pp = preprocess("Configure syslog remote logging")
        assert "logging" in pp.expanded_synonyms


# =========================================================================== #
#  Extraction tests                                                            #
# =========================================================================== #


class TestExtraction:
    def test_enforce_intent(self):
        pp = preprocess("Enable AAA authentication")
        ex = extract(pp)
        assert ex.intent == Intent.ENFORCE

    def test_prohibit_intent(self):
        pp = preprocess("Disable telnet access")
        ex = extract(pp)
        assert ex.intent == Intent.PROHIBIT

    def test_verify_intent(self):
        pp = preprocess("Verify that SSH version 2 is enforced")
        ex = extract(pp)
        assert ex.intent == Intent.VERIFY

    def test_unknown_intent(self):
        pp = preprocess("The weather is sunny")
        ex = extract(pp)
        assert ex.intent == Intent.UNKNOWN

    def test_negative_requirement_detection(self):
        pp = preprocess("The device must not allow HTTP management access")
        ex = extract(pp)
        assert ex.is_negative_requirement is True

    def test_positive_requirement_detection(self):
        pp = preprocess("Enable AAA authentication")
        ex = extract(pp)
        assert ex.is_negative_requirement is False

    def test_entity_extraction_aaa(self):
        pp = preprocess("Enable centralized authentication using RADIUS")
        ex = extract(pp)
        concepts = [e.concept for e in ex.entities]
        assert "aaa" in concepts

    def test_entity_extraction_ssh_version(self):
        pp = preprocess("Enforce SSH protocol version 2")
        ex = extract(pp)
        concepts = [e.concept for e in ex.entities]
        assert "ssh_version" in concepts
        ssh_ent = next(e for e in ex.entities if e.concept == "ssh_version")
        assert ssh_ent.parameters.get("version") == 2

    def test_entity_extraction_timeout_params(self):
        pp = preprocess("Set idle timeout to 300 seconds")
        ex = extract(pp)
        concepts = [e.concept for e in ex.entities]
        assert "idle_timeout" in concepts
        timeout_ent = next(e for e in ex.entities if e.concept == "idle_timeout")
        assert timeout_ent.parameters.get("timeout_seconds") == 300.0

    def test_entity_extraction_password_length(self):
        pp = preprocess("Minimum password length must be 10 characters")
        ex = extract(pp)
        concepts = [e.concept for e in ex.entities]
        assert "password_min_length" in concepts

    def test_no_entities_for_unrelated_text(self):
        pp = preprocess("The weather is sunny today")
        ex = extract(pp)
        assert len(ex.entities) == 0


# =========================================================================== #
#  Mapping tests                                                               #
# =========================================================================== #


class TestMapping:
    @pytest.fixture
    def pipeline(self):
        return NLPPipeline()

    @pytest.mark.parametrize("case", CANONICAL_CASES, ids=lambda c: c.text[:50])
    def test_canonical_requirements(self, pipeline, case):
        results = pipeline.process(case.text)
        all_rule_ids = []
        for r in results:
            all_rule_ids.extend(r.rule_ids)
        for expected_id in case.expected_rule_ids:
            assert expected_id in all_rule_ids, (
                f"Expected {expected_id} for '{case.text[:50]}', "
                f"got {all_rule_ids}"
            )

    @pytest.mark.parametrize("case", PARAPHRASE_CASES, ids=lambda c: c.text[:50])
    def test_paraphrased_requirements(self, pipeline, case):
        results = pipeline.process(case.text)
        all_rule_ids = []
        for r in results:
            all_rule_ids.extend(r.rule_ids)
        for expected_id in case.expected_rule_ids:
            assert expected_id in all_rule_ids, (
                f"Expected {expected_id} for paraphrase '{case.text[:50]}', "
                f"got {all_rule_ids}"
            )

    @pytest.mark.parametrize("case", NEGATION_CASES, ids=lambda c: c.text[:50])
    def test_negation_requirements(self, pipeline, case):
        results = pipeline.process(case.text)
        assert any(r.is_negative for r in results), (
            f"Expected negative requirement for '{case.text[:50]}'"
        )
        all_rule_ids = []
        for r in results:
            all_rule_ids.extend(r.rule_ids)
        for expected_id in case.expected_rule_ids:
            assert expected_id in all_rule_ids, (
                f"Expected {expected_id} for negation '{case.text[:50]}', "
                f"got {all_rule_ids}"
            )

    @pytest.mark.parametrize("case", VENDOR_CASES, ids=lambda c: c.text[:50])
    def test_vendor_terminology(self, pipeline, case):
        results = pipeline.process(case.text)
        all_rule_ids = []
        for r in results:
            all_rule_ids.extend(r.rule_ids)
        for expected_id in case.expected_rule_ids:
            assert expected_id in all_rule_ids, (
                f"Expected {expected_id} for vendor term '{case.text[:50]}', "
                f"got {all_rule_ids}"
            )

    @pytest.mark.parametrize("case", NUMERIC_CASES, ids=lambda c: c.text[:50])
    def test_numeric_parameters(self, pipeline, case):
        results = pipeline.process(case.text)
        all_rule_ids = []
        for r in results:
            all_rule_ids.extend(r.rule_ids)
        for expected_id in case.expected_rule_ids:
            assert expected_id in all_rule_ids, (
                f"Expected {expected_id} for numeric '{case.text[:50]}', "
                f"got {all_rule_ids}"
            )
        if case.expected_params:
            result = results[0]
            for key, val in case.expected_params.items():
                assert key in result.parameters, (
                    f"Expected param {key} for '{case.text[:50]}', "
                    f"got {result.parameters}"
                )
                assert result.parameters[key] == val, (
                    f"Expected {key}={val}, got {result.parameters[key]}"
                )

    @pytest.mark.parametrize("case", SYNONYM_CASES, ids=lambda c: c.text[:50])
    def test_synonym_handling(self, pipeline, case):
        results = pipeline.process(case.text)
        all_rule_ids = []
        for r in results:
            all_rule_ids.extend(r.rule_ids)
        for expected_id in case.expected_rule_ids:
            assert expected_id in all_rule_ids, (
                f"Expected {expected_id} for synonym '{case.text[:50]}', "
                f"got {all_rule_ids}"
            )

    @pytest.mark.parametrize("case", SENTENCE_STRUCTURE_CASES, ids=lambda c: c.text[:50])
    def test_sentence_structures(self, pipeline, case):
        results = pipeline.process(case.text)
        all_rule_ids = []
        for r in results:
            all_rule_ids.extend(r.rule_ids)
        for expected_id in case.expected_rule_ids:
            assert expected_id in all_rule_ids, (
                f"Expected {expected_id} for structure '{case.text[:50]}', "
                f"got {all_rule_ids}"
            )

    def test_multi_requirement_period_split(self, pipeline):
        case = MULTI_REQUIREMENT_CASES[0]
        results = pipeline.process(case.text)
        assert len(results) == 3, f"Expected 3 sub-requirements, got {len(results)}"
        all_rule_ids = []
        for r in results:
            all_rule_ids.extend(r.rule_ids)
        for expected_id in case.expected_rule_ids:
            assert expected_id in all_rule_ids, (
                f"Expected {expected_id} in multi-req, got {all_rule_ids}"
            )

    def test_multi_requirement_and_split(self, pipeline):
        case = MULTI_REQUIREMENT_CASES[1]
        results = pipeline.process(case.text)
        assert len(results) == 2, f"Expected 2 sub-requirements, got {len(results)}"
        all_rule_ids = []
        for r in results:
            all_rule_ids.extend(r.rule_ids)
        for expected_id in case.expected_rule_ids:
            assert expected_id in all_rule_ids, (
                f"Expected {expected_id} in multi-req, got {all_rule_ids}"
            )

    @pytest.mark.parametrize("case", UNSUPPORTED_CASES, ids=lambda c: c.text[:50])
    def test_unsupported_requirements(self, pipeline, case):
        results = pipeline.process(case.text)
        for r in results:
            assert r.status == "UNKNOWN", (
                f"Expected UNKNOWN for unsupported '{case.text[:50]}', "
                f"got {r.status}"
            )
            assert r.rule_ids == [], (
                f"Expected no rule_ids for unsupported '{case.text[:50]}', "
                f"got {r.rule_ids}"
            )

    @pytest.mark.parametrize("case", MALFORMED_CASES, ids=lambda c: repr(c.text)[:30])
    def test_malformed_input(self, pipeline, case):
        results = pipeline.process(case.text)
        assert len(results) >= 1
        for r in results:
            assert r.status == "UNKNOWN"
            assert r.rule_ids == []

    def test_confidence_above_threshold(self, pipeline):
        for case in CANONICAL_CASES:
            results = pipeline.process(case.text)
            for r in results:
                if r.status == "MAPPED":
                    assert r.confidence >= 0.40, (
                        f"Mapped result should have confidence >= 0.40, "
                        f"got {r.confidence} for '{case.text[:40]}'"
                    )

    def test_source_text_preserved(self, pipeline):
        text = "Enable AAA authentication on the device"
        results = pipeline.process(text)
        assert results[0].source_text == text

    def test_preprocessed_text_populated(self, pipeline):
        results = pipeline.process("Enable AAA authentication")
        assert results[0].preprocessed_text != ""


# =========================================================================== #
#  Compliance engine integration test                                          #
# =========================================================================== #


class TestComplianceEngineIntegration:
    def test_process_and_evaluate_mapped(self):
        from auditor.parsers.cisco_ios import CiscoIOSParser

        hardened = Path(PROJECT_ROOT / "samples" / "hardened_ios.conf")
        if not hardened.exists():
            pytest.skip("hardened_ios.conf not available")

        config = hardened.read_text(encoding="utf-8")
        parser = CiscoIOSParser()
        baseline = parser.parse(config, source_file="hardened_ios.conf")

        pipeline = NLPPipeline()
        output = pipeline.process_and_evaluate("Enable AAA authentication", baseline)

        assert len(output) == 1
        entry = output[0]
        assert entry["nlp_result"].status == "MAPPED"
        assert "aaa_enabled" in entry["nlp_result"].rule_ids
        assert len(entry["compliance_results"]) > 0

    def test_process_and_evaluate_unknown(self):
        from auditor.parsers.cisco_ios import CiscoIOSParser

        hardened = Path(PROJECT_ROOT / "samples" / "hardened_ios.conf")
        if not hardened.exists():
            pytest.skip("hardened_ios.conf not available")

        config = hardened.read_text(encoding="utf-8")
        parser = CiscoIOSParser()
        baseline = parser.parse(config, source_file="hardened_ios.conf")

        pipeline = NLPPipeline()
        output = pipeline.process_and_evaluate("Configure OSPF routing", baseline)

        assert len(output) == 1
        assert output[0]["nlp_result"].status == "UNKNOWN"
        assert output[0]["compliance_results"] == []


# =========================================================================== #
#  Aggregate metrics                                                           #
# =========================================================================== #


class TestAggregateMetrics:
    """Calculate and verify aggregate NLP metrics across all ground-truth cases."""

    @pytest.fixture(scope="class")
    def pipeline(self):
        return NLPPipeline()

    @pytest.fixture(scope="class")
    def all_results(self, pipeline):
        """Run all non-multi-requirement cases through the pipeline."""
        single_cases = [
            c for c in ALL_CASES
            if c.category != "multi"
        ]
        outputs = []
        for case in single_cases:
            results = pipeline.process(case.text)
            r = results[0]
            outputs.append((case, r))
        return outputs

    def test_intent_accuracy(self, all_results):
        """Intent classification accuracy across all cases."""
        correct = 0
        total = 0
        for case, result in all_results:
            if case.expected_intent == "UNKNOWN" and case.category in ("malformed", "unsupported"):
                continue
            total += 1
            if result.intent == case.expected_intent:
                correct += 1
        accuracy = correct / total if total else 0
        assert accuracy >= 0.70, (
            f"Intent accuracy {accuracy:.1%} below 70% threshold "
            f"({correct}/{total})"
        )

    def test_rule_mapping_accuracy(self, all_results):
        """Exact-match rule mapping accuracy for single-requirement cases."""
        correct = 0
        total = 0
        for case, result in all_results:
            if not case.expected_rule_ids:
                continue
            total += 1
            if set(result.rule_ids) == set(case.expected_rule_ids):
                correct += 1
        accuracy = correct / total if total else 0
        assert accuracy >= 0.75, (
            f"Rule-mapping accuracy {accuracy:.1%} below 75% threshold "
            f"({correct}/{total})"
        )

    def test_precision_recall_f1(self, all_results):
        """Precision, recall, F1 for rule mapping (micro-averaged)."""
        tp = 0
        fp = 0
        fn = 0
        for case, result in all_results:
            expected = set(case.expected_rule_ids)
            actual = set(result.rule_ids)
            tp += len(expected & actual)
            fp += len(actual - expected)
            fn += len(expected - actual)

        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = tp / (tp + fn) if (tp + fn) else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

        assert precision >= 0.75, f"Precision {precision:.1%} below 75%"
        assert recall >= 0.75, f"Recall {recall:.1%} below 75%"
        assert f1 >= 0.75, f"F1 {f1:.1%} below 75%"

    def test_unknown_detection_accuracy(self, all_results):
        """Accuracy of detecting unsupported/malformed input as UNKNOWN."""
        correct = 0
        total = 0
        for case, result in all_results:
            if case.category in ("unsupported", "malformed"):
                total += 1
                if result.status == "UNKNOWN":
                    correct += 1
        accuracy = correct / total if total else 0
        assert accuracy >= 0.85, (
            f"Unknown detection accuracy {accuracy:.1%} below 85% "
            f"({correct}/{total})"
        )

    def test_print_metrics_summary(self, all_results, capsys):
        """Print a summary of all NLP metrics (informational, always passes)."""
        intent_correct = 0
        intent_total = 0
        mapping_correct = 0
        mapping_total = 0
        tp = fp = fn = 0
        unknown_correct = 0
        unknown_total = 0

        for case, result in all_results:
            if case.expected_intent != "UNKNOWN" or case.category not in ("malformed", "unsupported"):
                intent_total += 1
                if result.intent == case.expected_intent:
                    intent_correct += 1

            if case.expected_rule_ids:
                mapping_total += 1
                if set(result.rule_ids) == set(case.expected_rule_ids):
                    mapping_correct += 1

            expected = set(case.expected_rule_ids)
            actual = set(result.rule_ids)
            tp += len(expected & actual)
            fp += len(actual - expected)
            fn += len(expected - actual)

            if case.category in ("unsupported", "malformed"):
                unknown_total += 1
                if result.status == "UNKNOWN":
                    unknown_correct += 1

        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = tp / (tp + fn) if (tp + fn) else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0

        print("\n" + "=" * 60)
        print("NLP PIPELINE METRICS SUMMARY")
        print("=" * 60)
        print(f"Total test cases:           {len(all_results)}")
        print(f"Intent accuracy:            {intent_correct}/{intent_total} = {intent_correct/intent_total:.1%}" if intent_total else "N/A")
        print(f"Rule-mapping accuracy:      {mapping_correct}/{mapping_total} = {mapping_correct/mapping_total:.1%}" if mapping_total else "N/A")
        print(f"Precision:                  {precision:.1%}")
        print(f"Recall:                     {recall:.1%}")
        print(f"F1:                         {f1:.1%}")
        print(f"Unknown detection:          {unknown_correct}/{unknown_total} = {unknown_correct/unknown_total:.1%}" if unknown_total else "N/A")
        print("=" * 60)
