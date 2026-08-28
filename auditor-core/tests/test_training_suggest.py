"""Tests for the AI suggestion module (auditor.training.suggest).

The suggestion module is an advisory-only capability: it never affects
compliance results.  These tests verify:

1. Heuristic matching produces correct field/strategy suggestions
2. AI-assisted path uses LLM client and derives patterns
3. Graceful fallback when LLM is unavailable
4. Invalid/unknown lines return a low-confidence fallback
5. Suggestions are never injected into compliance evaluation
"""

import dataclasses
from unittest.mock import MagicMock, patch

import pytest

from auditor.training.suggest import (
    MappingSuggestion,
    suggest_mapping,
    _heuristic_suggest,
    _derive_pattern,
    _closest_field,
    _fallback_suggestion,
)
from auditor.models.baseline import SecurityBaselineModel


# ---------------------------------------------------------------------------
# Heuristic-only suggestions
# ---------------------------------------------------------------------------


class TestHeuristicSuggest:
    """Keyword matching against known configuration patterns."""

    def test_ssh_version_line(self):
        result = _heuristic_suggest("ip ssh version 2", "", "cisco")
        assert result is not None
        assert result.field == "ssh_version"
        assert result.source == "heuristic"
        assert result.confidence > 0

    def test_exec_timeout_line(self):
        result = _heuristic_suggest("exec-timeout 10 0", "", "cisco")
        assert result is not None
        assert result.field == "vty_exec_timeout_seconds"

    def test_logging_buffered_line(self):
        result = _heuristic_suggest("logging buffered 16384", "", "cisco")
        assert result is not None
        assert result.field == "logging_buffered"

    def test_ntp_server_line(self):
        result = _heuristic_suggest("ntp server 10.20.30.40", "", "cisco")
        assert result is not None
        assert result.field == "ntp_servers"

    def test_banner_line(self):
        result = _heuristic_suggest("banner login ^Unauthorized access prohibited^", "", "cisco")
        assert result is not None
        assert result.field == "login_banner_present"

    def test_snmp_community_line(self):
        result = _heuristic_suggest("snmp-server community public RO 99", "", "cisco")
        assert result is not None
        assert result.field == "snmp_communities"

    def test_password_min_length_line(self):
        result = _heuristic_suggest("password min-length 8", "", "fortinet")
        assert result is not None
        assert result.field == "password_min_length"

    def test_fortios_admintimeout(self):
        result = _heuristic_suggest("set admintimeout 5", "", "fortinet")
        assert result is not None
        assert result.field == "vty_exec_timeout_seconds"

    def test_fortios_admin_lockout(self):
        result = _heuristic_suggest("set admin-lockout-threshold 3", "", "fortinet")
        assert result is not None
        assert result.field == "admin_lockout_threshold"

    def test_unknown_line_returns_none(self):
        result = _heuristic_suggest("set some-custom-setting foo", "", "fortinet")
        assert result is None

    def test_empty_line_returns_none(self):
        result = _heuristic_suggest("", "", "cisco")
        assert result is None

    def test_suggested_field_is_valid_observable(self):
        valid_fields = set(SecurityBaselineModel.observable_fields())
        for line in [
            "ip ssh version 2",
            "exec-timeout 10 0",
            "ntp server 10.20.30.40",
            "logging buffered 16384",
            "service password-encryption",
            "aaa new-model",
        ]:
            result = _heuristic_suggest(line, "", "cisco")
            if result is not None:
                assert result.field in valid_fields, f"Field '{result.field}' not in valid observable fields"


# ---------------------------------------------------------------------------
# Pattern derivation
# ---------------------------------------------------------------------------


class TestDerivePattern:
    """Extraction strategy selection based on line structure and field type."""

    def test_bool_field_exact(self):
        pattern, strategy, regex = _derive_pattern("service password-encryption", "password_encryption")
        assert strategy == "exact"
        assert pattern

    def test_int_field_token(self):
        pattern, strategy, regex = _derive_pattern("exec-timeout 10 0", "vty_exec_timeout_seconds")
        assert strategy in ("exact", "token")

    def test_list_field_token_list(self):
        pattern, strategy, regex = _derive_pattern("ntp server 10.20.30.40", "ntp_servers")
        assert strategy == "token_list"

    def test_string_field_token(self):
        pattern, strategy, regex = _derive_pattern("hostname CORE-RTR-01", "hostname")
        assert strategy == "token"
        assert pattern == "hostname"


# ---------------------------------------------------------------------------
# AI-assisted path
# ---------------------------------------------------------------------------


class TestAISuggest:
    """LLM client integration for mapping suggestions."""

    def test_ai_suggest_with_mock_client(self):
        mock_client = MagicMock()
        mock_client.propose_mapping.return_value = {
            "field": "ssh_enabled",
            "value": "true",
            "compliance_relevance": "SSH access control",
            "reasoning": "This line enables SSH on the device.",
        }

        result = suggest_mapping("ip ssh version 2", vendor="cisco", client=mock_client)
        assert result.source == "ai"
        assert result.field == "ssh_enabled"
        assert result.confidence == 0.75
        assert result.reasoning == "This line enables SSH on the device."
        mock_client.propose_mapping.assert_called_once()

    def test_ai_suggest_with_invalid_field_falls_back_to_closest(self):
        mock_client = MagicMock()
        mock_client.propose_mapping.return_value = {
            "field": "ssh",
            "value": "true",
            "compliance_relevance": "SSH",
            "reasoning": "SSH line.",
        }

        result = suggest_mapping("ip ssh version 2", vendor="cisco", client=mock_client)
        assert result.field == "ssh_enabled"
        assert result.source == "ai"

    def test_ai_suggest_with_completely_wrong_field_falls_to_heuristic(self):
        mock_client = MagicMock()
        mock_client.propose_mapping.return_value = {
            "field": "nonexistent_field_xyz_123",
            "value": "foo",
            "compliance_relevance": "Unknown",
            "reasoning": "Bad guess.",
        }

        result = suggest_mapping("ip ssh version 2", vendor="cisco", client=mock_client)
        assert result.source == "heuristic"
        assert result.field == "ssh_version"

    def test_ai_suggest_llm_unavailable_falls_to_heuristic(self):
        from auditor.parsers.llm.client import LLMUnavailableError

        mock_client = MagicMock()
        mock_client.propose_mapping.side_effect = LLMUnavailableError("No API key")

        result = suggest_mapping("ip ssh version 2", vendor="cisco", client=mock_client)
        assert result.source == "heuristic"
        assert result.field == "ssh_version"

    def test_ai_suggest_llm_response_error_falls_to_heuristic(self):
        from auditor.parsers.llm.client import LLMResponseError

        mock_client = MagicMock()
        mock_client.propose_mapping.side_effect = LLMResponseError("Bad response")

        result = suggest_mapping("exec-timeout 10 0", vendor="cisco", client=mock_client)
        assert result.source == "heuristic"
        assert result.field == "vty_exec_timeout_seconds"

    def test_ai_suggest_generic_exception_falls_to_heuristic(self):
        mock_client = MagicMock()
        mock_client.propose_mapping.side_effect = RuntimeError("Unexpected error")

        result = suggest_mapping("logging buffered 16384", vendor="cisco", client=mock_client)
        assert result.source == "heuristic"
        assert result.field == "logging_buffered"

    def test_ai_suggest_includes_heuristic_alternative(self):
        mock_client = MagicMock()
        mock_client.propose_mapping.return_value = {
            "field": "ssh_enabled",
            "value": "2",
            "compliance_relevance": "SSH protocol",
            "reasoning": "SSH config.",
        }

        result = suggest_mapping("ip ssh version 2", vendor="cisco", client=mock_client)
        assert result.source == "ai"
        assert result.field == "ssh_enabled"
        assert len(result.alternatives) == 1
        assert result.alternatives[0]["field"] == "ssh_version"


# ---------------------------------------------------------------------------
# Fallback (no match at all)
# ---------------------------------------------------------------------------


class TestFallbackSuggestion:
    """When nothing matches, return a minimal placeholder."""

    def test_fallback_unknown_line(self):
        result = suggest_mapping("some-proprietary-command foo bar")
        assert result.field == ""
        assert result.confidence == 0.0
        assert result.source == "none"
        assert result.pattern

    def test_fallback_empty_string(self):
        result = suggest_mapping("")
        assert result.confidence == 0.0
        assert result.source == "none"


# ---------------------------------------------------------------------------
# Integration: suggest_mapping public API
# ---------------------------------------------------------------------------


class TestSuggestMappingAPI:
    """Top-level suggest_mapping function."""

    def test_no_client_uses_heuristic(self):
        result = suggest_mapping("ntp server 10.0.0.1")
        assert result.source == "heuristic"
        assert result.field == "ntp_servers"

    def test_client_none_uses_heuristic(self):
        result = suggest_mapping("service password-encryption", client=None)
        assert result.source == "heuristic"
        assert result.field == "password_encryption"

    def test_returns_mapping_suggestion_type(self):
        result = suggest_mapping("exec-timeout 5 0", vendor="cisco")
        assert isinstance(result, MappingSuggestion)

    def test_all_fields_populated(self):
        result = suggest_mapping("ip ssh version 2", vendor="cisco")
        assert result.field
        assert result.pattern
        assert result.extraction_strategy in ("exact", "token", "token_list", "regex")
        assert 0 <= result.confidence <= 1
        assert result.reasoning
        assert result.source in ("ai", "heuristic", "none")


# ---------------------------------------------------------------------------
# Closest field matching
# ---------------------------------------------------------------------------


class TestClosestField:
    """Fuzzy matching of LLM-suggested field names to valid baseline fields."""

    def test_exact_match_after_normalization(self):
        valid = set(SecurityBaselineModel.observable_fields())
        assert _closest_field("ssh-enabled", valid) == "ssh_enabled"

    def test_substring_match(self):
        valid = set(SecurityBaselineModel.observable_fields())
        assert _closest_field("ssh", valid) == "ssh_enabled"

    def test_no_match(self):
        valid = set(SecurityBaselineModel.observable_fields())
        assert _closest_field("nonexistent_field_xyz_123", valid) is None


# ---------------------------------------------------------------------------
# Safety: suggestions never affect compliance
# ---------------------------------------------------------------------------


class TestSuggestionSafety:
    """Verify that suggestions are advisory only and never touch the engine."""

    def test_suggestion_does_not_create_learned_mapping(self):
        result = suggest_mapping("ip ssh version 2", vendor="cisco")
        assert not hasattr(result, "mapping_id")
        assert not hasattr(result, "approval_state")
        assert not hasattr(result, "status")

    def test_suggestion_dataclass_is_not_learned_mapping(self):
        from auditor.training.mappings import LearnedMapping
        result = suggest_mapping("ip ssh version 2", vendor="cisco")
        assert not isinstance(result, LearnedMapping)

    def test_multiple_suggestions_are_independent(self):
        r1 = suggest_mapping("ip ssh version 2", vendor="cisco")
        r2 = suggest_mapping("exec-timeout 10 0", vendor="cisco")
        assert r1.field != r2.field
        assert r1 is not r2
