"""A stub LLM client, shared by every test that needs a model's answers.

The parser's real work — grounding, gating, mapping onto the baseline — is
deterministic once the model's claims are fixed, so fixing them here buys full
coverage of that work with no API key, no network, and no cost. Every test that
exercises model-derived findings states the claims it wants and asserts what the
pipeline did with them.
"""

from typing import Optional

from auditor.parsers.llm import (
    BooleanFinding,
    IntegerFinding,
    LLMClient,
    LLMExtraction,
    SnmpCommunityFinding,
    TextFinding,
    TextListFinding,
)

#: The finding type each baseline field is claimed with.
KINDS = {
    "hostname": TextFinding,
    "telnet_enabled": BooleanFinding,
    "vty_transport_input": TextListFinding,
    "vty_exec_timeout_seconds": IntegerFinding,
    "ssh_enabled": BooleanFinding,
    "ssh_version": IntegerFinding,
    "http_server_enabled": BooleanFinding,
    "https_server_enabled": BooleanFinding,
    "management_acl_applied": BooleanFinding,
    "login_banner_present": BooleanFinding,
    "enable_secret_set": BooleanFinding,
    "enable_password_present": BooleanFinding,
    "password_encryption": BooleanFinding,
    "password_min_length": IntegerFinding,
    "aaa_enabled": BooleanFinding,
    "snmp_communities": SnmpCommunityFinding,
    "logging_enabled": BooleanFinding,
    "logging_hosts": TextListFinding,
    "logging_buffered": BooleanFinding,
    "ntp_servers": TextListFinding,
}


def found(value, source_line, confidence=0.95, reasoning="explicit statement"):
    return {
        "determined": True,
        "value": value,
        "source_line": source_line,
        "confidence": confidence,
        "reasoning": reasoning,
    }


def undetermined(reasoning="not mentioned in the configuration"):
    return {
        "determined": False,
        "value": None,
        "source_line": None,
        "confidence": 0.0,
        "reasoning": reasoning,
    }


def make_extraction(vendor="juniper", os_family="junos", **overrides) -> LLMExtraction:
    """Build a complete extraction; unspecified fields come back undetermined."""
    payload = {
        "vendor": vendor,
        "os_family": os_family,
        "identification_confidence": 0.97,
    }
    for field, kind in KINDS.items():
        payload[field] = kind.model_validate(overrides.get(field, undetermined()))
    return LLMExtraction.model_validate(payload)


class StubClient(LLMClient):
    """Returns a fixed extraction, and records that it was asked at all.

    ``calls`` is what proves the hybrid parser skipped the model when the
    deterministic pass had already settled everything — the saving is the point
    of running deterministically first, so it is asserted, not assumed.
    """

    def __init__(self, extraction=None, error=None):
        self.extraction = extraction if extraction is not None else make_extraction()
        self.error = error
        self.seen_config: Optional[str] = None
        self.calls = 0

    def extract(self, config_text: str) -> LLMExtraction:
        self.calls += 1
        self.seen_config = config_text
        if self.error:
            raise self.error
        return self.extraction
