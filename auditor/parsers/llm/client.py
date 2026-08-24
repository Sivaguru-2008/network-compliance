"""The LLM/AI provider transport and secrets redactor.

Supports local redaction of sensitive credentials, and defines abstractions
for local/mock/Gemini/OpenAI/Anthropic providers using standard libraries.
"""

from abc import ABC, abstractmethod
import json
import re
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from .prompt import build_system_prompt, build_user_message
from .schema import LLMExtraction, BooleanFinding, IntegerFinding, TextFinding, TextListFinding, SnmpCommunityFinding, SnmpCommunityClaim

DEFAULT_MODEL = "claude-opus-5"
DEFAULT_MAX_TOKENS = 16000
DEFAULT_MAX_RETRIES = 3


# ---------------------------------------------------------------------------
# Secrets Redactor
# ---------------------------------------------------------------------------

def redact_secrets(config_text: str) -> str:
    """Scan and redact passwords, SNMP communities, and private keys locally."""
    if not config_text:
        return config_text

    redacted = config_text

    # 1. Private keys / certificates
    redacted = re.sub(
        r"-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----",
        "-----BEGIN REDACTED PRIVATE KEY-----\n<REDACTED>\n-----END REDACTED PRIVATE KEY-----",
        redacted
    )

    # 2. IOS/Arista passwords and secrets
    # e.g., enable secret 9 $9$..., enable password 7 ..., username admin secret 9 $9$...
    redacted = re.sub(
        r"(?im)(\b(?:enable|username \S+)\s+(?:secret|password)\s+\d+\s+)\S+",
        r"\1<REDACTED>",
        redacted
    )
    redacted = re.sub(
        r"(?im)(\b(?:enable|username \S+)\s+(?:secret|password)\s+)\S+",
        r"\1<REDACTED>",
        redacted
    )

    # 3. SNMP Community Strings
    # e.g., snmp-server community public RO 99
    redacted = re.sub(
        r"(?im)(\bsnmp-server\s+community\s+)\S+",
        r"\1<REDACTED>",
        redacted
    )

    # 4. FortiOS passwords / secrets
    # e.g., set passwd ENC ..., set password ENC ...
    redacted = re.sub(
        r"(?im)(\bset\s+(?:passwd|password|private-key)\s+)\S+",
        r"\1<REDACTED>",
        redacted
    )

    # 5. Junos passwords/secrets
    # e.g., encrypted-password "$9$...";
    redacted = re.sub(
        r"(?im)(\b(?:encrypted-password|plain-text-password)\s+)\"[^\"]+\"",
        r'\1"<REDACTED>"',
        redacted
    )
    # e.g., community public { ... }
    redacted = re.sub(
        r"(?im)(\bcommunity\s+)\S+(\s*\{)",
        r"\1<REDACTED>\2",
        redacted
    )

    # 6. JSON / SONiC passwords
    # e.g., "password": "...", "community": "..."
    redacted = re.sub(
        r'(?i)("password"\s*:\s*)"[^"]+"',
        r'\1"<REDACTED>"',
        redacted
    )
    redacted = re.sub(
        r'(?i)("community"\s*:\s*)"[^"]+"',
        r'\1"<REDACTED>"',
        redacted
    )

    return redacted


# ---------------------------------------------------------------------------
# AI Abstractions & Classes
# ---------------------------------------------------------------------------

class LLMUnavailableError(Exception):
    """The LLM backend cannot be reached: SDK missing, no credentials, or network failure."""


class LLMResponseError(Exception):
    """The LLM was reached but did not return a usable extraction."""


class LLMClient(ABC):
    """Turns configuration text into a structured extraction."""

    @abstractmethod
    def extract(self, config_text: str) -> LLMExtraction:
        """Return the model's claims about ``config_text``."""

    @abstractmethod
    def propose_mapping(self, vendor: str, os_family: str, line: str) -> dict:
        """Propose a mapping for a raw config line."""

    @property
    def description(self) -> str:
        return type(self).__name__


class AIProvider(LLMClient):
    """Base class for all Antigravity AI Providers."""


# ---------------------------------------------------------------------------
# Mock & Local Providers
# ---------------------------------------------------------------------------

class MockProvider(AIProvider):
    """Offline, deterministic mockup for testing and fallback scenarios."""

    def __init__(self, vendor: str = "juniper", os_family: str = "junos") -> None:
        self.vendor = vendor
        self.os_family = os_family

    @property
    def description(self) -> str:
        return "mock:local-simulation"

    def extract(self, config_text: str) -> LLMExtraction:
        # Build simple mock rules to simulate basic intelligence
        is_ios = "hostname" in config_text and ("line vty" in config_text or "enable secret" in config_text)
        is_junos = "system" in config_text or "host-name" in config_text
        is_fortios = "config system global" in config_text or "allowaccess" in config_text
        is_sonic = "DEVICE_METADATA" in config_text

        vendor = "cisco" if is_ios else ("juniper" if is_junos else ("fortinet" if is_fortios else ("sonic" if is_sonic else self.vendor)))
        os_family = "ios" if is_ios else ("junos" if is_junos else ("fortios" if is_fortios else ("linux" if is_sonic else self.os_family)))

        # Find a hostname in text if possible
        hostname_match = re.search(r"(?im)^\s*hostname\s+(\S+)", config_text) or re.search(r"(?im)^\s*host-name\s+(\S+);", config_text)
        hostname_val = hostname_match.group(1) if hostname_match else "MOCK-SWITCH"

        def make_finding(val, line=None, determined=True):
            return {
                "determined": determined,
                "value": val,
                "source_line": line,
                "confidence": 0.95 if determined else 0.0,
                "reasoning": "Mock rule match" if determined else "Not configured",
            }

        payload = {
            "vendor": vendor,
            "os_family": os_family,
            "identification_confidence": 0.98,
            "hostname": TextFinding.model_validate(make_finding(hostname_val, f"hostname {hostname_val}")),
            "telnet_enabled": BooleanFinding.model_validate(make_finding(False, None, False)),
            "vty_transport_input": TextListFinding.model_validate(make_finding(["ssh"], "transport input ssh")),
            "vty_exec_timeout_seconds": IntegerFinding.model_validate(make_finding(600, "exec-timeout 10 0")),
            "ssh_enabled": BooleanFinding.model_validate(make_finding(True, "ip ssh version 2")),
            "ssh_version": IntegerFinding.model_validate(make_finding(2, "ip ssh version 2")),
            "http_server_enabled": BooleanFinding.model_validate(make_finding(False, "no ip http server")),
            "https_server_enabled": BooleanFinding.model_validate(make_finding(True, "ip http secure-server")),
            "management_acl_applied": BooleanFinding.model_validate(make_finding(True, "access-class 99 in")),
            "login_banner_present": BooleanFinding.model_validate(make_finding(True, "banner login")),
            "enable_secret_set": BooleanFinding.model_validate(make_finding(True, "enable secret")),
            "enable_password_present": BooleanFinding.model_validate(make_finding(False, None, False)),
            "password_encryption": BooleanFinding.model_validate(make_finding(True, "service password-encryption")),
            "password_min_length": IntegerFinding.model_validate(make_finding(8, "security passwords min-length 8")),
            "aaa_enabled": BooleanFinding.model_validate(make_finding(True, "aaa new-model")),
            "snmp_communities": SnmpCommunityFinding.model_validate({
                "determined": True,
                "value": [
                    {
                        "name": "public",
                        "access": "ro",
                        "acl": "99",
                        "view": None,
                        "source_line": "snmp-server community public RO 99"
                    }
                ],
                "source_line": "snmp-server community public RO 99",
                "confidence": 0.95,
                "reasoning": "Mock SNMP community"
            }),
            "logging_enabled": BooleanFinding.model_validate(make_finding(True, "logging host")),
            "logging_hosts": TextListFinding.model_validate(make_finding(["10.20.30.40"], "logging host 10.20.30.40")),
            "logging_buffered": BooleanFinding.model_validate(make_finding(True, "logging buffered")),
            "ntp_servers": TextListFinding.model_validate(make_finding(["10.20.30.41"], "ntp server 10.20.30.41"))
        }
        return LLMExtraction.model_validate(payload)

    def propose_mapping(self, vendor: str, os_family: str, line: str) -> dict:
        return {
            "field": "vty_exec_timeout_seconds",
            "value": "600",
            "compliance_relevance": "Management Plane Access Control",
            "reasoning": f"Local mock mapping for line: {line}"
        }


class LocalProvider(MockProvider):
    """Alias for MockProvider to support local/offline execution."""
    @property
    def description(self) -> str:
        return "local:offline-rules"


# ---------------------------------------------------------------------------
# OpenAI Provider
# ---------------------------------------------------------------------------

class OpenAIProvider(AIProvider):
    """Direct OpenAI API caller using standard urllib."""

    def __init__(self, api_key: str = "", model: str = "gpt-4o") -> None:
        self.api_key = api_key
        self.model = model

    @property
    def description(self) -> str:
        return f"openai:{self.model}"

    def extract(self, config_text: str) -> LLMExtraction:
        if not self.api_key:
            raise LLMUnavailableError("OpenAI API Key not set.")

        system_prompt = build_system_prompt("")
        user_message = build_user_message(config_text)

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            "response_format": {"type": "json_object"}
        }

        try:
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=45) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                choice = res_data["choices"][0]["message"]["content"]
                return LLMExtraction.model_validate_json(choice)
        except urllib.error.HTTPError as exc:
            raise LLMUnavailableError(f"OpenAI API Error: {exc.code} - {exc.read().decode('utf-8')}") from exc
        except Exception as exc:
            raise LLMResponseError(f"OpenAI parsing failed: {exc}") from exc

    def propose_mapping(self, vendor: str, os_family: str, line: str) -> dict:
        if not self.api_key:
            raise LLMUnavailableError("OpenAI API Key not set.")
        # Minimal proxy to get structured JSON
        from ...models.baseline import SecurityBaselineModel
        selectable_fields = ", ".join(SecurityBaselineModel.observable_fields())
        prompt = (
            f"Please map this configuration line to a baseline field: '{line}' for vendor '{vendor}'\n"
            f"Fields: {selectable_fields}\n"
            f"Respond with JSON format: {{\"field\": \"...\", \"value\": \"...\", \"compliance_relevance\": \"...\", \"reasoning\": \"...\"}}"
        )
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"}
        }
        try:
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=20) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                choice = res_data["choices"][0]["message"]["content"]
                return json.loads(choice)
        except Exception as exc:
            raise LLMResponseError(f"OpenAI propose mapping failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Gemini Provider
# ---------------------------------------------------------------------------

class GeminiProvider(AIProvider):
    """Direct Google Gemini API caller using standard urllib."""

    def __init__(self, api_key: str = "", model: str = "gemini-1.5-flash") -> None:
        self.api_key = api_key
        self.model = model

    @property
    def description(self) -> str:
        return f"gemini:{self.model}"

    def extract(self, config_text: str) -> LLMExtraction:
        if not self.api_key:
            raise LLMUnavailableError("Gemini API Key not set.")

        system_prompt = build_system_prompt("")
        user_message = build_user_message(config_text)

        # Build payload using Gemini v1beta chat/generate content API
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        
        payload = {
            "contents": [{
                "parts": [{
                    "text": f"{system_prompt}\n\nUser Configuration:\n{user_message}"
                }]
            }],
            "generationConfig": {
                "responseMimeType": "application/json"
            }
        }

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=45) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                text_content = res_data["candidates"][0]["content"]["parts"][0]["text"]
                return LLMExtraction.model_validate_json(text_content)
        except urllib.error.HTTPError as exc:
            raise LLMUnavailableError(f"Gemini API Error: {exc.code} - {exc.read().decode('utf-8')}") from exc
        except Exception as exc:
            raise LLMResponseError(f"Gemini parsing failed: {exc}") from exc

    def propose_mapping(self, vendor: str, os_family: str, line: str) -> dict:
        if not self.api_key:
            raise LLMUnavailableError("Gemini API Key not set.")
        from ...models.baseline import SecurityBaselineModel
        selectable_fields = ", ".join(SecurityBaselineModel.observable_fields())
        prompt = (
            f"Please map this configuration line to a baseline field: '{line}' for vendor '{vendor}'\n"
            f"Fields: {selectable_fields}\n"
            f"Respond with JSON format: {{\"field\": \"...\", \"value\": \"...\", \"compliance_relevance\": \"...\", \"reasoning\": \"...\"}}"
        )
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json"}
        }
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=20) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                text_content = res_data["candidates"][0]["content"]["parts"][0]["text"]
                return json.loads(text_content)
        except Exception as exc:
            raise LLMResponseError(f"Gemini propose mapping failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Anthropic Client (Backward-compatible wrapper)
# ---------------------------------------------------------------------------

class AnthropicClient(AIProvider):
    """Claude-backed extraction using the Anthropic Python SDK."""

    def __init__(
        self,
        *,
        model: str = DEFAULT_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        api_key: Optional[str] = None,
        client: Any = None,
        system_suffix: str = "",
    ) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self.system_prompt = build_system_prompt(system_suffix)
        self._anthropic = _import_anthropic()
        if client is not None:
            self._client = client
            return
        try:
            kwargs = {"max_retries": max_retries}
            if api_key:
                kwargs["api_key"] = api_key
            self._client = self._anthropic.Anthropic(**kwargs)
        except Exception as exc:
            raise LLMUnavailableError(
                f"Could not construct an Anthropic client: {exc}. Set ANTHROPIC_API_KEY "
                "or run `ant auth login`."
            ) from exc

    @property
    def description(self) -> str:
        return f"anthropic:{self.model}"

    def extract(self, config_text: str) -> LLMExtraction:
        anthropic = self._anthropic
        try:
            response = self._client.messages.parse(
                model=self.model,
                max_tokens=self.max_tokens,
                thinking={"type": "adaptive"},
                system=[
                    {
                        "type": "text",
                        "text": self.system_prompt,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
                messages=[{"role": "user", "content": build_user_message(config_text)}],
                output_format=LLMExtraction,
            )
        except anthropic.AuthenticationError as exc:
            raise LLMUnavailableError(f"Authentication failed: {exc}") from exc
        except anthropic.PermissionDeniedError as exc:
            raise LLMUnavailableError(f"Credentials lack access to {self.model}: {exc}") from exc
        except anthropic.NotFoundError as exc:
            raise LLMUnavailableError(f"Model {self.model!r} is not available: {exc}") from exc
        except anthropic.RateLimitError as exc:
            raise LLMUnavailableError(f"Rate limited: {exc}") from exc
        except anthropic.APIConnectionError as exc:
            raise LLMUnavailableError(f"Could not reach Anthropic: {exc}") from exc
        except anthropic.APIStatusError as exc:
            raise LLMUnavailableError(f"API error {exc.status_code}: {exc}") from exc
        except TypeError as exc:
            if "authentication" not in str(exc).lower():
                raise
            raise LLMUnavailableError("No Anthropic credentials found.") from exc

        if getattr(response, "stop_reason", None) == "refusal":
            raise LLMResponseError("Model declined to process configuration.")

        extraction = getattr(response, "parsed_output", None)
        if extraction is None:
            raise LLMResponseError("No structured output returned.")
        return extraction

    def propose_mapping(self, vendor: str, os_family: str, line: str) -> dict:
        from pydantic import BaseModel
        class AIPendingProposal(BaseModel):
            field: str
            value: str
            compliance_relevance: str
            reasoning: str

        from ...models.baseline import SecurityBaselineModel
        selectable_fields = ", ".join(SecurityBaselineModel.observable_fields())
        prompt = (
            f"Map raw config line '{line}' for vendor '{vendor}', OS '{os_family}'.\n"
            f"Baseline fields: {selectable_fields}"
        )
        try:
            response = self._client.messages.parse(
                model=self.model,
                max_tokens=2000,
                system="You propose semantic mappings.",
                messages=[{"role": "user", "content": prompt}],
                output_format=AIPendingProposal,
            )
            proposal = response.parsed_output
            if proposal is None:
                raise LLMResponseError("No structured output returned for proposal.")
            return proposal.model_dump()
        except Exception as exc:
            raise LLMResponseError(f"Anthropic proposal failed: {exc}") from exc


def _import_anthropic():
    try:
        import anthropic
    except ImportError as exc:
        raise LLMUnavailableError(
            "The 'anthropic' package is required for the LLM parser."
        ) from exc
    return anthropic
