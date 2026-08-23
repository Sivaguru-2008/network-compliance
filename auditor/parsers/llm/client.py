"""The LLM transport, behind an interface the parser can be tested without.

``LLMClient`` is the seam: ``LLMParser`` depends on this abstraction, so the
whole parser — grounding, mapping, confidence gating — is exercised in tests by
a stub client with no API key, no network, and no cost. ``AnthropicClient`` is
the production implementation; swapping in a different provider means writing
one more subclass, not touching the parser.

The ``anthropic`` SDK is imported lazily inside the constructor so the
deterministic core keeps working — and the test suite keeps running — on a
machine that has never installed it.
"""

from abc import ABC, abstractmethod
from typing import Any, Optional

from .prompt import build_system_prompt, build_user_message
from .schema import LLMExtraction

DEFAULT_MODEL = "claude-opus-5"
DEFAULT_MAX_TOKENS = 16000
DEFAULT_MAX_RETRIES = 3


class LLMUnavailableError(Exception):
    """The LLM backend cannot be reached: SDK missing, no credentials, or network failure."""


class LLMResponseError(Exception):
    """The LLM was reached but did not return a usable extraction."""


class LLMClient(ABC):
    """Turns configuration text into a structured extraction."""

    @abstractmethod
    def extract(self, config_text: str) -> LLMExtraction:
        """Return the model's claims about ``config_text``.

        Implementations raise ``LLMUnavailableError`` for transport problems and
        ``LLMResponseError`` when a response arrives but cannot be used.
        """

    @abstractmethod
    def propose_mapping(self, vendor: str, os_family: str, line: str) -> dict:
        """Propose a mapping for a raw config line."""

    @property
    def description(self) -> str:
        """Short identifier recorded in the report's provenance."""
        return type(self).__name__


class AnthropicClient(LLMClient):
    """Claude-backed extraction using schema-constrained structured output.

    The response is constrained to ``LLMExtraction`` by the SDK's ``parse``
    helper, so malformed or partial JSON never reaches the parser — a response
    either validates against the schema or raises.
    """

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
        # Worked examples fitted by the training loop, appended to the system
        # prompt. Stable within a run, so the cached prefix still holds.
        self.system_prompt = build_system_prompt(system_suffix)
        self._anthropic = _import_anthropic()
        if client is not None:
            self._client = client
            return
        try:
            kwargs = {"max_retries": max_retries}
            if api_key:
                kwargs["api_key"] = api_key
            # Credentials resolve from ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN,
            # or an `ant auth login` profile - the SDK handles the precedence.
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
                        # Stable prefix: the same instructions on every config,
                        # so repeated audits read the system prompt from cache.
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
            raise LLMUnavailableError(
                f"Rate limited after retries: {exc}. Retry later or lower concurrency."
            ) from exc
        except anthropic.APIConnectionError as exc:
            raise LLMUnavailableError(f"Could not reach the Anthropic API: {exc}") from exc
        except anthropic.APIStatusError as exc:
            raise LLMUnavailableError(f"API error {exc.status_code}: {exc}") from exc
        except TypeError as exc:
            # The SDK resolves credentials lazily, at request time rather than at
            # construction, and reports a missing credential source as TypeError.
            # Only translate that specific case - anything else is a real bug.
            if "authentication" not in str(exc).lower():
                raise
            raise LLMUnavailableError(
                "No Anthropic credentials found. Set ANTHROPIC_API_KEY, or run `ant auth login`, "
                "or pass a client with credentials already configured."
            ) from exc

        if getattr(response, "stop_reason", None) == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None)
            raise LLMResponseError(
                f"The model declined to process this configuration (category: {category}). "
                "Audit it with a deterministic parser, or review it manually."
            )

        extraction = getattr(response, "parsed_output", None)
        if extraction is None:
            raise LLMResponseError(
                f"No structured output returned (stop_reason: {getattr(response, 'stop_reason', 'unknown')}). "
                "If this is 'max_tokens', raise max_tokens for this client."
            )
        return extraction

    def propose_mapping(self, vendor: str, os_family: str, line: str) -> dict:
        _ = _import_anthropic()
        from ...models.baseline import SecurityBaselineModel
        selectable_fields = ", ".join(SecurityBaselineModel.observable_fields())
        prompt = (
            f"You are a network security compliance expert.\n"
            f"The deterministic parser encountered an unknown configuration structure for vendor '{vendor}' and OS '{os_family}'.\n"
            f"Please analyze this raw configuration line and map it to one of the existing baseline fields.\n"
            f"Raw configuration line: {line}\n\n"
            f"Selectable baseline fields: {selectable_fields}\n\n"
            f"Provide the suggested normalized field name, the extracted value (as a string), the compliance category relevance, and the reasoning."
        )
        try:
            response = self._client.messages.parse(
                model=self.model,
                max_tokens=2000,
                system="You propose semantic mappings for raw network configurations to normalized security baseline fields.",
                messages=[{"role": "user", "content": prompt}],
                output_format=AIPendingProposal,
            )
            proposal = response.parsed_output
            if proposal is None:
                raise LLMResponseError("No structured output returned for the proposal.")
            return proposal.model_dump()
        except Exception as exc:
            raise LLMResponseError(f"Failed to propose mapping: {exc}") from exc


from pydantic import BaseModel, Field

class AIPendingProposal(BaseModel):
    field: str = Field(description="The suggested normalized baseline field name from the existing schema.")
    value: str = Field(description="The suggested value extracted from the line.")
    compliance_relevance: str = Field(description="Suggested compliance relevance category.")
    reasoning: str = Field(description="Explanation for the suggested mapping.")


def _import_anthropic():
    try:
        import anthropic  # noqa: PLC0415 - deliberately lazy; keeps the core dependency-free
    except ImportError as exc:
        raise LLMUnavailableError(
            "The 'anthropic' package is required for the LLM parser. Install it with "
            "`pip install anthropic`, or audit this device with a deterministic parser."
        ) from exc
    return anthropic
