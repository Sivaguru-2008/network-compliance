"""The Security Baseline Model: one vendor-neutral view of a device.

This is the contract between parsing and evaluation.  Parsers (deterministic
today, LLM-backed later) produce it; the rule engine consumes it and never
looks at raw config text.  Adding a vendor must never require changing rules,
and adding a rule must never require changing parsers -- if a rule needs a
setting nobody normalizes yet, the field is added *here* first.

Field naming is deliberately vendor-neutral: ``vty_exec_timeout_seconds``, not
``line_vty_exec_timeout``; ``management_plaintext_protocols``, not ``telnet``.
"""

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .observation import Observation


def _unknown(kind):
    """Default factory: a field nobody has looked at yet is *unknown*, not secure."""
    return lambda: Observation[kind].unknown("Parser did not evaluate this field.")


class SnmpCommunity(BaseModel):
    """One SNMP v1/v2c community string as configured on the device."""

    model_config = ConfigDict(frozen=True)

    name: str
    access: Optional[str] = Field(default=None, description="ro | rw | None if unspecified")
    acl: Optional[str] = Field(default=None, description="ACL name/number restricting this community, if any")
    view: Optional[str] = None
    source_line: str
    line_number: Optional[int] = None


class ParserProvenance(BaseModel):
    """How this baseline was produced -- audit trail for the model itself."""

    parser_name: str
    parser_version: str
    vendor: str
    os_family: str
    detection_confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    warnings: List[str] = Field(default_factory=list)


class SecurityBaselineModel(BaseModel):
    """Vendor-neutral, evidence-carrying representation of a device's posture."""

    model_config = ConfigDict(frozen=False)

    # -- provenance / target identity -------------------------------------
    provenance: ParserProvenance
    source_file: Optional[str] = None
    source_sha256: Optional[str] = None
    config_line_count: int = 0
    hostname: Observation[str] = Field(default_factory=_unknown(str))

    # -- management access ------------------------------------------------
    telnet_enabled: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="True if any remote-admin line accepts a plaintext transport.",
    )
    vty_transport_input: Observation[List[str]] = Field(
        default_factory=_unknown(List[str]),
        description="Union of inbound transports permitted across all VTY lines.",
    )
    vty_exec_timeout_seconds: Observation[int] = Field(
        default_factory=_unknown(int),
        description="Worst-case (longest) idle timeout across VTY lines; 0 means never.",
    )
    ssh_enabled: Observation[bool] = Field(default_factory=_unknown(bool))
    ssh_version: Observation[int] = Field(
        default_factory=_unknown(int), description="Enforced SSH protocol version (1 or 2)."
    )
    http_server_enabled: Observation[bool] = Field(default_factory=_unknown(bool))
    https_server_enabled: Observation[bool] = Field(default_factory=_unknown(bool))
    management_acl_applied: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description=(
            "Remote administrative access is restricted to specific source addresses. "
            "Worst-case across management paths: false if any path is unrestricted."
        ),
    )
    login_banner_present: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="A banner is presented before or at login (legal notice / warning).",
    )

    # -- credentials ------------------------------------------------------
    enable_secret_set: Observation[bool] = Field(
        default_factory=_unknown(bool), description="A cryptographically hashed privileged-exec secret exists."
    )
    enable_password_present: Observation[bool] = Field(
        default_factory=_unknown(bool), description="A legacy reversible enable password exists."
    )
    password_encryption: Observation[bool] = Field(
        default_factory=_unknown(bool), description="Stored passwords are obfuscated at rest (service password-encryption)."
    )
    password_min_length: Observation[int] = Field(
        default_factory=_unknown(int),
        description="Minimum length the device enforces on locally set passwords; 0 means unenforced.",
    )

    # -- authentication, authorization, accounting ------------------------
    aaa_enabled: Observation[bool] = Field(default_factory=_unknown(bool))

    # -- monitoring -------------------------------------------------------
    snmp_communities: Observation[List[SnmpCommunity]] = Field(default_factory=_unknown(List[SnmpCommunity]))
    logging_enabled: Observation[bool] = Field(
        default_factory=_unknown(bool), description="At least one log destination (syslog host or local buffer) is configured."
    )
    logging_hosts: Observation[List[str]] = Field(default_factory=_unknown(List[str]))
    logging_buffered: Observation[bool] = Field(default_factory=_unknown(bool))
    ntp_servers: Observation[List[str]] = Field(
        default_factory=_unknown(List[str]),
        description="Configured NTP time sources. Log timestamps are only evidence if the clock is.",
    )

    # -- introspection used by the engine ---------------------------------

    @classmethod
    def observable_fields(cls) -> List[str]:
        """Names of every ``Observation``-typed field -- the rule engine's vocabulary."""
        names = []
        for name, info in cls.model_fields.items():
            origin = getattr(info.annotation, "__pydantic_generic_metadata__", None)
            if origin and origin.get("origin") is Observation:
                names.append(name)
        return names
