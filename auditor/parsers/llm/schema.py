"""The schema the model is constrained to return.

This is deliberately *not* ``SecurityBaselineModel``. The model is asked for
raw claims — "is this determinable, what is the value, which line says so, how
sure are you" — and the parser turns those claims into a baseline only after
verifying them against the actual configuration text. Keeping the two schemas
separate is what makes that verification step possible: the model never gets to
write a line number, an ``origin``, or a ``detected`` flag directly.

Every finding carries its own ``confidence`` and ``reasoning`` so that a
low-confidence claim can be downgraded rather than trusted, and so a human
reviewing a NEEDS_REVIEW verdict can see what the model was thinking.
"""

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class _Finding(BaseModel):
    """Fields common to every claim the model makes about one setting."""

    model_config = ConfigDict(extra="forbid")

    determined: bool = Field(
        description=(
            "True only if the configuration text conclusively establishes this setting. "
            "False if the setting is absent, ambiguous, or you are guessing."
        )
    )
    source_line: Optional[str] = Field(
        default=None,
        description=(
            "The single configuration line that establishes this value, copied VERBATIM "
            "from the input. Null if determined is false, or if your conclusion rests on "
            "the absence of a line rather than on a line that is present."
        ),
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Calibrated confidence in this specific finding, 0.0 to 1.0.",
    )
    reasoning: str = Field(
        default="",
        description="One sentence: why this value, or why it could not be determined.",
    )


class BooleanFinding(_Finding):
    value: Optional[bool] = None


class IntegerFinding(_Finding):
    value: Optional[int] = None


class TextFinding(_Finding):
    value: Optional[str] = None


class TextListFinding(_Finding):
    value: Optional[List[str]] = None


class SnmpCommunityClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="The community string exactly as configured.")
    access: Optional[str] = Field(default=None, description="'ro', 'rw', or null if not stated.")
    acl: Optional[str] = Field(default=None, description="ACL restricting this community, or null.")
    view: Optional[str] = None
    source_line: str = Field(description="The verbatim configuration line defining this community.")


class SnmpCommunityFinding(_Finding):
    value: Optional[List[SnmpCommunityClaim]] = None


class LLMExtraction(BaseModel):
    """One model response: an identification of the device plus one claim per setting."""

    model_config = ConfigDict(extra="forbid")

    vendor: str = Field(description="Device vendor in lowercase, e.g. 'juniper', 'arista', 'fortinet'.")
    os_family: str = Field(description="OS family in lowercase, e.g. 'junos', 'eos', 'fortios'.")
    identification_confidence: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Confidence in the vendor/os_family identification."
    )

    hostname: TextFinding
    telnet_enabled: BooleanFinding
    vty_transport_input: TextListFinding
    vty_exec_timeout_seconds: IntegerFinding
    ssh_enabled: BooleanFinding
    ssh_version: IntegerFinding
    http_server_enabled: BooleanFinding
    https_server_enabled: BooleanFinding
    management_acl_applied: BooleanFinding
    login_banner_present: BooleanFinding
    enable_secret_set: BooleanFinding
    enable_password_present: BooleanFinding
    password_encryption: BooleanFinding
    password_min_length: IntegerFinding
    aaa_enabled: BooleanFinding
    snmp_communities: SnmpCommunityFinding
    logging_enabled: BooleanFinding
    logging_hosts: TextListFinding
    logging_buffered: BooleanFinding
    ntp_servers: TextListFinding
    dns_servers: TextListFinding
    usb_auto_install_disabled: BooleanFinding
    ssl_static_key_ciphers_disabled: BooleanFinding
    strong_crypto_enabled: BooleanFinding
    admin_tls13_only: BooleanFinding
    management_min_tls_version: TextFinding
    gui_cdn_enabled: BooleanFinding
    log_single_cpu_high_enabled: BooleanFinding
    admin_lockout_threshold: IntegerFinding
    admin_lockout_duration: IntegerFinding
    admin_default_ports_changed: BooleanFinding
    pre_login_banner_present: BooleanFinding
    post_login_banner_present: BooleanFinding
    snmp_agent_enabled: BooleanFinding
    snmp_v3_users_present: BooleanFinding
    event_logging_enabled: BooleanFinding
    ntp_redundant: BooleanFinding
    verify_update_server_identity: BooleanFinding

    @classmethod
    def finding_fields(cls) -> List[str]:
        """Names of the per-setting findings — must match the baseline's vocabulary."""
        return [name for name, info in cls.model_fields.items() if _is_finding(info.annotation)]


def _is_finding(annotation) -> bool:
    return isinstance(annotation, type) and issubclass(annotation, _Finding)
