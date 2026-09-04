"""The Security Baseline Model: one vendor-neutral view of a device.

This is the contract between parsing and evaluation.  Parsers (deterministic
today, LLM-backed later) produce it; the rule engine consumes it and never
looks at raw config text.  Adding a vendor must never require changing rules,
and adding a rule must never require changing parsers -- if a rule needs a
setting nobody normalizes yet, the field is added *here* first.

Field naming is deliberately vendor-neutral: ``vty_exec_timeout_seconds``, not
``line_vty_exec_timeout``; ``management_plaintext_protocols``, not ``telnet``.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .observation import CapabilityStatus, Observation


def _unknown(kind):
    """Default factory: a field nobody has evaluated yet is *unknown*, not secure."""
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
    completeness: Optional[Dict[str, Any]] = Field(
        default=None, description="Configuration completeness assessment."
    )

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

    # -- extended hardening settings --------------------------------------
    dns_servers: Observation[List[str]] = Field(
        default_factory=_unknown(List[str]),
        description="Configured DNS servers for device name resolution.",
    )
    usb_auto_install_disabled: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="USB auto-install of config/firmware is disabled.",
    )
    ssl_static_key_ciphers_disabled: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="SSL static key ciphers are disabled.",
    )
    strong_crypto_enabled: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="Strong cryptographic ciphers are enforced for administrative access.",
    )
    admin_tls13_only: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="Administrative HTTPS access restricted to TLS 1.3 only.",
    )
    management_min_tls_version: Observation[str] = Field(
        default_factory=_unknown(str),
        description="Minimum TLS version enforced for administrative access (e.g. '1.3').",
    )
    gui_cdn_enabled: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="GUI CDN usage is enabled for FortiGuard web filtering.",
    )
    log_single_cpu_high_enabled: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="Logging of single-CPU-high events is enabled.",
    )
    admin_lockout_threshold: Observation[int] = Field(
        default_factory=_unknown(int),
        description="Number of failed login attempts before account lockout; 0 means disabled.",
    )
    admin_lockout_duration: Observation[int] = Field(
        default_factory=_unknown(int),
        description="Duration in seconds an account remains locked after reaching the threshold.",
    )
    admin_default_ports_changed: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="Administrative HTTP/HTTPS ports are changed from defaults (80/443).",
    )
    pre_login_banner_present: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="A banner is presented before login.",
    )
    post_login_banner_present: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="A banner is presented after login.",
    )
    snmp_agent_enabled: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="True if the SNMP agent is enabled.",
    )
    snmp_v3_users_present: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="True if at least one SNMPv3 user is configured.",
    )
    event_logging_enabled: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="True if all event logging is enabled under config log eventfilter.",
    )
    ntp_redundant: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="True if redundant (at least two) NTP servers are configured.",
    )
    verify_update_server_identity: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="True if update server identity verification is enabled.",
    )

    # -- Priority 1 Batch 1 Controls addition --
    ha_enabled: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="True if High Availability is configured and enabled.",
    )
    ha_monitor_interfaces: Observation[List[str]] = Field(
        default_factory=_unknown(List[str]),
        description="List of interfaces monitored by High Availability.",
    )
    av_push_updates_enabled: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="True if antivirus automatic updates are enabled (config system autoupdate schedule).",
    )
    security_fabric_enabled: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="True if Security Fabric (CSF) is enabled.",
    )
    password_min_uppercase: Observation[int] = Field(
        default_factory=_unknown(int),
        description="Minimum number of uppercase characters required in passwords.",
    )
    password_min_lowercase: Observation[int] = Field(
        default_factory=_unknown(int),
        description="Minimum number of lowercase characters required in passwords.",
    )
    password_min_numeric: Observation[int] = Field(
        default_factory=_unknown(int),
        description="Minimum number of numeric characters required in passwords.",
    )
    password_min_special: Observation[int] = Field(
        default_factory=_unknown(int),
        description="Minimum number of special characters required in passwords.",
    )
    password_max_age_days: Observation[int] = Field(
        default_factory=_unknown(int),
        description="Maximum allowed lifetime of passwords in days.",
    )
    password_new_diff_chars: Observation[int] = Field(
        default_factory=_unknown(int),
        description="Minimum number of characters that must differ between new and old passwords.",
    )
    password_history_reuse_limit: Observation[int] = Field(
        default_factory=_unknown(int),
        description="Number of previous passwords remembered to prevent reuse.",
    )

    # -- Priority 2 Batch 1 Controls addition --
    av_ai_detection_enabled: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="True if AI/heuristic-based malware detection is enabled (config antivirus settings).",
    )
    av_grayware_enabled: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="True if grayware detection is enabled (config antivirus settings).",
    )
    log_encryption_enabled: Observation[bool] = Field(
        default_factory=_unknown(bool),
        description="True if log encryption to FortiAnalyzer/FortiManager is enabled (enc-algorithm high + reliable enable).",
    )

    @classmethod
    def observable_fields(cls) -> List[str]:
        """Names of every ``Observation``-typed field -- the rule engine's vocabulary."""
        names = []
        for name, info in cls.model_fields.items():
            origin = getattr(info.annotation, "__pydantic_generic_metadata__", None)
            if origin and origin.get("origin") is Observation:
                names.append(name)
        return names

    def capabilities(self) -> Dict[str, str]:
        """Return explicit capability state for every observable field."""
        result = {}
        for field_name in self.observable_fields():
            obs = getattr(self, field_name)
            if isinstance(obs, Observation):
                result[field_name] = obs.capability_status.value
        return result
