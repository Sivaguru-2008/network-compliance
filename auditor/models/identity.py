"""Normalized device identity: who this device is, on the evidence available.

Identity is deliberately *not* part of ``SecurityBaselineModel``.  The baseline
is the contract the rule engine consumes, and no compliance control turns on a
serial number -- mixing the two would let identity fields drift into rule
conditions.  Identity answers a different question: which box produced this
file, so an inventory can list it and a per-device report can title itself.

Every field that can be absent is an ``Observation``, the same evidence-carrying
wrapper the baseline uses.  That is not decoration.  A running-config almost
never contains the hardware serial number -- serial lives in ``show version`` /
``show inventory`` (Cisco), ``show chassis hardware`` (Junos) and
``get system status`` (FortiOS), none of which are configuration.  So for a
config-only ingest the honest answer is ``value=None, detected=False``, and
this model has no way to express anything else: there is no default, no
placeholder, and no inference from an image filename.  A null serial is a
correct result, not a failure.
"""

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

from .observation import Observation

#: The vendor string used when nothing deterministic claimed the configuration.
UNKNOWN_VENDOR = "unknown"


def _unknown_str(note: str):
    return lambda: Observation[str].unknown(note)


class DeviceIdentity(BaseModel):
    """Vendor-neutral identity of one device, extracted from one ingested file.

    ``vendor`` is the platform key the rest of the tool already uses
    (``cisco_ios``, ``juniper_junos``, ``fortinet_fortios``, or ``unknown``), so
    an inventory row and a rule-pack lookup agree on what the device is without
    a translation table.

    The four ``Observation`` fields each carry the configuration line they were
    read from, so an inventory entry can be audited back to the source file the
    same way a compliance verdict can.
    """

    model_config = ConfigDict(frozen=True)

    vendor: str = Field(
        default=UNKNOWN_VENDOR,
        description="Platform key: cisco_ios | juniper_junos | fortinet_fortios | unknown.",
    )
    os_family: str = Field(default=UNKNOWN_VENDOR, description="Normalized OS family: ios | junos | fortios | unknown.")

    hostname: Observation[str] = Field(default_factory=_unknown_str("No hostname statement found."))
    os_version: Observation[str] = Field(
        default_factory=_unknown_str("No version statement found in this configuration."),
        description="Software version exactly as written in the source. Never reconstructed from an image filename.",
    )
    model: Observation[str] = Field(
        default_factory=_unknown_str(
            "Hardware model is not present in a configuration file; it requires show-command output."
        ),
    )
    serial_number: Observation[str] = Field(
        default_factory=_unknown_str(
            "Serial number is not present in a configuration file; it requires show-command output "
            "(show version / show inventory, show chassis hardware, get system status)."
        ),
    )

    #: Set when a companion show-output file was read alongside the config.
    companion_file: Optional[str] = None

    # -- convenience for reports -------------------------------------------

    @property
    def display_name(self) -> str:
        """What to call this device in a table. Never invented."""
        return self.hostname.value or "(hostname not found)"

    @property
    def is_identified(self) -> bool:
        return self.vendor != UNKNOWN_VENDOR

    def field_value(self, name: str) -> Optional[str]:
        """``None`` when the field was not established -- the only honest default."""
        observation = getattr(self, name)
        return observation.value if observation.detected else None
