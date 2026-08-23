"""Device inventory: one record per ingested file, and the batch that holds them.

The shape of this module follows one rule from the problem statement: *one
config in, one device record out*.  Nothing here merges devices, and nothing
here drops one.  When two files look like the same box, that similarity is
reported as a group alongside both records -- never by collapsing them, because
a collapse silently discards a configuration somebody uploaded on purpose.

``DeviceInventory`` is the contract the web dashboard (a later step) consumes,
so it serializes deterministically: sorted keys, stable device ordering, and no
values derived from the run itself except the two timestamps.
"""

import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .identity import DeviceIdentity
from .result import ControlResult, ReportSummary, Status, TargetInfo

INVENTORY_SCHEMA_VERSION = "1.0"


class DeviceStatus(str, Enum):
    """What became of one ingested file.

    The three values are exhaustive by construction: a file is audited, or its
    vendor was not recognised, or reading/parsing it raised. A batch never
    silently skips a file, so every input path appears under exactly one of
    these in the finished inventory.
    """

    AUDITED = "audited"
    UNKNOWN_VENDOR = "unknown_vendor"
    PARSE_ERROR = "parse_error"


class DeviceKeyTier(str, Enum):
    """Which identity tier produced a device's key -- recorded so it is auditable.

    Serial is the only tier that survives a hostname change, a re-IP, or a
    config rewrite, so it outranks everything. Hostname+vendor is a convention,
    not an identity: two devices can share one, and one device can change its
    own. Content hash is the honest last resort -- it does not identify a
    device at all, it identifies a *file*, and the tier says so.
    """

    SERIAL = "serial_number"
    HOSTNAME_VENDOR = "hostname_vendor"
    SOURCE_HASH = "source_hash"


class DuplicateKind(str, Enum):
    """Why two records were grouped. None of these merge anything."""

    #: Same serial number on two files: the same physical device, twice.
    DUPLICATE_SERIAL = "duplicate_serial"
    #: Byte-identical configurations, so the same file was ingested twice.
    DUPLICATE_CONTENT = "duplicate_content"
    #: Same hostname and vendor, different content. Either two snapshots of one
    #: device taken at different times, or two devices sharing a name. The tool
    #: cannot tell which from the files alone, so it flags and keeps both.
    POSSIBLE_CONFIG_DRIFT = "possible_config_drift"


class DuplicateGroup(BaseModel):
    """Two or more records that may describe the same device. Both are kept."""

    model_config = ConfigDict(frozen=True)

    kind: DuplicateKind
    key: str = Field(description="The shared value that grouped these records.")
    key_tier: DeviceKeyTier
    source_files: List[str] = Field(description="Every record in the group, in inventory order.")
    note: str


class InventoryCounts(BaseModel):
    """Batch outcome tallies. ``total`` always equals the number of files read."""

    model_config = ConfigDict(frozen=True)

    total: int = 0
    audited: int = 0
    unknown_vendor: int = 0
    parse_error: int = 0
    duplicate_groups: int = 0


class DeviceRecord(BaseModel):
    """One ingested configuration: who the device is, and how it scored.

    ``findings`` holds the existing ``ControlResult`` model unchanged, across
    every requested framework -- each result already carries its own
    ``framework``, so per-framework drill-down is a filter, not a second copy
    of the data. ``framework_summaries`` is the PASS/FAIL/REVIEW tally per
    framework, and preserves the three-valued logic exactly as a single-file
    run reports it.
    """

    model_config = ConfigDict(frozen=False)

    identity: DeviceIdentity
    source_file: str
    source_hash: Optional[str] = Field(
        default=None, description="SHA-256 of the file's bytes. None only when the file could not be read."
    )
    ingested_at: datetime
    status: DeviceStatus
    error: Optional[str] = None

    device_key: str = Field(description="Dedup key, computed by the tier below.")
    device_key_tier: DeviceKeyTier

    frameworks: List[str] = Field(default_factory=list)
    findings: List[ControlResult] = Field(default_factory=list)
    framework_summaries: Dict[str, ReportSummary] = Field(default_factory=dict)
    summary: ReportSummary = Field(default_factory=ReportSummary)

    #: Parse provenance, reusing the single-file report's own target block so a
    #: per-device report can be rendered from a record with no translation.
    target: Optional[TargetInfo] = None

    companion_file: Optional[str] = None

    # -- drill-down helpers -------------------------------------------------

    def findings_for(self, framework: str) -> List[ControlResult]:
        return [result for result in self.findings if result.framework == framework]

    def findings_with_status(self, status: Status) -> List[ControlResult]:
        return [result for result in self.findings if result.status is status]

    @property
    def hostname(self) -> Optional[str]:
        return self.identity.hostname.value

    @property
    def display_name(self) -> str:
        """A row label that never invents a name: the hostname, else the filename."""
        return self.identity.hostname.value or f"({self.source_file})"


class DeviceInventory(BaseModel):
    """The batch: every record, the rollup across them, and what looked duplicated."""

    model_config = ConfigDict(frozen=False)

    schema_version: str = INVENTORY_SCHEMA_VERSION
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tool: Dict[str, str] = Field(default_factory=dict)
    frameworks: List[str] = Field(default_factory=list, description="Frameworks requested for the batch.")
    counts: InventoryCounts = Field(default_factory=InventoryCounts)
    framework_rollup: Dict[str, ReportSummary] = Field(
        default_factory=dict,
        description="PASS/FAIL/REVIEW summed across every audited device, per framework.",
    )
    devices: List[DeviceRecord] = Field(default_factory=list)
    duplicates: List[DuplicateGroup] = Field(default_factory=list)
    warnings: List[str] = Field(
        default_factory=list,
        description="Input paths that resolved to no configuration files. Not devices, so not counted as any.",
    )

    # -- lookups ------------------------------------------------------------

    def devices_with_status(self, status: DeviceStatus) -> List[DeviceRecord]:
        return [device for device in self.devices if device.status is status]

    def device_by_source(self, source_file: str) -> Optional[DeviceRecord]:
        return next((device for device in self.devices if device.source_file == source_file), None)

    # -- serialization ------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=False)

    def to_json(self, *, indent: int = 2) -> str:
        """Deterministic JSON: sorted keys, so two runs of one directory diff cleanly."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=True)
