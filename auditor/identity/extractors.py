"""Deterministic device-identity extraction, one extractor per vendor.

Two rules shape everything here.

**Nothing is invented.**  An extractor may only report what is literally
written in the file it was given.  Where a value would have to be reconstructed
to be useful -- a Cisco ``boot system`` image name such as
``c2900-universalk9-mz.SPA.157-3.M2.bin`` implies IOS 15.7(3)M2, but only after
a transformation the file never states -- the extractor reports nothing.  An
inventory that says ``serial: null`` is telling the truth; one that says
``serial: FOC-UNKNOWN-01`` is not, and there is no third option.

**Identity is framework-neutral.**  No extractor, and no field on
``DeviceIdentity``, knows that CIS, NIST, STIG or ISO exist.  Identity says
which device this is; frameworks say whether it is compliant.

Extraction reuses the parse the pipeline already did -- ``hostname`` comes
straight off the produced ``SecurityBaselineModel``, evidence line intact, so
the config is never parsed twice for it.  Version and model are read with
narrow line patterns because no parser normalizes them today: they are identity,
not posture, so putting them on the baseline would offer them to rule
conditions, which is exactly what the identity/baseline split prevents.
"""

import re
from typing import Callable, Dict, List, Optional, Pattern, Tuple

from ..models.baseline import SecurityBaselineModel
from ..models.identity import UNKNOWN_VENDOR, DeviceIdentity
from ..models.observation import Observation

_QUOTE = "[\"']?"
_UNQUOTED = "[^\"'\\s]+"

#: (pattern, keyword) pairs used only when no deterministic parser claimed the file.
_BEST_EFFORT_HOSTNAME: List[Tuple[Pattern[str], str]] = [
    (re.compile(r"(?i)^\s*hostname\s+(\S+)\s*$"), "hostname"),
    (re.compile(r"(?i)^\s*sysname\s+(\S+)\s*$"), "sysname"),
    (re.compile(r"(?i)^\s*switchname\s+(\S+)\s*$"), "switchname"),
    (re.compile(r"(?i)^\s*system-name\s+(\S+)\s*$"), "system-name"),
    (re.compile(r"(?i)^\s*set system host-name\s+(\S+)\s*;?\s*$"), "set system host-name"),
    (re.compile(r"(?i)^\s*host-name\s+(\S+)\s*;\s*$"), "host-name"),
    (re.compile(r"(?i)^\s*set hostname\s+" + _QUOTE + "(" + _UNQUOTED + ")" + _QUOTE + r"\s*$"), "set hostname"),
]

_MISSING_MODEL_NOTE = (
    "Hardware model is not present in a {vendor} configuration file; it requires "
    "show-command output ({command})."
)
_MISSING_SERIAL_NOTE = (
    "Serial number is not present in a {vendor} configuration file; it requires "
    "show-command output ({command})."
)

#: Where the missing hardware facts actually live, per vendor. Quoted in the
#: notes so an operator reading an inventory knows what to capture next.
_HARDWARE_SOURCE = {
    "cisco_ios": "show version / show inventory",
    "juniper_junos": "show chassis hardware / show version",
    "fortinet_fortios": "get system status",
    "arista_eos": "show version / show inventory",
    "sonic": "show platform summary",
    "checkpoint_gaia": "cpstat os / fw ver",
    "mikrotik_routeros": "system resource print / system routerboard print",
    "stormshield_sns": "SYSTEM PROPERTY / SYS INFO / getconf",
    "watchguard_fireware": "show sysinfo / Fireware Web UI Dashboard",
    UNKNOWN_VENDOR: "the vendor's show-version equivalent",
}


def _missing(field: str, vendor: str) -> Observation[str]:
    template = _MISSING_SERIAL_NOTE if field == "serial_number" else _MISSING_MODEL_NOTE
    return Observation[str].unknown(
        template.format(
            vendor=vendor.replace("_", " "),
            command=_HARDWARE_SOURCE.get(vendor, "show output"),
        )
    )


def _scan(lines: List[str], pattern: Pattern[str], group: int = 1) -> Optional[Tuple[str, str, int]]:
    """First line matching ``pattern``, as (value, source_line, 1-based line number)."""
    for index, line in enumerate(lines, start=1):
        match = pattern.match(line)
        if match:
            value = match.group(group)
            if value:
                return value.strip(), line.strip(), index
    return None


def _found(hit: Tuple[str, str, int], note: Optional[str] = None) -> Observation[str]:
    value, source_line, line_number = hit
    return Observation[str].found(value, source_line, line_number, note=note)


# ---------------------------------------------------------------------------
# Cisco IOS
# ---------------------------------------------------------------------------

#: The running-config's own `version 15.7` line. Anchored to the start of the
#: line so `ip ssh version 2` and `snmp-server host ... version 2c` cannot match.
_IOS_VERSION = re.compile(r"(?i)^\s*version\s+(\d[\w.()]*)\s*$")

#: `license udi pid ISR4331/K9 sn FDO21520ABC` -- present on some platforms and
#: genuinely part of the configuration, so reading it is reporting, not guessing.
_IOS_LICENSE_UDI = re.compile(r"(?i)^\s*license udi pid\s+(\S+)\s+sn\s+(\S+)\s*$")


def _extract_cisco_ios(
    lines: List[str], baseline: Optional[SecurityBaselineModel]
) -> Dict[str, Observation]:
    fields: Dict[str, Observation] = {}

    version = _scan(lines, _IOS_VERSION)
    fields["os_version"] = (
        _found(version)
        if version
        else Observation[str].unknown(
            "No 'version' statement in this configuration. An IOS image name on a 'boot system' "
            "line is not a version string and is not reconstructed into one."
        )
    )

    udi = _scan(lines, _IOS_LICENSE_UDI)
    if udi:
        pid, source_line, line_number = udi
        serial = _IOS_LICENSE_UDI.match(source_line).group(2)
        note = "From the 'license udi' statement, which is part of the configuration itself."
        fields["model"] = Observation[str].found(pid, source_line, line_number, note=note)
        fields["serial_number"] = Observation[str].found(serial, source_line, line_number, note=note)
    else:
        fields["model"] = _missing("model", "cisco_ios")
        fields["serial_number"] = _missing("serial_number", "cisco_ios")
    return fields


# ---------------------------------------------------------------------------
# Juniper Junos
# ---------------------------------------------------------------------------

#: `set version 21.4R3-S4.9` (set format) and `version 21.4R3-S4.9;` (braces).
_JUNOS_VERSION = re.compile(r"(?i)^\s*(?:set\s+)?version\s+([^\s;]+)\s*;?\s*$")


def _extract_junos(
    lines: List[str], baseline: Optional[SecurityBaselineModel]
) -> Dict[str, Observation]:
    fields: Dict[str, Observation] = {}

    version = _scan(lines, _JUNOS_VERSION)
    fields["os_version"] = (
        _found(version)
        if version
        else Observation[str].unknown("No 'version' statement in this configuration.")
    )
    fields["model"] = _missing("model", "juniper_junos")
    fields["serial_number"] = _missing("serial_number", "juniper_junos")
    return fields


# ---------------------------------------------------------------------------
# Fortinet FortiOS
# ---------------------------------------------------------------------------

#: `#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0`
#: FortiOS writes the platform and firmware into the first line of a `show`.
#: Both halves are read verbatim; neither is assembled from anything else.
_FORTIOS_CONFIG_VERSION = re.compile(
    r"(?i)^\s*#\s*config-version\s*=\s*([A-Za-z0-9]+)-(\d[^-\s]*)-"
)


def _extract_fortios(
    lines: List[str], baseline: Optional[SecurityBaselineModel]
) -> Dict[str, Observation]:
    fields: Dict[str, Observation] = {}

    header = _scan(lines, _FORTIOS_CONFIG_VERSION, group=2)
    if header:
        _, source_line, line_number = header
        match = _FORTIOS_CONFIG_VERSION.match(source_line)
        fields["model"] = Observation[str].found(
            match.group(1), source_line, line_number, note="Platform code from the config-version header."
        )
        fields["os_version"] = Observation[str].found(
            match.group(2), source_line, line_number, note="Firmware version from the config-version header."
        )
    else:
        fields["model"] = _missing("model", "fortinet_fortios")
        fields["os_version"] = Observation[str].unknown(
            "No '#config-version=' header in this configuration; FortiOS writes one only at the "
            "top of a full 'show'."
        )
    # The config-version header carries the platform but never the serial.
    fields["serial_number"] = _missing("serial_number", "fortinet_fortios")
    return fields


# ---------------------------------------------------------------------------
# Unknown vendor
# ---------------------------------------------------------------------------


def _extract_unknown(
    lines: List[str], baseline: Optional[SecurityBaselineModel]
) -> Dict[str, Observation]:
    """Best-effort hostname only. Everything hardware stays null, by construction."""
    fields: Dict[str, Observation] = {
        "model": _missing("model", UNKNOWN_VENDOR),
        "serial_number": _missing("serial_number", UNKNOWN_VENDOR),
        "os_version": Observation[str].unknown(
            "No vendor was identified, so no version statement can be located with confidence."
        ),
    }
    hostname = _best_effort_hostname(lines)
    if hostname is not None:
        fields["hostname"] = hostname
    return fields


def _best_effort_hostname(lines: List[str]) -> Optional[Observation[str]]:
    """A hostname is worth guessing at; a serial number is not.

    The asymmetry is deliberate. A wrong hostname is visible to the operator
    reading the inventory and costs nothing but a re-read; a wrong serial number
    is an asset-management lie that looks authoritative. So this runs the common
    hostname-shaped spellings across vendors and reports what it finds, with the
    keyword it matched recorded in the note.
    """
    for pattern, keyword in _BEST_EFFORT_HOSTNAME:
        hit = _scan(lines, pattern)
        if hit:
            return _found(
                hit,
                note=(
                    f"Best-effort: matched a {keyword!r} statement in a configuration no "
                    "deterministic parser claimed."
                ),
            )
    return None


_ARISTA_DEVICE_HEADER = re.compile(
    r"(?i)^\s*!\s*device:\s*\S+\s*\(([^,]+),\s*EOS-([^)]+)\)"
)

_ARISTA_VERSION = re.compile(r"(?i)^\s*!\s*device:\s*\S+\s*\([^,]+,\s*EOS-([^)]+)\)")


def _extract_arista_eos(
    lines: List[str], baseline: Optional[SecurityBaselineModel]
) -> Dict[str, Observation]:
    fields: Dict[str, Observation] = {}

    header = _scan(lines, _ARISTA_DEVICE_HEADER, group=1)
    if header:
        model_val, source_line, line_number = header
        version_match = _ARISTA_VERSION.match(source_line)
        fields["model"] = Observation[str].found(
            model_val.strip(), source_line, line_number,
            note="Platform model from the '! device:' header.",
        )
        if version_match:
            fields["os_version"] = Observation[str].found(
                version_match.group(1).strip(), source_line, line_number,
                note="EOS version from the '! device:' header.",
            )
        else:
            fields["os_version"] = _missing("os_version", "arista_eos")
    else:
        fields["model"] = _missing("model", "arista_eos")
        fields["os_version"] = Observation[str].unknown(
            "No '! device:' header found in this configuration."
        )

    fields["serial_number"] = _missing("serial_number", "arista_eos")
    return fields


def _extract_sonic(
    lines: List[str], baseline: Optional[SecurityBaselineModel]
) -> Dict[str, Observation]:
    fields: Dict[str, Observation] = {}

    raw_text = "\n".join(lines)
    try:
        data = __import__("json").loads(raw_text)
    except Exception:
        data = {}

    meta = data.get("DEVICE_METADATA", {}).get("localhost", {})
    platform = meta.get("platform") or meta.get("hwsku")
    if platform:
        for idx, line in enumerate(lines, 1):
            if "platform" in line or "hwsku" in line:
                fields["model"] = Observation[str].found(
                    platform, line.strip(), idx,
                    note="Platform from DEVICE_METADATA.",
                )
                break
        else:
            fields["model"] = Observation[str].found(
                platform, "DEVICE_METADATA", None,
            )
    else:
        fields["model"] = _missing("model", "sonic")

    fields["os_version"] = Observation[str].unknown(
        "SONiC version is not stored in config_db.json; it requires "
        "'show version' output."
    )
    fields["serial_number"] = _missing("serial_number", "sonic")
    return fields


# ---------------------------------------------------------------------------
# Huawei VRP
# ---------------------------------------------------------------------------

_HUAWEI_VERSION = re.compile(r"(?i)^\s*!\s*Software Version\s+(\S+)\s*$")


def _extract_huawei(
    lines: List[str], baseline: Optional[SecurityBaselineModel]
) -> Dict[str, Observation]:
    fields: Dict[str, Observation] = {}

    version = _scan(lines, _HUAWEI_VERSION)
    fields["os_version"] = (
        _found(version)
        if version
        else Observation[str].unknown("No 'Software Version' statement in this configuration.")
    )
    fields["model"] = _missing("model", "huawei_vrp")
    fields["serial_number"] = _missing("serial_number", "huawei_vrp")
    return fields


def _extract_checkpoint_gaia(
    lines: List[str], baseline: Optional[SecurityBaselineModel]
) -> Dict[str, Observation]:
    fields: Dict[str, Observation] = {}

    fields["os_version"] = Observation[str].unknown(
        "Gaia OS version is not stored in 'show configuration' output; "
        "it requires 'cpstat os' or 'fw ver' command output."
    )
    fields["model"] = _missing("model", "checkpoint_gaia")
    fields["serial_number"] = _missing("serial_number", "checkpoint_gaia")
    return fields


_ROS_VERSION = re.compile(r"(?i)^\s*#.*by RouterOS\s+(\S+)")
_ROS_MODEL = re.compile(r"(?i)^\s*#\s*model\s*=\s*(\S+)")


def _extract_mikrotik_routeros(
    lines: List[str], baseline: Optional[SecurityBaselineModel]
) -> Dict[str, Observation]:
    fields: Dict[str, Observation] = {}

    version = _scan(lines, _ROS_VERSION)
    fields["os_version"] = (
        _found(version, note="RouterOS version from export header.")
        if version
        else Observation[str].unknown(
            "No '# ... by RouterOS <version>' header in this export."
        )
    )

    model = _scan(lines, _ROS_MODEL)
    fields["model"] = (
        _found(model, note="Hardware model from export header comment.")
        if model
        else _missing("model", "mikrotik_routeros")
    )

    fields["serial_number"] = _missing("serial_number", "mikrotik_routeros")
    return fields


# ---------------------------------------------------------------------------
# Stormshield Network Security (SNS)
# ---------------------------------------------------------------------------

_SNS_VERSION_COMMENT = re.compile(r"(?i)^\s*#.*(?:Stormshield Network Security|SNS)\s+v?(\d[\w.-]*)\b")
_SNS_VERSION_INI = re.compile(r"(?i)^\s*(?:version|firmware)\s*=\s*(\S+)")
_SNS_MODEL = re.compile(r"(?i)^\s*(?:#\s*)?model\s*[:=]\s*(\S+)")
_SNS_SERIAL = re.compile(r"(?i)^\s*(?:#\s*)?serial(?:number)?\s*[:=]\s*(\S+)")


def _extract_stormshield_sns(
    lines: List[str], baseline: Optional[SecurityBaselineModel]
) -> Dict[str, Observation]:
    fields: Dict[str, Observation] = {}

    version = _scan(lines, _SNS_VERSION_COMMENT) or _scan(lines, _SNS_VERSION_INI)
    fields["os_version"] = (
        _found(version, note="Stormshield SNS version from configuration/header.")
        if version
        else Observation[str].unknown(
            "No Stormshield version header or 'version=' setting in this configuration."
        )
    )

    model = _scan(lines, _SNS_MODEL)
    fields["model"] = (
        _found(model, note="Hardware model from configuration/header.")
        if model
        else _missing("model", "stormshield_sns")
    )

    serial = _scan(lines, _SNS_SERIAL)
    fields["serial_number"] = (
        _found(serial, note="Serial number from configuration/header.")
        if serial
        else _missing("serial_number", "stormshield_sns")
    )
    return fields


# ---------------------------------------------------------------------------
# WatchGuard Firebox / Fireware
# ---------------------------------------------------------------------------

_WG_VERSION = re.compile(
    r"(?i)(?:<configuration\b[^>]*\bversion=[\"']([^\"']+)[\"']|WatchGuard\s+Fireware\s+v?(\S+))"
)
_WG_MODEL = re.compile(r"(?i)(?:<model>([^<]+)</model>|Firebox\s+([A-Z0-9]+))")
_WG_SERIAL = re.compile(r"(?i)<serial(?:-number)?>([^<]+)</serial(?:-number)?>")


def _extract_watchguard_fireware(
    lines: List[str], baseline: Optional[SecurityBaselineModel]
) -> Dict[str, Observation]:
    fields: Dict[str, Observation] = {}
    version = _scan(lines, _WG_VERSION, group=1)
    if not version:
        version = _scan(lines, _WG_VERSION, group=2)
    fields["os_version"] = (
        _found(version, note="Fireware OS version.")
        if version
        else Observation[str].unknown("No Fireware version header in this configuration.")
    )

    model = _scan(lines, _WG_MODEL, group=1)
    if not model:
        model = _scan(lines, _WG_MODEL, group=2)
    fields["model"] = (
        _found(model, note="Firebox hardware model.")
        if model
        else _missing("model", "watchguard_fireware")
    )

    serial = _scan(lines, _WG_SERIAL)
    fields["serial_number"] = (
        _found(serial, note="Serial number from configuration/header.")
        if serial
        else _missing("serial_number", "watchguard_fireware")
    )
    return fields


_EXTRACTORS: Dict[
    str, Callable[[List[str], Optional[SecurityBaselineModel]], Dict[str, Observation]]
] = {
    "cisco_ios": _extract_cisco_ios,
    "juniper_junos": _extract_junos,
    "fortinet_fortios": _extract_fortios,
    "arista_eos": _extract_arista_eos,
    "sonic_sonic": _extract_sonic,
    "huawei_vrp": _extract_huawei,
    "checkpoint_gaia": _extract_checkpoint_gaia,
    "mikrotik_routeros": _extract_mikrotik_routeros,
    "stormshield_sns": _extract_stormshield_sns,
    "watchguard_fireware": _extract_watchguard_fireware,
}


def platform_key(baseline: SecurityBaselineModel) -> str:
    """The vendor key the rest of the tool speaks: ``cisco_ios``, ``juniper_junos``, ..."""
    return f"{baseline.provenance.vendor}_{baseline.provenance.os_family}"


def extract_identity(
    config_text: str,
    baseline: Optional[SecurityBaselineModel] = None,
    *,
    vendor: Optional[str] = None,
) -> DeviceIdentity:
    """Normalized identity for one ingested configuration.

    ``baseline`` is the parse the pipeline already produced. When it is present
    the hostname is taken from it verbatim -- same value, same line number, same
    evidence -- rather than being parsed a second time. When it is absent (an
    unknown vendor, or a file that failed to parse) extraction falls back to the
    best-effort scan, and every hardware field stays null.
    """
    lines = config_text.splitlines() if config_text else []

    if vendor is None:
        vendor = platform_key(baseline) if baseline is not None else UNKNOWN_VENDOR
    os_family = baseline.provenance.os_family if baseline is not None else UNKNOWN_VENDOR

    extractor = _EXTRACTORS.get(vendor, _extract_unknown)
    fields = extractor(lines, baseline)

    if baseline is not None:
        # The parser's own hostname observation, evidence untouched.
        fields["hostname"] = baseline.hostname
    elif "hostname" not in fields:
        # No parse to draw on -- a caller naming the vendor by hand, or a file
        # that failed to parse. Scan for a hostname rather than reporting none.
        best_effort = _best_effort_hostname(lines)
        if best_effort is not None:
            fields["hostname"] = best_effort
    fields.setdefault("hostname", Observation[str].unknown("No hostname statement found."))

    return DeviceIdentity(vendor=vendor, os_family=os_family, **fields)
