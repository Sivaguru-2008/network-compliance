"""Optional companion show-output, the only honest source of a serial number.

A configuration file does not contain the hardware serial: ``show version`` /
``show inventory`` (Cisco), ``show chassis hardware`` (Junos) and
``get system status`` (FortiOS) do, and none of those are configuration.  This
module reads such a capture *when an operator supplies one alongside the
config*, and does nothing at all when they do not.

The convention is filename-based and deliberately boring::

    samples/configs/core-rtr-01.conf
    samples/configs/core-rtr-01.show_version.txt   <- companion, read if present

Nothing here is required.  With no companion file the serial, model and version
observations stay ``detected=False`` with ``value=None``, which is the correct
answer for a config-only ingest.  Every value that *is* produced cites the
companion line it came from, and says in its note that the evidence came from
the companion rather than from the configuration -- so a reader is never left
thinking line 12 of the running-config carried a serial number.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Pattern, Tuple

from ..models.identity import DeviceIdentity
from ..models.observation import Observation

#: Suffixes appended to the config's stem to name its companion capture.
COMPANION_SUFFIXES: Tuple[str, ...] = (
    ".show_version.txt",
    ".show_version",
    ".show-version.txt",
    ".showver.txt",
)

#: Fields a companion capture may establish. Hostname stays with the config:
#: the config is the authority on what the device is configured to be called.
COMPANION_FIELDS = ("serial_number", "model", "os_version")

#: Every companion-sourced note opens with this. It is a shared constant rather
#: than a phrase each caller re-types, so a renderer can ask whether a value came
#: from show output instead of guessing from the wording -- and a serial is never
#: displayed as though line 24 of the *configuration* contained it.
COMPANION_NOTE_PREFIX = "Read from companion show output"

_Rule = Tuple[Pattern[str], str]


def _rules(pairs: List[Tuple[str, str]]) -> List[_Rule]:
    return [(re.compile(pattern), field) for pattern, field in pairs]


# Cisco: `show version` and `show inventory` output.
_CISCO_RULES = _rules(
    [
        (r"(?im)^\s*Processor board ID\s+(\S+)", "serial_number"),
        (r"(?im)^\s*System [Ss]erial [Nn]umber\s*[:=]\s*(\S+)", "serial_number"),
        (r"(?im)^.*\bSN:\s*(\S+)", "serial_number"),
        (r"(?im)^\s*Model [Nn]umber\s*[:=]\s*(\S+)", "model"),
        (r"(?im)^.*\bPID:\s*(\S+)", "model"),
        # `Cisco CISCO2911/K9 (revision 1.0) with 483328K/40960K bytes of memory.`
        # and the older `cisco WS-C2960-24TT-L (PowerPC405) processor ...`
        (r"(?im)^\s*[Cc]isco\s+(\S+)\s+\([^)]*\)\s+(?:with|processor)\b", "model"),
        (r"(?im)^.*Cisco IOS Software.*?,\s*Version\s+([^\s,]+)", "os_version"),
        (r"(?im)^.*\bIOS \(tm\).*?Version\s+([^\s,]+)", "os_version"),
    ]
)

# Junos: `show version` and `show chassis hardware` output.
_JUNOS_RULES = _rules(
    [
        (r"(?im)^\s*Chassis\s+(\S+)\s+(?:\S+)\s*$", "serial_number"),
        (r"(?im)^\s*[Ss]erial [Nn]umber\s*[:=]\s*(\S+)", "serial_number"),
        (r"(?im)^\s*Model\s*[:=]\s*(\S+)", "model"),
        (r"(?im)^\s*Junos\s*[:=]\s*(\S+)", "os_version"),
        (r"(?im)^.*JUNOS.*Release\s*\[([^\]]+)\]", "os_version"),
    ]
)

# FortiOS: `get system status` output.
_FORTIOS_RULES = _rules(
    [
        (r"(?im)^\s*Serial-Number\s*[:=]\s*(\S+)", "serial_number"),
        (r"(?im)^\s*Version\s*[:=]\s*(\S+)\s+v(\S+?),", "model"),
        (r"(?im)^\s*Version\s*[:=]\s*\S+\s+v([^\s,]+),", "os_version"),
    ]
)

# Applied when the companion belongs to a device no parser claimed. Only the
# unambiguous, vendor-independent spellings -- guessing across vendors here
# would put a fabricated serial into an inventory, which is the one thing this
# module exists to prevent.
_GENERIC_RULES = _rules(
    [
        (r"(?im)^\s*[Ss]erial[- ][Nn]umber\s*[:=]\s*(\S+)", "serial_number"),
        (r"(?im)^\s*Model\s*[:=]\s*(\S+)", "model"),
    ]
)

_RULES_BY_VENDOR: Dict[str, List[_Rule]] = {
    "cisco_ios": _CISCO_RULES,
    "juniper_junos": _JUNOS_RULES,
    "fortinet_fortios": _FORTIOS_RULES,
}


def companion_path(config_path: Path) -> Optional[Path]:
    """The companion capture sitting beside ``config_path``, if an operator wrote one.

    Both ``core-rtr-01.conf`` -> ``core-rtr-01.show_version.txt`` and the
    suffix-preserving ``core-rtr-01.conf.show_version.txt`` are accepted, since
    both fall out of ordinary shell habits.
    """
    config_path = Path(config_path)
    directory = config_path.parent
    for suffix in COMPANION_SUFFIXES:
        for stem in (config_path.stem, config_path.name):
            candidate = directory / f"{stem}{suffix}"
            if candidate.is_file():
                return candidate
    return None


def is_companion_file(path: Path) -> bool:
    """True for a capture that accompanies a config rather than being one.

    Directory scans use this so a companion is never ingested as a device in
    its own right -- one device must produce exactly one inventory record.
    """
    name = Path(path).name.lower()
    return any(suffix.lower() in name for suffix in COMPANION_SUFFIXES)


def enrich_from_companion(
    identity: DeviceIdentity,
    companion_text: str,
    *,
    companion_file: Optional[str] = None,
) -> DeviceIdentity:
    """Fill serial / model / version from show output, leaving the rest alone.

    Only fields the config could not establish are filled: the configuration
    wins where the two disagree on version, because the config is the artefact
    being audited.  A field the companion does not mention stays undetected.
    """
    if not companion_text or not companion_text.strip():
        return identity

    lines = companion_text.splitlines()
    rules = _RULES_BY_VENDOR.get(identity.vendor, _GENERIC_RULES)
    label = companion_file or "companion show output"

    updates: Dict[str, Observation] = {}
    for field in COMPANION_FIELDS:
        if getattr(identity, field).detected:
            continue  # the configuration already established it; do not overwrite
        found = _first_match(lines, rules, field)
        if found is None:
            continue
        value, source_line, line_number = found
        updates[field] = Observation[str].found(
            value,
            source_line,
            line_number,
            note=(
                f"{COMPANION_NOTE_PREFIX} {label} (line {line_number}), "
                "not from the configuration."
            ),
        )

    if not updates:
        return identity.model_copy(update={"companion_file": companion_file})
    updates["companion_file"] = companion_file
    return identity.model_copy(update=updates)


def _first_match(
    lines: List[str], rules: List[_Rule], field: str
) -> Optional[Tuple[str, str, int]]:
    """First line matching any rule for ``field``, with its 1-based line number."""
    for index, line in enumerate(lines, start=1):
        for pattern, rule_field in rules:
            if rule_field != field:
                continue
            match = pattern.match(line) or pattern.search(line)
            if match and match.group(1):
                return match.group(1).strip().strip(",;"), line.strip(), index
    return None


def is_from_companion(observation) -> bool:
    """True when this value was read from show output rather than the config.

    The one place that owns the convention. A report that cites a line number
    must be able to say *which file* that line is in.
    """
    note = getattr(observation, "note", None)
    return bool(note) and note.startswith(COMPANION_NOTE_PREFIX)
