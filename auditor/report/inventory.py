"""Fleet-level rendering: the inventory view over many devices.

The single-device table in ``table.py`` is untouched and remains the drill-down
view -- this is the layer above it, answering "what did the batch find?" rather
than "why did this control fail?".

It renders what is in the inventory and nothing else. A serial that was never
captured prints as ``null``, not as a blank that could be mistaken for a
formatting artefact, and a device that failed to parse gets a row of its own
with the reason attached. A fleet report that quietly omitted the files it could
not read would be worse than useless: it would look complete.
"""

from typing import List, Optional

from ..models.inventory import DeviceInventory, DeviceRecord, DeviceStatus
from ..models.result import ReportSummary, Status
from .table import _COLORS, _Painter, _truncate, supports_color

_STATUS_COLORS = {
    DeviceStatus.AUDITED: _COLORS[Status.PASS],
    DeviceStatus.UNKNOWN_VENDOR: _COLORS[Status.NEEDS_REVIEW],
    DeviceStatus.PARSE_ERROR: _COLORS[Status.FAIL],
}


def render_inventory(
    inventory: DeviceInventory,
    *,
    color: Optional[bool] = None,
    width: int = 118,
) -> str:
    """Render the whole batch: counts, per-framework rollup, then per device."""
    paint = _Painter(supports_color() if color is None else color)
    out: List[str] = [""]

    out.append(paint("NETWORK DEVICE INVENTORY", "\033[1m"))
    out.append("=" * width)
    out.append(f"  Generated     : {inventory.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    out.append(f"  Frameworks    : {', '.join(inventory.frameworks) or '(none)'}")
    out.append("=" * width)

    out.extend(_summary_block(inventory, paint))
    out.extend(_rollup_block(inventory, paint, width))
    out.extend(_device_block(inventory, paint, width))
    out.extend(_duplicate_block(inventory, paint, width))
    out.extend(_problem_block(inventory, paint, width))

    out.append("")
    return "\n".join(out)


def _summary_block(inventory: DeviceInventory, paint: _Painter) -> List[str]:
    counts = inventory.counts
    return [
        "",
        paint("INVENTORY SUMMARY", "\033[1m"),
        "─" * 40,
        f"  Devices:        {counts.total}",
        "  Audited:        " + paint(str(counts.audited), _COLORS[Status.PASS]),
        "  Unknown vendor: "
        + paint(str(counts.unknown_vendor), _COLORS[Status.NEEDS_REVIEW] if counts.unknown_vendor else None),
        "  Parse errors:   "
        + paint(str(counts.parse_error), _COLORS[Status.FAIL] if counts.parse_error else None),
        f"  Duplicates:     {counts.duplicate_groups} group(s)",
    ]


def _rollup_block(inventory: DeviceInventory, paint: _Painter, width: int) -> List[str]:
    if not inventory.framework_rollup:
        return ["", "  No framework results: nothing in this batch could be audited.", ""]

    out = ["", paint("PER-FRAMEWORK ROLLUP (across all devices)", "\033[1m"), "─" * width]
    label_width = max(len(name) for name in inventory.framework_rollup) + 2
    for name, summary in inventory.framework_rollup.items():
        out.append(f"  {name.ljust(label_width)}{_tally(summary, paint)}   of {summary.total} controls")
    out.append("")
    return out


def _tally(summary: ReportSummary, paint: _Painter) -> str:
    return (
        paint(f"PASS {summary.passed:<4}", _COLORS[Status.PASS])
        + paint(f"FAIL {summary.failed:<4}", _COLORS[Status.FAIL])
        + paint(f"REVIEW {summary.needs_review:<4}", _COLORS[Status.NEEDS_REVIEW])
    )


def _device_block(inventory: DeviceInventory, paint: _Painter, width: int) -> List[str]:
    out = [paint("PER-DEVICE", "\033[1m"), "─" * width]
    if not inventory.devices:
        out.extend(["  (no configuration files were ingested)", ""])
        return out

    for device in inventory.devices:
        out.extend(_device_rows(device, paint, width))
    out.append("")
    return out


def _device_rows(device: DeviceRecord, paint: _Painter, width: int) -> List[str]:
    identity = device.identity
    descriptor = f"{identity.vendor}, {_or_null(identity.field_value('os_version'))}"
    serial = _or_null(identity.field_value("serial_number"))
    model = _or_null(identity.field_value("model"))

    rows = [
        "  "
        + _truncate(device.display_name, 28).ljust(28)
        + f"  ({descriptor})".ljust(34)
        + f"  [serial: {serial}]".ljust(28)
        + paint(device.status.value, _STATUS_COLORS.get(device.status))
    ]
    rows.append(f"      file: {_path(device.source_file, width - 28)}   model: {model}")

    if device.status is DeviceStatus.AUDITED:
        label_width = max((len(name) for name in device.framework_summaries), default=0) + 2
        for name, summary in device.framework_summaries.items():
            rows.append(f"      {name.ljust(label_width)}{_tally(summary, paint)}")
    elif device.error:
        rows.append(
            "      "
            + paint(_truncate(f"reason: {device.error}", width - 10), _STATUS_COLORS.get(device.status))
        )
    return rows


def _duplicate_block(inventory: DeviceInventory, paint: _Painter, width: int) -> List[str]:
    if not inventory.duplicates:
        return []
    out = [paint("DUPLICATES AND COLLISIONS", "\033[1m"), "─" * width]
    for group in inventory.duplicates:
        out.append(
            "  "
            + paint(group.kind.value, _COLORS[Status.NEEDS_REVIEW])
            + f"  key={_truncate(group.key, 40)}  (matched on {group.key_tier.value})"
        )
        for source in group.source_files:
            out.append(f"      - {_path(source, width - 10)}")
        out.append(f"      {_truncate(group.note, width - 8)}")
    out.append("")
    return out


def _problem_block(inventory: DeviceInventory, paint: _Painter, width: int) -> List[str]:
    """Files that produced no audit, listed explicitly so they cannot be missed."""
    problems = [
        device for device in inventory.devices if device.status is not DeviceStatus.AUDITED
    ]
    if not problems:
        return []

    out = [paint("FILES NOT AUDITED", "\033[1m"), "─" * width]
    for device in problems:
        out.append(
            "  "
            + paint(device.status.value.ljust(16), _STATUS_COLORS.get(device.status))
            + _path(device.source_file, width - 22)
        )
        if device.error:
            out.append(f"      {_truncate(device.error, width - 8)}")
    out.append("")
    return out


def _or_null(value: Optional[str]) -> str:
    """``null`` is a result, and it is printed as one."""
    return value if value else "null"


def _path(text: str, width: int) -> str:
    """Shorten a path from the left, because the filename is the part worth keeping.

    Truncating ``.../uploads/site-a/closet-3/edge-sw-04.conf`` from the right
    leaves the operator with a directory prefix they already knew and no idea
    which file is being discussed.
    """
    text = str(text)
    if len(text) <= width:
        return text
    return "…" + text[-(width - 1) :]
