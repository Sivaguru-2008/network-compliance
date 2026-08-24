"""Loading rule packs from disk.

Rule packs are dynamically assembled from framework mappings, security controls,
and vendor remediations. This separates the security intent (conditions) from the
vendor-specific fix (remediations) and the framework citation (control references).
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pydantic import ValidationError

from ..models.rule import RuleSet, ComplianceRule, Platform, Remediation

FRAMEWORKS_DIR = Path(__file__).parent / "frameworks"
REMEDIATIONS_DIR = Path(__file__).parent / "remediations"
CONTROLS_PATH = Path(__file__).parent / "security_controls.json"


class RuleLoadError(Exception):
    """A rule pack is missing, unreadable, or does not satisfy the schema."""


def load_ruleset(path: Path) -> RuleSet:
    """Load and validate a single rule pack (for backward compatibility)."""
    path = Path(path)
    if not path.is_file():
        raise RuleLoadError(f"Rule pack not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuleLoadError(f"{path.name} is not valid JSON: {exc}") from exc
    try:
        return RuleSet.model_validate(payload)
    except ValidationError as exc:
        raise RuleLoadError(f"{path.name} does not satisfy the rule schema:\n{exc}") from exc


def _normalize_framework_name(framework: str) -> str:
    fw = framework.lower().strip()
    if fw in ("cis", "cis benchmarks"):
        return "cis"
    if fw in ("nist_800_53", "nist sp 800-53", "nist-800-53", "nist sp 800-53 rev. 5", "nistsp80053"):
        return "nist_800_53"
    if fw in ("disa_stig", "disa stigs", "disa stig", "stigs"):
        return "stig"
    if fw in ("iso_27001", "iso/iec 27001", "iso27001", "iso-27001"):
        return "iso_27001"
    return fw


def discover_packs(search_dir: Optional[Path] = None) -> Dict[Tuple[str, str], Path]:
    """Map (FRAMEWORK, platform_key) -> pack path for every pack in ``search_dir``."""
    directory = Path(search_dir) if search_dir else FRAMEWORKS_DIR
    packs: Dict[Tuple[str, str], Path] = {}
    if not directory.is_dir():
        return packs

    # 1. Scan for old-style JSON rule packs (like cis_cisco_ios.json)
    for candidate in sorted(directory.glob("*.json")):
        # If the filename contains "_" and isn't one of the new framework files, it could be old-style
        if candidate.stem in ("cis", "nist_800_53", "stig", "iso_27001"):
            continue
        try:
            header = json.loads(candidate.read_text(encoding="utf-8"))
            if "platform" in header and isinstance(header["platform"], dict) and "vendor" in header["platform"]:
                platform = header["platform"]
                key = (str(header["framework"]).upper(), f"{platform['vendor']}_{platform['os_family']}")
                packs[key] = candidate
        except Exception:
            continue

    # 2. Add new-style framework mappings for all known platforms
    rem_dir = search_dir.parent / "remediations" if search_dir else REMEDIATIONS_DIR
    platforms = []
    if rem_dir.is_dir():
        for r_file in rem_dir.glob("*.json"):
            platforms.append(r_file.stem)
    if not platforms:
        platforms = ["cisco_ios", "juniper_junos", "fortinet_fortios"]

    framework_ids = ["cis", "nist_800_53", "stig", "iso_27001"]
    for fw in framework_ids:
        fw_file = directory / f"{fw}.json"
        if fw_file.is_file():
            fw_name = fw.upper()
            if fw == "nist_800_53":
                fw_name = "NIST_800_53"
            elif fw == "iso_27001":
                fw_name = "ISO_27001"
            for plat in platforms:
                key = (fw_name, plat)
                if key not in packs:
                    packs[key] = fw_file

    return packs


def available_frameworks(search_dir: Optional[Path] = None) -> List[str]:
    return sorted({framework for framework, _ in discover_packs(search_dir)})


def load_framework(
    framework: str,
    platform_key: str,
    search_dir: Optional[Path] = None,
    *,
    allow_cross_platform: bool = False,
) -> RuleSet:
    """Load the pack for a framework/platform pair, e.g. ('CIS', 'cisco_ios')."""
    packs = discover_packs(search_dir)
    key = (framework.upper(), platform_key)

    # 1. Support direct loading of old-style JSON rule packs
    if key in packs:
        pack_path = packs[key]
        try:
            header = json.loads(pack_path.read_text(encoding="utf-8"))
            if "rules" in header:
                return load_ruleset(pack_path)
        except Exception:
            pass

    # 2. Perform dynamic compilation for new-style frameworks
    fw_clean = _normalize_framework_name(framework)
    fw_dir = Path(search_dir) if search_dir else FRAMEWORKS_DIR
    fw_path = fw_dir / f"{fw_clean}.json"

    if not fw_path.is_file():
        available = ", ".join(f"{f}/{p}" for f, p in sorted(packs)) or "(none found)"
        raise RuleLoadError(
            f"No rule pack for framework {framework!r} on platform {platform_key!r}. Available: {available}"
        )

    parts = platform_key.split("_", 1)
    if len(parts) == 2:
        vendor, os_family = parts[0], parts[1]
    else:
        vendor, os_family = platform_key, "unknown"

    if vendor == "fortinet":
        os_family = "fortios"
    elif vendor == "juniper":
        os_family = "junos"

    try:
        fw_data = json.loads(fw_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuleLoadError(f"Failed to load framework mapping {fw_path.name}: {exc}")

    controls_file = CONTROLS_PATH
    if not controls_file.is_file():
        controls_file = Path(__file__).parent / "security_controls.json"
    if not controls_file.is_file():
        raise RuleLoadError(f"Security controls registry not found: {controls_file}")

    try:
        controls_data = json.loads(controls_file.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuleLoadError(f"Failed to load security controls: {exc}")

    rem_dir = Path(search_dir).parent / "remediations" if search_dir else REMEDIATIONS_DIR
    if not rem_dir.is_dir():
        rem_dir = Path(__file__).parent / "remediations"
    rem_path = rem_dir / f"{platform_key}.json"

    remediations_data = {}
    if rem_path.is_file():
        try:
            remediations_data = json.loads(rem_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuleLoadError(f"Failed to load remediations for {platform_key}: {exc}")

    rules = []
    mappings = fw_data.get("mappings", {})

    for control_id, plat_mappings in mappings.items():
        mapping = plat_mappings.get(platform_key) or plat_mappings.get("default")
        if not mapping:
            continue

        control_def = controls_data.get(control_id)
        if not control_def:
            continue

        rem_def = remediations_data.get(control_id) or {}
        remediation = Remediation(
            summary=rem_def.get("summary", "No remediation provided."),
            cli=rem_def.get("cli", [])
        )

        try:
            rule = ComplianceRule(
                id=mapping["id"],
                control_ref=mapping.get("control_ref"),
                internal_control_id=control_id,
                verified_ref=mapping.get("verified", True),
                title=control_def["title"],
                description=control_def["description"],
                framework=fw_data["name"],
                severity=control_def["severity"],
                condition=control_def["condition"],
                rationale=control_def.get("rationale") or rem_def.get("notes"),
                remediation=remediation,
                references=mapping.get("references", [f"{fw_data['name']} - {mapping.get('control_ref') or control_id}"]),
                notes=rem_def.get("notes")
            )
            rules.append(rule)
        except ValidationError as exc:
            raise RuleLoadError(f"Failed to construct rule for {control_id}: {exc}")

    if not rules:
        raise RuleLoadError(f"No rules constructed for framework {framework} on platform {platform_key}")

    return RuleSet(
        schema_version="1.0",
        framework=fw_data["name"],
        framework_version=fw_data.get("versions", {}).get(platform_key) or fw_data.get("versions", {}).get("default") or fw_data.get("version", "1.0"),
        platform=Platform(vendor=vendor, os_family=os_family),
        source_note=fw_data.get("source_notes", {}).get(platform_key) or fw_data.get("source_note") or fw_data.get("description"),
        rules=rules
    )


def platform_mismatch_note(ruleset: RuleSet, vendor: str, os_family: str) -> Optional[str]:
    """Warn when a pack's remediation CLI was written for a different platform."""
    pack_platform = f"{ruleset.platform.vendor}/{ruleset.platform.os_family}"
    device_platform = f"{vendor}/{os_family}"
    if pack_platform == device_platform:
        return None
    return (
        f"Rule pack targets {pack_platform} but this device was identified as {device_platform}. "
        "The pass/fail conditions are vendor-neutral and still apply; the remediation commands "
        f"are written in {pack_platform} syntax and must be translated before use."
    )
