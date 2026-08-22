"""Loading rule packs from disk.

Rule packs are plain JSON so that adding a framework (NIST 800-53, a DISA
STIG, an internal policy) means dropping a file into ``frameworks/`` -- no code
change, no redeploy.  Discovery reads each pack's header, so a new file is
picked up automatically by ``--framework``.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from pydantic import ValidationError

from ..models.rule import RuleSet

FRAMEWORKS_DIR = Path(__file__).parent / "frameworks"


class RuleLoadError(Exception):
    """A rule pack is missing, unreadable, or does not satisfy the schema."""


def load_ruleset(path: Path) -> RuleSet:
    """Load and validate a single rule pack."""
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


def discover_packs(search_dir: Optional[Path] = None) -> Dict[Tuple[str, str], Path]:
    """Map (FRAMEWORK, platform_key) -> pack path for every pack in ``search_dir``."""
    directory = Path(search_dir) if search_dir else FRAMEWORKS_DIR
    packs: Dict[Tuple[str, str], Path] = {}
    if not directory.is_dir():
        return packs
    for candidate in sorted(directory.glob("*.json")):
        try:
            header = json.loads(candidate.read_text(encoding="utf-8"))
            platform = header["platform"]
            key = (str(header["framework"]).upper(), f"{platform['vendor']}_{platform['os_family']}")
        except (json.JSONDecodeError, KeyError, TypeError):
            continue  # not a rule pack; discovery must never crash on a stray file
        packs[key] = candidate
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
    """Load the pack for a framework/platform pair, e.g. ('CIS', 'cisco_ios').

    With ``allow_cross_platform``, a pack written for a different platform may
    be used when none exists for this one. That is sound for the *conditions* -
    they only reference vendor-neutral baseline fields - but not for the
    remediation commands, which are written in one vendor's CLI. Callers that
    opt in are expected to surface :func:`platform_mismatch_note` in the report.
    """
    packs = discover_packs(search_dir)
    key = (framework.upper(), platform_key)
    if key in packs:
        return load_ruleset(packs[key])

    if allow_cross_platform:
        candidates = {k: v for k, v in packs.items() if k[0] == framework.upper()}
        if len(candidates) == 1:
            return load_ruleset(next(iter(candidates.values())))
        if len(candidates) > 1:
            options = ", ".join(sorted(p for _, p in candidates))
            raise RuleLoadError(
                f"No rule pack for framework {framework!r} on platform {platform_key!r}, and "
                f"several could substitute ({options}). Choose one with --rules."
            )

    available = ", ".join(f"{f}/{p}" for f, p in sorted(packs)) or "(none found)"
    raise RuleLoadError(
        f"No rule pack for framework {framework!r} on platform {platform_key!r}. Available: {available}"
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
