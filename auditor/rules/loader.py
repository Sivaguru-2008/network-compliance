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


def load_framework(framework: str, platform_key: str, search_dir: Optional[Path] = None) -> RuleSet:
    """Load the pack for a framework/platform pair, e.g. ('CIS', 'cisco_ios')."""
    packs = discover_packs(search_dir)
    key = (framework.upper(), platform_key)
    if key not in packs:
        available = ", ".join(f"{f}/{p}" for f, p in sorted(packs)) or "(none found)"
        raise RuleLoadError(
            f"No rule pack for framework {framework!r} on platform {platform_key!r}. Available: {available}"
        )
    return load_ruleset(packs[key])
