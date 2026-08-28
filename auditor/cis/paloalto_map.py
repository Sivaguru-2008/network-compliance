"""
CIS Palo Alto Firewall 11 → SecurityBaselineModel mapping.

Each entry classifies a CIS recommendation by whether the current parser +
baseline can evaluate it deterministically, needs parser extension, or
requires manual/human review.

This module loads the authoritative mapping from paloalto_map.json and
validates it at runtime against the SecurityBaselineModel schema.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from auditor.cis.schema import EvaluationType
from auditor.models.baseline import SecurityBaselineModel


@dataclass(frozen=True)
class RuleMapping:
    """How one CIS recommendation maps to the evaluation pipeline."""

    cis_id: str
    baseline_field: Optional[str]
    internal_control: Optional[str]
    evaluation_type: EvaluationType
    condition_json: Optional[dict]
    gap_note: str = ""


def _collect_fields_from_condition(cond: dict) -> List[str]:
    """Recursively collect all field names referenced in a condition dictionary."""
    fields = []
    if "field" in cond:
        fields.append(cond["field"])
    if "all_of" in cond:
        for sub in cond["all_of"]:
            if isinstance(sub, dict):
                fields.extend(_collect_fields_from_condition(sub))
    if "any_of" in cond:
        for sub in cond["any_of"]:
            if isinstance(sub, dict):
                fields.extend(_collect_fields_from_condition(sub))
    if "not" in cond:
        if isinstance(cond["not"], dict):
            fields.extend(_collect_fields_from_condition(cond["not"]))
    return fields


def _reject_duplicates(pairs):
    """JSON decoder hook to reject duplicate keys."""
    seen = set()
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"Duplicate rule ID found in mapping: {key}")
        seen.add(key)
    return dict(pairs)


def load_and_validate_mappings(json_path: Path) -> Dict[str, RuleMapping]:
    """Load mappings from JSON and validate their integrity."""
    if not json_path.is_file():
        raise FileNotFoundError(f"Palo Alto mapping file not found at {json_path}")

    try:
        content = json_path.read_text(encoding="utf-8")
        raw_map = json.loads(content, object_pairs_hook=_reject_duplicates)
    except json.JSONDecodeError as e:
        raise ValueError(f"Malformed JSON in mapping file: {e}")

    valid_fields = set(SecurityBaselineModel.observable_fields())
    rule_map: Dict[str, RuleMapping] = {}

    for rule_id, raw in raw_map.items():
        # Validate that the dict contains all required keys
        required_keys = {"cis_id", "baseline_field", "internal_control", "evaluation_type", "condition_json"}
        missing = required_keys - raw.keys()
        if missing:
            raise ValueError(f"Control {rule_id} is missing required keys: {missing}")

        # Validate evaluation type
        try:
            eval_type = EvaluationType(raw["evaluation_type"])
        except ValueError:
            raise ValueError(f"Invalid evaluation_type for control {rule_id}: {raw['evaluation_type']}")

        # Validate baseline_field if present
        b_field = raw.get("baseline_field")
        if b_field and b_field not in valid_fields:
            raise ValueError(f"Unknown baseline field {b_field!r} referenced by control {rule_id}")

        # Validate condition_json fields if present
        cond = raw.get("condition_json")
        if cond:
            if not isinstance(cond, dict):
                raise ValueError(f"condition_json for control {rule_id} must be a dictionary")
            referenced = _collect_fields_from_condition(cond)
            for f in referenced:
                if f not in valid_fields:
                    raise ValueError(f"Unknown baseline field {f!r} referenced in condition for control {rule_id}")

        # Build mapping
        rule_map[rule_id] = RuleMapping(
            cis_id=raw["cis_id"],
            baseline_field=raw["baseline_field"],
            internal_control=raw["internal_control"],
            evaluation_type=eval_type,
            condition_json=raw["condition_json"],
            gap_note=raw.get("gap_note", ""),
        )

    return rule_map


# Load the authoritative mapping at module import time
MAP_JSON_PATH = Path(__file__).parent / "paloalto_map.json"
PALOALTO_RULE_MAP: Dict[str, RuleMapping] = load_and_validate_mappings(MAP_JSON_PATH)


def get_coverage_summary() -> Dict[str, List[str]]:
    """Return CIS IDs grouped by evaluation type."""
    result: Dict[str, List[str]] = {t.value: [] for t in EvaluationType}
    for cis_id, mapping in PALOALTO_RULE_MAP.items():
        result[mapping.evaluation_type.value].append(cis_id)
    return result
