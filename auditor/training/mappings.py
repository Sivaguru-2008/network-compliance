import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from ..models.baseline import SecurityBaselineModel, SnmpCommunity
from ..models.observation import Observation, Origin
from ..parsers.llm.parser import FIELD_TYPES


class LearnedMapping(BaseModel):
    mapping_id: str
    vendor: str
    os_family: str = "unknown"
    pattern: str
    field: str
    extraction_strategy: str  # "exact", "token", "token_list", "regex"
    regex_pattern: Optional[str] = None
    compliance_control: Optional[str] = None
    creator: str = "administrator"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "pending"  # "pending", "approved", "disabled", "rejected", "conflicting", "deleted"
    version: int = 1
    evidence_example: Optional[str] = None
    approval_state: str = "pending"  # "pending", "approved", "rejected"


class LearnedMappingStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._records: List[LearnedMapping] = []
        self.load()

    def load(self) -> None:
        self._records = []
        if self.path.is_file():
            try:
                for line in self.path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    self._records.append(LearnedMapping.model_validate_json(line))
            except Exception:
                pass
        self._resolve_conflicts()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as handle:
            for record in self._records:
                handle.write(record.model_dump_json() + "\n")

    def _resolve_conflicts(self) -> None:
        """Find approved mappings with the same vendor, pattern, and field, but different rules.
        If a conflict is detected, mark their status as 'conflicting'.
        """
        # First, find the active (latest version of each mapping_id) approved mappings
        active_approved = {}
        for r in self._records:
            if r.status in ("approved", "conflicting") or r.approval_state == "approved":
                # Keep latest version
                key = r.mapping_id
                existing = active_approved.get(key)
                if not existing or r.version >= existing.version:
                    active_approved[key] = r

        # Now group these by (vendor, pattern, field) to check conflicts
        grouped = {}
        for r in active_approved.values():
            if r.status == "deleted" or r.status == "disabled":
                continue
            group_key = (r.vendor.lower(), r.pattern, r.field)
            grouped.setdefault(group_key, []).append(r)

        # Mark conflict status in memory if different mappings exist for same group
        conflicting_ids = set()
        for group_key, mappings in grouped.items():
            if len(mappings) > 1:
                # Check if they actually differ in strategy/regex/value/control
                first = mappings[0]
                has_diff = False
                for other in mappings[1:]:
                    if (other.extraction_strategy != first.extraction_strategy or
                        other.regex_pattern != first.regex_pattern or
                        other.compliance_control != first.compliance_control):
                        has_diff = True
                        break
                if has_diff:
                    for m in mappings:
                        conflicting_ids.add(m.mapping_id)

        # Update in-memory records status
        for r in self._records:
            if r.mapping_id in conflicting_ids:
                object.__setattr__(r, "status", "conflicting")
            elif r.status == "conflicting" and r.mapping_id not in conflicting_ids:
                object.__setattr__(r, "status", "approved")

    def get_active_approved_mappings(self) -> List[LearnedMapping]:
        """Get the latest version of all approved, non-conflicting mappings."""
        latest_by_id = {}
        for r in self._records:
            existing = latest_by_id.get(r.mapping_id)
            if not existing or r.version >= existing.version:
                latest_by_id[r.mapping_id] = r
        return [
            m for m in latest_by_id.values()
            if m.status == "approved" and m.approval_state == "approved"
        ]

    def create_mapping(self, mapping: LearnedMapping) -> LearnedMapping:
        # Check if the mapping_id already exists to version it
        existing = [r for r in self._records if r.mapping_id == mapping.mapping_id]
        if existing:
            latest_version = max(r.version for r in existing)
            new_mapping = mapping.model_copy(update={"version": latest_version + 1})
        else:
            new_mapping = mapping
        
        # Verify regex pattern if extraction_strategy is regex
        if new_mapping.extraction_strategy == "regex":
            if not new_mapping.regex_pattern:
                raise ValueError("Regex pattern is required for regex extraction strategy.")
            try:
                re.compile(new_mapping.regex_pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern: {e}")

        # Field validation: must be a field in SecurityBaselineModel
        if new_mapping.field not in SecurityBaselineModel.observable_fields():
            raise ValueError(f"Unknown baseline field: {new_mapping.field}")

        self._records.append(new_mapping)
        self._resolve_conflicts()
        self.save()
        return new_mapping

    def list_mappings(self) -> List[LearnedMapping]:
        latest_by_id = {}
        for r in self._records:
            existing = latest_by_id.get(r.mapping_id)
            if not existing or r.version >= existing.version:
                latest_by_id[r.mapping_id] = r
        return list(latest_by_id.values())

    def retrieve_mapping(self, mapping_id: str) -> Optional[LearnedMapping]:
        versions = [r for r in self._records if r.mapping_id == mapping_id]
        if not versions:
            return None
        return max(versions, key=lambda r: r.version)

    def approve_mapping(self, mapping_id: str) -> Optional[LearnedMapping]:
        latest = self.retrieve_mapping(mapping_id)
        if not latest:
            return None
        if latest.status == "approved" and latest.approval_state == "approved":
            return latest
        approved = latest.model_copy(update={
            "status": "approved",
            "approval_state": "approved",
            "version": latest.version + 1
        })
        self._records.append(approved)
        self._resolve_conflicts()
        self.save()
        return approved

    def disable_mapping(self, mapping_id: str) -> Optional[LearnedMapping]:
        latest = self.retrieve_mapping(mapping_id)
        if not latest:
            return None
        disabled = latest.model_copy(update={
            "status": "disabled",
            "version": latest.version + 1
        })
        self._records.append(disabled)
        self._resolve_conflicts()
        self.save()
        return disabled

    def reject_mapping(self, mapping_id: str) -> "LearnedMapping | None":
        latest = self.retrieve_mapping(mapping_id)
        if not latest:
            return None
        if latest.status == "rejected" and latest.approval_state == "rejected":
            return latest
        rejected = latest.model_copy(update={
            "status": "rejected",
            "approval_state": "rejected",
            "version": latest.version + 1,
        })
        self._records.append(rejected)
        self._resolve_conflicts()
        self.save()
        return rejected

    def delete_mapping(self, mapping_id: str) -> bool:
        latest = self.retrieve_mapping(mapping_id)
        if not latest:
            return False
        deleted = latest.model_copy(update={
            "status": "deleted",
            "version": latest.version + 1
        })
        self._records.append(deleted)
        self._resolve_conflicts()
        self.save()
        return True


def cast_value(val: Any, target_type: Any) -> Any:
    if target_type == bool:
        if isinstance(val, bool):
            return val
        s = str(val).strip().lower()
        return s in ("true", "yes", "1", "on", "enable", "enabled")
    elif target_type == int:
        return int(val)
    elif target_type == float:
        return float(val)
    elif target_type == str:
        return str(val)
    elif target_type == List[str] or getattr(target_type, "__origin__", None) is list:
        args = getattr(target_type, "__args__", None)
        if args and args[0] is SnmpCommunity:
            if not isinstance(val, list):
                val = [val]
            communities = []
            for item in val:
                if isinstance(item, SnmpCommunity):
                    communities.append(item)
                elif isinstance(item, dict):
                    communities.append(SnmpCommunity.model_validate(item))
                else:
                    communities.append(SnmpCommunity(name=str(item), source_line="learned", line_number=0))
            return communities
        else:
            if isinstance(val, list):
                return [str(x) for x in val]
            return [str(val)]
    return val


def resolve_learned_mappings(
    config_text: str,
    baseline: SecurityBaselineModel,
    store: LearnedMappingStore,
    stats_path: Optional[Path] = None,
) -> SecurityBaselineModel:
    def norm_vendor(v: str) -> str:
        val = v.lower()
        if "cisco" in val:
            return "cisco"
        if "juniper" in val or "junos" in val:
            return "juniper"
        if "forti" in val:
            return "fortinet"
        if "arista" in val:
            return "arista"
        if "sonic" in val:
            return "sonic"
        if "unknown" in val:
            return "unknown"
        return val

    approved = store.get_active_approved_mappings()
    if not approved:
        return baseline

    fields = SecurityBaselineModel.observable_fields()
    gaps = [
        f for f in fields
        if not getattr(baseline, f).detected or getattr(baseline, f).origin in (Origin.LLM, Origin.HYBRID)
    ]
    if not gaps:
        return baseline

    updated = baseline.model_copy(deep=True)
    lines = config_text.splitlines()
    any_avoided = False

    for field in gaps:
        field_type = FIELD_TYPES[field]
        field_mappings = [
            m for m in approved
            if m.field == field and norm_vendor(m.vendor) == norm_vendor(baseline.provenance.vendor)
        ]
        if not field_mappings:
            continue

        extracted_values = []
        matching_lines = []
        matching_mapping_ids = []

        for line_num, raw_line in enumerate(lines, 1):
            line_stripped = raw_line.strip()
            if not line_stripped:
                continue

            for mapping in field_mappings:
                matched = False
                val = None
                if mapping.extraction_strategy == "regex":
                    try:
                        match = re.search(mapping.regex_pattern, line_stripped)
                        if match:
                            matched = True
                            val = match.group(1) if match.groups() else match.group(0)
                    except Exception:
                        pass
                else:
                    if mapping.pattern in line_stripped:
                        matched = True
                        if mapping.extraction_strategy == "exact":
                            val = True
                        elif mapping.extraction_strategy == "token":
                            pos = line_stripped.find(mapping.pattern)
                            remainder = line_stripped[pos + len(mapping.pattern):].strip()
                            tokens = remainder.split()
                            val = tokens[0] if tokens else None
                        elif mapping.extraction_strategy == "token_list":
                            pos = line_stripped.find(mapping.pattern)
                            remainder = line_stripped[pos + len(mapping.pattern):].strip()
                            val = remainder.split()

                if matched and val is not None:
                    try:
                        casted = cast_value(val, field_type)
                        extracted_values.append(casted)
                        matching_lines.append((line_num, raw_line))
                        matching_mapping_ids.append(mapping.mapping_id)
                    except Exception:
                        pass

        if extracted_values:
            final_value = None
            if field_type == list or getattr(field_type, "__origin__", None) is list:
                args = getattr(field_type, "__args__", None)
                if args and args[0] is SnmpCommunity:
                    merged = []
                    for v in extracted_values:
                        merged.extend(v)
                    seen_names = set()
                    final_value = []
                    for community in merged:
                        if community.name not in seen_names:
                            seen_names.add(community.name)
                            final_value.append(community)
                else:
                    merged = []
                    for v in extracted_values:
                        if isinstance(v, list):
                            merged.extend(v)
                        else:
                            merged.append(v)
                    final_value = list(dict.fromkeys(merged))
            elif field_type == bool:
                final_value = any(extracted_values)
            else:
                final_value = extracted_values[-1]

            last_line_num, last_raw_line = matching_lines[-1]
            last_mapping_id = matching_mapping_ids[-1]

            obs = Observation[field_type].found(
                value=final_value,
                source_line=last_raw_line,
                line_number=last_line_num,
                origin=Origin.LEARNED,
                confidence=1.0,
                note=f"Resolved via approved mapping #{last_mapping_id}",
            )
            # Set traceability attributes
            object.__setattr__(obs, "mapping_id", last_mapping_id)
            object.__setattr__(obs, "original_line", last_raw_line)
            object.__setattr__(obs, "original_line_number", last_line_num)

            setattr(updated, field, obs)
            any_avoided = True

    if any_avoided:
        updated.provenance.warnings.append(
            "Some fields resolved via approved learned mappings; avoided LLM calls."
        )
        if stats_path:
            increment_llm_calls_avoided(stats_path)

    return updated


def increment_llm_calls_avoided(stats_path: Path) -> None:
    stats_path = Path(stats_path)
    data = {"llm_calls_avoided": 0}
    if stats_path.is_file():
        try:
            data = json.loads(stats_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    data["llm_calls_avoided"] = data.get("llm_calls_avoided", 0) + 1
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    stats_path.write_text(json.dumps(data), encoding="utf-8")


def get_llm_calls_avoided(stats_path: Path) -> int:
    stats_path = Path(stats_path)
    if stats_path.is_file():
        try:
            data = json.loads(stats_path.read_text(encoding="utf-8"))
            return data.get("llm_calls_avoided", 0)
        except Exception:
            pass
    return 0


def get_used_line_numbers(baseline: SecurityBaselineModel) -> Set[int]:
    used = set()
    for field in SecurityBaselineModel.observable_fields():
        obs = getattr(baseline, field)
        if obs.detected and obs.line_number:
            used.add(obs.line_number)
        if isinstance(obs.value, list):
            for item in obs.value:
                line_num = getattr(item, "line_number", None)
                if line_num:
                    used.add(line_num)
    return used


def get_unrecognized_lines(config_text: str, baseline: SecurityBaselineModel) -> List[Dict[str, Any]]:
    used_lines = get_used_line_numbers(baseline)
    unrecognized = []
    for idx, line in enumerate(config_text.splitlines(), 1):
        line_stripped = line.strip()
        if not line_stripped:
            continue
        if line_stripped.startswith("!") or line_stripped.startswith("#") or line_stripped.startswith("/*"):
            continue
        if line_stripped in ("end", "next", "exit"):
            continue
        if idx not in used_lines:
            unrecognized.append({
                "line_number": idx,
                "text": line_stripped
            })
    return unrecognized


def check_all_unrecognized_lines_matched(
    unrecognized_lines: List[Dict[str, Any]],
    approved_mappings: List[LearnedMapping]
) -> bool:
    if not unrecognized_lines:
        return True
    for line in unrecognized_lines:
        line_text = line["text"]
        matched_any = False
        for mapping in approved_mappings:
            if mapping.extraction_strategy == "regex":
                try:
                    if re.search(mapping.regex_pattern, line_text):
                        matched_any = True
                        break
                except Exception:
                    pass
            else:
                if line_text.startswith(mapping.pattern) or mapping.pattern in line_text:
                    matched_any = True
                    break
        if not matched_any:
            return False
    return True
