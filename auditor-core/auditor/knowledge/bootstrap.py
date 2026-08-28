import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from .db import init_db, get_db_connection
from .repository import save_source, save_control

RULES_DIR = Path(__file__).parents[1] / "rules"
FRAMEWORKS_DIR = RULES_DIR / "frameworks"
REMEDIATIONS_DIR = RULES_DIR / "remediations"
CONTROLS_PATH = RULES_DIR / "security_controls.json"

def get_file_hash(path: Path) -> str:
    content = path.read_bytes()
    return hashlib.sha256(content).hexdigest()

def bootstrap_database_if_empty() -> bool:
    """Check if the database is empty, and if so, bootstrap from the static JSON rules files."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as count FROM controls")
    row = cursor.fetchone()
    count = row["count"] if row else 0
    conn.close()
    
    if count > 0:
        return False  # Already bootstrapped / has content
        
    print("Initializing compliance knowledge base from static rule packs...")
    
    # 1. Load security controls
    if not CONTROLS_PATH.is_file():
        print(f"Warning: Security controls file not found at {CONTROLS_PATH}")
        return False
        
    try:
        controls_data = json.loads(CONTROLS_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Error loading security controls: {exc}")
        return False
        
    # 2. Find framework mapping files
    if not FRAMEWORKS_DIR.is_dir():
        print(f"Warning: Frameworks directory not found at {FRAMEWORKS_DIR}")
        return False
        
    # 3. Find platform remediations
    if not REMEDIATIONS_DIR.is_dir():
        print(f"Warning: Remediations directory not found at {REMEDIATIONS_DIR}")
        return False
        
    platform_files = list(REMEDIATIONS_DIR.glob("*.json"))
    platforms = [p.stem for p in platform_files]
    if not platforms:
        platforms = ["cisco_ios", "juniper_junos", "fortinet_fortios", "arista_eos", "sonic_sonic"]
        
    # 4. Ingest each framework mapping file
    for fw_file in FRAMEWORKS_DIR.glob("*.json"):
        try:
            fw_content = fw_file.read_text(encoding="utf-8")
            fw_data = json.loads(fw_content)
            fw_hash = hashlib.sha256(fw_content.encode("utf-8")).hexdigest()
            fw_name = fw_data.get("framework_id", fw_file.stem).upper()
            fw_display_name = fw_data.get("name", fw_name)
            
            # Save framework source
            source_id = save_source(
                source_name=f"Authoritative {fw_name} Rule Pack",
                source_type="file",
                source_url_or_path=str(fw_file.resolve()),
                source_version=fw_data.get("version") or "1.0",
                source_date="2026-08-24",
                content_hash=fw_hash,
                validation_status="APPROVED"
            )
            
            # For each platform, compile rules and insert
            for platform in platforms:
                # Load remediation file
                rem_path = REMEDIATIONS_DIR / f"{platform}.json"
                remediations_data = {}
                if rem_path.is_file():
                    try:
                        remediations_data = json.loads(rem_path.read_text(encoding="utf-8"))
                    except Exception:
                        pass
                
                parts = platform.split("_", 1)
                vendor = parts[0] if len(parts) > 1 else platform
                
                version_val = (
                    fw_data.get("versions", {}).get(platform) or 
                    fw_data.get("versions", {}).get("default") or 
                    fw_data.get("version", "1.0")
                )
                
                source_note_val = (
                    fw_data.get("source_notes", {}).get(platform) or 
                    fw_data.get("source_note") or 
                    fw_data.get("description")
                )
                
                mappings = fw_data.get("mappings", {})
                for control_id, plat_mappings in mappings.items():
                    mapping = plat_mappings.get(platform) or plat_mappings.get("default")
                    if not mapping:
                        continue
                        
                    control_def = controls_data.get(control_id)
                    if not control_def:
                        continue
                        
                    rem_def = remediations_data.get(control_id) or {}
                    rem_summary = rem_def.get("summary", "No remediation provided.")
                    rem_cli = rem_def.get("cli", [])
                    rem_provenance = rem_def.get("provenance", "VERIFIED")
                    
                    # Extract fields referenced in condition for evidence_requirements
                    from ..models.rule import LeafCondition, AllOfCondition, AnyOfCondition, NotCondition
                    # Rather than importing referenced_fields and parsing, we can just extract from the condition dictionary:
                    def extract_fields(cond_dict: dict) -> list:
                        fields = set()
                        if "field" in cond_dict:
                            fields.add(cond_dict["field"])
                        if "all_of" in cond_dict:
                            for c in cond_dict["all_of"]:
                                fields.update(extract_fields(c))
                        if "any_of" in cond_dict:
                            for c in cond_dict["any_of"]:
                                fields.update(extract_fields(c))
                        if "not" in cond_dict:
                            fields.update(extract_fields(cond_dict["not"]))
                        return list(fields)
                    
                    ev_reqs = extract_fields(control_def["condition"])
                    verified_val = 1 if mapping.get("verified", True) else 0
                    
                    save_control(
                        framework=fw_name,
                        framework_version=version_val,
                        control_id=mapping["id"],
                        title=control_def["title"],
                        requirement=control_def.get("description"), # Use description as baseline requirement
                        description=control_def.get("description"),
                        severity=control_def["severity"],
                        vendor=vendor.capitalize(),
                        platform=platform,
                        evidence_requirements=ev_reqs,
                        pass_condition=control_def["condition"],
                        remediation_summary=rem_summary,
                        remediation_cli=rem_cli,
                        references=mapping.get("references", [f"{fw_name} - {mapping.get('control_ref') or control_id}"]),
                        source_id=source_id,
                        source_location=mapping.get("control_ref"),
                        validation_status="APPROVED",
                        internal_control_id=control_id,
                        source_note=source_note_val,
                        framework_display_name=fw_display_name,
                        verified_ref=verified_val,
                        remediation_provenance=rem_provenance
                    )
                    
        except Exception as exc:
            print(f"Error bootstrapping framework {fw_file.name}: {exc}")
            import traceback
            traceback.print_exc()
            
    print("Database bootstrapper finished.")
    return True
