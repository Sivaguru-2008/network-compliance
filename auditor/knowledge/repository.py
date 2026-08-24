import shutil
import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from .db import get_db_connection, DB_PATH

def save_source(
    source_name: str,
    source_type: str,
    source_url_or_path: Optional[str] = None,
    source_version: Optional[str] = None,
    source_date: Optional[str] = None,
    content_hash: Optional[str] = None,
    validation_status: str = "APPROVED"
) -> int:
    """Save a source and return its rowid."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    timestamp = datetime.now(timezone.utc).isoformat()
    
    cursor.execute("""
    INSERT INTO sources (
        source_name, source_type, source_url_or_path, source_version,
        source_date, content_hash, ingestion_timestamp, validation_status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        source_name, source_type, source_url_or_path, source_version,
        source_date, content_hash, timestamp, validation_status
    ))
    source_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return source_id

def save_control(
    framework: str,
    framework_version: str,
    control_id: str,
    title: str,
    requirement: Optional[str],
    description: Optional[str],
    severity: str,
    vendor: str,
    platform: str,
    evidence_requirements: List[str],
    pass_condition: Dict[str, Any],
    remediation_summary: str,
    remediation_cli: List[str],
    references: List[str],
    source_id: Optional[int] = None,
    source_location: Optional[str] = None,
    validation_status: str = "VALIDATION_PENDING",
    fail_condition: Optional[Dict[str, Any]] = None,
    needs_review_condition: Optional[Dict[str, Any]] = None,
    platform_version: str = "default",
    internal_control_id: Optional[str] = None,
    source_note: Optional[str] = None,
    framework_display_name: Optional[str] = None,
    verified_ref: int = 1
) -> int:
    """Save or replace a compliance control."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    timestamp = datetime.now(timezone.utc).isoformat()
    
    cursor.execute("""
    INSERT INTO controls (
        framework, framework_version, framework_display_name, control_id, internal_control_id, verified_ref, title, requirement, description,
        severity, vendor, platform, platform_version, evidence_requirements,
        pass_condition, fail_condition, needs_review_condition,
        remediation_summary, remediation_cli, references_json,
        source_id, source_location, source_note, ingestion_timestamp, validation_status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        framework, framework_version, framework_display_name, control_id, internal_control_id, verified_ref, title, requirement, description,
        severity.lower(), vendor, platform, platform_version,
        json.dumps(evidence_requirements),
        json.dumps(pass_condition),
        json.dumps(fail_condition) if fail_condition else None,
        json.dumps(needs_review_condition) if needs_review_condition else None,
        remediation_summary,
        json.dumps(remediation_cli),
        json.dumps(references),
        source_id, source_location, source_note, timestamp, validation_status
    ))
    control_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return control_id

def get_controls_for_framework(
    framework: str,
    platform: str,
    version: Optional[str] = None,
    include_unapproved: bool = False
) -> List[Dict[str, Any]]:
    """Retrieve controls matching framework, platform, and optional version."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
    SELECT c.*, s.source_name, s.source_type, s.source_url_or_path, s.source_version, s.source_date
    FROM controls c
    LEFT JOIN sources s ON c.source_id = s.id
    WHERE LOWER(c.framework) = LOWER(?) AND LOWER(c.platform) = LOWER(?)
    """
    params = [framework, platform]
    
    if version:
        query += " AND c.framework_version = ?"
        params.append(version)
        
    if not include_unapproved:
        query += " AND c.validation_status = 'APPROVED'"
        
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    # Convert Row objects to dicts and parse JSON fields
    results = []
    for r in rows:
        d = dict(r)
        d["evidence_requirements"] = json.loads(d["evidence_requirements"]) if d["evidence_requirements"] else []
        d["pass_condition"] = json.loads(d["pass_condition"]) if d["pass_condition"] else {}
        d["fail_condition"] = json.loads(d["fail_condition"]) if d["fail_condition"] else None
        d["needs_review_condition"] = json.loads(d["needs_review_condition"]) if d["needs_review_condition"] else None
        d["remediation_cli"] = json.loads(d["remediation_cli"]) if d["remediation_cli"] else []
        d["references"] = json.loads(d["references_json"]) if d["references_json"] else []
        results.append(d)
        
    return results

def approve_control(control_id_val: str, framework: Optional[str] = None, platform: Optional[str] = None) -> int:
    """Approve matching control(s) by setting status to APPROVED."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if framework and platform:
        cursor.execute("""
        UPDATE controls SET validation_status = 'APPROVED'
        WHERE control_id = ? AND LOWER(framework) = LOWER(?) AND LOWER(platform) = LOWER(?)
        """, (control_id_val, framework, platform))
    else:
        cursor.execute("""
        UPDATE controls SET validation_status = 'APPROVED'
        WHERE control_id = ?
        """, (control_id_val,))
        
    changes = cursor.rowcount
    conn.commit()
    conn.close()
    return changes

def reject_control(control_id_val: str, framework: Optional[str] = None, platform: Optional[str] = None) -> int:
    """Reject matching control(s) by setting status to REJECTED."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if framework and platform:
        cursor.execute("""
        UPDATE controls SET validation_status = 'REJECTED'
        WHERE control_id = ? AND LOWER(framework) = LOWER(?) AND LOWER(platform) = LOWER(?)
        """, (control_id_val, framework, platform))
    else:
        cursor.execute("""
        UPDATE controls SET validation_status = 'REJECTED'
        WHERE control_id = ?
        """, (control_id_val,))
        
    changes = cursor.rowcount
    conn.commit()
    conn.close()
    return changes

def list_controls(
    framework: Optional[str] = None,
    platform: Optional[str] = None,
    status: Optional[str] = None
) -> List[Dict[str, Any]]:
    """List controls matching optional filters."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM controls WHERE 1=1"
    params = []
    
    if framework:
        query += " AND LOWER(framework) = LOWER(?)"
        params.append(framework)
    if platform:
        query += " AND LOWER(platform) = LOWER(?)"
        params.append(platform)
    if status:
        query += " AND LOWER(validation_status) = LOWER(?)"
        params.append(status)
        
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_latest_framework_version(framework: str, platform: str) -> Optional[str]:
    """Get the latest version of a framework available for a platform."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT DISTINCT framework_version FROM controls
    WHERE LOWER(framework) = LOWER(?) AND LOWER(platform) = LOWER(?) AND validation_status = 'APPROVED'
    ORDER BY framework_version DESC LIMIT 1
    """, (framework, platform))
    row = cursor.fetchone()
    conn.close()
    return row["framework_version"] if row else None

def get_available_frameworks() -> List[Tuple[str, str]]:
    """Returns a list of all distinct (framework, version) pairs in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT DISTINCT framework, framework_version FROM controls
    WHERE validation_status = 'APPROVED'
    ORDER BY framework, framework_version
    """)
    rows = cursor.fetchall()
    conn.close()
    return [(r["framework"], r["framework_version"]) for r in rows]

def export_db(target_path: Path) -> None:
    """Copy the SQLite knowledge base file to a target destination."""
    target_path = Path(target_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(DB_PATH, target_path)

def import_db(source_path: Path) -> None:
    """Import a SQLite database file by copying it over the active DB."""
    source_path = Path(source_path)
    if not source_path.is_file():
        raise FileNotFoundError(f"Database file not found to import: {source_path}")
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, DB_PATH)
