"""SQLite database schema and data access layers.

Persists device inventories, audited configurations, control findings,
runs, and generated PDF paths, making them survive application restart.
"""

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime
import hashlib


def get_db_connection(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path) -> None:
    """Initialize the SQLite database schema if tables do not exist."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        
        # 1. Devices
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                device_key TEXT PRIMARY KEY,
                hostname TEXT,
                vendor TEXT,
                os_family TEXT,
                serial_number TEXT,
                status TEXT,
                ingest_error TEXT,
                ingested_at TEXT,
                source_file TEXT,
                source_hash TEXT
            )
        """)

        # 2. Configurations
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS configurations (
                source_hash TEXT PRIMARY KEY,
                config_text TEXT
            )
        """)

        # 3. Audit Runs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_runs (
                run_id TEXT PRIMARY KEY,
                device_key TEXT,
                run_at TEXT,
                summary_json TEXT
            )
        """)

        # 4. Findings
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                device_key TEXT,
                framework TEXT,
                control_id TEXT,
                status TEXT,
                severity TEXT,
                title TEXT,
                category TEXT,
                evidence TEXT,
                line_number INTEGER,
                remediation TEXT
            )
        """)

        # 5. Reports
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                report_id TEXT PRIMARY KEY,
                device_key TEXT,
                generated_at TEXT,
                pdf_path TEXT,
                json_path TEXT
            )
        """)
        
        conn.commit()
    finally:
        conn.close()


def save_audit_result(
    db_path: Path,
    record: Any,
    config_text: str,
    pdf_path: Optional[str] = None,
    json_path: Optional[str] = None
) -> None:
    """Insert or update device, configuration, and compliance findings in SQLite."""
    init_db(db_path)
    
    device_key = record.device_key or f"file:{record.source_hash}"
    source_hash = record.source_hash
    ingested_at_str = record.ingested_at.isoformat() if hasattr(record.ingested_at, "isoformat") else str(record.ingested_at)
    
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        
        # 1. Save Configuration
        if source_hash and config_text:
            cursor.execute(
                "INSERT OR REPLACE INTO configurations (source_hash, config_text) VALUES (?, ?)",
                (source_hash, config_text)
            )
            
        # 2. Save Device Metadata
        cursor.execute("""
            INSERT OR REPLACE INTO devices (
                device_key, hostname, vendor, os_family, serial_number, status, ingest_error, ingested_at, source_file, source_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            device_key,
            record.identity.field_value("hostname") or "unknown",
            record.identity.vendor or "unknown",
            record.identity.os_family or "unknown",
            record.identity.field_value("serial_number") or None,
            record.status.value if hasattr(record.status, "value") else str(record.status),
            record.error,
            ingested_at_str,
            record.source_file,
            source_hash
        ))

        # 3. Save Audit Run
        run_id = f"RUN-{hashlib_short(device_key + ingested_at_str)}"
        summary_data = {
            "passed": record.summary.passed if hasattr(record.summary, "passed") else 0,
            "failed": record.summary.failed if hasattr(record.summary, "failed") else 0,
            "needs_review": record.summary.needs_review if hasattr(record.summary, "needs_review") else 0,
        }
        cursor.execute("""
            INSERT OR REPLACE INTO audit_runs (run_id, device_key, run_at, summary_json)
            VALUES (?, ?, ?, ?)
        """, (
            run_id,
            device_key,
            ingested_at_str,
            json.dumps(summary_data)
        ))

        # 4. Save Findings
        # Clear old findings for this device first to prevent duplicates
        cursor.execute("DELETE FROM findings WHERE device_key = ?", (device_key,))
        
        for finding in record.findings:
            finding_id = f"FND-{hashlib_short(device_key + finding.framework + finding.rule_id)}"
            remediation_str = ""
            if hasattr(finding, "remediation") and finding.remediation:
                remediation_str = json.dumps({
                    "summary": finding.remediation.summary,
                    "cli": finding.remediation.cli
                })
            
            evidence_str = ""
            if hasattr(finding, "evidence_line"):
                evidence_str = finding.evidence_line
            elif hasattr(finding, "evidence") and finding.evidence:
                if isinstance(finding.evidence, list):
                    evidence_str = "; ".join(getattr(ev, "display", str(ev)) for ev in finding.evidence)
                else:
                    evidence_str = str(finding.evidence)
            
            line_num = 1
            if hasattr(finding, "line_number") and finding.line_number:
                line_num = finding.line_number
            elif hasattr(finding, "evidence") and finding.evidence and isinstance(finding.evidence, list):
                # Fallback to line number of first evidence item
                line_num = getattr(finding.evidence[0], "line_number", 1) or 1
            
            cursor.execute("""
                INSERT INTO findings (
                    finding_id, device_key, framework, control_id, status, severity, title, category, evidence, line_number, remediation
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding_id,
                device_key,
                finding.framework,
                finding.rule_id,
                finding.status.value if hasattr(finding.status, "value") else str(finding.status),
                finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                finding.title,
                finding.category if hasattr(finding, "category") else "",
                evidence_str,
                line_num,
                remediation_str
            ))

        # 5. Save Report
        if pdf_path or json_path:
            report_id = f"REP-{hashlib_short(device_key + ingested_at_str)}"
            cursor.execute("""
                INSERT OR REPLACE INTO reports (report_id, device_key, generated_at, pdf_path, json_path)
                VALUES (?, ?, ?, ?, ?)
            """, (
                report_id,
                device_key,
                ingested_at_str,
                pdf_path,
                json_path
            ))
            
        conn.commit()
    finally:
        conn.close()


def list_devices(db_path: Path) -> List[Dict[str, Any]]:
    init_db(db_path)
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices ORDER BY ingested_at DESC")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_device(db_path: Path, device_key: str) -> Optional[Dict[str, Any]]:
    init_db(db_path)
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices WHERE device_key = ?", (device_key,))
        row = cursor.fetchone()
        if not row:
            return None
        
        device = dict(row)
        
        # Join configuration
        cursor.execute("SELECT config_text FROM configurations WHERE source_hash = ?", (device["source_hash"],))
        conf_row = cursor.fetchone()
        device["config_text"] = conf_row["config_text"] if conf_row else None
        
        return device
    finally:
        conn.close()


def get_device_findings(db_path: Path, device_key: str) -> List[Dict[str, Any]]:
    init_db(db_path)
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE device_key = ?", (device_key,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_device_reports(db_path: Path, device_key: str) -> List[Dict[str, Any]]:
    init_db(db_path)
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM reports WHERE device_key = ? ORDER BY generated_at DESC", (device_key,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def list_findings(db_path: Path) -> List[Dict[str, Any]]:
    init_db(db_path)
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT f.*, d.hostname, d.vendor, d.os_family 
            FROM findings f 
            JOIN devices d ON f.device_key = d.device_key
        """)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def list_reports(db_path: Path) -> List[Dict[str, Any]]:
    init_db(db_path)
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.*, d.hostname, d.vendor 
            FROM reports r 
            JOIN devices d ON r.device_key = d.device_key
            ORDER BY r.generated_at DESC
        """)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_dashboard_stats(db_path: Path) -> Dict[str, Any]:
    """Calculate summary metrics for the home dashboard view."""
    init_db(db_path)
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        
        # 1. Total devices
        cursor.execute("SELECT COUNT(*) FROM devices")
        total_devices = cursor.fetchone()[0]
        
        # 2. Compliant vs Non-Compliant vs Needs Review counts
        cursor.execute("SELECT device_key FROM devices")
        device_keys = [r[0] for r in cursor.fetchall()]
        
        compliant = 0
        non_compliant = 0
        needs_review = 0
        unknown_vendor = 0
        
        for key in device_keys:
            cursor.execute("SELECT status FROM devices WHERE device_key = ?", (key,))
            status = cursor.fetchone()[0]
            if status == "unknown_vendor":
                unknown_vendor += 1
                continue
                
            cursor.execute("SELECT status FROM findings WHERE device_key = ?", (key,))
            statuses = [r[0] for r in cursor.fetchall()]
            
            if not statuses:
                needs_review += 1
            elif "FAIL" in statuses:
                non_compliant += 1
            elif "NEEDS_REVIEW" in statuses:
                needs_review += 1
            else:
                compliant += 1

        # 3. High Risk Findings count
        cursor.execute("SELECT COUNT(*) FROM findings WHERE status = 'FAIL' AND severity = 'high'")
        high_risk_findings = cursor.fetchone()[0]
        
        # 4. Framework rollups
        cursor.execute("SELECT framework, status, COUNT(*) FROM findings GROUP BY framework, status")
        rollup = {}
        for row in cursor.fetchall():
            fw, status, count = row[0], row[1], row[2]
            rollup.setdefault(fw, {})[status.lower()] = count

        return {
            "total_devices": total_devices,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "needs_review": needs_review,
            "unknown_vendor": unknown_vendor,
            "high_risk_findings": high_risk_findings,
            "framework_rollup": rollup
        }
    finally:
        conn.close()


def hashlib_short(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8", errors="replace")).hexdigest()[:8]
