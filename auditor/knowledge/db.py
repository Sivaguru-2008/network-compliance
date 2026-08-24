import sqlite3
from pathlib import Path

# Save database in rules directory so it is portable
DB_PATH = Path(__file__).parents[1] / "rules" / "knowledge.db"

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    """Initialize the schema for the local knowledge base."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Sources table to track original document provenance
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_name TEXT NOT NULL,
        source_type TEXT NOT NULL,
        source_url_or_path TEXT,
        source_version TEXT,
        source_date TEXT,
        content_hash TEXT,
        ingestion_timestamp TEXT NOT NULL,
        validation_status TEXT NOT NULL
    );
    """)
    
    # Controls table to track actual rule compliance conditions and metadata
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS controls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        framework TEXT NOT NULL,
        framework_version TEXT NOT NULL,
        framework_display_name TEXT,       -- e.g. "NIST SP 800-53"
        control_id TEXT NOT NULL,
        internal_control_id TEXT,          -- e.g. "secure_vty_transport"
        verified_ref INTEGER DEFAULT 1,    -- e.g. 1 (true) or 0 (false)
        title TEXT NOT NULL,
        requirement TEXT,
        description TEXT,
        severity TEXT NOT NULL,
        vendor TEXT NOT NULL,
        platform TEXT NOT NULL,
        platform_version TEXT DEFAULT 'default',
        evidence_requirements TEXT,  -- JSON string of list of fields
        pass_condition TEXT,         -- JSON string of condition
        fail_condition TEXT,         -- JSON string of condition (optional)
        needs_review_condition TEXT, -- JSON string of condition (optional)
        remediation_summary TEXT,
        remediation_cli TEXT,        -- JSON string of list of CLI commands
        references_json TEXT,        -- JSON string of list of references
        source_id INTEGER,
        source_location TEXT,
        source_note TEXT,            -- e.g. "Conditions and remediation follow..."
        ingestion_timestamp TEXT NOT NULL,
        validation_status TEXT NOT NULL, -- "EXTRACTED", "VALIDATION_PENDING", "APPROVED", "REJECTED"
        FOREIGN KEY(source_id) REFERENCES sources(id),
        UNIQUE(framework, framework_version, platform, control_id) ON CONFLICT REPLACE
    );
    """)
    
    conn.commit()
    conn.close()
