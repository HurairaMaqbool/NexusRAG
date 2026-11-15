"""
src/secure_rag/db/connection.py — Thread-safe SQLite Connection Manager
Configures WAL mode, enforces foreign keys, and validates schema compatibility.
"""

import os
import sqlite3
from pathlib import Path
from typing import Optional
from secure_rag.core.errors import DatabaseError
from secure_rag.db.constants import SCHEMA_VERSION

DEFAULT_DB_PATH = (
    os.getenv("DB_PATH")
    or os.getenv("SQLITE_PATH")
    or "data/nexus.db"
)

def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Creates and configures an isolated SQLite connection with WAL mode
    and strict foreign key enforcement.
    """
    target_path = db_path if db_path is not None else DEFAULT_DB_PATH
    
    # If using a file path, ensure parent directory exists
    if target_path != ":memory:":
        parent_dir = Path(target_path).parent
        if parent_dir and not parent_dir.exists():
            parent_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(
        target_path,
        timeout=10.0
    )
    conn.row_factory = sqlite3.Row

    # Enforce SQLite performance and integrity PRAGMAs
    with conn:
        conn.execute("PRAGMA foreign_keys = ON;")
        if target_path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")

    return conn

def check_db_schema_compatibility(conn: sqlite3.Connection) -> None:
    """
    Verifies that an existing database matches the hardened schema requirements (A6).
    Refuses startup if the database has outdated constraints, missing tables, or version mismatch.
    """
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row["name"] for row in cursor.fetchall()}
    user_version = conn.execute("PRAGMA user_version;").fetchone()[0]

    # If database contains tables and has a schema version set that does not match SCHEMA_VERSION
    if tables and user_version != 0 and user_version != SCHEMA_VERSION:
        raise DatabaseError(
            f"Database schema version mismatch: expected schema version {SCHEMA_VERSION}, "
            f"but found version {user_version}. For development, delete the existing database file to re-initialize."
        )

    # If users table exists (pre-existing DB), verify sessions table exists
    if "users" in tables and "sessions" not in tables:
        raise DatabaseError(
            "Database schema mismatch: missing 'sessions' table required by TASK-02. "
            "For development, delete the existing database file to re-initialize the hardened schema."
        )

    # If audit_logs table exists, verify decision_id is nullable
    if "audit_logs" in tables:
        col_cursor = conn.execute("PRAGMA table_info(audit_logs);")
        columns = {col["name"]: col["notnull"] for col in col_cursor.fetchall()}
        if columns.get("decision_id") == 1:
            raise DatabaseError(
                "Database schema mismatch: 'audit_logs.decision_id' is NOT NULL. "
                "For development, delete the existing database file to re-initialize the hardened schema."
            )

def init_db(db_path: Optional[str] = None, schema_file: Optional[str] = None) -> None:
    """
    Executes schema DDL against target database after validating schema compatibility.
    Sets PRAGMA user_version to SCHEMA_VERSION upon successful initialization.
    """
    if schema_file is None:
        schema_path = Path(__file__).parent / "schema.sql"
    else:
        schema_path = Path(schema_file)

    if not schema_path.exists():
        raise FileNotFoundError(f"Schema file not found at: {schema_path}")

    with open(schema_path, "r", encoding="utf-8") as f:
        ddl = f.read()

    conn = get_db_connection(db_path)
    try:
        check_db_schema_compatibility(conn)
        with conn:
            conn.executescript(ddl)
            conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION};")
    finally:
        conn.close()
