-- src/secure_rag/db/schema.sql
-- Authoritative Relational Schema for Secure RAG Platform (SQLite)
-- Enforces referential integrity, cascading chunk cleanup, and indexed queries.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS roles (
    role_id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    permissions TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role_id TEXT NOT NULL REFERENCES roles(role_id),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS documents (
    doc_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    access_level TEXT NOT NULL, -- 'employee' or 'hr'
    file_hash_sha256 TEXT NOT NULL,
    status TEXT NOT NULL,       -- 'indexing', 'indexed', 'failed', 'deleting'
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS document_chunks (
    chunk_id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL REFERENCES documents(doc_id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    chunk_text TEXT NOT NULL,
    access_level TEXT NOT NULL,
    chroma_id TEXT NOT NULL,
    baseline_risk_score REAL DEFAULT 0.0
);

CREATE TABLE IF NOT EXISTS queries (
    query_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id),
    query_text TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_decisions (
    decision_id TEXT PRIMARY KEY,
    query_id TEXT NOT NULL REFERENCES queries(query_id),
    decision TEXT NOT NULL,     -- 'ALLOW', 'REVIEW', 'BLOCK'
    risk_score REAL NOT NULL,
    reason_code TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sessions Table (Decision D9)
-- Stores token hashes (SHA-256); raw tokens are never persisted or logged.
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    revoked_at TIMESTAMP
);

-- Audit Logs Table (Control 7)
-- decision_id and user_id are nullable to allow logging authentication/system events
-- where no query decision exists or where login fails for an unknown user.
CREATE TABLE IF NOT EXISTS audit_logs (
    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id TEXT REFERENCES security_decisions(decision_id),
    user_id TEXT REFERENCES users(user_id),
    event_type TEXT NOT NULL,
    latency_ms REAL NOT NULL DEFAULT 0.0,
    provider_used TEXT NOT NULL DEFAULT 'system',
    details_json TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indices for low-latency lookups, filtered retrieval, and session validation
CREATE INDEX IF NOT EXISTS idx_chunks_access ON document_chunks(access_level);
CREATE INDEX IF NOT EXISTS idx_chunks_doc_id ON document_chunks(doc_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_decisions_reason ON security_decisions(reason_code);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_documents_hash ON documents(file_hash_sha256);
CREATE UNIQUE INDEX IF NOT EXISTS uq_docs_active_hash ON documents(file_hash_sha256) WHERE status IN ('indexing', 'indexed');

-- ─── Append-Only Triggers for Security Decisions & Audit Logs ────────────────
-- Defends against application-level and insider tampering with audit trails.

CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_logs_update
BEFORE UPDATE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs is append-only: updates are strictly prohibited');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_audit_logs_delete
BEFORE DELETE ON audit_logs
BEGIN
    SELECT RAISE(ABORT, 'audit_logs is append-only: deletions are strictly prohibited');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_security_decisions_update
BEFORE UPDATE ON security_decisions
BEGIN
    SELECT RAISE(ABORT, 'security_decisions is immutable: updates are strictly prohibited');
END;

CREATE TRIGGER IF NOT EXISTS trg_prevent_security_decisions_delete
BEFORE DELETE ON security_decisions
BEGIN
    SELECT RAISE(ABORT, 'security_decisions is immutable: deletions are strictly prohibited');
END;
