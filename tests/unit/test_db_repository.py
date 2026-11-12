"""
tests/unit/test_db_repository.py — Unit & Security Integrity Tests for SQLite Repository
Verifies ACID properties, referential integrity, cascading cleanup, SQL injection safety,
append-only audit triggers, and deny-by-default access level filtering.
"""

import pytest
import sqlite3
from secure_rag.core.errors import DatabaseError, UniqueConstraintError
from secure_rag.db.connection import get_db_connection

def test_schema_initialization_tables_exist(temp_db_path):
    """Verifies that init_db creates all 7 tables specified in the Blueprint."""
    conn = get_db_connection(temp_db_path)
    try:
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row["name"] for row in cursor.fetchall()}
        expected = {
            "roles",
            "users",
            "documents",
            "document_chunks",
            "queries",
            "security_decisions",
            "audit_logs"
        }
        assert expected.issubset(tables), f"Missing tables: {expected - tables}"
    finally:
        conn.close()

def test_role_creation_and_retrieval(repo):
    """Verifies creating and querying roles with JSON-serialized permissions."""
    role = repo.create_role(
        role_id="role-emp",
        name="Employee",
        permissions=["read:employee_docs", "use:calculator"]
    )
    assert role["role_id"] == "role-emp"

    fetched = repo.get_role("role-emp")
    assert fetched is not None
    assert fetched["name"] == "Employee"
    assert "use:calculator" in fetched["permissions"]

def test_user_creation_and_retrieval(repo):
    """Verifies user persistence, email lookup, and join with roles."""
    repo.create_role("role-hr", "HR", ["read:hr_docs", "read:employee_docs"])
    user = repo.create_user(
        user_id="user-01",
        email="alice@northwind.local",
        password_hash="$2b$12$fakehashforunittestonly",
        role_id="role-hr"
    )
    assert user["email"] == "alice@northwind.local"

    by_email = repo.get_user_by_email("alice@northwind.local")
    assert by_email is not None
    assert by_email["user_id"] == "user-01"
    assert by_email["role_name"] == "HR"
    assert "read:hr_docs" in by_email["permissions"]

    by_id = repo.get_user_by_id("user-01")
    assert by_id is not None
    assert by_id["email"] == "alice@northwind.local"

def test_document_and_chunks_lifecycle(repo):
    """Verifies document ingestion records and filtered chunk retrieval."""
    doc = repo.create_document(
        doc_id="doc-100",
        title="Northwind Employee Handbook",
        access_level="employee",
        file_hash_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert doc["title"] == "Northwind Employee Handbook"

    chunks = [
        {
            "chunk_id": "c-100-1",
            "doc_id": "doc-100",
            "chunk_index": 0,
            "chunk_text": "Company vacation policy grants 20 days annually.",
            "access_level": "employee",
            "chroma_id": "chroma-100-1",
            "baseline_risk_score": 0.0
        },
        {
            "chunk_id": "c-100-2",
            "doc_id": "doc-100",
            "chunk_index": 1,
            "chunk_text": "Working hours are 9am to 5pm Monday through Friday.",
            "access_level": "employee",
            "chroma_id": "chroma-100-2",
            "baseline_risk_score": 0.0
        }
    ]
    inserted = repo.insert_chunks(chunks)
    assert inserted == 2

    emp_chunks = repo.get_chunks_by_access_levels(["employee"])
    assert len(emp_chunks) == 2

    hr_chunks = repo.get_chunks_by_access_levels(["hr"])
    assert len(hr_chunks) == 0

def test_audit_logging_and_decision_trail(repo):
    """Verifies end-to-end recording of queries, security decisions, and audit events."""
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    repo.create_user("user-02", "bob@northwind.local", "hash", "role-emp")

    query = repo.record_query("q-001", "user-02", "What is the vacation policy?")
    assert query["query_id"] == "q-001"

    decision = repo.record_decision(
        decision_id="dec-001",
        query_id="q-001",
        decision="ALLOW",
        risk_score=0.05,
        reason_code="ALLOWED_AUTHORIZED_SOURCE"
    )
    assert decision["decision"] == "ALLOW"

    log_id = repo.append_audit_log(
        decision_id="dec-001",
        user_id="user-02",
        event_type="query_completion",
        latency_ms=142.5,
        provider_used="ollama",
        details={"chunks_count": 2, "citations": ["doc-100"]}
    )
    assert log_id > 0

    logs = repo.get_audit_logs(limit=10)
    assert len(logs) == 1
    log_entry = logs[0]
    assert log_entry["decision"] == "ALLOW"
    assert log_entry["reason_code"] == "ALLOWED_AUTHORIZED_SOURCE"
    assert log_entry["user_email"] == "bob@northwind.local"
    assert log_entry["details"]["chunks_count"] == 2

# ── Negative & Adversarial Security Tests ─────────────────────────────────────

def test_adversarial_foreign_key_violation_user_role(repo):
    """Adversarial test: Inserting a user with an unassigned/non-existent role must fail."""
    with pytest.raises(DatabaseError):
        repo.create_user(
            user_id="attacker-01",
            email="intruder@external.com",
            password_hash="hash",
            role_id="non-existent-role"
        )

def test_adversarial_foreign_key_violation_chunk_document(repo):
    """Adversarial test: Inserting a chunk referencing a non-existent document must fail."""
    with pytest.raises(DatabaseError):
        repo.insert_chunks([
            {
                "chunk_id": "orphan-1",
                "doc_id": "ghost-document-id",
                "chunk_index": 0,
                "chunk_text": "Malicious payload injection attempt.",
                "access_level": "employee",
                "chroma_id": "chroma-ghost",
                "baseline_risk_score": 0.99
            }
        ])

def test_unique_constraint_enforcement_duplicate_email(repo):
    """Security test: Attempting to register an existing email must raise UniqueConstraintError."""
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    repo.create_user("user-03", "charlie@northwind.local", "hash1", "role-emp")

    with pytest.raises(UniqueConstraintError):
        repo.create_user("user-04", "charlie@northwind.local", "hash2", "role-emp")

def test_cascading_document_deletion(repo):
    """Data integrity test: Deleting a document must cascade and remove all associated chunks."""
    repo.create_document("doc-200", "Executive Salaries", "hr", "sha256...")
    repo.insert_chunks([
        {
            "chunk_id": "c-200-1",
            "doc_id": "doc-200",
            "chunk_index": 0,
            "chunk_text": "CEO Salary: $1,200,000",
            "access_level": "hr",
            "chroma_id": "chroma-200-1",
            "baseline_risk_score": 0.0
        }
    ])
    assert len(repo.get_chunks_by_access_levels(["hr"])) == 1

    # Delete document
    deleted = repo.delete_document("doc-200")
    assert deleted is True

    # Assert chunks were automatically deleted by SQLite foreign key cascade
    assert len(repo.get_chunks_by_access_levels(["hr"])) == 0

def test_sql_injection_resilience(repo):
    """Security test: SQL injection strings in fields are treated strictly as literals."""
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    
    # Attack payload designed to terminate string and drop table
    malicious_email = "malicious'; DROP TABLE users; --@northwind.local"
    user = repo.create_user("user-inj", malicious_email, "hash", "role-emp")
    assert user["email"] == malicious_email.lower().strip()

    # Verify users table still exists and record is intact
    fetched = repo.get_user_by_email(malicious_email)
    assert fetched is not None
    assert fetched["user_id"] == "user-inj"

# ── Fix 1: Append-Only Audit & Immutability Trigger Tests ─────────────────────

def test_append_only_audit_logs_cannot_be_updated(repo, temp_db_path):
    """Security test: Direct UPDATE on audit_logs must be aborted by trigger."""
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    repo.create_user("user-audit", "auditor@northwind.local", "hash", "role-emp")
    repo.record_query("q-audit-1", "user-audit", "test query")
    repo.record_decision("dec-audit-1", "q-audit-1", "ALLOW", 0.0, "ALLOWED_AUTHORIZED_SOURCE")
    log_id = repo.append_audit_log("dec-audit-1", "user-audit", "query", 10.0, "ollama")

    conn = get_db_connection(temp_db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="audit_logs is append-only"):
            with conn:
                conn.execute(
                    "UPDATE audit_logs SET event_type = 'tampered' WHERE log_id = ?;",
                    (log_id,)
                )
    finally:
        conn.close()

def test_append_only_audit_logs_cannot_be_deleted(repo, temp_db_path):
    """Security test: Direct DELETE on audit_logs must be aborted by trigger."""
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    repo.create_user("user-audit-2", "auditor2@northwind.local", "hash", "role-emp")
    repo.record_query("q-audit-2", "user-audit-2", "test query")
    repo.record_decision("dec-audit-2", "q-audit-2", "ALLOW", 0.0, "ALLOWED_AUTHORIZED_SOURCE")
    log_id = repo.append_audit_log("dec-audit-2", "user-audit-2", "query", 10.0, "ollama")

    conn = get_db_connection(temp_db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="audit_logs is append-only"):
            with conn:
                conn.execute("DELETE FROM audit_logs WHERE log_id = ?;", (log_id,))
    finally:
        conn.close()

def test_immutable_security_decisions_cannot_be_updated_or_deleted(repo, temp_db_path):
    """Security test: Direct UPDATE or DELETE on security_decisions must be aborted by trigger."""
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    repo.create_user("user-dec", "dec@northwind.local", "hash", "role-emp")
    repo.record_query("q-dec-1", "user-dec", "query")
    repo.record_decision("dec-immut-1", "q-dec-1", "BLOCK", 0.9, "INPUT_INJECTION")

    conn = get_db_connection(temp_db_path)
    try:
        # Test UPDATE abort
        with pytest.raises(sqlite3.IntegrityError, match="security_decisions is immutable"):
            with conn:
                conn.execute(
                    "UPDATE security_decisions SET decision = 'ALLOW' WHERE decision_id = 'dec-immut-1';"
                )

        # Test DELETE abort
        with pytest.raises(sqlite3.IntegrityError, match="security_decisions is immutable"):
            with conn:
                conn.execute(
                    "DELETE FROM security_decisions WHERE decision_id = 'dec-immut-1';"
                )
    finally:
        conn.close()

def test_append_only_subsequent_inserts_succeed(repo):
    """Verifies that while UPDATE/DELETE are blocked, subsequent INSERTs succeed unimpeded."""
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    repo.create_user("user-seq", "seq@northwind.local", "hash", "role-emp")
    repo.record_query("q-seq-1", "user-seq", "first query")
    repo.record_decision("dec-seq-1", "q-seq-1", "ALLOW", 0.1, "ALLOWED_AUTHORIZED_SOURCE")
    log_1 = repo.append_audit_log("dec-seq-1", "user-seq", "query", 50.0, "ollama")

    repo.record_query("q-seq-2", "user-seq", "second query")
    repo.record_decision("dec-seq-2", "q-seq-2", "BLOCK", 0.85, "DOC_INJECTION_BLOCKED")
    log_2 = repo.append_audit_log("dec-seq-2", "user-seq", "query", 25.0, "ollama")

    assert log_1 < log_2
    assert repo.get_audit_logs_count() == 2

# ── Fix 2: Deny-by-Default Retrieval & Inactive User Tests ─────────────────────

def test_get_chunks_by_access_levels_empty_list_returns_empty(repo):
    """Deny-by-default: An empty role list returns an empty chunk list immediately."""
    repo.create_document("doc-300", "Public Handbook", "employee", "hash")
    repo.insert_chunks([
        {
            "chunk_id": "c-300-1",
            "doc_id": "doc-300",
            "chunk_index": 0,
            "chunk_text": "Sample text",
            "access_level": "employee",
            "chroma_id": "ch-300",
            "baseline_risk_score": 0.0
        }
    ])
    assert repo.get_chunks_by_access_levels([]) == []

def test_get_chunks_by_access_levels_unknown_level_returns_empty(repo):
    """Deny-by-default: Querying an unassigned or non-existent access level returns empty."""
    repo.create_document("doc-301", "Public Handbook", "employee", "hash")
    repo.insert_chunks([
        {
            "chunk_id": "c-301-1",
            "doc_id": "doc-301",
            "chunk_index": 0,
            "chunk_text": "Sample text",
            "access_level": "employee",
            "chroma_id": "ch-301",
            "baseline_risk_score": 0.0
        }
    ])
    assert repo.get_chunks_by_access_levels(["nonexistent_role"]) == []
    assert repo.get_chunks_by_access_levels(["admin"]) == []

def test_get_chunks_by_access_levels_normal_matching(repo):
    """Access segregation: Returns only authorized access levels and excludes unauthorized ones."""
    repo.create_document("doc-emp", "Employee Doc", "employee", "hash1")
    repo.create_document("doc-hr", "HR Payroll", "hr", "hash2")
    repo.insert_chunks([
        {
            "chunk_id": "c-emp-1",
            "doc_id": "doc-emp",
            "chunk_index": 0,
            "chunk_text": "Employee general benefit guide.",
            "access_level": "employee",
            "chroma_id": "ch-emp",
            "baseline_risk_score": 0.0
        },
        {
            "chunk_id": "c-hr-1",
            "doc_id": "doc-hr",
            "chunk_index": 0,
            "chunk_text": "HR salary details.",
            "access_level": "hr",
            "chroma_id": "ch-hr",
            "baseline_risk_score": 0.0
        }
    ])

    # Employee role should see only employee chunks
    emp_results = repo.get_chunks_by_access_levels(["employee"])
    assert len(emp_results) == 1
    assert emp_results[0]["chunk_id"] == "c-emp-1"

    # HR role sees both employee and hr chunks
    hr_results = repo.get_chunks_by_access_levels(["employee", "hr"])
    assert len(hr_results) == 2

def test_get_chunks_by_access_levels_injection_string_handled_as_literal(repo):
    """Security test: Injection attack strings in access_levels list are treated as literal strings."""
    repo.create_document("doc-sec", "Doc", "employee", "hash")
    repo.insert_chunks([
        {
            "chunk_id": "c-sec-1",
            "doc_id": "doc-sec",
            "chunk_index": 0,
            "chunk_text": "Content",
            "access_level": "employee",
            "chroma_id": "ch-sec",
            "baseline_risk_score": 0.0
        }
    ])
    # Malicious attempts to escape IN (...) clause
    malicious_inputs = [
        "' OR '1'='1",
        "employee') OR ('1'='1",
        "employee' UNION SELECT * FROM document_chunks --",
        "'; DROP TABLE document_chunks; --"
    ]
    # None of these match the exact literal access_level 'employee'
    for payload in malicious_inputs:
        result = repo.get_chunks_by_access_levels([payload])
        assert result == []

def test_inactive_user_representation(repo):
    """
    Repository state verification: An inactive user (is_active=0) is correctly stored
    and represented with is_active=False. (Authentication refusal enforcement is deferred to TASK-02).
    """
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    user = repo.create_user(
        user_id="user-inactive",
        email="inactive@northwind.local",
        password_hash="hash",
        role_id="role-emp",
        is_active=0
    )
    assert user["is_active"] is False

    fetched = repo.get_user_by_email("inactive@northwind.local")
    assert fetched is not None
    assert fetched["is_active"] is False

# ── Status Gating Tests (B3) ──────────────────────────────────────────────────

def test_status_gating_excludes_non_indexed_documents(repo):
    """
    Status Gating Security Test (B3):
    Every SQLite read path returning chunk text must ONLY return chunks from documents
    with status='indexed'. Chunks from documents in 'indexing', 'failed', and 'deleting'
    states must be strictly excluded for both employee and hr levels.
    """
    statuses = ["indexing", "failed", "deleting"]
    
    # Insert chunks under non-indexed statuses
    for idx, st in enumerate(statuses):
        doc_emp = f"doc-emp-{st}"
        doc_hr = f"doc-hr-{st}"
        
        repo.create_document(doc_emp, f"Emp {st}", "employee", f"hash-emp-{idx}", status=st)
        repo.create_document(doc_hr, f"HR {st}", "hr", f"hash-hr-{idx}", status=st)
        
        repo.insert_chunks([
            {
                "chunk_id": f"c-emp-{st}",
                "doc_id": doc_emp,
                "chunk_index": 0,
                "chunk_text": f"Secret employee content in {st} state",
                "access_level": "employee",
                "chroma_id": f"ch-emp-{st}",
                "baseline_risk_score": 0.0
            },
            {
                "chunk_id": f"c-hr-{st}",
                "doc_id": doc_hr,
                "chunk_index": 0,
                "chunk_text": f"Secret HR content in {st} state",
                "access_level": "hr",
                "chroma_id": f"ch-hr-{st}",
                "baseline_risk_score": 0.0
            }
        ])

    # Insert one valid indexed document at each level
    repo.create_document("doc-emp-valid", "Valid Emp", "employee", "hash-emp-valid", status="indexed")
    repo.insert_chunks([{
        "chunk_id": "c-emp-valid",
        "doc_id": "doc-emp-valid",
        "chunk_index": 0,
        "chunk_text": "Legitimate indexed employee text",
        "access_level": "employee",
        "chroma_id": "ch-emp-valid",
        "baseline_risk_score": 0.0
    }])

    repo.create_document("doc-hr-valid", "Valid HR", "hr", "hash-hr-valid", status="indexed")
    repo.insert_chunks([{
        "chunk_id": "c-hr-valid",
        "doc_id": "doc-hr-valid",
        "chunk_index": 0,
        "chunk_text": "Legitimate indexed HR text",
        "access_level": "hr",
        "chroma_id": "ch-hr-valid",
        "baseline_risk_score": 0.0
    }])

    # 1. Query employee level: must return ONLY c-emp-valid
    emp_chunks = repo.get_chunks_by_access_levels(["employee"])
    assert len(emp_chunks) == 1
    assert emp_chunks[0]["chunk_id"] == "c-emp-valid"

    # 2. Query hr level: must return ONLY c-emp-valid and c-hr-valid
    hr_chunks = repo.get_chunks_by_access_levels(["employee", "hr"])
    chunk_ids = {c["chunk_id"] for c in hr_chunks}
    assert chunk_ids == {"c-emp-valid", "c-hr-valid"}

