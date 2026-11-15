"""
tests/unit/test_ingestion_pipeline.py — Comprehensive Tests for Ingestion Pipeline
Verifies RBAC enforcement (D13), deduplication by hash (D16, B4), transactional two-store writing & rollback (D18, B2),
deletion staging (B2), status gating (B3), audit hygiene (B5), and Chroma telemetry opt-out (B6).
"""

import concurrent.futures
import hashlib
import secrets
from unittest.mock import MagicMock
import pytest

from secure_rag.core.errors import (
    AuthorizationError,
    DocumentValidationError,
    DuplicateDocumentError,
    VectorStoreError,
)
from secure_rag.ingestion.pipeline import IngestionPipeline, sanitize_document_title
from secure_rag.retrieval.embeddings import FakeEmbedder
from secure_rag.retrieval.vector_store import ChromaVectorStore

@pytest.fixture
def pipeline(repo):
    """Provides an IngestionPipeline with in-memory SQLite repo and in-memory Chroma."""
    coll_name = f"test_pipe_coll_{secrets.token_hex(6)}"
    vector_store = ChromaVectorStore(persist_dir=":memory:", collection_name=coll_name)
    embedder = FakeEmbedder()
    return IngestionPipeline(repo=repo, vector_store=vector_store, embedder=embedder)

def test_ingestion_rbac_enforcement(pipeline):
    """Security test: Only HR role has permissions to upload or ingest documents (Decision D13, B5: ingest_denied)."""
    payload = b"Sample text for RBAC verification."
    
    # 1. Employee cannot ingest
    with pytest.raises(AuthorizationError, match="Only HR role has permissions"):
        pipeline.ingest_file(payload, "test.txt", "employee", uploader_role="Employee")

    # 2. Admin cannot ingest
    with pytest.raises(AuthorizationError, match="Only HR role has permissions"):
        pipeline.ingest_file(payload, "test.txt", "employee", uploader_role="Admin")

    # 3. HR can ingest
    result = pipeline.ingest_file(payload, "test.txt", "employee", uploader_role="HR")
    assert result["status"] == "indexed"

def test_ingestion_access_level_assignment_restrictions(pipeline):
    """Security test: HR cannot assign access levels outside permitted levels."""
    payload = b"Sample policy text."
    with pytest.raises(AuthorizationError, match="not permitted to assign access level"):
        pipeline.ingest_file(payload, "test.txt", "unauthorized_level", uploader_role="HR")

def test_ingestion_deduplication_same_hash_same_level(pipeline, repo):
    """
    Deduplication test (Decision D16, B5: doc_duplicate):
    Identical hash and same access level returns existing document without duplicate chunks or vectors.
    """
    payload = b"Policy content for deduplication testing."
    res1 = pipeline.ingest_file(payload, "policy_v1.txt", "employee", uploader_role="HR")
    assert res1["status"] == "indexed"
    doc_id = res1["doc_id"]

    # Re-upload identical content under same level
    res2 = pipeline.ingest_file(payload, "policy_v1_copy.txt", "employee", uploader_role="HR")
    assert res2["status"] == "existing"
    assert res2["doc_id"] == doc_id

    # Check total documents in SQLite remains 1
    docs = repo.list_documents()
    assert len(docs) == 1

def test_ingestion_deduplication_conflicting_access_level_returns_existing(pipeline):
    """
    Same hash under a different access level returns the existing indexed doc
    (idempotent UX) and keeps the original classification.
    """
    payload = b"Confidential document content for reclassification test."
    first = pipeline.ingest_file(payload, "confidential.txt", "employee", uploader_role="HR")

    second = pipeline.ingest_file(
        payload, "confidential_reclassified.txt", "hr", uploader_role="HR"
    )
    assert second["status"] == "existing"
    assert second["doc_id"] == first["doc_id"]
    assert second["access_level"] == "employee"
    assert "warning" in second

def test_ingestion_two_store_consistency_and_verification(pipeline, repo):
    """
    Consistency test (Decision D18):
    Verifies that SQLite document, SQLite chunks, and Chroma vectors are all indexed and synchronized.
    """
    payload = (
        "Enterprise Data Protection Standard.\n\n"
        "All data at rest must be encrypted using AES-256.\n\n"
        "All data in transit must utilize TLS 1.3 encryption."
    ).encode("utf-8")

    result = pipeline.ingest_file(payload, "crypto_standard.txt", "employee", uploader_role="HR")
    assert result["status"] == "indexed"
    doc_id = result["doc_id"]

    # 1. Verify SQLite doc status is 'indexed'
    doc = repo.get_document(doc_id)
    assert doc is not None
    assert doc["status"] == "indexed"

    # 2. Verify SQLite chunks exist
    chunks = repo.get_chunks_by_document(doc_id)
    assert len(chunks) == result["chunks_count"]

    # 3. Verify Chroma vector count matches SQLite chunk count
    assert pipeline.vector_store.count() == len(chunks)

    # 4. Run verify_index_consistency
    audit = pipeline.verify_index_consistency()
    assert audit["is_consistent"] is True
    assert len(audit["missing_in_chroma"]) == 0
    assert len(audit["orphaned_in_chroma"]) == 0

# ── Rollback and Cleanup Tests (B2) ───────────────────────────────────────────

def test_ingestion_rollback_on_vector_store_failure(pipeline, repo):
    """
    Rollback test (Decision D18, B2):
    When vector store insertion fails:
    1. Chroma vectors for doc_id are deleted.
    2. Document chunk rows are deleted from SQLite.
    3. Document row remains with status 'failed' (no chunk text).
    """
    payload = b"Content that will trigger simulated vector store error."

    pipeline.vector_store.add_chunks = MagicMock(side_effect=VectorStoreError("Simulated ChromaDB disk failure"))

    with pytest.raises(VectorStoreError, match="Simulated ChromaDB disk failure"):
        pipeline.ingest_file(payload, "fail.txt", "employee", uploader_role="HR")

    # Verify SQLite document status was set to 'failed'
    docs = repo.list_documents()
    assert len(docs) == 1
    doc = docs[0]
    assert doc["status"] == "failed"

    # Strict check: Chunk rows MUST be deleted from SQLite for failed document
    chunks = repo.get_chunks_by_document(doc["doc_id"])
    assert len(chunks) == 0, "Chunk rows must be purged from SQLite upon ingestion failure."

    # Verify Chroma collection has 0 vectors
    assert pipeline.vector_store.count() == 0

def test_ingestion_rollback_failure_audits_incomplete_rollback(pipeline, repo):
    """
    Rollback failure test (B2):
    When vector store fails on add AND cleanup fails:
    1. Writes an audit event 'doc_rollback_incomplete' with failed stores and exception class name.
    2. Re-raises the ORIGINAL exception without masking.
    """
    payload = b"Content for rollback failure test."

    # Vector store add fails
    pipeline.vector_store.add_chunks = MagicMock(side_effect=VectorStoreError("Original Chroma add failure"))
    # Vector store delete also fails during rollback
    pipeline.vector_store.delete_chunks_by_doc_id = MagicMock(side_effect=RuntimeError("Cleanup purge failed"))

    with pytest.raises(VectorStoreError, match="Original Chroma add failure"):
        pipeline.ingest_file(payload, "fail_double.txt", "employee", uploader_role="HR")

    # Inspect audit logs for 'doc_rollback_incomplete'
    logs = repo.get_audit_logs(limit=10)
    rollback_events = [l for l in logs if l["event_type"] == "doc_rollback_incomplete"]
    assert len(rollback_events) == 1
    details = rollback_events[0]["details"]
    assert "chroma:RuntimeError" in details["failed_stores"]
    assert details["error_class"] == "VectorStoreError"

def test_document_deletion_staging_and_removes_vectors(pipeline, repo):
    """
    Deletion lifecycle test (Decision D13, D18, B2):
    1. Stages status as 'deleting'.
    2. Removes vectors from ChromaDB.
    3. Deletes SQLite document and cascading chunks.
    4. Non-HR roles are forbidden with AuthorizationError.
    """
    payload = b"Document to be deleted."
    result = pipeline.ingest_file(payload, "to_delete.txt", "employee", uploader_role="HR")
    doc_id = result["doc_id"]

    # 1. Employee cannot delete
    with pytest.raises(AuthorizationError, match="Only HR role has permissions to delete"):
        pipeline.delete_document(doc_id, uploader_role="Employee")

    # 2. HR can delete
    success = pipeline.delete_document(doc_id, uploader_role="HR")
    assert success is True

    # 3. Relational and vector index cleaned up
    assert repo.get_document(doc_id) is None
    assert len(repo.get_chunks_by_document(doc_id)) == 0
    assert pipeline.vector_store.count() == 0

    # Index remains consistent
    audit = pipeline.verify_index_consistency()
    assert audit["is_consistent"] is True

def test_document_deletion_failure_between_steps_leaves_deleting_status(pipeline, repo):
    """
    Deletion failure staging test (B2):
    If Chroma vector deletion fails, the document remains in 'deleting' status in SQLite,
    and its chunks are inaccessible to retrieval queries due to status gating (B3).
    """
    payload = b"Content to test deletion failure."
    result = pipeline.ingest_file(payload, "stage_delete.txt", "employee", uploader_role="HR")
    doc_id = result["doc_id"]

    # Mock Chroma deletion failure
    pipeline.vector_store.delete_chunks_by_doc_id = MagicMock(side_effect=VectorStoreError("Chroma network timeout"))

    with pytest.raises(VectorStoreError, match="Chroma network timeout"):
        pipeline.delete_document(doc_id, uploader_role="HR")

    # Verify SQLite document remains in 'deleting' status
    doc = repo.get_document(doc_id)
    assert doc is not None
    assert doc["status"] == "deleting"

    # Status gating check: Chunks must NOT be retrievable
    retrieved = repo.get_chunks_by_access_levels(["employee"])
    assert all(c["doc_id"] != doc_id for c in retrieved)

# ── Duplicates, Retry, and Concurrency Tests (B4) ─────────────────────────────

def test_ingestion_duplicates_status_handling(pipeline, repo):
    """
    Duplicate and retry behavior test (Decision D16, B4):
    - status='failed': clean retry permitted (does not return failed doc, purges failed record).
    - status='indexing': raises DocumentValidationError ('currently indexing').
    - status='deleting': raises DocumentValidationError ('currently deleting').
    """
    payload = b"Policy content for status handling test."
    file_hash = hashlib.sha256(payload).hexdigest()

    # 1. Clean retry for status='failed'
    repo.create_document("doc-old-failed", "Old Failed", "employee", file_hash, status="failed")
    # Ingesting same file hash overwrites/purges old failed record and succeeds
    res_retry = pipeline.ingest_file(payload, "retry.txt", "employee", uploader_role="HR")
    assert res_retry["status"] == "indexed"
    assert repo.get_document("doc-old-failed") is None

    # 2. Conflict when status='indexing'
    repo.create_document("doc-in-progress", "In Progress", "employee", "hash_indexing_test", status="indexing")
    pipeline.repo.get_document_by_hash = MagicMock(return_value={"doc_id": "doc-in-progress", "status": "indexing", "access_level": "employee"})
    with pytest.raises(DocumentValidationError, match="currently 'indexing'"):
        pipeline.ingest_file(b"Any content", "progress.txt", "employee", uploader_role="HR")

    # 3. Conflict when status='deleting'
    pipeline.repo.get_document_by_hash = MagicMock(return_value={"doc_id": "doc-deleting", "status": "deleting", "access_level": "employee"})
    with pytest.raises(DocumentValidationError, match="currently 'deleting'"):
        pipeline.ingest_file(b"Any content", "deleting.txt", "employee", uploader_role="HR")

def test_concurrent_uploads_identical_bytes_handled_cleanly(repo):
    """
    Concurrency test (B4):
    Simultaneous upload of identical content in 2 threads.
    Guaranteed by partial unique index uq_docs_active_hash:
    One thread succeeds, while the other is caught by unique constraint or handled idempotently.
    """
    coll_name = f"test_threaded_coll_{secrets.token_hex(6)}"
    vector_store = ChromaVectorStore(persist_dir=":memory:", collection_name=coll_name)
    embedder = FakeEmbedder()
    pipeline = IngestionPipeline(repo=repo, vector_store=vector_store, embedder=embedder)

    payload = b"Thread-safe identical upload test payload."
    results = []
    errors = []

    def upload_task():
        try:
            res = pipeline.ingest_file(payload, "concurrent.txt", "employee", uploader_role="HR")
            results.append(res)
        except Exception as e:
            errors.append(e)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(upload_task)
        f2 = executor.submit(upload_task)
        f1.result()
        f2.result()

    # Exactly one thread creates the indexed document
    docs = [d for d in repo.list_documents() if d["status"] == "indexed"]
    assert len(docs) == 1
    # Index consistency passes
    audit = pipeline.verify_index_consistency()
    assert audit["is_consistent"] is True

# ── Audit Hygiene & Telemetry Tests (B5, B6) ──────────────────────────────────

def test_audit_logs_do_not_leak_exception_message_sentinel(pipeline, repo):
    """
    Security hygiene test (B5):
    An exception whose message contains sensitive document text MUST NOT leak into audit_logs.
    Only exception class names are recorded.
    """
    secret_sentinel = "SENSITIVE_PAYROLL_DATA_ACCOUNT_99882211"
    payload = f"Document containing {secret_sentinel}".encode("utf-8")

    # Inject simulated exception carrying the secret in str(e)
    pipeline.vector_store.add_chunks = MagicMock(side_effect=Exception(f"Syntax error near: {secret_sentinel}"))

    with pytest.raises(Exception):
        pipeline.ingest_file(payload, "leak_test.txt", "employee", uploader_role="HR")

    # Inspect all audit logs
    logs = repo.get_audit_logs(limit=50)
    for entry in logs:
        serialized = str(entry)
        assert secret_sentinel not in serialized, (
            f"Sensitive document sentinel leaked in audit log! Entry: {serialized}"
        )
        assert "SYSTEM_ERROR" not in serialized, "SYSTEM_ERROR must not be used as reason code."

def test_chroma_telemetry_disabled_explicitly(pipeline):
    """
    Telemetry verification test (Decision D14, B6):
    Proves that Chroma telemetry is disabled on the client settings object.
    """
    client_settings = pipeline.vector_store.client.get_settings()
    assert client_settings.anonymized_telemetry is False, "Chroma anonymized_telemetry must be explicitly False."

def test_ingest_sample_data_files(pipeline):
    """Integration test: Ingests the real raw sample files created in data/raw."""
    from pathlib import Path

    emp_path = Path("data/raw/employee/leave_policy.txt")
    hr_path = Path("data/raw/hr/salary_bands.txt")

    assert emp_path.exists()
    assert hr_path.exists()

    res_emp = pipeline.ingest_file(
        emp_path.read_bytes(),
        "leave_policy.txt",
        access_level="employee",
        uploader_role="HR"
    )
    assert res_emp["status"] == "indexed"
    assert res_emp["chunks_count"] > 0

    res_hr = pipeline.ingest_file(
        hr_path.read_bytes(),
        "salary_bands.txt",
        access_level="hr",
        uploader_role="HR"
    )
    assert res_hr["status"] == "indexed"
    assert res_hr["chunks_count"] > 0

    consistency = pipeline.verify_index_consistency()
    assert consistency["is_consistent"] is True

def test_no_audit_event_contains_raw_uploaded_filename(pipeline, repo):
    """
    Security test (C3):
    Verifies that NO audit event contains the raw uploaded filename (e.g. directory traversals,
    relative paths, or unprintable characters). Only the sanitized title and doc_id are recorded.
    """
    import json
    raw_filename = "../../etc/shadow/passwords_secret_leak.txt"
    payload = b"Authorized employee document content for audit hygiene test."

    # 1. Successful ingestion with directory traversal filename
    result = pipeline.ingest_file(payload, raw_filename, access_level="employee", uploader_role="HR")
    assert result["status"] == "indexed"

    # 2. Unauthorized access rejection with directory traversal filename
    with pytest.raises(Exception):
        pipeline.ingest_file(payload, raw_filename, access_level="employee", uploader_role="Employee")

    # Inspect all SQLite audit logs
    conn = repo._get_connection()
    rows = conn.execute("SELECT event_type, details_json FROM audit_logs").fetchall()
    assert len(rows) > 0

    for r in rows:
        details_str = r["details_json"] or ""
        assert raw_filename not in details_str, f"Raw filename leaked in audit event '{r['event_type']}': {details_str}"
        assert "../../" not in details_str
        assert "shadow" not in details_str
        
        details = json.loads(details_str)
        if "title" in details:
            assert details["title"] == "passwords_secret_leak.txt"

