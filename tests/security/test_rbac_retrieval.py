"""
tests/security/test_rbac_retrieval.py — RBAC Retrieval Boundary Tests
Verifies that employee role NEVER retrieves HR-classified chunks.
"""

import pytest

from secure_rag.db.connection import get_db_connection, init_db
from secure_rag.db.repository import SQLiteRepository
from secure_rag.retrieval.embeddings import FakeEmbedder
from secure_rag.retrieval.hybrid_engine import HybridRetrievalEngine
from secure_rag.retrieval.vector_store import ChromaVectorStore


@pytest.fixture
def secured_engine(tmp_path):
    """Creates a hybrid engine with both employee and HR docs indexed."""
    db_path = str(tmp_path / "rbac_test.db")
    init_db(db_path)
    repo = SQLiteRepository(connection_factory=lambda: get_db_connection(db_path))
    embedder = FakeEmbedder(dimension=384)
    vs = ChromaVectorStore(persist_dir=":memory:", collection_name="rbac_test")

    # Employee documents
    repo.create_document(
        doc_id="doc-e1", title="Benefits Guide",
        access_level="employee", file_hash_sha256="e_hash_1", status="indexed",
    )
    emp_chunks = [
        {"chunk_id": "doc-e1-c0000", "doc_id": "doc-e1", "chunk_index": 0,
         "chunk_text": "All employees receive 401k matching up to 6%.",
         "access_level": "employee", "chroma_id": "doc-e1-c0000"},
    ]
    repo.insert_chunks(emp_chunks)

    # HR-restricted documents
    repo.create_document(
        doc_id="doc-h1", title="Salary Schedule 2026",
        access_level="hr", file_hash_sha256="h_hash_1", status="indexed",
    )
    hr_chunks = [
        {"chunk_id": "doc-h1-c0000", "doc_id": "doc-h1", "chunk_index": 0,
         "chunk_text": "VP Engineering base salary: $350,000. CTO: $425,000. Bonus: 30%.",
         "access_level": "hr", "chroma_id": "doc-h1-c0000"},
        {"chunk_id": "doc-h1-c0001", "doc_id": "doc-h1", "chunk_index": 1,
         "chunk_text": "HR confidential: Stock options vest over 4 years for executives.",
         "access_level": "hr", "chroma_id": "doc-h1-c0001"},
    ]
    repo.insert_chunks(hr_chunks)

    # Index all in vector store
    for chunk in emp_chunks + hr_chunks:
        emb = embedder.embed_text(chunk["chunk_text"])
        vs.add_chunks(
            chunk_ids=[chunk["chunk_id"]],
            embeddings=[emb],
            metadatas=[{
                "chunk_id": chunk["chunk_id"],
                "doc_id": chunk["doc_id"],
                "access_level": chunk["access_level"],
            }],
        )

    return HybridRetrievalEngine(repo=repo, vector_store=vs, embedder=embedder)


class TestEmployeeCannotAccessHR:
    """Core RBAC boundary: employee role must NEVER retrieve hr chunks."""

    def test_salary_query_returns_zero_hr_chunks(self, secured_engine):
        results = secured_engine.retrieve(
            query="salary VP CTO executive compensation",
            allowed_access_levels=["employee"],
        )
        hr_chunks = [c for c in results if c.access_level == "hr"]
        assert len(hr_chunks) == 0, (
            f"SECURITY VIOLATION: Employee retrieved {len(hr_chunks)} HR chunks: "
            f"{[c.chunk_id for c in hr_chunks]}"
        )

    def test_stock_options_query_returns_zero_hr_chunks(self, secured_engine):
        results = secured_engine.retrieve(
            query="stock options vesting executives",
            allowed_access_levels=["employee"],
        )
        for chunk in results:
            assert chunk.access_level != "hr", f"Employee got HR chunk: {chunk.chunk_id}"

    def test_broad_query_returns_zero_hr_chunks(self, secured_engine):
        results = secured_engine.retrieve(
            query="company benefits salary compensation",
            allowed_access_levels=["employee"],
        )
        for chunk in results:
            assert chunk.access_level == "employee"


class TestHRCanAccessAll:
    """HR role should retrieve both employee and HR documents."""

    def test_hr_sees_salary_data(self, secured_engine):
        results = secured_engine.retrieve(
            query="salary",
            allowed_access_levels=["employee", "hr"],
        )
        assert len(results) > 0


class TestAdminDenied:
    """Admin role has empty access — gets nothing."""

    def test_admin_retrieves_nothing(self, secured_engine):
        results = secured_engine.retrieve(
            query="salary benefits everything",
            allowed_access_levels=[],
        )
        assert len(results) == 0
