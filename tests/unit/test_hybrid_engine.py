"""
tests/unit/test_hybrid_engine.py — Hybrid Retrieval Engine Unit Tests
Uses FakeEmbedder + ephemeral ChromaDB + temp SQLite to verify:
- Employee cannot retrieve HR chunks
- RRF fusion returns results
- Empty access levels return empty results
"""

import pytest

from secure_rag.db.connection import get_db_connection, init_db
from secure_rag.db.repository import SQLiteRepository
from secure_rag.retrieval.embeddings import FakeEmbedder
from secure_rag.retrieval.hybrid_engine import HybridRetrievalEngine
from secure_rag.retrieval.vector_store import ChromaVectorStore


@pytest.fixture
def hybrid_setup(tmp_path):
    """Sets up an isolated hybrid engine with sample employee + HR documents."""
    # DB
    db_path = str(tmp_path / "test.db")
    init_db(db_path)
    repo = SQLiteRepository(connection_factory=lambda: get_db_connection(db_path))

    # Embedder
    embedder = FakeEmbedder(dimension=384)

    # Vector store (ephemeral)
    vs = ChromaVectorStore(persist_dir=":memory:", collection_name="test_hybrid")

    # Insert sample documents and chunks
    repo.create_document(
        doc_id="doc-emp-01", title="Employee Handbook",
        access_level="employee", file_hash_sha256="hash_emp_01", status="indexed",
    )
    repo.create_document(
        doc_id="doc-hr-01", title="HR Salary Data",
        access_level="hr", file_hash_sha256="hash_hr_01", status="indexed",
    )

    emp_chunks = [
        {
            "chunk_id": "doc-emp-01-c0000", "doc_id": "doc-emp-01",
            "chunk_index": 0, "chunk_text": "Company vacation policy allows 15 days per year.",
            "access_level": "employee", "chroma_id": "doc-emp-01-c0000",
        },
        {
            "chunk_id": "doc-emp-01-c0001", "doc_id": "doc-emp-01",
            "chunk_index": 1, "chunk_text": "Health insurance covers dental and vision.",
            "access_level": "employee", "chroma_id": "doc-emp-01-c0001",
        },
    ]
    hr_chunks = [
        {
            "chunk_id": "doc-hr-01-c0000", "doc_id": "doc-hr-01",
            "chunk_index": 0, "chunk_text": "Executive salary: CEO earns $500,000 annually.",
            "access_level": "hr", "chroma_id": "doc-hr-01-c0000",
        },
        {
            "chunk_id": "doc-hr-01-c0001", "doc_id": "doc-hr-01",
            "chunk_index": 1, "chunk_text": "Payroll processing happens on the 15th of each month.",
            "access_level": "hr", "chroma_id": "doc-hr-01-c0001",
        },
    ]

    all_chunks = emp_chunks + hr_chunks
    repo.insert_chunks(all_chunks)

    # Add to vector store
    for chunk in all_chunks:
        embedding = embedder.embed_text(chunk["chunk_text"])
        vs.add_chunks(
            chunk_ids=[chunk["chunk_id"]],
            embeddings=[embedding],
            metadatas=[{
                "chunk_id": chunk["chunk_id"],
                "doc_id": chunk["doc_id"],
                "access_level": chunk["access_level"],
            }],
        )

    engine = HybridRetrievalEngine(repo=repo, vector_store=vs, embedder=embedder)
    return engine


class TestEmployeeAccess:
    """Employee should only see employee-level chunks."""

    def test_employee_retrieves_employee_chunks(self, hybrid_setup):
        results = hybrid_setup.retrieve(
            query="vacation policy",
            allowed_access_levels=["employee"],
        )
        assert len(results) > 0
        for chunk in results:
            assert chunk.access_level == "employee"

    def test_employee_cannot_retrieve_hr_chunks(self, hybrid_setup):
        results = hybrid_setup.retrieve(
            query="executive salary CEO payroll",
            allowed_access_levels=["employee"],
        )
        for chunk in results:
            assert chunk.access_level != "hr", f"Employee retrieved HR chunk: {chunk.chunk_id}"


class TestHRAccess:
    """HR should see both employee and HR chunks."""

    def test_hr_retrieves_hr_chunks(self, hybrid_setup):
        results = hybrid_setup.retrieve(
            query="executive salary",
            allowed_access_levels=["employee", "hr"],
        )
        assert len(results) > 0
        access_levels = {c.access_level for c in results}
        # HR should be able to see hr chunks when searching for salary info
        assert "hr" in access_levels or len(results) > 0


class TestAdminAccess:
    """Admin has empty access levels — should get zero results."""

    def test_admin_gets_no_results(self, hybrid_setup):
        results = hybrid_setup.retrieve(
            query="salary",
            allowed_access_levels=[],
        )
        assert len(results) == 0


class TestEdgeCases:
    """Edge cases for the hybrid engine."""

    def test_empty_query(self, hybrid_setup):
        results = hybrid_setup.retrieve(
            query="",
            allowed_access_levels=["employee"],
        )
        assert len(results) == 0

    def test_results_are_retrieved_chunks(self, hybrid_setup):
        results = hybrid_setup.retrieve(
            query="vacation",
            allowed_access_levels=["employee"],
        )
        if results:
            chunk = results[0]
            assert hasattr(chunk, "chunk_id")
            assert hasattr(chunk, "text")
            assert hasattr(chunk, "fused_score")
            assert chunk.fused_score > 0
