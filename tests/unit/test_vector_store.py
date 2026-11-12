"""
tests/unit/test_vector_store.py — ChromaDB Vector Store & Embedding Verification Tests
Verifies cosine space configuration, telemetry opt-out, strict exclusion of chunk text from Chroma,
and pre-filtered query authorization (Decision D14, D15).
"""

import math
import secrets
import pytest

from secure_rag.retrieval.embeddings import FakeEmbedder, SentenceTransformerEmbedder
from secure_rag.retrieval.vector_store import ChromaVectorStore

@pytest.fixture
def memory_vector_store():
    """Provides an isolated in-memory ChromaVectorStore for fast testing."""
    coll_name = f"test_coll_{secrets.token_hex(6)}"
    return ChromaVectorStore(persist_dir=":memory:", collection_name=coll_name)

def test_fake_embedder_properties():
    """Verifies FakeEmbedder generates deterministic, unit-normalized vectors."""
    embedder = FakeEmbedder(dimension=384)
    vec1 = embedder.embed_text("Employee vacation guidelines")
    vec2 = embedder.embed_text("Employee vacation guidelines")
    vec3 = embedder.embed_text("Different query string")

    assert len(vec1) == 384
    assert vec1 == vec2
    assert vec1 != vec3

    # Verify L2 unit norm: sum(x^2) ~= 1.0
    norm = math.sqrt(sum(x * x for x in vec1))
    assert abs(norm - 1.0) < 1e-4

def test_vector_store_initialization_and_cosine_metric(memory_vector_store):
    """Verifies collection is created with cosine distance space (Decision D14)."""
    metadata = memory_vector_store.collection.metadata
    assert metadata.get("hnsw:space") == "cosine"

def test_no_chunk_text_stored_in_chroma(memory_vector_store):
    """
    STRICT SECURITY REQUIREMENT (Decision D14):
    ChromaDB must store ONLY vectors and minimal metadata (chunk_id, doc_id, access_level).
    Chunk text MUST NOT be stored in Chroma.
    """
    embedder = FakeEmbedder()
    chunk_ids = ["chunk-001", "chunk-002"]
    embeddings = embedder.embed_batch(["text one", "text two"])
    metadatas = [
        {"chunk_id": "chunk-001", "doc_id": "doc-1", "access_level": "employee"},
        {"chunk_id": "chunk-002", "doc_id": "doc-1", "access_level": "hr"},
    ]

    memory_vector_store.add_chunks(chunk_ids, embeddings, metadatas)

    # Inspect stored collection contents directly from Chroma
    stored = memory_vector_store.collection.get(ids=chunk_ids, include=["metadatas", "documents"])
    assert stored["documents"] is None or all(d is None for d in stored["documents"])
    for m in stored["metadatas"]:
        assert "chunk_text" not in m
        assert "content" not in m
        assert set(m.keys()) == {"chunk_id", "doc_id", "access_level"}

def test_vector_store_query_empty_access_levels_returns_empty_immediately(memory_vector_store):
    """
    Deny-by-default (Decision D14):
    Querying with an empty allowed_access_levels list returns [] immediately without querying Chroma.
    """
    embedder = FakeEmbedder()
    memory_vector_store.add_chunks(
        chunk_ids=["c-emp-1"],
        embeddings=[embedder.embed_text("Sample chunk")],
        metadatas=[{"chunk_id": "c-emp-1", "doc_id": "d-1", "access_level": "employee"}]
    )

    query_vec = embedder.embed_text("Search query")
    results = memory_vector_store.query(query_embedding=query_vec, allowed_access_levels=[])
    assert results == []

def test_vector_store_pre_filtered_query_isolation(memory_vector_store):
    """
    Access Control Test (Decision D14):
    Verifies that querying with ['employee'] NEVER retrieves 'hr' documents.
    """
    embedder = FakeEmbedder()
    chunks = [
        ("c-emp-1", "General policy on sick leave", "employee"),
        ("c-emp-2", "General policy on holidays", "employee"),
        ("c-hr-1", "Executive salary bands and bonus multipliers", "hr"),
        ("c-hr-2", "Disciplinary action records", "hr"),
    ]

    memory_vector_store.add_chunks(
        chunk_ids=[c[0] for c in chunks],
        embeddings=embedder.embed_batch([c[1] for c in chunks]),
        metadatas=[{"chunk_id": c[0], "doc_id": f"d-{c[0]}", "access_level": c[2]} for c in chunks]
    )

    query_vec = embedder.embed_text("salary and compensation")

    # 1. Employee query — must NEVER return HR chunks
    emp_results = memory_vector_store.query(query_vec, allowed_access_levels=["employee"], top_k=10)
    assert len(emp_results) > 0
    for r in emp_results:
        assert r["access_level"] == "employee"
        assert "hr" not in r["chunk_id"]

    # 2. HR query — can retrieve both employee and HR chunks
    hr_results = memory_vector_store.query(query_vec, allowed_access_levels=["employee", "hr"], top_k=10)
    levels = {r["access_level"] for r in hr_results}
    assert "hr" in levels or "employee" in levels

def test_vector_store_delete_document_vectors(memory_vector_store):
    """Verifies that delete_chunks_by_doc_id removes all vectors for that doc."""
    embedder = FakeEmbedder()
    memory_vector_store.add_chunks(
        chunk_ids=["c-1", "c-2", "c-3"],
        embeddings=embedder.embed_batch(["a", "b", "c"]),
        metadatas=[
            {"chunk_id": "c-1", "doc_id": "doc-del", "access_level": "employee"},
            {"chunk_id": "c-2", "doc_id": "doc-del", "access_level": "employee"},
            {"chunk_id": "c-3", "doc_id": "doc-keep", "access_level": "employee"},
        ]
    )
    assert memory_vector_store.count() == 3

    memory_vector_store.delete_chunks_by_doc_id("doc-del")
    assert memory_vector_store.count() == 1
    remaining = memory_vector_store.get_all_vector_ids()
    assert remaining == ["c-3"]

def test_chroma_zero_network_egress_when_telemetry_disabled(tmp_path, monkeypatch):
    """
    Security & telemetry egress test (D1):
    Blocks all network connections at the socket layer (socket.connect and socket.create_connection).
    Executes add, query, and delete against a real persistent Chroma client in tmp_path.
    The test passes if and only if NO network connection is attempted.
    """
    import socket

    def blocked_connect(*args, **kwargs):
        raise AssertionError("Network connection attempted during Chroma operation!")

    monkeypatch.setattr(socket.socket, "connect", blocked_connect)
    monkeypatch.setattr(socket, "create_connection", blocked_connect)

    persist_dir = str(tmp_path / "offline_chroma")
    store = ChromaVectorStore(persist_dir=persist_dir, collection_name="offline_test")

    chunk_ids = ["offline-1", "offline-2"]
    embeddings = [[0.05] * 384, [0.1] * 384]
    metadatas = [
        {"chunk_id": "offline-1", "doc_id": "doc-off-1", "access_level": "employee"},
        {"chunk_id": "offline-2", "doc_id": "doc-off-1", "access_level": "employee"},
    ]

    # Add chunks
    store.add_chunks(chunk_ids, embeddings, metadatas)
    assert store.count() == 2

    # Query chunks
    results = store.query([0.05] * 384, ["employee"], top_k=2)
    assert len(results) == 2

    # Delete chunks
    store.delete_chunks_by_doc_id("doc-off-1")
    assert store.count() == 0


# ── Slow Test: Real SentenceTransformer Verification (Decision D15) ───────────

@pytest.mark.slow
def test_real_sentence_transformer_model_loading_and_normalization():
    """
    Slow integration test:
    Loads real SentenceTransformer model ('all-MiniLM-L6-v2'), verifies dimension=384,
    and asserts vectors are unit-normalized (|norm - 1.0| < 1e-4).
    """
    embedder = SentenceTransformerEmbedder("sentence-transformers/all-MiniLM-L6-v2")
    assert embedder.dimension == 384

    vec = embedder.embed_text("Testing real sentence transformers integration.")
    assert len(vec) == 384

    norm = math.sqrt(sum(x * x for x in vec))
    assert abs(norm - 1.0) < 1e-4
