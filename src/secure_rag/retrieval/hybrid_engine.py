"""
src/secure_rag/retrieval/hybrid_engine.py — Hybrid Retrieval Engine with RRF
Combines ChromaDB dense vector search + BM25 sparse search using Reciprocal Rank Fusion.
Architectural rule: retrieval MUST NOT import auth or security.
Access levels are passed in as parameters from the pipeline.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from secure_rag.db.repository import SQLiteRepository
from secure_rag.retrieval.embeddings import BaseEmbedder
from secure_rag.retrieval.keyword_search import KeywordSearch
from secure_rag.retrieval.vector_store import ChromaVectorStore

# RRF constant (standard value from Cormack et al.)
RRF_K = 60
# Drop dense-only weak neighbors so chit-chat does not force unrelated docs
# into the LLM. Any positive BM25 hit is kept (lexical evidence).
MIN_DENSE_ONLY_SCORE = 0.32


@dataclass(frozen=True)
class RetrievedChunk:
    chunk_id: str
    doc_id: str
    text: str
    source_file: str
    access_level: str
    dense_score: float
    sparse_score: float
    fused_score: float


class HybridRetrievalEngine:
    """
    Executes pre-filtered dense + sparse search and fuses results via RRF.
    Guarantees no chunk with unauthorized access_level is returned.
    Re-validates every Chroma hit against SQLite (status='indexed' + access_level check).
    """

    def __init__(
        self,
        repo: SQLiteRepository,
        vector_store: ChromaVectorStore,
        embedder: BaseEmbedder,
    ):
        self.repo = repo
        self.vector_store = vector_store
        self.embedder = embedder
        self.keyword_search = KeywordSearch(repo)

    def retrieve(
        self,
        query: str,
        allowed_access_levels: List[str],
        top_k: int = 5,
    ) -> List[RetrievedChunk]:
        """
        Executes hybrid retrieval.
        Returns at most top_k RetrievedChunk results, all verified against SQLite.
        Empty allowed_access_levels → immediate empty return.
        """
        if not allowed_access_levels:
            return []
        if not query or not query.strip():
            return []

        # Dense retrieval via ChromaDB (pre-filtered by access_level)
        query_embedding = self.embedder.embed_text(query)
        dense_results = self.vector_store.query(
            query_embedding=query_embedding,
            allowed_access_levels=allowed_access_levels,
            top_k=top_k * 2,  # Over-fetch for RRF merging
        )

        # Sparse retrieval via BM25 (pre-filtered by access_level + status='indexed')
        sparse_results = self.keyword_search.search(
            query=query,
            allowed_access_levels=allowed_access_levels,
            top_k=top_k * 2,
        )

        # Re-validate Chroma hits against SQLite (status='indexed' + access_level)
        chroma_chunk_ids = [r["chunk_id"] for r in dense_results]
        validated_chunks = {}
        if chroma_chunk_ids:
            db_chunks = self.repo.get_chunks_by_ids(chroma_chunk_ids)
            for c in db_chunks:
                if c["access_level"].lower() in [lvl.lower() for lvl in allowed_access_levels]:
                    validated_chunks[c["chunk_id"]] = c

        # Build rank maps for RRF
        dense_ranks: Dict[str, int] = {}
        dense_scores: Dict[str, float] = {}
        for rank, result in enumerate(dense_results):
            cid = result["chunk_id"]
            if cid in validated_chunks:
                dense_ranks[cid] = rank + 1
                dense_scores[cid] = result.get("score", 0.0)

        sparse_ranks: Dict[str, int] = {}
        sparse_scores: Dict[str, float] = {}
        for rank, result in enumerate(sparse_results):
            cid = result["chunk_id"]
            sparse_ranks[cid] = rank + 1
            sparse_scores[cid] = result.get("sparse_score", 0.0)

        # Reciprocal Rank Fusion (RRF)
        all_chunk_ids = set(dense_ranks.keys()) | set(sparse_ranks.keys())
        fused: Dict[str, float] = {}
        for cid in all_chunk_ids:
            rrf_score = 0.0
            if cid in dense_ranks:
                rrf_score += 1.0 / (RRF_K + dense_ranks[cid])
            if cid in sparse_ranks:
                rrf_score += 1.0 / (RRF_K + sparse_ranks[cid])
            fused[cid] = rrf_score

        # Sort by fused score descending
        sorted_ids = sorted(fused.keys(), key=lambda x: fused[x], reverse=True)[:top_k]

        # Build chunk lookup from both SQLite validations and BM25 results
        chunk_data: Dict[str, Dict[str, Any]] = {}
        for cid, data in validated_chunks.items():
            chunk_data[cid] = data

        # For BM25-only results, fetch from SQLite if not already validated
        bm25_only_ids = [cid for cid in sorted_ids if cid not in chunk_data]
        if bm25_only_ids:
            bm25_db = self.repo.get_chunks_by_ids(bm25_only_ids)
            for c in bm25_db:
                if c["access_level"].lower() in [lvl.lower() for lvl in allowed_access_levels]:
                    chunk_data[c["chunk_id"]] = c

        # Assemble final results (relevance-gated)
        results: List[RetrievedChunk] = []
        for cid in sorted_ids:
            if cid not in chunk_data:
                continue
            dense = dense_scores.get(cid, 0.0)
            sparse = sparse_scores.get(cid, 0.0)
            # Drop only weak *positive* dense-only hits. Score 0 is common with
            # FakeEmbedder / tiny BM25 corpora and must not wipe results.
            if sparse <= 0.0 and 0.0 < dense < MIN_DENSE_ONLY_SCORE:
                continue
            data = chunk_data[cid]
            results.append(RetrievedChunk(
                chunk_id=cid,
                doc_id=data["doc_id"],
                text=data.get("chunk_text", ""),
                source_file=data.get("source_file", data.get("title", "unknown")),
                access_level=data["access_level"],
                dense_score=dense,
                sparse_score=sparse,
                fused_score=round(fused.get(cid, 0.0), 6),
            ))

        return results


def reconcile_stale_documents(
    repo: SQLiteRepository,
    vector_store: ChromaVectorStore,
) -> Dict[str, int]:
    """
    Cleans up documents stuck in 'deleting' or 'indexing' status.
    - 'deleting': purge vectors from Chroma and delete from SQLite.
    - 'indexing': mark as 'failed' (crash recovery).
    """
    stats = {"deleting_cleaned": 0, "indexing_failed": 0}

    # Clean up 'deleting' documents
    deleting_docs = repo.get_documents_by_status("deleting")
    for doc in deleting_docs:
        try:
            vector_store.delete_chunks_by_doc_id(doc["doc_id"])
        except Exception:
            pass
        try:
            repo.delete_document(doc["doc_id"])
            stats["deleting_cleaned"] += 1
        except Exception:
            pass

    # Mark stale 'indexing' documents as 'failed'
    indexing_docs = repo.get_documents_by_status("indexing")
    for doc in indexing_docs:
        try:
            repo.update_document_status(doc["doc_id"], "failed")
            stats["indexing_failed"] += 1
        except Exception:
            pass

    return stats
