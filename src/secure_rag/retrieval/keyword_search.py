"""
src/secure_rag/retrieval/keyword_search.py — BM25 Lexical Search over SQLite Chunks
Builds BM25 index from pre-filtered SQLite chunks (status='indexed' + access_level in permitted).
"""

from typing import Any, Dict, List

from rank_bm25 import BM25Okapi

from secure_rag.db.repository import SQLiteRepository


class KeywordSearch:
    """Filtered BM25 sparse search engine over SQLite document chunks."""

    def __init__(self, repo: SQLiteRepository):
        self.repo = repo

    def search(
        self,
        query: str,
        allowed_access_levels: List[str],
        top_k: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Builds a BM25 index from authorized SQLite chunks and returns top-k results.
        Chunks are pre-filtered by access_level and document status='indexed'.
        """
        if not allowed_access_levels or not query or not query.strip():
            return []

        # Fetch only authorized, indexed chunks from SQLite
        chunks = self.repo.get_chunks_by_access_levels(allowed_access_levels)
        if not chunks:
            return []

        # Tokenize chunk texts for BM25
        tokenized_corpus = [
            (c.get("chunk_text") or "").lower().split() for c in chunks
        ]

        # Handle case where all chunks are empty
        if not any(tokenized_corpus):
            return []

        bm25 = BM25Okapi(tokenized_corpus)
        query_tokens = query.lower().split()
        scores = bm25.get_scores(query_tokens)

        # Sort by score descending, take top-k with positive scores
        scored = [(i, float(scores[i])) for i in range(len(scores)) if scores[i] > 0]
        scored.sort(key=lambda x: x[1], reverse=True)

        results = []
        for idx, score in scored[:top_k]:
            chunk = chunks[idx]
            results.append({
                "chunk_id": chunk["chunk_id"],
                "doc_id": chunk["doc_id"],
                "chunk_text": chunk.get("chunk_text", ""),
                "access_level": chunk["access_level"],
                "sparse_score": round(score, 4),
            })

        return results
