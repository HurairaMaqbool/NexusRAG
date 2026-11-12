"""
src/secure_rag/agent/_legacy/hybrid_memory.py — In-Memory Hybrid Search Store
Combines dense (NumpyFlatL2) and sparse (BM25) retrieval with MD5 deduplication.
"""

import hashlib

import numpy as np
from rank_bm25 import BM25Okapi

from secure_rag.agent._legacy.memory_index import NumpyFlatL2


class HybridMemoryStore:
    """Manages in-memory chunks with dual dense+sparse search and deduplication."""

    def __init__(self, dimension: int):
        self.index = NumpyFlatL2(dimension)
        self.chunks: list[dict] = []
        self.bm25: BM25Okapi | None = None

    def _rebuild_bm25(self):
        if not self.chunks:
            self.bm25 = None
            return
        tokenized = [c["text"].lower().split() for c in self.chunks]
        self.bm25 = BM25Okapi(tokenized)

    def add(self, new_chunks: list[dict], embeddings: np.ndarray):
        """Append chunks and their embeddings to the store, then rebuild BM25."""
        self.chunks.extend(new_chunks)
        self.index.add(np.array(embeddings, dtype="float32"))
        self._rebuild_bm25()

    def search(self, query_embedding: np.ndarray, query_text: str, top_k: int = 5) -> list[dict]:
        """Combine semantic + keyword search, deduplicate by content hash."""
        if not self.chunks:
            return []

        top_k = min(top_k, len(self.chunks))

        # Semantic (dense) search
        _, I = self.index.search(np.array(query_embedding, dtype="float32"), top_k)
        semantic_results = [self.chunks[i] for i in I[0] if i < len(self.chunks)]

        # Keyword (sparse) BM25 search
        keyword_results = []
        if self.bm25:
            scores = self.bm25.get_scores(query_text.lower().split())
            bm25_top = np.argsort(scores)[::-1][:top_k]
            keyword_results = [self.chunks[i] for i in bm25_top if scores[i] > 0]

        # Merge + deduplicate by MD5 hash of text
        seen: set[str] = set()
        merged: list[dict] = []
        for c in semantic_results + keyword_results:
            key = hashlib.md5(c["text"].encode()).hexdigest()
            if key not in seen:
                seen.add(key)
                merged.append(c)

        return merged[:top_k]
