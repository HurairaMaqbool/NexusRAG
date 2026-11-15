"""
src/secure_rag/retrieval/cache.py — Role-Aware Semantic Query Cache
Caches verified responses for high-similarity queries under identical RBAC constraints.
"""

import math
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class CachedResponse:
    query_text: str
    query_embedding: List[float]
    user_role: str
    allowed_access_levels: List[str]
    answer: str
    decision: str
    reason_code: str
    risk_score: float
    request_id: str
    cached_at: float


def _cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
    if not vec1 or not vec2 or len(vec1) != len(vec2):
        return 0.0
    dot = sum(a * b for a, b in zip(vec1, vec2))
    norm1 = math.sqrt(sum(a * a for a, b in zip(vec1, vec1)))
    norm2 = math.sqrt(sum(b * b for a, b in zip(vec2, vec2)))
    if norm1 == 0.0 or norm2 == 0.0:
        return 0.0
    return max(0.0, min(1.0, dot / (norm1 * norm2)))


class SemanticQueryCache:
    """
    In-memory semantic query cache with similarity matching and strict RBAC isolation.
    Guarantees that a cached answer for one role is NEVER served to a different role.
    """

    def __init__(
        self,
        similarity_threshold: float = 0.96,
        max_entries: int = 200,
        ttl_seconds: float = 3600.0,
    ):
        self.similarity_threshold = similarity_threshold
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._entries: List[CachedResponse] = []
        self._lock = threading.Lock()

    def get(
        self,
        query_embedding: List[float],
        user_role: str,
        allowed_access_levels: List[str],
    ) -> Optional[CachedResponse]:
        """Looks up a semantically equivalent query for the same role and access levels."""
        if not query_embedding:
            return None

        role_clean = (user_role or "").lower().strip()
        levels_clean = sorted(lvl.lower().strip() for lvl in allowed_access_levels)
        now = time.time()

        with self._lock:
            # Purge expired
            self._entries = [e for e in self._entries if (now - e.cached_at) < self.ttl_seconds]

            best_match: Optional[CachedResponse] = None
            best_sim = 0.0

            for entry in self._entries:
                if entry.user_role != role_clean:
                    continue
                if sorted(entry.allowed_access_levels) != levels_clean:
                    continue

                sim = _cosine_similarity(query_embedding, entry.query_embedding)
                if sim >= self.similarity_threshold and sim > best_sim:
                    best_sim = sim
                    best_match = entry

            return best_match

    def put(
        self,
        query_text: str,
        query_embedding: List[float],
        user_role: str,
        allowed_access_levels: List[str],
        answer: str,
        decision: str,
        reason_code: str,
        risk_score: float,
        request_id: str,
    ) -> None:
        """Stores an allowed safe query response in the semantic cache."""
        if not query_embedding or not answer:
            return

        role_clean = (user_role or "").lower().strip()
        levels_clean = sorted(lvl.lower().strip() for lvl in allowed_access_levels)

        entry = CachedResponse(
            query_text=query_text,
            query_embedding=query_embedding,
            user_role=role_clean,
            allowed_access_levels=levels_clean,
            answer=answer,
            decision=decision,
            reason_code=reason_code,
            risk_score=risk_score,
            request_id=request_id,
            cached_at=time.time(),
        )

        with self._lock:
            if len(self._entries) >= self.max_entries:
                self._entries.pop(0)  # FIFO eviction
            self._entries.append(entry)

    def clear(self) -> None:
        """Flushes the cache (e.g., when new documents are indexed or deleted)."""
        with self._lock:
            self._entries.clear()
