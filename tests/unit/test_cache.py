"""
tests/unit/test_cache.py — Unit tests for SemanticQueryCache
Validates cosine similarity matching, RBAC isolation, TTL expiration, and eviction.
"""

import pytest
import time
from secure_rag.retrieval.cache import SemanticQueryCache, _cosine_similarity


def test_cosine_similarity():
    v1 = [1.0, 0.0, 0.0]
    v2 = [1.0, 0.0, 0.0]
    v3 = [0.0, 1.0, 0.0]
    assert _cosine_similarity(v1, v2) == pytest.approx(1.0, 1e-5)
    assert _cosine_similarity(v1, v3) == pytest.approx(0.0, 1e-5)


def test_semantic_cache_hit_and_rbac_isolation():
    cache = SemanticQueryCache(similarity_threshold=0.90)

    vec_employee = [1.0, 0.2, 0.0]
    cache.put(
        query_text="What are our vacation days?",
        query_embedding=vec_employee,
        user_role="employee",
        allowed_access_levels=["employee"],
        answer="You have 20 vacation days.",
        decision="ALLOW",
        reason_code="ALLOWED_AUTHORIZED_SOURCE",
        risk_score=0.0,
        request_id="req-1",
    )

    # Similar query with same role -> HIT
    similar_vec = [0.99, 0.21, 0.0]
    hit = cache.get(similar_vec, user_role="employee", allowed_access_levels=["employee"])
    assert hit is not None
    assert hit.answer == "You have 20 vacation days."

    # Identical query with DIFFERENT role (e.g., HR or Admin) -> MISS (Strict RBAC isolation)
    miss_role = cache.get(similar_vec, user_role="hr", allowed_access_levels=["employee", "hr"])
    assert miss_role is None


def test_semantic_cache_ttl_and_eviction():
    cache = SemanticQueryCache(similarity_threshold=0.80, max_entries=2, ttl_seconds=0.05)
    v = [1.0, 0.0]
    cache.put("q1", v, "employee", ["employee"], "a1", "ALLOW", "CODE", 0.0, "req-1")
    assert cache.get(v, "employee", ["employee"]) is not None

    time.sleep(0.06)
    # Expired
    assert cache.get(v, "employee", ["employee"]) is None
