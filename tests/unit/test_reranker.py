"""
tests/unit/test_reranker.py — Unit tests for neural reranking components
"""

import pytest
from secure_rag.retrieval.reranker import BaseReranker, CrossEncoderReranker, NoOpReranker


class _DummyChunk:
    def __init__(self, cid: str, text: str):
        self.chunk_id = cid
        self.text = text


def test_noop_reranker_preserves_order():
    chunks = [
        _DummyChunk("c1", "first chunk"),
        _DummyChunk("c2", "second chunk"),
        _DummyChunk("c3", "third chunk"),
    ]
    reranker = NoOpReranker()
    reranked = reranker.rerank("some query", chunks, top_k=2)
    assert len(reranked) == 2
    assert reranked[0].chunk_id == "c1"
    assert reranked[1].chunk_id == "c2"


def test_cross_encoder_reranker_fallback():
    # If model is unavailable or fails, gracefully falls back without throwing
    chunks = [
        _DummyChunk("c1", "Python programming language"),
        _DummyChunk("c2", "Cooking pasta recipe"),
    ]
    reranker = CrossEncoderReranker(model_name="non-existent-model-xyz")
    reranked = reranker.rerank("coding in python", chunks, top_k=2)
    assert len(reranked) == 2
    assert reranked[0].chunk_id == "c1"
