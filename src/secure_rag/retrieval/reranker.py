"""
src/secure_rag/retrieval/reranker.py — Neural Cross-Encoder Reranker
Re-ranks Stage-1 retrieval candidates using deep query-chunk cross-attention.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, List, Optional

logger = logging.getLogger(__name__)


class BaseReranker(ABC):
    """Abstract contract for retrieval rerankers."""

    @abstractmethod
    def rerank(self, query: str, chunks: List[Any], top_k: int = 5) -> List[Any]:
        """Re-ranks a list of candidate chunks for a query and returns top_k."""
        ...


class NoOpReranker(BaseReranker):
    """Pass-through reranker preserving incoming rank order (used in unit tests / fallback)."""

    def rerank(self, query: str, chunks: List[Any], top_k: int = 5) -> List[Any]:
        return chunks[:top_k]


class CrossEncoderReranker(BaseReranker):
    """
    Neural Cross-Encoder reranker using sentence-transformers.
    Computes cross-attention between the query and each chunk to eliminate noise.
    """

    def __init__(self, model_name: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"):
        self.model_name = model_name
        self._model = None
        self._load_failed = False

    def _get_model(self):
        if self._model is None and not self._load_failed:
            try:
                from sentence_transformers import CrossEncoder

                self._model = CrossEncoder(self.model_name)
            except Exception as e:
                logger.warning(
                    "Could not load CrossEncoder '%s': %s. Falling back to pass-through.",
                    self.model_name,
                    type(e).__name__,
                )
                self._load_failed = True
        return self._model

    def rerank(self, query: str, chunks: List[Any], top_k: int = 5) -> List[Any]:
        if not chunks or not query or not query.strip():
            return chunks[:top_k]

        model = self._get_model()
        if model is None:
            return chunks[:top_k]

        try:
            pairs = [[query, getattr(c, "text", "") or str(c)] for c in chunks]
            scores = model.predict(pairs)
            scored = sorted(zip(scores, chunks), key=lambda x: float(x[0]), reverse=True)
            return [chunk for _, chunk in scored[:top_k]]
        except Exception as e:
            logger.warning("Reranking failed (%s). Returning top_k un-reranked.", type(e).__name__)
            return chunks[:top_k]
