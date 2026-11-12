"""
src/secure_rag/retrieval/embeddings.py — Embedding Generation & Abstraction
Provides normalized embedding generation with dependency-injected mock/fake support for fast testing (Decision D15).
"""

from abc import ABC, abstractmethod
import hashlib
import math
from typing import List, Optional

class BaseEmbedder(ABC):
    """Abstract interface for dense embedding generation."""

    @abstractmethod
    def embed_text(self, text: str) -> List[float]:
        """Generates a dense vector for a single text string."""
        pass

    @abstractmethod
    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generates dense vectors for a batch of text strings."""
        pass

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Dimensionality of generated vectors."""
        pass

class SentenceTransformerEmbedder(BaseEmbedder):
    """
    Production embedder using sentence-transformers (all-MiniLM-L6-v2 by default).
    Generates L2-normalized embeddings suitable for cosine similarity.
    """

    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        self.model_name = model_name
        self._model = None
        self._dimension: Optional[int] = None

    def _get_model(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.model_name)
            dim_fn = getattr(self._model, "get_embedding_dimension", getattr(self._model, "get_sentence_embedding_dimension", None))
            self._dimension = dim_fn() if dim_fn else 384
        return self._model

    @property
    def dimension(self) -> int:
        if self._dimension is None:
            self._get_model()
        return self._dimension or 384

    def embed_text(self, text: str) -> List[float]:
        model = self._get_model()
        embedding = model.encode(text, normalize_embeddings=True)
        return embedding.tolist()

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []
        model = self._get_model()
        embeddings = model.encode(texts, normalize_embeddings=True)
        return [e.tolist() for e in embeddings]

class FakeEmbedder(BaseEmbedder):
    """
    Deterministic pseudo-embedder for fast, reproducible unit testing.
    Produces unit-normalized vectors derived from input text hashes without loading PyTorch.
    """

    def __init__(self, dimension: int = 384):
        self._dimension = dimension

    @property
    def dimension(self) -> int:
        return self._dimension

    def _hash_to_vector(self, text: str) -> List[float]:
        # Generate pseudo-random deterministic floats from text hash
        raw_bytes = hashlib.sha256(text.encode("utf-8")).digest()
        vec = []
        for i in range(self._dimension):
            byte_val = raw_bytes[i % len(raw_bytes)]
            val = ((byte_val ^ (i & 0xFF)) - 128.0) / 128.0
            vec.append(val)

        # L2-normalize vector to unit length
        norm = math.sqrt(sum(x * x for x in vec))
        if norm > 0:
            return [x / norm for x in vec]
        return [1.0 / math.sqrt(self._dimension)] * self._dimension

    def embed_text(self, text: str) -> List[float]:
        return self._hash_to_vector(text)

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        return [self._hash_to_vector(t) for t in texts]
