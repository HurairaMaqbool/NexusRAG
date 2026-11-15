"""
src/secure_rag/agent/_legacy/memory_index.py — Numpy L2 Flat Vector Index
Pure-NumPy vector index providing FAISS-compatible search without native dependencies.
"""

import numpy as np


class NumpyFlatL2:
    """L2 distance flat vector index — no FAISS dependency required."""

    def __init__(self, dimension: int):
        self.dimension = dimension
        self.embeddings: np.ndarray | None = None
        self.ntotal = 0

    def add(self, vectors: np.ndarray):
        if self.embeddings is None:
            self.embeddings = vectors.copy()
        else:
            self.embeddings = np.vstack((self.embeddings, vectors))
        self.ntotal = self.embeddings.shape[0]

    def search(self, queries: np.ndarray, k: int):
        if self.embeddings is None or self.ntotal == 0:
            return np.array([[]]), np.array([[]])
        k = min(k, self.ntotal)
        diff = self.embeddings[np.newaxis, :, :] - queries[:, np.newaxis, :]
        distances = np.sum(diff ** 2, axis=-1)
        indices = np.argsort(distances, axis=-1)[:, :k]
        top_distances = np.take_along_axis(distances, indices, axis=-1)
        return top_distances, indices

    def reset(self):
        self.embeddings = None
        self.ntotal = 0
