"""
src/secure_rag/retrieval — Production Retrieval Components
Exports: Embeddings, ChromaDB vector store, keyword search, and hybrid engine.
Legacy in-memory stores (NumpyFlatL2, HybridMemoryStore) live in agent/_legacy
and are importable from their old paths via re-export shims but are NOT part of
the production public API.
"""

from secure_rag.retrieval.embeddings import BaseEmbedder, SentenceTransformerEmbedder, FakeEmbedder
from secure_rag.retrieval.vector_store import ChromaVectorStore
from secure_rag.retrieval.keyword_search import KeywordSearch
from secure_rag.retrieval.hybrid_engine import HybridRetrievalEngine, RetrievedChunk

__all__ = [
    "BaseEmbedder",
    "SentenceTransformerEmbedder",
    "FakeEmbedder",
    "ChromaVectorStore",
    "KeywordSearch",
    "HybridRetrievalEngine",
    "RetrievedChunk",
]
