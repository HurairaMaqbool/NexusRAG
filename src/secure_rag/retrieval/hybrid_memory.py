"""
src/secure_rag/retrieval/hybrid_memory.py — Re-export shim (canonical: agent/_legacy/hybrid_memory)
Kept so that existing tests (qa_test_suite.py) continue to import HybridMemoryStore from this path.
"""

from secure_rag.agent._legacy.hybrid_memory import HybridMemoryStore  # noqa: F401

__all__ = ["HybridMemoryStore"]
