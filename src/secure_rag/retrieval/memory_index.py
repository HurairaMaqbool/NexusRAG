"""
src/secure_rag/retrieval/memory_index.py — Re-export shim (canonical: agent/_legacy/memory_index)
Kept so that existing tests (qa_test_suite.py) continue to import NumpyFlatL2 from this path.
"""

from secure_rag.agent._legacy.memory_index import NumpyFlatL2  # noqa: F401

__all__ = ["NumpyFlatL2"]
