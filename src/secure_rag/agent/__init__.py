"""
Agent package — intent detection (re-exported from routing) and legacy RAGSystem.

Production code should import detect_intent from secure_rag.routing.
RAGSystem is a legacy, unsecured orchestrator retained for offline QA testing only.
It is NOT eagerly imported to avoid pulling heavy dependencies (SentenceTransformer)
into processes that don't need it.
"""

from secure_rag.routing.intent import detect_intent

__all__ = ["detect_intent"]


def __getattr__(name: str):
    """Lazy import for RAGSystem to avoid loading SentenceTransformer at import time."""
    if name == "RAGSystem":
        from secure_rag.agent.rag_system import RAGSystem
        return RAGSystem
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
