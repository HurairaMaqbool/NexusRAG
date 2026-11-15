"""
src/secure_rag/agent/intent.py — Thin re-export shim (canonical: secure_rag.routing.intent)
Kept for backward-compatibility with qa_test_suite and legacy agent code.
"""

from secure_rag.routing.intent import detect_intent  # noqa: F401

__all__ = ["detect_intent"]
