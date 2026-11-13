"""
src/secure_rag/core/tracing.py — Lightweight Latency & Observability Tracing
Captures per-control execution spans across the 7 security controls.
"""

import time
from contextlib import contextmanager
from typing import Dict, Iterator


class SpanTracer:
    """Records millisecond latency spans for pipeline operations."""

    def __init__(self):
        self._spans: Dict[str, float] = {}

    @contextmanager
    def span(self, name: str) -> Iterator[None]:
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self._spans[name] = round(elapsed_ms, 2)

    def record_manual(self, name: str, elapsed_ms: float) -> None:
        self._spans[name] = round(elapsed_ms, 2)

    def summary(self) -> Dict[str, float]:
        return dict(self._spans)
