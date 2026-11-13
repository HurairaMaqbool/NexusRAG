"""
tests/unit/test_tracing.py — Unit tests for SpanTracer
"""

import time
from secure_rag.core.tracing import SpanTracer


def test_span_tracer_records_durations():
    tracer = SpanTracer()
    with tracer.span("test_operation"):
        time.sleep(0.01)

    summary = tracer.summary()
    assert "test_operation" in summary
    assert summary["test_operation"] >= 5.0  # At least ~10ms with margin
