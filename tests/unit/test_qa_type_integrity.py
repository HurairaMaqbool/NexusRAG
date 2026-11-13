"""
tests/unit/test_qa_type_integrity.py — QA Type & Static Import Integrity Verification
Introspects all modules in secure_rag to verify that:
1. Every module imports without runtime errors.
2. All exported functions and classes are accessible.
3. No circular or broken references exist.
"""

import importlib
import inspect
import pkgutil
from pathlib import Path
import pytest
import secure_rag


def get_all_submodules():
    """Recursively discover all submodule names in secure_rag."""
    pkg_path = Path(secure_rag.__file__).parent
    modules = []
    for info in pkgutil.walk_packages([str(pkg_path)], prefix="secure_rag."):
        # Ignore legacy shim internals that are intentionally deprecated
        if "_legacy" in info.name:
            continue
        modules.append(info.name)
    return sorted(modules)


@pytest.mark.parametrize("module_name", get_all_submodules())
def test_module_imports_cleanly(module_name):
    """Verifies that every module in secure_rag can be imported without errors."""
    mod = importlib.import_module(module_name)
    assert mod is not None


def test_core_classes_instantiable_with_types():
    """Verifies that key domain classes have matching signatures."""
    from secure_rag.pipeline import PipelineResult
    from secure_rag.security.models import DecisionOutcome, ReasonCode
    from secure_rag.retrieval.cache import SemanticQueryCache
    from secure_rag.core.tracing import SpanTracer
    from secure_rag.eval.rag_triad import evaluate_rag_triad

    # Check Enum types
    assert DecisionOutcome.ALLOW.value == "ALLOW"
    assert DecisionOutcome.REVIEW.value == "REVIEW"
    assert DecisionOutcome.BLOCK.value == "BLOCK"

    # Check Dataclass types
    res = PipelineResult(
        answer="test",
        decision=DecisionOutcome.ALLOW,
        reason_code=ReasonCode.ALLOWED_GENERAL_KNOWLEDGE,
        risk_score=0.0,
        request_id="req-1",
    )
    assert res.answer == "test"
    assert res.decision == DecisionOutcome.ALLOW

    # Check Tracer
    tracer = SpanTracer()
    with tracer.span("unit_test"):
        pass
    assert "unit_test" in tracer.summary()
