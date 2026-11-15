"""
tests/unit/test_differential_privacy.py — Unit tests for Vector Embedding Differential Privacy
"""

import math
import pytest
from secure_rag.retrieval.vector_store import apply_differential_privacy, _cosine_distance


def test_differential_privacy_preserves_similarity():
    # Original normalized unit vector
    vec = [0.6, 0.8, 0.0]
    perturbed = apply_differential_privacy(vec, noise_scale=0.0001)

    # Output must have same dimensionality
    assert len(perturbed) == len(vec)

    # Output must remain unit length (normalized)
    norm = math.sqrt(sum(v * v for v in perturbed))
    assert norm == pytest.approx(1.0, 1e-6)

    # Cosine distance between original and perturbed must be virtually 0 (< 0.0001)
    dist = _cosine_distance(vec, perturbed)
    assert dist < 0.0001


def test_differential_privacy_changes_raw_values():
    vec = [0.5, 0.5, 0.5, 0.5]
    perturbed = apply_differential_privacy(vec, noise_scale=0.001)
    # The raw values must differ to defeat raw vector inversion
    assert perturbed != vec
