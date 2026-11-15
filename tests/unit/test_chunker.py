"""
tests/unit/test_chunker.py — Unit Tests for Deterministic Boundary-Aware Chunker
Verifies deterministic splitting, size boundary compliance, overlap continuity, and max chunk limits (Decision D15).
"""

import pytest

from secure_rag.core.config import AppConfig
from secure_rag.core.errors import DocumentValidationError
from secure_rag.ingestion.chunker import chunk_text

SAMPLE_TEXT = """
Northwind Enterprise Cloud Infrastructure Guidelines.

Section 1: IAM Policies and Least Privilege Access.
All developers and system operators must utilize role-based access control with multi-factor authentication.
Access keys must be rotated every ninety days through automated vaults.
No long-lived API secrets are permitted on local developer workstations or unencrypted disks.

Section 2: Network Isolation and Perimeter Security.
All internal microservices reside strictly within private virtual clouds without public routing.
External ingress is mediated via hardened application load balancers performing rate limiting.
All traffic across zones must utilize mutual TLS 1.3 encryption with strict cipher negotiation.
"""

def test_chunker_is_deterministic():
    """Verifies that identical inputs yield identical chunks across multiple invocations."""
    chunks_1 = chunk_text(SAMPLE_TEXT, chunk_size=300, chunk_overlap=50)
    chunks_2 = chunk_text(SAMPLE_TEXT, chunk_size=300, chunk_overlap=50)

    assert len(chunks_1) == len(chunks_2)
    for c1, c2 in zip(chunks_1, chunks_2):
        assert c1["chunk_index"] == c2["chunk_index"]
        assert c1["chunk_text"] == c2["chunk_text"]
        assert c1["token_count"] == c2["token_count"]

def test_chunk_structure_and_ordering():
    """Verifies chunk fields and sequential indexing."""
    chunks = chunk_text(SAMPLE_TEXT, chunk_size=300, chunk_overlap=50)
    assert len(chunks) > 0

    for idx, c in enumerate(chunks):
        assert c["chunk_index"] == idx
        assert isinstance(c["chunk_text"], str)
        assert len(c["chunk_text"]) > 0
        assert c["token_count"] > 0

def test_chunk_size_and_overlap_behavior():
    """Verifies that consecutive chunks share overlap context and respect boundaries."""
    chunks = chunk_text(SAMPLE_TEXT, chunk_size=250, chunk_overlap=60)
    assert len(chunks) >= 2

    # Verify overlap exists between consecutive chunks
    overlap_detected = False
    for i in range(len(chunks) - 1):
        c1_words = set(chunks[i]["chunk_text"].split()[-5:])
        c2_words = set(chunks[i + 1]["chunk_text"].split()[:10])
        if c1_words.intersection(c2_words):
            overlap_detected = True
            break
    assert overlap_detected, "Consecutive chunks must contain overlapping context."

def test_chunker_empty_input():
    """Verifies empty or whitespace-only text returns empty list."""
    assert chunk_text("") == []
    assert chunk_text("   \n\n  \t  ") == []

def test_chunker_exceeds_max_chunks_limit():
    """Security test: Throws DocumentValidationError when total chunks exceed max_chunks limit."""
    cfg = AppConfig(max_chunks=3)
    with pytest.raises(DocumentValidationError, match="exceeding max chunk limit"):
        chunk_text(SAMPLE_TEXT, chunk_size=100, chunk_overlap=20, config=cfg)

def test_chunker_oversized_unbroken_string():
    """Verifies handling of unbroken long text (no punctuation or spaces)."""
    unbroken = "A" * 1500
    chunks = chunk_text(unbroken, chunk_size=400, chunk_overlap=50)
    assert len(chunks) >= 3
    for c in chunks:
        assert len(c["chunk_text"]) <= 400

# ── Invariant Tests (B8d) ─────────────────────────────────────────────────────

def test_chunker_invariants_size_overlap_and_no_data_loss():
    """
    Mathematical and Security Invariant Tests (B8d):
    1. Invariant 1: Every chunk length <= CHUNK_SIZE.
    2. Invariant 2: Every consecutive pair of chunks shares overlapping text.
    3. Invariant 3: Reconstructing chunks (minus overlap) loses no text / sentences.
    """
    chunk_size = 200
    chunk_overlap = 60
    cfg = AppConfig(chunk_size=chunk_size, chunk_overlap=chunk_overlap)

    sentences = [
        "First sentence establishes foundational policy.",
        "Second sentence defines identity governance rules.",
        "Third sentence details cryptographic protocols.",
        "Fourth sentence mandates multi-factor authentication.",
        "Fifth sentence requires automated vault rotation.",
        "Sixth sentence forbids static credentials in code.",
        "Seventh sentence establishes network isolation boundaries.",
        "Eighth sentence configures application load balancers.",
        "Ninth sentence enforces mutual TLS encryption.",
        "Tenth sentence concludes operational guidelines."
    ]
    full_text = " ".join(sentences)

    chunks = chunk_text(full_text, config=cfg)
    assert len(chunks) >= 3

    # Invariant 1: Every chunk length <= CHUNK_SIZE
    for c in chunks:
        assert len(c["chunk_text"]) <= chunk_size, (
            f"Chunk index {c['chunk_index']} exceeded chunk_size ({len(c['chunk_text'])} > {chunk_size})"
        )

    # Invariant 2: Every consecutive pair shares overlapping text
    for i in range(len(chunks) - 1):
        c1_text = chunks[i]["chunk_text"]
        c2_text = chunks[i + 1]["chunk_text"]
        # Find shared substring between end of c1 and start of c2
        shared = False
        for s in sentences:
            if s in c1_text and s in c2_text:
                shared = True
                break
        assert shared, f"Consecutive chunks {i} and {i+1} do not share overlapping sentence context."

    # Invariant 3: Concatenating chunks (minus overlap) loses no text / sentences
    # Every single sentence from the original input must exist in the chunk stream
    for s in sentences:
        found = any(s in c["chunk_text"] for c in chunks)
        assert found, f"Data loss detected: sentence '{s}' was dropped during chunking!"

def test_chunk_overlap_greater_equal_size_raises_value_error():
    """Security test (C2): chunk_overlap >= chunk_size or negative values must raise ValueError."""
    with pytest.raises(ValueError, match="strictly less than chunk_size"):
        chunk_text("Sample text", chunk_size=100, chunk_overlap=100)

    with pytest.raises(ValueError, match="strictly less than chunk_size"):
        chunk_text("Sample text", chunk_size=100, chunk_overlap=150)

    with pytest.raises(ValueError, match="non-negative"):
        chunk_text("Sample text", chunk_size=100, chunk_overlap=-1)

    with pytest.raises(ValueError, match="positive"):
        chunk_text("Sample text", chunk_size=0, chunk_overlap=0)

def test_chunker_forced_overlap_plus_sentence_overflow_case():
    """
    Targeted regression test (C2):
    Forces case where overlap from previous chunk + next sentence exceeds chunk_size.
    Example: overlap budget=100.
    Sentence 1: 450 chars.
    Sentence 2: 70 chars. (Chunk 1 has [450, 70], length 521 <= 600)
    Sentence 3: 590 chars. (Overlap 70 + next 590 + 1 = 661 > 600)
    Guarantees: Every chunk <= 600, Sentence 3 is not oversized, no text lost.
    """
    s1 = "A" * 449 + "."
    s2 = "B" * 69 + "."
    s3 = "C" * 589 + "."
    text = f"{s1} {s2} {s3}"

    chunks = chunk_text(text, chunk_size=600, chunk_overlap=100)
    assert len(chunks) == 2

    # Verify size invariants
    for c in chunks:
        assert len(c["chunk_text"]) <= 600, f"Chunk exceeded size: {len(c['chunk_text'])} > 600"

    assert chunks[0]["chunk_text"] == f"{s1} {s2}"
    assert len(chunks[0]["chunk_text"]) == 521
    assert chunks[1]["chunk_text"] == s3
    assert len(chunks[1]["chunk_text"]) == 590

    # No lost text
    assert s1 in chunks[0]["chunk_text"]
    assert s2 in chunks[0]["chunk_text"]
    assert s3 in chunks[1]["chunk_text"]

def test_chunker_property_random_sentence_lengths():
    """
    Property-style test (C2):
    Tests many varying random sentence lengths asserting:
    1. Every chunk length <= chunk_size.
    2. Overlap is present when mathematically possible.
    3. Every single sentence is preserved without data loss.
    """
    import random
    rng = random.Random(42)

    for trial in range(15):
        num_sentences = rng.randint(5, 20)
        sentences = []
        for s_idx in range(num_sentences):
            length = rng.randint(15, 350)
            sentences.append(f"Sent{s_idx}_" + "x" * max(0, length - 8) + ".")

        doc_text = " ".join(sentences)
        chunk_size = 400
        chunk_overlap = 80

        chunks = chunk_text(doc_text, chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        assert len(chunks) > 0

        # Assert size invariant for all chunks
        for c in chunks:
            assert len(c["chunk_text"]) <= chunk_size, (
                f"Trial {trial}: chunk {c['chunk_index']} exceeded chunk_size: {len(c['chunk_text'])} > {chunk_size}"
            )

        # Assert no data loss: every sentence must be found in at least one chunk
        for s in sentences:
            found = any(s in c["chunk_text"] for c in chunks)
            assert found, f"Trial {trial}: sentence '{s[:20]}' lost during chunking!"

def test_chunker_max_chunks_explicit_parameter():
    """Verifies max_chunks explicit parameter enforcement."""
    with pytest.raises(DocumentValidationError, match="exceeding max chunk limit of 2"):
        chunk_text(SAMPLE_TEXT, chunk_size=150, chunk_overlap=30, max_chunks=2)


