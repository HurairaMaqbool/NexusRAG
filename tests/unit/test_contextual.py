"""
tests/unit/test_contextual.py — Unit tests for Anthropic Contextual Retrieval
"""

from secure_rag.ingestion.contextual import build_contextual_prefix, enrich_chunk_with_context


def test_build_contextual_prefix():
    prefix = build_contextual_prefix(
        doc_title="Employee Handbook",
        section_name="PTO & Holidays",
        chunk_index=2,
        total_chunks=10,
        doc_summary="Company benefits and vacation policies",
    )
    assert "[Employee Handbook | Section: PTO & Holidays | Part 3/10 — Context: Company benefits and vacation policies]" in prefix


def test_enrich_chunk_with_context():
    chunk = "Full-time employees receive 20 days vacation."
    enriched = enrich_chunk_with_context(
        chunk_text=chunk,
        doc_title="Northwind Policies",
        section_name="Compensation",
        chunk_index=0,
        total_chunks=5,
    )
    assert enriched.startswith("[Northwind Policies | Section: Compensation | Part 1/5]")
    assert "Full-time employees receive 20 days vacation." in enriched
