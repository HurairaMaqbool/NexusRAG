"""
src/secure_rag/ingestion/contextual.py — Anthropic-Style Contextual Retrieval Engine
Situates raw chunks within the broader document structure to solve cross-boundary context loss.
"""

from typing import Optional


def build_contextual_prefix(
    doc_title: str,
    section_name: Optional[str] = None,
    chunk_index: int = 0,
    total_chunks: int = 1,
    doc_summary: Optional[str] = None,
) -> str:
    """
    Builds an auditable contextual preface string prepended to chunk text before embedding.
    Ensures both semantic vectors and BM25 retain parent document entities and scope.
    """
    clean_title = (doc_title or "Document").strip()
    sec_part = f" | Section: {section_name.strip()}" if section_name else ""
    summary_part = f" — Context: {doc_summary.strip()}" if doc_summary else ""

    return f"[{clean_title}{sec_part} | Part {chunk_index + 1}/{total_chunks}{summary_part}] "


def enrich_chunk_with_context(
    chunk_text: str,
    doc_title: str,
    section_name: Optional[str] = None,
    chunk_index: int = 0,
    total_chunks: int = 1,
    doc_summary: Optional[str] = None,
) -> str:
    """Combines contextual preface with chunk text."""
    prefix = build_contextual_prefix(
        doc_title=doc_title,
        section_name=section_name,
        chunk_index=chunk_index,
        total_chunks=total_chunks,
        doc_summary=doc_summary,
    )
    return f"{prefix}{chunk_text}"
