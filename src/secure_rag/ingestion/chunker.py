"""
src/secure_rag/ingestion/chunker.py — Deterministic Boundary-Aware Text Chunker
Splits document text into overlapping chunks respecting paragraph and sentence boundaries (Decision D15).
Enforces max chunk limits and guarantees deterministic indexing and overlap continuity (B8).
"""

import re
from typing import Any, Dict, List, Optional

from secure_rag.core.config import AppConfig
from secure_rag.core.errors import DocumentValidationError

# Regular expression for sentence splitting (retains punctuation)
_SENTENCE_SPLIT_REGEX = re.compile(r"(?<=[.!?])\s+|\n{2,}")

def chunk_text(
    text: str,
    chunk_size: Optional[int] = None,
    chunk_overlap: Optional[int] = None,
    config: Optional[AppConfig] = None,
    max_chunks: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Splits text into deterministic, boundary-aware chunks.
    
    Guarantees (Decision D15, B8, C2):
    1. Every chunk length is <= chunk_size.
    2. Consecutive chunks share overlapping boundary context when size permits.
    3. Overlap never causes chunk length to exceed chunk_size.
    4. No data loss: every sentence/character appears in at least one chunk.
    5. Deterministic indexing: identical text yields identical chunks.
    6. chunk_overlap >= chunk_size raises ValueError.
    7. Enforces max_chunks safety threshold (raising DocumentValidationError).
    """
    cfg = config if config is not None else AppConfig()
    size = chunk_size if chunk_size is not None else cfg.chunk_size
    overlap = chunk_overlap if chunk_overlap is not None else cfg.chunk_overlap
    limit_chunks = max_chunks if max_chunks is not None else cfg.max_chunks

    if size <= 0:
        raise ValueError("chunk_size must be positive.")
    if overlap < 0 or overlap >= size:
        raise ValueError("chunk_overlap must be non-negative and strictly less than chunk_size.")

    raw_text = text.strip()
    if not raw_text:
        return []

    # 1. Break text into atomic segments (sentences and paragraph breaks)
    raw_segments = _SENTENCE_SPLIT_REGEX.split(raw_text)
    segments = [s.strip() for s in raw_segments if s.strip()]

    if not segments:
        segments = [raw_text]

    # Pre-process: if any single segment exceeds chunk_size, slice it with step = (size - overlap)
    refined_segments: List[str] = []
    for seg in segments:
        if len(seg) <= size:
            refined_segments.append(seg)
        else:
            step = max(1, size - overlap)
            start = 0
            while start < len(seg):
                sub = seg[start : start + size].strip()
                if sub:
                    refined_segments.append(sub)
                start += step

    # 2. Build overlapping chunks
    # We maintain an index of the next unflushed segment that MUST be covered by the next chunk.
    chunks: List[str] = []
    uncovered_idx = 0

    while uncovered_idx < len(refined_segments):
        # Find how many overlap segments from before uncovered_idx can fit
        # along with refined_segments[uncovered_idx] in `size` characters.
        next_req_len = len(refined_segments[uncovered_idx])
        
        # Candidate overlap segments: scan backwards from uncovered_idx - 1
        overlap_cand: List[str] = []
        cand_len = 0
        cand_i = uncovered_idx - 1
        while cand_i >= 0:
            cand_seg = refined_segments[cand_i]
            add_len = len(cand_seg) + (1 if overlap_cand else 0)
            # Must satisfy: cand_len + add_len <= overlap AND total with next_req <= size
            if cand_len + add_len <= overlap and (cand_len + add_len + 1 + next_req_len) <= size:
                overlap_cand.insert(0, cand_seg)
                cand_len += add_len
                cand_i -= 1
            else:
                break

        current_parts = list(overlap_cand)
        current_len = sum(len(s) for s in current_parts) + max(0, len(current_parts) - 1)

        # Now append starting from uncovered_idx forward
        advance_idx = uncovered_idx
        while advance_idx < len(refined_segments):
            seg = refined_segments[advance_idx]
            add_len = len(seg) + (1 if current_parts else 0)
            if current_len + add_len <= size:
                current_parts.append(seg)
                current_len += add_len
                advance_idx += 1
            else:
                break

        # Edge case: if advance_idx did not advance (should not occur since segments are <= size)
        if advance_idx == uncovered_idx:
            current_parts = [refined_segments[uncovered_idx][:size]]
            advance_idx = uncovered_idx + 1

        chunk_str = " ".join(current_parts).strip()
        if len(chunk_str) > size:
            raise AssertionError(
                f"Chunk invariant violated: chunk length {len(chunk_str)} exceeds max size {size}."
            )

        chunks.append(chunk_str)
        uncovered_idx = advance_idx

    # 3. Security limit validation
    if len(chunks) > limit_chunks:
        raise DocumentValidationError(
            f"Generated {len(chunks)} chunks, exceeding max chunk limit of {limit_chunks}."
        )

    # 4. Format into structured records
    result = []
    for i, c_text in enumerate(chunks):
        token_count = max(1, len(c_text.split()))
        result.append({
            "chunk_index": i,
            "chunk_text": c_text,
            "token_count": token_count
        })

    return result
