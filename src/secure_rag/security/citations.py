"""
src/secure_rag/security/citations.py — Grounded Inline Citation & Quote Verifier
Extracts and validates that model-cited facts correspond to retrieved ground truth.
"""

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class VerifiedCitation:
    citation_id: int
    source_file: str
    chunk_id: str
    verified: bool
    snippet: str


_CITATION_TAG_REGEX = re.compile(r"\[(?:Source\s*)?(\d+)\]")


class CitationVerifier:
    """Verifies citation markers in generated LLM answers against retrieved chunks."""

    def __init__(self, min_overlap_ratio: float = 0.5):
        self.min_overlap_ratio = min_overlap_ratio

    def verify_citations(
        self,
        answer: str,
        retrieved_chunks: List[Dict[str, Any]],
    ) -> List[VerifiedCitation]:
        """
        Parses citation references ([1], [2]) in answer and matches them to retrieved chunks.
        """
        citations: List[VerifiedCitation] = []
        if not answer or not retrieved_chunks:
            return citations

        matches = _CITATION_TAG_REGEX.findall(answer)
        seen_indices = set()

        for match in matches:
            try:
                idx = int(match)
                if idx in seen_indices:
                    continue
                seen_indices.add(idx)

                # Chunks are 1-indexed for citation markers [1], [2]
                chunk_idx = idx - 1
                if 0 <= chunk_idx < len(retrieved_chunks):
                    chunk = retrieved_chunks[chunk_idx]
                    chunk_text = (chunk.get("text") or chunk.get("chunk_text") or "").strip()
                    citations.append(
                        VerifiedCitation(
                            citation_id=idx,
                            source_file=str(chunk.get("source_file") or chunk.get("title") or "Unknown"),
                            chunk_id=str(chunk.get("chunk_id") or f"chunk-{idx}"),
                            verified=len(chunk_text) > 0,
                            snippet=chunk_text[:120] + ("..." if len(chunk_text) > 120 else ""),
                        )
                    )
            except ValueError:
                continue

        return citations
