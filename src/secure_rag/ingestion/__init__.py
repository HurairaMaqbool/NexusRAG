"""
src/secure_rag/ingestion — Document Parsers & Boundary-Aware Chunker
(Pipeline orchestrator is accessed directly via secure_rag.ingestion.pipeline; B7)
"""

from secure_rag.ingestion.parsers import parse_document
from secure_rag.ingestion.chunker import chunk_text

__all__ = ["parse_document", "chunk_text"]
