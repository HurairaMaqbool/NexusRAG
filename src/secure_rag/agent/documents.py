"""
src/secure_rag/agent/documents.py — Document parsing and chunking helpers
Used by the RAG agent path (PDF / DOCX / TXT → sliding-window chunks).
"""

from __future__ import annotations

import os

from pypdf import PdfReader
from docx import Document


def parse_file(file_path: str, filename: str) -> list[dict]:
    """Parse PDF, DOCX, or TXT into a list of {text, source_id, file} dicts."""
    if not filename:
        filename = os.path.basename(file_path) or "document"
    ext = filename.rsplit(".", 1)[-1].lower()
    items: list[dict] = []

    if ext == "pdf":
        reader = PdfReader(file_path)
        for i, page in enumerate(reader.pages):
            text = (page.extract_text() or "").strip()
            if text:
                items.append({"text": text, "source_id": f"Page {i + 1}", "file": filename})

    elif ext == "docx":
        doc = Document(file_path)
        block: list[str] = []
        block_id = 1
        for para in doc.paragraphs:
            t = para.text.strip()
            if t:
                block.append(t)
            elif block:
                items.append({"text": " ".join(block), "source_id": f"Block {block_id}", "file": filename})
                block, block_id = [], block_id + 1
        if block:
            items.append({"text": " ".join(block), "source_id": f"Block {block_id}", "file": filename})

    elif ext == "txt":
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read().strip()
        if content:
            items.append({"text": content, "source_id": "Full text", "file": filename})

    else:
        raise ValueError(f"Unsupported file type: .{ext}. Supported: pdf, docx, txt")

    return items


def chunk_text(items: list[dict], chunk_size: int = 800, overlap: int = 150) -> list[dict]:
    """Sliding window chunker with overlap."""
    chunks: list[dict] = []
    for item in items:
        text = item["text"]
        start = 0
        while start < len(text):
            end = min(start + chunk_size, len(text))
            piece = text[start:end].strip()
            if piece:
                chunks.append({
                    "text": piece,
                    "source_id": item["source_id"],
                    "source_file": item["file"],
                })
            if end == len(text):
                break
            start += chunk_size - overlap
    return chunks
