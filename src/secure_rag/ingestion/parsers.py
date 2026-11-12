"""
src/secure_rag/ingestion/parsers.py — Safe In-Memory Document Parsers
Extracts raw text from PDF, DOCX, and TXT files strictly in memory using BytesIO.
Enforces magic bytes verification, zip-bomb mitigation, encryption checks, and size limits (Decision D17).
Crucially preserves invisible Unicode so downstream security scanners can inspect raw payloads.
"""

import io
import os
from pathlib import Path
from typing import Optional
import zipfile
import pypdf
import docx

from secure_rag.core.config import AppConfig, DEFAULT_CONFIG
from secure_rag.core.errors import DocumentValidationError

PDF_MAGIC = b"%PDF-"
ZIP_MAGIC = b"PK\x03\x04"

def parse_document(
    file_bytes: bytes,
    filename: str,
    config: Optional[AppConfig] = None
) -> str:
    """
    Parses document binary data in-memory based on filename extension and validated magic bytes.
    Enforces upload size, page count, zip-bomb restrictions, and character limits.
    """
    cfg = config or DEFAULT_CONFIG
    
    # 1. Total file size check
    max_bytes = cfg.max_upload_mb * 1024 * 1024
    if len(file_bytes) > max_bytes:
        raise DocumentValidationError(
            f"File size ({len(file_bytes) / (1024 * 1024):.2f} MB) exceeds maximum allowed limit of {cfg.max_upload_mb} MB."
        )

    if not file_bytes:
        raise DocumentValidationError("File is empty (0 bytes).")

    ext = Path(filename).suffix.lower()

    if ext == ".pdf":
        return _parse_pdf(file_bytes, cfg)
    elif ext == ".docx":
        return _parse_docx(file_bytes, cfg)
    elif ext in (".txt", ".md", ".log"):
        return _parse_txt(file_bytes, cfg)
    else:
        raise DocumentValidationError(
            f"Unsupported file format '{ext}'. Allowed formats are: .pdf, .docx, .txt"
        )

def _parse_pdf(file_bytes: bytes, cfg: AppConfig) -> str:
    """Safely extracts text from PDF with magic bytes validation and encryption checks."""
    if not file_bytes.startswith(PDF_MAGIC):
        raise DocumentValidationError("File content does not match PDF format (invalid magic bytes).")

    stream = io.BytesIO(file_bytes)
    try:
        reader = pypdf.PdfReader(stream)
    except Exception as e:
        raise DocumentValidationError(f"Failed to read PDF structure: {type(e).__name__}")

    # Check for password-protected / encrypted PDF
    if reader.is_encrypted:
        raise DocumentValidationError("Password-protected or encrypted PDFs are not supported.")

    total_pages = len(reader.pages)
    if total_pages > cfg.max_pages:
        raise DocumentValidationError(
            f"PDF page count ({total_pages}) exceeds maximum allowed limit of {cfg.max_pages} pages."
        )

    text_parts = []
    total_chars = 0

    for idx, page in enumerate(reader.pages):
        try:
            page_text = page.extract_text() or ""
        except Exception as e:
            raise DocumentValidationError(f"Error extracting text from page {idx + 1}: {type(e).__name__}")
        
        total_chars += len(page_text)
        if total_chars > cfg.max_text_chars:
            raise DocumentValidationError(
                f"Document text length exceeds maximum limit of {cfg.max_text_chars} characters."
            )
        text_parts.append(page_text)

    full_text = "\n\n".join(text_parts).strip()
    if not full_text:
        raise DocumentValidationError("PDF contains no extractable text.")

    return full_text

def _parse_docx(file_bytes: bytes, cfg: AppConfig) -> str:
    """Safely extracts text from DOCX with zip-bomb mitigation and structure verification."""
    if not file_bytes.startswith(ZIP_MAGIC):
        raise DocumentValidationError("File content does not match DOCX format (invalid magic bytes).")

    stream = io.BytesIO(file_bytes)

    # Zip-bomb inspection prior to full document parsing
    try:
        with zipfile.ZipFile(stream, "r") as zf:
            infolist = zf.infolist()
            namelist = zf.namelist()
            
            # Verify basic OOXML document structure
            if "[Content_Types].xml" not in namelist and not any(n.startswith("word/") for n in namelist):
                raise DocumentValidationError("Invalid DOCX format: missing required OOXML package parts.")

            total_uncompressed = sum(info.file_size for info in infolist)
            total_compressed = sum(info.compress_size for info in infolist)

            if total_uncompressed > cfg.max_uncompressed_docx_bytes:
                raise DocumentValidationError(
                    f"DOCX uncompressed size ({total_uncompressed / (1024 * 1024):.1f} MB) "
                    f"exceeds zip-bomb security threshold ({cfg.max_uncompressed_docx_bytes / (1024 * 1024):.1f} MB)."
                )

            if total_compressed > 0:
                ratio = total_uncompressed / total_compressed
                if ratio > cfg.max_docx_compression_ratio:
                    raise DocumentValidationError(
                        f"DOCX compression ratio ({ratio:.1f}:1) exceeds security limit ({cfg.max_docx_compression_ratio:.1f}:1)."
                    )

            # Bounded read verification: guarantee actual decompression cannot exceed safety threshold
            # Defends against spoofed header declarations in adversarial zip archives
            actual_read = 0
            for info in infolist:
                with zf.open(info) as entry:
                    while True:
                        chunk = entry.read(65536)
                        if not chunk:
                            break
                        actual_read += len(chunk)
                        if actual_read > cfg.max_uncompressed_docx_bytes:
                            raise DocumentValidationError(
                                f"DOCX actual decompressed read exceeds limit of {cfg.max_uncompressed_docx_bytes} bytes."
                            )
    except DocumentValidationError:
        raise
    except Exception as e:
        raise DocumentValidationError(f"Corrupted or invalid DOCX archive: {type(e).__name__}")

    # Re-seek stream and parse document text
    stream.seek(0)
    try:
        doc = docx.Document(stream)
    except Exception as e:
        raise DocumentValidationError(f"Failed to load DOCX document structure: {type(e).__name__}")

    text_parts = []
    total_chars = 0

    for p in doc.paragraphs:
        p_text = p.text
        if p_text:
            total_chars += len(p_text)
            if total_chars > cfg.max_text_chars:
                raise DocumentValidationError(
                    f"Document text length exceeds maximum limit of {cfg.max_text_chars} characters."
                )
            text_parts.append(p_text)

    # Also extract text from tables
    for table in doc.tables:
        for row in table.rows:
            row_text = "\t".join(cell.text.strip() for cell in row.cells if cell.text.strip())
            if row_text:
                total_chars += len(row_text)
                if total_chars > cfg.max_text_chars:
                    raise DocumentValidationError(
                        f"Document text length exceeds maximum limit of {cfg.max_text_chars} characters."
                    )
                text_parts.append(row_text)

    full_text = "\n\n".join(text_parts).strip()
    if not full_text:
        raise DocumentValidationError("DOCX document contains no readable text content.")

    return full_text

def _parse_txt(file_bytes: bytes, cfg: AppConfig) -> str:
    """Parses plain text with null byte validation and UTF-8 decoding."""
    # Reject binary files masquerading as text (null byte presence)
    if b"\x00" in file_bytes:
        raise DocumentValidationError("Binary content detected: plain text cannot contain null bytes.")

    try:
        text = file_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            # Fallback to latin-1 if utf-8 fails
            text = file_bytes.decode("latin-1")
        except Exception as e:
            raise DocumentValidationError(f"Failed to decode text file: {e}")

    if len(text) > cfg.max_text_chars:
        raise DocumentValidationError(
            f"Document text length ({len(text)} chars) exceeds maximum limit of {cfg.max_text_chars} characters."
        )

    stripped = text.strip()
    if not stripped:
        raise DocumentValidationError("Text file contains no readable content.")

    # Preserve all unicode characters (including zero-width and control characters)
    return stripped
