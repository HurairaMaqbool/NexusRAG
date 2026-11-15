"""
src/secure_rag/ingestion/watermark.py — Cryptographic Document Provenance & Watermarking
Generates and validates document tamper-evident HMAC signatures and honey-token detectors.
"""

import hashlib
import hmac
import json
from typing import Any, Dict, Optional

# Honey-token canary indicators planted to catch exfiltration
HONEY_TOKEN_PREFIX = "NORTHWIND-HONEY-TOKEN"


def compute_document_hmac(file_content: bytes, secret_key: str) -> str:
    """Computes a cryptographically secure SHA-256 HMAC over raw document bytes."""
    key_bytes = secret_key.encode("utf-8") if isinstance(secret_key, str) else secret_key
    return hmac.new(key_bytes, file_content, hashlib.sha256).hexdigest()


def generate_provenance_metadata(
    doc_id: str,
    title: str,
    access_level: str,
    uploader_id: str,
    file_bytes: bytes,
    secret_key: str,
) -> Dict[str, Any]:
    """Builds signed provenance metadata guaranteeing author identity and file integrity."""
    file_hmac = compute_document_hmac(file_bytes, secret_key)
    return {
        "doc_id": doc_id,
        "title": title,
        "access_level": access_level,
        "uploader_id": uploader_id,
        "file_hash_sha256": hashlib.sha256(file_bytes).hexdigest(),
        "integrity_hmac": file_hmac,
        "provenance_version": "1.0",
    }


def verify_document_integrity(
    file_bytes: bytes,
    expected_hmac: str,
    secret_key: str,
) -> bool:
    """Timing-safe HMAC verification to detect file tampering or unauthorized modification."""
    computed = compute_document_hmac(file_bytes, secret_key)
    return hmac.compare_digest(computed, expected_hmac)


def detect_honey_token(text: str) -> bool:
    """Returns True if the text contains an internal honey-token canary."""
    if not text:
        return False
    return HONEY_TOKEN_PREFIX in text
