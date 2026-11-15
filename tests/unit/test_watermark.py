"""
tests/unit/test_watermark.py — Unit tests for Cryptographic Provenance & Watermarking
"""

import pytest
from secure_rag.ingestion.watermark import (
    compute_document_hmac,
    detect_honey_token,
    generate_provenance_metadata,
    verify_document_integrity,
    HONEY_TOKEN_PREFIX,
)


def test_hmac_and_integrity_verification():
    secret = "test-secret-key-12345"
    content = b"Confidential Northwind Financial Report 2026"

    hmac_val = compute_document_hmac(content, secret)
    assert len(hmac_val) == 64  # SHA-256 hex string

    # Verification passes with untampered content
    assert verify_document_integrity(content, hmac_val, secret)

    # Verification fails if 1 single byte is tampered
    tampered = b"Confidential Northwind Financial Report 2027"
    assert not verify_document_integrity(tampered, hmac_val, secret)


def test_provenance_metadata_generation():
    secret = "enterprise-master-key"
    file_bytes = b"Employee handbook text content"
    meta = generate_provenance_metadata(
        doc_id="doc-99",
        title="Handbook",
        access_level="employee",
        uploader_id="user-123",
        file_bytes=file_bytes,
        secret_key=secret,
    )
    assert meta["doc_id"] == "doc-99"
    assert "integrity_hmac" in meta
    assert meta["access_level"] == "employee"


def test_honey_token_detection():
    clean_text = "Standard salary review guidelines for department leads."
    assert not detect_honey_token(clean_text)

    trapped_text = f"Top Secret Project Canary: {HONEY_TOKEN_PREFIX}-EXFIL-TEST"
    assert detect_honey_token(trapped_text)
