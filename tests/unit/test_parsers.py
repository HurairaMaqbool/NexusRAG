"""
tests/unit/test_parsers.py — Comprehensive Unit & Security Tests for Document Parsers
Verifies in-memory parsing, magic bytes verification, zip-bomb mitigation, encrypted PDF rejection,
and invisible Unicode preservation (Decision D17).
"""

import io
import zipfile
import pytest
import pypdf
import docx

from secure_rag.core.config import AppConfig
from secure_rag.core.errors import DocumentValidationError
from secure_rag.ingestion.parsers import parse_document

def test_parse_txt_preserves_invisible_unicode():
    """Security test: Ensures zero-width spaces and control characters are NOT stripped."""
    # Embedding zero-width space (\u200b) and bidirectional override (\u202e)
    content = "Confidential Report\u200b with hidden \u202eoverride text."
    raw_bytes = content.encode("utf-8")

    parsed = parse_document(raw_bytes, "test.txt")
    assert "\u200b" in parsed
    assert "\u202e" in parsed
    assert parsed == content

def test_parse_txt_rejects_null_bytes():
    """Security test: Binary file masquerading as .txt must be rejected."""
    bad_bytes = b"Hello\x00World binary content"
    with pytest.raises(DocumentValidationError, match="Binary content detected"):
        parse_document(bad_bytes, "exploit.txt")

def test_parse_rejects_unsupported_extensions():
    """Security test: Disallowed extensions are rejected."""
    with pytest.raises(DocumentValidationError, match="Unsupported file format"):
        parse_document(b"print('malicious')", "payload.py")

def test_parse_rejects_empty_file():
    """Validates that empty payloads are rejected."""
    with pytest.raises(DocumentValidationError, match="File is empty"):
        parse_document(b"", "empty.txt")

def test_parse_enforces_upload_size_limit():
    """Validates that files exceeding max_upload_mb are rejected before processing."""
    cfg = AppConfig(max_upload_mb=1)
    large_bytes = b"A" * (1024 * 1024 + 10)  # > 1MB
    with pytest.raises(DocumentValidationError, match="exceeds maximum allowed limit"):
        parse_document(large_bytes, "large.txt", config=cfg)

def test_parse_pdf_magic_bytes_validation():
    """Security test: Rejects non-PDF bytes named as .pdf."""
    fake_pdf = b"NOT_A_PDF_HEADER"
    with pytest.raises(DocumentValidationError, match="invalid magic bytes"):
        parse_document(fake_pdf, "forged.pdf")

def test_parse_valid_pdf_in_memory():
    """Verifies that a valid in-memory PDF is parsed properly."""
    stream = io.BytesIO()
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.write(stream)
    pdf_bytes = stream.getvalue()

    # Note: A blank page has no text, so it should trigger "no extractable text"
    with pytest.raises(DocumentValidationError, match="contains no extractable text"):
        parse_document(pdf_bytes, "blank.pdf")

def test_parse_docx_magic_bytes_validation():
    """Security test: Rejects non-ZIP bytes named as .docx."""
    fake_docx = b"NOT_A_ZIP_HEADER"
    with pytest.raises(DocumentValidationError, match="invalid magic bytes"):
        parse_document(fake_docx, "fake.docx")

def test_parse_docx_rejects_non_ooxml_zip():
    """Security test: Rejects generic zip archive missing OOXML document structure."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as zf:
        zf.writestr("random.txt", "not a docx")
    zip_bytes = stream.getvalue()

    with pytest.raises(DocumentValidationError, match="missing required OOXML package parts"):
        parse_document(zip_bytes, "corrupt.docx")

def test_parse_docx_zip_bomb_uncompressed_size_defense():
    """
    Security test: Rejects DOCX archive where total uncompressed size exceeds max threshold.
    """
    cfg = AppConfig(max_uncompressed_docx_bytes=5000)  # 5 KB threshold for test
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "A" * 10000)  # 10 KB uncompressed
    bomb_bytes = stream.getvalue()

    with pytest.raises(DocumentValidationError, match="exceeds zip-bomb security threshold"):
        parse_document(bomb_bytes, "bomb.docx", config=cfg)

def test_parse_valid_docx_in_memory():
    """Verifies valid DOCX created in memory extracts paragraphs and tables."""
    stream = io.BytesIO()
    doc = docx.Document()
    doc.add_heading("Employee Handbook", level=1)
    doc.add_paragraph("Employees are expected to adhere to security policies.")
    table = doc.add_table(rows=1, cols=2)
    table.rows[0].cells[0].text = "Key"
    table.rows[0].cells[1].text = "Value"
    doc.save(stream)
    docx_bytes = stream.getvalue()

    parsed = parse_document(docx_bytes, "handbook.docx")
    assert "Employee Handbook" in parsed
    assert "adhere to security policies" in parsed
    assert "Key\tValue" in parsed

# ── Corrupted File & Title Sanitization Tests (B5, B8) ────────────────────────

def test_parse_corrupted_truncated_pdf_raises_validation_error():
    """
    Robustness test (B8c):
    Corrupted or truncated PDF must raise DocumentValidationError, never a raw library exception.
    """
    truncated_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" # missing pages, EOF
    with pytest.raises(DocumentValidationError, match="Failed to read PDF structure"):
        parse_document(truncated_pdf, "truncated.pdf")

def test_parse_corrupted_truncated_docx_raises_validation_error():
    """
    Robustness test (B8c):
    Corrupted or truncated DOCX zip bytes must raise DocumentValidationError, never raw BadZipFile.
    """
    corrupt_docx = b"PK\x03\x04\x14\x00\x00\x00" + b"\xFF" * 50 # invalid zip stream
    with pytest.raises(DocumentValidationError, match="Corrupted or invalid DOCX archive"):
        parse_document(corrupt_docx, "corrupt.docx")

def test_sanitize_document_title_removes_path_traversals():
    """Security test (B5): Path traversals in filename are stripped to bare name."""
    from secure_rag.ingestion.pipeline import sanitize_document_title

    assert sanitize_document_title("../../etc/passwd.txt") == "passwd.txt"
    assert sanitize_document_title("..\\..\\windows\\win.ini") == "win.ini"
    assert sanitize_document_title("folder/sub/doc.pdf") == "doc.pdf"

def test_sanitize_document_title_removes_bidi_and_control_chars():
    """Security test (B5): Bidirectional overrides and control characters are stripped."""
    from secure_rag.ingestion.pipeline import sanitize_document_title

    # RLO character (\u202e), zero-width space (\u200b), control char (\x08)
    malicious_name = "report_\u202eexe.pdf\u200b\x08.txt"
    sanitized = sanitize_document_title(malicious_name)
    assert "\u202e" not in sanitized
    assert "\u200b" not in sanitized
    assert "\x08" not in sanitized
    assert sanitized == "report_exe.pdf.txt"

def test_sanitize_document_title_length_capping():
    """Security test (B5): Titles exceeding max length are safely capped."""
    from secure_rag.ingestion.pipeline import sanitize_document_title

    long_name = "A" * 200 + ".txt"
    sanitized = sanitize_document_title(long_name, max_length=128)
    assert len(sanitized) == 128

def test_sanitize_document_title_c3_required_cases():
    """Verifies all required C3 edge cases for filename sanitization."""
    from secure_rag.ingestion.pipeline import sanitize_document_title

    # 1. '....//x.txt'
    assert sanitize_document_title("....//x.txt") == "x.txt"

    # 2. '..\\..\\x.txt'
    assert sanitize_document_title("..\\..\\x.txt") == "x.txt"

    # 3. 'a/b\\c.txt'
    assert sanitize_document_title("a/b\\c.txt") == "c.txt"

    # 4. RLO / zero-width name
    assert sanitize_document_title("\u202esalary\u200b.pdf") == "salary.pdf"

    # 5. 500-char name
    long_name = "X" * 500 + ".txt"
    sanitized_long = sanitize_document_title(long_name, max_length=128)
    assert len(sanitized_long) == 128
    assert sanitized_long == "X" * 128

    # 6. Empty result defines fallback title 'untitled_document'
    assert sanitize_document_title("") == "untitled_document"
    assert sanitize_document_title("   ") == "untitled_document"
    assert sanitize_document_title("....///....") == "untitled_document"
    assert sanitize_document_title("/\\/\\") == "untitled_document"


def test_sanitize_document_title_d3_unicode_category_cases():
    """
    Security & internationalization tests (D3):
    1. Filter out tag characters (U+E0041), word joiner (U+2060), soft hyphen (U+00AD),
       line separator (U+2028), RLO (U+202E).
    2. Mixed case preserved.
    3. Legitimate accented, Arabic, and Urdu characters survive intact.
    """
    from secure_rag.ingestion.pipeline import sanitize_document_title

    # 1. Obfuscated / exploit characters
    # U+E0041 (tag 'A'), U+2060 (word joiner), U+00AD (soft hyphen), U+2028 (line separator), U+202E (RLO)
    exploit_name = "secret\U000E0041\u2060\u00ad\u2028\u202e_doc.pdf"
    assert sanitize_document_title(exploit_name) == "secret_doc.pdf"

    # 2. Mixed case
    assert sanitize_document_title("MyDocument_v2.PDF") == "MyDocument_v2.PDF"

    # 3. Accented characters survive
    assert sanitize_document_title("résumé_über_español.docx") == "résumé_über_español.docx"

    # 4. Arabic characters survive
    assert sanitize_document_title("وثيقة_الموظف.pdf") == "وثيقة_الموظف.pdf"

    # 5. Urdu characters survive
    assert sanitize_document_title("دستاویز_معاہدہ.txt") == "دستاویز_معاہدہ.txt"



