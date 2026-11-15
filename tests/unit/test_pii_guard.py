"""
tests/unit/test_pii_guard.py — Unit tests for PIIGuard
Validates detection and deterministic surrogate masking of SSNs, Cards, Phones, and Emails.
"""

import pytest
from secure_rag.security.pii_guard import PIIGuard


@pytest.fixture
def pii_guard():
    return PIIGuard()


def test_clean_text_no_pii(pii_guard):
    res = pii_guard.mask("Northwind was founded in 1994 and sells retail goods.")
    assert not res.has_pii
    assert res.entities_count == 0
    assert res.sanitized_text == "Northwind was founded in 1994 and sells retail goods."


def test_ssn_masking_and_unmasking(pii_guard):
    raw = "Employee John SSN is 000-12-3456 for payroll records."
    res = pii_guard.mask(raw)
    assert res.has_pii
    assert "000-12-3456" not in res.sanitized_text
    assert "[SSN_1]" in res.sanitized_text

    restored = pii_guard.unmask(res.sanitized_text, res.masked_entities)
    assert restored == raw


def test_phone_number_masking(pii_guard):
    raw = "Reach emergency line at (555) 234-5678 or 555-987-6543 immediately."
    res = pii_guard.mask(raw)
    assert res.has_pii
    assert "(555) 234-5678" not in res.sanitized_text
    assert "[PHONE_1]" in res.sanitized_text
    assert "[PHONE_2]" in res.sanitized_text


def test_credit_card_masking(pii_guard):
    raw = "Pay corporate card 4111 2222 3333 4444 for travel expense."
    res = pii_guard.mask(raw)
    assert res.has_pii
    assert "4111 2222 3333 4444" not in res.sanitized_text
    assert "[CARD_1]" in res.sanitized_text


def test_external_email_masking(pii_guard):
    raw = "Send feedback to external auditor john.smith@external-audit-firm.com today."
    res = pii_guard.mask(raw)
    assert res.has_pii
    assert "john.smith@external-audit-firm.com" not in res.sanitized_text
    assert "[EMAIL_1]" in res.sanitized_text


def test_internal_domain_preserved(pii_guard):
    raw = "Contact employee@northwind.local for intranet support."
    res = pii_guard.mask(raw)
    assert "employee@northwind.local" in res.sanitized_text
