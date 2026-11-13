"""tests/unit/test_intent.py — Production routing.intent classifier tests."""

import pytest

from secure_rag.routing.intent import detect_intent


@pytest.mark.parametrize(
    "query,expected",
    [
        ("2 + 2", "calculator"),
        ("what is 50 * 3", "calculator"),
        ("calculate 100 divided by 5", "calculator"),
        ("compute 9 - 4", "calculator"),
        ("latest AI news today", "web_search"),
        ("current price of bitcoin", "web_search"),
        ("who won the 2026 world cup", "web_search"),
        ("recent trends in technology", "web_search"),
        ("what is artificial intelligence", "pdf_rag"),
        ("what is ai", "pdf_rag"),
        ("explain machine learning", "pdf_rag"),
        ("summarize the document", "pdf_rag"),
        ("tell me about the report", "pdf_rag"),
        ("what is the current leave policy", "pdf_rag"),
        ("PTO policy for 2026", "pdf_rag"),
        ("calculate PTO for 15 days", "pdf_rag"),
        ("salary band for E5", "pdf_rag"),
    ],
)
def test_detect_intent(query, expected):
    assert detect_intent(query) == expected
