"""
src/secure_rag/routing/intent.py — Query Intent Classifier
Classifies user queries into calculator, web_search, or pdf_rag intents.
"""

import re


def detect_intent(query: str) -> str:
    """
    Intent priority:
      1. calculator — only if a numeric math expression is clearly present
      2. web_search — if the question is about real-time / current events
      3. pdf_rag    — default (answer from docs or general knowledge)
    """
    q = query.lower().strip()

    # Calculator: a real arithmetic expression. A bare hyphen (2-3, 2024-2025)
    # is a range, not subtraction, unless spaces surround the minus sign.
    has_expression = bool(
        re.search(r"\d(?:\s*[\+\*\/\^%]\s*|\s+-\s+)\d", query)
    )
    has_word_operator = bool(
        re.search(r"\b(divided by|multiplied by|times|plus|minus)\b", q)
        and re.search(r"\d", query)
    )
    calc_words = ("calculate", "compute", "solve", "simplify", "evaluate")
    is_calc_word = any(w in q for w in calc_words)

    if has_expression or (is_calc_word and (has_expression or has_word_operator)):
        return "calculator"

    # Prefer document RAG for workplace / policy questions even if they
    # contain words like "current" or a year.
    workplace_cues = (
        r"\b(pto|leave|vacation|policy|payroll|salary|band|hr|employee|"
        r"benefits|bereavement|parental|sick)\b"
    )
    if re.search(workplace_cues, q):
        return "pdf_rag"

    # Web search: real-time or current-events queries
    web_patterns = [
        r"\b(latest|recent|today|now|live)\b",
        r"\b(news|stock|price|weather|score|winner|election|trend)\b",
        r"\bwho (won|leads|runs)\b",
        r"\bwhat (is|are) (the )?(latest|today's)\b",
        r"\bcurrent (news|price|weather|stock|score)\b",
    ]
    if any(re.search(p, q) for p in web_patterns):
        return "web_search"

    return "pdf_rag"
