"""
src/secure_rag/routing/intent.py — Query Intent Classifier
Classifies user queries into calculator, web_search, or pdf_rag intents.
"""

import re


def detect_intent(query: str) -> str:
    """
    Intent priority:
      1. calculator — only if a numeric math expression is clearly present
      2. web_search — if the question is about real-time / current info
      3. pdf_rag    — default (answer from docs or general knowledge)
    """
    q = query.lower().strip()

    # Calculator: must have numbers AND operators together
    has_expression = bool(re.search(r'\d[\s]*[\+\-\*\/\^%][\s]*\d', query))
    calc_words = ["calculate", "compute", "solve", "simplify", "evaluate"]
    is_calc_word = any(w in q for w in calc_words)

    if has_expression or (is_calc_word and re.search(r'\d', query)):
        return "calculator"

    # Web search: real-time or current-events queries
    web_patterns = [
        r'\b(latest|recent|today|now|current|live)\b',
        r'\b(2024|2025|2026)\b',
        r'\b(news|stock|price|weather|score|winner|election|trend)\b',
        r'\bwho (is|are|was|won|leads|runs)\b',
        r'\bwhat (is|are) (the )?(current|latest|today)',
    ]
    if any(re.search(p, q) for p in web_patterns):
        return "web_search"

    return "pdf_rag"
