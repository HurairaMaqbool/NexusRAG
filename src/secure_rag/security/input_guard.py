"""
src/secure_rag/security/input_guard.py — Control 2: Direct Injection & Input Validation
Inspects user queries for delimiter injection, command phrases, and abnormal length.
"""

import re
from typing import List

from secure_rag.security.models import InputGuardResult

# Maximum allowed query length (characters)
MAX_QUERY_LENGTH = 1000

# Direct injection patterns (high-confidence indicators in raw user input).
# Avoid bare "act as" — it appears in normal workplace English.
_DIRECT_INJECTION_PATTERNS = [
    (
        re.compile(
            r"(?i)(ignore|disregard|forget|override)\s+(all\s+)?"
            r"(previous|prior|above|system)\s+(instructions?|prompts?|rules?)"
        ),
        "instruction_override",
        0.80,
    ),
    (
        re.compile(
            r"(?i)(you\s+are\s+now|pretend\s+(to\s+be|you\s+are)|"
            r"assume\s+the\s+role|roleplay\s+as|jailbreak\s+as)"
        ),
        "role_hijack",
        0.80,
    ),
    (
        re.compile(
            r"(?i)(show|reveal|print|output|repeat)\s+(me\s+)?"
            r"(the\s+)?(system\s+prompt|hidden\s+instructions?|your\s+instructions?)"
        ),
        "prompt_extraction",
        0.80,
    ),
    (
        re.compile(
            r"(?i)(</?system>|\[/?(INST|SYS)\]|<\|im_start\|>|<\|im_end\|>|<<SYS>>)"
        ),
        "delimiter_injection",
        0.80,
    ),
    (
        re.compile(
            r"(?i)(DAN\s*mode|do\s+anything\s+now|\bjailbreak\b|god\s+mode|"
            r"unrestricted\s+mode)"
        ),
        "jailbreak_attempt",
        0.80,
    ),
]


def inspect(query: str) -> InputGuardResult:
    """
    Inspects a user query for direct prompt injection indicators.
    Returns an InputGuardResult with flagging status, risk score, and matched reasons.
    """
    if not query or not isinstance(query, str):
        return InputGuardResult(is_flagged=False, risk_score=0.0, reasons=[])

    reasons: List[str] = []
    risk_score = 0.0

    # Hard-block on excessive length (DoS prevention)
    if len(query) > MAX_QUERY_LENGTH:
        return InputGuardResult(
            is_flagged=True,
            risk_score=1.0,
            reasons=["excessive_length"],
        )

    # Check each direct injection pattern
    for pattern, label, weight in _DIRECT_INJECTION_PATTERNS:
        if pattern.search(query):
            reasons.append(label)
            risk_score += weight

    # Cap risk at 1.0
    risk_score = min(risk_score, 1.0)

    is_flagged = risk_score >= 0.75

    return InputGuardResult(
        is_flagged=is_flagged,
        risk_score=round(risk_score, 4),
        reasons=reasons,
    )
