"""
src/secure_rag/security/input_guard.py — Control 2: Direct Injection & Input Validation
Inspects user queries for delimiter injection, command phrases, abnormal length, and obfuscation.
"""

import base64
import binascii
import re
import unicodedata
import urllib.parse
from typing import List, Tuple

from secure_rag.security.models import InputGuardResult

# Maximum allowed query length (characters)
MAX_QUERY_LENGTH = 1000

# Zero-width and formatting invisible characters used for obfuscation (including Unicode directional isolates)
_INVISIBLE_CHARS_REGEX = re.compile(r"[\u200B-\u200D\uFEFF\u00AD\u2060\u200E\u200F\u180E\u202A-\u202E\u2066-\u2069]")

# Base64 candidate regex (sequences of base64 chars, possibly spaced, totaling at least 16 chars)
_BASE64_SEQUENCE_REGEX = re.compile(r"(?:[A-Za-z0-9+/]{4,}\s*)+(?:={0,2})")

_LEET_MAP = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
})


def normalize_query(query: str) -> str:
    """
    Normalizes query by applying URL decoding, Unicode NFKC
    (collapsing homoglyphs/full-width chars), and removing invisible zero-width formatting characters.
    """
    if not query:
        return ""
    # URL percent-decoding if percent tokens are present
    normalized = query
    if "%" in normalized:
        try:
            normalized = urllib.parse.unquote_plus(normalized)
        except Exception:
            pass
    # Unicode compatibility decomposition + canonical composition
    normalized = unicodedata.normalize("NFKC", normalized)
    # Strip invisible zero-width spaces/joiners
    normalized = _INVISIBLE_CHARS_REGEX.sub("", normalized)
    return normalized


def deobfuscate_lexical(query: str) -> str:
    """
    De-spaces single characters (e.g., 'i g n o r e' -> 'ignore')
    and normalizes common 1337speak substitutions to uncover masked keywords.
    """
    if not query:
        return ""
    # Collapse spaced letters: "i g n o r e" -> "ignore"
    despaced = re.sub(r"(?<=\b[a-zA-Z0-9])\s+(?=[a-zA-Z0-9]\b)", "", query)
    # Translate common leetspeak characters
    deleeted = despaced.translate(_LEET_MAP)
    return deleeted


# Direct injection patterns (high-confidence indicators in raw user input).
# Avoid bare "act as" — it appears in normal workplace English.
_DIRECT_INJECTION_PATTERNS = [
    (
        re.compile(
            r"(?i)(ignore|disregard|forget|override)\s*(all\s*)?"
            r"(previous|prior|above|system)\s*(instructions?|prompts?|rules?|directives?)"
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
            r"(the\s+|your\s+)?(system\s+prompt|hidden\s+instructions?|instructions?)"
        ),
        "prompt_extraction",
        0.80,
    ),
    (
        re.compile(
            r"(?i)(</?system>|\[/?(INST|SYS|SYSTEM|USER\s+QUESTION|CONTEXT|RECENT_CHAT|INSTRUCTION|PROMPT)[^\]]*\]|<\|im_start\|>|<\|im_end\|>|<<SYS>>)"
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
    (
        re.compile(
            r"(?i)\b(system\s+directive|administrative\s+override|developer\s+mode|supervisor\s+override|root\s+override)\b"
        ),
        "authority_override",
        0.80,
    ),
]


def _check_base64_obfuscation(raw_query: str) -> Tuple[bool, List[str]]:
    """Inspects potential base64 embedded payloads for injection markers."""
    flagged = False
    reasons = []
    candidates = _BASE64_SEQUENCE_REGEX.findall(raw_query)
    for cand in candidates:
        cleaned = re.sub(r"\s+", "", cand)
        if len(cleaned) < 16:
            continue
        # Ensure padding length is valid for base64
        missing_padding = len(cleaned) % 4
        if missing_padding:
            cleaned += "=" * (4 - missing_padding)
        try:
            decoded = base64.b64decode(cleaned, validate=False).decode("utf-8", errors="ignore")
            if len(decoded.strip()) >= 8:
                norm_decoded = normalize_query(decoded)
                for pattern, label, _ in _DIRECT_INJECTION_PATTERNS:
                    if pattern.search(norm_decoded):
                        flagged = True
                        reasons.append(f"obfuscated_{label}")
        except (binascii.Error, ValueError):
            continue
    return flagged, reasons


def inspect(query: str) -> InputGuardResult:
    """
    Inspects a user query for direct prompt injection indicators.
    Normalizes Unicode/homoglyphs and strips zero-width bypass tokens before inspection.
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

    # 1. Normalize Unicode, URL percent-encoding, and strip zero-width obfuscations
    clean_query = normalize_query(query)
    deobf_query = deobfuscate_lexical(clean_query)

    # 2. Check each direct injection pattern against raw, normalized, and deobfuscated forms
    for pattern, label, weight in _DIRECT_INJECTION_PATTERNS:
        if pattern.search(query) or pattern.search(clean_query) or pattern.search(deobf_query):
            reasons.append(label)
            risk_score += weight

    # 3. Check for Base64 encoded payload obfuscation
    b64_flagged, b64_reasons = _check_base64_obfuscation(query)
    if b64_flagged:
        reasons.extend(b64_reasons)
        risk_score += 0.80

    # Deduplicate reasons while preserving order
    reasons = list(dict.fromkeys(reasons))

    # Cap risk at 1.0
    risk_score = min(risk_score, 1.0)

    is_flagged = risk_score >= 0.75

    return InputGuardResult(
        is_flagged=is_flagged,
        risk_score=round(risk_score, 4),
        reasons=reasons,
    )
