"""
src/secure_rag/security/pii_guard.py — Enterprise PII Redaction & Anonymization Engine
Sanitizes sensitive Personally Identifiable Information (PII) before external LLM dispatch.
Complies with GDPR and HIPAA data-minimization standards.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class PIIMaskResult:
    sanitized_text: str
    has_pii: bool
    masked_entities: Dict[str, str]
    entities_count: int


# High-precision PII detection patterns
_SSN_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CREDIT_CARD_REGEX = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b")
_PHONE_REGEX = re.compile(r"(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
_EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_IBAN_ROUTING_REGEX = re.compile(r"\b(?:[A-Z]{2}\d{2}[A-Z0-9]{11,30}|ABA\s*[:#]?\s*\d{9})\b")


class PIIGuard:
    """Detects and redacts PII using deterministic token replacement."""

    def __init__(self, preserve_domains: Tuple[str, ...] = ("northwind.local",)):
        self.preserve_domains = preserve_domains

    def mask(self, text: str) -> PIIMaskResult:
        """
        Replaces sensitive PII with surrogate placeholders ([SSN_1], [PHONE_1], etc.).
        Returns the sanitized text and the token substitution mapping.
        """
        if not text or not isinstance(text, str):
            return PIIMaskResult(sanitized_text=text or "", has_pii=False, masked_entities={}, entities_count=0)

        mapping: Dict[str, str] = {}
        counter: Dict[str, int] = {"SSN": 0, "CARD": 0, "PHONE": 0, "EMAIL": 0, "BANK": 0}

        def _sub_ssn(match):
            val = match.group(0)
            counter["SSN"] += 1
            token = f"[SSN_{counter['SSN']}]"
            mapping[token] = val
            return token

        def _sub_card(match):
            val = match.group(0)
            # Basic validation: discard obvious non-cards
            digits_only = re.sub(r"\D", "", val)
            if len(digits_only) not in (13, 15, 16):
                return val
            counter["CARD"] += 1
            token = f"[CARD_{counter['CARD']}]"
            mapping[token] = val
            return token

        def _sub_phone(match):
            val = match.group(0)
            counter["PHONE"] += 1
            token = f"[PHONE_{counter['PHONE']}]"
            mapping[token] = val
            return token

        def _sub_email(match):
            val = match.group(0)
            # Preserve internal organizational test domain if requested
            if any(val.lower().endswith(dom) for dom in self.preserve_domains):
                return val
            counter["EMAIL"] += 1
            token = f"[EMAIL_{counter['EMAIL']}]"
            mapping[token] = val
            return token

        def _sub_bank(match):
            val = match.group(0)
            counter["BANK"] += 1
            token = f"[BANK_{counter['BANK']}]"
            mapping[token] = val
            return token

        sanitized = _SSN_REGEX.sub(_sub_ssn, text)
        sanitized = _CREDIT_CARD_REGEX.sub(_sub_card, sanitized)
        sanitized = _PHONE_REGEX.sub(_sub_phone, sanitized)
        sanitized = _EMAIL_REGEX.sub(_sub_email, sanitized)
        sanitized = _IBAN_ROUTING_REGEX.sub(_sub_bank, sanitized)

        total_entities = len(mapping)
        return PIIMaskResult(
            sanitized_text=sanitized,
            has_pii=total_entities > 0,
            masked_entities=mapping,
            entities_count=total_entities,
        )

    def unmask(self, sanitized_text: str, mapping: Dict[str, str]) -> str:
        """Restores original PII values for authorized display."""
        if not sanitized_text or not mapping:
            return sanitized_text
        output = sanitized_text
        for token, original in mapping.items():
            output = output.replace(token, original)
        return output
