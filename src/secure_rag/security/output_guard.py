"""
src/secure_rag/security/output_guard.py — Control 6: Output Validation
Checks LLM output for canary token leakage, system prompt disclosure, and sensitive data patterns.
"""

import re
from typing import List, Optional

from secure_rag.security.models import OutputGuardResult

# Bare 9-digit numbers and ordinary emails are not blocked — they appear in
# normal answers. Dashed SSNs, API keys, and credentials still block.
_SENSITIVE_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "ssn_pattern"),
    (re.compile(r"(?i)\b(sk-[a-zA-Z0-9]{20,}|gsk_[a-zA-Z0-9]{20,}|api[_-]?key\s*[:=]\s*\S{10,})"), "api_key_pattern"),
    (re.compile(r"(?i)(password\s*[:=]\s*\S+|secret[_-]?key\s*[:=]\s*\S+)"), "credential_leak"),
]

# System prompt leak indicators
_SYSTEM_PROMPT_PATTERNS = [
    re.compile(r"(?i)\[SYSTEM\]"),
    re.compile(r"(?i)\[/SYSTEM\]"),
    re.compile(r"(?i)Security token.*CANARY"),
    re.compile(r"(?i)NEVER output this"),
]


def validate_output(
    output: str,
    canary_token: Optional[str] = None,
    check_sensitive: bool = True,
) -> OutputGuardResult:
    """
    Validates LLM output for safety violations.

    Checks:
    1. Canary token must be ABSENT from output (if provided).
    2. System prompt markers must be absent.
    3. Sensitive patterns (API keys, SSNs) must be absent.
    """
    if not output:
        return OutputGuardResult(is_safe=True, violations=[])

    violations: List[str] = []

    # Check canary token leak
    if canary_token and canary_token in output:
        violations.append("canary_token_leaked")

    # Check system prompt disclosure
    for pattern in _SYSTEM_PROMPT_PATTERNS:
        if pattern.search(output):
            violations.append("system_prompt_leak")
            break

    # Check sensitive data patterns
    if check_sensitive:
        for pattern, label in _SENSITIVE_PATTERNS:
            if pattern.search(output):
                violations.append(label)

    return OutputGuardResult(
        is_safe=len(violations) == 0,
        violations=violations,
    )
