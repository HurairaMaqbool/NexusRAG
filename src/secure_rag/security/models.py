"""
src/secure_rag/security/models.py — Security Enums & Dataclasses
Defines DecisionOutcome, ReasonCode, and PolicyEvaluationResult per ARCHITECTURE §7.1.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


class DecisionOutcome(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


class ReasonCode(str, Enum):
    ROLE_NOT_AUTHORIZED = "ROLE_NOT_AUTHORIZED"
    INPUT_INJECTION = "INPUT_INJECTION"
    DOC_INJECTION_FLAGGED = "DOC_INJECTION_FLAGGED"
    DOC_INJECTION_BLOCKED = "DOC_INJECTION_BLOCKED"
    OUTPUT_LEAK = "OUTPUT_LEAK"
    CANARY_TRIGGERED = "CANARY_TRIGGERED"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    NO_AUTHORIZED_CONTEXT = "NO_AUTHORIZED_CONTEXT"
    RATE_LIMITED = "RATE_LIMITED"
    ALLOWED_AUTHORIZED_SOURCE = "ALLOWED_AUTHORIZED_SOURCE"
    ALLOWED_GENERAL_KNOWLEDGE = "ALLOWED_GENERAL_KNOWLEDGE"
    CLOUD_PRIVACY_GATE = "CLOUD_PRIVACY_GATE"


@dataclass(frozen=True)
class PolicyEvaluationResult:
    decision: DecisionOutcome
    reason_code: ReasonCode
    risk_score: float
    details: str


@dataclass(frozen=True)
class ScanResult:
    """Result of scanning a chunk or set of chunks for injection patterns."""
    risk_score: float
    matched_signatures: List[str]
    details: str


@dataclass(frozen=True)
class InputGuardResult:
    """Result of inspecting user input for direct injection."""
    is_flagged: bool
    risk_score: float
    reasons: List[str]


@dataclass(frozen=True)
class OutputGuardResult:
    """Result of validating LLM output."""
    is_safe: bool
    violations: List[str]
