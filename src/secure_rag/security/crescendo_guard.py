"""
src/secure_rag/security/crescendo_guard.py — Multi-Turn Crescendo Jailbreak Defense
Inspects conversational dialogue history to detect progressive escalation attacks (MITRE ATLAS AML.T0054).
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional

from secure_rag.security.input_guard import inspect as inspect_input


@dataclass(frozen=True)
class CrescendoEvaluation:
    is_flagged: bool
    cumulative_risk: float
    escalation_detected: bool
    reasons: List[str]


# Escalation triggers across turns
_ESCALATION_PHRASES = [
    re.compile(r"(?i)\b(hypothetically|in\s+theory|for\s+educational\s+purposes\s+only)\b"),
    re.compile(r"(?i)\b(now\s+combine|put\s+them\s+together|step\s+by\s+step\s+exploit)\b"),
    re.compile(r"(?i)\b(bypass|circumvent|override|disable|ignore\s+safeguards)\b"),
    re.compile(r"(?i)\b(admin|root|master\s+key|canary|prompt\s+extraction)\b"),
]


class CrescendoGuard:
    """Detects multi-turn conversational attacks that gradually steer safety guards into collapse."""

    def __init__(self, risk_escalation_threshold: float = 1.2, max_turns_window: int = 6):
        self.risk_escalation_threshold = risk_escalation_threshold
        self.max_turns_window = max_turns_window

    def evaluate_history(
        self,
        current_query: str,
        history: Optional[List[Dict[str, str]]] = None,
    ) -> CrescendoEvaluation:
        """
        Analyzes current query alongside previous dialogue history turns.
        Scores cumulative risk and detects adversarial escalation.
        """
        history = history or []
        user_turns = [
            turn.get("content", "")
            for turn in history[-self.max_turns_window:]
            if turn.get("role") == "user" and turn.get("content")
        ]
        # Include current query
        all_user_prompts = user_turns + [current_query]

        cumulative_risk = 0.0
        matched_reasons = []
        escalation_markers_count = 0

        for prompt in all_user_prompts:
            guard_res = inspect_input(prompt)
            cumulative_risk += guard_res.risk_score
            matched_reasons.extend(guard_res.reasons)

            for pattern in _ESCALATION_PHRASES:
                if pattern.search(prompt):
                    escalation_markers_count += 1

        # Check for multi-turn pattern escalation
        escalation_detected = escalation_markers_count >= 2 and len(all_user_prompts) >= 2
        if escalation_detected:
            cumulative_risk += 0.50
            matched_reasons.append("multi_turn_crescendo_escalation")

        # Flag if cumulative risk exceeds threshold or escalation pattern was detected
        is_flagged = cumulative_risk >= self.risk_escalation_threshold or escalation_detected

        return CrescendoEvaluation(
            is_flagged=is_flagged,
            cumulative_risk=round(min(2.0, cumulative_risk), 4),
            escalation_detected=escalation_detected,
            reasons=list(dict.fromkeys(matched_reasons)),
        )
