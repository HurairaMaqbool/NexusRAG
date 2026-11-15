"""
src/secure_rag/security/policy_engine.py — Control 5: Centralized Policy Decision Engine
Evaluates risk score, user role, and provider destination to produce ALLOW/REVIEW/BLOCK.
Enforces Decision D1: HR chunks NEVER sent to Groq.
Security policy NEVER overrides RBAC.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from secure_rag.security.models import (
    DecisionOutcome,
    PolicyEvaluationResult,
    ReasonCode,
)

_DEFAULT_POLICY_PATH = Path(__file__).resolve().parent.parent.parent.parent / "config" / "policy.yaml"


class PolicyEngine:
    """
    Deterministic policy adjudicator.
    Applies risk thresholds from config/policy.yaml and enforces data-exfiltration rules.
    """

    def __init__(self, policy_path: Optional[str] = None):
        path = Path(policy_path) if policy_path else _DEFAULT_POLICY_PATH
        self._config = self._load_policy(path)

        thresholds = self._config.get("risk_thresholds", {})
        self.review_threshold = float(thresholds.get("review", 0.40))
        self.block_threshold = float(thresholds.get("block", 0.75))

        exfil = self._config.get("data_exfiltration_rules", {})
        self.prohibit_restricted_to_cloud = exfil.get("prohibit_restricted_chunks_to_cloud", True)

        # Role capability map from policy.yaml (fail-closed when missing).
        self.role_permissions: Dict[str, Any] = self._config.get("role_permissions", {}) or {}

    @staticmethod
    def _load_policy(path: Path) -> Dict[str, Any]:
        if not path.exists():
            return {}
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    def role_allows(self, user_role: str, capability: str) -> bool:
        """
        Returns True only when policy.yaml explicitly grants the capability
        for the role. Unknown roles/capabilities fail closed (False).
        Capabilities: can_use_calculator, can_use_web_search, can_ingest,
        can_view_audit_dashboard.
        """
        role_key = (user_role or "").lower().strip()
        cap_key = (capability or "").strip()
        if not role_key or not cap_key:
            return False
        role_cfg = self.role_permissions.get(role_key)
        if not isinstance(role_cfg, dict):
            return False
        return bool(role_cfg.get(cap_key, False))

    def evaluate_request(
        self,
        user_role: str,
        risk_score: float,
        target_llm_provider: str,
        retrieved_chunks: Optional[List[Dict[str, Any]]] = None,
    ) -> PolicyEvaluationResult:
        """
        Applies deterministic policy rules:
        1. Decision D1: If target is Groq and any chunk is not cloud-safe
           (employee/public/web), return BLOCK with POLICY_VIOLATION.
           HR and unknown levels never go to Groq.
        2. Risk >= block_threshold → BLOCK with DOC_INJECTION_BLOCKED.
        3. Risk >= review_threshold → REVIEW with DOC_INJECTION_FLAGGED.
        4. Otherwise → ALLOW with ALLOWED_AUTHORIZED_SOURCE.
        """
        chunks = retrieved_chunks or []

        # D1 enforcement: HR/restricted chunks must NEVER go to Groq.
        # Cloud-safe levels: employee docs + synthetic public/web search context.
        # Fail closed: empty/unknown access_level is treated as restricted.
        _CLOUD_SAFE = {"employee", "public", "web"}
        if self.prohibit_restricted_to_cloud and target_llm_provider.lower().strip() == "groq":
            for chunk in chunks:
                access_level = (chunk.get("access_level") or "").lower().strip()
                if access_level not in _CLOUD_SAFE:
                    label = access_level or "unknown"
                    return PolicyEvaluationResult(
                        decision=DecisionOutcome.BLOCK,
                        reason_code=ReasonCode.POLICY_VIOLATION,
                        risk_score=risk_score,
                        details=(
                            f"Chunk with access_level '{label}' cannot be sent to Groq "
                            "(Decision D1 — fail-closed)."
                        ),
                    )

        # Risk-based thresholds
        if risk_score >= self.block_threshold:
            return PolicyEvaluationResult(
                decision=DecisionOutcome.BLOCK,
                reason_code=ReasonCode.DOC_INJECTION_BLOCKED,
                risk_score=risk_score,
                details=f"Risk score {risk_score:.2f} >= block threshold {self.block_threshold}.",
            )

        if risk_score >= self.review_threshold:
            return PolicyEvaluationResult(
                decision=DecisionOutcome.REVIEW,
                reason_code=ReasonCode.DOC_INJECTION_FLAGGED,
                risk_score=risk_score,
                details=f"Risk score {risk_score:.2f} >= review threshold {self.review_threshold}.",
            )

        return PolicyEvaluationResult(
            decision=DecisionOutcome.ALLOW,
            reason_code=ReasonCode.ALLOWED_AUTHORIZED_SOURCE,
            risk_score=risk_score,
            details="Request passed all policy checks.",
        )
