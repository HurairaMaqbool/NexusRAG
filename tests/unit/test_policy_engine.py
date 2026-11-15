"""
tests/unit/test_policy_engine.py — Policy Engine Unit Tests
Validates ALLOW/REVIEW/BLOCK decisions and D1 enforcement.
"""

import pytest
from secure_rag.security.models import DecisionOutcome, ReasonCode
from secure_rag.security.policy_engine import PolicyEngine


@pytest.fixture
def engine():
    return PolicyEngine()


class TestRiskThresholds:
    """Risk score should map to correct decisions."""

    def test_low_risk_allows(self, engine):
        result = engine.evaluate_request(
            user_role="employee", risk_score=0.1, target_llm_provider="ollama"
        )
        assert result.decision == DecisionOutcome.ALLOW
        assert result.reason_code == ReasonCode.ALLOWED_AUTHORIZED_SOURCE

    def test_zero_risk_allows(self, engine):
        result = engine.evaluate_request(
            user_role="employee", risk_score=0.0, target_llm_provider="ollama"
        )
        assert result.decision == DecisionOutcome.ALLOW

    def test_medium_risk_review(self, engine):
        result = engine.evaluate_request(
            user_role="employee", risk_score=0.5, target_llm_provider="ollama"
        )
        assert result.decision == DecisionOutcome.REVIEW
        assert result.reason_code == ReasonCode.DOC_INJECTION_FLAGGED

    def test_at_review_threshold(self, engine):
        result = engine.evaluate_request(
            user_role="employee", risk_score=0.40, target_llm_provider="ollama"
        )
        assert result.decision == DecisionOutcome.REVIEW

    def test_high_risk_blocks(self, engine):
        result = engine.evaluate_request(
            user_role="employee", risk_score=0.8, target_llm_provider="ollama"
        )
        assert result.decision == DecisionOutcome.BLOCK
        assert result.reason_code == ReasonCode.DOC_INJECTION_BLOCKED

    def test_at_block_threshold(self, engine):
        result = engine.evaluate_request(
            user_role="employee", risk_score=0.75, target_llm_provider="ollama"
        )
        assert result.decision == DecisionOutcome.BLOCK


class TestD1GroqEnforcement:
    """D1: HR chunks must NEVER be sent to Groq."""

    def test_hr_chunks_to_groq_blocked(self, engine):
        chunks = [{"access_level": "hr", "chunk_id": "c1"}]
        result = engine.evaluate_request(
            user_role="hr",
            risk_score=0.0,
            target_llm_provider="groq",
            retrieved_chunks=chunks,
        )
        assert result.decision == DecisionOutcome.BLOCK
        assert result.reason_code == ReasonCode.POLICY_VIOLATION

    def test_employee_chunks_to_groq_allowed(self, engine):
        chunks = [{"access_level": "employee", "chunk_id": "c1"}]
        result = engine.evaluate_request(
            user_role="employee",
            risk_score=0.0,
            target_llm_provider="groq",
            retrieved_chunks=chunks,
        )
        assert result.decision == DecisionOutcome.ALLOW

    def test_public_web_chunks_to_groq_allowed(self, engine):
        chunks = [{"access_level": "public", "chunk_id": "web-1"}]
        result = engine.evaluate_request(
            user_role="hr",
            risk_score=0.0,
            target_llm_provider="groq",
            retrieved_chunks=chunks,
        )
        assert result.decision == DecisionOutcome.ALLOW

    def test_hr_chunks_to_ollama_allowed(self, engine):
        chunks = [{"access_level": "hr", "chunk_id": "c1"}]
        result = engine.evaluate_request(
            user_role="hr",
            risk_score=0.0,
            target_llm_provider="ollama",
            retrieved_chunks=chunks,
        )
        assert result.decision == DecisionOutcome.ALLOW

    def test_mixed_chunks_to_groq_blocked(self, engine):
        chunks = [
            {"access_level": "employee", "chunk_id": "c1"},
            {"access_level": "hr", "chunk_id": "c2"},
        ]
        result = engine.evaluate_request(
            user_role="hr",
            risk_score=0.0,
            target_llm_provider="groq",
            retrieved_chunks=chunks,
        )
        assert result.decision == DecisionOutcome.BLOCK
        assert result.reason_code == ReasonCode.POLICY_VIOLATION

    def test_missing_access_level_to_groq_blocked_fail_closed(self, engine):
        chunks = [{"access_level": "", "chunk_id": "c1"}]
        result = engine.evaluate_request(
            user_role="hr",
            risk_score=0.0,
            target_llm_provider="groq",
            retrieved_chunks=chunks,
        )
        assert result.decision == DecisionOutcome.BLOCK
        assert result.reason_code == ReasonCode.POLICY_VIOLATION


class TestRoleAllows:
    """role_allows must enforce policy.yaml role_permissions fail-closed."""

    def test_employee_web_search_false(self, engine):
        assert engine.role_allows("employee", "can_use_web_search") is False

    def test_hr_web_search_true(self, engine):
        assert engine.role_allows("hr", "can_use_web_search") is True

    def test_admin_calculator_false(self, engine):
        assert engine.role_allows("admin", "can_use_calculator") is False

    def test_unknown_role_fail_closed(self, engine):
        assert engine.role_allows("unknown", "can_use_calculator") is False

    def test_missing_capability_fail_closed(self, engine):
        assert engine.role_allows("hr", "can_fly") is False


class TestPolicyNeverOverridesRBAC:
    """Security policy must never upgrade access levels."""

    def test_low_risk_does_not_grant_extra_access(self, engine):
        result = engine.evaluate_request(
            user_role="employee", risk_score=0.0, target_llm_provider="ollama"
        )
        # Decision is ALLOW, but this doesn't change the caller's access levels
        assert result.decision == DecisionOutcome.ALLOW
        # The engine doesn't modify access levels — it only produces decisions
