"""
tests/unit/test_output_guard.py — Output Guard Unit Tests
Validates canary token detection, system prompt leak detection, and sensitive data patterns.
"""

import pytest
from secure_rag.security.output_guard import validate_output


class TestCanaryToken:
    """Canary token must be ABSENT from LLM output."""

    def test_clean_output(self):
        result = validate_output("The company policy states vacation is 15 days.", canary_token="CANARY-abc123")
        assert result.is_safe
        assert len(result.violations) == 0

    def test_canary_leak(self):
        result = validate_output("Here is the info: CANARY-abc123 is the token.", canary_token="CANARY-abc123")
        assert not result.is_safe
        assert "canary_token_leaked" in result.violations

    def test_no_canary_check(self):
        result = validate_output("Some normal output.", canary_token=None)
        assert result.is_safe


class TestSystemPromptLeak:
    """System prompt markers should be detected."""

    def test_system_tag_in_output(self):
        result = validate_output("[SYSTEM] You are a secure assistant [/SYSTEM]")
        assert not result.is_safe
        assert "system_prompt_leak" in result.violations

    def test_no_system_leak(self):
        result = validate_output("The system is designed to help users efficiently.")
        assert result.is_safe


class TestSensitivePatterns:
    """API keys, SSNs, and credentials should be caught."""

    def test_ssn_pattern(self):
        result = validate_output("The employee SSN is 123-45-6789.")
        assert not result.is_safe
        assert "ssn_pattern" in result.violations

    def test_api_key_pattern(self):
        result = validate_output("Use this key: sk-abcdefghijklmnopqrstuvwxyz123456")
        assert not result.is_safe
        assert "api_key_pattern" in result.violations

    def test_groq_key_pattern(self):
        result = validate_output("Key: gsk_abcdefghijklmnopqrstuvwxyz12345678")
        assert not result.is_safe

    def test_credential_leak(self):
        result = validate_output("password: supersecretpass123")
        assert not result.is_safe
        assert "credential_leak" in result.violations

    def test_no_sensitive_skip(self):
        result = validate_output("Secret info here: password=hunter2", check_sensitive=False)
        assert result.is_safe


class TestEdgeCases:
    """Edge cases and empty inputs."""

    def test_empty_output(self):
        result = validate_output("")
        assert result.is_safe

    def test_none_output(self):
        result = validate_output(None)
        assert result.is_safe

    def test_combined_violations(self):
        result = validate_output(
            "[SYSTEM] secret [/SYSTEM] SSN: 123-45-6789 CANARY-xyz",
            canary_token="CANARY-xyz",
        )
        assert not result.is_safe
        assert len(result.violations) >= 2
