"""
src/secure_rag/llm/factory.py — LLM Provider Factory
Creates the appropriate provider based on configuration.
"""

from typing import Optional

from secure_rag.core.config import AppConfig
from secure_rag.llm.base import BaseLLMProvider


class MockLLMProvider(BaseLLMProvider):
    """Deterministic mock provider for testing. Returns a fixed response."""

    def __init__(self, default_response: str = "This is a mock LLM response."):
        self._default_response = default_response

    @property
    def provider_name(self) -> str:
        return "mock"

    def generate(self, prompt: str, temperature: float = 0.2) -> str:
        return self._default_response

    def is_available(self) -> bool:
        return True


def create_provider(
    config: Optional[AppConfig] = None,
    provider_name: Optional[str] = None,
) -> BaseLLMProvider:
    """
    Factory that instantiates the appropriate LLM provider.
    Supports: 'ollama' (default), 'groq', 'mock'.
    """
    cfg = config or AppConfig.from_env()
    name = (provider_name or cfg.llm_provider).lower().strip()

    if name == "mock":
        return MockLLMProvider()

    if name == "groq":
        from secure_rag.llm.groq_provider import GroqProvider
        return GroqProvider()

    if name == "ollama":
        from secure_rag.llm.ollama_provider import OllamaProvider
        return OllamaProvider()

    # Default to mock in test scenarios, ollama otherwise
    from secure_rag.llm.ollama_provider import OllamaProvider
    return OllamaProvider()
