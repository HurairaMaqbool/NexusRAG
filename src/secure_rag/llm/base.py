"""
src/secure_rag/llm/base.py — BaseLLMProvider Abstract Contract
Defines the pluggable LLM provider interface per ARCHITECTURE §7.2.
"""

from abc import ABC, abstractmethod


class BaseLLMProvider(ABC):
    """Abstract base for all LLM providers (Ollama, Groq, Mock)."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Returns provider identifier: 'ollama', 'groq', or 'mock'."""
        ...

    @abstractmethod
    def generate(self, prompt: str, temperature: float = 0.2) -> str:
        """
        Executes completion against the underlying model.
        Raises LLMProviderError on communication failure.
        """
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Health check verifying provider responsiveness."""
        ...
