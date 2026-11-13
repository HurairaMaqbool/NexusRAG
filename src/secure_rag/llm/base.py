"""
src/secure_rag/llm/base.py — BaseLLMProvider Abstract Contract
Defines the pluggable LLM provider interface per ARCHITECTURE §7.2.
"""

from abc import ABC, abstractmethod
from typing import Iterator


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

    def generate_stream(self, prompt: str, temperature: float = 0.2) -> Iterator[str]:
        """
        Streams completion tokens against the underlying model.
        Default implementation yields the complete output in one chunk.
        """
        yield self.generate(prompt=prompt, temperature=temperature)

    @abstractmethod
    def is_available(self) -> bool:
        """Health check verifying provider responsiveness."""
        ...
