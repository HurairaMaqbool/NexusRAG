"""
LLM provider package — base abstraction, factory, and provider implementations.

Production API:
    BaseLLMProvider, create_provider, MockLLMProvider,
    GroqProvider, OllamaProvider

Legacy prompt helpers (ask_rag, ask_web, ask_general, ask_math_explainer) and
get_llm are available via deep imports (secure_rag.llm.prompts / groq_provider)
but are not part of the production public API.
"""

from secure_rag.llm.base import BaseLLMProvider
from secure_rag.llm.factory import create_provider, MockLLMProvider
from secure_rag.llm.groq_provider import GroqProvider
from secure_rag.llm.ollama_provider import OllamaProvider

__all__ = [
    "BaseLLMProvider",
    "MockLLMProvider",
    "create_provider",
    "GroqProvider",
    "OllamaProvider",
]
