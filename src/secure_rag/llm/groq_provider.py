"""
src/secure_rag/llm/groq_provider.py — Groq Cloud LLM Provider with Fallback Chain
Implements BaseLLMProvider. Tries multiple Groq-hosted models in order until one succeeds.
"""

import os
from typing import Optional

from langchain_groq import ChatGroq

from secure_rag.core.errors import LLMProviderError
from secure_rag.llm.base import BaseLLMProvider

GROQ_MODELS = [
    "openai/gpt-oss-120b",
    "llama3-70b-8192",
    "mixtral-8x7b-32768",
    "gemma2-9b-it",
]


class GroqProvider(BaseLLMProvider):
    """Groq cloud provider with fallback chain across multiple models."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        models: Optional[list] = None,
        default_temperature: float = 0.3,
    ):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY", "")
        self.models = models or GROQ_MODELS
        self.default_temperature = default_temperature

    @property
    def provider_name(self) -> str:
        return "groq"

    def generate(self, prompt: str, temperature: float = 0.2) -> str:
        """Tries each Groq model in the fallback chain."""
        if not self.api_key:
            raise LLMProviderError("GROQ_API_KEY not configured.")

        last_error = None
        for model in self.models:
            try:
                llm = ChatGroq(
                    model=model,
                    temperature=temperature,
                    api_key=self.api_key,
                )
                result = llm.invoke(prompt)
                return result.content
            except Exception as e:
                last_error = e
                continue

        raise LLMProviderError(
            f"All Groq models unavailable. Last error: {last_error}"
        )

    def is_available(self) -> bool:
        """Checks if Groq API key is configured."""
        return bool(self.api_key)


# Legacy compatibility function used by prompts.py and qa_test_suite
def get_llm(temperature: float = 0.3) -> ChatGroq:
    """Return a ChatGroq instance, trying each model in the fallback chain."""
    api_key = os.environ.get("GROQ_API_KEY", "")
    for model in GROQ_MODELS:
        try:
            return ChatGroq(model=model, temperature=temperature, api_key=api_key)
        except Exception:
            continue
    raise RuntimeError("All Groq models unavailable. Check your API key.")
