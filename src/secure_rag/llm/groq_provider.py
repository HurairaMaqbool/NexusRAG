"""
src/secure_rag/llm/groq_provider.py — Groq Cloud LLM Provider with Fallback Chain
Implements BaseLLMProvider. Tries multiple Groq-hosted models in order until one succeeds.
"""

import logging
import os
import re
from typing import Optional

from langchain_groq import ChatGroq

from secure_rag.core.errors import LLMProviderError
from secure_rag.llm.base import BaseLLMProvider

logger = logging.getLogger(__name__)

# Models this deployment can call. Faster model first.
# Decommissioned ids (llama3-70b-8192, mixtral-8x7b-32768) are omitted.
GROQ_MODELS = [
    "llama-3.1-8b-instant",
    "llama-3.3-70b-versatile",
    "openai/gpt-oss-20b",
    "openai/gpt-oss-120b",
]

# Per-model HTTP timeout. Three models stay inside the client chat timeout.
_REQUEST_TIMEOUT_SEC = 25.0
_MAX_TOKENS = 768
_THINK_BLOCK = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def _message_text(result) -> str:
    """Return visible answer text, dropping reasoning traces."""
    content = getattr(result, "content", "") or ""
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                parts.append(str(block.get("text") or ""))
        content = "".join(parts)
    elif not isinstance(content, str):
        content = str(content)
    return _THINK_BLOCK.sub("", content).strip()


def _chat_client(model: str, temperature: float, api_key: str) -> ChatGroq:
    """Build a Groq client that fails fast instead of reasoning without a limit."""
    kwargs = {
        "model": model,
        "temperature": temperature,
        "api_key": api_key,
        "timeout": _REQUEST_TIMEOUT_SEC,
        "max_retries": 0,
        "max_tokens": _MAX_TOKENS,
    }
    # Reasoning controls only apply to gpt-oss / reasoning-capable models.
    if "gpt-oss" in model or "qwen" in model:
        kwargs["reasoning_effort"] = "low"
        kwargs["reasoning_format"] = "hidden"
    return ChatGroq(**kwargs)


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
                result = _chat_client(model, temperature, self.api_key).invoke(prompt)
                text = _message_text(result)
                if text:
                    return text
                last_error = LLMProviderError(f"{model} returned empty content")
                logger.warning("Groq model %s returned empty content", model)
            except Exception as e:
                last_error = e
                logger.warning("Groq model %s failed: %s", model, type(e).__name__)
                continue

        raise LLMProviderError(
            f"All Groq models unavailable. Last error: {last_error}"
        )

    def is_available(self) -> bool:
        """Checks if Groq API key is configured."""
        return bool(self.api_key)


# Legacy compatibility function used by prompts.py and qa_test_suite
def get_llm(temperature: float = 0.3) -> ChatGroq:
    """Return a ChatGroq instance for the first configured model."""
    api_key = os.environ.get("GROQ_API_KEY", "")
    for model in GROQ_MODELS:
        try:
            return _chat_client(model, temperature, api_key)
        except Exception:
            continue
    raise RuntimeError("All Groq models unavailable. Check your API key.")
