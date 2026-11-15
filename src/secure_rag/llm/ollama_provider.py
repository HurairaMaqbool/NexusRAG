"""
src/secure_rag/llm/ollama_provider.py — Local Ollama LLM Provider
Communicates with Ollama via HTTP. Fails cleanly if unavailable.
"""

import json
from typing import Iterator

import httpx

from secure_rag.core.errors import LLMProviderError
from secure_rag.llm.base import BaseLLMProvider


class OllamaProvider(BaseLLMProvider):
    """Local Ollama provider using llama3.1:8b by default."""

    def __init__(
        self,
        model: str = "llama3.1:8b",
        base_url: str = "http://localhost:11434",
        timeout: float = 60.0,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    @property
    def provider_name(self) -> str:
        return "ollama"

    def generate(self, prompt: str, temperature: float = 0.2) -> str:
        """Sends a generate request to local Ollama."""
        try:
            response = httpx.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": temperature},
                },
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()
            return data.get("response", "")
        except httpx.ConnectError:
            raise LLMProviderError(
                f"Ollama is not running at {self.base_url}. "
                "Start Ollama with: ollama serve"
            )
        except httpx.HTTPStatusError as e:
            raise LLMProviderError(f"Ollama HTTP error: {e.response.status_code}")
        except Exception as e:
            raise LLMProviderError(f"Ollama provider error: {type(e).__name__}: {e}")

    def generate_stream(self, prompt: str, temperature: float = 0.2) -> Iterator[str]:
        """Streams completion tokens from local Ollama."""
        try:
            with httpx.stream(
                "POST",
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": True,
                    "options": {"temperature": temperature},
                },
                timeout=self.timeout,
            ) as response:
                response.raise_for_status()
                for line in response.iter_lines():
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        chunk = data.get("response", "")
                        if chunk:
                            yield chunk
                    except json.JSONDecodeError:
                        continue
        except httpx.ConnectError:
            raise LLMProviderError(
                f"Ollama is not running at {self.base_url}. "
                "Start Ollama with: ollama serve"
            )
        except Exception as e:
            raise LLMProviderError(f"Ollama streaming error: {type(e).__name__}: {e}")

    def is_available(self) -> bool:
        """Checks if Ollama is running and responsive."""
        try:
            resp = httpx.get(f"{self.base_url}/api/tags", timeout=5.0)
            return resp.status_code == 200
        except Exception:
            return False

