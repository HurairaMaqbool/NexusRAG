"""
src/secure_rag/agent/rag_system.py — LEGACY RAGSystem Orchestrator (DEPRECATED)

WARNING: This module is the pre-hardened agent path. It does NOT enforce:
  - RBAC / access level filtering
  - Input guard / output guard / scanner / policy engine
  - Audit logging
  - Session-based authentication

It is retained ONLY for offline testing via qa_test_suite.py.
Production traffic MUST use PipelineOrchestrator (src/secure_rag/pipeline.py).

In production (APP_ENV != 'dev'), instantiating RAGSystem raises SecurityConfigurationError.
"""

import os
import time
import warnings

import numpy as np
from sentence_transformers import SentenceTransformer

from secure_rag.agent.intent import detect_intent as _detect_intent
from secure_rag.agent import documents as _documents
from secure_rag.tools.calculator import calculator_tool as _calculator_tool
from secure_rag.tools.web_search import web_search_tool as _web_search_tool
from secure_rag.llm import prompts as _prompts
from secure_rag.agent._legacy.hybrid_memory import HybridMemoryStore


class RAGSystem:

    def __init__(self, embed_model=None):
        # Block instantiation in production to prevent bypassing the secure pipeline
        _env = os.getenv("APP_ENV", "dev").lower().strip()
        if _env not in ("dev", "test"):
            from secure_rag.core.errors import SecurityConfigurationError
            raise SecurityConfigurationError(
                "RAGSystem is a legacy, unsecured agent path. "
                "It cannot be used when APP_ENV is not 'dev' or 'test'. "
                "Use PipelineOrchestrator for production workloads."
            )
        warnings.warn(
            "RAGSystem is deprecated and lacks security controls. "
            "Use PipelineOrchestrator for production.",
            DeprecationWarning,
            stacklevel=2,
        )

        if embed_model is not None:
            self.embed_model = embed_model
        else:
            print("\u2699\ufe0f  Loading embedding model...")
            for attempt in range(5):
                try:
                    self.embed_model = SentenceTransformer("all-MiniLM-L6-v2")
                    break
                except Exception as e:
                    print(f"   Attempt {attempt + 1}/5 failed: {e}")
                    time.sleep(3)
            else:
                raise RuntimeError("Could not load embedding model after 5 attempts.")

        dim_fn = getattr(self.embed_model, "get_embedding_dimension", None)
        if dim_fn is None:
            dim_fn = getattr(self.embed_model, "get_sentence_embedding_dimension", None)
        dim = dim_fn() if dim_fn is not None else int(getattr(self.embed_model, "dimension", 384))

        self.store = HybridMemoryStore(dim)
        print("\u2705 RAG System ready.")

    # ── Convenience property so callers can still read rag.chunks ─────────
    @property
    def chunks(self) -> list[dict]:
        return self.store.chunks

    # ── Intent Detection (delegates to agent.intent) ─────────────────────
    def detect_intent(self, query: str) -> str:
        return _detect_intent(query)

    # ── Tools (delegates to tools package) ────────────────────────────────
    def calculator_tool(self, query: str) -> str:
        return _calculator_tool(query)

    def web_search_tool(self, query: str, max_results: int = 4) -> str:
        return _web_search_tool(query, max_results=max_results)

    # ── Document Processing (delegates to agent.documents) ────────────────
    def parse_file(self, file_path: str, filename: str) -> list[dict]:
        return _documents.parse_file(file_path, filename)

    def chunk_text(self, items: list[dict], chunk_size: int = 800, overlap: int = 150) -> list[dict]:
        return _documents.chunk_text(items, chunk_size=chunk_size, overlap=overlap)

    def add_document(self, file_path: str, filename: str) -> str:
        """Parse, chunk, embed, and index a document file."""
        try:
            items = self.parse_file(file_path, filename)
        except ValueError as e:
            return str(e)

        if not items:
            return f"No readable text found in {filename}."

        new_chunks = self.chunk_text(items)
        if not new_chunks:
            return f"File {filename} was empty after processing."

        texts = [c["text"] for c in new_chunks]
        embeddings = self.embed_model.encode(texts, show_progress_bar=False, batch_size=32)
        self.store.add(new_chunks, np.array(embeddings, dtype="float32"))

        return f"\u2705 Indexed {len(new_chunks)} chunks from **{filename}**. Ready to answer questions!"

    # ── Search ───────────────────────────────────────────────────────────
    def hybrid_search(self, query: str, top_k: int = 5) -> list[dict]:
        q_embed = self.embed_model.encode([query])
        return self.store.search(np.array(q_embed, dtype="float32"), query, top_k)

    # ── LLM Prompting (delegates to llm.prompts) ─────────────────────────
    def ask_rag(self, question: str, context: str) -> str:
        return _prompts.ask_rag(question, context)

    def ask_web(self, question: str, web_context: str) -> str:
        return _prompts.ask_web(question, web_context)

    def ask_general(self, question: str) -> str:
        return _prompts.ask_general(question)

    def ask_math_explainer(self, question: str, raw_result: str) -> str:
        return _prompts.ask_math_explainer(question, raw_result)

    # ── Main Chat Entry Point ────────────────────────────────────────────
    def chat(self, query: str) -> str:
        """Route query to the correct tool and return a formatted answer."""
        if not query or not query.strip():
            return "Please enter a valid question."

        try:
            intent = self.detect_intent(query)
        except Exception:
            intent = "pdf_rag"

        if intent == "calculator":
            raw = self.calculator_tool(query)
            explanation = self.ask_math_explainer(query, raw)
            if explanation:
                return f"\U0001f9ee **{raw}**\n\n{explanation}"
            return f"\U0001f9ee **{raw}**"

        elif intent == "web_search":
            web_results = self.web_search_tool(query)
            if "failed" in web_results.lower() or "unavailable" in web_results.lower():
                answer = self.ask_general(query)
                return f"\U0001f4a1 **Answer** *(web search unavailable \u2014 using AI knowledge)*\n\n{answer}"
            answer = self.ask_web(query, web_context=web_results)
            return f"\U0001f310 **Web Search Answer**\n\n{answer}"

        else:
            chunks = self.hybrid_search(query)
            if not chunks:
                answer = self.ask_general(query)
                return f"\U0001f4a1 **General Answer** *(no documents indexed \u2014 using AI knowledge)*\n\n{answer}"

            context = "\n\n---\n\n".join(c["text"] for c in chunks)
            sources = sorted(set(
                f"`{c.get('source_file', 'Unknown')}` \u2014 {c.get('source_id', '')}"
                for c in chunks
            ))
            answer = self.ask_rag(query, context=context)
            sources_str = "\n".join(f"- {s}" for s in sources)
            return f"\U0001f4c4 **Document Answer**\n\n{answer}\n\n---\n**\U0001f4ce Sources:**\n{sources_str}"
