"""
Secure RAG Platform — Hardened Retrieval-Augmented Generation Engine.

Modules:
    api         FastAPI application factory and REST endpoints
    agent       Legacy RAGSystem orchestrator (QA testing only)
    audit       Append-only audit logging service
    auth        Authentication, RBAC, and session management
    core        Shared configuration and domain exceptions
    db          SQLite connection factory, repository, and schema
    ingestion   In-memory document parsers and chunking pipeline
    llm         Pluggable LLM provider abstraction (Ollama / Groq / Mock)
    pipeline    Master 7-control security pipeline orchestrator
    retrieval   ChromaDB vector store, BM25 keyword search, hybrid engine
    routing     Intent classification (calculator / web_search / pdf_rag)
    security    Input guard, document scanner, policy engine, output guard
    tools       AST-safe calculator and policy-governed web search
"""

__version__ = "2.0.0"
