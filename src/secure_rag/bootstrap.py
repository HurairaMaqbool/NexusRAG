"""
src/secure_rag/bootstrap.py — Application Bootstrap Factory
Builds the complete FastAPI application with all dependencies wired.
Equivalent to TASK-07 DI: db, auth, seed, vector store, embedder, LLM,
scanner, policy, audit, retrieval engine, pipeline orchestrator, ingestion, create_app.
"""

import logging
import os
from pathlib import Path
from typing import Tuple

from fastapi import FastAPI

from secure_rag.api.app import create_app
from secure_rag.audit.service import AuditService
from secure_rag.auth.service import AuthService
from secure_rag.core.config import AppConfig
from secure_rag.db.connection import get_db_connection, init_db
from secure_rag.db.repository import SQLiteRepository
from secure_rag.ingestion.pipeline import IngestionPipeline
from secure_rag.llm.factory import create_provider
from secure_rag.pipeline import PipelineOrchestrator
from secure_rag.retrieval.embeddings import FakeEmbedder, SentenceTransformerEmbedder
from secure_rag.retrieval.hybrid_engine import HybridRetrievalEngine
from secure_rag.retrieval.vector_store import ChromaVectorStore
from secure_rag.security.policy_engine import PolicyEngine
from secure_rag.security.scanner import DocumentScanner

logger = logging.getLogger(__name__)


def _configure_logging() -> None:
    """Apply logging config from config/logging.yaml if present, else basicConfig."""
    config_path = Path("config/logging.yaml")
    if config_path.exists():
        try:
            import yaml
            import logging.config as logging_config

            with open(config_path, "r", encoding="utf-8") as f:
                log_cfg = yaml.safe_load(f)
            if log_cfg and isinstance(log_cfg, dict):
                logging_config.dictConfig(log_cfg)
                return
        except Exception:
            pass
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def _reseed_if_requested(config: AppConfig) -> None:
    """Delete local SQLite DBs when DEMO_FORCE_RESEED=1 in dev mode."""
    if (
        os.getenv("DEMO_FORCE_RESEED", "").strip() in ("1", "true", "yes")
        and config.app_env == "dev"
    ):
        for pattern in ("nexus.db*", "secure_rag.db*"):
            for path in Path("data").glob(pattern):
                try:
                    path.unlink(missing_ok=True)
                    print(f"  DEMO_FORCE_RESEED removed {path}")
                except OSError as e:
                    print(f"  Warning: could not remove {path}: {type(e).__name__}")


def _build_embedder(config: AppConfig):
    """Instantiate embedder: FakeEmbedder for CI/test, SentenceTransformer otherwise."""
    if os.getenv("EMBEDDING_FAKE", "").lower() in ("1", "true", "yes"):
        return FakeEmbedder(dimension=config.embedding_dimension)

    try:
        return SentenceTransformerEmbedder(config.embedding_model_name)
    except Exception as e:
        if config.app_env not in ("dev", "test"):
            print(
                f"  FATAL: Embedder load failed in {config.app_env} mode "
                f"({type(e).__name__}). FakeEmbedder is not allowed outside dev/test."
            )
            raise SystemExit(1)
        print(f"  Warning: Falling back to FakeEmbedder ({type(e).__name__})")
        return FakeEmbedder(dimension=config.embedding_dimension)


def _seed_dev_accounts(auth_service: AuthService, config: AppConfig) -> None:
    """Seed demo accounts in dev mode from DEMO_PASSWORD_* env vars."""
    if config.app_env != "dev":
        return
    try:
        passwords = auth_service.seed_dev_accounts()
        seeded = [
            email
            for email, pw in passwords.items()
            if pw != "[existing account preserved]"
        ]
        if seeded:
            print(f"  DEV accounts ready: {', '.join(seeded)} (passwords not logged)")
    except Exception as e:
        print(f"  Warning: Could not seed dev accounts: {type(e).__name__}")


def create_application() -> Tuple[FastAPI, AppConfig]:
    """
    Build and return ``(app, config)`` with all dependencies injected.
    This is the single production entrypoint for constructing the application.
    """
    _configure_logging()

    config = AppConfig.from_env()

    _reseed_if_requested(config)

    # Database
    init_db(config.db_path)
    repo = SQLiteRepository(
        connection_factory=lambda: get_db_connection(config.db_path)
    )

    # Auth
    auth_service = AuthService(
        repo=repo, app_env=config.app_env, secret_key=config.secret_key
    )
    auth_service.validate_startup_config()
    _seed_dev_accounts(auth_service, config)

    # Embedder & Vector Store
    vector_store = ChromaVectorStore(
        persist_dir=config.chroma_persist_dir, config=config
    )
    embedder = _build_embedder(config)

    # LLM
    llm_provider = create_provider(config)

    # Security
    scanner = DocumentScanner()
    policy_engine = PolicyEngine()
    audit_service = AuditService(repo=repo)

    # Retrieval
    retrieval_engine = HybridRetrievalEngine(
        repo=repo, vector_store=vector_store, embedder=embedder
    )

    # Pipeline Orchestrator
    pipeline_orchestrator = PipelineOrchestrator(
        retrieval_engine=retrieval_engine,
        llm_provider=llm_provider,
        scanner=scanner,
        policy_engine=policy_engine,
        audit_service=audit_service,
        config=config,
    )

    # Ingestion
    ingestion_pipeline = IngestionPipeline(
        repo=repo, vector_store=vector_store, embedder=embedder, config=config
    )

    # FastAPI app
    app = create_app(
        auth_service=auth_service,
        pipeline_orchestrator=pipeline_orchestrator,
        ingestion_pipeline=ingestion_pipeline,
    )

    return app, config
