"""
src/secure_rag/core/config.py — Centralized Runtime Configuration
Loads immutable configuration from environment variables with safe production defaults.
"""

from dataclasses import dataclass
import os
from pathlib import Path
from typing import Optional

@dataclass(frozen=True)
class AppConfig:
    """Immutable application and security configuration."""
    
    # Environment & Storage
    app_env: str = "dev"
    db_path: str = "data/nexus.db"
    chroma_persist_dir: str = "data/chroma"
    chroma_collection_name: str = "secure_rag_chunks"
    
    # Ingestion Limits (Decision D17)
    max_upload_mb: int = 10
    max_pages: int = 100
    max_text_chars: int = 500_000
    max_chunks: int = 1000
    max_uncompressed_docx_bytes: int = 20 * 1024 * 1024  # 20 MB zip bomb limit
    max_docx_compression_ratio: float = 100.0            # 100:1 ratio limit
    
    # Chunking Parameters (Decision D15)
    chunk_size: int = 600
    chunk_overlap: int = 80
    
    # Embeddings (Decision D15)
    embedding_model_name: str = "sentence-transformers/all-MiniLM-L6-v2"
    embedding_dimension: int = 384
    
    # Security & Provider
    secret_key: str = ""
    llm_provider: str = "ollama"
    enable_web_search: bool = False
    
    @classmethod
    def from_env(cls) -> "AppConfig":
        """Instantiates AppConfig by reading environment variables."""
        db_path = (
            os.getenv("DB_PATH")
            or os.getenv("SQLITE_PATH")
            or "data/nexus.db"
        )
        chroma_persist_dir = (
            os.getenv("CHROMA_PERSIST_DIR")
            or os.getenv("CHROMA_PATH")
            or "data/chroma"
        )
        return cls(
            app_env=os.getenv("APP_ENV", "dev").lower().strip(),
            db_path=db_path,
            chroma_persist_dir=chroma_persist_dir,
            chroma_collection_name=os.getenv("CHROMA_COLLECTION_NAME", "secure_rag_chunks"),
            max_upload_mb=int(os.getenv("MAX_UPLOAD_MB", "10")),
            max_pages=int(os.getenv("MAX_PAGES", "100")),
            max_text_chars=int(os.getenv("MAX_TEXT_CHARS", "500000")),
            max_chunks=int(os.getenv("MAX_CHUNKS", "1000")),
            max_uncompressed_docx_bytes=int(os.getenv("MAX_UNCOMPRESSED_DOCX_BYTES", str(20 * 1024 * 1024))),
            max_docx_compression_ratio=float(os.getenv("MAX_DOCX_COMPRESSION_RATIO", "100.0")),
            chunk_size=int(os.getenv("CHUNK_SIZE", "600")),
            chunk_overlap=int(os.getenv("CHUNK_OVERLAP", "80")),
            embedding_model_name=os.getenv("EMBEDDING_MODEL_NAME", "sentence-transformers/all-MiniLM-L6-v2"),
            embedding_dimension=int(os.getenv("EMBEDDING_DIMENSION", "384")),
            secret_key=os.getenv("SECRET_KEY", ""),
            llm_provider=os.getenv("LLM_PROVIDER", "ollama").lower().strip(),
            enable_web_search=os.getenv("ENABLE_WEB_SEARCH", "false").lower().strip() in ("1", "true", "yes")
        )

# Global default configuration instance
DEFAULT_CONFIG = AppConfig()
