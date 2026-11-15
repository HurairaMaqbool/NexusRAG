"""
src/secure_rag/ingestion/pipeline.py — Authoritative Document Ingestion Pipeline
Coordinates multi-format parsing, chunking, two-store transactional writing (SQLite + ChromaDB),
deduplication by SHA-256 hash, title sanitization, and index consistency verification (Decisions D13-D18, B2-B8).
Architectural boundary: Ingestion does NOT import auth; authorization rules are injected or resolved via callable (B7).
"""

from collections.abc import Callable
import hashlib
import os
from pathlib import Path
import secrets
from typing import Any, Dict, List, Optional

from secure_rag.core.config import AppConfig
from secure_rag.core.errors import (
    AuthorizationError,
    DocumentValidationError,
    DuplicateDocumentError,
    VectorStoreError,
    DatabaseError,
    UniqueConstraintError,
)
from secure_rag.db.repository import SQLiteRepository
from secure_rag.ingestion.parsers import parse_document
from secure_rag.ingestion.chunker import chunk_text
from secure_rag.retrieval.embeddings import BaseEmbedder, FakeEmbedder
from secure_rag.retrieval.vector_store import ChromaVectorStore

import unicodedata

FORBIDDEN_UNICODE_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}

def sanitize_document_title(filename: str, max_length: int = 128) -> str:
    """
    Sanitizes uploaded filename into a safe title string (B5, C3, D3):
    1. Normalizes both forward and backward slashes and extracts only the last path component.
    2. Strips unprintable, control, format, surrogate, private use, unassigned, and separator characters
       using unicodedata.category filtering (removing categories: Cc, Cf, Cs, Co, Cn, Zl, Zp).
    3. Preserves legitimate accented, Arabic, and Urdu characters.
    4. Strips leading/trailing dots and spaces to prevent relative directory traversal artifacts.
    5. Returns 'untitled_document' fallback if empty.
    6. Truncates to max_length (default: 128).
    """
    if not filename or not isinstance(filename, str):
        return "untitled_document"

    # 1. Normalize both separators ('/' and '\\') and extract the final path component
    normalized = filename.replace("\\", "/")
    segments = [s for s in normalized.split("/") if s]
    base = segments[-1] if segments else ""

    # Strip leading/trailing dots and spaces from the component (e.g. "...." -> "")
    base = base.strip(". ")

    # 2. Filter characters by Unicode general category
    clean_chars = [
        ch for ch in base
        if unicodedata.category(ch) not in FORBIDDEN_UNICODE_CATEGORIES
    ]

    cleaned = "".join(clean_chars).strip(". ")
    if not cleaned:
        cleaned = "untitled_document"

    return cleaned[:max_length]

class IngestionPipeline:
    """
    Orchestrates the ingestion, chunking, embedding, and storage lifecycle.
    Guarantees transactional integrity between SQLite (relational source of truth)
    and ChromaDB (vector index).
    """

    def __init__(
        self,
        repo: SQLiteRepository,
        vector_store: ChromaVectorStore,
        embedder: Optional[BaseEmbedder] = None,
        config: Optional[AppConfig] = None,
        can_ingest_fn: Optional[Callable[[str], bool]] = None,
        role_access_fn: Optional[Callable[[str], List[str]]] = None
    ):
        self.repo = repo
        self.vector_store = vector_store
        self.embedder = embedder or FakeEmbedder()
        self.config = config if config is not None else AppConfig()

        # Decoupled authorization check (B7: ingestion must not import auth)
        self.can_ingest_fn = can_ingest_fn or (lambda role: role.lower().strip() == "hr")
        self.role_access_fn = role_access_fn or (
            lambda role: ["employee", "hr"] if role.lower().strip() == "hr" else (
                ["employee"] if role.lower().strip() == "employee" else []
            )
        )

    def ingest_file(
        self,
        file_bytes: bytes,
        filename: str,
        access_level: str,
        uploader_role: str,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes end-to-end document ingestion.
        
        Write Order (Decision D18):
        1. Access control verification (HR only; access_level in role's allowed levels).
        2. Filename sanitization (B5).
        3. In-memory parsing, format validation, and limits enforcement (D17, B8).
        4. Deduplication via SHA-256 hash with status handling (D16, B4).
        5. Deterministic boundary-aware chunking (D15, B8).
        6. SQLite document inserted with status 'indexing'.
        7. SQLite chunks inserted.
        8. Embeddings computed and added to ChromaDB with access_level metadata.
        9. SQLite document updated to status 'indexed'.
        10. Success audit log recorded (event: 'doc_ingested').
        
        Rollback Order (B2):
        On failure, Chroma vectors for doc_id are removed, SQLite chunk rows are deleted,
        and SQLite document status is set to 'failed'. If cleanup fails, 'doc_rollback_incomplete'
        is audited without masking the original exception.
        """
        clean_role = uploader_role.lower().strip()
        clean_access_level = access_level.lower().strip()
        clean_title = sanitize_document_title(filename)

        # 1. Access Control Enforcement (Decision D13, B5 event: ingest_denied)
        if not self.can_ingest_fn(clean_role):
            try:
                self.repo.append_audit_log(
                    decision_id=None,
                    user_id=user_id,
                    event_type="ingest_denied",
                    details={
                        "title": clean_title,
                        "uploader_role": uploader_role,
                        "reason_code": "ROLE_NOT_AUTHORIZED"
                    }
                )
            except Exception:
                pass
            raise AuthorizationError("Only HR role has permissions to upload or ingest documents.")

        allowed_levels = self.role_access_fn(clean_role)
        if clean_access_level not in allowed_levels:
            try:
                self.repo.append_audit_log(
                    decision_id=None,
                    user_id=user_id,
                    event_type="ingest_denied",
                    details={
                        "title": clean_title,
                        "requested_level": clean_access_level,
                        "uploader_role": uploader_role,
                        "reason_code": "ROLE_NOT_AUTHORIZED"
                    }
                )
            except Exception:
                pass
            raise AuthorizationError(
                f"Role '{uploader_role}' is not permitted to assign access level '{access_level}'."
            )

        # 2. In-Memory Parsing & Structural Validation (Decision D17, B8)
        raw_text = parse_document(file_bytes, filename, config=self.config)

        # 3. Deduplication by SHA-256 Hash with Status Gating (Decision D16, B4, B5)
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        existing_doc = self.repo.get_document_by_hash(file_hash)

        if existing_doc:
            doc_status = existing_doc["status"].lower().strip()

            if doc_status == "indexed":
                if existing_doc["access_level"] == clean_access_level:
                    # Idempotent re-upload of active indexed document (B5 event: doc_duplicate)
                    existing_chunks = self.repo.get_chunks_by_document(existing_doc["doc_id"])
                    try:
                        self.repo.append_audit_log(
                            decision_id=None,
                            user_id=user_id,
                            event_type="doc_duplicate",
                            details={
                                "doc_id": existing_doc["doc_id"],
                                "file_hash": file_hash,
                                "access_level": clean_access_level,
                                "reason_code": "ALLOWED_AUTHORIZED_SOURCE"
                            }
                        )
                    except Exception:
                        pass
                    return {
                        "doc_id": existing_doc["doc_id"],
                        "title": existing_doc["title"],
                        "access_level": existing_doc["access_level"],
                        "status": "existing",
                        "chunks_count": len(existing_chunks)
                    }
                else:
                    # Same bytes already indexed under another access level — treat as
                    # idempotent success so the UI is not a dead-end; keep existing level.
                    existing_chunks = self.repo.get_chunks_by_document(existing_doc["doc_id"])
                    try:
                        self.repo.append_audit_log(
                            decision_id=None,
                            user_id=user_id,
                            event_type="doc_duplicate_conflict",
                            details={
                                "title": clean_title,
                                "file_hash": file_hash,
                                "existing_level": existing_doc["access_level"],
                                "attempted_level": clean_access_level,
                                "reason_code": "CLASSIFICATION_CONFLICT",
                                "resolution": "return_existing",
                            }
                        )
                    except Exception:
                        pass
                    return {
                        "doc_id": existing_doc["doc_id"],
                        "title": existing_doc["title"],
                        "access_level": existing_doc["access_level"],
                        "status": "existing",
                        "chunks_count": len(existing_chunks),
                        "warning": (
                            f"Already indexed as '{existing_doc['access_level']}' "
                            f"(you requested '{clean_access_level}'). "
                            "Using the existing classification."
                        ),
                    }
            elif doc_status == "failed":
                # Clean retry: purge old failed document record before re-attempting (B4)
                self.repo.delete_document(existing_doc["doc_id"])
            elif doc_status in ("indexing", "deleting"):
                # In-progress conflict (B4)
                raise DocumentValidationError(
                    f"Document operation currently '{doc_status}' for identical content. Retry later."
                )

        # 4. Boundary-Aware Chunking (Decision D15, B8)
        chunks = chunk_text(raw_text, config=self.config)
        if not chunks:
            raise DocumentValidationError("Document text generated 0 chunks.")

        doc_id = f"doc-{secrets.token_hex(8)}"
        doc_created = False

        # 5 & 6. Transactional SQLite insertion (doc status='indexing')
        try:
            try:
                self.repo.create_document(
                    doc_id=doc_id,
                    title=clean_title,
                    access_level=clean_access_level,
                    file_hash_sha256=file_hash,
                    status="indexing"
                )
                doc_created = True
            except UniqueConstraintError:
                # Concurrent race condition caught by uq_docs_active_hash partial unique index (B4)
                raise DocumentValidationError(
                    "Concurrent upload race: document is already being indexed by another request."
                )

            chunk_payload = []
            chunk_texts = []
            for c in chunks:
                chunk_id = f"{doc_id}-c{c['chunk_index']:04d}"
                chunk_texts.append(c["chunk_text"])
                chunk_payload.append({
                    "chunk_id": chunk_id,
                    "doc_id": doc_id,
                    "chunk_index": c["chunk_index"],
                    "chunk_text": c["chunk_text"],
                    "access_level": clean_access_level,
                    "chroma_id": chunk_id,
                    "baseline_risk_score": 0.0
                })

            self.repo.insert_chunks(chunk_payload)

            # 7. Generate embeddings & insert into ChromaDB
            embeddings = self.embedder.embed_batch(chunk_texts)
            chunk_ids = [p["chunk_id"] for p in chunk_payload]
            metadatas = [
                {
                    "chunk_id": p["chunk_id"],
                    "doc_id": doc_id,
                    "access_level": clean_access_level
                }
                for p in chunk_payload
            ]

            self.vector_store.add_chunks(
                chunk_ids=chunk_ids,
                embeddings=embeddings,
                metadatas=metadatas
            )

            # 8. Mark document as indexed in SQLite
            self.repo.update_document_status(doc_id, "indexed")

            # 9. Audit success (B5 event: doc_ingested)
            try:
                self.repo.append_audit_log(
                    decision_id=None,
                    user_id=user_id,
                    event_type="doc_ingested",
                    details={
                        "doc_id": doc_id,
                        "title": clean_title,
                        "chunks_count": len(chunks),
                        "access_level": clean_access_level,
                        "reason_code": "ALLOWED_AUTHORIZED_SOURCE"
                    }
                )
            except Exception:
                pass

            return {
                "doc_id": doc_id,
                "title": clean_title,
                "access_level": clean_access_level,
                "status": "indexed",
                "chunks_count": len(chunks)
            }

        except Exception as orig_exc:
            # Rollback Path (Decision D18, B2, B5)
            # Purges Chroma vectors and SQLite chunk rows; keeps doc row marked 'failed' (no chunk text)
            cleanup_failures = []
            if doc_created:
                try:
                    self.vector_store.delete_chunks_by_doc_id(doc_id)
                except Exception as ce:
                    cleanup_failures.append(f"chroma:{type(ce).__name__}")

                try:
                    self.repo.delete_chunks_by_doc_id(doc_id)
                except Exception as se:
                    cleanup_failures.append(f"sqlite_chunks:{type(se).__name__}")

                try:
                    self.repo.update_document_status(doc_id, "failed")
                except Exception as ue:
                    cleanup_failures.append(f"sqlite_status:{type(ue).__name__}")

            if cleanup_failures:
                try:
                    self.repo.append_audit_log(
                        decision_id=None,
                        user_id=user_id,
                        event_type="doc_rollback_incomplete",
                        details={
                            "doc_id": doc_id,
                            "failed_stores": cleanup_failures,
                            "error_class": type(orig_exc).__name__
                        }
                    )
                except Exception:
                    pass
            else:
                try:
                    self.repo.append_audit_log(
                        decision_id=None,
                        user_id=user_id,
                        event_type="doc_rejected",
                        details={
                            "doc_id": doc_id if doc_created else None,
                            "title": clean_title,
                            "error_class": type(orig_exc).__name__
                        }
                    )
                except Exception:
                    pass

            raise orig_exc

    def delete_document(
        self,
        doc_id: str,
        uploader_role: str,
        user_id: Optional[str] = None
    ) -> bool:
        """
        Deletes a document using explicit 'deleting' status staging (Decision D18, B2).
        Flow:
        1. Authorization check (HR only).
        2. Mark document status 'deleting' in SQLite.
        3. Delete vectors from ChromaDB.
        4. Delete document row from SQLite (cascades to chunk rows).
        5. Audit 'doc_deleted'.
        """
        clean_role = uploader_role.lower().strip()
        if not self.can_ingest_fn(clean_role):
            try:
                self.repo.append_audit_log(
                    decision_id=None,
                    user_id=user_id,
                    event_type="ingest_denied",
                    details={
                        "doc_id": doc_id,
                        "uploader_role": uploader_role,
                        "reason_code": "ROLE_NOT_AUTHORIZED"
                    }
                )
            except Exception:
                pass
            raise AuthorizationError("Only HR role has permissions to delete documents.")

        doc = self.repo.get_document(doc_id)
        if not doc:
            return False

        # Step 1: Mark status as 'deleting' (hides chunks from any retrieval paths)
        self.repo.update_document_status(doc_id, "deleting")

        # Step 2: Remove vectors from ChromaDB
        self.vector_store.delete_chunks_by_doc_id(doc_id)

        # Step 3: Remove document from SQLite (ON DELETE CASCADE removes chunks)
        deleted = self.repo.delete_document(doc_id)

        if deleted:
            try:
                self.repo.append_audit_log(
                    decision_id=None,
                    user_id=user_id,
                    event_type="doc_deleted",
                    details={"doc_id": doc_id, "reason_code": "ALLOWED_AUTHORIZED_SOURCE"}
                )
            except Exception:
                pass

        return deleted

    def verify_index_consistency(self) -> Dict[str, Any]:
        """
        Verifies synchronization between SQLite relational chunks and ChromaDB vector index (Decision D18).
        Identifies any missing or orphaned vectors across both stores.
        """
        sqlite_chunk_ids = set(self.repo.get_all_chunk_ids())
        chroma_vector_ids = set(self.vector_store.get_all_vector_ids())

        missing_in_chroma = list(sqlite_chunk_ids - chroma_vector_ids)
        orphaned_in_chroma = list(chroma_vector_ids - sqlite_chunk_ids)

        is_consistent = (len(missing_in_chroma) == 0 and len(orphaned_in_chroma) == 0)

        return {
            "is_consistent": is_consistent,
            "sqlite_chunk_count": len(sqlite_chunk_ids),
            "chroma_vector_count": len(chroma_vector_ids),
            "missing_in_chroma": missing_in_chroma,
            "orphaned_in_chroma": orphaned_in_chroma
        }
