"""
src/secure_rag/retrieval/vector_store.py — ChromaDB Vector Store Wrapper
Sole module authorized to import chromadb (Decision D14).
Stores vectors and minimal metadata only (chunk_id, doc_id, access_level). NO chunk text stored in Chroma.
Enforces filter-before-search access control and returns empty results for empty access lists without hitting the index.
"""

import logging
import os
from typing import Any, Dict, List, Optional

# Primary switch: disable Chroma telemetry via environment variable before module import (Decision D14, B6)
os.environ["ANONYMIZED_TELEMETRY"] = "False"

import chromadb
from chromadb.config import Settings

# Silence noisy posthog client logger when telemetry is disabled
logging.getLogger("chromadb.telemetry.product.posthog").setLevel(logging.CRITICAL)

from secure_rag.core.config import AppConfig, DEFAULT_CONFIG
from secure_rag.core.errors import VectorStoreError

class ChromaVectorStore:
    """
    Encapsulated ChromaDB vector store.
    Enforces cosine distance, telemetry opt-out, and pre-filtered query authorization.
    """

    def __init__(
        self,
        persist_dir: Optional[str] = None,
        collection_name: Optional[str] = None,
        config: Optional[AppConfig] = None
    ):
        cfg = config or DEFAULT_CONFIG
        self.persist_dir = persist_dir if persist_dir is not None else cfg.chroma_persist_dir
        self.collection_name = collection_name if collection_name is not None else cfg.chroma_collection_name

        # Opt out of telemetry (Decision D14)
        chroma_settings = Settings(anonymized_telemetry=False, is_persistent=True)

        try:
            if self.persist_dir == ":memory:":
                self.client = chromadb.EphemeralClient(settings=Settings(anonymized_telemetry=False))
            else:
                self.client = chromadb.PersistentClient(path=self.persist_dir, settings=chroma_settings)

            # Ensure collection uses cosine distance space
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"hnsw:space": "cosine"}
            )
        except Exception as e:
            raise VectorStoreError(f"Failed to initialize ChromaDB vector store: {e}")

    def add_chunks(
        self,
        chunk_ids: List[str],
        embeddings: List[List[float]],
        metadatas: List[Dict[str, Any]]
    ) -> None:
        """
        Adds vectors and minimal access-control metadata to Chroma.
        STRICT REQUIREMENT: NO chunk text is passed or stored in Chroma (Decision D14).
        """
        if not chunk_ids:
            return

        if len(chunk_ids) != len(embeddings) or len(chunk_ids) != len(metadatas):
            raise VectorStoreError("Mismatched counts for chunk_ids, embeddings, and metadatas.")

        # Ensure metadata contains only allowable scalar fields (chunk_id, doc_id, access_level)
        clean_metadatas = []
        for m in metadatas:
            clean_m = {
                "chunk_id": str(m["chunk_id"]),
                "doc_id": str(m["doc_id"]),
                "access_level": str(m["access_level"]).lower().strip()
            }
            clean_metadatas.append(clean_m)

        try:
            # We explicitly do NOT pass 'documents' parameter to ChromaDB
            self.collection.add(
                ids=chunk_ids,
                embeddings=embeddings,
                metadatas=clean_metadatas
            )
        except Exception as e:
            raise VectorStoreError(f"ChromaDB insert failed: {e}")

    def query(
        self,
        query_embedding: List[float],
        allowed_access_levels: List[str],
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Executes pre-filtered semantic retrieval.
        Decision D14: If allowed_access_levels is empty, returns [] immediately without calling Chroma.
        """
        if not allowed_access_levels:
            # Deny by default — never query index without verified access levels
            return []

        clean_levels = [lvl.lower().strip() for lvl in allowed_access_levels if lvl.strip()]
        if not clean_levels:
            return []

        # Construct Chroma metadata filter
        if len(clean_levels) == 1:
            where_filter = {"access_level": {"$eq": clean_levels[0]}}
        else:
            where_filter = {"access_level": {"$in": clean_levels}}

        try:
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=top_k,
                where=where_filter,
                include=["metadatas", "distances"]
            )
        except Exception as e:
            raise VectorStoreError(f"ChromaDB query execution failed: {e}")

        matched = []
        ids = results.get("ids", [[]])[0]
        distances = results.get("distances", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]

        for chunk_id, dist, meta in zip(ids, distances, metadatas):
            if not meta:
                continue
            # For cosine distance, similarity score can be mapped to 1.0 - distance
            score = max(0.0, 1.0 - float(dist)) if dist is not None else 0.0
            matched.append({
                "chunk_id": chunk_id,
                "doc_id": meta.get("doc_id"),
                "access_level": meta.get("access_level"),
                "score": round(score, 4),
                "distance": round(float(dist), 4) if dist is not None else None
            })

        return matched

    def delete_chunks_by_doc_id(self, doc_id: str) -> None:
        """Removes all vectors belonging to a specific document ID."""
        try:
            self.collection.delete(where={"doc_id": {"$eq": doc_id}})
        except Exception as e:
            raise VectorStoreError(f"Failed to delete document vectors from ChromaDB: {e}")

    # Explicit alias supporting both naming conventions
    delete_document_vectors = delete_chunks_by_doc_id

    def delete_chunks_by_ids(self, chunk_ids: List[str]) -> None:
        """Removes specific vector IDs from collection."""
        if not chunk_ids:
            return
        try:
            self.collection.delete(ids=chunk_ids)
        except Exception as e:
            raise VectorStoreError(f"Failed to delete chunk vectors by IDs from ChromaDB: {e}")

    def get_all_vector_ids(self) -> List[str]:
        """Returns all vector IDs stored in collection (used for consistency audits)."""
        try:
            records = self.collection.get(include=[])
            return records.get("ids", [])
        except Exception as e:
            raise VectorStoreError(f"Failed to inspect vector IDs in ChromaDB: {e}")

    def count(self) -> int:
        """Returns total vector count in collection."""
        try:
            return self.collection.count()
        except Exception as e:
            raise VectorStoreError(f"Failed to get vector count: {e}")
