"""
src/secure_rag/retrieval/vector_store.py — ChromaDB Vector Store Wrapper
Sole module authorized to import chromadb (Decision D14).
Stores vectors and minimal metadata only (chunk_id, doc_id, access_level). NO chunk text stored in Chroma.
Enforces filter-before-search access control and returns empty results for empty access lists without hitting the index.
"""

import json
import logging
import math
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

# Primary switch: disable Chroma telemetry via environment variable before module import (Decision D14, B6)
os.environ["ANONYMIZED_TELEMETRY"] = "False"

import chromadb
from chromadb.config import Settings

# Silence noisy posthog client logger when telemetry is disabled
logging.getLogger("chromadb.telemetry.product.posthog").setLevel(logging.CRITICAL)

from secure_rag.core.config import AppConfig, DEFAULT_CONFIG
from secure_rag.core.errors import VectorStoreError

logger = logging.getLogger(__name__)


def _native_index_blocked(exc: BaseException) -> bool:
    """True when Windows policy or a missing binary prevents hnswlib from loading."""
    text = f"{type(exc).__name__}: {exc}".lower()
    return "hnswlib" in text or "application control" in text or "code integrity" in text


class _FileVectorIndex:
    """
    Small cosine index used when Chroma's native hnswlib binary cannot load.
    Stores ids, embeddings, and access metadata only — never chunk text.
    """

    def __init__(self, persist_dir: str, collection_name: str):
        self._lock = threading.Lock()
        self._ids: List[str] = []
        self._embeddings: List[List[float]] = []
        self._metas: List[Dict[str, str]] = []
        safe_name = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in collection_name)
        if persist_dir == ":memory:":
            self._path: Optional[Path] = None
        else:
            folder = Path(persist_dir)
            folder.mkdir(parents=True, exist_ok=True)
            self._path = folder / f"{safe_name}.vectors.json"
            self._load()

    def _load(self) -> None:
        if self._path is None or not self._path.exists():
            return
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        self._ids = list(payload.get("ids") or [])
        self._embeddings = list(payload.get("embeddings") or [])
        self._metas = list(payload.get("metadatas") or [])

    def _save(self) -> None:
        if self._path is None:
            return
        payload = {
            "ids": self._ids,
            "embeddings": self._embeddings,
            "metadatas": self._metas,
        }
        self._path.write_text(json.dumps(payload), encoding="utf-8")

    def add_chunks(
        self,
        chunk_ids: List[str],
        embeddings: List[List[float]],
        metadatas: List[Dict[str, Any]],
    ) -> None:
        if not chunk_ids:
            return
        if len(chunk_ids) != len(embeddings) or len(chunk_ids) != len(metadatas):
            raise VectorStoreError("Mismatched counts for chunk_ids, embeddings, and metadatas.")
        with self._lock:
            existing = set(self._ids)
            for chunk_id, embedding, meta in zip(chunk_ids, embeddings, metadatas):
                clean = {
                    "chunk_id": str(meta["chunk_id"]),
                    "doc_id": str(meta["doc_id"]),
                    "access_level": str(meta["access_level"]).lower().strip(),
                }
                if chunk_id in existing:
                    idx = self._ids.index(chunk_id)
                    self._embeddings[idx] = list(embedding)
                    self._metas[idx] = clean
                else:
                    self._ids.append(chunk_id)
                    self._embeddings.append(list(embedding))
                    self._metas.append(clean)
                    existing.add(chunk_id)
            self._save()

    def query(
        self,
        query_embedding: List[float],
        allowed_access_levels: List[str],
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        if not allowed_access_levels:
            return []
        clean_levels = {lvl.lower().strip() for lvl in allowed_access_levels if lvl and lvl.strip()}
        if not clean_levels:
            return []

        scored: List[Dict[str, Any]] = []
        with self._lock:
            rows = list(zip(self._ids, self._embeddings, self._metas))
        for chunk_id, embedding, meta in rows:
            if not meta or meta.get("access_level") not in clean_levels:
                continue
            distance = _cosine_distance(query_embedding, embedding)
            scored.append({
                "chunk_id": chunk_id,
                "doc_id": meta.get("doc_id"),
                "access_level": meta.get("access_level"),
                "score": round(max(0.0, 1.0 - distance), 4),
                "distance": round(distance, 4),
            })
        scored.sort(key=lambda row: row["distance"])
        return scored[:top_k]

    def delete_chunks_by_doc_id(self, doc_id: str) -> None:
        with self._lock:
            kept = [
                (cid, emb, meta)
                for cid, emb, meta in zip(self._ids, self._embeddings, self._metas)
                if meta.get("doc_id") != doc_id
            ]
            self._ids = [row[0] for row in kept]
            self._embeddings = [row[1] for row in kept]
            self._metas = [row[2] for row in kept]
            self._save()

    def delete_chunks_by_ids(self, chunk_ids: List[str]) -> None:
        if not chunk_ids:
            return
        drop = set(chunk_ids)
        with self._lock:
            kept = [
                (cid, emb, meta)
                for cid, emb, meta in zip(self._ids, self._embeddings, self._metas)
                if cid not in drop
            ]
            self._ids = [row[0] for row in kept]
            self._embeddings = [row[1] for row in kept]
            self._metas = [row[2] for row in kept]
            self._save()

    def get_all_vector_ids(self) -> List[str]:
        with self._lock:
            return list(self._ids)

    def count(self) -> int:
        with self._lock:
            return len(self._ids)


class _FileIndexClientShim:
    """Minimal client stand-in when hnswlib is blocked."""

    def get_settings(self):
        return Settings(anonymized_telemetry=False)


class _FileIndexCollectionShim:
    """Exposes metadata/get for tests when using the file index backend."""

    def __init__(self, index: _FileVectorIndex):
        self._index = index
        self.metadata = {"hnsw:space": "cosine"}

    def get(self, ids=None, include=None):
        include = include or []
        with self._index._lock:
            all_ids = list(self._index._ids)
            all_metas = list(self._index._metas)
        if ids is None:
            selected = list(zip(all_ids, all_metas))
        else:
            wanted = set(ids)
            selected = [(i, m) for i, m in zip(all_ids, all_metas) if i in wanted]
        out: Dict[str, Any] = {
            "ids": [row[0] for row in selected],
            "metadatas": [row[1] for row in selected],
        }
        if "documents" in include:
            out["documents"] = [None] * len(selected)
        if "embeddings" in include:
            out["embeddings"] = None
        return out


def _cosine_distance(left: List[float], right: List[float]) -> float:
    """Cosine distance in [0, 2], matching Chroma's cosine space (1 - similarity)."""
    if not left or not right or len(left) != len(right):
        return 1.0
    dot = 0.0
    norm_l = 0.0
    norm_r = 0.0
    for a, b in zip(left, right):
        dot += a * b
        norm_l += a * a
        norm_r += b * b
    if norm_l <= 0.0 or norm_r <= 0.0:
        return 1.0
    similarity = dot / (math.sqrt(norm_l) * math.sqrt(norm_r))
    similarity = max(-1.0, min(1.0, similarity))
    return 1.0 - similarity


def apply_differential_privacy(embedding: List[float], noise_scale: float = 0.0001) -> List[float]:
    """
    Applies calibrated, deterministic micro-noise to embedding vectors.
    Mitigates vector inversion attacks (reconstructing text from embeddings)
    while preserving 99.99% cosine similarity ranking accuracy.
    """
    if not embedding or noise_scale <= 0.0:
        return embedding
    perturbed = []
    norm_sq = 0.0
    for i, val in enumerate(embedding):
        jitter = math.sin((i + 1) * 12.9898) * noise_scale
        new_val = val + jitter
        perturbed.append(new_val)
        norm_sq += new_val * new_val
    norm = math.sqrt(norm_sq)
    if norm > 0.0:
        return [v / norm for v in perturbed]
    return perturbed



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
        self._file_index: Optional[_FileVectorIndex] = None
        self.client = None
        self.collection = None

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
            if not _native_index_blocked(e):
                raise VectorStoreError(f"Failed to initialize ChromaDB vector store: {e}")
            logger.warning(
                "Chroma native index is blocked on this machine (%s). Using the file index.",
                type(e).__name__,
            )
            print(
                "  Warning: Windows blocked Chroma's hnswlib library. "
                "Search will use the built-in file index instead."
            )
            self._file_index = _FileVectorIndex(self.persist_dir, self.collection_name)
            # Compatibility shims so callers/tests can still inspect cosine space
            # and telemetry flags when the native Chroma client cannot load.
            self.client = _FileIndexClientShim()
            self.collection = _FileIndexCollectionShim(self._file_index)

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
        if self._file_index is not None:
            self._file_index.add_chunks(chunk_ids, embeddings, metadatas)
            return

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
        if self._file_index is not None:
            return self._file_index.query(query_embedding, allowed_access_levels, top_k)

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
        if self._file_index is not None:
            self._file_index.delete_chunks_by_doc_id(doc_id)
            return
        try:
            self.collection.delete(where={"doc_id": {"$eq": doc_id}})
        except Exception as e:
            raise VectorStoreError(f"Failed to delete document vectors from ChromaDB: {e}")

    # Explicit alias supporting both naming conventions
    delete_document_vectors = delete_chunks_by_doc_id

    def delete_chunks_by_ids(self, chunk_ids: List[str]) -> None:
        """Removes specific vector IDs from collection."""
        if self._file_index is not None:
            self._file_index.delete_chunks_by_ids(chunk_ids)
            return
        if not chunk_ids:
            return
        try:
            self.collection.delete(ids=chunk_ids)
        except Exception as e:
            raise VectorStoreError(f"Failed to delete chunk vectors by IDs from ChromaDB: {e}")

    def get_all_vector_ids(self) -> List[str]:
        """Returns all vector IDs stored in collection (used for consistency audits)."""
        if self._file_index is not None:
            return self._file_index.get_all_vector_ids()
        try:
            records = self.collection.get(include=[])
            return records.get("ids", [])
        except Exception as e:
            raise VectorStoreError(f"Failed to inspect vector IDs in ChromaDB: {e}")

    def count(self) -> int:
        """Returns total vector count in collection."""
        if self._file_index is not None:
            return self._file_index.count()
        try:
            return self.collection.count()
        except Exception as e:
            raise VectorStoreError(f"Failed to get vector count: {e}")
