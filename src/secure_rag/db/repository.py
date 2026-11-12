"""
src/secure_rag/db/repository.py — Data Access Object (DAO) for Relational SQLite
Authoritative repository implementing atomic, parameterized operations for all entities.
"""

import json
import sqlite3
from typing import Any, Dict, List, Optional
from secure_rag.core.errors import DatabaseError, RecordNotFoundError, UniqueConstraintError

class SQLiteRepository:
    """Thread-safe Data Access Object managing relational persistence."""

    def __init__(self, connection_factory):
        self._connection_factory = connection_factory

    def _get_connection(self) -> sqlite3.Connection:
        return self._connection_factory()

    # ── Role Operations ────────────────────────────────────────────────────────

    def create_role(self, role_id: str, name: str, permissions: List[str]) -> Dict[str, Any]:
        perms_str = json.dumps(permissions)
        conn = self._get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO roles (role_id, name, permissions) VALUES (?, ?, ?);",
                    (role_id, name, perms_str)
                )
            return {"role_id": role_id, "name": name, "permissions": permissions}
        except sqlite3.IntegrityError as e:
            raise UniqueConstraintError(f"Role '{role_id}' or name '{name}' already exists: {e}")
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to create role: {e}")
        finally:
            conn.close()

    def get_role(self, role_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT role_id, name, permissions FROM roles WHERE role_id = ?;",
                (role_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "role_id": row["role_id"],
                "name": row["name"],
                "permissions": json.loads(row["permissions"])
            }
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to fetch role '{role_id}': {e}")
        finally:
            conn.close()

    def list_roles(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cursor = conn.execute("SELECT role_id, name, permissions FROM roles ORDER BY name ASC;")
            rows = cursor.fetchall()
            return [
                {
                    "role_id": r["role_id"],
                    "name": r["name"],
                    "permissions": json.loads(r["permissions"])
                }
                for r in rows
            ]
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to list roles: {e}")
        finally:
            conn.close()

    # ── User Operations ────────────────────────────────────────────────────────

    def create_user(
        self,
        user_id: str,
        email: str,
        password_hash: str,
        role_id: str,
        is_active: int = 1
    ) -> Dict[str, Any]:
        conn = self._get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO users (user_id, email, password_hash, role_id, is_active)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    (user_id, email.lower().strip(), password_hash, role_id, is_active)
                )
            return {
                "user_id": user_id,
                "email": email.lower().strip(),
                "role_id": role_id,
                "is_active": bool(is_active)
            }
        except sqlite3.IntegrityError as e:
            raise UniqueConstraintError(f"User with ID '{user_id}' or email '{email}' already exists: {e}")
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to create user: {e}")
        finally:
            conn.close()

    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """
                SELECT u.user_id, u.email, u.password_hash, u.role_id, u.is_active, u.created_at,
                       r.name as role_name, r.permissions
                FROM users u
                JOIN roles r ON u.role_id = r.role_id
                WHERE u.email = ?;
                """,
                (email.lower().strip(),)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "user_id": row["user_id"],
                "email": row["email"],
                "password_hash": row["password_hash"],
                "role_id": row["role_id"],
                "role_name": row["role_name"],
                "permissions": json.loads(row["permissions"]),
                "is_active": bool(row["is_active"]),
                "created_at": row["created_at"]
            }
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to fetch user by email: {e}")
        finally:
            conn.close()

    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """
                SELECT u.user_id, u.email, u.password_hash, u.role_id, u.is_active, u.created_at,
                       r.name as role_name, r.permissions
                FROM users u
                JOIN roles r ON u.role_id = r.role_id
                WHERE u.user_id = ?;
                """,
                (user_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "user_id": row["user_id"],
                "email": row["email"],
                "password_hash": row["password_hash"],
                "role_id": row["role_id"],
                "role_name": row["role_name"],
                "permissions": json.loads(row["permissions"]),
                "is_active": bool(row["is_active"]),
                "created_at": row["created_at"]
            }
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to fetch user by ID: {e}")
        finally:
            conn.close()

    # ── Document & Chunk Operations ───────────────────────────────────────────

    def create_document(
        self,
        doc_id: str,
        title: str,
        access_level: str,
        file_hash_sha256: str,
        status: str = "indexed"
    ) -> Dict[str, Any]:
        conn = self._get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO documents (doc_id, title, access_level, file_hash_sha256, status)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    (doc_id, title, access_level.lower().strip(), file_hash_sha256, status)
                )
            return {
                "doc_id": doc_id,
                "title": title,
                "access_level": access_level.lower().strip(),
                "file_hash_sha256": file_hash_sha256,
                "status": status
            }
        except sqlite3.IntegrityError as e:
            raise UniqueConstraintError(f"Document with ID '{doc_id}' already exists: {e}")
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to create document: {e}")
        finally:
            conn.close()

    def get_document(self, doc_id: str) -> Optional[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT doc_id, title, access_level, file_hash_sha256, status, uploaded_at FROM documents WHERE doc_id = ?;",
                (doc_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return dict(row)
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to fetch document: {e}")
        finally:
            conn.close()

    def list_documents(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cursor = conn.execute("SELECT doc_id, title, access_level, file_hash_sha256, status, uploaded_at FROM documents ORDER BY uploaded_at DESC;")
            return [dict(r) for r in cursor.fetchall()]
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to list documents: {e}")
        finally:
            conn.close()

    def get_document_by_hash(self, file_hash_sha256: str) -> Optional[Dict[str, Any]]:
        """Finds an existing document by its file SHA-256 hash (Decision D16)."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT doc_id, title, access_level, file_hash_sha256, status, uploaded_at FROM documents WHERE file_hash_sha256 = ?;",
                (file_hash_sha256,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return dict(row)
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to fetch document by hash: {e}")
        finally:
            conn.close()

    def update_document_status(self, doc_id: str, status: str) -> bool:
        """Updates document status (e.g. 'indexing' -> 'indexed' or 'failed') (Decision D18)."""
        conn = self._get_connection()
        try:
            with conn:
                cursor = conn.execute(
                    "UPDATE documents SET status = ? WHERE doc_id = ?;",
                    (status, doc_id)
                )
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to update document status: {e}")
        finally:
            conn.close()

    def delete_document(self, doc_id: str) -> bool:
        """Deletes a document and relies on ON DELETE CASCADE for its chunks."""
        conn = self._get_connection()
        try:
            with conn:
                cursor = conn.execute("DELETE FROM documents WHERE doc_id = ?;", (doc_id,))
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to delete document: {e}")
        finally:
            conn.close()

    def get_chunks_by_document(self, doc_id: str) -> List[Dict[str, Any]]:
        """Retrieves all chunks associated with a specific document ID."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT chunk_id, doc_id, chunk_index, chunk_text, access_level, chroma_id, baseline_risk_score FROM document_chunks WHERE doc_id = ? ORDER BY chunk_index;",
                (doc_id,)
            )
            return [dict(r) for r in cursor.fetchall()]
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to fetch chunks for document: {e}")
        finally:
            conn.close()

    def get_all_chunk_ids(self) -> List[str]:
        """Retrieves all chunk IDs stored in SQLite for index consistency verification (Decision D18)."""
        conn = self._get_connection()
        try:
            cursor = conn.execute("SELECT chunk_id FROM document_chunks;")
            return [row["chunk_id"] for row in cursor.fetchall()]
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to fetch all chunk IDs: {e}")
        finally:
            conn.close()

    def insert_chunks(self, chunks: List[Dict[str, Any]]) -> int:
        """Atomically inserts a batch of document chunks."""
        if not chunks:
            return 0
        conn = self._get_connection()
        try:
            payload = [
                (
                    c["chunk_id"],
                    c["doc_id"],
                    c["chunk_index"],
                    c["chunk_text"],
                    c["access_level"].lower().strip(),
                    c["chroma_id"],
                    c.get("baseline_risk_score", 0.0)
                )
                for c in chunks
            ]
            with conn:
                conn.executemany(
                    """
                    INSERT INTO document_chunks 
                    (chunk_id, doc_id, chunk_index, chunk_text, access_level, chroma_id, baseline_risk_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?);
                    """,
                    payload
                )
            return len(payload)
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to insert chunks: {e}")
        finally:
            conn.close()

    def delete_chunks_by_doc_id(self, doc_id: str) -> int:
        """Deletes all chunks belonging to a document while preserving the document row (Decision D18, B2)."""
        conn = self._get_connection()
        try:
            with conn:
                cursor = conn.execute("DELETE FROM document_chunks WHERE doc_id = ?;", (doc_id,))
                return cursor.rowcount
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to delete chunks for document: {e}")
        finally:
            conn.close()

    def get_chunks_by_ids(self, chunk_ids: List[str]) -> List[Dict[str, Any]]:
        """
        Retrieves chunks by their IDs, joining with documents to enforce status='indexed'.
        Only returns chunks whose parent document is in 'indexed' status.
        """
        if not chunk_ids:
            return []
        conn = self._get_connection()
        try:
            placeholders = ",".join("?" for _ in chunk_ids)
            query = f"""
                SELECT c.chunk_id, c.doc_id, c.chunk_index, c.chunk_text, c.access_level,
                       c.chroma_id, c.baseline_risk_score, d.title as source_file
                FROM document_chunks c
                JOIN documents d ON c.doc_id = d.doc_id
                WHERE c.chunk_id IN ({placeholders})
                  AND d.status = 'indexed'
                ORDER BY c.doc_id, c.chunk_index;
            """
            cursor = conn.execute(query, chunk_ids)
            return [dict(r) for r in cursor.fetchall()]
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to fetch chunks by IDs: {e}")
        finally:
            conn.close()

    def get_documents_by_status(self, status: str) -> List[Dict[str, Any]]:
        """Retrieves all documents matching a given status (e.g. 'deleting', 'indexing')."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT doc_id, title, access_level, file_hash_sha256, status, uploaded_at FROM documents WHERE status = ?;",
                (status,)
            )
            return [dict(r) for r in cursor.fetchall()]
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to fetch documents by status: {e}")
        finally:
            conn.close()

    def get_chunks_by_access_levels(self, allowed_levels: List[str]) -> List[Dict[str, Any]]:
        """
        Retrieves all chunks matching allowed access levels.
        Status Gating (B3): ONLY returns chunks whose document status is 'indexed'.
        Chunks from documents in 'indexing', 'failed', or 'deleting' status are strictly excluded.
        """
        if not allowed_levels:
            return []
        conn = self._get_connection()
        try:
            placeholders = ",".join("?" for _ in allowed_levels)
            query = f"""
                SELECT c.chunk_id, c.doc_id, c.chunk_index, c.chunk_text, c.access_level, c.chroma_id, c.baseline_risk_score
                FROM document_chunks c
                JOIN documents d ON c.doc_id = d.doc_id
                WHERE c.access_level IN ({placeholders})
                  AND d.status = 'indexed'
                ORDER BY c.doc_id, c.chunk_index;
            """
            cursor = conn.execute(query, [lvl.lower().strip() for lvl in allowed_levels])
            return [dict(r) for r in cursor.fetchall()]
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to fetch chunks by access level: {e}")
        finally:
            conn.close()

    # ── Query & Security Decision Operations ──────────────────────────────────

    def record_query(self, query_id: str, user_id: str, query_text: str, status: str = "pending") -> Dict[str, Any]:
        conn = self._get_connection()
        try:
            with conn:
                conn.execute(
                    "INSERT INTO queries (query_id, user_id, query_text, status) VALUES (?, ?, ?, ?);",
                    (query_id, user_id, query_text, status)
                )
            return {"query_id": query_id, "user_id": user_id, "query_text": query_text, "status": status}
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to record query: {e}")
        finally:
            conn.close()

    def record_decision(
        self,
        decision_id: str,
        query_id: str,
        decision: str,
        risk_score: float,
        reason_code: str
    ) -> Dict[str, Any]:
        conn = self._get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO security_decisions (decision_id, query_id, decision, risk_score, reason_code)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    (decision_id, query_id, decision, float(risk_score), reason_code)
                )
            return {
                "decision_id": decision_id,
                "query_id": query_id,
                "decision": decision,
                "risk_score": risk_score,
                "reason_code": reason_code
            }
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to record security decision: {e}")
        finally:
            conn.close()

    # ── Audit Log Operations (Append-Only) ────────────────────────────────────

    # ── Session Operations (Decision D9 & D10) ────────────────────────────────

    def create_session(
        self,
        session_id: str,
        user_id: str,
        token_hash: str,
        expires_at: str
    ) -> Dict[str, Any]:
        conn = self._get_connection()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT INTO sessions (session_id, user_id, token_hash, expires_at)
                    VALUES (?, ?, ?, ?);
                    """,
                    (session_id, user_id, token_hash, expires_at)
                )
            return {
                "session_id": session_id,
                "user_id": user_id,
                "token_hash": token_hash,
                "expires_at": expires_at
            }
        except sqlite3.IntegrityError as e:
            raise UniqueConstraintError(f"Session with ID '{session_id}' or token already exists: {e}")
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to create session: {e}")
        finally:
            conn.close()

    def get_session_by_token_hash(self, token_hash: str) -> Optional[Dict[str, Any]]:
        """
        Fetches session joined with authoritative users and roles tables.
        Guarantees that user's current is_active status and role are read
        directly from the database on every check (Decision D10).
        """
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """
                SELECT s.session_id, s.user_id, s.token_hash, s.created_at, s.expires_at, s.revoked_at,
                       u.email, u.is_active, u.role_id,
                       r.name as role_name, r.permissions
                FROM sessions s
                JOIN users u ON s.user_id = u.user_id
                JOIN roles r ON u.role_id = r.role_id
                WHERE s.token_hash = ?;
                """,
                (token_hash,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "session_id": row["session_id"],
                "user_id": row["user_id"],
                "token_hash": row["token_hash"],
                "created_at": row["created_at"],
                "expires_at": row["expires_at"],
                "revoked_at": row["revoked_at"],
                "email": row["email"],
                "is_active": bool(row["is_active"]),
                "role_id": row["role_id"],
                "role_name": row["role_name"],
                "permissions": json.loads(row["permissions"])
            }
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to fetch session: {e}")
        finally:
            conn.close()

    def touch_session(self, session_id: str, new_expires_at: str) -> bool:
        """Extends a session's expires_at for idle-timeout sliding window."""
        conn = self._get_connection()
        try:
            with conn:
                cursor = conn.execute(
                    "UPDATE sessions SET expires_at = ? WHERE session_id = ? AND revoked_at IS NULL;",
                    (new_expires_at, session_id),
                )
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to touch session: {e}")
        finally:
            conn.close()

    def revoke_session(self, session_id: str) -> bool:
        """Revokes a session by recording revoked_at timestamp."""
        conn = self._get_connection()
        try:
            with conn:
                cursor = conn.execute(
                    "UPDATE sessions SET revoked_at = CURRENT_TIMESTAMP WHERE session_id = ? AND revoked_at IS NULL;",
                    (session_id,)
                )
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to revoke session: {e}")
        finally:
            conn.close()

    # ── Audit Log Operations (Append-Only) ────────────────────────────────────

    def append_audit_log(
        self,
        decision_id: Optional[str],
        user_id: Optional[str],
        event_type: str,
        latency_ms: float = 0.0,
        provider_used: str = "system",
        details: Optional[Dict[str, Any]] = None
    ) -> int:
        details_str = json.dumps(details) if details else "{}"
        conn = self._get_connection()
        try:
            with conn:
                cursor = conn.execute(
                    """
                    INSERT INTO audit_logs 
                    (decision_id, user_id, event_type, latency_ms, provider_used, details_json)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (decision_id, user_id, event_type, float(latency_ms), provider_used, details_str)
                )
                return cursor.lastrowid
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to append audit log: {e}")
        finally:
            conn.close()

    def get_audit_logs(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                """
                SELECT a.log_id, a.decision_id, a.user_id, a.event_type, a.latency_ms,
                       a.provider_used, a.details_json, a.timestamp,
                       d.decision, d.risk_score, d.reason_code,
                       u.email as user_email
                FROM audit_logs a
                LEFT JOIN security_decisions d ON a.decision_id = d.decision_id
                LEFT JOIN users u ON a.user_id = u.user_id
                ORDER BY a.timestamp DESC, a.log_id DESC
                LIMIT ? OFFSET ?;
                """,
                (limit, offset)
            )
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                if item.get("details_json"):
                    try:
                        item["details"] = json.loads(item["details_json"])
                    except Exception:
                        item["details"] = {}
                results.append(item)
            return results
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to fetch audit logs: {e}")
        finally:
            conn.close()

    def get_audit_logs_count(self) -> int:
        conn = self._get_connection()
        try:
            cursor = conn.execute("SELECT COUNT(*) as cnt FROM audit_logs;")
            row = cursor.fetchone()
            return row["cnt"] if row else 0
        except sqlite3.Error as e:
            raise DatabaseError(f"Failed to count audit logs: {e}")
        finally:
            conn.close()

