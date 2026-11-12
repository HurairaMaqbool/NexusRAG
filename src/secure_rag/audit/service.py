"""
src/secure_rag/audit/service.py — Control 7: Append-Only Audit Service
Records every request, security decision, and event to SQLite.
NEVER logs passwords, raw tokens, canaries, or secrets.
"""

import logging
import secrets
from typing import Any, Dict, Optional

from secure_rag.core.errors import DatabaseError
from secure_rag.db.repository import SQLiteRepository
from secure_rag.security.models import DecisionOutcome, ReasonCode

logger = logging.getLogger(__name__)

# Patterns to strip from audit details to prevent secret leakage
_REDACT_KEYS = {"password", "token", "raw_token", "canary", "canary_token", "secret", "api_key"}


def _sanitize_details(details: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Strips sensitive fields from audit detail payloads."""
    if not details:
        return details
    clean = {}
    for key, val in details.items():
        if key.lower() in _REDACT_KEYS:
            clean[key] = "[REDACTED]"
        else:
            clean[key] = val
    return clean


class AuditService:
    """Append-only audit logger backed by SQLite."""

    def __init__(self, repo: SQLiteRepository):
        self.repo = repo

    def record_event(
        self,
        request_id: str,
        user_id: Optional[str],
        user_role: str,
        query_text: str,
        decision: DecisionOutcome,
        reason_code: ReasonCode,
        risk_score: float,
        chunks_retrieved_count: int = 0,
        latency_ms: float = 0.0,
        provider_used: str = "system",
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Records an audit event to SQLite.
        Creates a query record + security_decision + audit_log entry when user_id is known.
        Raises DatabaseError if the append-only audit_log write fails.
        """
        safe_details = _sanitize_details(details)
        decision_id = f"dec-{secrets.token_hex(8)}"
        decision_recorded = False

        # queries.user_id is NOT NULL FK — only record when we have a real user.
        if user_id:
            try:
                self.repo.record_query(
                    query_id=request_id,
                    user_id=user_id,
                    query_text=(query_text or "")[:500],
                    status=decision.value.lower(),
                )
            except Exception as exc:
                # Duplicate request_id is acceptable on retries.
                logger.warning("audit query record skipped: %s", type(exc).__name__)

            try:
                self.repo.record_decision(
                    decision_id=decision_id,
                    query_id=request_id,
                    decision=decision.value,
                    risk_score=risk_score,
                    reason_code=reason_code.value,
                )
                decision_recorded = True
            except Exception as exc:
                logger.warning("audit decision record skipped: %s", type(exc).__name__)
                decision_id_for_log = None
            else:
                decision_id_for_log = decision_id
        else:
            decision_id_for_log = None

        audit_details = {
            "user_role": user_role,
            "chunks_retrieved": chunks_retrieved_count,
            "reason_code": reason_code.value,
            "request_id": request_id,
        }
        if safe_details:
            audit_details.update(safe_details)

        try:
            self.repo.append_audit_log(
                decision_id=decision_id_for_log if decision_recorded else None,
                user_id=user_id,
                event_type=f"pipeline_{decision.value.lower()}",
                latency_ms=latency_ms,
                provider_used=provider_used,
                details=audit_details,
            )
        except Exception as exc:
            logger.critical("append_audit_log failed for request_id=%s", request_id, exc_info=True)
            raise DatabaseError(f"Failed to append audit log: {type(exc).__name__}") from exc

        return decision_id if decision_recorded else f"audit-only-{secrets.token_hex(6)}"
