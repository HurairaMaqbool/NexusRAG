"""
src/secure_rag/api/app.py — Secure FastAPI Application Factory
REST API with authentication, pipeline execution, and audit endpoints.
Uses dependency injection to avoid importing pipeline module directly (architecture boundary B7).
"""

import json
import logging
import os
import time
import threading
from collections import defaultdict
from typing import Any, Optional

logger = logging.getLogger(__name__)

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.base import BaseHTTPMiddleware

from secure_rag.auth.constants import ROLE_ACCESS_MAPPING, can_ingest
from secure_rag.auth.service import AuthService
from secure_rag.core.config import DEFAULT_CONFIG
from secure_rag.core.errors import (
    AuthenticationError,
    AuthorizationError,
    DocumentValidationError,
    DuplicateDocumentError,
    RateLimitExceededError,
    VectorStoreError,
    DatabaseError,
    LLMProviderError,
)

_UPLOAD_CHUNK_SIZE = 64 * 1024  # 64 KB streaming chunks
_HARD_MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # hard ceiling if config is mis-set


# ── Security Headers Middleware ──────────────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds security headers to every response (nosniff, frame-deny, referrer, basic CSP)."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response


# ── Per-User/IP Rate Limiter for Authenticated Endpoints ────────────────────

class EndpointRateLimiter:
    """
    In-memory per-key sliding-window rate limiter.
    Keys are (client_ip, endpoint) or (user_id, endpoint) pairs.
    """

    def __init__(self, max_requests: int = 30, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._buckets: dict[str, list[float]] = defaultdict(list)

    def is_limited(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._buckets[key]
            self._buckets[key] = [t for t in bucket if t > cutoff]
            if len(self._buckets[key]) >= self.max_requests:
                return True
            self._buckets[key].append(now)
            return False


# Shared rate limiter instances for authenticated endpoints
_chat_limiter = EndpointRateLimiter(max_requests=30, window_seconds=60)
_upload_limiter = EndpointRateLimiter(max_requests=10, window_seconds=60)


# ── Request Body Size Guard ─────────────────────────────────────────────────

MAX_REQUEST_BODY_BYTES = 11 * 1024 * 1024  # 11 MB (slightly above max_upload_mb to allow form overhead)

class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects requests whose Content-Length exceeds the maximum allowed body size."""

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_REQUEST_BODY_BYTES:
            return JSONResponse(
                {"error": "Request body too large."},
                status_code=413,
            )
        return await call_next(request)


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=1, max_length=320)
    password: str = Field(..., min_length=1, max_length=72)


_CHAT_HISTORY_CONTENT_MAX = 2000


class ChatHistoryTurn(BaseModel):
    role: str = Field(..., min_length=1, max_length=32)
    # Accept long assistant replies from the UI; truncate instead of 422.
    content: str = Field(..., min_length=1, max_length=20000)

    @field_validator("content", mode="before")
    @classmethod
    def _truncate_content(cls, value: object) -> object:
        if isinstance(value, str) and len(value) > _CHAT_HISTORY_CONTENT_MAX:
            return value[:_CHAT_HISTORY_CONTENT_MAX]
        return value


class ChatRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=1000)
    history: list[ChatHistoryTurn] = Field(default_factory=list, max_length=8)


def _extract_bearer_token(request: Request) -> str:
    """Extracts Bearer token from Authorization header."""
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return ""


def create_app(
    auth_service: Optional[AuthService] = None,
    pipeline_orchestrator: Optional[Any] = None,
    ingestion_pipeline: Optional[Any] = None,
    policy_engine: Optional[Any] = None,
) -> FastAPI:
    """
    Build and return the configured FastAPI application.
    Dependencies are injected to maintain architecture boundaries.
    """
    app_env = os.getenv("APP_ENV", "dev").lower().strip()

    # Fix 5: Disable OpenAPI/docs in production
    if app_env in ("dev", "test"):
        application = FastAPI(title="Secure RAG Platform API", version="2.0.0")
    else:
        application = FastAPI(
            title="Secure RAG Platform API",
            version="2.0.0",
            docs_url=None,
            redoc_url=None,
            openapi_url=None,
        )

    # Restrict CORS outside explicit configuration (fail closed for browser abuse).
    cors_raw = os.getenv("CORS_ORIGINS", "").strip()
    if cors_raw:
        allow_origins = [o.strip() for o in cors_raw.split(",") if o.strip()]
    elif app_env in ("dev", "test"):
        allow_origins = ["http://127.0.0.1:8501", "http://localhost:8501"]
    else:
        allow_origins = []

    application.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # Security hardening middlewares (evaluated inside-out: size → headers → CORS)
    application.add_middleware(SecurityHeadersMiddleware)
    application.add_middleware(RequestSizeLimitMiddleware)

    # Global exception handler — never leak internal error details
    @application.exception_handler(Exception)
    async def _global_exception_handler(request: Request, exc: Exception):
        return JSONResponse(
            {"error": "An internal error occurred. Please try again later."},
            status_code=500,
        )

    # Store injected dependencies on the app state
    application.state.auth_service = auth_service
    application.state.pipeline = pipeline_orchestrator
    application.state.ingestion = ingestion_pipeline
    application.state.policy_engine = policy_engine

    # ── Auth Endpoints ──────────────────────────────────────────────────

    @application.post("/auth/login")
    async def login(data: LoginRequest, request: Request):
        auth = application.state.auth_service
        if not auth:
            return JSONResponse({"error": "Service unavailable"}, status_code=503)

        client_ip = request.client.host if request.client else "127.0.0.1"
        try:
            raw_token, session = auth.login(
                email=data.email,
                password=data.password,
                client_ip=client_ip,
            )
            return {
                "token": raw_token,
                "role": session.role_name,
                "email": session.email,
            }
        except RateLimitExceededError:
            return JSONResponse(
                {"error": "Too many failed attempts. Please try again later."},
                status_code=429,
            )
        except AuthenticationError:
            return JSONResponse(
                {"error": "Invalid email or password."},
                status_code=401,
            )

    @application.post("/auth/logout")
    async def logout(request: Request):
        auth = application.state.auth_service
        if not auth:
            return JSONResponse({"error": "Service unavailable"}, status_code=503)

        token = _extract_bearer_token(request)
        if not token:
            return JSONResponse({"error": "Missing token"}, status_code=401)

        success = auth.logout(token)
        return {"logged_out": success}

    # ── Chat Endpoint ───────────────────────────────────────────────────

    @application.post("/chat")
    async def chat(data: ChatRequest, request: Request):
        auth = application.state.auth_service
        pipe = application.state.pipeline
        if not auth or not pipe:
            return JSONResponse({"error": "Service unavailable"}, status_code=503)

        token = _extract_bearer_token(request)
        if not token:
            return JSONResponse({"error": "Authentication required."}, status_code=401)

        try:
            session = auth.validate_session(token)
        except RateLimitExceededError:
            return JSONResponse(
                {"error": "Too many requests. Please try again later."},
                status_code=429,
            )
        except AuthenticationError:
            return JSONResponse({"error": "Invalid or expired session."}, status_code=401)

        # Fix 10: Strip whitespace and reject null bytes in question
        clean_question = data.question.strip()
        if not clean_question or "\x00" in clean_question:
            return JSONResponse(
                {"error": "Invalid question content."},
                status_code=422,
            )

        # Per-user chat rate limiting
        rate_key = f"chat:{session.user_id}"
        if _chat_limiter.is_limited(rate_key):
            return JSONResponse(
                {"error": "Too many requests. Please slow down."},
                status_code=429,
            )

        history_payload = []
        for turn in (data.history or [])[-6:]:
            role = (turn.role or "").strip().lower()
            if role not in ("user", "assistant"):
                continue
            content = (turn.content or "").strip()
            if not content or "\x00" in content:
                continue
            history_payload.append({"role": role, "content": content[:500]})

        try:
            result = pipe.execute(
                question=clean_question,
                user_id=session.user_id,
                user_role=session.role_name,
                allowed_access_levels=session.allowed_access_levels,
                user_email=getattr(session, "email", None),
                history=history_payload,
            )
        except Exception as e:
            logger.exception("Pipeline chat failed: %s", type(e).__name__)
            return JSONResponse(
                {"error": "An internal error occurred. Please try again later."},
                status_code=500,
            )

        return {
            "answer": result.answer,
            "decision": result.decision.value,
            "reason_code": result.reason_code.value,
            "request_id": result.request_id,
        }

    @application.post("/chat/stream")
    async def chat_stream(data: ChatRequest, request: Request):
        auth = application.state.auth_service
        pipe = application.state.pipeline
        if not auth or not pipe:
            return JSONResponse({"error": "Service unavailable"}, status_code=503)

        token = _extract_bearer_token(request)
        if not token:
            return JSONResponse({"error": "Authentication required."}, status_code=401)

        try:
            session = auth.validate_session(token)
        except RateLimitExceededError:
            return JSONResponse(
                {"error": "Too many requests. Please try again later."},
                status_code=429,
            )
        except AuthenticationError:
            return JSONResponse({"error": "Invalid or expired session."}, status_code=401)

        clean_question = data.question.strip()
        if not clean_question or "\x00" in clean_question:
            return JSONResponse(
                {"error": "Invalid question content."},
                status_code=422,
            )

        rate_key = f"chat:{session.user_id}"
        if _chat_limiter.is_limited(rate_key):
            return JSONResponse(
                {"error": "Too many requests. Please slow down."},
                status_code=429,
            )

        history_payload = []
        for turn in (data.history or [])[-6:]:
            role = (turn.role or "").strip().lower()
            if role not in ("user", "assistant"):
                continue
            content = (turn.content or "").strip()
            if not content or "\x00" in content:
                continue
            history_payload.append({"role": role, "content": content[:500]})

        def event_stream():
            try:
                for evt in pipe.execute_stream(
                    question=clean_question,
                    user_id=session.user_id,
                    user_role=session.role_name,
                    allowed_access_levels=session.allowed_access_levels,
                    user_email=getattr(session, "email", None),
                    history=history_payload,
                ):
                    yield f"data: {json.dumps(evt)}\n\n"
            except Exception as exc:
                logger.exception("Pipeline streaming failed: %s", type(exc).__name__)
                yield f"data: {json.dumps({'event': 'error', 'data': 'An internal error occurred. Please try again later.'})}\n\n"

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )


    # ── Upload Endpoint ─────────────────────────────────────────────────

    @application.post("/upload")
    async def upload(
        request: Request,
        file: UploadFile = File(...),
        access_level: str = Form("employee"),
    ):
        auth = application.state.auth_service
        ingestion = application.state.ingestion
        if not auth or not ingestion:
            return JSONResponse({"error": "Service unavailable"}, status_code=503)

        token = _extract_bearer_token(request)
        if not token:
            return JSONResponse({"error": "Authentication required."}, status_code=401)

        try:
            session = auth.validate_session(token)
        except RateLimitExceededError:
            return JSONResponse(
                {"error": "Too many requests. Please try again later."},
                status_code=429,
            )
        except AuthenticationError:
            return JSONResponse({"error": "Invalid or expired session."}, status_code=401)

        # Per-user upload rate limiting
        rate_key = f"upload:{session.user_id}"
        if _upload_limiter.is_limited(rate_key):
            return JSONResponse(
                {"error": "Too many upload requests. Please slow down."},
                status_code=429,
            )

        if not can_ingest(session.role_name):
            return JSONResponse(
                {"error": "You do not have permission to upload documents."},
                status_code=403,
            )

        requested_level = (access_level or "employee").lower().strip()
        permitted = {
            lvl.lower()
            for lvl in ROLE_ACCESS_MAPPING.get(session.role_name.lower().strip(), [])
        }
        if requested_level not in permitted:
            return JSONResponse(
                {"error": "Selected access level is not permitted for your role."},
                status_code=403,
            )

        # Stream upload in chunks — Content-Length may be omitted/spoofed.
        max_upload_mb = getattr(DEFAULT_CONFIG, "max_upload_mb", 10) or 10
        max_bytes = min(int(max_upload_mb) * 1024 * 1024, _HARD_MAX_UPLOAD_BYTES)
        if max_bytes <= 0:
            max_bytes = _HARD_MAX_UPLOAD_BYTES

        try:
            buffer = bytearray()
            while True:
                chunk = await file.read(_UPLOAD_CHUNK_SIZE)
                if not chunk:
                    break
                if len(buffer) + len(chunk) > max_bytes:
                    return JSONResponse(
                        {"error": "Uploaded file exceeds the maximum allowed size."},
                        status_code=413,
                    )
                buffer.extend(chunk)
            file_bytes = bytes(buffer)
            result = ingestion.ingest_file(
                file_bytes=file_bytes,
                filename=file.filename or "upload.bin",
                access_level=requested_level,
                uploader_role=session.role_name,
                user_id=session.user_id,
            )
            # Invalidate semantic cache so stale responses are cleared
            pipeline = getattr(application.state, "pipeline", None)
            if pipeline and hasattr(pipeline, "cache") and pipeline.cache:
                pipeline.cache.clear()

            # Avoid status overwrite if ingest result already includes "status"
            return {"ok": True, "document": result}
        except AuthorizationError:
            return JSONResponse(
                {"error": "You do not have permission to upload documents."},
                status_code=403,
            )
        except DuplicateDocumentError:
            return JSONResponse(
                {"error": "Document already exists or conflicts with an existing record."},
                status_code=409,
            )
        except DocumentValidationError as e:
            return JSONResponse({"error": str(e)}, status_code=422)
        except (VectorStoreError, DatabaseError):
            return JSONResponse(
                {"error": "Document processing failed. Please try again."},
                status_code=500,
            )

    # ── Audit Endpoint ──────────────────────────────────────────────────

    @application.get("/audit")
    async def get_audit(request: Request):
        auth = application.state.auth_service
        if not auth:
            return JSONResponse({"error": "Service unavailable"}, status_code=503)

        token = _extract_bearer_token(request)
        if not token:
            return JSONResponse({"error": "Authentication required."}, status_code=401)

        try:
            session = auth.validate_session(token)
        except RateLimitExceededError:
            return JSONResponse(
                {"error": "Too many requests. Please try again later."},
                status_code=429,
            )
        except AuthenticationError:
            return JSONResponse({"error": "Invalid or expired session."}, status_code=401)

        policy = application.state.policy_engine
        can_view_audit = False
        if policy is not None and hasattr(policy, "role_allows"):
            can_view_audit = bool(
                policy.role_allows(session.role_name, "can_view_audit_dashboard")
            )
        else:
            # Fail closed to admin-only when policy is not injected.
            can_view_audit = session.role_name.lower().strip() == "admin"
        if not can_view_audit:
            return JSONResponse(
                {"error": "Access denied. Audit dashboard permission required."},
                status_code=403,
            )

        # Access the repo through auth_service
        logs = auth.repo.get_audit_logs(limit=100)
        return {"audit_logs": logs, "count": len(logs)}

    # ── Health Check ────────────────────────────────────────────────────

    @application.get("/health")
    async def health():
        return {
            "status": "online",
            "version": "2.0.0",
            "llm_provider": os.getenv("LLM_PROVIDER", "ollama").lower().strip(),
        }

    return application
