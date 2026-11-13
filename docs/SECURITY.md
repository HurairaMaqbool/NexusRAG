# Security Policy & Threat Model — Nexus AI Secure RAG Platform

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it privately.
Do **not** open a public GitHub issue for security bugs.

Email: security@northwind.local (or your org's security contact)

## Architecture Overview

The Secure RAG Platform enforces a 7-control security pipeline on every request:

1. **Session Authentication** — Server-side sessions with SHA-256 hashed tokens; bcrypt password hashing with constant-work timing mitigation.
2. **Input Guard** — Regex-based direct prompt injection detection on user queries.
3. **Intent Routing** — Deterministic classification into calculator / web_search / document RAG.
4. **Document Scanner** — YAML-configurable regex scanner for indirect injection in retrieved chunks.
5. **Policy Engine** — Risk-threshold adjudication (ALLOW / REVIEW / BLOCK) with data-exfiltration rules (Decision D1: HR data never sent to cloud LLM). `role_permissions` from `config/policy.yaml` are enforced for calculator, web search, ingest, and audit dashboard capabilities (fail-closed).
6. **Output Guard** — Canary token leak detection, system prompt disclosure checks, sensitive data pattern matching (dashed SSN, API keys, credential leaks). Ordinary emails and bare 9-digit numbers are **not** blocked.
7. **Audit Trail** — Append-only SQLite audit logs with tamper-prevention triggers.

## RBAC Model

| Role     | Document Access        | Ingest | Audit Dashboard | Calculator | Web Search | General Q&A |
|----------|------------------------|--------|-----------------|------------|------------|-------------|
| Employee | employee-level only    | No     | No              | Yes        | No         | Yes         |
| HR       | employee + HR\*        | Yes    | No              | Yes        | Yes\*\*    | Yes         |
| Admin    | None (no company docs) | No     | Yes             | No (falls through to general Q&A) | No | Yes |

\*With `LLM_PROVIDER=groq`, HR-restricted chunk text is never sent to Groq (D1). The platform tries a local Ollama model when available; otherwise it returns a clear privacy-gate message (it does **not** invent HR salary facts from general knowledge).  
\*\*Web search also requires `ENABLE_WEB_SEARCH=true` (env). The `enable_web_search` key in `policy.yaml` is documentary only.

## Chatbot UX notes (dev)

- Empty retrieval falls back to **general knowledge** (not a hard “no documents” refusal).
- `/chat` accepts optional `history` (last few turns) for short conversational context.
- “Who am I?” is answered from the signed-in session email/role.
- Streamlit shows an HR tip when the active provider is Groq.

## Key Security Decisions

- **D1**: HR-classified and unknown-access chunks are NEVER sent to Groq. Cloud-safe levels are `employee`, `public`, and `web` (web-search snippets). Enforced by PolicyEngine.
- **D9**: Raw session tokens are never persisted — only SHA-256 hashes stored.
- **D10**: Every session validation re-checks user active status and role from the database.
- **D11**: Admin role has empty access level list — cannot retrieve documents.
- **D12**: Bcrypt with cost factor >= 12 in production; constant-work login (single bcrypt call in all branches).
- **D13**: Only HR can ingest/delete documents.
- **D14**: ChromaDB stores NO chunk text — only vector embeddings + access_level metadata.
- **D17**: Upload limits: 10 MB file, 100 pages, 500K chars, zip-bomb detection on DOCX. Upload handler streams chunks and enforces a size cap even when `Content-Length` is omitted.
- **Login throttling**: Failed logins are rate-limited by **both client IP and email** (in-memory sliding window); counters are not cleared on success.

## Production Hardening Requirements

Before deploying with `APP_ENV=prod`:

1. **SECRET_KEY**: Must be a cryptographically random string >= 32 characters. The startup validator will refuse insecure placeholders.
2. **DEMO_FORCE_RESEED**: Must be `0`. Startup refused if enabled in production.
3. **EMBEDDING_FAKE**: Must be `0`. Startup refused if enabled in production. If the real embedder fails to load in prod, the application will exit (no silent FakeEmbedder fallback).
4. **GROQ_API_KEY**: Rotate any key that was ever committed or shared. Use a secrets manager.
5. **CORS_ORIGINS**: Restrict to your production frontend domain(s).
6. **API_HOST**: Bind to `127.0.0.1` behind a reverse proxy; never `0.0.0.0` in production without firewall rules.
7. **SHOW_DEMO_CREDENTIALS**: Do not set to `1` in production.
8. **TLS/HTTPS**: Never expose the uvicorn HTTP server directly to the internet. Always deploy behind a TLS-terminating reverse proxy (nginx, Caddy, Traefik, etc.). The API server listens on HTTP `127.0.0.1:8000` by default — the reverse proxy handles external TLS traffic.
9. **OpenAPI Docs**: Swagger UI, ReDoc, and the OpenAPI JSON schema are automatically disabled when `APP_ENV` is not `dev` or `test`.

## Accepted Residual Risks

The following are known limitations accepted in the current design:

| Risk | Severity | Mitigation | Notes |
|------|----------|------------|-------|
| **Regex-based injection detection is bypassable** | Medium | Defense-in-depth with scanner + output guard + canary; not a single point of failure | Production should add ML-based detection layer |
| **In-memory rate limiting resets on restart** | Low | Acceptable for single-instance; use Redis for distributed deployments | Login rate limiting is per-IP and per-email; chat/upload per-user |
| **SQLite is single-writer** | Low | WAL mode mitigates; suitable for small-to-medium deployments | Migrate to PostgreSQL for high concurrency |
| **No CSRF protection on API** | Low | API uses Bearer token auth (not cookies); CORS restricts browser origins | Streamlit client uses `requests` (not browser JS) |
| **Session tokens stored in Streamlit session_state** | Medium | Tokens expire via idle sliding window (30 min) + absolute max (8 hr); revoked on logout; re-validated on every API call | In-browser state is inherent to Streamlit architecture |
| **Audit log query text truncated to 500 chars** | Low | Prevents storage abuse; full queries are not needed for audit purposes | |
| **BM25 index rebuilt per query** | Low | Performance concern, not security; acceptable for current scale | |
| **Legacy RAGSystem module exists** | Low | Gated: refuses instantiation when APP_ENV is not dev/test | Retained for offline QA test suite only |

## Previously Fixed Security Items

| Item | Fix |
|------|-----|
| Chat question DoS (unbounded length) | Pydantic `max_length=1000` on `ChatRequest.question`; `input_guard` hard-blocks queries > 1000 chars (risk=1.0) |
| Login field length abuse | `LoginRequest.email` max 320 chars, `password` max 72 bytes |
| Null-byte injection in chat | Chat endpoint strips whitespace and rejects `\x00` |
| Loopback IP rate-limit flooding | When `client_ip` is loopback (`127.0.0.1`, `::1`), only email-based rate limiting applies |
| No idle session timeout | Sliding idle window (`SESSION_TIMEOUT_MIN`) extended on each `validate_session`; absolute max enforced from `created_at` (`ABSOLUTE_SESSION_MAX_MIN=480`) |
| Calculator Pow DoS (`2**999999`) | Exponent capped at ±10; result magnitude capped at 1e12; AST depth capped at 20 |
| OpenAPI/Swagger exposed in prod | `docs_url`, `redoc_url`, `openapi_url` set to `None` when `APP_ENV` is not dev/test |
| Audit fail-open on ALLOW path | `_audit()` returns bool; ALLOW paths block the response if audit write fails |
| Duplicate document error leaks internals | Upload 409 now returns a generic message |
| Silent FakeEmbedder in prod | Embedder load failure in non-dev/test raises `SystemExit(1)` |
| No TLS guidance | `.env.example` and SECURITY.md document reverse-proxy TLS requirement |
