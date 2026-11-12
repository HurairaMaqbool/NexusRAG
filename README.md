<div align="center">

# ✦ Nexus AI Engine — Secure RAG Platform

**An industry-secure, multi-role Retrieval-Augmented Generation platform with 7 layered security controls, RBAC, append-only audit logging, and a pluggable LLM backend.**

Combines ChromaDB dense semantic search with BM25 sparse matching, pre-filtered by role-based access levels. Enforces input guard, document scanner, centralized policy engine, canary token output guard, and immutable audit trails across every request.

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-Frontend-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-Filtered_Vectors-0057B7?style=for-the-badge)](https://www.trychroma.com/)
[![SQLite](https://img.shields.io/badge/SQLite-Authoritative_RBAC-003B57?style=for-the-badge)](https://sqlite.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

[📧 Contact](mailto:hurairac37@gmail.com) · [💼 Fiverr Profile](https://www.fiverr.com/huraira_maqbool) · [🔗 LinkedIn](https://www.linkedin.com/in/huraira-maqbool-b696a5277/)

</div>

---

## 🌟 Overview

**Nexus Secure RAG** upgrades the original research agent into a **risk-aware Secure RAG Platform**: authorize before retrieve, score document risk, decide ALLOW / REVIEW / BLOCK, generate with delimited prompts + canary tokens, then validate and audit every response.

### Why this platform?
- **7 Security Controls**: Auth/RBAC → Input Guard → Pre-filtered Retrieval → Document Scanner → Policy Engine → Output Guard → Append-only Audit
- **Deny-by-default RBAC**: Employee / HR / Admin with SQLite as the authority; ChromaDB metadata filter-before-search; SQLite re-validation of every hit
- **Hybrid Retrieval**: ChromaDB dense search + BM25 sparse search fused with Reciprocal Rank Fusion (no unauthorized chunks reach the LLM)
- **LLM Privacy Gate (D1)**: Local Ollama by default; Groq optional and never receives HR/restricted chunks
- **Thin Clients**: FastAPI is the only pipeline engine; Streamlit is an authenticated HTTP UI (no local RAG state)

---

## 📁 Repository Structure

```
nexys/
├── main.py                           # Thin FastAPI entry point (loads bootstrap)
├── app.py                            # Streamlit thin client UI (HTTP only)
├── pyproject.toml                    # Package metadata & pytest config
├── requirements.txt                  # Pinned production dependencies (==)
├── requirements-dev.txt              # Dev / test extras (pytest)
├── .env.example                      # Environment variable template
├── config/
│   ├── policy.yaml                   # Risk thresholds and role permissions
│   ├── injection_rules.yaml          # Regex / keyword scanner signatures
│   └── logging.yaml                  # Structured logging configuration
├── data/
│   ├── nexus.db                      # Authoritative SQLite database (runtime)
│   ├── chroma/                       # Persistent ChromaDB vector storage (runtime)
│   ├── raw/
│   │   ├── employee/                 # General employee documents
│   │   ├── hr/                       # Restricted HR / payroll documents
│   │   └── poisoned/                 # Indirect prompt-injection test docs
│   └── test_cases/                   # Benchmark attack & benign query sets
├── src/secure_rag/
│   ├── __init__.py                   # Package root (version + module docstring)
│   ├── bootstrap.py                  # DI factory: builds (app, config) from env
│   ├── pipeline.py                   # Master 7-control security orchestrator
│   ├── core/
│   │   ├── config.py                 # Immutable AppConfig dataclass from env
│   │   └── errors.py                 # Domain exception taxonomy
│   ├── db/
│   │   ├── constants.py              # SCHEMA_VERSION
│   │   ├── connection.py             # Thread-safe SQLite connection factory
│   │   ├── schema.sql                # Authoritative DDL (roles, users, audit, …)
│   │   └── repository.py             # DAO with ACID guarantees
│   ├── auth/
│   │   ├── constants.py              # ROLE_ACCESS_MAPPING, password limits, bcrypt
│   │   ├── security.py               # Password hashing & token creation
│   │   └── service.py                # Login, session validation, RBAC
│   ├── ingestion/
│   │   ├── parsers.py                # In-memory PDF/DOCX/TXT with zip-bomb defense
│   │   ├── chunker.py                # Boundary-aware sentence chunker
│   │   └── pipeline.py               # Parse → tag → SQLite → ChromaDB
│   ├── retrieval/
│   │   ├── embeddings.py             # SentenceTransformer + FakeEmbedder
│   │   ├── vector_store.py           # ChromaDB client (metadata pre-filter)
│   │   ├── keyword_search.py         # Filtered BM25 lexical engine
│   │   ├── hybrid_engine.py          # RRF rank fusion combiner
│   │   ├── memory_index.py           # ← shim → agent/_legacy (backward compat)
│   │   └── hybrid_memory.py          # ← shim → agent/_legacy (backward compat)
│   ├── routing/
│   │   ├── __init__.py               # Shared intent detection
│   │   └── intent.py                 # calculator / web_search / pdf_rag classifier
│   ├── security/
│   │   ├── input_guard.py            # Direct injection & syntax validation
│   │   ├── scanner.py                # Rule-based indirect injection detector
│   │   ├── models.py                 # DecisionOutcome, ReasonCode enums
│   │   ├── policy_engine.py          # ALLOW / REVIEW / BLOCK risk adjudicator
│   │   ├── prompt_builder.py         # System/Context/User delimiters + canary
│   │   └── output_guard.py           # Canary detector & sensitive-data sanitizer
│   ├── llm/
│   │   ├── base.py                   # BaseLLMProvider abstract contract
│   │   ├── factory.py                # Provider factory (ollama / groq / mock)
│   │   ├── ollama_provider.py        # Local Ollama client (default)
│   │   ├── groq_provider.py          # Groq cloud fallback chain (optional)
│   │   └── prompts.py                # Legacy prompt helpers (agent path only)
│   ├── tools/
│   │   ├── calculator.py             # AST-safe deterministic math evaluator
│   │   └── web_search.py             # Policy-governed DuckDuckGo client
│   ├── audit/
│   │   └── service.py                # Append-only SQLite audit log writer
│   ├── api/
│   │   └── app.py                    # FastAPI application factory + routes
│   └── agent/
│       ├── __init__.py               # Lazy RAGSystem import; re-exports detect_intent
│       ├── intent.py                 # ← shim → routing/intent (backward compat)
│       ├── documents.py              # Document parsing helpers (legacy agent)
│       ├── rag_system.py             # DEPRECATED legacy unsecured RAGSystem
│       └── _legacy/
│           ├── memory_index.py       # NumpyFlatL2 in-memory vector index
│           └── hybrid_memory.py      # In-memory hybrid dense+sparse store
├── tests/
│   ├── conftest.py                   # Shared fixtures (temp DB, repo)
│   ├── qa_test_suite.py              # Procedural regression suite
│   ├── unit/                         # Fast deterministic unit tests
│   ├── integration/                  # Component interaction tests
│   └── security/                     # Adversarial RBAC & injection tests
└── docs/
    └── ARCHITECTURE.md               # Binding architecture specification (D1–D18)
```

---

## ⚡ Quick Start

### 1. Clone & Set Up

```bash
git clone <repo-url>
cd nexys
python -m venv .venv

# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

# Linux / macOS
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env — set SECRET_KEY, DEMO_PASSWORD_*, LLM_PROVIDER (ollama|groq|mock)
```

### 3. Launch the Application

**Terminal 1 — FastAPI backend:**
```bash
python main.py
# → http://127.0.0.1:8000  (API)
# → http://127.0.0.1:8000/docs  (Swagger, dev only)
```

**Terminal 2 — Streamlit frontend:**
```bash
streamlit run app.py
# → http://localhost:8501
```

### 4. Run Tests

```bash
# Full pytest suite
pytest tests -q

# Legacy QA regression suite
python tests/qa_test_suite.py
```

---

## 🔒 7 Security Controls

| # | Control | Module | Enforcement |
|---|---------|--------|-------------|
| 1 | **Auth & RBAC** | `auth/service.py` | Server-side sessions, bcrypt, deny-by-default roles |
| 2 | **Input Guard** | `security/input_guard.py` | Delimiter injection, command phrase, length checks |
| 3 | **Pre-filtered Retrieval** | `retrieval/vector_store.py` + `keyword_search.py` | ChromaDB `where` clause + BM25 corpus filtering |
| 4 | **Document Scanner** | `security/scanner.py` | Regex + structural heuristic risk scoring |
| 5 | **Policy Engine** | `security/policy_engine.py` | ALLOW / REVIEW / BLOCK with risk thresholds |
| 6 | **Output Guard** | `security/output_guard.py` | Canary token + regex leak detection |
| 7 | **Audit Logging** | `audit/service.py` | Append-only SQLite with immutability triggers |

---

## 👥 RBAC Matrix

| Role | Document Access | Calculator | Web Search | Audit Dashboard |
|------|----------------|------------|------------|-----------------|
| **Employee** | `employee` only | ✅ | ❌ | ❌ |
| **HR** | `employee` + `hr` | ✅ | ✅ | ❌ |
| **Admin** | None (no doc retrieval) | ❌ | ❌ | ✅ |

---

## 📡 REST API

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/auth/login` | — | Authenticate, receive session token |
| `POST` | `/auth/logout` | Bearer | Revoke session |
| `POST` | `/chat` | Bearer | Query the secure pipeline |
| `POST` | `/upload` | Bearer (HR) | Ingest document (PDF/DOCX/TXT) |
| `GET`  | `/audit` | Bearer (Admin) | View audit logs |
| `GET`  | `/health` | — | Server status check |

---

## ⚙️ Configuration

Key environment variables (see `.env.example` for full list):

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `dev` | Environment mode (`dev` / `test` / `prod`) |
| `LLM_PROVIDER` | `ollama` | LLM backend (`ollama` / `groq` / `mock`) |
| `SECRET_KEY` | — | Session signing key (≥32 chars in prod) |
| `EMBEDDING_FAKE` | `0` | Use FakeEmbedder for fast CI/tests |
| `ENABLE_WEB_SEARCH` | `false` | Enable DuckDuckGo web search tool |
| `DEMO_FORCE_RESEED` | `0` | Delete DB + re-seed demo accounts on boot |

---

## 🧪 Testing

- **`tests/unit/`** — Fast deterministic tests (calculator, chunker, scanner, auth, DB, boundaries, …)
- **`tests/security/`** — Adversarial RBAC bypass and injection pipeline tests
- **`tests/integration/`** — Component interaction tests
- **`tests/qa_test_suite.py`** — Full procedural QA regression suite (legacy agent path)

---

## 🤝 Contributing

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Run `pytest` and `python tests/qa_test_suite.py` to verify
4. Commit (`git commit -m 'feat: Add AmazingFeature'`)
5. Push and open a Pull Request

---

## 👤 Author

**Huraira Maqbool** — *AI Engineer & RAG Specialist*

- 📧 [hurairac37@gmail.com](mailto:hurairac37@gmail.com)
- 💼 [Fiverr](https://www.fiverr.com/huraira_maqbool)
- 🔗 [LinkedIn](https://www.linkedin.com/in/huraira-maqbool-b696a5277/)

---

<div align="center">
  <sub>Built with ❤️ using FastAPI, ChromaDB, SQLite, and Streamlit.</sub>
</div>
