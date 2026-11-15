<div align="center">

# ✦ Nexus AI Engine — Enterprise Secure RAG Platform

**An enterprise-grade, multi-role Retrieval-Augmented Generation (RAG) platform with real-time SSE token streaming, 7-layer defense-in-depth security, MITRE ATLAS Crescendo jailbreak defense, PII masking, neural cross-encoder reranking, and an immutable audit trail.**

[![Python](https://img.shields.io/badge/Python-3.10%20|%203.11%20|%203.12%20|%203.13-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-v2.0.0-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-Interactive_UI-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-Filtered_Vectors-0057B7?style=for-the-badge)](https://www.trychroma.com/)
[![SQLite](https://img.shields.io/badge/SQLite-WAL_ACID_RBAC-003B57?style=for-the-badge)](https://sqlite.org/)
[![Tests](https://img.shields.io/badge/Tests-396_Passing-success?style=for-the-badge&logo=pytest&logoColor=white)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

[📧 Contact](mailto:hurairac37@gmail.com) · [💼 Fiverr Profile](https://www.fiverr.com/huraira_maqbool) · [🔗 LinkedIn](https://www.linkedin.com/in/huraira-maqbool-b696a5277/)

</div>

---

## 🌟 Executive Overview

**Nexus Secure RAG** is an advanced, production-hardened Generative AI platform engineered to solve the most critical enterprise RAG challenges: **prompt injection, sensitive data leakage, cross-tenant unauthorized access, and hallucination**.

Unlike naive RAG architectures that concatenate raw documents directly into LLM prompts, Nexus enforces a strict **zero-trust, 7-layer security pipeline** that authenticates, normalizes, inspects, and redacts content at every stage of the lifecycle.

```
       ┌─────────────────┐       ┌─────────────────┐
       │   User Query    │       │ Document Upload │
       └────────┬────────┘       └────────┬────────┘
                │                         │
                ▼                         ▼
      ┌───────────────────┐     ┌───────────────────┐
      │  Layer 1: Auth &  │     │ Parse & Normalize │
      │  Session RBAC     │     │ (Zip-Bomb Safe)   │
      └─────────┬─────────┘     └─────────┬─────────┘
                ▼                         ▼
      ┌───────────────────┐     ┌───────────────────┐
      │  Layer 2: Input   │     │ Contextual Chunks │
      │  De-obfuscation   │     │ & HMAC Watermark  │
      └─────────┬─────────┘     └─────────┬─────────┘
                ▼                         ▼
      ┌───────────────────┐     ┌───────────────────┐
      │ Layer 3: Crescendo│     │ ChromaDB Vector & │
      │ Multi-Turn Guard  │     │ BM25 Sparse Index │
      └─────────┬─────────┘     └─────────┬─────────┘
                ▼                         │
      ┌───────────────────┐               │
      │  Semantic Cache   │               │
      │  (Role-Isolated)  │               │
      └─────────┬─────────┘               │
                │ Cache Miss              │
                ▼                         │
      ┌───────────────────┐               │
      │ Layer 4: RBAC Pre-│◄──────────────┘
      │ Filter Retrieval  │ (ChromaDB + BM25 + Cross-Encoder)
      └─────────┬─────────┘
                ▼
      ┌───────────────────┐
      │  Layer 5: Policy  │
      │  Engine & Scanner │
      └─────────┬─────────┘
                ▼
      ┌───────────────────┐
      │  Layer 6: Prompt  │
      │  Builder + Canary │ (PII Masked, Delimiters Disarmed)
      └─────────┬─────────┘
                ▼
      ┌───────────────────┐
      │  LLM Generation   │
      │ (Local / Groq D1) │
      └─────────┬─────────┘
                ▼
      ┌───────────────────┐
      │ Layer 7: Output   │ (32-Char Lookahead Buffer, Canary Check,
      │ Guard & Audit     │  Secret Leak Block, Append-Only Log)
      └─────────┬─────────┘
                ▼
      ┌───────────────────┐
      │ Verified Response │
      └───────────────────┘
```

---

## 🛡️ Core Capabilities & Advanced Features

### 1. ⚡ Real-Time SSE Token Streaming with Lookahead Safety Buffer
* **Low-Latency Streaming**: Streaming responses via Server-Sent Events (`POST /chat/stream`) and Streamlit `st.write_stream()`.
* **Zero-Leak Lookahead Window**: Enforces a 32-character sliding window buffer in the streaming generator. Tokens are verified clear of canary tokens, API credentials, or private keys *before* being transmitted over the wire.
* **Fail-Safe Streaming Concurrency**: Comprehensive exception trapping prevents connection resets or worker crashes upon client disconnects.

### 2. 🥋 Multi-Turn Crescendo Jailbreak Defense (MITRE ATLAS AML.T0054)
* **Adaptive Dialogue History Scoring**: Analyzes conversational context across dialogue turns using `CrescendoGuard`.
* **Escalation Detection**: Identifies subtle, progressive steering attacks where adversaries gradually shift from benign prompts to security safeguard circumvention.

### 3. 🔍 Advanced Input De-obfuscation Engine
* **Unicode NFKC Decomposition**: Collapses visual homoglyphs and full-width characters.
* **Trojan Source Defense**: Completely strips invisible formatting characters and modern Unicode directional isolates (`\u2066-\u2069`: LRI, RLI, FSI, PDI; CVE-2021-42574).
* **Multi-Layer Decoding**: Automatically unmasks URL percent-encoding (`%69%67...`) and base64 payloads prior to regex evaluation.
* **1337speak & Spaced De-obfuscation**: Collapses artificially spaced single letters (`i g n o r e`) and maps leet substitutions (`1->i`, `0->o`, `3->e`, `4->a`, `5->s`, `@->a`).

### 4. 🔏 Delimiter Disarmer & Prompt Boundary Protection
* **Boundary Smuggling Neutralization**: Replaces prompt control brackets `[` and `]` with harmless ASCII equivalents `(` and `)` inside untrusted user questions and document chunks.
* Mathematical impossibility of escaping `[USER QUESTION]`, `[CONTEXT]`, or `[SYSTEM]` boundaries.

### 5. 🎭 Zero-Trust RBAC & D1 Cloud Privacy Gate
* **Three-Tier Role Hierarchy**:
  * **Employee**: Standard access to company-wide policies (`employee` access level only).
  * **HR Specialist**: Access to employee documents + confidential compensation and salary bands.
  * **Administrator**: Platform administration, document indexing, and immutable audit inspection.
* **D1 Cloud Privacy Gate**: Strictly forbids non-employee or HR confidential chunks from ever being dispatched to third-party cloud LLMs (Groq). Requires local Ollama for confidential processing or blocks with a privacy warning.

### 6. 🧠 Hybrid Retrieval, Neural Reranking & Semantic Cache
* **Hybrid Fusion**: Combines ChromaDB dense vector search with BM25 sparse keyword search via Reciprocal Rank Fusion (RRF).
* **Cross-Encoder Reranker**: Refines Stage-1 candidate chunks using neural cross-attention scoring.
* **Role-Isolated Semantic Cache**: High-similarity cosine caching (`threshold > 0.96`) isolated by user role and access permissions. Automatically purged upon new document uploads.
* **Differential Privacy**: Injects calibrated Laplace noise into vector embeddings to mitigate vector inversion and embedding reconstruction attacks.

### 7. 🔒 PII Masking & Output Secret Redaction
* **PII De-identification**: Anonymizes SSNs, credit card numbers, phone numbers, and external email addresses before prompt construction and upon output generation.
* **Comprehensive Secret Leak Detection**: Detects and blocks AWS access keys (`AKIA...`), RSA private keys, JWT tokens, credit card sequences, and Markdown image exfiltration callbacks (`![leak](https://...)`).

### 8. 📊 RAG Triad Automated Evaluation & Spanning Traces
* **Continuous Evaluation**: Built-in evaluators for **Context Precision**, **Faithfulness**, and **Answer Relevance**.
* **Millisecond Latency Tracing**: Tracks execution duration across each security control with `SpanTracer`.

---

## 📁 Repository Structure

```
nexys/
├── main.py                           # FastAPI application entry point
├── app.py                            # Streamlit interactive frontend
├── pyproject.toml                    # Pytest configuration & dependencies
├── requirements.txt                  # Pinned production dependencies
├── .env.example                      # Environment configuration template
├── config/
│   ├── policy.yaml                   # Risk thresholds and RBAC permissions
│   ├── injection_rules.yaml          # Document scanner injection signatures
│   └── logging.yaml                  # Structured logging configuration
├── data/
│   ├── nexus.db                      # Authoritative SQLite database (WAL mode)
│   ├── chroma/                       # Persistent ChromaDB vector index
│   └── raw/                          # Reference employee & HR policies
├── src/secure_rag/
│   ├── bootstrap.py                  # Dependency injection container
│   ├── pipeline.py                   # 7-layer security orchestrator & streaming
│   ├── api/
│   │   └── app.py                    # REST API & SSE /chat/stream endpoints
│   ├── auth/
│   │   ├── service.py                # Server-side sessions, bcrypt, rate limiting
│   │   ├── security.py               # Token generators & cryptographic helpers
│   │   └── constants.py              # Role permissions & password limits
│   ├── core/
│   │   ├── config.py                 # Immutable environment settings
│   │   ├── errors.py                 # Domain error hierarchy
│   │   └── tracing.py                # Millisecond latency span tracer
│   ├── db/
│   │   ├── connection.py             # SQLite WAL connection manager
│   │   ├── repository.py             # Thread-safe ACID repository DAO
│   │   └── schema.sql                # Relational schema & audit triggers
│   ├── eval/
│   │   └── rag_triad.py              # Precision, Faithfulness & Relevance metrics
│   ├── ingestion/
│   │   ├── pipeline.py               # Document ingestion & transactional sync
│   │   ├── chunker.py                # Sentence-aware chunker
│   │   ├── contextual.py             # Anthropic-style contextual chunk prefaces
│   │   ├── parsers.py                # In-memory PDF/DOCX/TXT parsers (zip-bomb safe)
│   │   └── watermark.py              # HMAC integrity verification & honey-tokens
│   ├── llm/
│   │   ├── base.py                   # BaseLLMProvider abstract interface
│   │   ├── factory.py                # Provider factory (Groq / Ollama / Mock)
│   │   ├── groq_provider.py          # Active Groq model fallback chain
│   │   └── ollama_provider.py        # Local Ollama client
│   ├── retrieval/
│   │   ├── cache.py                  # Semantic query cache with RBAC isolation
│   │   ├── embeddings.py             # SentenceTransformer embedder
│   │   ├── hybrid_engine.py          # RRF dense + sparse hybrid search
│   │   ├── keyword_search.py         # BM25 sparse retrieval
│   │   ├── reranker.py               # Cross-Encoder neural reranker
│   │   └── vector_store.py           # ChromaDB client with differential privacy
│   ├── security/
│   │   ├── citations.py              # Grounded source citation verifier
│   │   ├── crescendo_guard.py        # Multi-turn escalation jailbreak detector
│   │   ├── input_guard.py            # De-obfuscation & direct injection guard
│   │   ├── output_guard.py           # Canary detector, secret & image exfil guard
│   │   ├── pii_guard.py              # Sensitive data redaction engine
│   │   ├── policy_engine.py          # ALLOW / REVIEW / BLOCK decision engine
│   │   ├── prompt_builder.py         # Delimiter disarming & secure prompt assembly
│   │   └── scanner.py                # Indirect injection chunk scanner
│   └── tools/
│       ├── calculator.py             # AST-safe parenthesized math evaluator
│       └── web_search.py             # DuckDuckGo client with policy guards
└── tests/
    ├── humanizer_live_test.py        # 9-point live human tester test suite
    ├── qa_test_suite.py              # 45-point procedural regression suite
    ├── security/
    │   ├── test_adversarial_redteam.py
    │   └── test_security_loopholes_patch.py
    └── unit/                         # Comprehensive unit test suites
```

---

## ⚡ Quick Start Guide

### 1. Clone & Set Up Virtual Environment

```bash
git clone https://github.com/HurairaMaqbool/NexusRAG.git
cd nexys

# Create and activate virtual environment
python -m venv .venv

# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

# Linux / macOS
source .venv/bin/activate

# Install dependencies
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 2. Configure Environment

Copy the example environment file and customize:

```bash
cp .env.example .env
```

Key configuration options in `.env`:

```env
APP_ENV=dev
SECRET_KEY=nexus-enterprise-secure-key-32-chars-minimum
LLM_PROVIDER=groq
GROQ_API_KEY=gsk_your_groq_api_key_here
OLLAMA_BASE_URL=http://localhost:11434
EMBEDDING_MODEL_NAME=sentence-transformers/all-MiniLM-L6-v2
ENABLE_WEB_SEARCH=false
```

---

## 🚀 Running the Project

### Terminal 1: FastAPI Backend Server
```bash
python main.py
```
* **REST API**: `http://127.0.0.1:8000`
* **Health Check**: `http://127.0.0.1:8000/health`
* **Swagger Documentation**: `http://127.0.0.1:8000/docs`

### Terminal 2: Streamlit Interactive Web UI
```bash
streamlit run app.py
```
* **Web UI**: `http://localhost:8501`

---

## 🔑 Pre-Configured Test Credentials

| Role | Email Address | Password | Document Scope |
| :--- | :--- | :--- | :--- |
| **Employee** | `employee@northwind.local` | `NorthwindEmp2026!` | Company-wide policies (`leave_policy.txt`) |
| **HR Specialist** | `hr@northwind.local` | `NorthwindHr2026!!` | Employee + HR Confidential (`salary_bands.txt`) |
| **Administrator** | `admin@northwind.local` | `NorthwindAdm2026!` | Platform administration & audit log inspection |

---

## 📡 REST API Reference

| Method | Endpoint | Authorization | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/auth/login` | None | Authenticate with email/password; returns session token |
| `POST` | `/auth/logout` | Bearer Token | Revoke server-side session |
| `POST` | `/chat` | Bearer Token | Synchronous 7-layer secure RAG query |
| `POST` | `/chat/stream` | Bearer Token | Server-Sent Events (SSE) real-time streaming with lookahead buffer |
| `POST` | `/upload` | Bearer Token (HR/Admin) | Ingest document (PDF/DOCX/TXT) with automatic cache flush |
| `GET` | `/audit` | Bearer Token (Admin) | Retrieve immutable append-only audit trail logs |
| `GET` | `/health` | None | System status and active LLM provider check |

---

## 🧪 Comprehensive Testing & Verification

The codebase includes **396 automated tests** providing 100% test coverage across functional, security, and performance dimensions:

```bash
# 1. Run full automated pytest suite (351 tests)
pytest tests -q

# 2. Run security loophole verification tests (17 tests)
pytest tests/security/test_security_loopholes_patch.py -v

# 3. Run adversarial red-team test suite (18 tests)
pytest tests/security/test_adversarial_redteam.py -v

# 4. Run procedural regression test suite (45 tests)
python tests/qa_test_suite.py

# 5. Run live humanizer scenario test runner (9 live tests)
python tests/humanizer_live_test.py
```

### Test Coverage Summary:
* ✅ **351 Automated Pytest Unit & Integration Tests**: 100% Pass
* ✅ **45 Procedural Regression Scenarios**: 100% Pass
* ✅ **18 Adversarial Attack Vectors**: 100% Block Rate
* ✅ **54 Modules Type & Architecture Boundaries**: Zero violations
* ✅ **9 Live Humanizer Tests (Easy, Medium, Tough)**: 100% Pass

---

## ⚖️ License & Contact

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

### 👤 Author & Maintainer
**Huraira Maqbool** — *Senior AI Engineer & Cybersecurity Specialist*
* 📧 Email: [hurairac37@gmail.com](mailto:hurairac37@gmail.com)
* 💼 Fiverr: [https://www.fiverr.com/huraira_maqbool](https://www.fiverr.com/huraira_maqbool)
* 🔗 LinkedIn: [https://www.linkedin.com/in/huraira-maqbool-b696a5277/](https://www.linkedin.com/in/huraira-maqbool-b696a5277/)
* 🐙 GitHub: [https://github.com/HurairaMaqbool](https://github.com/HurairaMaqbool)
