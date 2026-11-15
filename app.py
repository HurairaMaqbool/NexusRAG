"""
app.py — Streamlit Thin Client for Secure RAG Platform
Communicates with FastAPI backend via HTTP. Stores only session token in state.
No local RAG, no direct DB access — all logic lives on the backend.
"""

import json
import os

import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

API_BASE_URL = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")

st.set_page_config(
    page_title="Nexus AI | Secure RAG Platform",
    page_icon="✦",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Minimal Theme CSS ─────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Outfit:wght@400;600;800&display=swap');
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.stApp { background: #F8F9FF; color: #1A1A2E; }
#MainMenu {visibility: hidden;} footer {visibility: hidden;}
.hero-header {
    text-align: center; padding: 2rem 1rem; border-radius: 16px; margin-bottom: 1rem;
    background: linear-gradient(135deg, #6366F1 0%, #8B5CF6 50%, #EC4899 100%);
    box-shadow: 0 8px 32px rgba(99,102,241,0.2);
}
.hero-title { font-family:'Outfit'; font-size:2.2rem; font-weight:800; color:#FFF; }
.hero-subtitle { color:rgba(255,255,255,0.85); font-size:0.9rem; }
</style>
""", unsafe_allow_html=True)

# ─── Session State Init ────────────────────────────────────────────────────────
for key in ("token", "role", "email", "messages"):
    if key not in st.session_state:
        st.session_state[key] = [] if key == "messages" else None


def _safe_json(resp) -> dict:
    """Parse JSON body; return {} on any failure."""
    if resp is None:
        return {}
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _api(method: str, path: str, **kwargs) -> requests.Response | None:
    """Fire an HTTP request to the backend; return None on connection failure or timeout."""
    timeout = kwargs.pop("timeout", 20)
    try:
        return requests.request(method, f"{API_BASE_URL}{path}", timeout=timeout, **kwargs)
    except requests.Timeout:
        # Marker object so callers can distinguish timeout vs offline.
        resp = requests.Response()
        resp.status_code = 598
        resp._content = b'{"error":"Request timed out. Try again - large uploads can take a minute."}'
        return resp
    except requests.ConnectionError:
        return None
    except requests.RequestException as exc:
        resp = requests.Response()
        resp.status_code = 599
        resp._content = f'{{"error":"Request failed: {type(exc).__name__}"}}'.encode("utf-8")
        return resp


def _headers() -> dict:
    return {"Authorization": f"Bearer {st.session_state.token}"} if st.session_state.token else {}


# ─── Backend health check ──────────────────────────────────────────────────────
health = _api("GET", "/health")
backend_online = (
    health is not None
    and getattr(health, "status_code", None) == 200
)


# ─── Login Screen ──────────────────────────────────────────────────────────────
if not st.session_state.token:
    st.markdown("""
    <div class='hero-header'>
        <div class='hero-title'>✦ Nexus AI — Secure RAG Platform</div>
        <div class='hero-subtitle'>Role-Based Access · 7 Security Controls · Audit Trail</div>
    </div>
    """, unsafe_allow_html=True)

    if not backend_online:
        st.error("⚠️ Backend is offline. Start the FastAPI server first: `python main.py`")
        st.stop()

    st.subheader("🔐 Login")

    app_env = os.getenv("APP_ENV", "dev").lower()
    show_creds = os.getenv("SHOW_DEMO_CREDENTIALS", "0").strip().lower() in ("1", "true", "yes")
    if app_env == "dev" and show_creds:
        demo_emp = os.getenv("DEMO_PASSWORD_EMPLOYEE", "")
        demo_hr = os.getenv("DEMO_PASSWORD_HR", "")
        demo_admin = os.getenv("DEMO_PASSWORD_ADMIN", "")
        hint_lines = [
            "**DEV mode** — Demo accounts (passwords from `DEMO_PASSWORD_*` in `.env`):",
            f"- `employee@northwind.local` — `{demo_emp}`" if demo_emp else "- `employee@northwind.local` — set `DEMO_PASSWORD_EMPLOYEE` in `.env`",
            f"- `hr@northwind.local` — `{demo_hr}`" if demo_hr else "- `hr@northwind.local` — set `DEMO_PASSWORD_HR` in `.env`",
            f"- `admin@northwind.local` — `{demo_admin}`" if demo_admin else "- `admin@northwind.local` — set `DEMO_PASSWORD_ADMIN` in `.env`",
        ]
        st.info("\n".join(hint_lines))
    elif app_env == "dev":
        st.info("**DEV mode** — Demo accounts: `employee@`, `hr@`, `admin@` `northwind.local`. "
                "Set `SHOW_DEMO_CREDENTIALS=1` in `.env` to display passwords here.")

    with st.form("login_form"):
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")

    if submitted and email and password:
        resp = _api("POST", "/auth/login", json={"email": email, "password": password})
        if resp is None:
            st.error("Backend unreachable.")
        elif resp.status_code == 200:
            data = _safe_json(resp)
            st.session_state.token = data.get("token")
            st.session_state.role = data.get("role")
            st.session_state.email = data.get("email")
            st.rerun()
        elif resp.status_code == 429:
            st.error("Too many login attempts. Please wait and try again.")
        else:
            st.error("Invalid email or password.")
    st.stop()


# ─── Authenticated Interface ───────────────────────────────────────────────────

# Sidebar
with st.sidebar:
    st.markdown(f"**✦ Nexus AI** — Logged in as `{st.session_state.email}` ({st.session_state.role})")
    st.divider()

    if st.button("🚪 Logout"):
        _api("POST", "/auth/logout", headers=_headers())
        for key in ("token", "role", "email", "messages"):
            st.session_state[key] = [] if key == "messages" else None
        st.rerun()

    # Upload (HR only)
    if st.session_state.role and st.session_state.role.lower() == "hr":
        st.markdown("### 📄 Upload Document")
        uploaded_file = st.file_uploader("Choose a file", type=["pdf", "docx", "txt"])
        access_level = st.selectbox("Access Level", ["employee", "hr"])
        if st.button("⚡ Upload & Index") and uploaded_file:
            with st.spinner("Uploading & indexing (may take up to a minute)..."):
                resp = _api(
                    "POST", "/upload",
                    headers=_headers(),
                    files={"file": (uploaded_file.name, uploaded_file.getvalue())},
                    data={"access_level": access_level},
                    timeout=300,
                )
                if resp and resp.status_code == 200:
                    payload = _safe_json(resp)
                    document = payload.get("document") if isinstance(payload.get("document"), dict) else {}
                    title = document.get("title") or payload.get("title") or uploaded_file.name
                    status = document.get("status") or "indexed"
                    level = document.get("access_level") or access_level
                    chunks = document.get("chunks_count")
                    warn = document.get("warning")
                    msg = f"✅ {'Already indexed' if status == 'existing' else 'Indexed'}: {title} ({level}"
                    if chunks is not None:
                        msg += f", {chunks} chunks"
                    msg += ")"
                    st.success(msg)
                    if warn:
                        st.warning(warn)
                elif resp and resp.status_code == 598:
                    st.error(_safe_json(resp).get("error", "Upload timed out."))
                elif resp:
                    st.error(_safe_json(resp).get("error", "Upload failed."))
                else:
                    st.error(
                        f"Backend unreachable at {API_BASE_URL}. "
                        "Start the API with `python main.py`, then try again."
                    )

    # Audit viewer (Admin only)
    if st.session_state.role and st.session_state.role.lower() == "admin":
        st.markdown("### 📊 Audit Logs")
        if st.button("🔄 Load Audit Logs"):
            resp = _api("GET", "/audit", headers=_headers())
            if resp and resp.status_code == 200:
                logs = _safe_json(resp).get("audit_logs", [])
                if logs:
                    st.dataframe(logs, use_container_width=True)
                else:
                    st.info("No audit logs yet.")
            elif resp:
                st.error(_safe_json(resp).get("error", "Failed to load audit logs."))
            else:
                st.error("Backend unreachable.")

    if not backend_online:
        st.warning("⚠️ Backend offline")

# ─── Main Chat Area ────────────────────────────────────────────────────────────
st.markdown("""
<div class='hero-header'>
    <div class='hero-title'>✦ Nexus AI Engine</div>
    <div class='hero-subtitle'>Secure RAG · Role-Based Access · 7 Security Controls</div>
</div>
""", unsafe_allow_html=True)

role_lower = (st.session_state.role or "").lower()
if role_lower == "admin":
    st.info(
        "Admin: company document retrieval is disabled. "
        "You can ask general questions and view the audit dashboard."
    )
elif role_lower == "hr":
    llm_name = ""
    if isinstance(health, requests.Response) and health.status_code == 200:
        llm_name = str(_safe_json(health).get("llm_provider") or "")
    if llm_name == "groq":
        st.info(
            "HR tip: with the cloud LLM (Groq), HR-only documents stay private and "
            "are not sent to the cloud. Use employee-level docs, or set "
            "`LLM_PROVIDER=ollama` for full HR document answers."
        )

# Display messages
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# Chat input
if prompt := st.chat_input("Ask about your documents, general knowledge, or math..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        prior = []
        for m in st.session_state.messages[:-1][-6:]:
            if m.get("role") not in ("user", "assistant") or not m.get("content"):
                continue
            prior.append(
                {
                    "role": m["role"],
                    "content": str(m["content"])[:2000],
                }
            )

        def _token_stream_generator():
            try:
                s_resp = requests.post(
                    f"{API_BASE_URL}/chat/stream",
                    json={"question": prompt, "history": prior},
                    headers=_headers(),
                    stream=True,
                    timeout=90,
                )
                if s_resp.status_code == 200:
                    for line in s_resp.iter_lines():
                        if not line:
                            continue
                        line_str = line.decode("utf-8") if isinstance(line, bytes) else line
                        if line_str.startswith("data: "):
                            raw_data = line_str[6:].strip()
                            try:
                                evt = json.loads(raw_data)
                                if evt.get("event") == "token":
                                    yield evt.get("data", "")
                                elif evt.get("event") == "error":
                                    yield f"\n\n⚠️ {evt.get('data', 'Error occurred.')}"
                            except Exception:
                                continue
                else:
                    yield None
            except Exception:
                yield None

        stream_worked = False
        full_tokens = []
        try:
            gen = _token_stream_generator()
            first = next(gen, None)
            if first is not None:
                stream_worked = True
                full_tokens.append(first)
                def _full_gen():
                    yield first
                    for t in gen:
                        if t is not None:
                            full_tokens.append(t)
                            yield t
                st.write_stream(_full_gen())
                answer = "".join(full_tokens)
        except Exception:
            stream_worked = False

        if not stream_worked:
            placeholder = st.empty()
            with st.spinner("Processing..."):
                resp = _api(
                    "POST",
                    "/chat",
                    json={"question": prompt, "history": prior},
                    headers=_headers(),
                    timeout=90,
                )
                if resp is None:
                    answer = "⚠️ Backend is unreachable. Start the API with `python main.py`."
                elif resp.status_code == 598:
                    answer = "⚠️ The assistant timed out. Please try again."
                elif resp.status_code == 200:
                    payload = _safe_json(resp)
                    answer = payload.get("answer", "No response.")
                    decision = (payload.get("decision") or "").upper()
                    reason = (payload.get("reason_code") or "").upper()
                    if decision and decision != "ALLOW":
                        answer = f"{answer}\n\n_Decision: {decision}_"
                    elif reason == "CLOUD_PRIVACY_GATE":
                        answer = f"{answer}\n\n_Privacy: HR documents were not sent to the cloud LLM._"
                elif resp.status_code == 401:
                    answer = "⚠️ Session expired. Please log in again."
                    st.session_state.token = None
                else:
                    payload = _safe_json(resp)
                    detail = payload.get("detail")
                    if isinstance(detail, list) and detail:
                        first_err = detail[0] if isinstance(detail[0], dict) else {}
                        answer = first_err.get("msg") or payload.get("error") or "An error occurred."
                    else:
                        answer = payload.get("error") or (
                            detail if isinstance(detail, str) else "An error occurred."
                        )
                    answer = f"⚠️ {answer}"
                placeholder.markdown(answer)

        st.session_state.messages.append({"role": "assistant", "content": answer})
