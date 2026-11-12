"""
app.py — Streamlit Thin Client for Secure RAG Platform
Communicates with FastAPI backend via HTTP. Stores only session token in state.
No local RAG, no direct DB access — all logic lives on the backend.
"""

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
    """Fire an HTTP request to the backend; return None on connection failure."""
    try:
        return requests.request(method, f"{API_BASE_URL}{path}", timeout=30, **kwargs)
    except requests.ConnectionError:
        return None


def _headers() -> dict:
    return {"Authorization": f"Bearer {st.session_state.token}"} if st.session_state.token else {}


# ─── Backend health check ──────────────────────────────────────────────────────
health = _api("GET", "/health")
backend_online = health is not None and health.status_code == 200


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
            with st.spinner("Uploading..."):
                resp = _api(
                    "POST", "/upload",
                    headers=_headers(),
                    files={"file": (uploaded_file.name, uploaded_file.getvalue())},
                    data={"access_level": access_level},
                )
                if resp and resp.status_code == 200:
                    payload = _safe_json(resp)
                    document = payload.get("document") if isinstance(payload.get("document"), dict) else {}
                    title = document.get("title") or payload.get("title") or uploaded_file.name
                    st.success(f"✅ Indexed: {title}")
                elif resp:
                    st.error(_safe_json(resp).get("error", "Upload failed."))
                else:
                    st.error("Backend unreachable.")

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

# Display messages
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# Chat input
if prompt := st.chat_input("Ask about your documents, search the web, or solve math..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        placeholder = st.empty()
        with st.spinner("Processing..."):
            resp = _api("POST", "/chat", json={"question": prompt}, headers=_headers())
            if resp is None:
                answer = "⚠️ Backend is offline. Please start the server."
            elif resp.status_code == 200:
                answer = _safe_json(resp).get("answer", "No response.")
            elif resp.status_code == 401:
                answer = "⚠️ Session expired. Please log in again."
                st.session_state.token = None
            else:
                answer = _safe_json(resp).get("error", "An error occurred.")
            placeholder.markdown(answer)
            st.session_state.messages.append({"role": "assistant", "content": answer})
