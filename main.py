"""main.py — Thin FastAPI entry point. All DI lives in secure_rag.bootstrap."""
import sys
from dotenv import load_dotenv

load_dotenv()

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import os

from secure_rag.bootstrap import create_application

app, config = create_application()

if __name__ == "__main__":
    import uvicorn

    host = os.getenv("API_HOST", "127.0.0.1").strip() or "127.0.0.1"
    if config.app_env != "dev" and host in ("0.0.0.0", "::"):
        print(
            f"\u26a0\ufe0f  WARNING: Binding to {host} in {config.app_env} mode. "
            "Ensure a reverse proxy or firewall restricts access."
        )
    print(f"\u2705 Starting Secure RAG Platform on {host}:8000")
    uvicorn.run("main:app", host=host, port=8000, reload=False)
