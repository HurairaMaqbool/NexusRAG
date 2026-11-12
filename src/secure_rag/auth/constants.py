"""
src/secure_rag/auth/constants.py — Authentication & RBAC Constants
Authoritative role-to-access mappings, password constraints, and security limits.
"""

import os

# Decision D11: Single authoritative mapping of roles to accessible document levels
# Admin is explicitly mapped to empty list [] (no document retrieval permitted)
ROLE_ACCESS_MAPPING = {
    "employee": ["employee"],
    "hr": ["employee", "hr"],
    "admin": []
}

def can_ingest(role: str) -> bool:
    """
    Decision D13: Central authorization rule for document ingestion and deletion.
    Only HR role has permissions to upload or remove documents.
    """
    return role.lower().strip() == "hr"

# Decision D12: Password length constraints
# bcrypt natively truncates or errors at 72 bytes; enforced explicitly with clear validation
PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 72

# Default bcrypt cost factor (A2: Enforce floor of 12 outside dev/test)
def get_bcrypt_rounds() -> int:
    """
    Resolves bcrypt rounds safely.
    Honors BCRYPT_ROUNDS only when APP_ENV is 'dev' or 'test'.
    In all other environments, enforces strict floor of 12.
    """
    env = os.getenv("APP_ENV", "dev").lower().strip()
    env_rounds = os.getenv("BCRYPT_ROUNDS")
    if env_rounds is not None:
        if env in ("dev", "test"):
            try:
                return max(4, int(env_rounds))
            except ValueError:
                return 12
        else:
            # Production/staging ignores lower values
            try:
                val = int(env_rounds)
                return max(12, val)
            except ValueError:
                return 12
    return 12

# Rate limiting and session timeouts
MAX_FAILED_LOGIN_ATTEMPTS = 5
RATE_LIMIT_LOCKOUT_SECONDS = 900  # 15 minutes lockout window
DEFAULT_SESSION_TIMEOUT_MIN = 30
ABSOLUTE_SESSION_MAX_MIN = 480  # 8 hours — hard cap regardless of idle sliding

# Insecure placeholder keys forbidden outside dev environment
PLACEHOLDER_SECRETS = {
    "change-me-long-random",
    "dev-secret-key-change-in-production-32bytes-min",
    "nexus-dev-secret-key-rotate-in-prod-64chars-min-please-change",
    "secret",
    "password",
    "",
}

# Minimum SECRET_KEY length for production environments
PROD_SECRET_KEY_MIN_LENGTH = 32

# Authoritative schema version (lives in db layer; re-exported for backwards compatibility)
from secure_rag.db.constants import SCHEMA_VERSION
