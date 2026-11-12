"""
src/secure_rag/auth package — Authentication & Role-Based Access Control.
"""

from secure_rag.auth.constants import (
    ROLE_ACCESS_MAPPING,
    PASSWORD_MIN_LENGTH,
    PASSWORD_MAX_LENGTH,
)
from secure_rag.auth.security import (
    hash_password,
    verify_password,
    generate_session_token,
    hash_token,
)
from secure_rag.auth.service import AuthService, UserSession

__all__ = [
    "AuthService",
    "UserSession",
    "ROLE_ACCESS_MAPPING",
    "PASSWORD_MIN_LENGTH",
    "PASSWORD_MAX_LENGTH",
    "hash_password",
    "verify_password",
    "generate_session_token",
    "hash_token",
]
