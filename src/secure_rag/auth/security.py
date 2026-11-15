"""
src/secure_rag/auth/security.py — Cryptographic Primitives & Token Handling
Implements bcrypt password hashing with byte-length validation and SHA-256 token hashing.
"""

import hashlib
import os
import secrets
from typing import Optional
import bcrypt
from secure_rag.auth.constants import (
    PASSWORD_MIN_LENGTH,
    PASSWORD_MAX_LENGTH,
    get_bcrypt_rounds,
)

# Module-level cache: unknown-email login must do constant bcrypt work without
# regenerating salt on every call (timing side-channel mitigation).
_DUMMY_BCRYPT_HASH_CACHE: dict[int, bytes] = {}


def get_dummy_bcrypt_hash(rounds: Optional[int] = None) -> bytes:
    """
    Returns a cached dummy bcrypt hash with cost factor matching
    the active bcrypt rounds configuration (A3).
    """
    actual_rounds = rounds if rounds is not None else get_bcrypt_rounds()
    cached = _DUMMY_BCRYPT_HASH_CACHE.get(actual_rounds)
    if cached is not None:
        return cached
    hashed = bcrypt.hashpw(
        b"dummy_timing_mitigation_password",
        bcrypt.gensalt(rounds=actual_rounds),
    )
    _DUMMY_BCRYPT_HASH_CACHE[actual_rounds] = hashed
    return hashed

def validate_password_length(password: str) -> None:
    """
    Enforces minimum 12 chars and maximum 72 bytes constraint.
    Decision D12: bcrypt 5.x rejects passwords > 72 bytes; enforce explicitly with clear error.
    """
    pw_bytes = password.encode("utf-8")
    if len(password) < PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must be at least {PASSWORD_MIN_LENGTH} characters.")
    if len(pw_bytes) > PASSWORD_MAX_LENGTH:
        raise ValueError(f"Password cannot exceed {PASSWORD_MAX_LENGTH} bytes due to bcrypt limitation.")

def hash_password(password: str, rounds: Optional[int] = None) -> str:
    """Hashes a password with bcrypt and returns a UTF-8 string."""
    validate_password_length(password)
    actual_rounds = rounds if rounds is not None else get_bcrypt_rounds()
    salt = bcrypt.gensalt(rounds=actual_rounds)
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain password against a bcrypt hash.
    Safely handles passwords exceeding 72 bytes by truncating before check.
    """
    pw_bytes = plain_password.encode("utf-8")[:PASSWORD_MAX_LENGTH]
    try:
        return bcrypt.checkpw(pw_bytes, hashed_password.encode("utf-8"))
    except Exception:
        return False

def generate_session_token() -> str:
    """Generates a high-entropy URL-safe token (32 bytes = 256 bits of entropy)."""
    return secrets.token_urlsafe(32)

def hash_token(raw_token: str) -> str:
    """
    Computes SHA-256 hash of a session token for storage.
    Decision D9: Raw tokens are never persisted or logged.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
