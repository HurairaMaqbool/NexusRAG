"""
src/secure_rag/auth/service.py — Authoritative Authentication & RBAC Service
Manages server-side sessions, credential verification, rate-limiting, and RBAC enforcement.
"""

from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
import hashlib
import os
import secrets
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
import bcrypt

from secure_rag.auth.constants import (
    ROLE_ACCESS_MAPPING,
    PASSWORD_MIN_LENGTH,
    PASSWORD_MAX_LENGTH,
    MAX_FAILED_LOGIN_ATTEMPTS,
    RATE_LIMIT_LOCKOUT_SECONDS,
    DEFAULT_SESSION_TIMEOUT_MIN,
    ABSOLUTE_SESSION_MAX_MIN,
    PLACEHOLDER_SECRETS,
    PROD_SECRET_KEY_MIN_LENGTH,
)
from secure_rag.auth.security import (
    hash_password,
    generate_session_token,
    hash_token,
    get_dummy_bcrypt_hash,
)
from secure_rag.core.errors import (
    AuthenticationError,
    RateLimitExceededError,
    SecurityConfigurationError,
)
from secure_rag.db.repository import SQLiteRepository

@dataclass(frozen=True)
class UserSession:
    """Immutable representation of an active, validated session."""
    session_id: str
    user_id: str
    email: str
    role_name: str
    allowed_access_levels: List[str]
    created_at: str
    expires_at: str

class AuthService:
    """
    Central authority for user authentication and RBAC.
    Enforces server-side session lookup (D9), database authority on every request (D10),
    role-to-access mappings (D11), and timing-safe bcrypt operations (D12).
    """

    def __init__(
        self,
        repo: SQLiteRepository,
        session_timeout_min: int = DEFAULT_SESSION_TIMEOUT_MIN,
        app_env: Optional[str] = None,
        secret_key: Optional[str] = None
    ):
        self.repo = repo
        self.session_timeout_min = session_timeout_min
        self.app_env = (app_env or os.getenv("APP_ENV", "dev")).lower().strip()
        self.secret_key = secret_key if secret_key is not None else os.getenv("SECRET_KEY", "")
        self._lock = threading.Lock()
        self._failed_attempts: Dict[str, List[float]] = {}

    # Loopback addresses where IP rate bucket is skipped (Streamlit single-origin).
    # When client_ip is loopback, only email-based rate limiting applies.
    _LOOPBACK_IPS = frozenset({"127.0.0.1", "::1", "localhost"})

    # ── Rate Limiting (In-Memory IP + Email Throttling) ────────────────────────

    @staticmethod
    def _email_rate_key(clean_email: str) -> str:
        """Stable key for per-email failure tracking (never stores the password)."""
        return f"email:{clean_email}"

    @staticmethod
    def _email_audit_hint(clean_email: str) -> Dict[str, str]:
        """Safe email identifiers for audit logs (hash + truncated), never password."""
        if not clean_email:
            return {"email_hash": "", "email_truncated": ""}
        email_hash = hashlib.sha256(clean_email.encode("utf-8")).hexdigest()[:16]
        local, _, domain = clean_email.partition("@")
        truncated = f"{local[:2]}…@{domain}" if domain else f"{clean_email[:3]}…"
        return {"email_hash": email_hash, "email_truncated": truncated}

    def _is_rate_limited(self, key: str) -> bool:
        """Checks if a rate-limit key is currently limited (5 failures in 15 min)."""
        now = time.time()
        with self._lock:
            attempts = self._failed_attempts.get(key, [])
            recent = [t for t in attempts if now - t < RATE_LIMIT_LOCKOUT_SECONDS]
            self._failed_attempts[key] = recent
            return len(recent) >= MAX_FAILED_LOGIN_ATTEMPTS

    def _record_failure(self, key: str) -> None:
        now = time.time()
        with self._lock:
            attempts = self._failed_attempts.get(key, [])
            attempts.append(now)
            self._failed_attempts[key] = attempts

    def _clear_failures(self, key: str) -> None:
        with self._lock:
            if key in self._failed_attempts:
                del self._failed_attempts[key]

    # ── Authentication Operations ─────────────────────────────────────────────

    def login(
        self,
        email: str,
        password: str,
        client_ip: str = "127.0.0.1"
    ) -> Tuple[str, UserSession]:
        """
        Authenticates credentials and establishes a server-side session.
        Returns: (raw_session_token, UserSession) on success.
        Raises: RateLimitExceededError on throttling, AuthenticationError on credential failure.
        Decision D12 / Constant-Work Login:
          Executes EXACTLY ONE bcrypt.checkpw call across ALL scenarios (unknown email,
          password too short, password too long, inactive user, wrong password, correct password).
        """
        clean_email = email.lower().strip() if email else ""
        email_key = self._email_rate_key(clean_email) if clean_email else ""
        email_hint = self._email_audit_hint(clean_email)

        # 1. Rate limiting: check BOTH IP and email before auth (fail closed).
        # When client_ip is loopback (Streamlit co-located), skip IP bucket — only email applies.
        ip_is_loopback = client_ip in self._LOOPBACK_IPS
        ip_limited = (not ip_is_loopback) and self._is_rate_limited(client_ip)
        email_limited = email_key and self._is_rate_limited(email_key)
        if ip_limited or email_limited:
            self.repo.append_audit_log(
                decision_id=None,
                user_id=None,
                event_type="login_rate_limited",
                details={
                    "client_ip": client_ip,
                    "reason_code": "RATE_LIMITED",
                    **email_hint,
                }
            )
            raise RateLimitExceededError("Too many failed login attempts. Please try again later.")

        # 2. Database lookup
        user = self.repo.get_user_by_email(clean_email) if clean_email else None

        # 3. Prepare candidate hash and byte payload for constant-work execution
        candidate_hash = user["password_hash"].encode("utf-8") if user else get_dummy_bcrypt_hash()

        pw_bytes = password.encode("utf-8") if password else b""
        # Truncate to 72 bytes for the bcrypt.checkpw invocation so bcrypt 5.x does not raise
        safe_pw_bytes = pw_bytes[:PASSWORD_MAX_LENGTH]

        # Invalidation conditions evaluated after the single bcrypt call
        # password may be None; treat as empty to avoid TypeError on len(None)
        length_invalid = len(password or "") < PASSWORD_MIN_LENGTH or len(pw_bytes) > PASSWORD_MAX_LENGTH
        user_invalid = user is None
        inactive_invalid = bool(user and not user["is_active"])

        # 4. EXACTLY ONE bcrypt.checkpw call in ALL execution branches
        pw_matches = False
        try:
            pw_matches = bcrypt.checkpw(safe_pw_bytes, candidate_hash)
        except Exception:
            pw_matches = False

        # 5. Fail-closed rejection: fails if length invalid, user unknown, hash mismatch, or inactive
        if length_invalid or user_invalid or not pw_matches or inactive_invalid:
            if not ip_is_loopback:
                self._record_failure(client_ip)
            if email_key:
                self._record_failure(email_key)
            user_id = user["user_id"] if user else None
            event_type = "login_rejected_inactive" if inactive_invalid else "login_failed"
            self.repo.append_audit_log(
                decision_id=None,
                user_id=user_id,
                event_type=event_type,
                details={
                    "client_ip": client_ip,
                    "reason_code": "ROLE_NOT_AUTHORIZED",
                    **email_hint,
                }
            )
            # Universal generic error message
            raise AuthenticationError("Invalid email or password.")

        # 6. Authentication Successful
        # Fix A1: Do NOT clear failure history on success; failures must expire naturally
        raw_token = generate_session_token()
        token_hash = hash_token(raw_token)
        session_id = f"sess-{secrets.token_hex(8)}"
        
        now_dt = datetime.now(timezone.utc)
        expires_dt = now_dt + timedelta(minutes=self.session_timeout_min)
        expires_at_iso = expires_dt.isoformat()

        self.repo.create_session(
            session_id=session_id,
            user_id=user["user_id"],
            token_hash=token_hash,
            expires_at=expires_at_iso
        )

        role_name = user["role_name"].lower()
        allowed_access = ROLE_ACCESS_MAPPING.get(role_name, [])

        session = UserSession(
            session_id=session_id,
            user_id=user["user_id"],
            email=user["email"],
            role_name=user["role_name"],
            allowed_access_levels=allowed_access,
            created_at=now_dt.isoformat(),
            expires_at=expires_at_iso
        )

        # Audit log success without logging raw token or passwords
        self.repo.append_audit_log(
            decision_id=None,
            user_id=user["user_id"],
            event_type="login_success",
            details={
                "client_ip": client_ip,
                "role": user["role_name"],
                "reason_code": "ALLOWED_AUTHORIZED_SOURCE"
            }
        )

        return raw_token, session

    def validate_session(self, raw_token: str) -> UserSession:
        """
        Validates token against database and loads fresh user and role state.
        Decision D10: Never trusts cached or client-provided claims.
        """
        if not raw_token or not raw_token.strip():
            raise AuthenticationError("Session token missing.")

        token_hash = hash_token(raw_token.strip())
        record = self.repo.get_session_by_token_hash(token_hash)

        if not record:
            self.repo.append_audit_log(
                decision_id=None,
                user_id=None,
                event_type="session_rejected_invalid",
                details={"reason_code": "ROLE_NOT_AUTHORIZED"}
            )
            raise AuthenticationError("Invalid or unknown session token.")

        user_id = record["user_id"]

        # Check revocation
        if record["revoked_at"] is not None:
            self.repo.append_audit_log(
                decision_id=None,
                user_id=user_id,
                event_type="session_rejected_revoked",
                details={"reason_code": "ROLE_NOT_AUTHORIZED"}
            )
            raise AuthenticationError("Session has been revoked.")

        # Check idle-window expiration
        expires_dt = datetime.fromisoformat(record["expires_at"])
        if expires_dt.tzinfo is None:
            expires_dt = expires_dt.replace(tzinfo=timezone.utc)
        now_dt = datetime.now(timezone.utc)

        if now_dt >= expires_dt:
            self.repo.append_audit_log(
                decision_id=None,
                user_id=user_id,
                event_type="session_rejected_expired",
                details={"reason_code": "ROLE_NOT_AUTHORIZED"}
            )
            raise AuthenticationError("Session has expired.")

        # Enforce absolute max session lifetime from created_at
        created_dt = datetime.fromisoformat(record["created_at"])
        if created_dt.tzinfo is None:
            created_dt = created_dt.replace(tzinfo=timezone.utc)
        absolute_max_dt = created_dt + timedelta(minutes=ABSOLUTE_SESSION_MAX_MIN)
        if now_dt >= absolute_max_dt:
            self.repo.append_audit_log(
                decision_id=None,
                user_id=user_id,
                event_type="session_rejected_absolute_max",
                details={"reason_code": "ROLE_NOT_AUTHORIZED"}
            )
            raise AuthenticationError("Session has expired.")

        # Slide the idle-timeout window forward (capped at absolute max)
        new_idle_expires = now_dt + timedelta(minutes=self.session_timeout_min)
        if new_idle_expires > absolute_max_dt:
            new_idle_expires = absolute_max_dt
        self.repo.touch_session(record["session_id"], new_idle_expires.isoformat())

        # Decision D10: Check fresh is_active status directly from database
        if not record["is_active"]:
            self.repo.append_audit_log(
                decision_id=None,
                user_id=user_id,
                event_type="session_rejected_inactive_user",
                details={"reason_code": "ROLE_NOT_AUTHORIZED"}
            )
            raise AuthenticationError("User account is inactive.")

        # Decision D10 & D11: Resolve role and access levels fresh from database
        role_name = record["role_name"].lower()
        allowed_access = ROLE_ACCESS_MAPPING.get(role_name, [])

        return UserSession(
            session_id=record["session_id"],
            user_id=record["user_id"],
            email=record["email"],
            role_name=record["role_name"],
            allowed_access_levels=allowed_access,
            created_at=record["created_at"],
            expires_at=record["expires_at"]
        )

    def logout(self, raw_token: str) -> bool:
        """Revokes an active session."""
        if not raw_token or not raw_token.strip():
            return False

        token_hash = hash_token(raw_token.strip())
        record = self.repo.get_session_by_token_hash(token_hash)
        if not record:
            return False

        revoked = self.repo.revoke_session(record["session_id"])
        if revoked:
            self.repo.append_audit_log(
                decision_id=None,
                user_id=record["user_id"],
                event_type="logout_success",
                details={"reason_code": "ALLOWED_AUTHORIZED_SOURCE"}
            )
        return revoked

    # ── Role & Access Level Helper ────────────────────────────────────────────

    def get_allowed_access_levels(self, role: str) -> List[str]:
        """Decision D11: Central authority for role-to-document access levels."""
        return ROLE_ACCESS_MAPPING.get(role.lower().strip(), [])

    # ── Dev Seeding & Startup Verification ────────────────────────────────────

    def seed_dev_accounts(self, custom_passwords: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Seeds standard demo accounts (employee, hr, admin @northwind.local)
        ONLY when APP_ENV=dev. Refuses if APP_ENV != 'dev'.
        Passwords are generated in memory and never written to logs or disk.
        """
        if self.app_env != "dev":
            raise SecurityConfigurationError("Refused to seed demo accounts: APP_ENV must be 'dev'.")

        # 1. Ensure Roles exist with exact authoritative names
        existing_roles = {r["name"].lower(): r["role_id"] for r in self.repo.list_roles()}
        role_defs = {
            "employee": ("role-emp", "Employee", ["read:employee_docs", "use:calculator"]),
            "hr": ("role-hr", "HR", ["read:employee_docs", "read:hr_docs", "use:calculator", "use:web_search"]),
            "admin": ("role-admin", "Admin", ["read:dashboard", "read:audit_logs"])
        }

        for r_key, (r_id, r_display, perms) in role_defs.items():
            if r_key not in existing_roles:
                self.repo.create_role(role_id=r_id, name=r_display, permissions=perms)
                existing_roles[r_key] = r_id

        # 2. Seed Users
        accounts = [
            ("user-emp-01", "employee@northwind.local", "employee"),
            ("user-hr-01", "hr@northwind.local", "hr"),
            ("user-admin-01", "admin@northwind.local", "admin")
        ]

        generated_passwords = {}
        custom = custom_passwords or {}

        for u_id, email, role_key in accounts:
            existing = self.repo.get_user_by_email(email)
            if not existing:
                env_var_name = f"DEMO_PASSWORD_{role_key.upper()}"
                plain_pw = custom.get(email) or os.getenv(env_var_name) or secrets.token_urlsafe(16)
                pw_hash = hash_password(plain_pw)
                self.repo.create_user(
                    user_id=u_id,
                    email=email,
                    password_hash=pw_hash,
                    role_id=existing_roles[role_key],
                    is_active=1
                )
                generated_passwords[email] = plain_pw
            else:
                generated_passwords[email] = "[existing account preserved]"

        # Audit log records only email list, never the plain passwords
        self.repo.append_audit_log(
            decision_id=None,
            user_id=None,
            event_type="dev_accounts_seeded",
            details={"seeded_accounts": list(generated_passwords.keys()), "reason_code": "ALLOWED_AUTHORIZED_SOURCE"}
        )

        return generated_passwords

    def validate_startup_config(self) -> None:
        """
        Validates critical configuration before startup.
        Refuses startup if APP_ENV is not dev and SECRET_KEY is an insecure placeholder or too short.
        Also blocks DEMO_FORCE_RESEED and EMBEDDING_FAKE in production.
        """
        if self.app_env != "dev":
            if not self.secret_key or self.secret_key.strip() in PLACEHOLDER_SECRETS:
                raise SecurityConfigurationError(
                    "Production startup refused: SECRET_KEY is set to an insecure placeholder. "
                    "Configure a strong random SECRET_KEY in .env before running outside dev."
                )
            if len(self.secret_key.strip()) < PROD_SECRET_KEY_MIN_LENGTH:
                raise SecurityConfigurationError(
                    f"Production startup refused: SECRET_KEY must be at least "
                    f"{PROD_SECRET_KEY_MIN_LENGTH} characters. Current length: {len(self.secret_key.strip())}."
                )
            if os.getenv("DEMO_FORCE_RESEED", "").strip().lower() in ("1", "true", "yes"):
                raise SecurityConfigurationError(
                    "Production startup refused: DEMO_FORCE_RESEED must not be enabled outside dev."
                )
            if os.getenv("EMBEDDING_FAKE", "").strip().lower() in ("1", "true", "yes"):
                raise SecurityConfigurationError(
                    "Production startup refused: EMBEDDING_FAKE must not be enabled outside dev. "
                    "FakeEmbedder provides no semantic retrieval quality."
                )
