"""
tests/unit/test_auth_service.py — Comprehensive Unit & Security Tests for AuthService
Verifies authentication, server-side session management (D9), database authority (D10),
role-to-access mappings (D11), constant-work bcrypt timing defense (D12), rate-limiting, and audit hygiene.
"""

from datetime import datetime, timezone, timedelta
from unittest.mock import patch
import pytest
import sqlite3
import bcrypt

from secure_rag.auth.constants import (
    ROLE_ACCESS_MAPPING,
    PASSWORD_MIN_LENGTH,
    PASSWORD_MAX_LENGTH,
    get_bcrypt_rounds,
    SCHEMA_VERSION,
)
from secure_rag.auth.security import (
    hash_password,
    verify_password,
    generate_session_token,
    hash_token,
    get_dummy_bcrypt_hash,
)
from secure_rag.auth.service import AuthService, UserSession
from secure_rag.core.errors import (
    AuthenticationError,
    RateLimitExceededError,
    SecurityConfigurationError,
    DatabaseError,
)
from secure_rag.db.connection import get_db_connection, init_db, check_db_schema_compatibility

@pytest.fixture
def auth_service(repo):
    """Provides an initialized AuthService in dev mode."""
    return AuthService(repo=repo, session_timeout_min=30, app_env="dev", secret_key="dev-secret")

def test_login_success_and_session_validation(auth_service, repo):
    """Verifies standard login creates an active session retrievable via raw token."""
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    plain_pw = "ValidPassword2026!"
    repo.create_user("u-01", "user1@northwind.local", hash_password(plain_pw), "role-emp")

    token, session = auth_service.login("user1@northwind.local", plain_pw)
    assert token is not None
    assert session.email == "user1@northwind.local"
    assert session.role_name == "Employee"
    assert session.allowed_access_levels == ["employee"]

    # Validate session using the raw token
    validated = auth_service.validate_session(token)
    assert validated.user_id == "u-01"
    assert validated.email == "user1@northwind.local"
    assert validated.role_name == "Employee"
    assert validated.allowed_access_levels == ["employee"]

def test_login_wrong_password_raises_generic_authentication_error(auth_service, repo):
    """Security test: Wrong password raises a generic AuthenticationError."""
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    repo.create_user("u-02", "user2@northwind.local", hash_password("ValidPassword2026!"), "role-emp")

    with pytest.raises(AuthenticationError, match="Invalid email or password"):
        auth_service.login("user2@northwind.local", "WrongPassword123!")

def test_login_unknown_email_raises_identical_generic_authentication_error(auth_service):
    """Security test: Unknown email raises identical generic error (prevents user enumeration)."""
    with pytest.raises(AuthenticationError, match="Invalid email or password"):
        auth_service.login("nonexistent@northwind.local", "AnyPassword123!")

def test_login_inactive_user_rejected_with_generic_message(auth_service, repo):
    """Security test: Disabled user is refused with the same generic message to prevent enumeration."""
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    repo.create_user(
        "u-inactive",
        "disabled@northwind.local",
        hash_password("ValidPassword2026!"),
        "role-emp",
        is_active=0
    )

    with pytest.raises(AuthenticationError, match="Invalid email or password"):
        auth_service.login("disabled@northwind.local", "ValidPassword2026!")

# ── Item A: Deterministic Constant-Work bcrypt Execution Tests ────────────────

@pytest.mark.parametrize("scenario,email,password", [
    ("unknown_email", "unknown_user@northwind.local", "ValidPassword2026!"),
    ("password_too_short", "known@northwind.local", "short"),
    ("password_too_long", "known@northwind.local", "P" * 80),
    ("inactive_user", "inactive@northwind.local", "ValidPassword2026!"),
    ("wrong_password", "known@northwind.local", "WrongPassword999!"),
    ("correct_password", "known@northwind.local", "ValidPassword2026!"),
])
def test_constant_work_bcrypt_called_exactly_once(scenario, email, password, auth_service, repo):
    """
    Deterministic verification (Item A):
    Asserts that in EVERY scenario (unknown email, password too short, password too long,
    inactive user, wrong password, correct password), bcrypt.checkpw is called EXACTLY ONCE.
    """
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    valid_hash = hash_password("ValidPassword2026!")
    repo.create_user("u-known", "known@northwind.local", valid_hash, "role-emp", is_active=1)
    repo.create_user("u-inact", "inactive@northwind.local", valid_hash, "role-emp", is_active=0)

    with patch("bcrypt.checkpw", wraps=bcrypt.checkpw) as spy_checkpw:
        if scenario == "correct_password":
            token, sess = auth_service.login(email, password, client_ip=f"10.0.0.{scenario}")
            assert token is not None
        else:
            with pytest.raises(AuthenticationError, match="Invalid email or password"):
                auth_service.login(email, password, client_ip=f"10.0.0.{scenario}")

        assert spy_checkpw.call_count == 1, (
            f"Expected exactly 1 bcrypt.checkpw call for scenario '{scenario}', "
            f"but got {spy_checkpw.call_count}"
        )

# ── Session Lifecycle & Authority Tests (Decision D9 & D10) ───────────────────

def test_validate_session_inactive_user_rejected_even_with_valid_session(auth_service, repo, temp_db_path):
    """
    Decision D10 Authority: If a user account is deactivated in the database AFTER login,
    the very next request must immediately reject the session.
    """
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    plain_pw = "ValidPassword2026!"
    repo.create_user("u-temp", "active_then_deactivated@northwind.local", hash_password(plain_pw), "role-emp")

    token, session = auth_service.login("active_then_deactivated@northwind.local", plain_pw)
    assert token is not None

    # Deactivate user directly in the database
    conn = get_db_connection(temp_db_path)
    try:
        with conn:
            conn.execute("UPDATE users SET is_active = 0 WHERE user_id = 'u-temp';")
    finally:
        conn.close()

    # The next validate_session must refuse the token
    with pytest.raises(AuthenticationError, match="inactive"):
        auth_service.validate_session(token)

def test_validate_session_expired(auth_service, repo, temp_db_path):
    """Security test: Expired session token is rejected (Absolute expiry)."""
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    plain_pw = "ValidPassword2026!"
    repo.create_user("u-exp", "exp@northwind.local", hash_password(plain_pw), "role-emp")

    token, session = auth_service.login("exp@northwind.local", plain_pw)
    assert token is not None

    # Backdate the session's expires_at in the database
    conn = get_db_connection(temp_db_path)
    try:
        past_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        with conn:
            conn.execute(
                "UPDATE sessions SET expires_at = ? WHERE session_id = ?;",
                (past_time, session.session_id)
            )
    finally:
        conn.close()

    with pytest.raises(AuthenticationError, match="expired"):
        auth_service.validate_session(token)

def test_validate_session_revoked_on_logout(auth_service, repo):
    """Security test: Logged out session is marked revoked and rejected immediately."""
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    plain_pw = "ValidPassword2026!"
    repo.create_user("u-out", "logout_user@northwind.local", hash_password(plain_pw), "role-emp")

    token, session = auth_service.login("logout_user@northwind.local", plain_pw)
    assert token is not None

    logged_out = auth_service.logout(token)
    assert logged_out is True

    with pytest.raises(AuthenticationError, match="revoked"):
        auth_service.validate_session(token)

def test_validate_session_tampered_token_rejected(auth_service):
    """Security test: Unknown or tampered token raises AuthenticationError."""
    with pytest.raises(AuthenticationError, match="Invalid or unknown"):
        auth_service.validate_session("fabricated-tampered-token-xyz")

def test_role_changed_in_database_takes_effect_on_next_request(auth_service, repo, temp_db_path):
    """
    Decision D10 Authority: When a user's role is updated in the database,
    the active session immediately inherits the new role and access levels on the next call.
    """
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    repo.create_role("role-hr", "HR", ["read:employee_docs", "read:hr_docs"])
    plain_pw = "ValidPassword2026!"
    repo.create_user("u-promote", "promote_me@northwind.local", hash_password(plain_pw), "role-emp")

    token, session = auth_service.login("promote_me@northwind.local", plain_pw)
    assert session.role_name == "Employee"
    assert session.allowed_access_levels == ["employee"]

    # Promote user to HR role in the database
    conn = get_db_connection(temp_db_path)
    try:
        with conn:
            conn.execute("UPDATE users SET role_id = 'role-hr' WHERE user_id = 'u-promote';")
    finally:
        conn.close()

    # Next validation call reflects HR role and expanded access levels immediately
    refreshed = auth_service.validate_session(token)
    assert refreshed.role_name == "HR"
    assert refreshed.allowed_access_levels == ["employee", "hr"]

def test_admin_gets_empty_access_levels(auth_service, repo):
    """Decision D11: Admin role is explicitly mapped to empty list [] (no document retrieval)."""
    repo.create_role("role-admin", "Admin", ["read:dashboard", "read:audit_logs"])
    plain_pw = "ValidPassword2026!"
    repo.create_user("u-adm", "admin_test@northwind.local", hash_password(plain_pw), "role-admin")

    token, session = auth_service.login("admin_test@northwind.local", plain_pw)
    assert session.role_name == "Admin"
    assert session.allowed_access_levels == []

    validated = auth_service.validate_session(token)
    assert validated.allowed_access_levels == []

def test_hr_includes_employee_level(auth_service, repo):
    """Decision D11: HR role has access to both employee and hr levels."""
    repo.create_role("role-hr", "HR", ["read:employee_docs", "read:hr_docs"])
    plain_pw = "ValidPassword2026!"
    repo.create_user("u-hr", "hr_test@northwind.local", hash_password(plain_pw), "role-hr")

    token, session = auth_service.login("hr_test@northwind.local", plain_pw)
    assert session.allowed_access_levels == ["employee", "hr"]

def test_password_length_constraints(auth_service, repo):
    """Decision D12: Passwords under 12 characters or over 72 bytes are rejected."""
    with pytest.raises(ValueError, match="at least 12"):
        hash_password("short123")

    long_pw = "A" * 73
    with pytest.raises(ValueError, match="cannot exceed 72 bytes"):
        hash_password(long_pw)

    exact_72_pw = "A" * 72
    hashed = hash_password(exact_72_pw)
    assert verify_password(exact_72_pw, hashed) is True

    # Login attempt with > 72 bytes raises AuthenticationError safely
    with pytest.raises(AuthenticationError, match="Invalid email or password"):
        auth_service.login("any@northwind.local", "B" * 80)

def test_sql_injection_string_as_email(auth_service):
    """Security test: SQL injection in email field is handled safely as a literal."""
    malicious = "admin' OR '1'='1"
    with pytest.raises(AuthenticationError, match="Invalid email or password"):
        auth_service.login(malicious, "AnyValidPassword123!")

def test_secret_key_placeholder_refused_outside_dev(repo):
    """Security test: App startup is refused outside dev if SECRET_KEY is a placeholder."""
    prod_service = AuthService(
        repo=repo,
        app_env="production",
        secret_key="dev-secret-key-change-in-production-32bytes-min"
    )
    with pytest.raises(SecurityConfigurationError, match="insecure placeholder"):
        prod_service.validate_startup_config()

    valid_prod = AuthService(
        repo=repo,
        app_env="production",
        secret_key="strong-production-cryptographic-secret-key-999"
    )
    valid_prod.validate_startup_config()  # Does not raise

def test_dev_seeding_refused_outside_dev(repo):
    """Security test: Account seeding is refused outside dev."""
    prod_service = AuthService(repo=repo, app_env="production", secret_key="prod-secret")
    with pytest.raises(SecurityConfigurationError, match="must be 'dev'"):
        prod_service.seed_dev_accounts()

def test_dev_seeding_creates_accounts_in_dev(auth_service, repo):
    """Verifies seeding creates employee, hr, admin @northwind.local with exact role names."""
    creds = auth_service.seed_dev_accounts()
    assert "employee@northwind.local" in creds
    assert "hr@northwind.local" in creds
    assert "admin@northwind.local" in creds

    emp_token, emp_sess = auth_service.login("employee@northwind.local", creds["employee@northwind.local"])
    assert emp_token is not None
    assert emp_sess.role_name == "Employee"
    assert emp_sess.allowed_access_levels == ["employee"]

    hr_token, hr_sess = auth_service.login("hr@northwind.local", creds["hr@northwind.local"])
    assert hr_token is not None
    assert hr_sess.role_name == "HR"
    assert hr_sess.allowed_access_levels == ["employee", "hr"]

    admin_token, admin_sess = auth_service.login("admin@northwind.local", creds["admin@northwind.local"])
    assert admin_token is not None
    assert admin_sess.role_name == "Admin"
    assert admin_sess.allowed_access_levels == []

def test_audit_logs_contain_no_passwords_or_tokens(auth_service, repo):
    """
    Security hygiene test: Verifies that login success, failure, and logout write audit records,
    and asserts that raw passwords or raw session tokens NEVER appear in audit records.
    """
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    secret_pw = "SuperSecretPassword123!"
    repo.create_user("u-hygiene", "hygiene@northwind.local", hash_password(secret_pw), "role-emp")

    # 1. Failed login
    with pytest.raises(AuthenticationError):
        auth_service.login("hygiene@northwind.local", "WrongGuessPassword!")

    # 2. Successful login
    raw_token, session = auth_service.login("hygiene@northwind.local", secret_pw)
    assert raw_token is not None

    # 3. Logout
    auth_service.logout(raw_token)

    # 4. Inspect audit logs
    logs = repo.get_audit_logs(limit=100)
    assert len(logs) >= 3

    for entry in logs:
        serialized = str(entry)
        assert secret_pw not in serialized, "Raw password leaked in audit log!"
        assert raw_token not in serialized, "Raw session token leaked in audit log!"
        assert "WrongGuessPassword!" not in serialized, "Attempted password leaked in audit log!"

def test_rate_limiting_after_repeated_failures(auth_service, repo):
    """Security test (Item B): 5 consecutive failed logins from an IP trigger rate limit lock."""
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    repo.create_user("u-rate", "target@northwind.local", hash_password("ValidPassword2026!"), "role-emp")

    for i in range(5):
        with pytest.raises(AuthenticationError):
            auth_service.login("target@northwind.local", f"WrongGuess_{i}!", client_ip="192.168.1.100")

    # 6th attempt from the same IP raises RateLimitExceededError
    with pytest.raises(RateLimitExceededError, match="Too many failed login attempts"):
        auth_service.login("target@northwind.local", "ValidPassword2026!", client_ip="192.168.1.100")

def test_rate_limit_bypass_prevention_on_successful_login(auth_service, repo):
    """
    Security test (Item A1): A successful login MUST NOT clear the IP failure counter.
    An attacker who attempts 4 wrong guesses, logs into their own account from the same IP,
    and then makes 1 more failed guess must still be locked out on the 5th failure.
    """
    repo.create_role("role-emp", "Employee", ["read:employee_docs"])
    repo.create_user("u-attacker", "attacker@northwind.local", hash_password("AttackerPass2026!"), "role-emp")
    repo.create_user("u-target", "victim@northwind.local", hash_password("VictimPass2026!"), "role-emp")
    attacker_ip = "10.0.0.99"

    # 4 failed attempts against victim
    for i in range(4):
        with pytest.raises(AuthenticationError):
            auth_service.login("victim@northwind.local", f"WrongPass_{i}!", client_ip=attacker_ip)

    # Attacker logs into own account from same IP -> succeeds
    raw_token, session = auth_service.login("attacker@northwind.local", "AttackerPass2026!", client_ip=attacker_ip)
    assert raw_token is not None

    # 5th failed attempt against victim
    with pytest.raises(AuthenticationError):
        auth_service.login("victim@northwind.local", "WrongPass_4!", client_ip=attacker_ip)

    # 6th attempt from same IP must be rejected by rate-limiting (lockout window not reset by login)
    with pytest.raises(RateLimitExceededError, match="Too many failed login attempts"):
        auth_service.login("victim@northwind.local", "VictimPass2026!", client_ip=attacker_ip)

def test_bcrypt_rounds_configuration(monkeypatch):
    """
    Security test (Item A2):
    BCRYPT_ROUNDS is honored only when APP_ENV is 'dev' or 'test'.
    In all other environments (e.g. 'prod', 'staging'), a strict floor of 12 is enforced.
    """
    # 1. In dev/test, honors value >= 4
    monkeypatch.setenv("APP_ENV", "dev")
    monkeypatch.setenv("BCRYPT_ROUNDS", "4")
    assert get_bcrypt_rounds() == 4

    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("BCRYPT_ROUNDS", "6")
    assert get_bcrypt_rounds() == 6

    # 2. In prod, low values are strictly floored at 12
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("BCRYPT_ROUNDS", "4")
    assert get_bcrypt_rounds() == 12

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("BCRYPT_ROUNDS", "8")
    assert get_bcrypt_rounds() == 12

    # In prod, higher values (e.g. 14) are permitted
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("BCRYPT_ROUNDS", "14")
    assert get_bcrypt_rounds() == 14

def test_dummy_bcrypt_hash_cost_prefix():
    """
    Security test (Item A3):
    Dummy bcrypt hash must match the active cost factor ($2b$NN$ prefix)
    so timing and cryptographic cost are indistinguishable from real user hashes.
    """
    dummy_hash_4 = get_dummy_bcrypt_hash(rounds=4)
    assert dummy_hash_4.startswith(b"$2b$04$"), f"Expected $2b$04$, got {dummy_hash_4[:7]}"

    dummy_hash_active = get_dummy_bcrypt_hash()
    expected_prefix = f"$2b${get_bcrypt_rounds():02d}$".encode("utf-8")
    assert dummy_hash_active.startswith(expected_prefix), f"Expected {expected_prefix}, got {dummy_hash_active[:7]}"

# ── Item D: Schema Compatibility Verification Test ────────────────────────────

def test_schema_compatibility_refuses_outdated_database(tmp_path):
    """
    Item D: Verifies that init_db refuses to load an existing database with an outdated schema
    (e.g. audit_logs.decision_id NOT NULL or missing sessions table) with an explicit actionable message.
    """
    db_file = tmp_path / "outdated.db"
    conn = sqlite3.connect(str(db_file))
    with conn:
        # Create outdated audit_logs table with NOT NULL decision_id
        conn.execute("""
            CREATE TABLE audit_logs (
                log_id INTEGER PRIMARY KEY,
                decision_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                event_type TEXT NOT NULL
            );
        """)
    conn.close()

    # Attempting to init_db on the outdated database must raise DatabaseError
    with pytest.raises(DatabaseError, match="Database schema mismatch"):
        init_db(str(db_file))

def test_schema_compatibility_refuses_version_mismatch(tmp_path):
    """
    Security test (Item A6):
    Verifies that a database with an unexpected PRAGMA user_version is rejected.
    """
    db_file = tmp_path / "mismatched_version.db"
    conn = sqlite3.connect(str(db_file))
    with conn:
        conn.execute("CREATE TABLE dummy (id INTEGER PRIMARY KEY);")
        conn.execute("PRAGMA user_version = 99;")
    conn.close()

    with pytest.raises(DatabaseError, match="Database schema version mismatch"):
        init_db(str(db_file))
