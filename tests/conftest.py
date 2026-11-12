"""
tests/conftest.py — Global Test Fixtures
Provides isolated in-memory and file-based test databases for unit and integration testing.
"""

import sys
import os
from pathlib import Path
import pytest

# Configure fast bcrypt rounds (4) for automated test suites
# Production default remains strictly 12
os.environ["BCRYPT_ROUNDS"] = "4"

from secure_rag.db.connection import get_db_connection, init_db
from secure_rag.db.repository import SQLiteRepository

@pytest.fixture
def temp_db_path(tmp_path):
    """Provides an isolated database path in a temporary directory."""
    db_file = tmp_path / "test_secure_rag.db"
    init_db(str(db_file))
    return str(db_file)

@pytest.fixture
def repo(temp_db_path):
    """Provides a fully initialized SQLiteRepository bound to the temporary database."""
    factory = lambda: get_db_connection(temp_db_path)
    return SQLiteRepository(connection_factory=factory)
