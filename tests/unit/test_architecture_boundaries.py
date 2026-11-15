"""
tests/unit/test_architecture_boundaries.py — Static Architecture & Dependency Direction Tests (B7)
Uses Python's AST parser to strictly verify layer separation:
1. db may import only core and standard library.
2. retrieval must not import auth or security.
3. ingestion must not import auth.
4. No package imports pipeline.
"""

import ast
from pathlib import Path
import pytest

SRC_ROOT = Path(__file__).resolve().parent.parent.parent / "src" / "secure_rag"

def get_imports(py_file: Path):
    """Parses a Python file with ast and extracts all imported module names."""
    tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
    imported_modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_modules.append(node.module)
    return imported_modules

def test_db_layer_imports_only_core_and_stdlib():
    """Rule (B7): db may import only core and the standard library."""
    db_dir = SRC_ROOT / "db"
    for py_file in db_dir.glob("*.py"):
        imports = get_imports(py_file)
        for imp in imports:
            if imp.startswith("secure_rag."):
                assert imp.startswith("secure_rag.core") or imp.startswith("secure_rag.db"), (
                    f"Forbidden import in {py_file.name}: '{imp}'. db layer may only import from secure_rag.core or secure_rag.db."
                )

def test_retrieval_layer_does_not_import_auth_or_security():
    """Rule (B7): retrieval must not import auth or security."""
    retrieval_dir = SRC_ROOT / "retrieval"
    for py_file in retrieval_dir.glob("*.py"):
        imports = get_imports(py_file)
        for imp in imports:
            assert not imp.startswith("secure_rag.auth"), (
                f"Forbidden import in {py_file.name}: '{imp}'. retrieval must not import auth."
            )
            assert not imp.startswith("secure_rag.security"), (
                f"Forbidden import in {py_file.name}: '{imp}'. retrieval must not import security."
            )

def test_ingestion_layer_does_not_import_auth():
    """Rule (B7): ingestion must not import auth (the caller passes the role or user)."""
    ingestion_dir = SRC_ROOT / "ingestion"
    for py_file in ingestion_dir.glob("*.py"):
        imports = get_imports(py_file)
        for imp in imports:
            assert not imp.startswith("secure_rag.auth"), (
                f"Forbidden import in {py_file.name}: '{imp}'. ingestion must not import auth."
            )

def test_no_package_imports_pipeline():
    """Rule (B7): no package imports pipeline."""
    # bootstrap.py is the DI factory (equivalent to main.py) — it MUST import pipeline.
    ALLOWED_PIPELINE_IMPORTERS = {"pipeline.py", "bootstrap.py"}
    for py_file in SRC_ROOT.rglob("*.py"):
        if py_file.name in ALLOWED_PIPELINE_IMPORTERS:
            continue
        imports = get_imports(py_file)
        for imp in imports:
            assert not imp.endswith(".pipeline"), (
                f"Forbidden import in {py_file.relative_to(SRC_ROOT)}: '{imp}'. No package may import pipeline."
            )
