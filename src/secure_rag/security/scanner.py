"""
src/secure_rag/security/scanner.py — Control 4: Rule-Based Document Scanner
Loads injection_rules.yaml and scores retrieved chunks for indirect prompt injection risk.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from secure_rag.security.models import ScanResult

# Default path to injection rules config
_DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent.parent.parent / "config" / "injection_rules.yaml"


class DocumentScanner:
    """Scans retrieved document chunks against configurable injection detection rules."""

    def __init__(self, rules_path: Optional[str] = None):
        path = Path(rules_path) if rules_path else _DEFAULT_RULES_PATH
        self._rules = self._load_rules(path)

    @staticmethod
    def _load_rules(path: Path) -> List[Dict[str, Any]]:
        """Loads and compiles regex rules from YAML configuration."""
        if not path.exists():
            return []
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        raw_rules = data.get("rules", [])
        compiled = []
        for rule in raw_rules:
            try:
                compiled.append({
                    "id": rule["id"],
                    "pattern": re.compile(rule["pattern"]),
                    "description": rule.get("description", ""),
                    "weight": float(rule.get("weight", 0.5)),
                })
            except (re.error, KeyError, TypeError):
                continue
        return compiled

    def scan_text(self, text: str) -> ScanResult:
        """Scans a single text string against all loaded rules."""
        if not text:
            return ScanResult(risk_score=0.0, matched_signatures=[], details="empty input")

        matched: List[str] = []
        total_weight = 0.0

        for rule in self._rules:
            if rule["pattern"].search(text):
                matched.append(rule["id"])
                total_weight += rule["weight"]

        # Normalize score to [0, 1]
        risk_score = min(total_weight, 1.0)

        return ScanResult(
            risk_score=round(risk_score, 4),
            matched_signatures=matched,
            details=f"matched {len(matched)} rules" if matched else "clean",
        )

    def scan_chunks(self, chunks: List[Dict[str, Any]]) -> ScanResult:
        """
        Scans a list of retrieved chunk dicts. Uses the maximum risk score
        across all chunks and aggregates matched signatures.
        """
        if not chunks:
            return ScanResult(risk_score=0.0, matched_signatures=[], details="no chunks")

        max_score = 0.0
        all_matched: List[str] = []

        for chunk in chunks:
            text = chunk.get("text", "") or chunk.get("chunk_text", "")
            result = self.scan_text(text)
            if result.risk_score > max_score:
                max_score = result.risk_score
            all_matched.extend(result.matched_signatures)

        # Deduplicate signatures
        unique_signatures = list(dict.fromkeys(all_matched))

        return ScanResult(
            risk_score=round(max_score, 4),
            matched_signatures=unique_signatures,
            details=f"scanned {len(chunks)} chunks, matched {len(unique_signatures)} unique rules",
        )
