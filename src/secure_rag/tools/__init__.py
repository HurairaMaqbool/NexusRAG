"""Tools package — deterministic calculator and web search."""

from secure_rag.tools.calculator import safe_eval, calculator_tool
from secure_rag.tools.web_search import web_search_tool

__all__ = ["safe_eval", "calculator_tool", "web_search_tool"]
