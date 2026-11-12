"""
src/secure_rag/tools/web_search.py — DuckDuckGo Web Search Wrapper
Provides web search with graceful fallback when packages are unavailable.
"""

try:
    from ddgs import DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        DDGS = None


def web_search_tool(query: str, max_results: int = 4) -> str:
    """Search the web using DuckDuckGo and return formatted results."""
    if DDGS is None:
        return "Web search unavailable — install 'ddgs' package."
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))
        if not results:
            return f"No web results found for: {query}"
        lines = []
        for r in results:
            lines.append(f"Title: {r.get('title', 'N/A')}\nSummary: {r.get('body', 'N/A')}")
        return "\n\n".join(lines)
    except Exception:
        return "Web search temporarily unavailable. Please try again later."
