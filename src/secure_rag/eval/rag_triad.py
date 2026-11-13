"""
src/secure_rag/eval/rag_triad.py — Production RAG Triad Evaluator
Calculates Context Precision, Faithfulness (groundedness), and Answer Relevance scores.
"""

import re
from typing import Any, Dict, List, Optional


def _extract_keywords(text: str) -> set:
    if not text:
        return set()
    words = re.findall(r"\b[a-zA-Z]{3,}\b", text.lower())
    # Common English stopwords
    stopwords = {
        "the", "and", "for", "with", "that", "this", "from", "are", "have", "you",
        "was", "what", "which", "will", "would", "there", "their", "about", "your"
    }
    return {w for w in words if w not in stopwords}


def score_context_precision(
    query: str,
    retrieved_chunks: List[str],
    ground_truth: Optional[str] = None,
) -> float:
    """
    Measures the proportion of retrieved chunks containing relevant information.
    Scores 1.0 if all chunks contain query terms/truth keywords.
    """
    if not retrieved_chunks:
        return 0.0

    target_words = _extract_keywords(query)
    if ground_truth:
        target_words |= _extract_keywords(ground_truth)

    if not target_words:
        return 1.0

    relevant_count = 0
    for chunk in retrieved_chunks:
        chunk_words = _extract_keywords(chunk)
        overlap = target_words & chunk_words
        if len(overlap) >= 1:
            relevant_count += 1

    return round(relevant_count / len(retrieved_chunks), 4)


def score_faithfulness(answer: str, retrieved_chunks: List[str]) -> float:
    """
    Measures groundedness: checks that claims in the answer derive from the chunks.
    Penalizes hallucinated facts not supported by context.
    """
    if not answer or not answer.strip():
        return 0.0
    if not retrieved_chunks:
        return 0.0

    combined_context = " ".join(retrieved_chunks).lower()
    context_words = _extract_keywords(combined_context)
    if not context_words:
        return 0.0

    # Split answer into sentence claims
    sentences = [s.strip() for s in re.split(r"[.!?\n]+", answer) if len(s.strip()) > 8]
    if not sentences:
        return 1.0

    supported_count = 0
    for s in sentences:
        s_words = _extract_keywords(s)
        if not s_words:
            supported_count += 1
            continue
        # If at least 40% of substantive keywords appear in context, claim is grounded
        supported_words = s_words & context_words
        ratio = len(supported_words) / len(s_words)
        if ratio >= 0.40:
            supported_count += 1

    return round(supported_count / len(sentences), 4)


def score_answer_relevance(query: str, answer: str) -> float:
    """
    Measures how directly the answer addresses the user query.
    """
    if not query or not answer:
        return 0.0

    query_words = _extract_keywords(query)
    if not query_words:
        return 1.0

    answer_words = _extract_keywords(answer)
    overlap = query_words & answer_words
    # Ratio of query concepts addressed in answer
    relevance = min(1.0, len(overlap) / max(1, len(query_words)))
    return round(relevance, 4)


def evaluate_rag_triad(
    query: str,
    answer: str,
    retrieved_chunks: List[str],
    ground_truth: Optional[str] = None,
) -> Dict[str, float]:
    """
    Evaluates the complete RAG Triad:
    Context Precision + Faithfulness + Answer Relevance.
    """
    c_prec = score_context_precision(query, retrieved_chunks, ground_truth)
    faith = score_faithfulness(answer, retrieved_chunks)
    ans_rel = score_answer_relevance(query, answer)
    triad_avg = round((c_prec + faith + ans_rel) / 3.0, 4)

    return {
        "context_precision": c_prec,
        "faithfulness": faith,
        "answer_relevance": ans_rel,
        "overall_triad_score": triad_avg,
    }
