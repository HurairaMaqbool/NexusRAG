"""
tests/unit/test_rag_triad.py — Unit tests for RAG Triad Evaluation Harness
Validates Context Precision, Faithfulness (groundedness), and Answer Relevance.
"""

import pytest
from secure_rag.eval.rag_triad import (
    evaluate_rag_triad,
    score_answer_relevance,
    score_context_precision,
    score_faithfulness,
)


def test_context_precision_perfect_match():
    query = "What is the vacation policy for full-time employees?"
    chunks = [
        "Full-time employees receive 20 days of paid vacation per year.",
        "Vacation policy guidelines and rollover procedures.",
    ]
    score = score_context_precision(query, chunks)
    assert score == 1.0


def test_context_precision_partial_match():
    query = "Tell me about remote work policies and salary compensation."
    chunks = [
        "Remote work is supported up to 3 days per week.",
        "The cafeteria lunch menu is updated weekly on Mondays.",
    ]
    score = score_context_precision(query, chunks)
    assert score == 0.5


def test_faithfulness_fully_grounded():
    chunks = ["Northwind Retail was founded in 1994 and is headquartered in Seattle, Washington."]
    answer = "Northwind Retail was founded in 1994 in Seattle, Washington."
    score = score_faithfulness(answer, chunks)
    assert score >= 0.8


def test_faithfulness_hallucination_penalized():
    chunks = ["Northwind Retail was founded in 1994."]
    # Hallucinating revenue and employee numbers not in chunks
    hallucinated_answer = "Northwind Retail generates 500 billion dollars with 2 million astronauts on Mars."
    score = score_faithfulness(hallucinated_answer, chunks)
    assert score < 0.5


def test_answer_relevance_high():
    query = "How do I request paternity leave?"
    answer = "You can request paternity leave through the HR portal under the leave section."
    score = score_answer_relevance(query, answer)
    assert score >= 0.5


def test_complete_triad_evaluation():
    query = "What are the health benefits offered?"
    chunks = ["Health benefits include comprehensive medical, dental, and vision insurance."]
    answer = "The health benefits include comprehensive medical and vision insurance coverage."
    result = evaluate_rag_triad(query, answer, chunks)
    assert "context_precision" in result
    assert "faithfulness" in result
    assert "answer_relevance" in result
    assert "overall_triad_score" in result
    assert result["overall_triad_score"] > 0.6
