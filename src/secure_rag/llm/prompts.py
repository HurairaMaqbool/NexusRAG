"""
src/secure_rag/llm/prompts.py — LLM prompt helpers for the RAG agent.
All helpers obtain a Groq chat model via get_llm from groq_provider.
"""

from __future__ import annotations

from secure_rag.llm.groq_provider import get_llm


def ask_rag(question: str, context: str) -> str:
    prompt = f"""You are a world-class AI research assistant specializing in document analysis.
Your job is to answer the user's question using ONLY the provided document context.
If the context does not contain a clear answer, say so honestly — do NOT hallucinate or make things up.

Follow this Chain of Thought:
1. Identify the core intent of the question.
2. Scan the context for every relevant fact, number, or statement.
3. Reason through the evidence step by step.
4. Present a well-structured, markdown-formatted final answer.

--- EXAMPLES ---

Example 1:
Context: "The Transformer architecture was introduced in the paper 'Attention is All You Need' (2017). It relies on a self-attention mechanism instead of recurrence."
Question: What mechanism does the Transformer use instead of recurrence?
Thought: The context states it uses "self-attention" instead of recurrence.
Answer: The Transformer uses a **self-attention mechanism**, which allows it to process all tokens simultaneously rather than sequentially.

Example 2:
Context: "Revenue for FY2023 was $4.2B. Operating costs were $2.8B."
Question: What was the operating profit?
Thought: Operating profit = Revenue - Costs = $4.2B - $2.8B = $1.4B.
Answer: The operating profit for FY2023 was **$1.4 billion**.

--- YOUR TASK ---

Context:
{context}

Question: {question}

Thought:"""
    try:
        llm = get_llm()
        return llm.invoke(prompt).content
    except Exception:
        return "I'm unable to generate a response right now. Please try again later."


def ask_web(question: str, web_context: str) -> str:
    prompt = f"""You are a knowledgeable AI assistant that synthesizes real-time web search results into clear, factual answers.
Use ONLY the provided search results. Do NOT fabricate facts. If results are insufficient, say so.

Chain of Thought:
1. Read all search results carefully.
2. Identify the most relevant and credible snippets.
3. Cross-reference multiple sources where possible.
4. Write a well-structured answer with key points in **bold**.

--- EXAMPLE ---
Search Results:
Title: Python 3.12 Released
Summary: Python 3.12 was released in October 2023 with major performance improvements and new syntax.

Question: When was Python 3.12 released?
Thought: The result says October 2023.
Answer: Python 3.12 was released in **October 2023**, featuring significant performance improvements.

--- YOUR TASK ---

Search Results:
{web_context}

Question: {question}

Thought:"""
    try:
        llm = get_llm()
        return llm.invoke(prompt).content
    except Exception:
        return "I'm unable to generate a response right now. Please try again later."


def ask_general(question: str) -> str:
    prompt = f"""You are a brilliant, concise AI assistant. Answer the question using your knowledge.

Chain of Thought:
1. Understand exactly what the user is asking.
2. Break the answer into logical steps if needed.
3. Provide a clear, well-structured, markdown-formatted answer.

Question: {question}

Thought:"""
    try:
        llm = get_llm()
        return llm.invoke(prompt).content
    except Exception:
        return "I'm unable to generate a response right now. Please try again later."


def ask_math_explainer(question: str, raw_result: str) -> str:
    prompt = f"""You are a patient and precise math tutor.
The user asked: "{question}"
The computed result is: {raw_result}

Chain of Thought:
1. Identify the mathematical operation(s) involved.
2. Show each calculation step clearly.
3. Confirm the final answer with proper units if applicable.

Explain the solution clearly and confirm the result."""
    try:
        llm = get_llm(temperature=0.1)
        return llm.invoke(prompt).content
    except Exception as e:
        return ""
