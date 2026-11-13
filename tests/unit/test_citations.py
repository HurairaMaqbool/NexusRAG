"""
tests/unit/test_citations.py — Unit tests for CitationVerifier
"""

from secure_rag.security.citations import CitationVerifier


def test_verify_citations_valid():
    verifier = CitationVerifier()
    answer = "Employees accrue 20 vacation days per year [1] and receive 12 weeks parental leave [2]."
    chunks = [
        {"chunk_id": "c-1", "source_file": "Handbook.pdf", "text": "Employees accrue 20 vacation days per year."},
        {"chunk_id": "c-2", "source_file": "ParentalPolicy.pdf", "text": "Parental leave covers 12 weeks fully paid."},
    ]
    citations = verifier.verify_citations(answer, chunks)
    assert len(citations) == 2
    assert citations[0].citation_id == 1
    assert citations[0].source_file == "Handbook.pdf"
    assert citations[0].verified
    assert citations[1].citation_id == 2
    assert citations[1].source_file == "ParentalPolicy.pdf"
    assert citations[1].verified


def test_verify_citations_out_of_bounds():
    verifier = CitationVerifier()
    answer = "This references an unprovided source [99]."
    chunks = [
        {"chunk_id": "c-1", "source_file": "Handbook.pdf", "text": "Some text."},
    ]
    citations = verifier.verify_citations(answer, chunks)
    # Citation 99 exceeds chunk count, so it is safely ignored
    assert len(citations) == 0
