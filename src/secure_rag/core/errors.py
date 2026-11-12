"""
src/secure_rag/core/errors.py — Custom Exception Taxonomy
"""

class SecureRAGError(Exception):
    """Base exception for all domain errors within Secure RAG Platform."""
    pass

class DatabaseError(SecureRAGError):
    """Base exception for database failures."""
    pass

class RecordNotFoundError(DatabaseError):
    """Raised when an expected database record does not exist."""
    pass

class UniqueConstraintError(DatabaseError):
    """Raised when an operation violates a unique index or constraint."""
    pass

class AuthenticationError(SecureRAGError):
    """Raised when authentication or session validation fails."""
    pass

class RateLimitExceededError(AuthenticationError):
    """Raised when request frequency exceeds allowed limits."""
    pass

class SecurityConfigurationError(SecureRAGError):
    """Raised when runtime security configuration or environment is invalid."""
    pass

class AuthorizationError(SecureRAGError):
    """Raised when a user or role attempts an action outside their permissions."""
    pass

class DocumentValidationError(SecureRAGError):
    """Raised when a document fails structural, format, or limit validation."""
    pass

class DuplicateDocumentError(SecureRAGError):
    """Raised when document deduplication detects conflicting access levels for identical content."""
    pass

class VectorStoreError(SecureRAGError):
    """Raised when vector store operations (ChromaDB) fail."""
    pass

class LLMProviderError(SecureRAGError):
    """Raised when an LLM provider fails to generate a response."""
    pass
