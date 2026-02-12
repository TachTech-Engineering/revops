"""Custom exceptions for the Panther SDK."""

from __future__ import annotations

from typing import Any


class PantherError(Exception):
    """Base exception for all Panther SDK errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(message)


class ConfigurationError(PantherError):
    """Raised when there's a configuration problem."""

    pass


class AuthenticationError(PantherError):
    """Raised when authentication fails."""

    pass


class AuthorizationError(PantherError):
    """Raised when the user lacks permission for an operation."""

    pass


class NotFoundError(PantherError):
    """Raised when a requested resource is not found."""

    def __init__(
        self, resource_type: str, resource_id: str, details: dict[str, Any] | None = None
    ) -> None:
        self.resource_type = resource_type
        self.resource_id = resource_id
        message = f"{resource_type} not found: {resource_id}"
        super().__init__(message, details)


class ValidationError(PantherError):
    """Raised when request validation fails."""

    pass


class RateLimitError(PantherError):
    """Raised when API rate limit is exceeded."""

    def __init__(
        self, retry_after: int | None = None, details: dict[str, Any] | None = None
    ) -> None:
        self.retry_after = retry_after
        message = "Rate limit exceeded"
        if retry_after:
            message += f". Retry after {retry_after} seconds"
        super().__init__(message, details)


class APIError(PantherError):
    """Raised for general API errors."""

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        response_body: dict[str, Any] | None = None,
    ) -> None:
        self.status_code = status_code
        self.response_body = response_body
        details = {"status_code": status_code, "response_body": response_body}
        super().__init__(message, details)


class GraphQLError(PantherError):
    """Raised for GraphQL-specific errors."""

    def __init__(self, errors: list[dict[str, Any]]) -> None:
        self.errors = errors
        messages = [e.get("message", str(e)) for e in errors]
        message = "GraphQL errors: " + "; ".join(messages)
        super().__init__(message, {"errors": errors})


class DetectionError(PantherError):
    """Base exception for detection-related errors."""

    pass


class DetectionTestError(DetectionError):
    """Raised when a detection test fails."""

    def __init__(
        self,
        test_name: str,
        expected: Any,
        actual: Any,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.test_name = test_name
        self.expected = expected
        self.actual = actual
        message = f"Test '{test_name}' failed: expected {expected}, got {actual}"
        super().__init__(message, details)
