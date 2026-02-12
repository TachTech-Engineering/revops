"""Exceptions for the Splunk SPL to Panther converter."""

from __future__ import annotations

from typing import Any


class SPLConversionError(Exception):
    """Base exception for SPL conversion errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        self.message = message
        self.details = details or {}
        super().__init__(message)


class SPLLexerError(SPLConversionError):
    """Raised when the lexer encounters an invalid token."""

    def __init__(
        self,
        message: str,
        position: int | None = None,
        line: int | None = None,
        column: int | None = None,
    ) -> None:
        self.position = position
        self.line = line
        self.column = column
        details = {"position": position, "line": line, "column": column}
        super().__init__(message, details)


class SPLParserError(SPLConversionError):
    """Raised when the parser encounters a syntax error."""

    def __init__(
        self,
        message: str,
        token: Any | None = None,
        expected: str | None = None,
    ) -> None:
        self.token = token
        self.expected = expected
        details = {"token": str(token), "expected": expected}
        super().__init__(message, details)


class SPLSemanticError(SPLConversionError):
    """Raised when semantic analysis fails."""

    pass


class SPLUnsupportedFeatureError(SPLConversionError):
    """Raised when an unsupported SPL feature is encountered."""

    def __init__(self, feature: str, suggestion: str | None = None) -> None:
        self.feature = feature
        self.suggestion = suggestion
        message = f"Unsupported SPL feature: {feature}"
        if suggestion:
            message += f". Suggestion: {suggestion}"
        details = {"feature": feature, "suggestion": suggestion}
        super().__init__(message, details)


class SPLTransformError(SPLConversionError):
    """Raised when transformation to Python fails."""

    pass


class SPLCodeGenerationError(SPLConversionError):
    """Raised when code generation fails."""

    pass
