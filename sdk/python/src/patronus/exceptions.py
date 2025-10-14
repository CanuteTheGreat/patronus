"""Exceptions for Patronus SDK."""


class PatronusError(Exception):
    """Base exception for Patronus SDK."""

    pass


class APIError(PatronusError):
    """API request error."""

    def __init__(self, message: str, status_code: int = None, response: dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class AuthenticationError(PatronusError):
    """Authentication error."""

    pass


class ValidationError(PatronusError):
    """Validation error."""

    pass


class NotFoundError(APIError):
    """Resource not found error."""

    pass


class RateLimitError(APIError):
    """Rate limit exceeded error."""

    pass
