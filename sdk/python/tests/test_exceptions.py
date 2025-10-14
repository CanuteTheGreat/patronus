"""Tests for exceptions."""

import pytest
from patronus.exceptions import (
    PatronusError,
    APIError,
    AuthenticationError,
    ValidationError,
    NotFoundError,
    RateLimitError,
)


def test_patronus_error():
    """Test base PatronusError."""
    error = PatronusError("Something went wrong")

    assert str(error) == "Something went wrong"
    assert isinstance(error, Exception)


def test_api_error():
    """Test APIError."""
    error = APIError("API request failed", status_code=500, response={"detail": "error"})

    assert str(error) == "API request failed"
    assert error.status_code == 500
    assert error.response == {"detail": "error"}
    assert isinstance(error, PatronusError)


def test_api_error_without_details():
    """Test APIError without status code and response."""
    error = APIError("API request failed")

    assert str(error) == "API request failed"
    assert error.status_code is None
    assert error.response is None


def test_authentication_error():
    """Test AuthenticationError."""
    error = AuthenticationError("Invalid API key")

    assert str(error) == "Invalid API key"
    assert isinstance(error, PatronusError)


def test_validation_error():
    """Test ValidationError."""
    error = ValidationError("Invalid input")

    assert str(error) == "Invalid input"
    assert isinstance(error, PatronusError)


def test_not_found_error():
    """Test NotFoundError."""
    error = NotFoundError("Resource not found", status_code=404)

    assert str(error) == "Resource not found"
    assert error.status_code == 404
    assert isinstance(error, APIError)


def test_rate_limit_error():
    """Test RateLimitError."""
    error = RateLimitError("Rate limit exceeded", status_code=429)

    assert str(error) == "Rate limit exceeded"
    assert error.status_code == 429
    assert isinstance(error, APIError)


def test_exception_hierarchy():
    """Test exception hierarchy."""
    # All exceptions should inherit from PatronusError
    assert issubclass(APIError, PatronusError)
    assert issubclass(AuthenticationError, PatronusError)
    assert issubclass(ValidationError, PatronusError)
    assert issubclass(NotFoundError, APIError)
    assert issubclass(RateLimitError, APIError)


def test_raising_exceptions():
    """Test raising exceptions."""
    with pytest.raises(PatronusError):
        raise PatronusError("test")

    with pytest.raises(APIError):
        raise APIError("test", status_code=500)

    with pytest.raises(AuthenticationError):
        raise AuthenticationError("test")

    with pytest.raises(NotFoundError):
        raise NotFoundError("test", status_code=404)

    with pytest.raises(RateLimitError):
        raise RateLimitError("test", status_code=429)
