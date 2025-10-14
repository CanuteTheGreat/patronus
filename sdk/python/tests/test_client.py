"""Tests for API client."""

import pytest
from patronus.client import PatronusClient, AsyncPatronusClient, BaseClient
from patronus.exceptions import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    APIError,
)


def test_client_initialization():
    """Test client initialization."""
    client = PatronusClient(api_url="https://api.patronus.io", api_key="test-key")

    assert client.api_url == "https://api.patronus.io"
    assert client.api_key == "test-key"
    assert client.timeout == 30


def test_client_strips_trailing_slash():
    """Test that API URL trailing slashes are stripped."""
    client = PatronusClient(api_url="https://api.patronus.io/", api_key="test-key")

    assert client.api_url == "https://api.patronus.io"


def test_client_has_api_modules():
    """Test that client has API modules."""
    client = PatronusClient(api_url="https://api.patronus.io", api_key="test-key")

    assert hasattr(client, "sites")
    assert hasattr(client, "tunnels")
    assert hasattr(client, "policies")
    assert hasattr(client, "organizations")
    assert hasattr(client, "metrics")
    assert hasattr(client, "ml_models")


def test_client_headers():
    """Test client request headers."""
    client = PatronusClient(api_url="https://api.patronus.io", api_key="test-key")

    headers = client._get_headers()

    assert headers["Authorization"] == "Bearer test-key"
    assert headers["Content-Type"] == "application/json"
    assert "patronus-python-sdk" in headers["User-Agent"]


def test_handle_authentication_error():
    """Test authentication error handling."""
    client = PatronusClient(api_url="https://api.patronus.io", api_key="test-key")

    with pytest.raises(AuthenticationError):
        client._handle_error(401, {"error": "Unauthorized"})


def test_handle_not_found_error():
    """Test not found error handling."""
    client = PatronusClient(api_url="https://api.patronus.io", api_key="test-key")

    with pytest.raises(NotFoundError) as exc_info:
        client._handle_error(404, {"error": "Resource not found"})

    assert exc_info.value.status_code == 404


def test_handle_rate_limit_error():
    """Test rate limit error handling."""
    client = PatronusClient(api_url="https://api.patronus.io", api_key="test-key")

    with pytest.raises(RateLimitError) as exc_info:
        client._handle_error(429, {"error": "Rate limit exceeded"})

    assert exc_info.value.status_code == 429


def test_handle_generic_api_error():
    """Test generic API error handling."""
    client = PatronusClient(api_url="https://api.patronus.io", api_key="test-key")

    with pytest.raises(APIError) as exc_info:
        client._handle_error(500, {"error": "Internal server error"})

    assert exc_info.value.status_code == 500


def test_async_client_initialization():
    """Test async client initialization."""
    client = AsyncPatronusClient(api_url="https://api.patronus.io", api_key="test-key")

    assert client.api_url == "https://api.patronus.io"
    assert client.api_key == "test-key"


def test_async_client_has_api_modules():
    """Test that async client has API modules."""
    client = AsyncPatronusClient(api_url="https://api.patronus.io", api_key="test-key")

    assert hasattr(client, "sites")
    assert hasattr(client, "tunnels")


@pytest.mark.asyncio
async def test_async_client_context_manager():
    """Test async client context manager."""
    async with AsyncPatronusClient(
        api_url="https://api.patronus.io", api_key="test-key"
    ) as client:
        assert client.api_url == "https://api.patronus.io"


def test_base_client():
    """Test BaseClient functionality."""
    client = BaseClient(
        api_url="https://api.patronus.io", api_key="test-key", timeout=60
    )

    assert client.api_url == "https://api.patronus.io"
    assert client.api_key == "test-key"
    assert client.timeout == 60


def test_client_custom_timeout():
    """Test client with custom timeout."""
    client = PatronusClient(
        api_url="https://api.patronus.io", api_key="test-key", timeout=120
    )

    assert client.timeout == 120
