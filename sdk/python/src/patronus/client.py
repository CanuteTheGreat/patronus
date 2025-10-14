"""Patronus API client."""

from typing import Optional, List, Dict, Any
import requests
import httpx
from .models import Site, Tunnel, Policy, Organization, Metrics, MLModel
from .exceptions import APIError, AuthenticationError, NotFoundError, RateLimitError


class BaseClient:
    """Base client with common functionality."""

    def __init__(self, api_url: str, api_key: str, timeout: int = 30):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "patronus-python-sdk/0.1.0",
        }

    def _handle_error(self, status_code: int, response_data: dict):
        """Handle API errors."""
        message = response_data.get("error", "Unknown error")

        if status_code == 401:
            raise AuthenticationError(message)
        elif status_code == 404:
            raise NotFoundError(message, status_code, response_data)
        elif status_code == 429:
            raise RateLimitError(message, status_code, response_data)
        else:
            raise APIError(message, status_code, response_data)


class SitesAPI:
    """Sites management API."""

    def __init__(self, client):
        self.client = client

    def list(self) -> List[Site]:
        """List all sites."""
        raise NotImplementedError("Sync implementation")

    def get(self, site_id: str) -> Site:
        """Get a site by ID."""
        raise NotImplementedError("Sync implementation")

    def create(
        self, name: str, location: str, wan_interfaces: List[str], **kwargs
    ) -> Site:
        """Create a new site."""
        raise NotImplementedError("Sync implementation")

    def update(self, site_id: str, **kwargs) -> Site:
        """Update a site."""
        raise NotImplementedError("Sync implementation")

    def delete(self, site_id: str) -> None:
        """Delete a site."""
        raise NotImplementedError("Sync implementation")


class TunnelsAPI:
    """Tunnels management API."""

    def __init__(self, client):
        self.client = client

    def list(self) -> List[Tunnel]:
        """List all tunnels."""
        raise NotImplementedError("Sync implementation")

    def get(self, tunnel_id: str) -> Tunnel:
        """Get a tunnel by ID."""
        raise NotImplementedError("Sync implementation")

    def create(
        self, name: str, local_site_id: str, remote_site_id: str, protocol: str
    ) -> Tunnel:
        """Create a new tunnel."""
        raise NotImplementedError("Sync implementation")

    def get_status(self, tunnel_id: str) -> Dict[str, Any]:
        """Get tunnel status."""
        raise NotImplementedError("Sync implementation")

    def delete(self, tunnel_id: str) -> None:
        """Delete a tunnel."""
        raise NotImplementedError("Sync implementation")


class PoliciesAPI:
    """Policies management API."""

    def __init__(self, client):
        self.client = client

    def list(self) -> List[Policy]:
        """List all policies."""
        raise NotImplementedError("Sync implementation")

    def get(self, policy_id: str) -> Policy:
        """Get a policy by ID."""
        raise NotImplementedError("Sync implementation")

    def create(self, name: str, rules: List[Dict], **kwargs) -> Policy:
        """Create a new policy."""
        raise NotImplementedError("Sync implementation")

    def delete(self, policy_id: str) -> None:
        """Delete a policy."""
        raise NotImplementedError("Sync implementation")


class OrganizationsAPI:
    """Organizations management API."""

    def __init__(self, client):
        self.client = client

    def list(self) -> List[Organization]:
        """List all organizations."""
        raise NotImplementedError("Sync implementation")

    def get(self, org_id: str) -> Organization:
        """Get an organization by ID."""
        raise NotImplementedError("Sync implementation")

    def create(self, name: str, display_name: str, **kwargs) -> Organization:
        """Create a new organization."""
        raise NotImplementedError("Sync implementation")


class MetricsAPI:
    """Metrics API."""

    def __init__(self, client):
        self.client = client

    def query(
        self, metric_name: str, start_time: str, end_time: str, **kwargs
    ) -> Metrics:
        """Query metrics."""
        raise NotImplementedError("Sync implementation")


class MLModelsAPI:
    """ML Models API."""

    def __init__(self, client):
        self.client = client

    def list(self) -> List[MLModel]:
        """List all ML models."""
        raise NotImplementedError("Sync implementation")

    def get(self, model_id: str) -> MLModel:
        """Get an ML model by ID."""
        raise NotImplementedError("Sync implementation")

    def deploy(self, model_id: str) -> MLModel:
        """Deploy an ML model."""
        raise NotImplementedError("Sync implementation")


class PatronusClient(BaseClient):
    """Synchronous Patronus API client."""

    def __init__(self, api_url: str, api_key: str, timeout: int = 30):
        super().__init__(api_url, api_key, timeout)
        self.sites = SitesAPI(self)
        self.tunnels = TunnelsAPI(self)
        self.policies = PoliciesAPI(self)
        self.organizations = OrganizationsAPI(self)
        self.metrics = MetricsAPI(self)
        self.ml_models = MLModelsAPI(self)


class AsyncSitesAPI:
    """Async sites management API."""

    def __init__(self, client):
        self.client = client

    async def list(self) -> List[Site]:
        """List all sites."""
        url = f"{self.client.api_url}/api/v1/sites"
        async with httpx.AsyncClient() as http_client:
            response = await http_client.get(
                url, headers=self.client._get_headers(), timeout=self.client.timeout
            )

            if response.status_code != 200:
                self.client._handle_error(response.status_code, response.json())

            data = response.json()
            return [Site(**item) for item in data["sites"]]

    async def get(self, site_id: str) -> Site:
        """Get a site by ID."""
        url = f"{self.client.api_url}/api/v1/sites/{site_id}"
        async with httpx.AsyncClient() as http_client:
            response = await http_client.get(
                url, headers=self.client._get_headers(), timeout=self.client.timeout
            )

            if response.status_code != 200:
                self.client._handle_error(response.status_code, response.json())

            return Site(**response.json())

    async def create(
        self, name: str, location: str, wan_interfaces: List[str], **kwargs
    ) -> Site:
        """Create a new site."""
        url = f"{self.client.api_url}/api/v1/sites"
        data = {
            "name": name,
            "location": location,
            "wan_interfaces": wan_interfaces,
            **kwargs,
        }

        async with httpx.AsyncClient() as http_client:
            response = await http_client.post(
                url,
                json=data,
                headers=self.client._get_headers(),
                timeout=self.client.timeout,
            )

            if response.status_code != 201:
                self.client._handle_error(response.status_code, response.json())

            return Site(**response.json())

    async def delete(self, site_id: str) -> None:
        """Delete a site."""
        url = f"{self.client.api_url}/api/v1/sites/{site_id}"
        async with httpx.AsyncClient() as http_client:
            response = await http_client.delete(
                url, headers=self.client._get_headers(), timeout=self.client.timeout
            )

            if response.status_code != 204:
                self.client._handle_error(response.status_code, response.json())


class AsyncTunnelsAPI:
    """Async tunnels management API."""

    def __init__(self, client):
        self.client = client

    async def list(self) -> List[Tunnel]:
        """List all tunnels."""
        url = f"{self.client.api_url}/api/v1/tunnels"
        async with httpx.AsyncClient() as http_client:
            response = await http_client.get(
                url, headers=self.client._get_headers(), timeout=self.client.timeout
            )

            if response.status_code != 200:
                self.client._handle_error(response.status_code, response.json())

            data = response.json()
            return [Tunnel(**item) for item in data["tunnels"]]

    async def create(
        self, name: str, local_site_id: str, remote_site_id: str, protocol: str
    ) -> Tunnel:
        """Create a new tunnel."""
        url = f"{self.client.api_url}/api/v1/tunnels"
        data = {
            "name": name,
            "local_site_id": local_site_id,
            "remote_site_id": remote_site_id,
            "protocol": protocol,
        }

        async with httpx.AsyncClient() as http_client:
            response = await http_client.post(
                url,
                json=data,
                headers=self.client._get_headers(),
                timeout=self.client.timeout,
            )

            if response.status_code != 201:
                self.client._handle_error(response.status_code, response.json())

            return Tunnel(**response.json())


class AsyncPatronusClient(BaseClient):
    """Asynchronous Patronus API client."""

    def __init__(self, api_url: str, api_key: str, timeout: int = 30):
        super().__init__(api_url, api_key, timeout)
        self.sites = AsyncSitesAPI(self)
        self.tunnels = AsyncTunnelsAPI(self)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass
