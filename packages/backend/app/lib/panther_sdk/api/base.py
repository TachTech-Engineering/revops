"""Base HTTP client for the Panther SDK."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Iterator
from typing import Any, TypeVar

import httpx

from ..config import PantherConfig
from ..exceptions import (
    APIError,
    AuthenticationError,
    AuthorizationError,
    NotFoundError,
    RateLimitError,
    ValidationError,
)

logger = logging.getLogger("panther_sdk")

T = TypeVar("T")


class BaseClient:
    """Base HTTP client with common functionality."""

    def __init__(self, config: PantherConfig) -> None:
        self.config = config
        self._client: httpx.Client | None = None
        self._async_client: httpx.AsyncClient | None = None

    @property
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.config.api_token}",
            "X-API-Key": self.config.api_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "panther-sdk/0.1.0",
        }

    @property
    def client(self) -> httpx.Client:
        """Get or create the sync HTTP client."""
        if self._client is None:
            self._client = httpx.Client(
                base_url=self.config.rest_url,
                headers=self._headers,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )
        return self._client

    @property
    def async_client(self) -> httpx.AsyncClient:
        """Get or create the async HTTP client."""
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(
                base_url=self.config.rest_url,
                headers=self._headers,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )
        return self._async_client

    def close(self) -> None:
        """Close the sync HTTP client."""
        if self._client is not None:
            self._client.close()
            self._client = None

    async def aclose(self) -> None:
        """Close the async HTTP client."""
        if self._async_client is not None:
            await self._async_client.aclose()
            self._async_client = None

    def _handle_response(self, response: httpx.Response) -> dict[str, Any]:
        """Handle HTTP response and raise appropriate exceptions."""
        if self.config.debug:
            logger.debug(f"Response status: {response.status_code}")
            logger.debug(f"Response body: {response.text[:500]}")

        if response.status_code == 204:
            return {}

        try:
            data = response.json() if response.text else {}
        except Exception:
            data = {"raw": response.text}

        if response.is_success:
            return data

        # Handle error responses
        error_message = data.get("message") or data.get("error") or response.reason_phrase

        if response.status_code == 401:
            raise AuthenticationError(error_message, data)
        elif response.status_code == 403:
            raise AuthorizationError(error_message, data)
        elif response.status_code == 404:
            raise NotFoundError("Resource", "unknown", data)
        elif response.status_code == 422:
            raise ValidationError(error_message, data)
        elif response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            raise RateLimitError(
                retry_after=int(retry_after) if retry_after else None,
                details=data,
            )
        else:
            raise APIError(error_message, response.status_code, data)

    def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make a sync HTTP request."""
        if self.config.debug:
            logger.debug(f"Request: {method} {path}")
            if params:
                logger.debug(f"Params: {params}")
            if json:
                logger.debug(f"Body: {json}")

        # Filter out None values from params
        if params:
            params = {k: v for k, v in params.items() if v is not None}

        response = self.client.request(method, path, params=params, json=json, **kwargs)
        return self._handle_response(response)

    async def _arequest(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Make an async HTTP request."""
        if self.config.debug:
            logger.debug(f"Async request: {method} {path}")
            if params:
                logger.debug(f"Params: {params}")
            if json:
                logger.debug(f"Body: {json}")

        # Filter out None values from params
        if params:
            params = {k: v for k, v in params.items() if v is not None}

        response = await self.async_client.request(method, path, params=params, json=json, **kwargs)
        return self._handle_response(response)

    def get(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Make a sync GET request."""
        return self._request("GET", path, **kwargs)

    async def aget(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Make an async GET request."""
        return await self._arequest("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Make a sync POST request."""
        return self._request("POST", path, **kwargs)

    async def apost(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Make an async POST request."""
        return await self._arequest("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Make a sync PUT request."""
        return self._request("PUT", path, **kwargs)

    async def aput(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Make an async PUT request."""
        return await self._arequest("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Make a sync PATCH request."""
        return self._request("PATCH", path, **kwargs)

    async def apatch(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Make an async PATCH request."""
        return await self._arequest("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Make a sync DELETE request."""
        return self._request("DELETE", path, **kwargs)

    async def adelete(self, path: str, **kwargs: Any) -> dict[str, Any]:
        """Make an async DELETE request."""
        return await self._arequest("DELETE", path, **kwargs)


class PaginatedResource:
    """Mixin for resources that support pagination."""

    def _paginate(
        self,
        client: BaseClient,
        path: str,
        params: dict[str, Any] | None = None,
        page_size: int = 50,
        max_items: int | None = None,
        results_key: str = "results",
    ) -> Iterator[dict[str, Any]]:
        """Iterate over paginated results synchronously."""
        params = params or {}
        params["pageSize"] = page_size
        cursor: str | None = None
        items_yielded = 0

        while True:
            if cursor:
                params["cursor"] = cursor

            response = client.get(path, params=params)
            items = response.get(results_key, [])

            for item in items:
                yield item
                items_yielded += 1
                if max_items and items_yielded >= max_items:
                    return

            cursor = response.get("cursor")
            if not cursor or not items:
                break

    async def _apaginate(
        self,
        client: BaseClient,
        path: str,
        params: dict[str, Any] | None = None,
        page_size: int = 50,
        max_items: int | None = None,
        results_key: str = "results",
    ) -> AsyncIterator[dict[str, Any]]:
        """Iterate over paginated results asynchronously."""
        params = params or {}
        params["pageSize"] = page_size
        cursor: str | None = None
        items_yielded = 0

        while True:
            if cursor:
                params["cursor"] = cursor

            response = await client.aget(path, params=params)
            items = response.get(results_key, [])

            for item in items:
                yield item
                items_yielded += 1
                if max_items and items_yielded >= max_items:
                    return

            cursor = response.get("cursor")
            if not cursor or not items:
                break
