"""
HTTP Action Connector

Makes arbitrary HTTP requests for workflow automation.
"""

import time
import json
from typing import Any

import httpx

from app.db.models import ConnectorCategory
from app.services.connectors.base import (
    ActionConnector,
    ConnectorMetadata,
    ConnectionTestResult,
    ActionResult,
)


class HTTPActionConnector(ActionConnector):
    """
    Generic HTTP action connector for making API calls.

    Supports all HTTP methods with flexible authentication options.
    Used for integrating with any REST API in workflows.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="http",
            category=ConnectorCategory.ACTION,
            display_name="HTTP Request",
            description="HTTP Request - Make calls to any REST API",
            icon="http",
            config_schema={
                "type": "object",
                "properties": {
                    "base_url": {
                        "type": "string",
                        "title": "Base URL",
                        "description": "Base URL for API requests (optional)",
                    },
                    "default_headers": {
                        "type": "object",
                        "title": "Default Headers",
                        "description": "Headers included in all requests",
                    },
                    "verify_ssl": {
                        "type": "boolean",
                        "title": "Verify SSL",
                        "description": "Verify SSL certificates",
                        "default": True,
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "title": "Timeout",
                        "description": "Request timeout in seconds",
                        "default": 30,
                    },
                },
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "auth_type": {
                        "type": "string",
                        "enum": ["none", "basic", "bearer", "api_key", "custom_header"],
                        "title": "Authentication Type",
                        "description": "Type of authentication",
                        "default": "none",
                    },
                    "username": {
                        "type": "string",
                        "title": "Username",
                        "description": "Username for basic auth",
                    },
                    "password": {
                        "type": "string",
                        "title": "Password",
                        "description": "Password for basic auth",
                        "format": "password",
                    },
                    "bearer_token": {
                        "type": "string",
                        "title": "Bearer Token",
                        "description": "Bearer token for authorization",
                        "format": "password",
                    },
                    "api_key": {
                        "type": "string",
                        "title": "API Key",
                        "description": "API key value",
                        "format": "password",
                    },
                    "api_key_header": {
                        "type": "string",
                        "title": "API Key Header",
                        "description": "Header name for API key (default: X-API-Key)",
                        "default": "X-API-Key",
                    },
                    "custom_auth_header": {
                        "type": "string",
                        "title": "Custom Auth Header",
                        "description": "Custom header name for authentication",
                    },
                    "custom_auth_value": {
                        "type": "string",
                        "title": "Custom Auth Value",
                        "description": "Custom header value for authentication",
                        "format": "password",
                    },
                },
            },
        )

    @classmethod
    def get_action_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
                    "title": "Method",
                    "description": "HTTP method",
                    "default": "GET",
                },
                "url": {
                    "type": "string",
                    "title": "URL",
                    "description": "Request URL (appended to base_url if configured)",
                },
                "headers": {
                    "type": "object",
                    "title": "Headers",
                    "description": "Additional request headers",
                },
                "query_params": {
                    "type": "object",
                    "title": "Query Parameters",
                    "description": "URL query parameters",
                },
                "body": {
                    "oneOf": [
                        {"type": "object"},
                        {"type": "string"},
                        {"type": "array"},
                    ],
                    "title": "Body",
                    "description": "Request body (JSON or string)",
                },
                "content_type": {
                    "type": "string",
                    "title": "Content Type",
                    "description": "Request content type",
                    "default": "application/json",
                },
                "follow_redirects": {
                    "type": "boolean",
                    "title": "Follow Redirects",
                    "description": "Follow HTTP redirects",
                    "default": True,
                },
                "expect_json": {
                    "type": "boolean",
                    "title": "Expect JSON",
                    "description": "Parse response as JSON",
                    "default": True,
                },
            },
            "required": ["method", "url"],
        }

    def _build_auth(self) -> tuple[str, str] | None:
        """Build basic auth tuple if configured."""
        auth_type = self.credentials.get("auth_type", "none")
        if auth_type == "basic":
            return (
                self.credentials.get("username", ""),
                self.credentials.get("password", ""),
            )
        return None

    def _build_headers(self, action_headers: dict[str, str] | None = None) -> dict[str, str]:
        """Build request headers including auth and custom headers."""
        headers = {}

        # Add default headers
        if self.config.get("default_headers"):
            headers.update(self.config["default_headers"])

        # Add auth headers
        auth_type = self.credentials.get("auth_type", "none")
        if auth_type == "bearer":
            headers["Authorization"] = f"Bearer {self.credentials.get('bearer_token', '')}"
        elif auth_type == "api_key":
            header_name = self.credentials.get("api_key_header", "X-API-Key")
            headers[header_name] = self.credentials.get("api_key", "")
        elif auth_type == "custom_header":
            header_name = self.credentials.get("custom_auth_header", "Authorization")
            headers[header_name] = self.credentials.get("custom_auth_value", "")

        # Add action-specific headers
        if action_headers:
            headers.update(action_headers)

        return headers

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection by making a simple request."""
        start_time = time.time()
        try:
            base_url = self.config.get("base_url", "")
            if not base_url:
                return ConnectionTestResult(
                    success=True,
                    message="HTTP connector configured (no base URL to test)",
                    details={"auth_type": self.credentials.get("auth_type", "none")},
                )

            verify_ssl = self.config.get("verify_ssl", True)
            timeout = self.config.get("timeout_seconds", 30)

            async with httpx.AsyncClient(timeout=float(timeout), verify=verify_ssl) as client:
                response = await client.head(
                    base_url,
                    headers=self._build_headers(),
                    auth=self._build_auth(),
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code < 500:
                return ConnectionTestResult(
                    success=True,
                    message="HTTP endpoint is reachable",
                    details={"base_url": base_url, "status": response.status_code},
                    latency_ms=latency_ms,
                )
            else:
                return ConnectionTestResult(
                    success=False,
                    message=f"HTTP endpoint returned status {response.status_code}",
                    latency_ms=latency_ms,
                )

        except Exception as e:
            return ConnectionTestResult(
                success=False,
                message=f"Connection error: {str(e)}",
            )

    async def execute(self, action_config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Execute an HTTP request."""
        start_time = time.time()

        try:
            # Build URL
            base_url = self.config.get("base_url", "")
            url = action_config.get("url", "")
            if base_url and not url.startswith("http"):
                full_url = f"{base_url.rstrip('/')}/{url.lstrip('/')}"
            else:
                full_url = url

            if not full_url:
                return ActionResult(
                    success=False,
                    message="URL is required",
                    error="No URL provided",
                )

            # Build request
            method = action_config.get("method", "GET")
            headers = self._build_headers(action_config.get("headers"))
            content_type = action_config.get("content_type", "application/json")
            headers["Content-Type"] = content_type

            verify_ssl = self.config.get("verify_ssl", True)
            timeout = self.config.get("timeout_seconds", 30)
            follow_redirects = action_config.get("follow_redirects", True)

            # Prepare body
            body = action_config.get("body")
            content = None
            if body is not None and method not in ("GET", "HEAD", "OPTIONS"):
                if content_type == "application/json":
                    content = json.dumps(body)
                elif isinstance(body, str):
                    content = body
                else:
                    content = str(body)

            # Make request
            async with httpx.AsyncClient(
                timeout=float(timeout),
                verify=verify_ssl,
                follow_redirects=follow_redirects,
            ) as client:
                response = await client.request(
                    method=method,
                    url=full_url,
                    headers=headers,
                    auth=self._build_auth(),
                    params=action_config.get("query_params"),
                    content=content,
                )

            execution_time_ms = int((time.time() - start_time) * 1000)

            # Parse response
            response_body: Any
            if action_config.get("expect_json", True):
                try:
                    response_body = response.json()
                except json.JSONDecodeError:
                    response_body = response.text
            else:
                response_body = response.text

            output = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response_body,
            }

            if response.status_code < 400:
                return ActionResult(
                    success=True,
                    message=f"HTTP {method} {response.status_code}",
                    output=output,
                    execution_time_ms=execution_time_ms,
                )
            else:
                return ActionResult(
                    success=False,
                    message=f"HTTP {method} failed with status {response.status_code}",
                    error=str(response_body)[:500] if response_body else f"Status {response.status_code}",
                    output=output,
                    execution_time_ms=execution_time_ms,
                )

        except httpx.TimeoutException:
            return ActionResult(
                success=False,
                message="HTTP request timed out",
                error="Request timed out",
                execution_time_ms=int((time.time() - start_time) * 1000),
            )
        except Exception as e:
            return ActionResult(
                success=False,
                message=f"HTTP request failed: {str(e)}",
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000),
            )
