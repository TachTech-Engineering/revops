"""
Webhook Action Connector

Sends HTTP webhook notifications to arbitrary endpoints.
"""

import time
import json
import hmac
import hashlib
from typing import Any

import httpx

from app.db.models import ConnectorCategory
from app.services.connectors.base import (
    ActionConnector,
    ConnectorMetadata,
    ConnectionTestResult,
    ActionResult,
)


class WebhookActionConnector(ActionConnector):
    """
    Generic webhook action connector.

    Sends POST requests to configured webhook URLs with
    optional HMAC signature for authentication.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="webhook",
            category=ConnectorCategory.ACTION,
            display_name="Webhook",
            description="Generic webhook - Send data to any HTTP endpoint",
            icon="webhook",
            config_schema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "title": "Webhook URL",
                        "description": "Destination URL for webhook delivery",
                        "format": "uri",
                    },
                    "method": {
                        "type": "string",
                        "enum": ["POST", "PUT", "PATCH"],
                        "title": "HTTP Method",
                        "description": "HTTP method for requests",
                        "default": "POST",
                    },
                    "content_type": {
                        "type": "string",
                        "enum": ["application/json", "application/x-www-form-urlencoded", "text/plain"],
                        "title": "Content Type",
                        "description": "Request content type",
                        "default": "application/json",
                    },
                    "headers": {
                        "type": "object",
                        "title": "Custom Headers",
                        "description": "Additional HTTP headers",
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
                "required": ["url"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "secret": {
                        "type": "string",
                        "title": "Signing Secret",
                        "description": "HMAC secret for request signing (optional)",
                        "format": "password",
                    },
                    "auth_header": {
                        "type": "string",
                        "title": "Authorization Header",
                        "description": "Value for Authorization header (e.g., 'Bearer token')",
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
                "payload": {
                    "type": "object",
                    "title": "Payload",
                    "description": "JSON payload to send",
                },
                "url_override": {
                    "type": "string",
                    "title": "URL Override",
                    "description": "Override the configured URL",
                },
                "headers_override": {
                    "type": "object",
                    "title": "Headers Override",
                    "description": "Additional headers for this request",
                },
            },
        }

    def _sign_payload(self, payload: bytes) -> str:
        """Generate HMAC signature for payload."""
        secret = self.credentials.get("secret", "")
        if not secret:
            return ""

        signature = hmac.new(
            secret.encode(),
            payload,
            hashlib.sha256,
        ).hexdigest()

        return f"sha256={signature}"

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to webhook endpoint."""
        start_time = time.time()
        try:
            url = self.config.get("url", "")
            if not url:
                return ConnectionTestResult(
                    success=False,
                    message="Webhook URL is required",
                )

            verify_ssl = self.config.get("verify_ssl", True)
            timeout = self.config.get("timeout_seconds", 30)

            # Send a test ping (HEAD request to verify endpoint exists)
            async with httpx.AsyncClient(timeout=float(timeout), verify=verify_ssl) as client:
                response = await client.head(url)

            latency_ms = int((time.time() - start_time) * 1000)

            # Accept any successful status or 405 (method not allowed - endpoint exists but doesn't support HEAD)
            if response.status_code < 500 or response.status_code == 405:
                return ConnectionTestResult(
                    success=True,
                    message="Webhook endpoint is reachable",
                    details={"url": url, "status": response.status_code},
                    latency_ms=latency_ms,
                )
            else:
                return ConnectionTestResult(
                    success=False,
                    message=f"Webhook endpoint returned status {response.status_code}",
                    latency_ms=latency_ms,
                )

        except httpx.TimeoutException:
            return ConnectionTestResult(
                success=False,
                message="Connection timed out",
            )
        except Exception as e:
            return ConnectionTestResult(
                success=False,
                message=f"Connection error: {str(e)}",
            )

    async def execute(self, action_config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Execute webhook delivery."""
        start_time = time.time()

        try:
            url = action_config.get("url_override") or self.config.get("url")
            if not url:
                return ActionResult(
                    success=False,
                    message="Webhook URL is required",
                    error="No URL configured",
                )

            method = self.config.get("method", "POST")
            content_type = self.config.get("content_type", "application/json")
            verify_ssl = self.config.get("verify_ssl", True)
            timeout = self.config.get("timeout_seconds", 30)

            # Build headers
            headers = {"Content-Type": content_type}
            if self.config.get("headers"):
                headers.update(self.config["headers"])
            if action_config.get("headers_override"):
                headers.update(action_config["headers_override"])

            # Add auth header if configured
            if self.credentials.get("auth_header"):
                headers["Authorization"] = self.credentials["auth_header"]

            # Prepare payload
            payload = action_config.get("payload", {})
            if content_type == "application/json":
                body = json.dumps(payload).encode()
            elif content_type == "application/x-www-form-urlencoded":
                body = "&".join(f"{k}={v}" for k, v in payload.items()).encode()
            else:
                body = str(payload).encode()

            # Add signature if secret is configured
            signature = self._sign_payload(body)
            if signature:
                headers["X-Signature"] = signature
                headers["X-Hub-Signature-256"] = signature

            # Send request
            async with httpx.AsyncClient(timeout=float(timeout), verify=verify_ssl) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body,
                )

            execution_time_ms = int((time.time() - start_time) * 1000)

            # Parse response
            try:
                response_body = response.json()
            except json.JSONDecodeError:
                response_body = response.text[:1000]

            if response.status_code < 400:
                return ActionResult(
                    success=True,
                    message=f"Webhook delivered successfully (status {response.status_code})",
                    output={
                        "status_code": response.status_code,
                        "response": response_body,
                    },
                    execution_time_ms=execution_time_ms,
                )
            else:
                return ActionResult(
                    success=False,
                    message=f"Webhook delivery failed (status {response.status_code})",
                    error=str(response_body),
                    output={"status_code": response.status_code, "response": response_body},
                    execution_time_ms=execution_time_ms,
                )

        except httpx.TimeoutException:
            return ActionResult(
                success=False,
                message="Webhook request timed out",
                error="Request timed out",
                execution_time_ms=int((time.time() - start_time) * 1000),
            )
        except Exception as e:
            return ActionResult(
                success=False,
                message=f"Webhook delivery failed: {str(e)}",
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000),
            )
