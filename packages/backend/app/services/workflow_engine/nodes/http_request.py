"""
HTTP Request Node Executor

Makes HTTP API calls as part of workflow execution.
"""

import json
import time
from typing import Any

import httpx

from app.services.workflow_engine.nodes.base import NodeExecutor, NodeResult
from app.services.workflow_engine.context import ExecutionContext


class HTTPRequestExecutor(NodeExecutor):
    """
    Executes HTTP requests.

    Config:
    - method: HTTP method (GET, POST, PUT, PATCH, DELETE)
    - url: Request URL
    - headers: Request headers
    - query_params: URL query parameters
    - body: Request body (for POST/PUT/PATCH)
    - content_type: Content type (default: application/json)
    - timeout_seconds: Request timeout
    - verify_ssl: Whether to verify SSL certificates
    """

    async def execute(self, context: ExecutionContext) -> NodeResult:
        """Execute HTTP request."""
        start_time = time.time()

        try:
            method = self.config.get("method", "GET").upper()
            url = self.config.get("url", "")
            if not url:
                return NodeResult(
                    success=False,
                    error="URL is required",
                )

            headers = self.config.get("headers", {})
            content_type = self.config.get("content_type", "application/json")
            if content_type and "Content-Type" not in headers:
                headers["Content-Type"] = content_type

            query_params = self.config.get("query_params", {})
            body = self.config.get("body")
            timeout = self.config.get("timeout_seconds", 30)
            verify_ssl = self.config.get("verify_ssl", True)

            # Prepare body
            content = None
            if body is not None and method not in ("GET", "HEAD", "OPTIONS"):
                if content_type == "application/json":
                    content = json.dumps(body) if not isinstance(body, str) else body
                else:
                    content = str(body)

            # Make request
            async with httpx.AsyncClient(
                timeout=float(timeout),
                verify=verify_ssl,
                follow_redirects=True,
            ) as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=query_params,
                    content=content,
                )

            duration_ms = int((time.time() - start_time) * 1000)

            # Parse response
            try:
                response_body = response.json()
            except json.JSONDecodeError:
                response_body = response.text

            output = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response_body,
                "duration_ms": duration_ms,
            }

            if response.status_code < 400:
                return NodeResult(
                    success=True,
                    output=output,
                    next_handle="default",
                )
            else:
                return NodeResult(
                    success=False,
                    output=output,
                    error=f"HTTP {response.status_code}",
                )

        except httpx.TimeoutException:
            return NodeResult(
                success=False,
                error="Request timed out",
            )
        except Exception as e:
            return NodeResult(
                success=False,
                error=str(e),
            )
