"""
SentinelOne Action Connector

Executes response actions via SentinelOne API.
"""

import time
from typing import Any

import httpx

from app.db.models import ConnectorCategory
from app.services.connectors.base import (
    ActionConnector,
    ConnectorMetadata,
    ConnectionTestResult,
    ActionResult,
)


class SentinelOneActionConnector(ActionConnector):
    """
    SentinelOne action connector for EDR response actions.

    Supports network isolation, threat mitigation, and agent management.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="sentinelone",
            category=ConnectorCategory.ACTION,
            display_name="SentinelOne",
            description="SentinelOne - Autonomous endpoint protection",
            icon="sentinelone",
            config_schema={
                "type": "object",
                "properties": {
                    "base_url": {
                        "type": "string",
                        "title": "Base URL",
                        "description": "SentinelOne console URL (e.g., https://usea1-partners.sentinelone.net)",
                    },
                },
                "required": ["base_url"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "api_token": {
                        "type": "string",
                        "title": "API Token",
                        "description": "SentinelOne API token",
                        "format": "password",
                    },
                },
                "required": ["api_token"],
            },
        )

    @classmethod
    def get_action_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "disconnect_from_network",
                        "reconnect_to_network",
                        "initiate_scan",
                        "abort_scan",
                        "mitigate_threat",
                    ],
                    "title": "Action",
                    "description": "Action to perform",
                },
                "agent_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "title": "Agent IDs",
                    "description": "SentinelOne agent IDs",
                },
                "threat_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "title": "Threat IDs",
                    "description": "Threat IDs for mitigation actions",
                },
                "hostname": {
                    "type": "string",
                    "title": "Hostname",
                    "description": "Hostname to look up (alternative to agent_ids)",
                },
                "mitigation_action": {
                    "type": "string",
                    "enum": ["kill", "quarantine", "remediate", "rollback"],
                    "title": "Mitigation Action",
                    "description": "Threat mitigation action type",
                    "default": "quarantine",
                },
            },
            "required": ["action"],
        }

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with authentication."""
        return {
            "Authorization": f"ApiToken {self.credentials.get('api_token', '')}",
            "Content-Type": "application/json",
        }

    def _get_base_url(self) -> str:
        """Get the SentinelOne API base URL."""
        return self.config.get("base_url", "").rstrip("/")

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to SentinelOne API."""
        start_time = time.time()
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self._get_base_url()}/web/api/v2.1/system/info",
                    headers=self._get_headers(),
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json()
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to SentinelOne",
                    details={"deployment": data.get("data", {}).get("deployment")},
                    latency_ms=latency_ms,
                )
            elif response.status_code == 401:
                return ConnectionTestResult(
                    success=False,
                    message="Authentication failed - check API token",
                    latency_ms=latency_ms,
                )
            else:
                return ConnectionTestResult(
                    success=False,
                    message=f"API returned status {response.status_code}",
                    latency_ms=latency_ms,
                )

        except Exception as e:
            return ConnectionTestResult(
                success=False,
                message=f"Connection error: {str(e)}",
            )

    async def execute(self, action_config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Execute a SentinelOne action."""
        start_time = time.time()
        action = action_config.get("action")

        try:
            if action == "disconnect_from_network":
                result = await self._disconnect_from_network(action_config)
            elif action == "reconnect_to_network":
                result = await self._reconnect_to_network(action_config)
            elif action == "initiate_scan":
                result = await self._initiate_scan(action_config)
            elif action == "abort_scan":
                result = await self._abort_scan(action_config)
            elif action == "mitigate_threat":
                result = await self._mitigate_threat(action_config)
            else:
                return ActionResult(
                    success=False,
                    message=f"Unknown action: {action}",
                )

            execution_time_ms = int((time.time() - start_time) * 1000)
            result.execution_time_ms = execution_time_ms
            return result

        except Exception as e:
            return ActionResult(
                success=False,
                message=f"SentinelOne action failed: {str(e)}",
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    async def _get_agent_ids(self, config: dict[str, Any]) -> list[str]:
        """Get agent IDs from config or lookup by hostname."""
        if config.get("agent_ids"):
            return config["agent_ids"]

        hostname = config.get("hostname")
        if not hostname:
            raise Exception("Either agent_ids or hostname is required")

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{self._get_base_url()}/web/api/v2.1/agents",
                headers=self._get_headers(),
                params={"computerName__contains": hostname, "limit": 10},
            )

        if response.status_code != 200:
            raise Exception(f"Failed to lookup agent: {response.status_code}")

        data = response.json()
        agents = data.get("data", [])
        if not agents:
            raise Exception(f"No agent found with hostname: {hostname}")

        return [agent["id"] for agent in agents]

    async def _disconnect_from_network(self, config: dict[str, Any]) -> ActionResult:
        """Disconnect an agent from the network."""
        agent_ids = await self._get_agent_ids(config)

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self._get_base_url()}/web/api/v2.1/agents/actions/disconnect",
                headers=self._get_headers(),
                json={"filter": {"ids": agent_ids}},
            )

        if response.status_code == 200:
            data = response.json()
            return ActionResult(
                success=True,
                message=f"Disconnected {data.get('data', {}).get('affected', 0)} agent(s) from network",
                output={"agent_ids": agent_ids, "affected": data.get("data", {}).get("affected")},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to disconnect agents: {response.status_code}",
                error=response.text,
            )

    async def _reconnect_to_network(self, config: dict[str, Any]) -> ActionResult:
        """Reconnect an agent to the network."""
        agent_ids = await self._get_agent_ids(config)

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self._get_base_url()}/web/api/v2.1/agents/actions/connect",
                headers=self._get_headers(),
                json={"filter": {"ids": agent_ids}},
            )

        if response.status_code == 200:
            data = response.json()
            return ActionResult(
                success=True,
                message=f"Reconnected {data.get('data', {}).get('affected', 0)} agent(s) to network",
                output={"agent_ids": agent_ids, "affected": data.get("data", {}).get("affected")},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to reconnect agents: {response.status_code}",
                error=response.text,
            )

    async def _initiate_scan(self, config: dict[str, Any]) -> ActionResult:
        """Initiate a full disk scan on agents."""
        agent_ids = await self._get_agent_ids(config)

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self._get_base_url()}/web/api/v2.1/agents/actions/initiate-scan",
                headers=self._get_headers(),
                json={"filter": {"ids": agent_ids}},
            )

        if response.status_code == 200:
            data = response.json()
            return ActionResult(
                success=True,
                message=f"Initiated scan on {data.get('data', {}).get('affected', 0)} agent(s)",
                output={"agent_ids": agent_ids, "affected": data.get("data", {}).get("affected")},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to initiate scan: {response.status_code}",
                error=response.text,
            )

    async def _abort_scan(self, config: dict[str, Any]) -> ActionResult:
        """Abort running scans on agents."""
        agent_ids = await self._get_agent_ids(config)

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self._get_base_url()}/web/api/v2.1/agents/actions/abort-scan",
                headers=self._get_headers(),
                json={"filter": {"ids": agent_ids}},
            )

        if response.status_code == 200:
            data = response.json()
            return ActionResult(
                success=True,
                message=f"Aborted scan on {data.get('data', {}).get('affected', 0)} agent(s)",
                output={"agent_ids": agent_ids, "affected": data.get("data", {}).get("affected")},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to abort scan: {response.status_code}",
                error=response.text,
            )

    async def _mitigate_threat(self, config: dict[str, Any]) -> ActionResult:
        """Mitigate threats on agents."""
        threat_ids = config.get("threat_ids")
        if not threat_ids:
            return ActionResult(
                success=False,
                message="Threat IDs are required for mitigation",
                error="No threat_ids provided",
            )

        mitigation_action = config.get("mitigation_action", "quarantine")

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self._get_base_url()}/web/api/v2.1/threats/mitigate/{mitigation_action}",
                headers=self._get_headers(),
                json={"filter": {"ids": threat_ids}},
            )

        if response.status_code == 200:
            data = response.json()
            return ActionResult(
                success=True,
                message=f"Mitigated {data.get('data', {}).get('affected', 0)} threat(s) with action: {mitigation_action}",
                output={
                    "threat_ids": threat_ids,
                    "action": mitigation_action,
                    "affected": data.get("data", {}).get("affected"),
                },
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to mitigate threats: {response.status_code}",
                error=response.text,
            )
