"""
CrowdStrike Action Connector

Executes response actions via CrowdStrike Falcon API.
"""

import time
from typing import Any

import httpx

from app.db.models import ConnectorCategory
from app.services.connectors.base import (
    ActionConnector,
    ActionResult,
    ConnectionTestResult,
    ConnectorMetadata,
)


class CrowdStrikeActionConnector(ActionConnector):
    """
    CrowdStrike Falcon action connector for EDR response actions.

    Supports host containment, real-time response commands, and detection management.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="crowdstrike",
            category=ConnectorCategory.ACTION,
            display_name="CrowdStrike",
            description="CrowdStrike Falcon - Endpoint detection and response",
            icon="crowdstrike",
            config_schema={
                "type": "object",
                "properties": {
                    "base_url": {
                        "type": "string",
                        "title": "Base URL",
                        "description": "CrowdStrike API base URL",
                        "enum": [
                            "https://api.crowdstrike.com",
                            "https://api.us-2.crowdstrike.com",
                            "https://api.eu-1.crowdstrike.com",
                            "https://api.laggar.gcw.crowdstrike.com",
                        ],
                        "default": "https://api.crowdstrike.com",
                    },
                },
                "required": ["base_url"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "client_id": {
                        "type": "string",
                        "title": "Client ID",
                        "description": "CrowdStrike API client ID",
                    },
                    "client_secret": {
                        "type": "string",
                        "title": "Client Secret",
                        "description": "CrowdStrike API client secret",
                        "format": "password",
                    },
                },
                "required": ["client_id", "client_secret"],
            },
        )

    @classmethod
    def get_action_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["contain_host", "lift_containment", "hide_host", "unhide_host"],
                    "title": "Action",
                    "description": "Action to perform",
                },
                "host_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "title": "Host IDs",
                    "description": "CrowdStrike device IDs",
                },
                "hostname": {
                    "type": "string",
                    "title": "Hostname",
                    "description": "Hostname to look up (alternative to host_ids)",
                },
            },
            "required": ["action"],
        }

    async def _get_access_token(self) -> str:
        """Get OAuth2 access token from CrowdStrike."""
        base_url = self.config.get("base_url", "https://api.crowdstrike.com")

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{base_url}/oauth2/token",
                data={
                    "client_id": self.credentials.get("client_id", ""),
                    "client_secret": self.credentials.get("client_secret", ""),
                },
            )

        if response.status_code != 201:
            raise Exception(f"Failed to get access token: {response.status_code}")

        data = response.json()
        return data.get("access_token", "")

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to CrowdStrike API."""
        start_time = time.time()
        try:
            token = await self._get_access_token()
            base_url = self.config.get("base_url", "https://api.crowdstrike.com")

            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{base_url}/sensors/queries/sensors/v1",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"limit": 1},
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to CrowdStrike",
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
        """Execute a CrowdStrike action."""
        start_time = time.time()
        action = action_config.get("action")

        try:
            token = await self._get_access_token()

            if action == "contain_host":
                result = await self._contain_host(action_config, token)
            elif action == "lift_containment":
                result = await self._lift_containment(action_config, token)
            elif action == "hide_host":
                result = await self._hide_host(action_config, token)
            elif action == "unhide_host":
                result = await self._unhide_host(action_config, token)
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
                message=f"CrowdStrike action failed: {str(e)}",
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    async def _get_host_ids(self, config: dict[str, Any], token: str) -> list[str]:
        """Get host IDs from config or lookup by hostname."""
        if config.get("host_ids"):
            return config["host_ids"]

        hostname = config.get("hostname")
        if not hostname:
            raise Exception("Either host_ids or hostname is required")

        base_url = self.config.get("base_url", "https://api.crowdstrike.com")

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{base_url}/devices/queries/devices/v1",
                headers={"Authorization": f"Bearer {token}"},
                params={"filter": f"hostname:'{hostname}'"},
            )

        if response.status_code != 200:
            raise Exception(f"Failed to lookup host: {response.status_code}")

        data = response.json()
        host_ids = data.get("resources", [])
        if not host_ids:
            raise Exception(f"No host found with hostname: {hostname}")

        return host_ids

    async def _contain_host(self, config: dict[str, Any], token: str) -> ActionResult:
        """Contain a host (network isolation)."""
        host_ids = await self._get_host_ids(config, token)
        base_url = self.config.get("base_url", "https://api.crowdstrike.com")

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{base_url}/devices/entities/devices-actions/v2",
                headers={"Authorization": f"Bearer {token}"},
                params={"action_name": "contain"},
                json={"ids": host_ids},
            )

        if response.status_code == 202:
            return ActionResult(
                success=True,
                message=f"Contained {len(host_ids)} host(s)",
                output={"host_ids": host_ids, "action": "contain"},
            )
        else:
            data = response.json()
            return ActionResult(
                success=False,
                message=f"Failed to contain host: {response.status_code}",
                error=str(data.get("errors", [])),
            )

    async def _lift_containment(self, config: dict[str, Any], token: str) -> ActionResult:
        """Lift containment from a host."""
        host_ids = await self._get_host_ids(config, token)
        base_url = self.config.get("base_url", "https://api.crowdstrike.com")

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{base_url}/devices/entities/devices-actions/v2",
                headers={"Authorization": f"Bearer {token}"},
                params={"action_name": "lift_containment"},
                json={"ids": host_ids},
            )

        if response.status_code == 202:
            return ActionResult(
                success=True,
                message=f"Lifted containment on {len(host_ids)} host(s)",
                output={"host_ids": host_ids, "action": "lift_containment"},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to lift containment: {response.status_code}",
                error=response.text,
            )

    async def _hide_host(self, config: dict[str, Any], token: str) -> ActionResult:
        """Hide a host from the console."""
        host_ids = await self._get_host_ids(config, token)
        base_url = self.config.get("base_url", "https://api.crowdstrike.com")

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{base_url}/devices/entities/devices-actions/v2",
                headers={"Authorization": f"Bearer {token}"},
                params={"action_name": "hide_host"},
                json={"ids": host_ids},
            )

        if response.status_code == 202:
            return ActionResult(
                success=True,
                message=f"Hid {len(host_ids)} host(s)",
                output={"host_ids": host_ids, "action": "hide_host"},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to hide host: {response.status_code}",
                error=response.text,
            )

    async def _unhide_host(self, config: dict[str, Any], token: str) -> ActionResult:
        """Unhide a host in the console."""
        host_ids = await self._get_host_ids(config, token)
        base_url = self.config.get("base_url", "https://api.crowdstrike.com")

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{base_url}/devices/entities/devices-actions/v2",
                headers={"Authorization": f"Bearer {token}"},
                params={"action_name": "unhide_host"},
                json={"ids": host_ids},
            )

        if response.status_code == 202:
            return ActionResult(
                success=True,
                message=f"Unhid {len(host_ids)} host(s)",
                output={"host_ids": host_ids, "action": "unhide_host"},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to unhide host: {response.status_code}",
                error=response.text,
            )
