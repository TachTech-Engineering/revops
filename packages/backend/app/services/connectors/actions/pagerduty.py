"""
PagerDuty Action Connector

Creates and manages incidents in PagerDuty for alerting and on-call management.
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


class PagerDutyActionConnector(ActionConnector):
    """
    PagerDuty action connector for incident management.

    Supports creating incidents, triggering events, and managing on-call.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="pagerduty",
            category=ConnectorCategory.ACTION,
            display_name="PagerDuty",
            description="PagerDuty - Incident management and on-call scheduling",
            icon="pagerduty",
            config_schema={
                "type": "object",
                "properties": {
                    "default_service_id": {
                        "type": "string",
                        "title": "Default Service ID",
                        "description": "Default PagerDuty service ID for incidents",
                    },
                    "routing_key": {
                        "type": "string",
                        "title": "Routing Key",
                        "description": "Events API v2 routing key for events integration",
                    },
                },
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "api_key": {
                        "type": "string",
                        "title": "API Key",
                        "description": "PagerDuty REST API key",
                        "format": "password",
                    },
                },
                "required": ["api_key"],
            },
        )

    @classmethod
    def get_action_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["create_incident", "trigger_event", "resolve_incident", "acknowledge_incident"],
                    "title": "Action",
                    "description": "Action to perform",
                    "default": "trigger_event",
                },
                "service_id": {
                    "type": "string",
                    "title": "Service ID",
                    "description": "PagerDuty service ID",
                },
                "incident_id": {
                    "type": "string",
                    "title": "Incident ID",
                    "description": "Incident ID for resolve/acknowledge actions",
                },
                "title": {
                    "type": "string",
                    "title": "Title",
                    "description": "Incident title",
                },
                "urgency": {
                    "type": "string",
                    "enum": ["high", "low"],
                    "title": "Urgency",
                    "description": "Incident urgency",
                    "default": "high",
                },
                "body": {
                    "type": "string",
                    "title": "Body",
                    "description": "Incident body/details",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "error", "warning", "info"],
                    "title": "Severity",
                    "description": "Event severity for trigger_event",
                    "default": "error",
                },
                "dedup_key": {
                    "type": "string",
                    "title": "Deduplication Key",
                    "description": "Key for deduplicating events",
                },
                "custom_details": {
                    "type": "object",
                    "title": "Custom Details",
                    "description": "Additional custom details",
                },
            },
            "required": ["action"],
        }

    def _get_headers(self) -> dict[str, str]:
        """Get request headers with authentication."""
        return {
            "Authorization": f"Token token={self.credentials.get('api_key', '')}",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to PagerDuty API."""
        start_time = time.time()
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    "https://api.pagerduty.com/abilities",
                    headers=self._get_headers(),
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json()
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to PagerDuty",
                    details={"abilities": data.get("abilities", [])[:5]},
                    latency_ms=latency_ms,
                )
            elif response.status_code == 401:
                return ConnectionTestResult(
                    success=False,
                    message="Authentication failed - check API key",
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
        """Execute a PagerDuty action."""
        start_time = time.time()
        action = action_config.get("action", "trigger_event")

        try:
            if action == "create_incident":
                result = await self._create_incident(action_config, context)
            elif action == "trigger_event":
                result = await self._trigger_event(action_config, context)
            elif action == "resolve_incident":
                result = await self._resolve_incident(action_config, context)
            elif action == "acknowledge_incident":
                result = await self._acknowledge_incident(action_config, context)
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
                message=f"PagerDuty action failed: {str(e)}",
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    async def _trigger_event(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Trigger a PagerDuty event via Events API v2."""
        routing_key = self.config.get("routing_key")
        if not routing_key:
            return ActionResult(
                success=False,
                message="Routing key is required for event triggering",
                error="No routing_key configured",
            )

        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": config.get("title", "Alert triggered"),
                "severity": config.get("severity", "error"),
                "source": "panther-dashboard",
            },
        }

        if config.get("dedup_key"):
            payload["dedup_key"] = config["dedup_key"]

        if config.get("custom_details"):
            payload["payload"]["custom_details"] = config["custom_details"]

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
            )

        if response.status_code in (200, 202):
            data = response.json()
            return ActionResult(
                success=True,
                message="Event triggered successfully",
                output={
                    "status": data.get("status"),
                    "dedup_key": data.get("dedup_key"),
                    "message": data.get("message"),
                },
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to trigger event: {response.status_code}",
                error=response.text,
            )

    async def _create_incident(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Create a PagerDuty incident via REST API."""
        service_id = config.get("service_id") or self.config.get("default_service_id")
        if not service_id:
            return ActionResult(
                success=False,
                message="Service ID is required",
                error="No service_id specified",
            )

        payload = {
            "incident": {
                "type": "incident",
                "title": config.get("title", "New Incident"),
                "service": {"id": service_id, "type": "service_reference"},
                "urgency": config.get("urgency", "high"),
            }
        }

        if config.get("body"):
            payload["incident"]["body"] = {"type": "incident_body", "details": config["body"]}

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.pagerduty.com/incidents",
                headers=self._get_headers(),
                json=payload,
            )

        if response.status_code in (200, 201):
            data = response.json()
            incident = data.get("incident", {})
            return ActionResult(
                success=True,
                message=f"Created incident {incident.get('incident_number')}",
                output={
                    "incident_id": incident.get("id"),
                    "incident_number": incident.get("incident_number"),
                    "html_url": incident.get("html_url"),
                },
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to create incident: {response.status_code}",
                error=response.text,
            )

    async def _resolve_incident(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Resolve a PagerDuty incident."""
        incident_id = config.get("incident_id")
        if not incident_id:
            return ActionResult(
                success=False,
                message="Incident ID is required",
                error="No incident_id provided",
            )

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.put(
                f"https://api.pagerduty.com/incidents/{incident_id}",
                headers=self._get_headers(),
                json={"incident": {"type": "incident_reference", "status": "resolved"}},
            )

        if response.status_code == 200:
            return ActionResult(
                success=True,
                message=f"Resolved incident {incident_id}",
                output={"incident_id": incident_id, "status": "resolved"},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to resolve incident: {response.status_code}",
                error=response.text,
            )

    async def _acknowledge_incident(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Acknowledge a PagerDuty incident."""
        incident_id = config.get("incident_id")
        if not incident_id:
            return ActionResult(
                success=False,
                message="Incident ID is required",
                error="No incident_id provided",
            )

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.put(
                f"https://api.pagerduty.com/incidents/{incident_id}",
                headers=self._get_headers(),
                json={"incident": {"type": "incident_reference", "status": "acknowledged"}},
            )

        if response.status_code == 200:
            return ActionResult(
                success=True,
                message=f"Acknowledged incident {incident_id}",
                output={"incident_id": incident_id, "status": "acknowledged"},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to acknowledge incident: {response.status_code}",
                error=response.text,
            )
