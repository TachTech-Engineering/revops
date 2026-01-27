"""
ServiceNow Action Connector

Creates and manages incidents and tickets in ServiceNow.
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


class ServiceNowActionConnector(ActionConnector):
    """
    ServiceNow action connector for IT service management.

    Supports creating and updating incidents, problems, and change requests.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="servicenow",
            category=ConnectorCategory.ACTION,
            display_name="ServiceNow",
            description="ServiceNow - IT service management and workflow",
            icon="servicenow",
            config_schema={
                "type": "object",
                "properties": {
                    "instance_url": {
                        "type": "string",
                        "title": "Instance URL",
                        "description": "ServiceNow instance URL (e.g., https://company.service-now.com)",
                    },
                    "default_assignment_group": {
                        "type": "string",
                        "title": "Default Assignment Group",
                        "description": "Default assignment group sys_id",
                    },
                },
                "required": ["instance_url"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "title": "Username",
                        "description": "ServiceNow username",
                    },
                    "password": {
                        "type": "string",
                        "title": "Password",
                        "description": "ServiceNow password",
                        "format": "password",
                    },
                },
                "required": ["username", "password"],
            },
        )

    @classmethod
    def get_action_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["create_incident", "update_incident", "add_work_note", "resolve_incident"],
                    "title": "Action",
                    "description": "Action to perform",
                    "default": "create_incident",
                },
                "sys_id": {
                    "type": "string",
                    "title": "Sys ID",
                    "description": "Incident sys_id for update/resolve actions",
                },
                "short_description": {
                    "type": "string",
                    "title": "Short Description",
                    "description": "Incident short description (title)",
                },
                "description": {
                    "type": "string",
                    "title": "Description",
                    "description": "Detailed description",
                },
                "urgency": {
                    "type": "string",
                    "enum": ["1", "2", "3"],
                    "title": "Urgency",
                    "description": "Incident urgency (1=High, 2=Medium, 3=Low)",
                    "default": "2",
                },
                "impact": {
                    "type": "string",
                    "enum": ["1", "2", "3"],
                    "title": "Impact",
                    "description": "Incident impact (1=High, 2=Medium, 3=Low)",
                    "default": "2",
                },
                "category": {
                    "type": "string",
                    "title": "Category",
                    "description": "Incident category",
                },
                "subcategory": {
                    "type": "string",
                    "title": "Subcategory",
                    "description": "Incident subcategory",
                },
                "assignment_group": {
                    "type": "string",
                    "title": "Assignment Group",
                    "description": "Assignment group sys_id",
                },
                "assigned_to": {
                    "type": "string",
                    "title": "Assigned To",
                    "description": "Assignee user sys_id",
                },
                "work_notes": {
                    "type": "string",
                    "title": "Work Notes",
                    "description": "Work notes to add",
                },
                "close_notes": {
                    "type": "string",
                    "title": "Close Notes",
                    "description": "Resolution notes for closing",
                },
                "close_code": {
                    "type": "string",
                    "title": "Close Code",
                    "description": "Resolution close code",
                },
                "custom_fields": {
                    "type": "object",
                    "title": "Custom Fields",
                    "description": "Additional custom fields",
                },
            },
            "required": ["action"],
        }

    def _get_auth(self) -> tuple[str, str]:
        """Get basic auth credentials."""
        return (
            self.credentials.get("username", ""),
            self.credentials.get("password", ""),
        )

    def _get_base_url(self) -> str:
        """Get the ServiceNow API base URL."""
        return self.config.get("instance_url", "").rstrip("/")

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to ServiceNow API."""
        start_time = time.time()
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self._get_base_url()}/api/now/table/sys_user?sysparm_limit=1",
                    auth=self._get_auth(),
                    headers={"Accept": "application/json"},
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to ServiceNow",
                    latency_ms=latency_ms,
                )
            elif response.status_code == 401:
                return ConnectionTestResult(
                    success=False,
                    message="Authentication failed - check credentials",
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
        """Execute a ServiceNow action."""
        start_time = time.time()
        action = action_config.get("action", "create_incident")

        try:
            if action == "create_incident":
                result = await self._create_incident(action_config, context)
            elif action == "update_incident":
                result = await self._update_incident(action_config, context)
            elif action == "add_work_note":
                result = await self._add_work_note(action_config, context)
            elif action == "resolve_incident":
                result = await self._resolve_incident(action_config, context)
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
                message=f"ServiceNow action failed: {str(e)}",
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    async def _create_incident(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Create a new ServiceNow incident."""
        payload = {
            "short_description": config.get("short_description", "New Incident"),
            "urgency": config.get("urgency", "2"),
            "impact": config.get("impact", "2"),
        }

        if config.get("description"):
            payload["description"] = config["description"]
        if config.get("category"):
            payload["category"] = config["category"]
        if config.get("subcategory"):
            payload["subcategory"] = config["subcategory"]

        assignment_group = config.get("assignment_group") or self.config.get("default_assignment_group")
        if assignment_group:
            payload["assignment_group"] = assignment_group

        if config.get("assigned_to"):
            payload["assigned_to"] = config["assigned_to"]

        if config.get("custom_fields"):
            payload.update(config["custom_fields"])

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self._get_base_url()}/api/now/table/incident",
                auth=self._get_auth(),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json=payload,
            )

        if response.status_code in (200, 201):
            data = response.json()
            result = data.get("result", {})
            return ActionResult(
                success=True,
                message=f"Created incident {result.get('number')}",
                output={
                    "sys_id": result.get("sys_id"),
                    "number": result.get("number"),
                    "link": f"{self._get_base_url()}/incident.do?sys_id={result.get('sys_id')}",
                },
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to create incident: {response.status_code}",
                error=response.text,
            )

    async def _update_incident(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Update an existing ServiceNow incident."""
        sys_id = config.get("sys_id")
        if not sys_id:
            return ActionResult(
                success=False,
                message="sys_id is required for update",
                error="No sys_id provided",
            )

        payload = {}
        for field in ["short_description", "description", "urgency", "impact", "category", "subcategory", "assignment_group", "assigned_to"]:
            if config.get(field):
                payload[field] = config[field]

        if config.get("custom_fields"):
            payload.update(config["custom_fields"])

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.patch(
                f"{self._get_base_url()}/api/now/table/incident/{sys_id}",
                auth=self._get_auth(),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json=payload,
            )

        if response.status_code == 200:
            data = response.json()
            result = data.get("result", {})
            return ActionResult(
                success=True,
                message=f"Updated incident {result.get('number')}",
                output={"sys_id": sys_id, "number": result.get("number")},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to update incident: {response.status_code}",
                error=response.text,
            )

    async def _add_work_note(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Add a work note to a ServiceNow incident."""
        sys_id = config.get("sys_id")
        work_notes = config.get("work_notes")

        if not sys_id:
            return ActionResult(
                success=False,
                message="sys_id is required",
                error="No sys_id provided",
            )
        if not work_notes:
            return ActionResult(
                success=False,
                message="work_notes is required",
                error="No work_notes provided",
            )

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.patch(
                f"{self._get_base_url()}/api/now/table/incident/{sys_id}",
                auth=self._get_auth(),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json={"work_notes": work_notes},
            )

        if response.status_code == 200:
            return ActionResult(
                success=True,
                message="Added work note to incident",
                output={"sys_id": sys_id},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to add work note: {response.status_code}",
                error=response.text,
            )

    async def _resolve_incident(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Resolve a ServiceNow incident."""
        sys_id = config.get("sys_id")
        if not sys_id:
            return ActionResult(
                success=False,
                message="sys_id is required for resolve",
                error="No sys_id provided",
            )

        payload = {
            "state": "6",  # Resolved
            "close_notes": config.get("close_notes", "Resolved"),
        }

        if config.get("close_code"):
            payload["close_code"] = config["close_code"]

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.patch(
                f"{self._get_base_url()}/api/now/table/incident/{sys_id}",
                auth=self._get_auth(),
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                json=payload,
            )

        if response.status_code == 200:
            data = response.json()
            result = data.get("result", {})
            return ActionResult(
                success=True,
                message=f"Resolved incident {result.get('number')}",
                output={"sys_id": sys_id, "number": result.get("number"), "state": "Resolved"},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to resolve incident: {response.status_code}",
                error=response.text,
            )
