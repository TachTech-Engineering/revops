"""
Jira Action Connector

Creates and updates tickets in Jira for incident response workflows.
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


class JiraActionConnector(ActionConnector):
    """
    Jira action connector for ticket management.

    Supports creating issues, updating fields, adding comments,
    and transitioning issue status.
    """

    @classmethod
    def get_metadata(cls) -> ConnectorMetadata:
        return ConnectorMetadata(
            connector_type="jira",
            category=ConnectorCategory.ACTION,
            display_name="Jira",
            description="Jira - Project tracking and issue management",
            icon="jira",
            config_schema={
                "type": "object",
                "properties": {
                    "base_url": {
                        "type": "string",
                        "title": "Base URL",
                        "description": "Jira instance URL (e.g., https://company.atlassian.net)",
                    },
                    "default_project": {
                        "type": "string",
                        "title": "Default Project",
                        "description": "Default project key for new issues",
                    },
                },
                "required": ["base_url"],
            },
            credentials_schema={
                "type": "object",
                "properties": {
                    "email": {
                        "type": "string",
                        "title": "Email",
                        "description": "Jira user email",
                    },
                    "api_token": {
                        "type": "string",
                        "title": "API Token",
                        "description": "Jira API token",
                        "format": "password",
                    },
                },
                "required": ["email", "api_token"],
            },
        )

    @classmethod
    def get_action_schema(cls) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["create_issue", "update_issue", "add_comment", "transition_issue"],
                    "title": "Action",
                    "description": "Action to perform",
                },
                "project": {
                    "type": "string",
                    "title": "Project",
                    "description": "Project key (uses default if not specified)",
                },
                "issue_key": {
                    "type": "string",
                    "title": "Issue Key",
                    "description": "Issue key for update/comment/transition actions",
                },
                "issue_type": {
                    "type": "string",
                    "title": "Issue Type",
                    "description": "Issue type (Bug, Task, Story, etc.)",
                    "default": "Task",
                },
                "summary": {
                    "type": "string",
                    "title": "Summary",
                    "description": "Issue summary/title",
                },
                "description": {
                    "type": "string",
                    "title": "Description",
                    "description": "Issue description (supports Jira wiki markup)",
                },
                "priority": {
                    "type": "string",
                    "title": "Priority",
                    "description": "Issue priority",
                },
                "labels": {
                    "type": "array",
                    "items": {"type": "string"},
                    "title": "Labels",
                    "description": "Issue labels",
                },
                "assignee": {
                    "type": "string",
                    "title": "Assignee",
                    "description": "Assignee account ID or email",
                },
                "comment": {
                    "type": "string",
                    "title": "Comment",
                    "description": "Comment text for add_comment action",
                },
                "transition_id": {
                    "type": "string",
                    "title": "Transition ID",
                    "description": "Transition ID for transition_issue action",
                },
                "custom_fields": {
                    "type": "object",
                    "title": "Custom Fields",
                    "description": "Additional custom fields as key-value pairs",
                },
            },
            "required": ["action"],
        }

    def _get_auth(self) -> tuple[str, str]:
        """Get basic auth credentials."""
        return (
            self.credentials.get("email", ""),
            self.credentials.get("api_token", ""),
        )

    def _get_base_url(self) -> str:
        """Get the Jira API base URL."""
        return self.config.get("base_url", "").rstrip("/")

    async def test_connection(self) -> ConnectionTestResult:
        """Test connection to Jira API."""
        start_time = time.time()
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self._get_base_url()}/rest/api/3/myself",
                    auth=self._get_auth(),
                )

            latency_ms = int((time.time() - start_time) * 1000)

            if response.status_code == 200:
                data = response.json()
                return ConnectionTestResult(
                    success=True,
                    message="Successfully connected to Jira",
                    details={
                        "account_id": data.get("accountId"),
                        "display_name": data.get("displayName"),
                    },
                    latency_ms=latency_ms,
                )
            elif response.status_code == 401:
                return ConnectionTestResult(
                    success=False,
                    message="Authentication failed - check email and API token",
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
        """Execute a Jira action."""
        start_time = time.time()
        action = action_config.get("action", "create_issue")

        try:
            if action == "create_issue":
                result = await self._create_issue(action_config, context)
            elif action == "update_issue":
                result = await self._update_issue(action_config, context)
            elif action == "add_comment":
                result = await self._add_comment(action_config, context)
            elif action == "transition_issue":
                result = await self._transition_issue(action_config, context)
            else:
                return ActionResult(
                    success=False,
                    message=f"Unknown action: {action}",
                    error=(
                        "Supported actions: create_issue, update_issue, "
                        "add_comment, transition_issue"
                    ),
                )

            execution_time_ms = int((time.time() - start_time) * 1000)
            result.execution_time_ms = execution_time_ms
            return result

        except Exception as e:
            return ActionResult(
                success=False,
                message=f"Jira action failed: {str(e)}",
                error=str(e),
                execution_time_ms=int((time.time() - start_time) * 1000),
            )

    async def _create_issue(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Create a new Jira issue."""
        project = config.get("project") or self.config.get("default_project")
        if not project:
            return ActionResult(
                success=False,
                message="Project key is required",
                error="No project specified and no default project configured",
            )

        fields = {
            "project": {"key": project},
            "summary": config.get("summary", "New Issue"),
            "issuetype": {"name": config.get("issue_type", "Task")},
        }

        if config.get("description"):
            fields["description"] = {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": config["description"]}],
                    }
                ],
            }

        if config.get("priority"):
            fields["priority"] = {"name": config["priority"]}

        if config.get("labels"):
            fields["labels"] = config["labels"]

        if config.get("assignee"):
            fields["assignee"] = {"accountId": config["assignee"]}

        # Add custom fields
        if config.get("custom_fields"):
            fields.update(config["custom_fields"])

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self._get_base_url()}/rest/api/3/issue",
                auth=self._get_auth(),
                json={"fields": fields},
            )

        if response.status_code in (200, 201):
            data = response.json()
            return ActionResult(
                success=True,
                message=f"Created issue {data.get('key')}",
                output={
                    "issue_key": data.get("key"),
                    "issue_id": data.get("id"),
                    "issue_url": f"{self._get_base_url()}/browse/{data.get('key')}",
                },
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to create issue: {response.status_code}",
                error=response.text,
            )

    async def _update_issue(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Update an existing Jira issue."""
        issue_key = config.get("issue_key")
        if not issue_key:
            return ActionResult(
                success=False,
                message="Issue key is required for update",
                error="No issue_key provided",
            )

        fields = {}
        if config.get("summary"):
            fields["summary"] = config["summary"]
        if config.get("description"):
            fields["description"] = {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": config["description"]}],
                    }
                ],
            }
        if config.get("priority"):
            fields["priority"] = {"name": config["priority"]}
        if config.get("labels"):
            fields["labels"] = config["labels"]
        if config.get("assignee"):
            fields["assignee"] = {"accountId": config["assignee"]}
        if config.get("custom_fields"):
            fields.update(config["custom_fields"])

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.put(
                f"{self._get_base_url()}/rest/api/3/issue/{issue_key}",
                auth=self._get_auth(),
                json={"fields": fields},
            )

        if response.status_code == 204:
            return ActionResult(
                success=True,
                message=f"Updated issue {issue_key}",
                output={"issue_key": issue_key},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to update issue: {response.status_code}",
                error=response.text,
            )

    async def _add_comment(self, config: dict[str, Any], context: dict[str, Any]) -> ActionResult:
        """Add a comment to a Jira issue."""
        issue_key = config.get("issue_key")
        comment = config.get("comment")

        if not issue_key:
            return ActionResult(
                success=False,
                message="Issue key is required",
                error="No issue_key provided",
            )
        if not comment:
            return ActionResult(
                success=False,
                message="Comment text is required",
                error="No comment provided",
            )

        body = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": comment}],
                    }
                ],
            }
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self._get_base_url()}/rest/api/3/issue/{issue_key}/comment",
                auth=self._get_auth(),
                json=body,
            )

        if response.status_code in (200, 201):
            data = response.json()
            return ActionResult(
                success=True,
                message=f"Added comment to {issue_key}",
                output={
                    "issue_key": issue_key,
                    "comment_id": data.get("id"),
                },
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to add comment: {response.status_code}",
                error=response.text,
            )

    async def _transition_issue(
        self, config: dict[str, Any], context: dict[str, Any]
    ) -> ActionResult:
        """Transition a Jira issue to a new status."""
        issue_key = config.get("issue_key")
        transition_id = config.get("transition_id")

        if not issue_key:
            return ActionResult(
                success=False,
                message="Issue key is required",
                error="No issue_key provided",
            )
        if not transition_id:
            return ActionResult(
                success=False,
                message="Transition ID is required",
                error="No transition_id provided",
            )

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self._get_base_url()}/rest/api/3/issue/{issue_key}/transitions",
                auth=self._get_auth(),
                json={"transition": {"id": transition_id}},
            )

        if response.status_code == 204:
            return ActionResult(
                success=True,
                message=f"Transitioned issue {issue_key}",
                output={"issue_key": issue_key, "transition_id": transition_id},
            )
        else:
            return ActionResult(
                success=False,
                message=f"Failed to transition issue: {response.status_code}",
                error=response.text,
            )
