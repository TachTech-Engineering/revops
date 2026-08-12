import logging
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time_utils import utcnow
from app.db import ActionType, ExecutionStatus, Playbook, PlaybookExecution
from app.services.integrations import (
    ActionConnector,
    ActionResult,
    CrowdStrikeConnector,
    FirewallConnector,
    JiraConnector,
    SentinelOneConnector,
    ServiceNowConnector,
    SOARConnector,
    WebhookConnector,
)

logger = logging.getLogger(__name__)


class PlaybookService:
    """Service for executing playbooks."""

    # Map action types to connectors
    CONNECTORS: dict[str, type[ActionConnector]] = {
        ActionType.WEBHOOK.value: WebhookConnector,
        ActionType.JIRA_TICKET.value: JiraConnector,
        ActionType.SERVICENOW_TICKET.value: ServiceNowConnector,
        ActionType.CROWDSTRIKE_ISOLATE.value: CrowdStrikeConnector,
        ActionType.SENTINELONE_ISOLATE.value: SentinelOneConnector,
        ActionType.FIREWALL_BLOCK.value: FirewallConnector,
        ActionType.SOAR_TRIGGER.value: SOARConnector,
    }

    def __init__(self, db: AsyncSession):
        self.db = db

    async def execute_playbook(
        self,
        playbook_id: UUID,
        alert_data: dict,
        triggered_by: str = "system",
    ) -> PlaybookExecution:
        """Execute a playbook for an alert."""
        # Get playbook
        result = await self.db.execute(select(Playbook).where(Playbook.id == playbook_id))
        playbook = result.scalar_one_or_none()
        if not playbook:
            raise ValueError(f"Playbook {playbook_id} not found")

        # Create execution record
        execution = PlaybookExecution(
            playbook_id=playbook_id,
            alert_id=alert_data.get("id", "unknown"),
            status=ExecutionStatus.RUNNING,
            started_at=utcnow(),
            triggered_by=triggered_by,
            action_results=[],
        )
        self.db.add(execution)
        await self.db.flush()

        # Execute actions
        action_results = []
        all_success = True
        any_success = False

        for idx, action_config in enumerate(playbook.actions):
            action_type = action_config.get("type")
            if not action_type:
                action_results.append(
                    {
                        "index": idx,
                        "type": "unknown",
                        "success": False,
                        "message": "Missing action type",
                    }
                )
                all_success = False
                continue

            try:
                result = await self._execute_action(action_type, action_config, alert_data)
                action_results.append(
                    {
                        "index": idx,
                        "type": action_type,
                        "success": result.success,
                        "message": result.message,
                        "data": result.data,
                        "error": result.error,
                    }
                )

                if result.success:
                    any_success = True
                else:
                    all_success = False

                # Check if we should stop on failure
                if not result.success and action_config.get("stop_on_failure", False):
                    break

            except Exception as e:
                logger.error(f"Error executing action {idx}: {e}")
                action_results.append(
                    {
                        "index": idx,
                        "type": action_type,
                        "success": False,
                        "message": "Action execution failed",
                        "error": str(e),
                    }
                )
                all_success = False

        # Update execution record
        execution.action_results = action_results
        execution.completed_at = utcnow()

        if all_success:
            execution.status = ExecutionStatus.SUCCESS
        elif any_success:
            execution.status = ExecutionStatus.PARTIAL
        else:
            execution.status = ExecutionStatus.FAILED
            if action_results:
                execution.error_message = action_results[-1].get("error")

        await self.db.flush()
        await self.db.refresh(execution)

        return execution

    async def _execute_action(
        self,
        action_type: str,
        config: dict,
        alert_data: dict,
    ) -> ActionResult:
        """Execute a single action."""
        # Handle special action types
        if action_type == ActionType.UPDATE_ALERT.value:
            return await self._update_alert_action(config, alert_data)
        elif action_type == ActionType.RUN_QUERY.value:
            return await self._run_query_action(config, alert_data)

        # Get connector for action type
        connector_class = self.CONNECTORS.get(action_type)
        if not connector_class:
            return ActionResult(
                success=False,
                message=f"Unknown action type: {action_type}",
                error="Unsupported action type",
            )

        connector = connector_class()

        # Validate config
        is_valid, error = connector.validate_config(config)
        if not is_valid:
            return ActionResult(
                success=False,
                message="Invalid action configuration",
                error=error,
            )

        # Execute action
        return await connector.execute(config, alert_data)

    async def _update_alert_action(self, config: dict, alert_data: dict) -> ActionResult:
        """Update alert status in Panther."""
        # This would call Panther API to update alert
        # For now, return success as placeholder
        new_status = config.get("status")
        assignee = config.get("assignee")

        logger.info(
            f"Would update alert {alert_data.get('id')} - "
            f"status: {new_status}, assignee: {assignee}"
        )

        return ActionResult(
            success=True,
            message=f"Alert update queued (status: {new_status})",
            data={"status": new_status, "assignee": assignee},
        )

    async def _run_query_action(self, config: dict, alert_data: dict) -> ActionResult:
        """Run a query in Panther Data Lake."""
        # This would call Panther API to run query
        # For now, return success as placeholder
        query = config.get("query")

        logger.info(f"Would run query: {query}")

        return ActionResult(
            success=True,
            message="Query execution queued",
            data={"query": query},
        )

    def check_trigger_conditions(self, playbook: Playbook, alert_data: dict) -> bool:
        """Check if alert matches playbook trigger conditions."""
        conditions = playbook.trigger_conditions
        if not conditions:
            return True

        # Check severity
        if "severities" in conditions:
            if alert_data.get("severity") not in conditions["severities"]:
                return False

        # Check rule ID
        if "rule_ids" in conditions:
            rule = alert_data.get("rule", {})
            if rule.get("id") not in conditions["rule_ids"]:
                return False

        # Check title pattern
        if "title_pattern" in conditions:
            import re

            title = alert_data.get("title", "")
            if not re.search(conditions["title_pattern"], title, re.IGNORECASE):
                return False

        return True


async def get_playbook_service(db: AsyncSession) -> PlaybookService:
    """Factory function to create a playbook service."""
    return PlaybookService(db)
