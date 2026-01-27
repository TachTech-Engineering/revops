"""
Connector Action Node Executor

Executes actions via configured connectors (Jira, Slack, etc.).
"""

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.workflow_engine.nodes.base import NodeExecutor, NodeResult
from app.services.workflow_engine.context import ExecutionContext
from app.db.models import Connector, ConnectorCategory, ConnectorStatus
from app.services.encryption import get_encryption_service
from app.services.connectors.base import get_connector_registry


class ConnectorActionExecutor(NodeExecutor):
    """
    Executes an action via a configured connector.

    Config:
    - connector_id: UUID of the connector to use
    - action_config: Configuration for the specific action
    """

    def __init__(self, node_key: str, config: dict[str, Any], db_session: AsyncSession):
        super().__init__(node_key, config)
        self.db = db_session

    async def execute(self, context: ExecutionContext) -> NodeResult:
        """Execute connector action."""
        try:
            connector_id = self.config.get("connector_id")
            if not connector_id:
                return NodeResult(
                    success=False,
                    error="connector_id is required",
                )

            # Parse UUID
            try:
                connector_uuid = UUID(connector_id) if isinstance(connector_id, str) else connector_id
            except ValueError:
                return NodeResult(
                    success=False,
                    error=f"Invalid connector_id: {connector_id}",
                )

            # Get connector from database
            result = await self.db.execute(
                select(Connector).where(Connector.id == connector_uuid)
            )
            connector = result.scalar_one_or_none()

            if not connector:
                return NodeResult(
                    success=False,
                    error=f"Connector not found: {connector_id}",
                )

            if connector.category != ConnectorCategory.ACTION:
                return NodeResult(
                    success=False,
                    error=f"Connector {connector_id} is not an action connector",
                )

            if connector.status != ConnectorStatus.CONNECTED:
                return NodeResult(
                    success=False,
                    error=f"Connector {connector_id} is not connected (status: {connector.status.value})",
                )

            # Decrypt credentials
            credentials = {}
            if connector.credentials_encrypted:
                encryption = get_encryption_service()
                credentials = encryption.decrypt(connector.credentials_encrypted)

            # Get connector implementation
            registry = get_connector_registry()
            connector_cls = registry.get_action(connector.connector_type)

            if not connector_cls:
                return NodeResult(
                    success=False,
                    error=f"Unknown connector type: {connector.connector_type}",
                )

            # Instantiate connector
            connector_instance = connector_cls(connector.id, connector.config, credentials)

            # Get action config
            action_config = self.config.get("action_config", {})

            # Execute action
            action_result = await connector_instance.execute(
                action_config,
                context.to_template_context(),
            )

            return NodeResult(
                success=action_result.success,
                output={
                    "connector_type": connector.connector_type,
                    "message": action_result.message,
                    "result": action_result.output,
                    "execution_time_ms": action_result.execution_time_ms,
                },
                error=action_result.error,
                next_handle="default",
            )

        except Exception as e:
            return NodeResult(
                success=False,
                error=f"Connector action error: {str(e)}",
            )
