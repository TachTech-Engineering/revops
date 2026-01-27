"""
Base Node Executor

Abstract base class for all workflow node executors.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from app.services.workflow_engine.context import ExecutionContext


@dataclass
class NodeResult:
    """Result from executing a node."""
    success: bool
    output: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    next_handle: str = "default"  # Which output handle to follow (default, true, false, loop_item, loop_complete)


class NodeExecutor(ABC):
    """
    Abstract base class for node executors.

    Each node type (HTTP, condition, transform, etc.) has a
    corresponding executor that handles its specific logic.
    """

    def __init__(self, node_key: str, config: dict[str, Any]):
        """
        Initialize the executor.

        Args:
            node_key: Unique key identifying this node in the workflow
            config: Node configuration (already template-resolved)
        """
        self.node_key = node_key
        self.config = config

    @abstractmethod
    async def execute(self, context: ExecutionContext) -> NodeResult:
        """
        Execute the node logic.

        Args:
            context: Current execution context with trigger data and step outputs

        Returns:
            NodeResult with success status, output data, and next handle
        """
        pass

    def get_timeout(self) -> int:
        """Get the timeout in seconds for this node."""
        return self.config.get("timeout_seconds", 300)


class TriggerNodeExecutor(NodeExecutor):
    """
    Executor for trigger nodes (alert, schedule, webhook, manual).

    Trigger nodes don't have much execution logic - they just
    pass through the trigger data to the next node.
    """

    async def execute(self, context: ExecutionContext) -> NodeResult:
        """Pass trigger data to next nodes."""
        return NodeResult(
            success=True,
            output=context.trigger_data,
            next_handle="default",
        )
