"""
Delay Node Executor

Pauses workflow execution for a specified duration.
"""

import asyncio
from typing import Any

from app.services.workflow_engine.nodes.base import NodeExecutor, NodeResult
from app.services.workflow_engine.context import ExecutionContext


class DelayExecutor(NodeExecutor):
    """
    Delays workflow execution.

    Config:
    - seconds: Number of seconds to delay (default: 0)
    - max_seconds: Maximum allowed delay (default: 300)
    """

    async def execute(self, context: ExecutionContext) -> NodeResult:
        """Execute delay."""
        try:
            seconds = self.config.get("seconds", 0)
            max_seconds = self.config.get("max_seconds", 300)

            # Validate and cap delay
            seconds = min(max(0, seconds), max_seconds)

            if seconds > 0:
                await asyncio.sleep(seconds)

            return NodeResult(
                success=True,
                output={
                    "delayed_seconds": seconds,
                },
                next_handle="default",
            )

        except asyncio.CancelledError:
            return NodeResult(
                success=False,
                error="Delay was cancelled",
            )
        except Exception as e:
            return NodeResult(
                success=False,
                error=f"Delay error: {str(e)}",
            )
