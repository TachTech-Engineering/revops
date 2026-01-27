"""
Workflow Engine

Executes workflows by traversing the node graph and running each node's logic.
"""

import asyncio
import time
from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Workflow,
    WorkflowNode,
    WorkflowEdge,
    WorkflowExecution,
    WorkflowStepExecution,
    WorkflowStatus,
    WorkflowExecutionStatus,
    NodeType,
)
from app.services.workflow_engine.context import ExecutionContext
from app.services.workflow_engine.templating import resolve_templates
from app.services.workflow_engine.nodes.base import NodeExecutor, NodeResult, TriggerNodeExecutor
from app.services.workflow_engine.nodes.http_request import HTTPRequestExecutor
from app.services.workflow_engine.nodes.condition import ConditionExecutor
from app.services.workflow_engine.nodes.transform import TransformExecutor
from app.services.workflow_engine.nodes.delay import DelayExecutor
from app.services.workflow_engine.nodes.loop import LoopExecutor
from app.services.workflow_engine.nodes.connector_action import ConnectorActionExecutor
from app.services.workflow_engine.nodes.set_variable import SetVariableExecutor


class WorkflowEngine:
    """
    Executes workflows by traversing the node graph.

    Handles:
    - Graph traversal following edges
    - Conditional branching
    - Loop iteration
    - Step execution tracking
    - Error handling and retry
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def execute_workflow(
        self,
        workflow_id: UUID,
        trigger_data: dict[str, Any],
        triggered_by: str,
    ) -> WorkflowExecution:
        """
        Execute a workflow with the given trigger data.

        Args:
            workflow_id: ID of the workflow to execute
            trigger_data: Data that triggered the workflow
            triggered_by: User or system that triggered execution

        Returns:
            WorkflowExecution record with results
        """
        # Get workflow
        result = await self.db.execute(
            select(Workflow).where(Workflow.id == workflow_id)
        )
        workflow = result.scalar_one_or_none()
        if not workflow:
            raise ValueError(f"Workflow not found: {workflow_id}")

        if workflow.status != WorkflowStatus.ACTIVE:
            raise ValueError(f"Workflow is not active: {workflow.status.value}")

        # Get nodes and edges
        nodes_result = await self.db.execute(
            select(WorkflowNode).where(WorkflowNode.workflow_id == workflow_id)
        )
        nodes = {n.node_key: n for n in nodes_result.scalars().all()}

        edges_result = await self.db.execute(
            select(WorkflowEdge).where(WorkflowEdge.workflow_id == workflow_id)
        )
        edges = list(edges_result.scalars().all())

        if not nodes:
            raise ValueError("Workflow has no nodes")

        # Create execution record
        execution = WorkflowExecution(
            workflow_id=workflow_id,
            workflow_version=workflow.version,
            status=WorkflowExecutionStatus.RUNNING,
            trigger_data=trigger_data,
            context={},
            variables={},
            started_at=datetime.utcnow(),
            triggered_by=triggered_by,
        )
        self.db.add(execution)
        await self.db.flush()

        # Create execution context
        context = ExecutionContext(
            execution_id=execution.id,
            workflow_id=workflow_id,
            trigger_data=trigger_data,
        )

        try:
            # Find trigger node (entry point)
            trigger_node = self._find_trigger_node(nodes)
            if not trigger_node:
                raise ValueError("Workflow has no trigger node")

            # Build adjacency list for graph traversal
            adjacency = self._build_adjacency(edges)

            # Execute graph
            await self._execute_graph(
                trigger_node.node_key,
                nodes,
                adjacency,
                context,
                execution.id,
            )

            # Mark execution complete
            execution.status = WorkflowExecutionStatus.COMPLETED
            execution.completed_at = datetime.utcnow()
            execution.context = context.to_dict()
            execution.variables = context.variables

        except Exception as e:
            execution.status = WorkflowExecutionStatus.FAILED
            execution.completed_at = datetime.utcnow()
            execution.error_message = str(e)
            execution.context = context.to_dict()
            execution.variables = context.variables

        await self.db.flush()
        return execution

    def _find_trigger_node(self, nodes: dict[str, WorkflowNode]) -> Optional[WorkflowNode]:
        """Find the trigger node (entry point) of the workflow."""
        trigger_types = {
            NodeType.TRIGGER_ALERT,
            NodeType.TRIGGER_SCHEDULE,
            NodeType.TRIGGER_WEBHOOK,
            NodeType.TRIGGER_MANUAL,
        }
        for node in nodes.values():
            if node.node_type in trigger_types:
                return node
        return None

    def _build_adjacency(self, edges: list[WorkflowEdge]) -> dict[str, dict[str, list[str]]]:
        """
        Build adjacency list grouped by source handle.

        Returns: {source_key: {handle: [target_keys]}}
        """
        adjacency: dict[str, dict[str, list[str]]] = {}
        for edge in edges:
            if edge.source_node_key not in adjacency:
                adjacency[edge.source_node_key] = {}
            handle = edge.source_handle or "default"
            if handle not in adjacency[edge.source_node_key]:
                adjacency[edge.source_node_key][handle] = []
            adjacency[edge.source_node_key][handle].append(edge.target_node_key)
        return adjacency

    async def _execute_graph(
        self,
        start_node_key: str,
        nodes: dict[str, WorkflowNode],
        adjacency: dict[str, dict[str, list[str]]],
        context: ExecutionContext,
        execution_id: UUID,
    ) -> None:
        """Execute the workflow graph starting from the given node."""
        visited: set[str] = set()
        queue: list[str] = [start_node_key]

        while queue:
            node_key = queue.pop(0)

            # Prevent infinite loops
            visit_key = f"{node_key}:{context.current_loop.current_index if context.current_loop else 0}"
            if visit_key in visited:
                continue
            visited.add(visit_key)

            node = nodes.get(node_key)
            if not node:
                continue

            # Execute node
            result = await self._execute_node(node, context, execution_id)

            # Record step output
            context.set_step_output(
                node_key,
                result.output,
                status="completed" if result.success else "failed",
                error=result.error,
            )

            # Handle failure
            if not result.success:
                on_error = node.on_error or "fail"
                if on_error == "fail":
                    raise RuntimeError(f"Node {node_key} failed: {result.error}")
                elif on_error == "goto_node" and node.error_handler_node:
                    queue.append(node.error_handler_node)
                    continue
                # else: continue to next node

            # Get next nodes based on output handle
            next_handle = result.next_handle
            next_nodes = adjacency.get(node_key, {}).get(next_handle, [])

            # For loops, we may need to come back to this node
            if node.node_type == NodeType.LOOP and next_handle == "loop_item":
                # After processing loop_item branch, come back to loop node
                loop_item_targets = next_nodes
                if loop_item_targets:
                    # Add loop node back after processing items
                    queue.extend(loop_item_targets)
                    queue.append(node_key)  # Re-evaluate loop
                    visited.discard(visit_key)  # Allow revisit
            else:
                queue.extend(next_nodes)

    async def _execute_node(
        self,
        node: WorkflowNode,
        context: ExecutionContext,
        execution_id: UUID,
    ) -> NodeResult:
        """Execute a single node and record step execution."""
        start_time = time.time()

        # Create step execution record
        step_execution = WorkflowStepExecution(
            execution_id=execution_id,
            node_key=node.node_key,
            node_type=node.node_type.value,
            status="running",
            input_data=node.config,
            started_at=datetime.utcnow(),
            loop_index=context.current_loop.current_index if context.current_loop else None,
        )
        self.db.add(step_execution)
        await self.db.flush()

        try:
            # Resolve templates in config
            resolved_config = resolve_templates(node.config, context.to_template_context())

            # Get executor for node type
            executor = self._get_executor(node.node_type, node.node_key, resolved_config)

            # Execute with timeout
            timeout = node.timeout_seconds or 300
            result = await asyncio.wait_for(
                executor.execute(context),
                timeout=timeout,
            )

            # Update step execution
            duration_ms = int((time.time() - start_time) * 1000)
            step_execution.status = "completed" if result.success else "failed"
            step_execution.output_data = result.output
            step_execution.error_message = result.error
            step_execution.completed_at = datetime.utcnow()
            step_execution.duration_ms = duration_ms

            result.output["_duration_ms"] = duration_ms
            await self.db.flush()

            return result

        except asyncio.TimeoutError:
            step_execution.status = "failed"
            step_execution.error_message = f"Node timed out after {node.timeout_seconds}s"
            step_execution.completed_at = datetime.utcnow()
            step_execution.duration_ms = int((time.time() - start_time) * 1000)
            await self.db.flush()

            return NodeResult(
                success=False,
                error=f"Node timed out after {node.timeout_seconds}s",
            )

        except Exception as e:
            step_execution.status = "failed"
            step_execution.error_message = str(e)
            step_execution.completed_at = datetime.utcnow()
            step_execution.duration_ms = int((time.time() - start_time) * 1000)
            await self.db.flush()

            return NodeResult(
                success=False,
                error=str(e),
            )

    def _get_executor(self, node_type: NodeType, node_key: str, config: dict) -> NodeExecutor:
        """Get the appropriate executor for a node type."""
        executors = {
            NodeType.TRIGGER_ALERT: TriggerNodeExecutor,
            NodeType.TRIGGER_SCHEDULE: TriggerNodeExecutor,
            NodeType.TRIGGER_WEBHOOK: TriggerNodeExecutor,
            NodeType.TRIGGER_MANUAL: TriggerNodeExecutor,
            NodeType.HTTP_REQUEST: HTTPRequestExecutor,
            NodeType.CONDITION: ConditionExecutor,
            NodeType.TRANSFORM: TransformExecutor,
            NodeType.DELAY: DelayExecutor,
            NodeType.LOOP: LoopExecutor,
            NodeType.SET_VARIABLE: SetVariableExecutor,
        }

        executor_cls = executors.get(node_type)
        if not executor_cls:
            if node_type == NodeType.CONNECTOR_ACTION:
                return ConnectorActionExecutor(node_key, config, self.db)
            raise ValueError(f"No executor for node type: {node_type}")

        return executor_cls(node_key, config)
