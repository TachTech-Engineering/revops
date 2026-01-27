"""
Workflows API

Endpoints for managing visual workflows and their executions.
All endpoints are organization-scoped for multi-tenancy.
"""

from typing import Annotated, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, Query, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy import select, desc, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db, User
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
from app.api.v1.deps import OrgUserDep, OrgIdDep, OrgAnalystDep
from app.services.workflow_engine import WorkflowEngine

router = APIRouter()


# ==================== Request/Response Models ====================

class NodeCreate(BaseModel):
    node_key: str
    node_type: NodeType
    label: str
    position_x: float = 0.0
    position_y: float = 0.0
    config: dict = {}
    on_error: str = "fail"
    error_handler_node: Optional[str] = None
    timeout_seconds: int = 300


class EdgeCreate(BaseModel):
    source_node_key: str
    source_handle: str = "default"
    target_node_key: str
    condition: Optional[str] = None
    label: Optional[str] = None


class WorkflowCreate(BaseModel):
    name: str
    description: Optional[str] = None
    trigger_type: Optional[str] = None
    trigger_config: dict = {}
    viewport: dict = {"x": 0, "y": 0, "zoom": 1}
    tags: list[str] = []
    nodes: list[NodeCreate] = []
    edges: list[EdgeCreate] = []


class WorkflowUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[WorkflowStatus] = None
    trigger_type: Optional[str] = None
    trigger_config: Optional[dict] = None
    viewport: Optional[dict] = None
    tags: Optional[list[str]] = None
    nodes: Optional[list[NodeCreate]] = None
    edges: Optional[list[EdgeCreate]] = None


class NodeResponse(BaseModel):
    id: UUID
    node_key: str
    node_type: NodeType
    label: str
    position_x: float
    position_y: float
    config: dict
    on_error: str
    error_handler_node: Optional[str]
    timeout_seconds: int

    class Config:
        from_attributes = True


class EdgeResponse(BaseModel):
    id: UUID
    source_node_key: str
    source_handle: str
    target_node_key: str
    condition: Optional[str]
    label: Optional[str]

    class Config:
        from_attributes = True


class WorkflowResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    status: WorkflowStatus
    trigger_type: Optional[str]
    trigger_config: dict
    viewport: dict
    version: int
    tags: list[str]
    created_by: str
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class WorkflowDetailResponse(WorkflowResponse):
    nodes: list[NodeResponse]
    edges: list[EdgeResponse]


class ExecuteRequest(BaseModel):
    trigger_data: dict = {}


class ExecutionResponse(BaseModel):
    id: UUID
    workflow_id: UUID
    workflow_version: int
    status: WorkflowExecutionStatus
    trigger_data: dict
    context: dict
    variables: dict
    started_at: Optional[str]
    completed_at: Optional[str]
    error_message: Optional[str]
    failed_node_key: Optional[str]
    triggered_by: str
    created_at: str

    class Config:
        from_attributes = True


class StepExecutionResponse(BaseModel):
    id: UUID
    node_key: str
    node_type: str
    status: str
    input_data: dict
    output_data: dict
    error_message: Optional[str]
    started_at: Optional[str]
    completed_at: Optional[str]
    duration_ms: Optional[int]
    loop_index: Optional[int]

    class Config:
        from_attributes = True


class WorkflowListResponse(BaseModel):
    items: list[WorkflowResponse]
    total: int
    page: int
    page_size: int


# ==================== Workflow Endpoints ====================

@router.get("")
async def list_workflows(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    status: Optional[WorkflowStatus] = None,
    tag: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
) -> WorkflowListResponse:
    """List all workflows for the current organization."""
    query = select(Workflow).where(
        Workflow.organization_id == org_id
    ).order_by(desc(Workflow.updated_at))

    if status:
        query = query.where(Workflow.status == status)

    result = await db.execute(query)
    workflows = result.scalars().all()

    # Filter by tag if specified
    if tag:
        workflows = [w for w in workflows if tag in (w.tags or [])]

    total = len(workflows)

    # Apply pagination
    start = (page - 1) * page_size
    end = start + page_size
    paginated = workflows[start:end]

    items = [
        WorkflowResponse(
            id=w.id,
            name=w.name,
            description=w.description,
            status=w.status,
            trigger_type=w.trigger_type,
            trigger_config=w.trigger_config,
            viewport=w.viewport,
            version=w.version,
            tags=w.tags or [],
            created_by=w.created_by,
            created_at=w.created_at.isoformat(),
            updated_at=w.updated_at.isoformat(),
        )
        for w in paginated
    ]

    return WorkflowListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{workflow_id}")
async def get_workflow(
    workflow_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> WorkflowDetailResponse:
    """Get a workflow with its nodes and edges (must belong to user's organization)."""
    result = await db.execute(
        select(Workflow).where(
            and_(
                Workflow.id == workflow_id,
                Workflow.organization_id == org_id,
            )
        )
    )
    workflow = result.scalar_one_or_none()
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    # Get nodes
    nodes_result = await db.execute(
        select(WorkflowNode).where(WorkflowNode.workflow_id == workflow_id)
    )
    nodes = nodes_result.scalars().all()

    # Get edges
    edges_result = await db.execute(
        select(WorkflowEdge).where(WorkflowEdge.workflow_id == workflow_id)
    )
    edges = edges_result.scalars().all()

    return WorkflowDetailResponse(
        id=workflow.id,
        name=workflow.name,
        description=workflow.description,
        status=workflow.status,
        trigger_type=workflow.trigger_type,
        trigger_config=workflow.trigger_config,
        viewport=workflow.viewport,
        version=workflow.version,
        tags=workflow.tags or [],
        created_by=workflow.created_by,
        created_at=workflow.created_at.isoformat(),
        updated_at=workflow.updated_at.isoformat(),
        nodes=[
            NodeResponse(
                id=n.id,
                node_key=n.node_key,
                node_type=n.node_type,
                label=n.label,
                position_x=n.position_x,
                position_y=n.position_y,
                config=n.config,
                on_error=n.on_error,
                error_handler_node=n.error_handler_node,
                timeout_seconds=n.timeout_seconds,
            )
            for n in nodes
        ],
        edges=[
            EdgeResponse(
                id=e.id,
                source_node_key=e.source_node_key,
                source_handle=e.source_handle,
                target_node_key=e.target_node_key,
                condition=e.condition,
                label=e.label,
            )
            for e in edges
        ],
    )


@router.post("")
async def create_workflow(
    workflow: WorkflowCreate,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> WorkflowDetailResponse:
    """Create a new workflow for the organization. Requires analyst role."""
    db_workflow = Workflow(
        organization_id=analyst.organization_id,
        name=workflow.name,
        description=workflow.description,
        status=WorkflowStatus.DRAFT,
        trigger_type=workflow.trigger_type,
        trigger_config=workflow.trigger_config,
        viewport=workflow.viewport,
        tags=workflow.tags,
        version=1,
        created_by=analyst.email,
    )
    db.add(db_workflow)
    await db.flush()

    # Create nodes
    db_nodes = []
    for node in workflow.nodes:
        db_node = WorkflowNode(
            workflow_id=db_workflow.id,
            node_key=node.node_key,
            node_type=node.node_type,
            label=node.label,
            position_x=node.position_x,
            position_y=node.position_y,
            config=node.config,
            on_error=node.on_error,
            error_handler_node=node.error_handler_node,
            timeout_seconds=node.timeout_seconds,
        )
        db.add(db_node)
        db_nodes.append(db_node)

    # Create edges
    db_edges = []
    for edge in workflow.edges:
        db_edge = WorkflowEdge(
            workflow_id=db_workflow.id,
            source_node_key=edge.source_node_key,
            source_handle=edge.source_handle,
            target_node_key=edge.target_node_key,
            condition=edge.condition,
            label=edge.label,
        )
        db.add(db_edge)
        db_edges.append(db_edge)

    await db.flush()
    await db.refresh(db_workflow)

    return WorkflowDetailResponse(
        id=db_workflow.id,
        name=db_workflow.name,
        description=db_workflow.description,
        status=db_workflow.status,
        trigger_type=db_workflow.trigger_type,
        trigger_config=db_workflow.trigger_config,
        viewport=db_workflow.viewport,
        version=db_workflow.version,
        tags=db_workflow.tags or [],
        created_by=db_workflow.created_by,
        created_at=db_workflow.created_at.isoformat(),
        updated_at=db_workflow.updated_at.isoformat(),
        nodes=[
            NodeResponse(
                id=n.id,
                node_key=n.node_key,
                node_type=n.node_type,
                label=n.label,
                position_x=n.position_x,
                position_y=n.position_y,
                config=n.config,
                on_error=n.on_error,
                error_handler_node=n.error_handler_node,
                timeout_seconds=n.timeout_seconds,
            )
            for n in db_nodes
        ],
        edges=[
            EdgeResponse(
                id=e.id,
                source_node_key=e.source_node_key,
                source_handle=e.source_handle,
                target_node_key=e.target_node_key,
                condition=e.condition,
                label=e.label,
            )
            for e in db_edges
        ],
    )


@router.patch("/{workflow_id}")
async def update_workflow(
    workflow_id: UUID,
    update: WorkflowUpdate,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> WorkflowDetailResponse:
    """Update a workflow. Requires analyst role."""
    result = await db.execute(
        select(Workflow).where(
            and_(
                Workflow.id == workflow_id,
                Workflow.organization_id == analyst.organization_id,
            )
        )
    )
    workflow = result.scalar_one_or_none()
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    update_data = update.model_dump(exclude_unset=True)

    # Handle nodes/edges separately
    new_nodes = update_data.pop("nodes", None)
    new_edges = update_data.pop("edges", None)

    # Update basic fields
    for field, value in update_data.items():
        setattr(workflow, field, value)

    # Increment version if nodes/edges changed
    if new_nodes is not None or new_edges is not None:
        workflow.version += 1

    # Replace nodes if provided
    if new_nodes is not None:
        # Delete existing nodes
        existing_nodes = await db.execute(
            select(WorkflowNode).where(WorkflowNode.workflow_id == workflow_id)
        )
        for node in existing_nodes.scalars().all():
            await db.delete(node)

        # Create new nodes
        for node_data in new_nodes:
            db_node = WorkflowNode(
                workflow_id=workflow_id,
                node_key=node_data["node_key"],
                node_type=NodeType(node_data["node_type"]),
                label=node_data["label"],
                position_x=node_data.get("position_x", 0),
                position_y=node_data.get("position_y", 0),
                config=node_data.get("config", {}),
                on_error=node_data.get("on_error", "fail"),
                error_handler_node=node_data.get("error_handler_node"),
                timeout_seconds=node_data.get("timeout_seconds", 300),
            )
            db.add(db_node)

    # Replace edges if provided
    if new_edges is not None:
        # Delete existing edges
        existing_edges = await db.execute(
            select(WorkflowEdge).where(WorkflowEdge.workflow_id == workflow_id)
        )
        for edge in existing_edges.scalars().all():
            await db.delete(edge)

        # Create new edges
        for edge_data in new_edges:
            db_edge = WorkflowEdge(
                workflow_id=workflow_id,
                source_node_key=edge_data["source_node_key"],
                source_handle=edge_data.get("source_handle", "default"),
                target_node_key=edge_data["target_node_key"],
                condition=edge_data.get("condition"),
                label=edge_data.get("label"),
            )
            db.add(db_edge)

    await db.flush()

    # Fetch updated data
    return await get_workflow(workflow_id, analyst, analyst.organization_id, db)


@router.delete("/{workflow_id}")
async def delete_workflow(
    workflow_id: UUID,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete a workflow. Requires analyst role."""
    result = await db.execute(
        select(Workflow).where(
            and_(
                Workflow.id == workflow_id,
                Workflow.organization_id == analyst.organization_id,
            )
        )
    )
    workflow = result.scalar_one_or_none()
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    # Delete nodes
    nodes = await db.execute(
        select(WorkflowNode).where(WorkflowNode.workflow_id == workflow_id)
    )
    for node in nodes.scalars().all():
        await db.delete(node)

    # Delete edges
    edges = await db.execute(
        select(WorkflowEdge).where(WorkflowEdge.workflow_id == workflow_id)
    )
    for edge in edges.scalars().all():
        await db.delete(edge)

    # Delete workflow
    await db.delete(workflow)

    return {"status": "deleted"}


# ==================== Execution Endpoints ====================

@router.post("/{workflow_id}/execute")
async def execute_workflow(
    workflow_id: UUID,
    request: ExecuteRequest,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ExecutionResponse:
    """Execute a workflow manually. Requires analyst role."""
    # Verify workflow exists, is active, and belongs to user's org
    result = await db.execute(
        select(Workflow).where(
            and_(
                Workflow.id == workflow_id,
                Workflow.organization_id == analyst.organization_id,
            )
        )
    )
    workflow = result.scalar_one_or_none()
    if not workflow:
        raise HTTPException(status_code=404, detail="Workflow not found")

    if workflow.status != WorkflowStatus.ACTIVE:
        raise HTTPException(status_code=400, detail="Workflow is not active")

    # Execute workflow
    engine = WorkflowEngine(db)
    execution = await engine.execute_workflow(
        workflow_id,
        request.trigger_data,
        triggered_by=analyst.email,
        organization_id=analyst.organization_id,
    )

    return ExecutionResponse(
        id=execution.id,
        workflow_id=execution.workflow_id,
        workflow_version=execution.workflow_version,
        status=execution.status,
        trigger_data=execution.trigger_data,
        context=execution.context,
        variables=execution.variables,
        started_at=execution.started_at.isoformat() if execution.started_at else None,
        completed_at=execution.completed_at.isoformat() if execution.completed_at else None,
        error_message=execution.error_message,
        failed_node_key=execution.failed_node_key,
        triggered_by=execution.triggered_by,
        created_at=execution.created_at.isoformat(),
    )


@router.get("/{workflow_id}/executions")
async def list_workflow_executions(
    workflow_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[WorkflowExecutionStatus] = None,
) -> dict:
    """List executions for a workflow (must belong to user's organization)."""
    # Verify workflow belongs to user's org
    workflow_result = await db.execute(
        select(Workflow).where(
            and_(
                Workflow.id == workflow_id,
                Workflow.organization_id == org_id,
            )
        )
    )
    if not workflow_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Workflow not found")

    # Build query
    query = select(WorkflowExecution).where(
        and_(
            WorkflowExecution.workflow_id == workflow_id,
            WorkflowExecution.organization_id == org_id,
        )
    )
    if status:
        query = query.where(WorkflowExecution.status == status)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Get executions
    query = query.order_by(desc(WorkflowExecution.created_at))
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    executions = result.scalars().all()

    return {
        "items": [
            ExecutionResponse(
                id=e.id,
                workflow_id=e.workflow_id,
                workflow_version=e.workflow_version,
                status=e.status,
                trigger_data=e.trigger_data,
                context=e.context,
                variables=e.variables,
                started_at=e.started_at.isoformat() if e.started_at else None,
                completed_at=e.completed_at.isoformat() if e.completed_at else None,
                error_message=e.error_message,
                failed_node_key=e.failed_node_key,
                triggered_by=e.triggered_by,
                created_at=e.created_at.isoformat(),
            )
            for e in executions
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/executions/{execution_id}")
async def get_execution(
    execution_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Get execution details with step executions (must belong to user's organization)."""
    result = await db.execute(
        select(WorkflowExecution).where(
            and_(
                WorkflowExecution.id == execution_id,
                WorkflowExecution.organization_id == org_id,
            )
        )
    )
    execution = result.scalar_one_or_none()
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    # Get step executions
    steps_result = await db.execute(
        select(WorkflowStepExecution)
        .where(WorkflowStepExecution.execution_id == execution_id)
        .order_by(WorkflowStepExecution.created_at)
    )
    steps = steps_result.scalars().all()

    return {
        "id": str(execution.id),
        "workflow_id": str(execution.workflow_id),
        "workflow_version": execution.workflow_version,
        "status": execution.status.value,
        "trigger_data": execution.trigger_data,
        "context": execution.context,
        "variables": execution.variables,
        "started_at": execution.started_at.isoformat() if execution.started_at else None,
        "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
        "error_message": execution.error_message,
        "failed_node_key": execution.failed_node_key,
        "triggered_by": execution.triggered_by,
        "created_at": execution.created_at.isoformat(),
        "steps": [
            StepExecutionResponse(
                id=s.id,
                node_key=s.node_key,
                node_type=s.node_type,
                status=s.status,
                input_data=s.input_data,
                output_data=s.output_data,
                error_message=s.error_message,
                started_at=s.started_at.isoformat() if s.started_at else None,
                completed_at=s.completed_at.isoformat() if s.completed_at else None,
                duration_ms=s.duration_ms,
                loop_index=s.loop_index,
            )
            for s in steps
        ],
    }


@router.get("/executions/recent")
async def list_recent_executions(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(10, ge=1, le=50),
) -> list[ExecutionResponse]:
    """List recent workflow executions across all workflows for the current organization."""
    query = (
        select(WorkflowExecution)
        .where(WorkflowExecution.organization_id == org_id)
        .order_by(desc(WorkflowExecution.created_at))
        .limit(limit)
    )
    result = await db.execute(query)
    executions = result.scalars().all()

    return [
        ExecutionResponse(
            id=e.id,
            workflow_id=e.workflow_id,
            workflow_version=e.workflow_version,
            status=e.status,
            trigger_data=e.trigger_data,
            context=e.context,
            variables=e.variables,
            started_at=e.started_at.isoformat() if e.started_at else None,
            completed_at=e.completed_at.isoformat() if e.completed_at else None,
            error_message=e.error_message,
            failed_node_key=e.failed_node_key,
            triggered_by=e.triggered_by,
            created_at=e.created_at.isoformat(),
        )
        for e in executions
    ]


# ==================== Node Type Info ====================

@router.get("/node-types")
async def list_node_types(
    user: OrgUserDep,
) -> list[dict]:
    """List all available node types with their configuration schemas."""
    node_types = [
        {
            "type": "trigger_alert",
            "category": "trigger",
            "label": "Alert Trigger",
            "description": "Triggered when an alert matches conditions",
            "handles": {"outputs": ["default"]},
            "config_schema": {
                "type": "object",
                "properties": {
                    "severities": {"type": "array", "items": {"type": "string"}},
                    "rule_ids": {"type": "array", "items": {"type": "string"}},
                    "connector_ids": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
        {
            "type": "trigger_schedule",
            "category": "trigger",
            "label": "Schedule Trigger",
            "description": "Triggered on a cron schedule",
            "handles": {"outputs": ["default"]},
            "config_schema": {
                "type": "object",
                "properties": {
                    "cron": {"type": "string", "description": "Cron expression"},
                    "timezone": {"type": "string", "default": "UTC"},
                },
                "required": ["cron"],
            },
        },
        {
            "type": "trigger_webhook",
            "category": "trigger",
            "label": "Webhook Trigger",
            "description": "Triggered by incoming webhook",
            "handles": {"outputs": ["default"]},
            "config_schema": {
                "type": "object",
                "properties": {
                    "secret": {"type": "string", "description": "Webhook secret for validation"},
                },
            },
        },
        {
            "type": "trigger_manual",
            "category": "trigger",
            "label": "Manual Trigger",
            "description": "Triggered manually by user",
            "handles": {"outputs": ["default"]},
            "config_schema": {"type": "object", "properties": {}},
        },
        {
            "type": "http_request",
            "category": "action",
            "label": "HTTP Request",
            "description": "Make an HTTP API call",
            "handles": {"inputs": ["default"], "outputs": ["default"]},
            "config_schema": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]},
                    "url": {"type": "string"},
                    "headers": {"type": "object"},
                    "query_params": {"type": "object"},
                    "body": {"type": "object"},
                },
                "required": ["method", "url"],
            },
        },
        {
            "type": "connector_action",
            "category": "action",
            "label": "Connector Action",
            "description": "Execute action via configured connector",
            "handles": {"inputs": ["default"], "outputs": ["default"]},
            "config_schema": {
                "type": "object",
                "properties": {
                    "connector_id": {"type": "string"},
                    "action_config": {"type": "object"},
                },
                "required": ["connector_id"],
            },
        },
        {
            "type": "condition",
            "category": "logic",
            "label": "Condition",
            "description": "Branch based on conditions",
            "handles": {"inputs": ["default"], "outputs": ["true", "false"]},
            "config_schema": {
                "type": "object",
                "properties": {
                    "conditions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "field": {"type": "string"},
                                "operator": {"type": "string"},
                                "value": {},
                            },
                        },
                    },
                },
            },
        },
        {
            "type": "transform",
            "category": "logic",
            "label": "Transform",
            "description": "Transform and reshape data",
            "handles": {"inputs": ["default"], "outputs": ["default"]},
            "config_schema": {
                "type": "object",
                "properties": {
                    "mode": {"type": "string", "enum": ["template", "extract", "merge", "map"]},
                    "template": {"type": "object"},
                    "field": {"type": "string"},
                    "sources": {"type": "array"},
                },
            },
        },
        {
            "type": "delay",
            "category": "logic",
            "label": "Delay",
            "description": "Wait for specified duration",
            "handles": {"inputs": ["default"], "outputs": ["default"]},
            "config_schema": {
                "type": "object",
                "properties": {
                    "seconds": {"type": "integer", "minimum": 0, "maximum": 300},
                },
            },
        },
        {
            "type": "loop",
            "category": "logic",
            "label": "Loop",
            "description": "Iterate over array",
            "handles": {"inputs": ["default"], "outputs": ["loop_item", "loop_complete"]},
            "config_schema": {
                "type": "object",
                "properties": {
                    "items": {"description": "Array to iterate (can be template)"},
                    "max_iterations": {"type": "integer", "default": 100},
                },
            },
        },
        {
            "type": "set_variable",
            "category": "utility",
            "label": "Set Variable",
            "description": "Set workflow variables",
            "handles": {"inputs": ["default"], "outputs": ["default"]},
            "config_schema": {
                "type": "object",
                "properties": {
                    "variables": {"type": "object"},
                },
            },
        },
    ]
    return node_types
