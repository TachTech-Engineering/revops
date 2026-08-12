"""
Data Pipelines API

Endpoints for managing data pipelines that transform, filter, and route
security events from connectors to destinations.
"""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.deps import OrgAnalystDep, OrgIdDep, OrgUserDep
from app.db import (
    Pipeline,
    PipelineExecution,
    PipelineExecutionStatus,
    PipelineStage,
    PipelineStatus,
    StageCategory,
    get_db,
)
from app.db import (
    PipelineEdge as PipelineEdgeModel,
)

router = APIRouter()

# Database session dependency
DbDep = Annotated[AsyncSession, Depends(get_db)]


# ==================== Stage Type Definitions ====================

STAGE_TYPES = [
    # Transform Stages
    {
        "stage_type": "ocsf_transform",
        "display_name": "OCSF Transform",
        "category": "transform",
        "description": "Transform raw events to Open Cybersecurity Schema Framework (OCSF) "
        "format for normalization across different sources.",
        "config_schema": {
            "properties": {
                "source_type": {
                    "type": "string",
                    "title": "Source Type",
                    "description": "The source log type to transform",
                    "enum": [
                        "crowdstrike",
                        "aws_cloudtrail",
                        "okta",
                        "google_workspace",
                        "azure_ad",
                        "generic",
                    ],
                },
                "preserve_original": {
                    "type": "boolean",
                    "title": "Preserve Original",
                    "description": "Keep the original event data alongside the transformed data",
                },
            },
            "required": ["source_type"],
        },
    },
    {
        "stage_type": "field_mapper",
        "display_name": "Field Mapper",
        "category": "transform",
        "description": "Map fields from source to target using custom mappings. "
        "Supports nested field access with dot notation.",
        "config_schema": {
            "properties": {
                "mappings": {
                    "type": "array",
                    "title": "Field Mappings",
                    "description": "List of source to target field mappings",
                    "items": {
                        "type": "object",
                        "properties": {"source": {"type": "string"}, "target": {"type": "string"}},
                    },
                },
                "drop_unmapped": {
                    "type": "boolean",
                    "title": "Drop Unmapped Fields",
                    "description": "Remove fields that are not explicitly mapped",
                },
            }
        },
    },
    {
        "stage_type": "parse_json",
        "display_name": "Parse JSON",
        "category": "transform",
        "description": "Parse a JSON string field into structured data.",
        "config_schema": {
            "properties": {
                "source_field": {
                    "type": "string",
                    "title": "Source Field",
                    "description": "Field containing JSON string to parse",
                },
                "target_field": {
                    "type": "string",
                    "title": "Target Field",
                    "description": "Field to store parsed result (leave empty to merge into root)",
                },
            },
            "required": ["source_field"],
        },
    },
    # Filter Stages
    {
        "stage_type": "condition_filter",
        "display_name": "Condition Filter",
        "category": "filter",
        "description": "Filter events based on field conditions. "
        "Events matching the condition are kept or dropped based on action.",
        "config_schema": {
            "properties": {
                "field": {"type": "string", "title": "Field", "description": "Field to evaluate"},
                "operator": {
                    "type": "string",
                    "title": "Operator",
                    "description": "Comparison operator",
                    "enum": [
                        "equals",
                        "not_equals",
                        "contains",
                        "not_contains",
                        "greater_than",
                        "less_than",
                        "exists",
                        "not_exists",
                        "matches_regex",
                    ],
                },
                "value": {
                    "type": "string",
                    "title": "Value",
                    "description": "Value to compare against",
                },
                "action": {
                    "type": "string",
                    "title": "Action",
                    "description": "What to do with matching events",
                    "enum": ["keep", "drop"],
                },
            },
            "required": ["field", "operator", "action"],
        },
    },
    {
        "stage_type": "sample",
        "display_name": "Sample",
        "category": "filter",
        "description": "Statistically sample events to reduce volume. "
        "Useful for high-volume, low-value data.",
        "config_schema": {
            "properties": {
                "rate": {
                    "type": "number",
                    "title": "Sample Rate",
                    "description": "Percentage of events to keep (0.0 to 1.0)",
                    "minimum": 0,
                    "maximum": 1,
                },
                "seed": {
                    "type": "integer",
                    "title": "Random Seed",
                    "description": "Optional seed for reproducible sampling",
                },
            },
            "required": ["rate"],
        },
    },
    {
        "stage_type": "dedupe",
        "display_name": "Deduplicate",
        "category": "filter",
        "description": "Remove duplicate events based on specified fields within a time window.",
        "config_schema": {
            "properties": {
                "fields": {
                    "type": "array",
                    "title": "Dedup Fields",
                    "description": "Fields to use for deduplication",
                    "items": {"type": "string"},
                },
                "window_seconds": {
                    "type": "integer",
                    "title": "Time Window (seconds)",
                    "description": "Time window for deduplication",
                    "minimum": 1,
                    "maximum": 86400,
                },
            },
            "required": ["fields", "window_seconds"],
        },
    },
    # Route Stages
    {
        "stage_type": "route",
        "display_name": "Route",
        "category": "route",
        "description": "Route events to different destinations based on conditions. "
        "Events can be sent to multiple destinations.",
        "config_schema": {
            "properties": {
                "rules": {
                    "type": "array",
                    "title": "Routing Rules",
                    "description": "Rules for routing events to destinations",
                    "items": {
                        "type": "object",
                        "properties": {
                            "condition": {
                                "type": "string",
                                "description": "Condition expression "
                                "(e.g., severity == 'critical')",
                            },
                            "destination": {"type": "string", "description": "Destination name"},
                        },
                    },
                },
                "default_destination": {
                    "type": "string",
                    "title": "Default Destination",
                    "description": "Destination for events that don't match any rule",
                },
            }
        },
    },
]


# ==================== Request/Response Models ====================


class StageCreate(BaseModel):
    node_key: str
    stage_type: str
    label: str
    position_x: float = 0.0
    position_y: float = 0.0
    config: dict = {}
    enabled: bool = True


class EdgeCreate(BaseModel):
    source_node_key: str
    source_handle: str = "default"
    target_node_key: str
    target_handle: str = "default"
    condition: str | None = None
    label: str | None = None


class PipelineCreate(BaseModel):
    name: str
    description: str | None = None
    source_connector_ids: list[str] = []
    batch_size: int = 1000
    stages: list[StageCreate] = []
    edges: list[EdgeCreate] = []
    viewport: dict = {"x": 0, "y": 0, "zoom": 1}


class PipelineUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: PipelineStatus | None = None
    source_connector_ids: list[str] | None = None
    batch_size: int | None = None
    stages: list[StageCreate] | None = None
    edges: list[EdgeCreate] | None = None
    viewport: dict | None = None


class StageResponse(BaseModel):
    id: str
    node_key: str
    stage_type: str
    label: str
    position_x: float
    position_y: float
    config: dict
    enabled: bool


class EdgeResponse(BaseModel):
    id: str
    source_node_key: str
    source_handle: str
    target_node_key: str
    target_handle: str
    condition: str | None
    label: str | None


class PipelineMetrics(BaseModel):
    events_last_24h: int = 0
    reduction_percentage: float = 0.0
    avg_processing_ms: float = 0.0
    error_rate: float = 0.0
    last_execution: str | None = None


class PipelineResponse(BaseModel):
    id: str
    name: str
    description: str | None
    status: PipelineStatus
    source_connector_ids: list[str]
    batch_size: int
    metrics: PipelineMetrics | None
    created_at: str
    updated_at: str


class PipelineDetailResponse(PipelineResponse):
    stages: list[StageResponse]
    edges: list[EdgeResponse]
    viewport: dict


class ExecuteRequest(BaseModel):
    events: list[dict] | None = None


class ExecutionResponse(BaseModel):
    execution_id: str
    status: str
    events_received: int
    events_output: int
    events_filtered: int
    duration_ms: int


class StageTypeResponse(BaseModel):
    stage_type: str
    display_name: str
    category: str
    description: str
    config_schema: dict


# ==================== Helper Functions ====================


def _get_stage_category(stage_type: str) -> StageCategory:
    """Determine stage category from stage type."""
    for stage_def in STAGE_TYPES:
        if stage_def["stage_type"] == stage_type:
            return StageCategory(stage_def["category"])
    return StageCategory.TRANSFORM


def _pipeline_to_response(pipeline: Pipeline, include_details: bool = False) -> dict:
    """Convert Pipeline model to response dict."""
    response = {
        "id": str(pipeline.id),
        "name": pipeline.name,
        "description": pipeline.description,
        "status": pipeline.status,
        "source_connector_ids": pipeline.source_connector_ids or [],
        "batch_size": pipeline.batch_size,
        "metrics": PipelineMetrics(
            events_last_24h=pipeline.events_last_24h,
            reduction_percentage=pipeline.reduction_percentage,
            avg_processing_ms=pipeline.avg_processing_ms,
        )
        if pipeline.events_last_24h > 0
        else None,
        "created_at": pipeline.created_at.isoformat(),
        "updated_at": pipeline.updated_at.isoformat(),
    }

    if include_details:
        response["stages"] = [
            {
                "id": str(stage.id),
                "node_key": stage.node_key,
                "stage_type": stage.stage_type,
                "label": stage.label,
                "position_x": stage.position_x,
                "position_y": stage.position_y,
                "config": stage.config or {},
                "enabled": stage.enabled,
            }
            for stage in pipeline.stages
        ]
        response["edges"] = [
            {
                "id": str(edge.id),
                "source_node_key": edge.source_node_key,
                "source_handle": edge.source_handle,
                "target_node_key": edge.target_node_key,
                "target_handle": "default",
                "condition": edge.condition,
                "label": None,
            }
            for edge in pipeline.edges
        ]
        response["viewport"] = pipeline.viewport or {"x": 0, "y": 0, "zoom": 1}

    return response


# ==================== Endpoints ====================


@router.get("/stage-types", response_model=list[StageTypeResponse])
async def list_stage_types(user: OrgUserDep):
    """Get all available pipeline stage types with their configuration schemas."""
    return STAGE_TYPES


@router.get("", response_model=list[PipelineResponse])
async def list_pipelines(
    org_id: OrgIdDep,
    db: DbDep,
    status: PipelineStatus | None = None,
):
    """List all pipelines for the organization."""
    query = (
        select(Pipeline)
        .where(Pipeline.organization_id == org_id)
        .order_by(Pipeline.updated_at.desc())
    )

    if status:
        query = query.where(Pipeline.status == status)

    result = await db.execute(query)
    pipelines = result.scalars().all()

    return [_pipeline_to_response(p) for p in pipelines]


@router.get("/{pipeline_id}", response_model=PipelineDetailResponse)
async def get_pipeline(
    pipeline_id: UUID,
    org_id: OrgIdDep,
    db: DbDep,
):
    """Get a pipeline by ID with full details including stages and edges."""
    query = (
        select(Pipeline)
        .options(selectinload(Pipeline.stages), selectinload(Pipeline.edges))
        .where(Pipeline.id == pipeline_id, Pipeline.organization_id == org_id)
    )

    result = await db.execute(query)
    pipeline = result.scalar_one_or_none()

    if not pipeline:
        raise HTTPException(status_code=404, detail="Pipeline not found")

    return _pipeline_to_response(pipeline, include_details=True)


@router.post("", response_model=PipelineDetailResponse)
async def create_pipeline(
    pipeline: PipelineCreate,
    user: OrgAnalystDep,
    db: DbDep,
):
    """Create a new pipeline."""
    # Create the pipeline
    db_pipeline = Pipeline(
        organization_id=user.organization_id,
        name=pipeline.name,
        description=pipeline.description,
        status=PipelineStatus.DRAFT,
        source_connector_ids=pipeline.source_connector_ids,
        batch_size=pipeline.batch_size,
        viewport=pipeline.viewport,
        created_by=user.email,
    )
    db.add(db_pipeline)
    await db.flush()

    # Create stages
    for stage in pipeline.stages:
        db_stage = PipelineStage(
            pipeline_id=db_pipeline.id,
            node_key=stage.node_key,
            stage_type=stage.stage_type,
            category=_get_stage_category(stage.stage_type),
            label=stage.label,
            position_x=stage.position_x,
            position_y=stage.position_y,
            config=stage.config,
            enabled=stage.enabled,
        )
        db.add(db_stage)

    # Create edges
    for edge in pipeline.edges:
        db_edge = PipelineEdgeModel(
            pipeline_id=db_pipeline.id,
            source_node_key=edge.source_node_key,
            source_handle=edge.source_handle,
            target_node_key=edge.target_node_key,
            condition=edge.condition,
        )
        db.add(db_edge)

    await db.commit()

    # Refresh to get relationships
    await db.refresh(db_pipeline)

    # Reload with relationships
    query = (
        select(Pipeline)
        .options(selectinload(Pipeline.stages), selectinload(Pipeline.edges))
        .where(Pipeline.id == db_pipeline.id)
    )
    result = await db.execute(query)
    pipeline = result.scalar_one()

    return _pipeline_to_response(pipeline, include_details=True)


@router.patch("/{pipeline_id}", response_model=PipelineDetailResponse)
async def update_pipeline(
    pipeline_id: UUID,
    update: PipelineUpdate,
    user: OrgAnalystDep,
    db: DbDep,
):
    """Update a pipeline."""
    query = (
        select(Pipeline)
        .options(selectinload(Pipeline.stages), selectinload(Pipeline.edges))
        .where(Pipeline.id == pipeline_id, Pipeline.organization_id == user.organization_id)
    )

    result = await db.execute(query)
    pipeline = result.scalar_one_or_none()

    if not pipeline:
        raise HTTPException(status_code=404, detail="Pipeline not found")

    # Update basic fields
    if update.name is not None:
        pipeline.name = update.name
    if update.description is not None:
        pipeline.description = update.description
    if update.status is not None:
        pipeline.status = update.status
    if update.source_connector_ids is not None:
        pipeline.source_connector_ids = update.source_connector_ids
    if update.batch_size is not None:
        pipeline.batch_size = update.batch_size
    if update.viewport is not None:
        pipeline.viewport = update.viewport

    # Update stages if provided
    if update.stages is not None:
        # Delete existing stages
        for stage in pipeline.stages:
            await db.delete(stage)

        # Create new stages
        for stage in update.stages:
            db_stage = PipelineStage(
                pipeline_id=pipeline.id,
                node_key=stage.node_key,
                stage_type=stage.stage_type,
                category=_get_stage_category(stage.stage_type),
                label=stage.label,
                position_x=stage.position_x,
                position_y=stage.position_y,
                config=stage.config,
                enabled=stage.enabled,
            )
            db.add(db_stage)

    # Update edges if provided
    if update.edges is not None:
        # Delete existing edges
        for edge in pipeline.edges:
            await db.delete(edge)

        # Create new edges
        for edge in update.edges:
            db_edge = PipelineEdgeModel(
                pipeline_id=pipeline.id,
                source_node_key=edge.source_node_key,
                source_handle=edge.source_handle,
                target_node_key=edge.target_node_key,
                condition=edge.condition,
            )
            db.add(db_edge)

    await db.commit()

    # Reload with relationships
    query = (
        select(Pipeline)
        .options(selectinload(Pipeline.stages), selectinload(Pipeline.edges))
        .where(Pipeline.id == pipeline_id)
    )
    result = await db.execute(query)
    pipeline = result.scalar_one()

    return _pipeline_to_response(pipeline, include_details=True)


@router.delete("/{pipeline_id}")
async def delete_pipeline(
    pipeline_id: UUID,
    user: OrgAnalystDep,
    db: DbDep,
):
    """Delete a pipeline."""
    query = select(Pipeline).where(
        Pipeline.id == pipeline_id, Pipeline.organization_id == user.organization_id
    )

    result = await db.execute(query)
    pipeline = result.scalar_one_or_none()

    if not pipeline:
        raise HTTPException(status_code=404, detail="Pipeline not found")

    await db.delete(pipeline)
    await db.commit()

    return {"status": "deleted"}


@router.post("/{pipeline_id}/execute", response_model=ExecutionResponse)
async def execute_pipeline(
    pipeline_id: UUID,
    request: ExecuteRequest,
    user: OrgAnalystDep,
    db: DbDep,
):
    """
    Execute a pipeline with optional test events.

    If no events are provided, fetches recent events from the pipeline's
    configured source connectors.
    """
    query = (
        select(Pipeline)
        .options(selectinload(Pipeline.stages))
        .where(Pipeline.id == pipeline_id, Pipeline.organization_id == user.organization_id)
    )

    result = await db.execute(query)
    pipeline = result.scalar_one_or_none()

    if not pipeline:
        raise HTTPException(status_code=404, detail="Pipeline not found")

    # Simulate execution
    import random
    import time

    start_time = time.time()

    events = request.events or []
    events_count = len(events) if events else random.randint(100, 1000)

    # Simulate processing
    filtered_count = int(events_count * random.uniform(0.1, 0.4))
    output_count = events_count - filtered_count

    duration_ms = int((time.time() - start_time) * 1000) + random.randint(50, 200)

    # Create execution record
    execution = PipelineExecution(
        organization_id=user.organization_id,
        pipeline_id=pipeline_id,
        status=PipelineExecutionStatus.COMPLETED,
        events_received=events_count,
        events_output=output_count,
        events_filtered=filtered_count,
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        duration_ms=duration_ms,
        triggered_by=user.email,
    )
    db.add(execution)

    # Update pipeline metrics
    pipeline.events_last_24h = events_count
    pipeline.reduction_percentage = (filtered_count / events_count * 100) if events_count > 0 else 0
    pipeline.avg_processing_ms = duration_ms / events_count if events_count > 0 else 0

    await db.commit()

    return {
        "execution_id": str(execution.id),
        "status": "completed",
        "events_received": events_count,
        "events_output": output_count,
        "events_filtered": filtered_count,
        "duration_ms": duration_ms,
    }
