from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db, EnrichmentPipeline, EnrichmentType
from app.api.v1.deps import RequireAnalystDep, CurrentUserDep
from app.services.enrichment_service import (
    run_enrichment,
    enrich_alert,
    get_alert_enrichments,
)

router = APIRouter()


class EnrichmentPipelineCreate(BaseModel):
    name: str
    description: Optional[str] = None
    enrichment_type: EnrichmentType
    source_field: str
    target_field: str
    api_endpoint: Optional[str] = None
    api_headers: dict = {}
    api_key_env: Optional[str] = None
    cache_ttl_minutes: int = 60
    is_active: bool = True
    auto_enrich: bool = False
    severity_filter: list[str] = []


class EnrichmentPipelineUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    source_field: Optional[str] = None
    target_field: Optional[str] = None
    api_endpoint: Optional[str] = None
    api_headers: Optional[dict] = None
    api_key_env: Optional[str] = None
    cache_ttl_minutes: Optional[int] = None
    is_active: Optional[bool] = None
    auto_enrich: Optional[bool] = None
    severity_filter: Optional[list[str]] = None


class EnrichmentPipelineResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    enrichment_type: EnrichmentType
    source_field: str
    target_field: str
    api_endpoint: Optional[str]
    api_headers: dict
    api_key_env: Optional[str]
    cache_ttl_minutes: int
    is_active: bool
    auto_enrich: bool
    severity_filter: list[str]
    created_by: str
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class EnrichValueRequest(BaseModel):
    value: str


class EnrichAlertRequest(BaseModel):
    alert_id: str
    alert_data: dict
    pipeline_ids: Optional[list[str]] = None


@router.get("")
async def list_enrichment_pipelines(
    user: CurrentUserDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    active_only: bool = False,
    enrichment_type: Optional[EnrichmentType] = None,
) -> list[EnrichmentPipelineResponse]:
    """List all enrichment pipelines."""
    query = select(EnrichmentPipeline).order_by(EnrichmentPipeline.created_at.desc())

    if active_only:
        query = query.where(EnrichmentPipeline.is_active == True)
    if enrichment_type:
        query = query.where(EnrichmentPipeline.enrichment_type == enrichment_type)

    result = await db.execute(query)
    pipelines = result.scalars().all()

    return [
        EnrichmentPipelineResponse(
            id=p.id,
            name=p.name,
            description=p.description,
            enrichment_type=p.enrichment_type,
            source_field=p.source_field,
            target_field=p.target_field,
            api_endpoint=p.api_endpoint,
            api_headers=p.api_headers,
            api_key_env=p.api_key_env,
            cache_ttl_minutes=p.cache_ttl_minutes,
            is_active=p.is_active,
            auto_enrich=p.auto_enrich,
            severity_filter=p.severity_filter,
            created_by=p.created_by,
            created_at=p.created_at.isoformat(),
            updated_at=p.updated_at.isoformat(),
        )
        for p in pipelines
    ]


@router.get("/types")
async def get_enrichment_types(user: CurrentUserDep) -> list[dict]:
    """Get available enrichment types."""
    return [
        {"value": t.value, "label": t.value.replace("_", " ").title()}
        for t in EnrichmentType
    ]


@router.get("/{pipeline_id}")
async def get_enrichment_pipeline(
    pipeline_id: UUID,
    user: CurrentUserDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> EnrichmentPipelineResponse:
    """Get an enrichment pipeline by ID."""
    result = await db.execute(
        select(EnrichmentPipeline).where(EnrichmentPipeline.id == pipeline_id)
    )
    pipeline = result.scalar_one_or_none()
    if not pipeline:
        raise HTTPException(status_code=404, detail="Enrichment pipeline not found")

    return EnrichmentPipelineResponse(
        id=pipeline.id,
        name=pipeline.name,
        description=pipeline.description,
        enrichment_type=pipeline.enrichment_type,
        source_field=pipeline.source_field,
        target_field=pipeline.target_field,
        api_endpoint=pipeline.api_endpoint,
        api_headers=pipeline.api_headers,
        api_key_env=pipeline.api_key_env,
        cache_ttl_minutes=pipeline.cache_ttl_minutes,
        is_active=pipeline.is_active,
        auto_enrich=pipeline.auto_enrich,
        severity_filter=pipeline.severity_filter,
        created_by=pipeline.created_by,
        created_at=pipeline.created_at.isoformat(),
        updated_at=pipeline.updated_at.isoformat(),
    )


@router.post("")
async def create_enrichment_pipeline(
    pipeline: EnrichmentPipelineCreate,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> EnrichmentPipelineResponse:
    """Create a new enrichment pipeline. Requires analyst role."""
    email, _ = analyst

    db_pipeline = EnrichmentPipeline(
        name=pipeline.name,
        description=pipeline.description,
        enrichment_type=pipeline.enrichment_type,
        source_field=pipeline.source_field,
        target_field=pipeline.target_field,
        api_endpoint=pipeline.api_endpoint,
        api_headers=pipeline.api_headers,
        api_key_env=pipeline.api_key_env,
        cache_ttl_minutes=pipeline.cache_ttl_minutes,
        is_active=pipeline.is_active,
        auto_enrich=pipeline.auto_enrich,
        severity_filter=pipeline.severity_filter,
        created_by=email,
    )
    db.add(db_pipeline)
    await db.flush()
    await db.refresh(db_pipeline)

    return EnrichmentPipelineResponse(
        id=db_pipeline.id,
        name=db_pipeline.name,
        description=db_pipeline.description,
        enrichment_type=db_pipeline.enrichment_type,
        source_field=db_pipeline.source_field,
        target_field=db_pipeline.target_field,
        api_endpoint=db_pipeline.api_endpoint,
        api_headers=db_pipeline.api_headers,
        api_key_env=db_pipeline.api_key_env,
        cache_ttl_minutes=db_pipeline.cache_ttl_minutes,
        is_active=db_pipeline.is_active,
        auto_enrich=db_pipeline.auto_enrich,
        severity_filter=db_pipeline.severity_filter,
        created_by=db_pipeline.created_by,
        created_at=db_pipeline.created_at.isoformat(),
        updated_at=db_pipeline.updated_at.isoformat(),
    )


@router.patch("/{pipeline_id}")
async def update_enrichment_pipeline(
    pipeline_id: UUID,
    update: EnrichmentPipelineUpdate,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> EnrichmentPipelineResponse:
    """Update an enrichment pipeline. Requires analyst role."""
    result = await db.execute(
        select(EnrichmentPipeline).where(EnrichmentPipeline.id == pipeline_id)
    )
    pipeline = result.scalar_one_or_none()
    if not pipeline:
        raise HTTPException(status_code=404, detail="Enrichment pipeline not found")

    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(pipeline, field, value)

    await db.flush()
    await db.refresh(pipeline)

    return EnrichmentPipelineResponse(
        id=pipeline.id,
        name=pipeline.name,
        description=pipeline.description,
        enrichment_type=pipeline.enrichment_type,
        source_field=pipeline.source_field,
        target_field=pipeline.target_field,
        api_endpoint=pipeline.api_endpoint,
        api_headers=pipeline.api_headers,
        api_key_env=pipeline.api_key_env,
        cache_ttl_minutes=pipeline.cache_ttl_minutes,
        is_active=pipeline.is_active,
        auto_enrich=pipeline.auto_enrich,
        severity_filter=pipeline.severity_filter,
        created_by=pipeline.created_by,
        created_at=pipeline.created_at.isoformat(),
        updated_at=pipeline.updated_at.isoformat(),
    )


@router.delete("/{pipeline_id}")
async def delete_enrichment_pipeline(
    pipeline_id: UUID,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete an enrichment pipeline. Requires analyst role."""
    result = await db.execute(
        select(EnrichmentPipeline).where(EnrichmentPipeline.id == pipeline_id)
    )
    pipeline = result.scalar_one_or_none()
    if not pipeline:
        raise HTTPException(status_code=404, detail="Enrichment pipeline not found")

    await db.delete(pipeline)
    return {"status": "deleted"}


@router.post("/{pipeline_id}/test")
async def test_enrichment_pipeline(
    pipeline_id: UUID,
    request: EnrichValueRequest,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Test an enrichment pipeline with a value."""
    result = await db.execute(
        select(EnrichmentPipeline).where(EnrichmentPipeline.id == pipeline_id)
    )
    pipeline = result.scalar_one_or_none()
    if not pipeline:
        raise HTTPException(status_code=404, detail="Enrichment pipeline not found")

    enrichment_result = await run_enrichment(db, pipeline, request.value)

    return {
        "pipeline_id": str(pipeline_id),
        "pipeline_name": pipeline.name,
        "input_value": request.value,
        "source": enrichment_result.get("source"),
        "data": enrichment_result.get("data", {}),
    }


@router.post("/enrich-alert")
async def enrich_alert_endpoint(
    request: EnrichAlertRequest,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Enrich an alert using active enrichment pipelines."""
    email, _ = analyst

    pipeline_ids = None
    if request.pipeline_ids:
        pipeline_ids = [UUID(pid) for pid in request.pipeline_ids]

    enrichments = await enrich_alert(
        db=db,
        alert_id=request.alert_id,
        alert_data=request.alert_data,
        user_email=email,
        pipeline_ids=pipeline_ids,
    )

    return {
        "alert_id": request.alert_id,
        "enrichment_count": len(enrichments),
        "enrichments": enrichments,
    }


@router.get("/alerts/{alert_id}")
async def get_alert_enrichments_endpoint(
    alert_id: str,
    user: CurrentUserDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Get all enrichments for an alert."""
    enrichments = await get_alert_enrichments(db, alert_id)

    return {
        "alert_id": alert_id,
        "enrichment_count": len(enrichments),
        "enrichments": enrichments,
    }
