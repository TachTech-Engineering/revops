"""
Compliance Dashboard API

Provides endpoints for managing compliance frameworks, controls, and assessments.
"""

import csv
import io
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.deps import OrgAdminDep, OrgIdDep, OrgUserDep
from app.core.time_utils import utcnow
from app.db import get_db
from app.db.models import (
    ComplianceAssessment,
    ComplianceControl,
    ComplianceFramework,
    ComplianceStatus,
)

router = APIRouter()


# ==================== Request/Response Models ====================


class FrameworkCreate(BaseModel):
    name: str
    description: str | None = None
    version: str | None = None


class FrameworkResponse(BaseModel):
    id: str
    name: str
    description: str | None
    version: str | None
    is_active: bool
    total_controls: int
    implemented_controls: int
    coverage_percentage: float
    last_assessment_date: str | None
    next_assessment_date: str | None
    created_at: str


class ControlCreate(BaseModel):
    control_id: str
    title: str
    description: str | None = None
    owner: str | None = None
    due_date: datetime | None = None


class ControlUpdate(BaseModel):
    status: str | None = None
    evidence: str | None = None
    evidence_links: list[str] | None = None
    owner: str | None = None
    due_date: datetime | None = None
    notes: str | None = None


class ControlResponse(BaseModel):
    id: str
    framework_id: str
    control_id: str
    title: str
    description: str | None
    status: str
    evidence: str | None
    evidence_links: list[str]
    owner: str | None
    due_date: str | None
    last_reviewed_at: str | None
    reviewed_by: str | None
    notes: str | None
    created_at: str
    updated_at: str


class AssessmentCreate(BaseModel):
    notes: str | None = None


class AssessmentResponse(BaseModel):
    id: str
    framework_id: str
    assessment_date: str
    coverage_score: float
    total_controls: int
    implemented_count: int
    partial_count: int
    not_implemented_count: int
    notes: str | None
    assessor: str | None


class DashboardSummary(BaseModel):
    total_frameworks: int
    active_frameworks: int
    total_controls: int
    implemented_controls: int
    partial_controls: int
    not_implemented_controls: int
    overall_coverage: float
    frameworks_summary: list[dict]


# ==================== Framework Endpoints ====================


@router.get("/frameworks", response_model=list[FrameworkResponse])
async def list_frameworks(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    is_active: bool | None = Query(None, description="Filter by active status"),
):
    """List all compliance frameworks for the organization."""
    query = select(ComplianceFramework).where(ComplianceFramework.organization_id == org_id)

    if is_active is not None:
        query = query.where(ComplianceFramework.is_active == is_active)

    query = query.order_by(ComplianceFramework.name)

    result = await db.execute(query)
    frameworks = result.scalars().all()

    return [
        FrameworkResponse(
            id=str(f.id),
            name=f.name,
            description=f.description,
            version=f.version,
            is_active=f.is_active,
            total_controls=f.total_controls,
            implemented_controls=f.implemented_controls,
            coverage_percentage=f.coverage_percentage,
            last_assessment_date=f.last_assessment_date.isoformat()
            if f.last_assessment_date
            else None,
            next_assessment_date=f.next_assessment_date.isoformat()
            if f.next_assessment_date
            else None,
            created_at=f.created_at.isoformat(),
        )
        for f in frameworks
    ]


@router.post("/frameworks", response_model=FrameworkResponse)
async def create_framework(
    request: FrameworkCreate,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Create a new compliance framework."""
    framework = ComplianceFramework(
        organization_id=org_id,
        name=request.name,
        description=request.description,
        version=request.version,
        created_by=user.email,
    )
    db.add(framework)
    await db.commit()
    await db.refresh(framework)

    return FrameworkResponse(
        id=str(framework.id),
        name=framework.name,
        description=framework.description,
        version=framework.version,
        is_active=framework.is_active,
        total_controls=framework.total_controls,
        implemented_controls=framework.implemented_controls,
        coverage_percentage=framework.coverage_percentage,
        last_assessment_date=None,
        next_assessment_date=None,
        created_at=framework.created_at.isoformat(),
    )


@router.get("/frameworks/{framework_id}", response_model=FrameworkResponse)
async def get_framework(
    framework_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific compliance framework."""
    result = await db.execute(
        select(ComplianceFramework).where(
            and_(
                ComplianceFramework.id == framework_id,
                ComplianceFramework.organization_id == org_id,
            )
        )
    )
    framework = result.scalar_one_or_none()

    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    return FrameworkResponse(
        id=str(framework.id),
        name=framework.name,
        description=framework.description,
        version=framework.version,
        is_active=framework.is_active,
        total_controls=framework.total_controls,
        implemented_controls=framework.implemented_controls,
        coverage_percentage=framework.coverage_percentage,
        last_assessment_date=framework.last_assessment_date.isoformat()
        if framework.last_assessment_date
        else None,
        next_assessment_date=framework.next_assessment_date.isoformat()
        if framework.next_assessment_date
        else None,
        created_at=framework.created_at.isoformat(),
    )


# ==================== Control Endpoints ====================


@router.get("/frameworks/{framework_id}/controls", response_model=list[ControlResponse])
async def list_controls(
    framework_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    status: str | None = Query(None, description="Filter by status"),
):
    """List all controls for a framework."""
    # Verify framework belongs to org
    framework_result = await db.execute(
        select(ComplianceFramework).where(
            and_(
                ComplianceFramework.id == framework_id,
                ComplianceFramework.organization_id == org_id,
            )
        )
    )
    if not framework_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Framework not found")

    query = select(ComplianceControl).where(ComplianceControl.framework_id == framework_id)

    if status:
        try:
            status_enum = ComplianceStatus(status)
            query = query.where(ComplianceControl.status == status_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    query = query.order_by(ComplianceControl.control_id)

    result = await db.execute(query)
    controls = result.scalars().all()

    return [
        ControlResponse(
            id=str(c.id),
            framework_id=str(c.framework_id),
            control_id=c.control_id,
            title=c.title,
            description=c.description,
            status=c.status.value,
            evidence=c.evidence,
            evidence_links=c.evidence_links or [],
            owner=c.owner,
            due_date=c.due_date.isoformat() if c.due_date else None,
            last_reviewed_at=c.last_reviewed_at.isoformat() if c.last_reviewed_at else None,
            reviewed_by=c.reviewed_by,
            notes=c.notes,
            created_at=c.created_at.isoformat(),
            updated_at=c.updated_at.isoformat(),
        )
        for c in controls
    ]


@router.post("/frameworks/{framework_id}/controls", response_model=ControlResponse)
async def create_control(
    framework_id: UUID,
    request: ControlCreate,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Create a new control for a framework."""
    # Verify framework
    framework_result = await db.execute(
        select(ComplianceFramework).where(
            and_(
                ComplianceFramework.id == framework_id,
                ComplianceFramework.organization_id == org_id,
            )
        )
    )
    framework = framework_result.scalar_one_or_none()
    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    control = ComplianceControl(
        organization_id=org_id,
        framework_id=framework_id,
        control_id=request.control_id,
        title=request.title,
        description=request.description,
        owner=request.owner,
        due_date=request.due_date,
    )
    db.add(control)

    # Update framework control count
    framework.total_controls += 1
    framework.coverage_percentage = (
        framework.implemented_controls / framework.total_controls * 100
        if framework.total_controls > 0
        else 0
    )

    await db.commit()
    await db.refresh(control)

    return ControlResponse(
        id=str(control.id),
        framework_id=str(control.framework_id),
        control_id=control.control_id,
        title=control.title,
        description=control.description,
        status=control.status.value,
        evidence=control.evidence,
        evidence_links=control.evidence_links or [],
        owner=control.owner,
        due_date=control.due_date.isoformat() if control.due_date else None,
        last_reviewed_at=None,
        reviewed_by=None,
        notes=control.notes,
        created_at=control.created_at.isoformat(),
        updated_at=control.updated_at.isoformat(),
    )


@router.patch("/controls/{control_id}", response_model=ControlResponse)
async def update_control(
    control_id: UUID,
    request: ControlUpdate,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Update a compliance control status."""
    result = await db.execute(
        select(ComplianceControl)
        .options(selectinload(ComplianceControl.framework))
        .where(
            and_(
                ComplianceControl.id == control_id,
                ComplianceControl.organization_id == org_id,
            )
        )
    )
    control = result.scalar_one_or_none()

    if not control:
        raise HTTPException(status_code=404, detail="Control not found")

    old_status = control.status

    # Update fields
    if request.status is not None:
        try:
            control.status = ComplianceStatus(request.status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {request.status}")

    if request.evidence is not None:
        control.evidence = request.evidence
    if request.evidence_links is not None:
        control.evidence_links = request.evidence_links
    if request.owner is not None:
        control.owner = request.owner
    if request.due_date is not None:
        control.due_date = request.due_date
    if request.notes is not None:
        control.notes = request.notes

    # Track review
    control.last_reviewed_at = utcnow()
    control.reviewed_by = user.email

    # Update framework counts if status changed
    if request.status and old_status != control.status:
        framework = control.framework

        # Recalculate implemented count
        impl_result = await db.execute(
            select(func.count(ComplianceControl.id)).where(
                and_(
                    ComplianceControl.framework_id == framework.id,
                    ComplianceControl.status == ComplianceStatus.IMPLEMENTED,
                )
            )
        )
        framework.implemented_controls = impl_result.scalar() or 0
        framework.coverage_percentage = (
            framework.implemented_controls / framework.total_controls * 100
            if framework.total_controls > 0
            else 0
        )

    await db.commit()
    await db.refresh(control)

    return ControlResponse(
        id=str(control.id),
        framework_id=str(control.framework_id),
        control_id=control.control_id,
        title=control.title,
        description=control.description,
        status=control.status.value,
        evidence=control.evidence,
        evidence_links=control.evidence_links or [],
        owner=control.owner,
        due_date=control.due_date.isoformat() if control.due_date else None,
        last_reviewed_at=control.last_reviewed_at.isoformat() if control.last_reviewed_at else None,
        reviewed_by=control.reviewed_by,
        notes=control.notes,
        created_at=control.created_at.isoformat(),
        updated_at=control.updated_at.isoformat(),
    )


# ==================== Dashboard Endpoints ====================


@router.get("/dashboard/summary", response_model=DashboardSummary)
async def get_dashboard_summary(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get compliance dashboard summary metrics."""
    # Get all frameworks
    frameworks_result = await db.execute(
        select(ComplianceFramework).where(ComplianceFramework.organization_id == org_id)
    )
    frameworks = frameworks_result.scalars().all()

    # Get control counts by status
    control_counts_result = await db.execute(
        select(ComplianceControl.status, func.count(ComplianceControl.id).label("count"))
        .where(ComplianceControl.organization_id == org_id)
        .group_by(ComplianceControl.status)
    )
    control_counts = {row[0].value: row[1] for row in control_counts_result.fetchall()}

    total_controls = sum(control_counts.values())
    implemented = control_counts.get("implemented", 0)
    partial = control_counts.get("partial", 0)
    not_implemented = control_counts.get("not_implemented", 0)

    overall_coverage = (implemented / total_controls * 100) if total_controls > 0 else 0

    frameworks_summary = [
        {
            "id": str(f.id),
            "name": f.name,
            "coverage": f.coverage_percentage,
            "total_controls": f.total_controls,
            "implemented": f.implemented_controls,
        }
        for f in frameworks
    ]

    return DashboardSummary(
        total_frameworks=len(frameworks),
        active_frameworks=sum(1 for f in frameworks if f.is_active),
        total_controls=total_controls,
        implemented_controls=implemented,
        partial_controls=partial,
        not_implemented_controls=not_implemented,
        overall_coverage=round(overall_coverage, 2),
        frameworks_summary=frameworks_summary,
    )


# ==================== Assessment Endpoints ====================


@router.post("/frameworks/{framework_id}/assessments", response_model=AssessmentResponse)
async def create_assessment(
    framework_id: UUID,
    request: AssessmentCreate,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Create a point-in-time compliance assessment."""
    # Get framework
    framework_result = await db.execute(
        select(ComplianceFramework).where(
            and_(
                ComplianceFramework.id == framework_id,
                ComplianceFramework.organization_id == org_id,
            )
        )
    )
    framework = framework_result.scalar_one_or_none()
    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")

    # Count controls by status
    counts_result = await db.execute(
        select(ComplianceControl.status, func.count(ComplianceControl.id).label("count"))
        .where(ComplianceControl.framework_id == framework_id)
        .group_by(ComplianceControl.status)
    )
    counts = {row[0].value: row[1] for row in counts_result.fetchall()}

    total = sum(counts.values())
    implemented = counts.get("implemented", 0)
    partial = counts.get("partial", 0)
    not_impl = counts.get("not_implemented", 0)

    coverage = (implemented / total * 100) if total > 0 else 0

    assessment = ComplianceAssessment(
        organization_id=org_id,
        framework_id=framework_id,
        assessment_date=utcnow(),
        coverage_score=coverage,
        total_controls=total,
        implemented_count=implemented,
        partial_count=partial,
        not_implemented_count=not_impl,
        notes=request.notes,
        assessor=user.email,
    )
    db.add(assessment)

    # Update framework
    framework.last_assessment_date = utcnow()

    await db.commit()
    await db.refresh(assessment)

    return AssessmentResponse(
        id=str(assessment.id),
        framework_id=str(assessment.framework_id),
        assessment_date=assessment.assessment_date.isoformat(),
        coverage_score=assessment.coverage_score,
        total_controls=assessment.total_controls,
        implemented_count=assessment.implemented_count,
        partial_count=assessment.partial_count,
        not_implemented_count=assessment.not_implemented_count,
        notes=assessment.notes,
        assessor=assessment.assessor,
    )


@router.get("/frameworks/{framework_id}/assessments", response_model=list[AssessmentResponse])
async def list_assessments(
    framework_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    limit: int = Query(10, le=100),
):
    """List assessment history for a framework."""
    result = await db.execute(
        select(ComplianceAssessment)
        .where(
            and_(
                ComplianceAssessment.framework_id == framework_id,
                ComplianceAssessment.organization_id == org_id,
            )
        )
        .order_by(ComplianceAssessment.assessment_date.desc())
        .limit(limit)
    )
    assessments = result.scalars().all()

    return [
        AssessmentResponse(
            id=str(a.id),
            framework_id=str(a.framework_id),
            assessment_date=a.assessment_date.isoformat(),
            coverage_score=a.coverage_score,
            total_controls=a.total_controls,
            implemented_count=a.implemented_count,
            partial_count=a.partial_count,
            not_implemented_count=a.not_implemented_count,
            notes=a.notes,
            assessor=a.assessor,
        )
        for a in assessments
    ]


# ==================== Export Endpoints ====================


@router.post("/reports/export")
async def export_compliance_report(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    framework_id: UUID | None = Query(None, description="Filter by framework"),
    format: str = Query("csv", description="Export format: csv or pdf"),
):
    """Export compliance report as CSV or PDF."""
    # Build query
    query = select(ComplianceControl).where(ComplianceControl.organization_id == org_id)
    if framework_id:
        query = query.where(ComplianceControl.framework_id == framework_id)

    query = query.order_by(ComplianceControl.control_id)

    result = await db.execute(query)
    controls = result.scalars().all()

    if format == "csv":
        # Generate CSV
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "Control ID",
                "Title",
                "Status",
                "Owner",
                "Due Date",
                "Last Reviewed",
                "Evidence",
                "Notes",
            ]
        )

        for c in controls:
            writer.writerow(
                [
                    c.control_id,
                    c.title,
                    c.status.value,
                    c.owner or "",
                    c.due_date.isoformat() if c.due_date else "",
                    c.last_reviewed_at.isoformat() if c.last_reviewed_at else "",
                    c.evidence or "",
                    c.notes or "",
                ]
            )

        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": (
                    f"attachment; filename=compliance_report_{utcnow().strftime('%Y%m%d')}.csv"
                )
            },
        )

    elif format == "pdf":
        # For PDF, we'd typically use a library like reportlab or weasyprint
        # For now, return a message indicating PDF generation
        raise HTTPException(
            status_code=501, detail="PDF export not yet implemented. Please use CSV format."
        )

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")
