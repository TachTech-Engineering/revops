from typing import Annotated, Optional
from uuid import UUID
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db, ScheduledReport, ReportFrequency
from app.api.v1.deps import RequireAnalystDep, CurrentUserDep
from app.services.report_service import ReportService
from app.services.email_service import email_service
from app.services.report_delivery_service import report_delivery_service

router = APIRouter()


class DeliveryConfig(BaseModel):
    type: str  # email, slack, teams, webhook
    recipients: Optional[list[str]] = None  # For email
    webhook_url: Optional[str] = None  # For webhooks


class ScheduledReportCreate(BaseModel):
    name: str
    description: Optional[str] = None
    report_type: str  # alert_summary, rule_summary, sla_metrics
    frequency: ReportFrequency
    recipients: list[str] = []
    filters: dict = {}
    delivery: Optional[list[DeliveryConfig]] = None
    is_active: bool = True


class ScheduledReportUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    report_type: Optional[str] = None
    frequency: Optional[ReportFrequency] = None
    recipients: Optional[list[str]] = None
    filters: Optional[dict] = None
    is_active: Optional[bool] = None


class ScheduledReportResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    report_type: str
    frequency: ReportFrequency
    recipients: list[str]
    filters: dict
    is_active: bool
    last_run_at: Optional[str]
    next_run_at: Optional[str]
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


@router.get("")
async def list_scheduled_reports(
    user: CurrentUserDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    active_only: bool = False,
) -> list[ScheduledReportResponse]:
    """List all scheduled reports."""
    query = select(ScheduledReport).order_by(ScheduledReport.created_at.desc())
    if active_only:
        query = query.where(ScheduledReport.is_active == True)

    result = await db.execute(query)
    reports = result.scalars().all()

    return [
        ScheduledReportResponse(
            id=r.id,
            name=r.name,
            description=r.description,
            report_type=r.report_type,
            frequency=r.frequency,
            recipients=r.recipients,
            filters=r.filters,
            is_active=r.is_active,
            last_run_at=r.last_run_at.isoformat() if r.last_run_at else None,
            next_run_at=r.next_run_at.isoformat() if r.next_run_at else None,
            created_at=r.created_at.isoformat(),
            updated_at=r.updated_at.isoformat(),
        )
        for r in reports
    ]


@router.get("/{report_id}")
async def get_scheduled_report(
    report_id: UUID,
    user: CurrentUserDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ScheduledReportResponse:
    """Get a scheduled report by ID."""
    result = await db.execute(select(ScheduledReport).where(ScheduledReport.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    return ScheduledReportResponse(
        id=report.id,
        name=report.name,
        description=report.description,
        report_type=report.report_type,
        frequency=report.frequency,
        recipients=report.recipients,
        filters=report.filters,
        is_active=report.is_active,
        last_run_at=report.last_run_at.isoformat() if report.last_run_at else None,
        next_run_at=report.next_run_at.isoformat() if report.next_run_at else None,
        created_at=report.created_at.isoformat(),
        updated_at=report.updated_at.isoformat(),
    )


@router.post("")
async def create_scheduled_report(
    report: ScheduledReportCreate,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ScheduledReportResponse:
    """Create a new scheduled report. Requires analyst role."""
    db_report = ScheduledReport(
        name=report.name,
        description=report.description,
        report_type=report.report_type,
        frequency=report.frequency,
        recipients=report.recipients,
        filters=report.filters,
        is_active=report.is_active,
    )
    db.add(db_report)
    await db.flush()
    await db.refresh(db_report)

    return ScheduledReportResponse(
        id=db_report.id,
        name=db_report.name,
        description=db_report.description,
        report_type=db_report.report_type,
        frequency=db_report.frequency,
        recipients=db_report.recipients,
        filters=db_report.filters,
        is_active=db_report.is_active,
        last_run_at=db_report.last_run_at.isoformat() if db_report.last_run_at else None,
        next_run_at=db_report.next_run_at.isoformat() if db_report.next_run_at else None,
        created_at=db_report.created_at.isoformat(),
        updated_at=db_report.updated_at.isoformat(),
    )


@router.patch("/{report_id}")
async def update_scheduled_report(
    report_id: UUID,
    update: ScheduledReportUpdate,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ScheduledReportResponse:
    """Update a scheduled report. Requires analyst role."""
    result = await db.execute(select(ScheduledReport).where(ScheduledReport.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(report, field, value)

    await db.flush()
    await db.refresh(report)

    return ScheduledReportResponse(
        id=report.id,
        name=report.name,
        description=report.description,
        report_type=report.report_type,
        frequency=report.frequency,
        recipients=report.recipients,
        filters=report.filters,
        is_active=report.is_active,
        last_run_at=report.last_run_at.isoformat() if report.last_run_at else None,
        next_run_at=report.next_run_at.isoformat() if report.next_run_at else None,
        created_at=report.created_at.isoformat(),
        updated_at=report.updated_at.isoformat(),
    )


@router.delete("/{report_id}")
async def delete_scheduled_report(
    report_id: UUID,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete a scheduled report. Requires analyst role."""
    result = await db.execute(select(ScheduledReport).where(ScheduledReport.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    await db.delete(report)
    return {"status": "deleted"}


@router.post("/{report_id}/run")
async def run_report_now(
    report_id: UUID,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Run a scheduled report immediately. Requires analyst role."""
    result = await db.execute(select(ScheduledReport).where(ScheduledReport.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    # Generate report
    report_service = ReportService(db)
    filename, content, mime_type = await report_service.generate_report(report)

    # Mock summary for delivery
    summary = {
        'total_alerts': 150,
        'by_severity': {'CRITICAL': 5, 'HIGH': 25, 'MEDIUM': 50, 'LOW': 50, 'INFO': 20},
        'by_status': {'OPEN': 30, 'TRIAGED': 40, 'RESOLVED': 60, 'CLOSED': 20},
    }
    period = "Last 7 days"

    # Deliver via email if recipients configured
    email_sent = False
    if report.recipients and email_service.is_configured():
        html_body = report_service.generate_html_email(report.name, summary, period)
        email_sent = await email_service.send_email(
            to=report.recipients,
            subject=f"Report: {report.name}",
            body_html=html_body,
            attachments=[(filename, content, mime_type)],
        )

    # Update last_run_at
    report.last_run_at = datetime.utcnow()
    await db.flush()

    return {
        "status": "completed",
        "filename": filename,
        "email_sent": email_sent,
        "recipients": report.recipients if email_sent else [],
    }


@router.get("/types")
async def list_report_types() -> list[dict]:
    """List available report types."""
    return [
        {"id": "alert_summary", "name": "Alert Summary", "description": "Summary of alerts by severity and status"},
        {"id": "rule_summary", "name": "Rule Summary", "description": "Summary of rule triggers"},
        {"id": "sla_metrics", "name": "SLA Metrics", "description": "SLA compliance metrics"},
    ]
