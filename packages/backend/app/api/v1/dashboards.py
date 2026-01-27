from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import select, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db, CustomDashboard, WidgetType
from app.api.v1.deps import OrgUserDep, OrgIdDep, OrgAnalystDep

router = APIRouter()


class WidgetConfig(BaseModel):
    id: str
    widget_type: WidgetType
    title: str
    config: dict = {}


class LayoutItem(BaseModel):
    i: str  # Widget ID
    x: int
    y: int
    w: int
    h: int
    minW: Optional[int] = None
    minH: Optional[int] = None


class DashboardCreate(BaseModel):
    name: str
    description: Optional[str] = None
    is_shared: bool = False
    layout: list[LayoutItem] = []
    widgets: list[WidgetConfig] = []


class DashboardUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_default: Optional[bool] = None
    is_shared: Optional[bool] = None
    layout: Optional[list[LayoutItem]] = None
    widgets: Optional[list[WidgetConfig]] = None


class DashboardResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    is_default: bool
    is_shared: bool
    layout: list
    widgets: list
    owner_email: str
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


@router.get("")
async def list_dashboards(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[DashboardResponse]:
    """List all dashboards accessible to the current user."""
    email, _ = user

    # Get user's own dashboards and shared dashboards within the organization
    result = await db.execute(
        select(CustomDashboard)
        .where(
            and_(
                CustomDashboard.organization_id == org_id,
                or_(
                    CustomDashboard.owner_email == email,
                    CustomDashboard.is_shared == True,
                ),
            )
        )
        .order_by(CustomDashboard.is_default.desc(), CustomDashboard.created_at.desc())
    )
    dashboards = result.scalars().all()

    return [
        DashboardResponse(
            id=d.id,
            name=d.name,
            description=d.description,
            is_default=d.is_default,
            is_shared=d.is_shared,
            layout=d.layout,
            widgets=d.widgets,
            owner_email=d.owner_email,
            created_at=d.created_at.isoformat(),
            updated_at=d.updated_at.isoformat(),
        )
        for d in dashboards
    ]


@router.get("/widget-types")
async def get_widget_types(user: OrgUserDep) -> list[dict]:
    """Get available widget types."""
    widget_info = {
        WidgetType.ALERT_SUMMARY: {
            "label": "Alert Summary",
            "description": "Shows total alerts count with breakdown",
            "default_size": {"w": 2, "h": 2},
        },
        WidgetType.ALERTS_BY_SEVERITY: {
            "label": "Alerts by Severity",
            "description": "Pie/bar chart of alerts by severity",
            "default_size": {"w": 3, "h": 3},
        },
        WidgetType.ALERTS_BY_STATUS: {
            "label": "Alerts by Status",
            "description": "Pie/bar chart of alerts by status",
            "default_size": {"w": 3, "h": 3},
        },
        WidgetType.ALERTS_OVER_TIME: {
            "label": "Alerts Over Time",
            "description": "Line chart showing alert trend",
            "default_size": {"w": 4, "h": 3},
        },
        WidgetType.TOP_RULES: {
            "label": "Top Alerting Rules",
            "description": "List of rules with most alerts",
            "default_size": {"w": 3, "h": 4},
        },
        WidgetType.RECENT_ALERTS: {
            "label": "Recent Alerts",
            "description": "Table of most recent alerts",
            "default_size": {"w": 4, "h": 4},
        },
        WidgetType.INCIDENT_SUMMARY: {
            "label": "Incident Summary",
            "description": "Overview of incidents by status",
            "default_size": {"w": 2, "h": 2},
        },
        WidgetType.CASE_SUMMARY: {
            "label": "Case Summary",
            "description": "Overview of cases by status",
            "default_size": {"w": 2, "h": 2},
        },
        WidgetType.SLA_STATUS: {
            "label": "SLA Status",
            "description": "SLA compliance overview",
            "default_size": {"w": 3, "h": 2},
        },
        WidgetType.CUSTOM_QUERY: {
            "label": "Custom Query",
            "description": "Display results from a custom query",
            "default_size": {"w": 4, "h": 4},
        },
    }

    return [
        {
            "value": t.value,
            "label": widget_info[t]["label"],
            "description": widget_info[t]["description"],
            "default_size": widget_info[t]["default_size"],
        }
        for t in WidgetType
    ]


@router.get("/{dashboard_id}")
async def get_dashboard(
    dashboard_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DashboardResponse:
    """Get a dashboard by ID."""
    email, _ = user

    result = await db.execute(
        select(CustomDashboard).where(
            and_(
                CustomDashboard.id == dashboard_id,
                CustomDashboard.organization_id == org_id,
            )
        )
    )
    dashboard = result.scalar_one_or_none()

    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")

    # Check access
    if dashboard.owner_email != email and not dashboard.is_shared:
        raise HTTPException(status_code=403, detail="Access denied")

    return DashboardResponse(
        id=dashboard.id,
        name=dashboard.name,
        description=dashboard.description,
        is_default=dashboard.is_default,
        is_shared=dashboard.is_shared,
        layout=dashboard.layout,
        widgets=dashboard.widgets,
        owner_email=dashboard.owner_email,
        created_at=dashboard.created_at.isoformat(),
        updated_at=dashboard.updated_at.isoformat(),
    )


@router.post("")
async def create_dashboard(
    dashboard: DashboardCreate,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DashboardResponse:
    """Create a new dashboard."""
    db_dashboard = CustomDashboard(
        name=dashboard.name,
        description=dashboard.description,
        is_shared=dashboard.is_shared,
        layout=[l.model_dump() for l in dashboard.layout],
        widgets=[w.model_dump() for w in dashboard.widgets],
        owner_email=analyst.email,
        organization_id=analyst.organization_id,
    )
    db.add(db_dashboard)
    await db.flush()
    await db.refresh(db_dashboard)

    return DashboardResponse(
        id=db_dashboard.id,
        name=db_dashboard.name,
        description=db_dashboard.description,
        is_default=db_dashboard.is_default,
        is_shared=db_dashboard.is_shared,
        layout=db_dashboard.layout,
        widgets=db_dashboard.widgets,
        owner_email=db_dashboard.owner_email,
        created_at=db_dashboard.created_at.isoformat(),
        updated_at=db_dashboard.updated_at.isoformat(),
    )


@router.patch("/{dashboard_id}")
async def update_dashboard(
    dashboard_id: UUID,
    update: DashboardUpdate,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> DashboardResponse:
    """Update a dashboard."""
    result = await db.execute(
        select(CustomDashboard).where(
            and_(
                CustomDashboard.id == dashboard_id,
                CustomDashboard.organization_id == analyst.organization_id,
            )
        )
    )
    dashboard = result.scalar_one_or_none()

    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")

    if dashboard.owner_email != analyst.email:
        raise HTTPException(status_code=403, detail="Only owner can update dashboard")

    update_data = update.model_dump(exclude_unset=True)

    # Handle setting as default
    if update_data.get("is_default"):
        # Unset other default dashboards for this user within the organization
        await db.execute(
            CustomDashboard.__table__.update()
            .where(
                and_(
                    CustomDashboard.owner_email == analyst.email,
                    CustomDashboard.organization_id == analyst.organization_id,
                    CustomDashboard.id != dashboard_id,
                )
            )
            .values(is_default=False)
        )

    # Convert nested models to dicts
    if "layout" in update_data and update_data["layout"]:
        update_data["layout"] = [
            l.model_dump() if hasattr(l, 'model_dump') else l
            for l in update_data["layout"]
        ]
    if "widgets" in update_data and update_data["widgets"]:
        update_data["widgets"] = [
            w.model_dump() if hasattr(w, 'model_dump') else w
            for w in update_data["widgets"]
        ]

    for field, value in update_data.items():
        setattr(dashboard, field, value)

    await db.flush()
    await db.refresh(dashboard)

    return DashboardResponse(
        id=dashboard.id,
        name=dashboard.name,
        description=dashboard.description,
        is_default=dashboard.is_default,
        is_shared=dashboard.is_shared,
        layout=dashboard.layout,
        widgets=dashboard.widgets,
        owner_email=dashboard.owner_email,
        created_at=dashboard.created_at.isoformat(),
        updated_at=dashboard.updated_at.isoformat(),
    )


@router.delete("/{dashboard_id}")
async def delete_dashboard(
    dashboard_id: UUID,
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete a dashboard."""
    result = await db.execute(
        select(CustomDashboard).where(
            and_(
                CustomDashboard.id == dashboard_id,
                CustomDashboard.organization_id == analyst.organization_id,
            )
        )
    )
    dashboard = result.scalar_one_or_none()

    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")

    if dashboard.owner_email != analyst.email:
        raise HTTPException(status_code=403, detail="Only owner can delete dashboard")

    await db.delete(dashboard)
    return {"status": "deleted"}
