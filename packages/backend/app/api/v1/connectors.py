"""
Connectors API

Endpoints for managing data source and action connectors.
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
    Connector,
    NormalizedAlert,
    ConnectorCategory,
    ConnectorStatus,
)
from app.api.v1.deps import OrgUserDep, OrgIdDep, OrgAdminDep
from app.services.encryption import get_encryption_service, EncryptionError
from app.services.connectors.base import (
    get_connector_registry,
    ConnectionTestResult,
)

router = APIRouter()


# ==================== Request/Response Models ====================

class ConnectorCreate(BaseModel):
    name: str
    description: Optional[str] = None
    category: ConnectorCategory
    connector_type: str
    config: dict = {}
    credentials: dict = {}
    sync_enabled: bool = True
    sync_interval_minutes: int = 5


class ConnectorUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    config: Optional[dict] = None
    credentials: Optional[dict] = None
    sync_enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = None
    status: Optional[ConnectorStatus] = None


class ConnectorResponse(BaseModel):
    id: UUID
    name: str
    description: Optional[str]
    category: ConnectorCategory
    connector_type: str
    status: ConnectorStatus
    config: dict
    sync_enabled: bool
    sync_interval_minutes: int
    last_health_check: Optional[str]
    last_error: Optional[str]
    last_sync_at: Optional[str]
    created_by: str
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


class ConnectorTypeInfo(BaseModel):
    type: str
    category: str
    name: str
    description: str
    icon: str
    config_schema: dict
    credential_schema: dict


class ConnectionTestResponse(BaseModel):
    success: bool
    message: str
    details: Optional[dict] = None
    latency_ms: Optional[int] = None


class NormalizedAlertResponse(BaseModel):
    id: UUID
    connector_id: UUID
    source_type: str
    external_id: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    created_at_source: str
    updated_at_source: Optional[str]
    rule_id: Optional[str]
    rule_name: Optional[str]
    tags: list
    mitre_tactics: list
    mitre_techniques: list
    ingested_at: str

    class Config:
        from_attributes = True


class ConnectorListResponse(BaseModel):
    items: list[ConnectorResponse]
    total: int


# ==================== Connector Endpoints ====================

@router.get("/types")
async def list_connector_types(
    user: OrgUserDep,
    category: Optional[ConnectorCategory] = None,
) -> list[ConnectorTypeInfo]:
    """List all available connector types with their configuration schemas."""
    registry = get_connector_registry()

    types = []
    if category is None or category == ConnectorCategory.DATA_SOURCE:
        for metadata in registry.list_data_sources():
            types.append(ConnectorTypeInfo(
                type=metadata.connector_type,
                category=metadata.category.value,
                name=metadata.display_name,
                description=metadata.description,
                icon=metadata.icon,
                config_schema=metadata.config_schema,
                credential_schema=metadata.credentials_schema,
            ))

    if category is None or category == ConnectorCategory.ACTION:
        for metadata in registry.list_actions():
            types.append(ConnectorTypeInfo(
                type=metadata.connector_type,
                category=metadata.category.value,
                name=metadata.display_name,
                description=metadata.description,
                icon=metadata.icon,
                config_schema=metadata.config_schema,
                credential_schema=metadata.credentials_schema,
            ))

    return types


@router.get("")
async def list_connectors(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    category: Optional[ConnectorCategory] = None,
    status: Optional[ConnectorStatus] = None,
) -> ConnectorListResponse:
    """List all configured connectors for the current organization."""
    query = select(Connector).where(
        Connector.organization_id == org_id
    ).order_by(desc(Connector.created_at))

    if category:
        query = query.where(Connector.category == category)
    if status:
        query = query.where(Connector.status == status)

    result = await db.execute(query)
    connectors = result.scalars().all()

    items = [
        ConnectorResponse(
            id=c.id,
            name=c.name,
            description=c.description,
            category=c.category,
            connector_type=c.connector_type,
            status=c.status,
            config=c.config,
            sync_enabled=c.sync_enabled,
            sync_interval_minutes=c.sync_interval_minutes,
            last_health_check=c.last_health_check.isoformat() if c.last_health_check else None,
            last_error=c.last_error,
            last_sync_at=c.last_sync_at.isoformat() if c.last_sync_at else None,
            created_by=c.created_by,
            created_at=c.created_at.isoformat(),
            updated_at=c.updated_at.isoformat(),
        )
        for c in connectors
    ]

    return ConnectorListResponse(items=items, total=len(items))


@router.get("/{connector_id}")
async def get_connector(
    connector_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ConnectorResponse:
    """Get a connector by ID (must belong to user's organization)."""
    result = await db.execute(
        select(Connector).where(
            and_(
                Connector.id == connector_id,
                Connector.organization_id == org_id,
            )
        )
    )
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")

    return ConnectorResponse(
        id=connector.id,
        name=connector.name,
        description=connector.description,
        category=connector.category,
        connector_type=connector.connector_type,
        status=connector.status,
        config=connector.config,
        sync_enabled=connector.sync_enabled,
        sync_interval_minutes=connector.sync_interval_minutes,
        last_health_check=connector.last_health_check.isoformat() if connector.last_health_check else None,
        last_error=connector.last_error,
        last_sync_at=connector.last_sync_at.isoformat() if connector.last_sync_at else None,
        created_by=connector.created_by,
        created_at=connector.created_at.isoformat(),
        updated_at=connector.updated_at.isoformat(),
    )


@router.post("")
async def create_connector(
    connector: ConnectorCreate,
    admin: OrgAdminDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ConnectorResponse:
    """Create a new connector for the organization. Requires admin role."""
    # Validate connector type exists
    registry = get_connector_registry()
    if connector.category == ConnectorCategory.DATA_SOURCE:
        if not registry.get_data_source(connector.connector_type):
            raise HTTPException(status_code=400, detail=f"Unknown data source type: {connector.connector_type}")
    else:
        if not registry.get_action(connector.connector_type):
            raise HTTPException(status_code=400, detail=f"Unknown action type: {connector.connector_type}")

    # Encrypt credentials
    encrypted_creds = None
    if connector.credentials:
        encryption = get_encryption_service()
        try:
            encrypted_creds = encryption.encrypt(connector.credentials)
        except EncryptionError as e:
            raise HTTPException(status_code=500, detail=f"Failed to encrypt credentials: {str(e)}")

    db_connector = Connector(
        organization_id=admin.organization_id,
        name=connector.name,
        description=connector.description,
        category=connector.category,
        connector_type=connector.connector_type,
        status=ConnectorStatus.PENDING,
        config=connector.config,
        credentials_encrypted=encrypted_creds,
        sync_enabled=connector.sync_enabled,
        sync_interval_minutes=connector.sync_interval_minutes,
        created_by=admin.email,
    )
    db.add(db_connector)
    await db.flush()
    await db.refresh(db_connector)

    return ConnectorResponse(
        id=db_connector.id,
        name=db_connector.name,
        description=db_connector.description,
        category=db_connector.category,
        connector_type=db_connector.connector_type,
        status=db_connector.status,
        config=db_connector.config,
        sync_enabled=db_connector.sync_enabled,
        sync_interval_minutes=db_connector.sync_interval_minutes,
        last_health_check=None,
        last_error=None,
        last_sync_at=None,
        created_by=db_connector.created_by,
        created_at=db_connector.created_at.isoformat(),
        updated_at=db_connector.updated_at.isoformat(),
    )


@router.patch("/{connector_id}")
async def update_connector(
    connector_id: UUID,
    update: ConnectorUpdate,
    admin: OrgAdminDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ConnectorResponse:
    """Update a connector. Requires admin role."""
    result = await db.execute(
        select(Connector).where(
            and_(
                Connector.id == connector_id,
                Connector.organization_id == admin.organization_id,
            )
        )
    )
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")

    update_data = update.model_dump(exclude_unset=True)

    # Handle credential updates
    if "credentials" in update_data and update_data["credentials"]:
        encryption = get_encryption_service()
        try:
            connector.credentials_encrypted = encryption.encrypt(update_data["credentials"])
        except EncryptionError as e:
            raise HTTPException(status_code=500, detail=f"Failed to encrypt credentials: {str(e)}")
        del update_data["credentials"]

    for field, value in update_data.items():
        setattr(connector, field, value)

    await db.flush()
    await db.refresh(connector)

    return ConnectorResponse(
        id=connector.id,
        name=connector.name,
        description=connector.description,
        category=connector.category,
        connector_type=connector.connector_type,
        status=connector.status,
        config=connector.config,
        sync_enabled=connector.sync_enabled,
        sync_interval_minutes=connector.sync_interval_minutes,
        last_health_check=connector.last_health_check.isoformat() if connector.last_health_check else None,
        last_error=connector.last_error,
        last_sync_at=connector.last_sync_at.isoformat() if connector.last_sync_at else None,
        created_by=connector.created_by,
        created_at=connector.created_at.isoformat(),
        updated_at=connector.updated_at.isoformat(),
    )


@router.delete("/{connector_id}")
async def delete_connector(
    connector_id: UUID,
    admin: OrgAdminDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete a connector. Requires admin role."""
    result = await db.execute(
        select(Connector).where(
            and_(
                Connector.id == connector_id,
                Connector.organization_id == admin.organization_id,
            )
        )
    )
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")

    await db.delete(connector)
    return {"status": "deleted"}


@router.post("/{connector_id}/test")
async def test_connector(
    connector_id: UUID,
    admin: OrgAdminDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ConnectionTestResponse:
    """Test a connector's connection. Requires admin role."""
    result = await db.execute(
        select(Connector).where(
            and_(
                Connector.id == connector_id,
                Connector.organization_id == admin.organization_id,
            )
        )
    )
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")

    # Decrypt credentials
    credentials = {}
    if connector.credentials_encrypted:
        encryption = get_encryption_service()
        try:
            credentials = encryption.decrypt(connector.credentials_encrypted)
        except EncryptionError as e:
            raise HTTPException(status_code=500, detail=f"Failed to decrypt credentials: {str(e)}")

    # Get connector implementation
    registry = get_connector_registry()
    if connector.category == ConnectorCategory.DATA_SOURCE:
        connector_cls = registry.get_data_source(connector.connector_type)
    else:
        connector_cls = registry.get_action(connector.connector_type)

    if not connector_cls:
        raise HTTPException(status_code=400, detail=f"Unknown connector type: {connector.connector_type}")

    # Test connection
    connector_instance = connector_cls(connector.id, connector.config, credentials)
    test_result = await connector_instance.test_connection()

    # Update connector status
    connector.last_health_check = datetime.utcnow()
    if test_result.success:
        connector.status = ConnectorStatus.CONNECTED
        connector.last_error = None
    else:
        connector.status = ConnectorStatus.ERROR
        connector.last_error = test_result.message

    await db.flush()

    return ConnectionTestResponse(
        success=test_result.success,
        message=test_result.message,
        details=test_result.details,
        latency_ms=test_result.latency_ms,
    )


@router.post("/{connector_id}/sync")
async def trigger_sync(
    connector_id: UUID,
    admin: OrgAdminDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    background_tasks: BackgroundTasks,
) -> dict:
    """Trigger a manual sync for a data source connector. Requires admin role."""
    result = await db.execute(
        select(Connector).where(
            and_(
                Connector.id == connector_id,
                Connector.organization_id == admin.organization_id,
            )
        )
    )
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")

    if connector.category != ConnectorCategory.DATA_SOURCE:
        raise HTTPException(status_code=400, detail="Only data source connectors can be synced")

    if connector.status != ConnectorStatus.CONNECTED:
        raise HTTPException(status_code=400, detail="Connector is not connected")

    # Queue sync in background (pass org_id for proper alert creation)
    background_tasks.add_task(sync_connector_alerts, connector_id, admin.organization_id)

    return {"status": "sync_queued", "connector_id": str(connector_id)}


async def sync_connector_alerts(connector_id: UUID, organization_id: UUID):
    """Background task to sync alerts from a connector."""
    from app.db.session import AsyncSessionLocal
    from app.config import settings

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Connector).where(
                and_(
                    Connector.id == connector_id,
                    Connector.organization_id == organization_id,
                )
            )
        )
        connector = result.scalar_one_or_none()
        if not connector:
            return

        # Decrypt credentials
        credentials = {}
        if connector.credentials_encrypted:
            encryption = get_encryption_service()
            credentials = encryption.decrypt(connector.credentials_encrypted)

        # Get connector implementation
        registry = get_connector_registry()
        connector_cls = registry.get_data_source(connector.connector_type)
        if not connector_cls:
            return

        connector_instance = connector_cls(connector.id, connector.config, credentials)

        # Calculate sync time range
        from datetime import timedelta
        since = datetime.utcnow() - timedelta(days=settings.alert_sync_max_age_days)
        if connector.last_sync_at:
            since = connector.last_sync_at

        try:
            cursor = connector.last_sync_cursor
            total_synced = 0

            while True:
                alerts, next_cursor = await connector_instance.fetch_alerts(
                    since=since,
                    limit=settings.alert_sync_batch_size,
                    cursor=cursor,
                )

                for alert in alerts:
                    # Set organization_id on the alert
                    alert.organization_id = organization_id

                    # Check if alert already exists
                    existing = await db.execute(
                        select(NormalizedAlert).where(
                            and_(
                                NormalizedAlert.organization_id == organization_id,
                                NormalizedAlert.connector_id == connector_id,
                                NormalizedAlert.external_id == alert.external_id,
                            )
                        )
                    )
                    if existing.scalar_one_or_none():
                        continue

                    db.add(alert)
                    total_synced += 1

                await db.flush()

                if not next_cursor:
                    break
                cursor = next_cursor

            connector.last_sync_at = datetime.utcnow()
            connector.last_sync_cursor = None
            connector.last_error = None
            await db.commit()

        except Exception as e:
            connector.last_error = str(e)
            await db.commit()


# ==================== Normalized Alerts Endpoints ====================

@router.get("/{connector_id}/alerts")
async def list_connector_alerts(
    connector_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
) -> dict:
    """List alerts from a specific connector (must belong to user's organization)."""
    # Verify connector exists and belongs to user's org
    result = await db.execute(
        select(Connector).where(
            and_(
                Connector.id == connector_id,
                Connector.organization_id == org_id,
            )
        )
    )
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")

    # Build query - filter by org_id
    query = select(NormalizedAlert).where(
        and_(
            NormalizedAlert.organization_id == org_id,
            NormalizedAlert.connector_id == connector_id,
        )
    )

    if severity:
        query = query.where(NormalizedAlert.severity == severity.lower())
    if status:
        query = query.where(NormalizedAlert.status == status.lower())

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Get alerts
    query = query.order_by(desc(NormalizedAlert.created_at_source))
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return {
        "items": [
            NormalizedAlertResponse(
                id=a.id,
                connector_id=a.connector_id,
                source_type=a.source_type,
                external_id=a.external_id,
                title=a.title,
                description=a.description,
                severity=a.severity,
                status=a.status,
                created_at_source=a.created_at_source.isoformat(),
                updated_at_source=a.updated_at_source.isoformat() if a.updated_at_source else None,
                rule_id=a.rule_id,
                rule_name=a.rule_name,
                tags=a.tags,
                mitre_tactics=a.mitre_tactics,
                mitre_techniques=a.mitre_techniques,
                ingested_at=a.ingested_at.isoformat(),
            )
            for a in alerts
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/alerts/unified")
async def list_unified_alerts(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    source_type: Optional[str] = None,
    connector_id: Optional[UUID] = None,
) -> dict:
    """List alerts from all connected sources (unified view) for the current organization."""
    # Filter by organization
    query = select(NormalizedAlert).where(NormalizedAlert.organization_id == org_id)

    if severity:
        query = query.where(NormalizedAlert.severity == severity.lower())
    if status:
        query = query.where(NormalizedAlert.status == status.lower())
    if source_type:
        query = query.where(NormalizedAlert.source_type == source_type)
    if connector_id:
        query = query.where(NormalizedAlert.connector_id == connector_id)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Get alerts
    query = query.order_by(desc(NormalizedAlert.created_at_source))
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    alerts = result.scalars().all()

    return {
        "items": [
            NormalizedAlertResponse(
                id=a.id,
                connector_id=a.connector_id,
                source_type=a.source_type,
                external_id=a.external_id,
                title=a.title,
                description=a.description,
                severity=a.severity,
                status=a.status,
                created_at_source=a.created_at_source.isoformat(),
                updated_at_source=a.updated_at_source.isoformat() if a.updated_at_source else None,
                rule_id=a.rule_id,
                rule_name=a.rule_name,
                tags=a.tags,
                mitre_tactics=a.mitre_tactics,
                mitre_techniques=a.mitre_techniques,
                ingested_at=a.ingested_at.isoformat(),
            )
            for a in alerts
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@router.get("/alerts/{alert_id}")
async def get_normalized_alert(
    alert_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Get a normalized alert with its raw data (must belong to user's organization)."""
    result = await db.execute(
        select(NormalizedAlert).where(
            and_(
                NormalizedAlert.id == alert_id,
                NormalizedAlert.organization_id == org_id,
            )
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {
        "id": str(alert.id),
        "connector_id": str(alert.connector_id),
        "source_type": alert.source_type,
        "external_id": alert.external_id,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "status": alert.status,
        "created_at_source": alert.created_at_source.isoformat(),
        "updated_at_source": alert.updated_at_source.isoformat() if alert.updated_at_source else None,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "tags": alert.tags,
        "mitre_tactics": alert.mitre_tactics,
        "mitre_techniques": alert.mitre_techniques,
        "raw_data": alert.raw_data,
        "ingested_at": alert.ingested_at.isoformat(),
    }
