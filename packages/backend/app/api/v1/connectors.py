"""
Connectors API

Endpoints for managing data source and action connectors.
All endpoints are organization-scoped for multi-tenancy.
"""

import logging
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAdminDep, OrgIdDep, OrgUserDep
from app.core.time_utils import utcnow
from app.db import get_db
from app.db.models import (
    Connector,
    ConnectorCategory,
    ConnectorStatus,
    NormalizedAlert,
)
from app.services.connectors.base import (
    get_connector_registry,
)
from app.services.encryption import EncryptionError, get_encryption_service

logger = logging.getLogger(__name__)

router = APIRouter()


# ==================== Request/Response Models ====================


class ConnectorCreate(BaseModel):
    name: str
    description: str | None = None
    category: ConnectorCategory
    connector_type: str
    config: dict = {}
    credentials: dict = {}
    sync_enabled: bool = True
    sync_interval_minutes: int = 5


class ConnectorUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    config: dict | None = None
    credentials: dict | None = None
    sync_enabled: bool | None = None
    sync_interval_minutes: int | None = None
    status: ConnectorStatus | None = None


class ConnectorResponse(BaseModel):
    id: UUID
    name: str
    description: str | None
    category: ConnectorCategory
    connector_type: str
    status: ConnectorStatus
    config: dict
    sync_enabled: bool
    sync_interval_minutes: int
    last_health_check: str | None
    last_error: str | None
    last_sync_at: str | None
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
    details: dict | None = None
    latency_ms: int | None = None


class NormalizedAlertResponse(BaseModel):
    id: UUID
    connector_id: UUID
    source_type: str
    external_id: str
    title: str
    description: str | None
    severity: str
    status: str
    created_at_source: str
    updated_at_source: str | None
    rule_id: str | None
    rule_name: str | None
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
    category: ConnectorCategory | None = None,
) -> list[ConnectorTypeInfo]:
    """List all available connector types with their configuration schemas."""
    registry = get_connector_registry()

    types = []
    if category is None or category == ConnectorCategory.DATA_SOURCE:
        for metadata in registry.list_data_sources():
            types.append(
                ConnectorTypeInfo(
                    type=metadata.connector_type,
                    category=metadata.category.value,
                    name=metadata.display_name,
                    description=metadata.description,
                    icon=metadata.icon,
                    config_schema=metadata.config_schema,
                    credential_schema=metadata.credentials_schema,
                )
            )

    if category is None or category == ConnectorCategory.ACTION:
        for metadata in registry.list_actions():
            types.append(
                ConnectorTypeInfo(
                    type=metadata.connector_type,
                    category=metadata.category.value,
                    name=metadata.display_name,
                    description=metadata.description,
                    icon=metadata.icon,
                    config_schema=metadata.config_schema,
                    credential_schema=metadata.credentials_schema,
                )
            )

    return types


@router.get("")
async def list_connectors(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    category: ConnectorCategory | None = None,
    status: ConnectorStatus | None = None,
) -> ConnectorListResponse:
    """List all configured connectors for the current organization."""
    query = (
        select(Connector)
        .where(Connector.organization_id == org_id)
        .order_by(desc(Connector.created_at))
    )

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
        last_health_check=connector.last_health_check.isoformat()
        if connector.last_health_check
        else None,
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
            raise HTTPException(
                status_code=400, detail=f"Unknown data source type: {connector.connector_type}"
            )
    else:
        if not registry.get_action(connector.connector_type):
            raise HTTPException(
                status_code=400, detail=f"Unknown action type: {connector.connector_type}"
            )

    # Encrypt credentials
    encrypted_creds = None
    if connector.credentials:
        encryption = get_encryption_service()
        try:
            encrypted_creds = encryption.encrypt(connector.credentials)
        except EncryptionError:
            logger.exception("Failed to encrypt connector credentials")
            raise HTTPException(status_code=500, detail="Failed to encrypt credentials")

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
        except EncryptionError:
            logger.exception("Failed to encrypt connector credentials")
            raise HTTPException(status_code=500, detail="Failed to encrypt credentials")
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
        last_health_check=connector.last_health_check.isoformat()
        if connector.last_health_check
        else None,
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
        except EncryptionError:
            logger.exception("Failed to decrypt connector credentials")
            raise HTTPException(status_code=500, detail="Failed to decrypt credentials")

    # Get connector implementation
    registry = get_connector_registry()
    if connector.category == ConnectorCategory.DATA_SOURCE:
        connector_cls = registry.get_data_source(connector.connector_type)
    else:
        connector_cls = registry.get_action(connector.connector_type)

    if not connector_cls:
        raise HTTPException(
            status_code=400, detail=f"Unknown connector type: {connector.connector_type}"
        )

    # Test connection
    connector_instance = connector_cls(connector.id, connector.config, credentials)
    test_result = await connector_instance.test_connection()

    # Update connector status
    connector.last_health_check = utcnow()
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
    full_sync: bool = Query(
        False, description="Force full resync from max age window, ignoring last sync time"
    ),
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

    if connector.status == ConnectorStatus.PENDING:
        raise HTTPException(
            status_code=400,
            detail="Connector has not been tested yet. Please test the connection first.",
        )

    if connector.status == ConnectorStatus.ERROR:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Connector is in error state: {connector.last_error or 'Unknown error'}. "
                "Please fix the issue and test the connection again."
            ),
        )

    if connector.status == ConnectorStatus.DISABLED:
        raise HTTPException(status_code=400, detail="Connector is disabled")

    if connector.status != ConnectorStatus.CONNECTED:
        raise HTTPException(
            status_code=400, detail=f"Connector is not connected (status: {connector.status.value})"
        )

    # Queue sync in background (pass org_id for proper alert creation)
    background_tasks.add_task(sync_connector_alerts, connector_id, admin.organization_id, full_sync)

    return {"status": "sync_queued", "connector_id": str(connector_id), "full_sync": full_sync}


async def _insert_alerts_skipping_duplicates(
    db: AsyncSession, alerts: list[NormalizedAlert]
) -> list[NormalizedAlert]:
    """Insert alerts, dropping any that collide on the alert unique index.

    ``uq_normalized_alerts_org_connector_external`` makes
    (organization_id, connector_id, external_id) unique, which is the only
    place the check-then-insert race between two overlapping syncs of the same
    connector can actually be settled. A collision used to abort the entire
    sync batch; here the batch is flushed inside a SAVEPOINT and, if it
    conflicts, retried alert-by-alert so only the duplicates are dropped.

    Returns the alerts that were actually inserted.
    """
    if not alerts:
        return []

    try:
        async with db.begin_nested():
            db.add_all(alerts)
            await db.flush()
        return list(alerts)
    except IntegrityError:
        logger.info(
            "Duplicate alert(s) in a batch of %d; falling back to per-alert insert",
            len(alerts),
        )

    inserted: list[NormalizedAlert] = []
    for alert in alerts:
        try:
            async with db.begin_nested():
                db.add(alert)
                await db.flush()
            inserted.append(alert)
        except IntegrityError:
            logger.debug(
                "Skipping alert already ingested for connector %s (external_id=%s)",
                alert.connector_id,
                alert.external_id,
            )
    return inserted


async def sync_connector_alerts(connector_id: UUID, organization_id: UUID, full_sync: bool = False):
    """Background task to sync alerts from a connector."""
    import logging

    from app.config import settings
    from app.db.session import AsyncSessionLocal
    from app.services.correlation_service import CorrelationService

    logger = logging.getLogger(__name__)
    logger.info(f"Starting sync for connector {connector_id}, full_sync={full_sync}")

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

        # Initialize correlation service for auto-incident creation
        correlation_service = CorrelationService(db)

        # Calculate sync time range
        from datetime import timedelta

        since = utcnow() - timedelta(days=settings.alert_sync_max_age_days)
        if connector.last_sync_at and not full_sync:
            since = connector.last_sync_at

        logger.info(f"Syncing alerts since {since} (full_sync={full_sync})")

        try:
            cursor = connector.last_sync_cursor
            total_synced = 0
            total_incidents = 0

            while True:
                alerts, next_cursor = await connector_instance.fetch_alerts(
                    since=since,
                    limit=settings.alert_sync_batch_size,
                    cursor=cursor,
                )

                candidates = []
                for alert in alerts:
                    # Set organization_id on the alert
                    alert.organization_id = organization_id

                    # Cheap pre-filter for alerts we already have. This is a
                    # check-then-insert and therefore racy on its own; the
                    # unique index is what actually settles concurrent syncs.
                    existing = await db.execute(
                        select(NormalizedAlert.id)
                        .where(
                            and_(
                                NormalizedAlert.organization_id == organization_id,
                                NormalizedAlert.connector_id == connector_id,
                                NormalizedAlert.external_id == alert.external_id,
                            )
                        )
                        .limit(1)
                    )
                    if existing.scalar():
                        continue

                    candidates.append(alert)

                new_alerts = await _insert_alerts_skipping_duplicates(db, candidates)
                total_synced += len(new_alerts)

                # Process new alerts through correlation rules
                if new_alerts:
                    incidents = await correlation_service.process_alerts_batch(
                        new_alerts, organization_id
                    )
                    total_incidents += len(incidents)

                # CNAPP layer: upsert the assets these alerts concern, then
                # re-evaluate toxic combinations on them. Contained: a failure
                # here must never abort the alert sync itself.
                if new_alerts:
                    try:
                        from app.services.asset_service import link_alerts_batch
                        from app.services.attack_path_service import evaluate_assets

                        touched_assets = await link_alerts_batch(
                            db, new_alerts, organization_id
                        )
                        if touched_assets:
                            await evaluate_assets(db, organization_id, touched_assets)
                    except Exception:
                        logger.exception(
                            f"Asset/attack-path processing failed for connector {connector_id}"
                        )

                if not next_cursor:
                    break
                cursor = next_cursor

            connector.last_sync_at = utcnow()
            connector.last_sync_cursor = None
            connector.last_error = None
            await db.commit()

            logger.info(
                f"Sync completed for connector {connector_id}: "
                f"{total_synced} alerts synced, {total_incidents} incidents created"
            )

        except Exception as e:
            logger.exception(f"Sync failed for connector {connector_id}: {e}")
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
    severity: str | None = None,
    status: str | None = None,
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
    severity: str | None = None,
    status: str | None = None,
    source_type: str | None = None,
    connector_id: UUID | None = None,
    exclude_resolved: bool | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
) -> dict:
    """List alerts from all connected sources (unified view) for the current organization."""
    # Filter by organization
    query = select(NormalizedAlert).where(NormalizedAlert.organization_id == org_id)

    if severity:
        query = query.where(NormalizedAlert.severity == severity.lower())
    if status:
        query = query.where(NormalizedAlert.status == status.lower())
    if exclude_resolved:
        query = query.where(NormalizedAlert.status != "resolved")
    if source_type:
        query = query.where(NormalizedAlert.source_type == source_type)
    if connector_id:
        query = query.where(NormalizedAlert.connector_id == connector_id)
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00")).replace(
                tzinfo=None
            )
            query = query.where(NormalizedAlert.created_at_source >= start_dt)
        except ValueError:
            pass
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00")).replace(tzinfo=None)
            query = query.where(NormalizedAlert.created_at_source <= end_dt)
        except ValueError:
            pass

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    # Get severity counts (apply all filters except severity filter for accurate totals)
    severity_counts_query = select(NormalizedAlert.severity, func.count().label("count")).where(
        NormalizedAlert.organization_id == org_id
    )
    # Apply same filters as main query (except severity) for accurate counts
    if status:
        severity_counts_query = severity_counts_query.where(
            NormalizedAlert.status == status.lower()
        )
    if exclude_resolved:
        severity_counts_query = severity_counts_query.where(NormalizedAlert.status != "resolved")
    if source_type:
        severity_counts_query = severity_counts_query.where(
            NormalizedAlert.source_type == source_type
        )
    if connector_id:
        severity_counts_query = severity_counts_query.where(
            NormalizedAlert.connector_id == connector_id
        )
    if start_date:
        try:
            start_dt = datetime.fromisoformat(start_date.replace("Z", "+00:00")).replace(
                tzinfo=None
            )
            severity_counts_query = severity_counts_query.where(
                NormalizedAlert.created_at_source >= start_dt
            )
        except ValueError:
            pass
    if end_date:
        try:
            end_dt = datetime.fromisoformat(end_date.replace("Z", "+00:00")).replace(tzinfo=None)
            severity_counts_query = severity_counts_query.where(
                NormalizedAlert.created_at_source <= end_dt
            )
        except ValueError:
            pass

    severity_counts_query = severity_counts_query.group_by(NormalizedAlert.severity)
    severity_result = await db.execute(severity_counts_query)
    severity_rows = severity_result.all()
    severity_counts = {row[0]: row[1] for row in severity_rows if row[0]}

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
        "severity_counts": severity_counts,
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
        "updated_at_source": alert.updated_at_source.isoformat()
        if alert.updated_at_source
        else None,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "tags": alert.tags,
        "mitre_tactics": alert.mitre_tactics,
        "mitre_techniques": alert.mitre_techniques,
        "raw_data": alert.raw_data,
        "ingested_at": alert.ingested_at.isoformat(),
    }
