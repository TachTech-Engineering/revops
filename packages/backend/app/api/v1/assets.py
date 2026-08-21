"""
Cloud Asset Inventory API

Read/query surface for the CNAPP asset layer (CloudAsset, AssetRelationship,
AssetAlertLink) plus the bulk import endpoint external inventory tools
(Cartography, CloudQuery) push into.
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAnalystDep, OrgIdDep, OrgUserDep
from app.db import get_db
from app.db.models import (
    AssetAlertLink,
    AssetRelationship,
    AssetType,
    AttackPathFinding,
    AttackPathStatus,
    CloudAsset,
    NormalizedAlert,
)
from app.services.asset_service import upsert_asset, upsert_relationship

router = APIRouter()

IDENTITY_ASSET_TYPES = (AssetType.IAM_IDENTITY, AssetType.IAM_ROLE)


class AssetResponse(BaseModel):
    id: UUID
    external_id: str
    asset_type: str
    name: str
    provider: str | None
    account_id: str | None
    region: str | None
    internet_exposed: bool
    criticality: int
    data_classification: str | None
    labels: dict
    attrs: dict
    sources: list
    first_seen: str
    last_seen: str
    open_alert_count: int = 0
    open_attack_path_count: int = 0

    class Config:
        from_attributes = True


def _asset_response(
    asset: CloudAsset, open_alerts: int = 0, open_paths: int = 0
) -> AssetResponse:
    return AssetResponse(
        id=asset.id,
        external_id=asset.external_id,
        asset_type=asset.asset_type.value,
        name=asset.name,
        provider=asset.provider,
        account_id=asset.account_id,
        region=asset.region,
        internet_exposed=asset.internet_exposed,
        criticality=asset.criticality,
        data_classification=asset.data_classification,
        labels=asset.labels or {},
        attrs=asset.attrs or {},
        sources=asset.sources or [],
        first_seen=asset.first_seen.isoformat(),
        last_seen=asset.last_seen.isoformat(),
        open_alert_count=open_alerts,
        open_attack_path_count=open_paths,
    )


@router.get("")
async def list_assets(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    asset_type: str | None = None,
    provider: str | None = None,
    exposed_only: bool = False,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List assets with open alert / attack path counts."""
    open_alerts = (
        select(
            AssetAlertLink.asset_id.label("asset_id"),
            func.count(NormalizedAlert.id).label("alert_count"),
        )
        .join(NormalizedAlert, NormalizedAlert.id == AssetAlertLink.alert_id)
        .where(NormalizedAlert.status.in_(["open", "acknowledged"]))
        .group_by(AssetAlertLink.asset_id)
        .subquery()
    )
    open_paths = (
        select(
            AttackPathFinding.asset_id.label("asset_id"),
            func.count(AttackPathFinding.id).label("path_count"),
        )
        .where(AttackPathFinding.status == AttackPathStatus.OPEN)
        .group_by(AttackPathFinding.asset_id)
        .subquery()
    )

    query = (
        select(
            CloudAsset,
            func.coalesce(open_alerts.c.alert_count, 0),
            func.coalesce(open_paths.c.path_count, 0),
        )
        .outerjoin(open_alerts, open_alerts.c.asset_id == CloudAsset.id)
        .outerjoin(open_paths, open_paths.c.asset_id == CloudAsset.id)
        .where(CloudAsset.organization_id == org_id)
    )

    if asset_type:
        try:
            query = query.where(CloudAsset.asset_type == AssetType(asset_type))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unknown asset type: {asset_type}")
    if provider:
        query = query.where(CloudAsset.provider == provider)
    if exposed_only:
        query = query.where(CloudAsset.internet_exposed.is_(True))
    if search:
        pattern = f"%{search}%"
        query = query.where(
            or_(CloudAsset.name.ilike(pattern), CloudAsset.external_id.ilike(pattern))
        )

    count_result = await db.execute(
        select(func.count()).select_from(query.order_by(None).subquery())
    )
    total = count_result.scalar() or 0

    query = (
        query.order_by(
            func.coalesce(open_paths.c.path_count, 0).desc(),
            func.coalesce(open_alerts.c.alert_count, 0).desc(),
            CloudAsset.last_seen.desc(),
        )
        .limit(min(limit, 200))
        .offset(offset)
    )
    result = await db.execute(query)

    return {
        "total": total,
        "assets": [
            _asset_response(asset, alert_count, path_count)
            for asset, alert_count, path_count in result.all()
        ],
    }


@router.get("/summary")
async def asset_summary(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Inventory rollup for the dashboard."""
    by_type_result = await db.execute(
        select(CloudAsset.asset_type, func.count())
        .where(CloudAsset.organization_id == org_id)
        .group_by(CloudAsset.asset_type)
    )
    by_type = {row[0].value: row[1] for row in by_type_result.all()}

    exposed_result = await db.execute(
        select(func.count()).where(
            and_(
                CloudAsset.organization_id == org_id,
                CloudAsset.internet_exposed.is_(True),
            )
        )
    )
    by_provider_result = await db.execute(
        select(CloudAsset.provider, func.count())
        .where(
            and_(CloudAsset.organization_id == org_id, CloudAsset.provider.is_not(None))
        )
        .group_by(CloudAsset.provider)
    )

    return {
        "total": sum(by_type.values()),
        "by_type": by_type,
        "by_provider": {row[0]: row[1] for row in by_provider_result.all()},
        "internet_exposed": exposed_result.scalar() or 0,
    }


@router.get("/graph")
async def asset_graph(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = 500,
) -> dict:
    """Nodes/edges payload of the asset inventory for the graph view."""
    assets_result = await db.execute(
        select(CloudAsset)
        .where(CloudAsset.organization_id == org_id)
        .order_by(CloudAsset.last_seen.desc())
        .limit(min(limit, 2000))
    )
    assets = assets_result.scalars().all()
    asset_ids = {a.id for a in assets}

    edges_result = await db.execute(
        select(AssetRelationship).where(AssetRelationship.organization_id == org_id)
    )
    edges = [
        e
        for e in edges_result.scalars().all()
        if e.source_asset_id in asset_ids and e.target_asset_id in asset_ids
    ]

    open_paths_result = await db.execute(
        select(AttackPathFinding.asset_id, func.count())
        .where(
            and_(
                AttackPathFinding.organization_id == org_id,
                AttackPathFinding.status == AttackPathStatus.OPEN,
            )
        )
        .group_by(AttackPathFinding.asset_id)
    )
    open_paths = dict(open_paths_result.all())

    return {
        "nodes": [
            {
                "id": str(a.id),
                "label": a.name,
                "type": a.asset_type.value,
                "provider": a.provider,
                "internet_exposed": a.internet_exposed,
                "open_attack_paths": open_paths.get(a.id, 0),
            }
            for a in assets
        ],
        "edges": [
            {
                "id": str(e.id),
                "source": str(e.source_asset_id),
                "target": str(e.target_asset_id),
                "type": e.relationship_type,
            }
            for e in edges
        ],
    }


@router.get("/ciem/summary")
async def ciem_summary(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """CIEM-lite rollup: identity assets and their risk findings."""
    identity_count_result = await db.execute(
        select(func.count()).where(
            and_(
                CloudAsset.organization_id == org_id,
                CloudAsset.asset_type.in_(IDENTITY_ASSET_TYPES),
            )
        )
    )

    risky_result = await db.execute(
        select(CloudAsset, AttackPathFinding)
        .join(AttackPathFinding, AttackPathFinding.asset_id == CloudAsset.id)
        .where(
            and_(
                CloudAsset.organization_id == org_id,
                AttackPathFinding.rule_key == "privileged_identity_risk",
                AttackPathFinding.status == AttackPathStatus.OPEN,
            )
        )
        .order_by(AttackPathFinding.risk_score.desc())
        .limit(50)
    )
    risky = [
        {
            "asset_id": str(asset.id),
            "name": asset.name,
            "asset_type": asset.asset_type.value,
            "provider": asset.provider,
            "account_id": asset.account_id,
            "finding_id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity,
            "risk_score": finding.risk_score,
        }
        for asset, finding in risky_result.all()
    ]

    # Open IAM findings by severity across identity/account assets
    iam_alerts_result = await db.execute(
        select(NormalizedAlert.severity, func.count(func.distinct(NormalizedAlert.id)))
        .join(AssetAlertLink, AssetAlertLink.alert_id == NormalizedAlert.id)
        .join(CloudAsset, CloudAsset.id == AssetAlertLink.asset_id)
        .where(
            and_(
                CloudAsset.organization_id == org_id,
                CloudAsset.asset_type.in_(
                    (*IDENTITY_ASSET_TYPES, AssetType.CLOUD_ACCOUNT)
                ),
                NormalizedAlert.status.in_(["open", "acknowledged"]),
            )
        )
        .group_by(NormalizedAlert.severity)
    )

    return {
        "identity_assets": identity_count_result.scalar() or 0,
        "risky_identities": risky,
        "open_identity_findings_by_severity": dict(iam_alerts_result.all()),
    }


# ==================== Bulk import (Cartography / CloudQuery) ====================


class AssetImport(BaseModel):
    external_id: str = Field(max_length=1000)
    asset_type: str
    name: str = Field(max_length=500)
    provider: str | None = None
    account_id: str | None = None
    region: str | None = None
    internet_exposed: bool | None = None
    criticality: int | None = Field(default=None, ge=1, le=10)
    data_classification: str | None = None
    labels: dict = Field(default_factory=dict)
    attrs: dict = Field(default_factory=dict)


class RelationshipImport(BaseModel):
    source_external_id: str
    target_external_id: str
    relationship_type: str = Field(max_length=50)
    attrs: dict = Field(default_factory=dict)


class InventoryImport(BaseModel):
    source: str = Field(default="import", max_length=50)  # e.g. "cartography"
    assets: list[AssetImport] = Field(default_factory=list, max_length=5000)
    relationships: list[RelationshipImport] = Field(default_factory=list, max_length=10000)


@router.post("/import")
async def import_inventory(
    payload: InventoryImport,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Bulk upsert assets and relationships from an external inventory tool.

    Imports are authoritative for exposure: an explicit internet_exposed=False
    clears a flag finding-extraction set, because the inventory tool can see
    the actual network path.
    """
    imported = 0
    errors: list[str] = []
    id_by_external: dict[str, UUID] = {}

    for item in payload.assets:
        try:
            asset_type = AssetType(item.asset_type)
        except ValueError:
            errors.append(f"Unknown asset type '{item.asset_type}' for {item.external_id}")
            continue
        asset = await upsert_asset(
            db,
            org_id,
            item.external_id,
            asset_type,
            item.name,
            source=payload.source,
            provider=item.provider,
            account_id=item.account_id,
            region=item.region,
            internet_exposed=item.internet_exposed,
            criticality=item.criticality,
            data_classification=item.data_classification,
            labels=item.labels,
            attrs=item.attrs,
        )
        # Authoritative clear (upsert_asset only ever upgrades the flag)
        if item.internet_exposed is False and asset.internet_exposed:
            asset.internet_exposed = False
        id_by_external[item.external_id] = asset.id
        imported += 1

    linked = 0
    for rel in payload.relationships:
        source_id = id_by_external.get(rel.source_external_id)
        target_id = id_by_external.get(rel.target_external_id)
        # Fall back to assets already in inventory from a previous import
        if source_id is None:
            source_id = await _lookup_asset_id(db, org_id, rel.source_external_id)
        if target_id is None:
            target_id = await _lookup_asset_id(db, org_id, rel.target_external_id)
        if not source_id or not target_id:
            errors.append(
                f"Relationship references unknown asset(s): "
                f"{rel.source_external_id} -> {rel.target_external_id}"
            )
            continue
        await upsert_relationship(
            db, org_id, source_id, target_id, rel.relationship_type, rel.attrs
        )
        linked += 1

    return {
        "assets_imported": imported,
        "relationships_imported": linked,
        "errors": errors[:50],
    }


async def _lookup_asset_id(
    db: AsyncSession, org_id: UUID, external_id: str
) -> UUID | None:
    result = await db.execute(
        select(CloudAsset.id).where(
            and_(
                CloudAsset.organization_id == org_id,
                CloudAsset.external_id == external_id,
            )
        )
    )
    return result.scalar_one_or_none()


# ==================== Single asset (keep after static routes) ====================


@router.get("/{asset_id}")
async def get_asset(
    asset_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Asset detail with its relationships and open attack paths."""
    result = await db.execute(
        select(CloudAsset).where(
            and_(CloudAsset.id == asset_id, CloudAsset.organization_id == org_id)
        )
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    rel_result = await db.execute(
        select(AssetRelationship, CloudAsset)
        .join(
            CloudAsset,
            or_(
                and_(
                    AssetRelationship.source_asset_id == asset_id,
                    CloudAsset.id == AssetRelationship.target_asset_id,
                ),
                and_(
                    AssetRelationship.target_asset_id == asset_id,
                    CloudAsset.id == AssetRelationship.source_asset_id,
                ),
            ),
        )
        .where(AssetRelationship.organization_id == org_id)
    )
    relationships = [
        {
            "id": str(rel.id),
            "relationship_type": rel.relationship_type,
            "direction": "outbound" if rel.source_asset_id == asset_id else "inbound",
            "related_asset": {
                "id": str(other.id),
                "name": other.name,
                "asset_type": other.asset_type.value,
            },
        }
        for rel, other in rel_result.all()
    ]

    paths_result = await db.execute(
        select(AttackPathFinding)
        .where(
            and_(
                AttackPathFinding.asset_id == asset_id,
                AttackPathFinding.organization_id == org_id,
            )
        )
        .order_by(AttackPathFinding.risk_score.desc())
    )
    attack_paths = [
        {
            "id": str(f.id),
            "rule_key": f.rule_key,
            "title": f.title,
            "severity": f.severity,
            "status": f.status.value,
            "risk_score": f.risk_score,
            "first_detected": f.first_detected.isoformat(),
        }
        for f in paths_result.scalars().all()
    ]

    return {
        "asset": _asset_response(asset).model_dump(),
        "relationships": relationships,
        "attack_paths": attack_paths,
    }


@router.get("/{asset_id}/findings")
async def get_asset_findings(
    asset_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    include_closed: bool = False,
) -> dict:
    """Every alert linked to this asset, newest first."""
    query = (
        select(NormalizedAlert)
        .join(AssetAlertLink, AssetAlertLink.alert_id == NormalizedAlert.id)
        .where(
            and_(
                AssetAlertLink.asset_id == asset_id,
                NormalizedAlert.organization_id == org_id,
            )
        )
        .order_by(NormalizedAlert.created_at_source.desc())
        .limit(500)
    )
    if not include_closed:
        query = query.where(NormalizedAlert.status.in_(["open", "acknowledged"]))

    result = await db.execute(query)
    alerts = result.scalars().all()
    return {
        "findings": [
            {
                "id": str(a.id),
                "source_type": a.source_type,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "rule_id": a.rule_id,
                "tags": a.tags or [],
                "created_at_source": a.created_at_source.isoformat(),
            }
            for a in alerts
        ]
    }
