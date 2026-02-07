"""
AI Alert Clustering API - Feature 5
Group similar alerts to reduce analyst fatigue.
"""
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, desc, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgUserDep, OrgIdDep, OrgAnalystDep
from app.db import get_db, AlertCluster, AlertClusterMember, AlertClusterStatus
from fastapi import Depends

router = APIRouter()


class AlertClusterResponse(BaseModel):
    id: str
    name: str
    summary: str
    severity: str
    status: str
    primary_rule_id: Optional[str]
    cluster_type: str
    alert_count: int
    first_alert_at: str
    last_alert_at: str
    common_entities: dict
    assignee: Optional[str]
    created_at: str

    class Config:
        from_attributes = True


class ClusterListResponse(BaseModel):
    clusters: list[AlertClusterResponse]
    total: int


class ClusterMemberResponse(BaseModel):
    id: str
    cluster_id: str
    alert_id: str
    similarity_score: float
    added_at: str


class GenerateClusterRequest(BaseModel):
    time_window_hours: int = 24
    min_cluster_size: int = 3
    cluster_by: list[str] = ["rule_id", "entity"]  # rule_id, entity, time


class UpdateClusterRequest(BaseModel):
    status: Optional[str] = None
    assignee: Optional[str] = None


class MergeClustersRequest(BaseModel):
    source_cluster_ids: list[str]


def serialize_cluster(cluster: AlertCluster) -> AlertClusterResponse:
    return AlertClusterResponse(
        id=str(cluster.id),
        name=cluster.name,
        summary=cluster.summary,
        severity=cluster.severity,
        status=cluster.status.value,
        primary_rule_id=cluster.primary_rule_id,
        cluster_type=cluster.cluster_type,
        alert_count=cluster.alert_count,
        first_alert_at=cluster.first_alert_at.isoformat(),
        last_alert_at=cluster.last_alert_at.isoformat(),
        common_entities=cluster.common_entities,
        assignee=cluster.assignee,
        created_at=cluster.created_at.isoformat(),
    )


@router.get("", response_model=ClusterListResponse)
async def list_clusters(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    """List alert clusters."""
    query = select(AlertCluster).where(AlertCluster.organization_id == org_id)

    if status:
        query = query.where(AlertCluster.status == AlertClusterStatus(status))
    if severity:
        query = query.where(AlertCluster.severity == severity)

    # Count total
    count_result = await db.execute(
        select(func.count(AlertCluster.id)).where(AlertCluster.organization_id == org_id)
    )
    total = count_result.scalar() or 0

    # Paginate
    offset = (page - 1) * page_size
    query = query.order_by(desc(AlertCluster.last_alert_at)).offset(offset).limit(page_size)

    result = await db.execute(query)
    clusters = result.scalars().all()

    return ClusterListResponse(
        clusters=[serialize_cluster(c) for c in clusters],
        total=total,
    )


@router.get("/{cluster_id}", response_model=AlertClusterResponse)
async def get_cluster(
    cluster_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific cluster."""
    result = await db.execute(
        select(AlertCluster)
        .where(AlertCluster.id == UUID(cluster_id))
        .where(AlertCluster.organization_id == org_id)
    )
    cluster = result.scalar_one_or_none()

    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    return serialize_cluster(cluster)


@router.get("/{cluster_id}/alerts", response_model=list[ClusterMemberResponse])
async def get_cluster_alerts(
    cluster_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get alerts in a cluster."""
    result = await db.execute(
        select(AlertClusterMember)
        .where(AlertClusterMember.cluster_id == UUID(cluster_id))
        .where(AlertClusterMember.organization_id == org_id)
        .order_by(desc(AlertClusterMember.similarity_score))
    )
    members = result.scalars().all()

    return [
        ClusterMemberResponse(
            id=str(m.id),
            cluster_id=str(m.cluster_id),
            alert_id=m.alert_id,
            similarity_score=m.similarity_score,
            added_at=m.added_at.isoformat(),
        )
        for m in members
    ]


@router.patch("/{cluster_id}", response_model=AlertClusterResponse)
async def update_cluster(
    cluster_id: str,
    request: UpdateClusterRequest,
    user: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Update cluster status or assignee."""
    result = await db.execute(
        select(AlertCluster)
        .where(AlertCluster.id == UUID(cluster_id))
        .where(AlertCluster.organization_id == org_id)
    )
    cluster = result.scalar_one_or_none()

    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    if request.status:
        cluster.status = AlertClusterStatus(request.status)
    if request.assignee is not None:
        cluster.assignee = request.assignee

    await db.commit()
    await db.refresh(cluster)

    return serialize_cluster(cluster)


@router.post("/generate")
async def generate_clusters(
    request: GenerateClusterRequest,
    user: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Trigger AI clustering of alerts."""
    # In production, this would:
    # 1. Fetch recent alerts from the time window
    # 2. Compute similarity based on rule_id, entities, time proximity
    # 3. Use clustering algorithm (e.g., DBSCAN)
    # 4. Call LLM to generate cluster names and summaries
    # 5. Create cluster records

    # Demo: create sample clusters
    now = datetime.utcnow()

    demo_clusters = [
        AlertCluster(
            organization_id=org_id,
            name="Brute Force Login Attempts - DC01",
            summary="Multiple failed login attempts detected from external IP addresses targeting domain controller DC01. Pattern suggests automated credential stuffing attack.",
            severity="high",
            status=AlertClusterStatus.OPEN,
            primary_rule_id="rule-failed-login-001",
            cluster_type="rule_based",
            alert_count=47,
            first_alert_at=now - timedelta(hours=6),
            last_alert_at=now - timedelta(minutes=15),
            common_entities={"target_host": "DC01", "attack_type": "credential_stuffing"},
        ),
        AlertCluster(
            organization_id=org_id,
            name="Suspicious PowerShell Activity - Engineering Workstations",
            summary="Encoded PowerShell commands executed across multiple engineering workstations. Commands appear to be reconnaissance scripts.",
            severity="medium",
            status=AlertClusterStatus.OPEN,
            primary_rule_id="rule-powershell-suspicious-001",
            cluster_type="entity_based",
            alert_count=12,
            first_alert_at=now - timedelta(hours=2),
            last_alert_at=now - timedelta(minutes=30),
            common_entities={"department": "engineering", "technique": "T1059.001"},
        ),
    ]

    for cluster in demo_clusters:
        db.add(cluster)

    await db.commit()

    return {
        "status": "success",
        "clusters_created": len(demo_clusters),
        "time_window_hours": request.time_window_hours,
        "cluster_criteria": request.cluster_by,
    }


@router.post("/{cluster_id}/merge")
async def merge_clusters(
    cluster_id: str,
    request: MergeClustersRequest,
    user: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Merge multiple clusters into one."""
    # Get target cluster
    result = await db.execute(
        select(AlertCluster)
        .where(AlertCluster.id == UUID(cluster_id))
        .where(AlertCluster.organization_id == org_id)
    )
    target_cluster = result.scalar_one_or_none()

    if not target_cluster:
        raise HTTPException(status_code=404, detail="Target cluster not found")

    # Move members from source clusters
    total_moved = 0
    for source_id in request.source_cluster_ids:
        if source_id == cluster_id:
            continue

        # Update members to point to target cluster
        member_result = await db.execute(
            update(AlertClusterMember)
            .where(AlertClusterMember.cluster_id == UUID(source_id))
            .values(cluster_id=UUID(cluster_id))
            .returning(AlertClusterMember.id)
        )
        moved = len(member_result.all())
        total_moved += moved

        # Delete source cluster
        source_result = await db.execute(
            select(AlertCluster).where(AlertCluster.id == UUID(source_id))
        )
        source = source_result.scalar_one_or_none()
        if source:
            target_cluster.alert_count += source.alert_count
            if source.first_alert_at < target_cluster.first_alert_at:
                target_cluster.first_alert_at = source.first_alert_at
            if source.last_alert_at > target_cluster.last_alert_at:
                target_cluster.last_alert_at = source.last_alert_at
            await db.delete(source)

    await db.commit()
    await db.refresh(target_cluster)

    return {
        "status": "success",
        "target_cluster_id": cluster_id,
        "clusters_merged": len(request.source_cluster_ids),
        "alerts_moved": total_moved,
        "new_alert_count": target_cluster.alert_count,
    }


@router.delete("/{cluster_id}", status_code=204)
async def delete_cluster(
    cluster_id: str,
    user: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Delete a cluster (members are preserved, just unlinked)."""
    result = await db.execute(
        select(AlertCluster)
        .where(AlertCluster.id == UUID(cluster_id))
        .where(AlertCluster.organization_id == org_id)
    )
    cluster = result.scalar_one_or_none()

    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    # Delete members first (cascade should handle this, but being explicit)
    await db.execute(
        select(AlertClusterMember).where(AlertClusterMember.cluster_id == UUID(cluster_id))
    )

    await db.delete(cluster)
    await db.commit()
