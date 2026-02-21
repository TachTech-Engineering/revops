"""
AI Alert Clustering API - Feature 5
Group similar alerts to reduce analyst fatigue.
"""
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, desc, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgUserDep, OrgIdDep, OrgAnalystDep, OrgAdminDep
from app.db import get_db, AlertCluster, AlertClusterMember, AlertClusterStatus, NormalizedAlert
from app.services.llm_service import llm_service
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


class BulkDeleteClustersRequest(BaseModel):
    cluster_ids: list[str]


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
    # 1. Fetch recent alerts from the time window that aren't already clustered
    time_limit = datetime.utcnow() - timedelta(hours=request.time_window_hours)
    
    # Get IDs of alerts that are already in a cluster
    clustered_alerts_query = select(AlertClusterMember.alert_id).where(
        AlertClusterMember.organization_id == org_id
    )
    clustered_ids_result = await db.execute(clustered_alerts_query)
    clustered_ids = set(r[0] for r in clustered_ids_result.all())

    # Fetch alerts
    alerts_query = select(NormalizedAlert).where(
        NormalizedAlert.organization_id == org_id,
        NormalizedAlert.ingested_at >= time_limit
    )
    alerts_result = await db.execute(alerts_query)
    all_alerts = alerts_result.scalars().all()
    
    # Filter out already clustered alerts
    new_alerts = [a for a in all_alerts if str(a.id) not in clustered_ids]

    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Found {len(new_alerts)} new alerts to cluster out of {len(all_alerts)} total recent alerts.")

    if not new_alerts:
        return {
            "status": "success",
            "clusters_created": 0,
            "message": "No new alerts found to cluster in the specified time window."
        }

    # 2. Group alerts (Cross-source logic: by common entities or rule_id)
    import re
    
    groups = {}
    
    # Simple regex for IPs and Emails
    IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    EMAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

    for alert in new_alerts:
        # Collect possible group keys for this alert
        keys = []
        if alert.rule_id:
            keys.append(f"rule:{alert.rule_id}")
        
        # Extract entities from title/description
        text_to_search = f"{alert.title} {alert.description or ''}"
        ips = re.findall(IP_REGEX, text_to_search)
        emails = re.findall(EMAIL_REGEX, text_to_search)
        
        for ip in ips:
            keys.append(f"ip:{ip}")
        for email in emails:
            keys.append(f"email:{email}")
            
        # If no identifiers found, fall back to title
        if not keys:
            keys.append(f"title:{alert.title}")

        # Add alert to all applicable groups (one alert can be in multiple potential clusters)
        for key in keys:
            if key not in groups:
                groups[key] = []
            groups[key].append(alert)

    created_count = 0
    
    # 3. Prepare clustering tasks
    # Track clustered alert IDs to avoid adding the same alert to multiple new clusters in one run
    already_added_in_this_run = set()
    clustering_tasks = []

    # Filter groups that meet the minimum size first
    valid_groups = []
    for key, group_alerts in groups.items():
        available_alerts = [a for a in group_alerts if a.id not in already_added_in_this_run]
        if len(available_alerts) >= request.min_cluster_size:
            valid_groups.append((key, available_alerts))
            # Mark these alerts as "processed" for this run so they don't get put in other clusters
            for a in available_alerts:
                already_added_in_this_run.add(a.id)

    # Define a helper function for the task
    async def create_cluster_with_ai(key, group_alerts):
        first_alert = min(group_alerts, key=lambda a: a.created_at_source)
        
        # Determine severity
        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_severity = max(group_alerts, key=lambda a: severity_rank.get(a.severity.lower(), 0)).severity
        
        # AI Narrative
        alerts_for_llm = [
            {
                "title": a.title,
                "description": a.description,
                "severity": a.severity,
                "source": a.source_type,
            } for a in group_alerts[:15]
        ]
        
        ai_narrative = await llm_service.cluster_alerts(db, org_id, alerts_for_llm)
        
        return {
            "name": ai_narrative["name"],
            "summary": ai_narrative["narrative"],
            "severity": max_severity,
            "primary_rule_id": group_alerts[0].rule_id,
            "cluster_type": "entity_based" if (key.startswith("ip:") or key.startswith("email:")) else "rule_based",
            "alert_count": len(group_alerts),
            "first_alert_at": first_alert.created_at_source,
            "last_alert_at": first_alert.created_at_source,
            "common_entities": {"identifier": key, "sources": list(set(a.source_type for a in group_alerts))},
            "alerts": group_alerts
        }

    # Create tasks for all valid groups
    import asyncio
    tasks = [create_cluster_with_ai(key, group) for key, group in valid_groups]
    
    if tasks:
        # Run all AI narrative generations in parallel
        cluster_results = await asyncio.gather(*tasks)
        
        # 4. Save clusters to database
        for res in cluster_results:
            cluster = AlertCluster(
                organization_id=org_id,
                name=res["name"],
                summary=res["summary"],
                severity=res["severity"],
                status=AlertClusterStatus.OPEN,
                primary_rule_id=res["primary_rule_id"],
                cluster_type=res["cluster_type"],
                alert_count=res["alert_count"],
                first_alert_at=res["first_alert_at"],
                last_alert_at=res["last_alert_at"],
                common_entities=res["common_entities"],
            )
            db.add(cluster)
            await db.flush()

            # Link members
            added_to_this_cluster = set()
            for alert in res["alerts"]:
                if alert.id in added_to_this_cluster:
                    continue
                    
                member = AlertClusterMember(
                    organization_id=org_id,
                    cluster_id=cluster.id,
                    alert_id=str(alert.id),
                    similarity_score=1.0
                )
                db.add(member)
                added_to_this_cluster.add(alert.id)
            
            created_count += 1

    await db.commit()

    await db.commit()

    return {
        "status": "success",
        "clusters_created": created_count,
        "alerts_processed": len(new_alerts),
        "time_window_hours": request.time_window_hours,
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


@router.post("/bulk-delete")
async def bulk_delete_clusters(
    request: BulkDeleteClustersRequest,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Bulk delete alert clusters."""
    if not request.cluster_ids:
        return {"status": "success", "deleted_count": 0}

    # Convert strings to UUIDs
    cluster_uuids = [UUID(cid) for cid in request.cluster_ids]

    # Delete clusters (ensure they belong to the org)
    from sqlalchemy import delete
    
    # Delete members first (if not handled by cascade)
    await db.execute(
        delete(AlertClusterMember).where(
            and_(
                AlertClusterMember.cluster_id.in_(cluster_uuids),
                AlertClusterMember.organization_id == org_id
            )
        )
    )

    # Delete clusters
    result = await db.execute(
        delete(AlertCluster).where(
            and_(
                AlertCluster.id.in_(cluster_uuids),
                AlertCluster.organization_id == org_id
            )
        )
    )
    
    deleted_count = result.rowcount
    await db.commit()

    return {
        "status": "success",
        "deleted_count": deleted_count
    }
