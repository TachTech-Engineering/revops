"""
Attack Path Findings API

Read/triage surface for toxic-combination findings produced by the attack
path engine (app/services/attack_path_service.py).
"""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAnalystDep, OrgIdDep, OrgUserDep
from app.core.time_utils import utcnow
from app.db import get_db
from app.db.models import (
    AttackPathFinding,
    AttackPathStatus,
    CloudAsset,
    NormalizedAlert,
)

router = APIRouter()


def _finding_summary(finding: AttackPathFinding, asset: CloudAsset) -> dict:
    return {
        "id": str(finding.id),
        "rule_key": finding.rule_key,
        "title": finding.title,
        "severity": finding.severity,
        "status": finding.status.value,
        "risk_score": finding.risk_score,
        "asset": {
            "id": str(asset.id),
            "name": asset.name,
            "asset_type": asset.asset_type.value,
            "provider": asset.provider,
            "internet_exposed": asset.internet_exposed,
        },
        "incident_id": str(finding.incident_id) if finding.incident_id else None,
        "evidence_count": len(finding.alert_ids or []),
        "first_detected": finding.first_detected.isoformat(),
        "last_evaluated": finding.last_evaluated.isoformat(),
    }


@router.get("")
async def list_attack_paths(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    status: str | None = "open",
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List attack path findings, riskiest first."""
    query = (
        select(AttackPathFinding, CloudAsset)
        .join(CloudAsset, CloudAsset.id == AttackPathFinding.asset_id)
        .where(AttackPathFinding.organization_id == org_id)
    )
    if status and status != "all":
        try:
            query = query.where(AttackPathFinding.status == AttackPathStatus(status))
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unknown status: {status}")
    if severity:
        query = query.where(AttackPathFinding.severity == severity)

    count_result = await db.execute(
        select(func.count()).select_from(query.order_by(None).subquery())
    )
    total = count_result.scalar() or 0

    result = await db.execute(
        query.order_by(AttackPathFinding.risk_score.desc())
        .limit(min(limit, 200))
        .offset(offset)
    )

    return {
        "total": total,
        "findings": [_finding_summary(f, a) for f, a in result.all()],
    }


@router.get("/summary")
async def attack_path_summary(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Counts by status/severity/rule for the dashboard."""
    by_severity_result = await db.execute(
        select(AttackPathFinding.severity, func.count())
        .where(
            and_(
                AttackPathFinding.organization_id == org_id,
                AttackPathFinding.status == AttackPathStatus.OPEN,
            )
        )
        .group_by(AttackPathFinding.severity)
    )
    by_rule_result = await db.execute(
        select(AttackPathFinding.rule_key, func.count())
        .where(
            and_(
                AttackPathFinding.organization_id == org_id,
                AttackPathFinding.status == AttackPathStatus.OPEN,
            )
        )
        .group_by(AttackPathFinding.rule_key)
    )
    by_status_result = await db.execute(
        select(AttackPathFinding.status, func.count())
        .where(AttackPathFinding.organization_id == org_id)
        .group_by(AttackPathFinding.status)
    )
    return {
        "open_by_severity": dict(by_severity_result.all()),
        "open_by_rule": dict(by_rule_result.all()),
        "by_status": {row[0].value: row[1] for row in by_status_result.all()},
    }


@router.get("/{finding_id}")
async def get_attack_path(
    finding_id: UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Full finding: description, path graph payload, and evidence alerts."""
    result = await db.execute(
        select(AttackPathFinding, CloudAsset)
        .join(CloudAsset, CloudAsset.id == AttackPathFinding.asset_id)
        .where(
            and_(
                AttackPathFinding.id == finding_id,
                AttackPathFinding.organization_id == org_id,
            )
        )
    )
    row = result.one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Attack path finding not found")
    finding, asset = row

    evidence: list[dict] = []
    alert_ids = [UUID(a) for a in (finding.alert_ids or []) if a]
    if alert_ids:
        alerts_result = await db.execute(
            select(NormalizedAlert).where(
                and_(
                    NormalizedAlert.id.in_(alert_ids),
                    NormalizedAlert.organization_id == org_id,
                )
            )
        )
        evidence = [
            {
                "id": str(a.id),
                "source_type": a.source_type,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "rule_id": a.rule_id,
                "tags": a.tags or [],
            }
            for a in alerts_result.scalars().all()
        ]

    summary = _finding_summary(finding, asset)
    summary["description"] = finding.description
    summary["path"] = finding.path or {}
    summary["evidence"] = evidence
    summary["resolved_at"] = finding.resolved_at.isoformat() if finding.resolved_at else None
    return summary


@router.post("/{finding_id}/dismiss")
async def dismiss_attack_path(
    finding_id: UUID,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Dismiss a finding (accepted risk). Stays dismissed across re-evaluation."""
    finding = await _get_finding(db, finding_id, org_id)
    finding.status = AttackPathStatus.DISMISSED
    finding.resolved_at = utcnow()
    return {"status": "dismissed"}


@router.post("/{finding_id}/reopen")
async def reopen_attack_path(
    finding_id: UUID,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Reopen a dismissed/resolved finding for triage."""
    finding = await _get_finding(db, finding_id, org_id)
    finding.status = AttackPathStatus.OPEN
    finding.resolved_at = None
    return {"status": "open"}


async def _get_finding(
    db: AsyncSession, finding_id: UUID, org_id: UUID
) -> AttackPathFinding:
    result = await db.execute(
        select(AttackPathFinding).where(
            and_(
                AttackPathFinding.id == finding_id,
                AttackPathFinding.organization_id == org_id,
            )
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Attack path finding not found")
    return finding
