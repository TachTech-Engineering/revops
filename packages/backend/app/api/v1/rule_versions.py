"""
Rule Version History API - Feature 1
Track rule changes with diff and rollback capability.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAnalystDep, OrgIdDep, OrgUserDep
from app.db import RuleChangeType, RuleVersion, get_db

router = APIRouter()


class RuleVersionResponse(BaseModel):
    id: str
    rule_id: str
    version: int
    change_type: str
    rule_snapshot: dict
    changed_fields: list
    change_summary: str | None
    changed_by: str
    created_at: str

    class Config:
        from_attributes = True


class RuleVersionListResponse(BaseModel):
    versions: list[RuleVersionResponse]
    total: int


class DiffResponse(BaseModel):
    rule_id: str
    from_version: int
    to_version: int
    changes: dict
    summary: str | None


class CreateVersionRequest(BaseModel):
    rule_id: str
    change_type: str
    rule_snapshot: dict
    changed_fields: list = []
    change_summary: str | None = None


@router.get("/{rule_id}/versions", response_model=RuleVersionListResponse)
async def list_rule_versions(
    rule_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=100),
):
    """List all versions of a rule."""
    result = await db.execute(
        select(RuleVersion)
        .where(RuleVersion.organization_id == org_id)
        .where(RuleVersion.rule_id == rule_id)
        .order_by(desc(RuleVersion.version))
        .limit(limit)
    )
    versions = result.scalars().all()

    count_result = await db.execute(
        select(func.count(RuleVersion.id))
        .where(RuleVersion.organization_id == org_id)
        .where(RuleVersion.rule_id == rule_id)
    )
    total = count_result.scalar() or 0

    return RuleVersionListResponse(
        versions=[
            RuleVersionResponse(
                id=str(v.id),
                rule_id=v.rule_id,
                version=v.version,
                change_type=v.change_type.value,
                rule_snapshot=v.rule_snapshot,
                changed_fields=v.changed_fields,
                change_summary=v.change_summary,
                changed_by=v.changed_by,
                created_at=v.created_at.isoformat(),
            )
            for v in versions
        ],
        total=total,
    )


@router.get("/{rule_id}/versions/{version}", response_model=RuleVersionResponse)
async def get_rule_version(
    rule_id: str,
    version: int,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific version of a rule."""
    result = await db.execute(
        select(RuleVersion)
        .where(RuleVersion.organization_id == org_id)
        .where(RuleVersion.rule_id == rule_id)
        .where(RuleVersion.version == version)
    )
    rule_version = result.scalar_one_or_none()

    if not rule_version:
        raise HTTPException(status_code=404, detail="Rule version not found")

    return RuleVersionResponse(
        id=str(rule_version.id),
        rule_id=rule_version.rule_id,
        version=rule_version.version,
        change_type=rule_version.change_type.value,
        rule_snapshot=rule_version.rule_snapshot,
        changed_fields=rule_version.changed_fields,
        change_summary=rule_version.change_summary,
        changed_by=rule_version.changed_by,
        created_at=rule_version.created_at.isoformat(),
    )


@router.get("/{rule_id}/diff", response_model=DiffResponse)
async def diff_rule_versions(
    rule_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    from_version: int = Query(..., description="Starting version"),
    to_version: int = Query(..., description="Ending version"),
):
    """Compare two versions of a rule."""
    result = await db.execute(
        select(RuleVersion)
        .where(RuleVersion.organization_id == org_id)
        .where(RuleVersion.rule_id == rule_id)
        .where(RuleVersion.version.in_([from_version, to_version]))
    )
    versions = {v.version: v for v in result.scalars().all()}

    if from_version not in versions or to_version not in versions:
        raise HTTPException(status_code=404, detail="One or both versions not found")

    from_snapshot = versions[from_version].rule_snapshot
    to_snapshot = versions[to_version].rule_snapshot

    # Compute diff
    changes = {}
    all_keys = set(from_snapshot.keys()) | set(to_snapshot.keys())
    for key in all_keys:
        old_val = from_snapshot.get(key)
        new_val = to_snapshot.get(key)
        if old_val != new_val:
            changes[key] = {"old": old_val, "new": new_val}

    return DiffResponse(
        rule_id=rule_id,
        from_version=from_version,
        to_version=to_version,
        changes=changes,
        summary=versions[to_version].change_summary,
    )


@router.post("/{rule_id}/rollback/{version}")
async def rollback_rule(
    rule_id: str,
    version: int,
    user: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Rollback a rule to a specific version."""
    result = await db.execute(
        select(RuleVersion)
        .where(RuleVersion.organization_id == org_id)
        .where(RuleVersion.rule_id == rule_id)
        .where(RuleVersion.version == version)
    )
    target_version = result.scalar_one_or_none()

    if not target_version:
        raise HTTPException(status_code=404, detail="Target version not found")

    # Get latest version number
    latest_result = await db.execute(
        select(func.max(RuleVersion.version))
        .where(RuleVersion.organization_id == org_id)
        .where(RuleVersion.rule_id == rule_id)
    )
    latest_version = latest_result.scalar() or 0

    # Create new version with rollback snapshot
    new_version = RuleVersion(
        organization_id=org_id,
        rule_id=rule_id,
        version=latest_version + 1,
        change_type=RuleChangeType.UPDATED,
        rule_snapshot=target_version.rule_snapshot,
        changed_fields=list(target_version.rule_snapshot.keys()),
        change_summary=f"Rolled back to version {version}",
        changed_by=user.email,
    )
    db.add(new_version)
    await db.commit()
    await db.refresh(new_version)

    return {
        "status": "success",
        "message": f"Rule rolled back to version {version}",
        "new_version": latest_version + 1,
        "rule_snapshot": target_version.rule_snapshot,
    }


@router.post("", status_code=201)
async def create_rule_version(
    request: CreateVersionRequest,
    user: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Create a new version entry for a rule (called when rule is updated)."""
    # Get latest version number
    latest_result = await db.execute(
        select(func.max(RuleVersion.version))
        .where(RuleVersion.organization_id == org_id)
        .where(RuleVersion.rule_id == request.rule_id)
    )
    latest_version = latest_result.scalar() or 0

    new_version = RuleVersion(
        organization_id=org_id,
        rule_id=request.rule_id,
        version=latest_version + 1,
        change_type=RuleChangeType(request.change_type),
        rule_snapshot=request.rule_snapshot,
        changed_fields=request.changed_fields,
        change_summary=request.change_summary,
        changed_by=user.email,
    )
    db.add(new_version)
    await db.commit()
    await db.refresh(new_version)

    return {
        "id": str(new_version.id),
        "rule_id": new_version.rule_id,
        "version": new_version.version,
        "change_type": new_version.change_type.value,
    }
