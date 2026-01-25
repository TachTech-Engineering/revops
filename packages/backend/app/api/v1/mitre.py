from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db, MitreMapping, MitreTactic
from app.api.v1.deps import RequireAnalystDep, CurrentUserDep

router = APIRouter()


# MITRE ATT&CK tactics in order
TACTICS_ORDER = [
    MitreTactic.RECONNAISSANCE,
    MitreTactic.RESOURCE_DEVELOPMENT,
    MitreTactic.INITIAL_ACCESS,
    MitreTactic.EXECUTION,
    MitreTactic.PERSISTENCE,
    MitreTactic.PRIVILEGE_ESCALATION,
    MitreTactic.DEFENSE_EVASION,
    MitreTactic.CREDENTIAL_ACCESS,
    MitreTactic.DISCOVERY,
    MitreTactic.LATERAL_MOVEMENT,
    MitreTactic.COLLECTION,
    MitreTactic.COMMAND_AND_CONTROL,
    MitreTactic.EXFILTRATION,
    MitreTactic.IMPACT,
]

TACTIC_LABELS = {
    MitreTactic.RECONNAISSANCE: "Reconnaissance",
    MitreTactic.RESOURCE_DEVELOPMENT: "Resource Development",
    MitreTactic.INITIAL_ACCESS: "Initial Access",
    MitreTactic.EXECUTION: "Execution",
    MitreTactic.PERSISTENCE: "Persistence",
    MitreTactic.PRIVILEGE_ESCALATION: "Privilege Escalation",
    MitreTactic.DEFENSE_EVASION: "Defense Evasion",
    MitreTactic.CREDENTIAL_ACCESS: "Credential Access",
    MitreTactic.DISCOVERY: "Discovery",
    MitreTactic.LATERAL_MOVEMENT: "Lateral Movement",
    MitreTactic.COLLECTION: "Collection",
    MitreTactic.COMMAND_AND_CONTROL: "Command and Control",
    MitreTactic.EXFILTRATION: "Exfiltration",
    MitreTactic.IMPACT: "Impact",
}


class MitreMappingCreate(BaseModel):
    rule_id: str
    rule_name: str
    technique_id: str
    technique_name: str
    subtechnique_id: Optional[str] = None
    subtechnique_name: Optional[str] = None
    tactic: MitreTactic
    notes: Optional[str] = None


class MitreMappingUpdate(BaseModel):
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    subtechnique_id: Optional[str] = None
    subtechnique_name: Optional[str] = None
    tactic: Optional[MitreTactic] = None
    notes: Optional[str] = None


class MitreMappingResponse(BaseModel):
    id: UUID
    rule_id: str
    rule_name: str
    technique_id: str
    technique_name: str
    subtechnique_id: Optional[str]
    subtechnique_name: Optional[str]
    tactic: MitreTactic
    notes: Optional[str]
    created_by: str
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


@router.get("/tactics")
async def get_tactics(user: CurrentUserDep) -> list[dict]:
    """Get all MITRE ATT&CK tactics in order."""
    return [
        {"value": t.value, "label": TACTIC_LABELS[t]}
        for t in TACTICS_ORDER
    ]


@router.get("/mappings")
async def list_mappings(
    user: CurrentUserDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    tactic: Optional[MitreTactic] = None,
    technique_id: Optional[str] = None,
) -> list[MitreMappingResponse]:
    """List all MITRE mappings."""
    query = select(MitreMapping).order_by(MitreMapping.technique_id)

    if tactic:
        query = query.where(MitreMapping.tactic == tactic)
    if technique_id:
        query = query.where(MitreMapping.technique_id == technique_id)

    result = await db.execute(query)
    mappings = result.scalars().all()

    return [
        MitreMappingResponse(
            id=m.id,
            rule_id=m.rule_id,
            rule_name=m.rule_name,
            technique_id=m.technique_id,
            technique_name=m.technique_name,
            subtechnique_id=m.subtechnique_id,
            subtechnique_name=m.subtechnique_name,
            tactic=m.tactic,
            notes=m.notes,
            created_by=m.created_by,
            created_at=m.created_at.isoformat(),
            updated_at=m.updated_at.isoformat(),
        )
        for m in mappings
    ]


@router.get("/coverage")
async def get_coverage(
    user: CurrentUserDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Get MITRE ATT&CK coverage summary."""
    # Get counts by tactic
    result = await db.execute(
        select(MitreMapping.tactic, func.count(func.distinct(MitreMapping.technique_id)))
        .group_by(MitreMapping.tactic)
    )
    tactic_counts = {row[0]: row[1] for row in result.all()}

    # Get unique techniques by tactic
    result = await db.execute(
        select(
            MitreMapping.tactic,
            MitreMapping.technique_id,
            MitreMapping.technique_name,
            func.count(MitreMapping.rule_id).label('rule_count')
        )
        .group_by(MitreMapping.tactic, MitreMapping.technique_id, MitreMapping.technique_name)
    )

    techniques_by_tactic = {}
    for row in result.all():
        tactic = row[0].value
        if tactic not in techniques_by_tactic:
            techniques_by_tactic[tactic] = []
        techniques_by_tactic[tactic].append({
            "technique_id": row[1],
            "technique_name": row[2],
            "rule_count": row[3],
        })

    # Get total unique techniques
    total_result = await db.execute(
        select(func.count(func.distinct(MitreMapping.technique_id)))
    )
    total_techniques = total_result.scalar() or 0

    # Get total rules with mappings
    rules_result = await db.execute(
        select(func.count(func.distinct(MitreMapping.rule_id)))
    )
    total_mapped_rules = rules_result.scalar() or 0

    return {
        "total_techniques": total_techniques,
        "total_mapped_rules": total_mapped_rules,
        "by_tactic": [
            {
                "tactic": t.value,
                "label": TACTIC_LABELS[t],
                "technique_count": tactic_counts.get(t, 0),
                "techniques": techniques_by_tactic.get(t.value, []),
            }
            for t in TACTICS_ORDER
        ],
    }


@router.get("/rules/{rule_id}")
async def get_rule_mappings(
    rule_id: str,
    user: CurrentUserDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[MitreMappingResponse]:
    """Get MITRE mappings for a specific rule."""
    result = await db.execute(
        select(MitreMapping)
        .where(MitreMapping.rule_id == rule_id)
        .order_by(MitreMapping.technique_id)
    )
    mappings = result.scalars().all()

    return [
        MitreMappingResponse(
            id=m.id,
            rule_id=m.rule_id,
            rule_name=m.rule_name,
            technique_id=m.technique_id,
            technique_name=m.technique_name,
            subtechnique_id=m.subtechnique_id,
            subtechnique_name=m.subtechnique_name,
            tactic=m.tactic,
            notes=m.notes,
            created_by=m.created_by,
            created_at=m.created_at.isoformat(),
            updated_at=m.updated_at.isoformat(),
        )
        for m in mappings
    ]


@router.post("/mappings")
async def create_mapping(
    mapping: MitreMappingCreate,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MitreMappingResponse:
    """Create a new MITRE mapping. Requires analyst role."""
    email, _ = analyst

    db_mapping = MitreMapping(
        rule_id=mapping.rule_id,
        rule_name=mapping.rule_name,
        technique_id=mapping.technique_id,
        technique_name=mapping.technique_name,
        subtechnique_id=mapping.subtechnique_id,
        subtechnique_name=mapping.subtechnique_name,
        tactic=mapping.tactic,
        notes=mapping.notes,
        created_by=email,
    )
    db.add(db_mapping)
    await db.flush()
    await db.refresh(db_mapping)

    return MitreMappingResponse(
        id=db_mapping.id,
        rule_id=db_mapping.rule_id,
        rule_name=db_mapping.rule_name,
        technique_id=db_mapping.technique_id,
        technique_name=db_mapping.technique_name,
        subtechnique_id=db_mapping.subtechnique_id,
        subtechnique_name=db_mapping.subtechnique_name,
        tactic=db_mapping.tactic,
        notes=db_mapping.notes,
        created_by=db_mapping.created_by,
        created_at=db_mapping.created_at.isoformat(),
        updated_at=db_mapping.updated_at.isoformat(),
    )


@router.patch("/mappings/{mapping_id}")
async def update_mapping(
    mapping_id: UUID,
    update: MitreMappingUpdate,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MitreMappingResponse:
    """Update a MITRE mapping. Requires analyst role."""
    result = await db.execute(
        select(MitreMapping).where(MitreMapping.id == mapping_id)
    )
    mapping = result.scalar_one_or_none()
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")

    for field, value in update.model_dump(exclude_unset=True).items():
        setattr(mapping, field, value)

    await db.flush()
    await db.refresh(mapping)

    return MitreMappingResponse(
        id=mapping.id,
        rule_id=mapping.rule_id,
        rule_name=mapping.rule_name,
        technique_id=mapping.technique_id,
        technique_name=mapping.technique_name,
        subtechnique_id=mapping.subtechnique_id,
        subtechnique_name=mapping.subtechnique_name,
        tactic=mapping.tactic,
        notes=mapping.notes,
        created_by=mapping.created_by,
        created_at=mapping.created_at.isoformat(),
        updated_at=mapping.updated_at.isoformat(),
    )


@router.delete("/mappings/{mapping_id}")
async def delete_mapping(
    mapping_id: UUID,
    analyst: RequireAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete a MITRE mapping. Requires analyst role."""
    result = await db.execute(
        select(MitreMapping).where(MitreMapping.id == mapping_id)
    )
    mapping = result.scalar_one_or_none()
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")

    await db.delete(mapping)
    return {"status": "deleted"}
