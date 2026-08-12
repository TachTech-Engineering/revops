import logging
import re
from datetime import datetime, timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OptionalPantherServiceDep, OrgAnalystDep, OrgIdDep, OrgUserDep
from app.db import MitreMapping, MitreTactic, NormalizedAlert, get_db

logger = logging.getLogger(__name__)

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

# Map MITRE tactic IDs (TAxxxx) to tactic enum values (use hyphens to match MitreTactic enum)
TACTIC_ID_MAP = {
    "TA0043": "reconnaissance",
    "TA0042": "resource-development",
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0011": "command-and-control",
    "TA0010": "exfiltration",
    "TA0040": "impact",
}


class MitreMappingCreate(BaseModel):
    rule_id: str
    rule_name: str
    technique_id: str
    technique_name: str
    subtechnique_id: str | None = None
    subtechnique_name: str | None = None
    tactic: MitreTactic
    notes: str | None = None


class MitreMappingUpdate(BaseModel):
    technique_id: str | None = None
    technique_name: str | None = None
    subtechnique_id: str | None = None
    subtechnique_name: str | None = None
    tactic: MitreTactic | None = None
    notes: str | None = None


class MitreMappingResponse(BaseModel):
    id: UUID
    rule_id: str
    rule_name: str
    technique_id: str
    technique_name: str
    subtechnique_id: str | None
    subtechnique_name: str | None
    tactic: MitreTactic
    notes: str | None
    created_by: str
    created_at: str
    updated_at: str

    class Config:
        from_attributes = True


@router.get("/tactics")
async def get_tactics(user: OrgUserDep) -> list[dict]:
    """Get all MITRE ATT&CK tactics in order."""
    return [{"value": t.value, "label": TACTIC_LABELS[t]} for t in TACTICS_ORDER]


@router.get("/mappings")
async def list_mappings(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    tactic: MitreTactic | None = None,
    technique_id: str | None = None,
) -> list[MitreMappingResponse]:
    """List all MITRE mappings."""
    query = (
        select(MitreMapping)
        .where(MitreMapping.organization_id == org_id)
        .order_by(MitreMapping.technique_id)
    )

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
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Get MITRE ATT&CK coverage summary."""
    # Get counts by tactic
    result = await db.execute(
        select(MitreMapping.tactic, func.count(func.distinct(MitreMapping.technique_id)))
        .where(MitreMapping.organization_id == org_id)
        .group_by(MitreMapping.tactic)
    )
    tactic_counts = {row[0]: row[1] for row in result.all()}

    # Get unique techniques by tactic
    result = await db.execute(
        select(
            MitreMapping.tactic,
            MitreMapping.technique_id,
            MitreMapping.technique_name,
            func.count(MitreMapping.rule_id).label("rule_count"),
        )
        .where(MitreMapping.organization_id == org_id)
        .group_by(MitreMapping.tactic, MitreMapping.technique_id, MitreMapping.technique_name)
    )

    techniques_by_tactic = {}
    for row in result.all():
        tactic = row[0].value
        if tactic not in techniques_by_tactic:
            techniques_by_tactic[tactic] = []
        techniques_by_tactic[tactic].append(
            {
                "technique_id": row[1],
                "technique_name": row[2],
                "rule_count": row[3],
            }
        )

    # Get total unique techniques
    total_result = await db.execute(
        select(func.count(func.distinct(MitreMapping.technique_id))).where(
            MitreMapping.organization_id == org_id
        )
    )
    total_techniques = total_result.scalar() or 0

    # Get total rules with mappings
    rules_result = await db.execute(
        select(func.count(func.distinct(MitreMapping.rule_id))).where(
            MitreMapping.organization_id == org_id
        )
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


def parse_mitre_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    """
    Parse MITRE ATT&CK tactics and techniques from Panther tags.

    Common formats:
    - attack.t1003, attack.T1003
    - attack.execution, attack.initial_access
    - MITRE:T1003
    - t1003.001 (subtechnique)

    Returns (tactics, techniques)
    """
    tactics = []
    techniques = []

    # Technique pattern: T followed by 4 digits, optionally with .xxx subtechnique
    technique_pattern = re.compile(r"[Tt](\d{4})(?:\.(\d{3}))?")

    # Map common tactic names
    tactic_names = {
        "reconnaissance": "reconnaissance",
        "resource_development": "resource_development",
        "initial_access": "initial_access",
        "execution": "execution",
        "persistence": "persistence",
        "privilege_escalation": "privilege_escalation",
        "defense_evasion": "defense_evasion",
        "credential_access": "credential_access",
        "discovery": "discovery",
        "lateral_movement": "lateral_movement",
        "collection": "collection",
        "command_and_control": "command_and_control",
        "exfiltration": "exfiltration",
        "impact": "impact",
    }

    for tag in tags:
        tag_lower = tag.lower().replace("-", "_").replace(" ", "_")

        # Check for technique ID
        match = technique_pattern.search(tag)
        if match:
            tech_id = f"T{match.group(1)}"
            if match.group(2):
                tech_id += f".{match.group(2)}"
            if tech_id not in techniques:
                techniques.append(tech_id)

        # Check for tactic name (e.g., attack.execution)
        for tactic_key, tactic_value in tactic_names.items():
            if tactic_key in tag_lower:
                if tactic_value not in tactics:
                    tactics.append(tactic_value)
                break

    return tactics, techniques


@router.get("/coverage/alerts")
async def get_alert_coverage(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
    panther: OptionalPantherServiceDep,
    days: int = Query(30, ge=1, le=365, description="Number of days to analyze"),
) -> dict:
    """
    Get MITRE ATT&CK coverage from ingested alerts.

    Aggregates MITRE tactics and techniques from:
    1. Panther alerts (via API)
    2. Normalized alerts from connectors (via database)

    This shows what techniques are being detected in your environment.
    """
    since = datetime.utcnow() - timedelta(days=days)

    # Aggregate by tactic and technique
    tactic_data = {}
    technique_data = {}
    technique_alerts = {}  # technique_id -> list of alert info
    total_alerts_with_mitre = 0

    # 1. Fetch Panther alerts and extract MITRE data from tags
    panther_alerts_processed = 0
    try:
        if panther:
            logger.info(f"Fetching Panther alerts for MITRE coverage (last {days} days)")
            alerts_list, _ = await panther.list_alerts(
                created_after=since,
                page_size=100,
                max_items=500,  # Limit to avoid too many API calls
            )

            for alert in alerts_list:
                tags = alert.get("tags", []) or []
                if not tags:
                    continue

                tactics, techniques = parse_mitre_tags(tags)
                if not tactics and not techniques:
                    continue

                panther_alerts_processed += 1
                total_alerts_with_mitre += 1

                rule_name = alert.get("title") or alert.get("detectionId") or "Unknown"
                severity = str(alert.get("severity", "medium")).lower()

                # Process tactics
                for tactic in tactics:
                    # Normalize tactic: handle both TA IDs (TA0005) and names (defense-evasion)
                    tactic_upper = tactic.upper()
                    if tactic_upper in TACTIC_ID_MAP:
                        tactic_key = TACTIC_ID_MAP[tactic_upper]
                    else:
                        # Keep hyphens, just lowercase and replace spaces
                        tactic_key = tactic.lower().replace(" ", "-").replace("_", "-")

                    if tactic_key not in tactic_data:
                        tactic_data[tactic_key] = {
                            "alert_count": 0,
                            "techniques": set(),
                            "rules": set(),
                        }
                    tactic_data[tactic_key]["alert_count"] += 1
                    tactic_data[tactic_key]["rules"].add(rule_name)
                    for tech in techniques:
                        tactic_data[tactic_key]["techniques"].add(tech)

                # Process techniques
                for technique in techniques:
                    if technique not in technique_data:
                        technique_data[technique] = {
                            "alert_count": 0,
                            "rules": set(),
                            "severities": {},
                        }
                    technique_data[technique]["alert_count"] += 1
                    technique_data[technique]["rules"].add(rule_name)
                    technique_data[technique]["severities"][severity] = (
                        technique_data[technique]["severities"].get(severity, 0) + 1
                    )

                    # Track alerts per technique
                    if technique not in technique_alerts:
                        technique_alerts[technique] = []
                    technique_alerts[technique].append(
                        {
                            "rule_name": rule_name,
                            "alert_count": 1,
                            "severity": severity,
                            "tactics": tactics,
                            "source": "panther",
                        }
                    )

            logger.info(
                f"Processed {panther_alerts_processed} Panther alerts with MITRE tags "
                f"out of {len(alerts_list)} total"
            )
    except Exception as e:
        logger.warning(f"Failed to fetch Panther alerts for MITRE coverage: {e}")

    # 2. Get connector alerts with MITRE data from database
    # Fetch alerts individually (can't GROUP BY JSON columns in PostgreSQL)
    result = await db.execute(
        select(
            NormalizedAlert.mitre_tactics,
            NormalizedAlert.mitre_techniques,
            NormalizedAlert.rule_name,
            NormalizedAlert.severity,
        ).where(
            NormalizedAlert.organization_id == org_id,
            NormalizedAlert.created_at_source >= since,
        )
    )

    for row in result.all():
        tactics = row[0] or []
        techniques = row[1] or []
        rule_name = row[2]
        severity = row[3]
        alert_count = 1  # Each row is one alert

        if not tactics and not techniques:
            continue

        total_alerts_with_mitre += alert_count

        # Process tactics
        for tactic in tactics:
            # Normalize tactic: handle both TA IDs (TA0005) and names (defense_evasion)
            tactic_upper = tactic.upper()
            if tactic_upper in TACTIC_ID_MAP:
                tactic_key = TACTIC_ID_MAP[tactic_upper]
            else:
                tactic_key = tactic.lower().replace(" ", "_").replace("-", "_")

            if tactic_key not in tactic_data:
                tactic_data[tactic_key] = {
                    "alert_count": 0,
                    "techniques": set(),
                    "rules": set(),
                }
            tactic_data[tactic_key]["alert_count"] += alert_count
            tactic_data[tactic_key]["rules"].add(rule_name)
            for tech in techniques:
                tactic_data[tactic_key]["techniques"].add(tech)

        # Process techniques
        for technique in techniques:
            if technique not in technique_data:
                technique_data[technique] = {
                    "alert_count": 0,
                    "rules": set(),
                    "severities": {},
                }
            technique_data[technique]["alert_count"] += alert_count
            technique_data[technique]["rules"].add(rule_name)
            if severity:
                sev = severity.lower()
                technique_data[technique]["severities"][sev] = (
                    technique_data[technique]["severities"].get(sev, 0) + alert_count
                )

            # Track alerts per technique
            if technique not in technique_alerts:
                technique_alerts[technique] = []
            technique_alerts[technique].append(
                {
                    "rule_name": rule_name,
                    "alert_count": alert_count,
                    "severity": severity,
                    "tactics": tactics,
                }
            )

    # Map tactics to standard MITRE names

    # Build response with tactics in order
    by_tactic = []
    for tactic in TACTICS_ORDER:
        tactic_key = tactic.value
        data = tactic_data.get(tactic_key, {"alert_count": 0, "techniques": set(), "rules": set()})

        # Get techniques for this tactic
        techniques_list = []
        for tech_id in data["techniques"]:
            tech_info = technique_data.get(tech_id, {})
            techniques_list.append(
                {
                    "technique_id": tech_id,
                    "technique_name": tech_id,  # Would need MITRE data to get the name
                    "alert_count": tech_info.get("alert_count", 0),
                    "rule_count": len(tech_info.get("rules", set())),
                    "severities": tech_info.get("severities", {}),
                }
            )

        by_tactic.append(
            {
                "tactic": tactic_key,
                "label": TACTIC_LABELS[tactic],
                "alert_count": data["alert_count"],
                "technique_count": len(data["techniques"]),
                "rule_count": len(data["rules"]),
                "techniques": sorted(techniques_list, key=lambda x: x["alert_count"], reverse=True),
            }
        )

    # Top techniques by alert count
    top_techniques = sorted(
        [
            {
                "technique_id": tech_id,
                "alert_count": info["alert_count"],
                "rule_count": len(info["rules"]),
                "rules": list(info["rules"])[:5],  # Top 5 rules
                "severities": info["severities"],
            }
            for tech_id, info in technique_data.items()
        ],
        key=lambda x: x["alert_count"],
        reverse=True,
    )[:20]  # Top 20 techniques

    return {
        "period_days": days,
        "total_alerts_with_mitre": total_alerts_with_mitre,
        "total_techniques_detected": len(technique_data),
        "total_tactics_detected": len([t for t in tactic_data.values() if t["alert_count"] > 0]),
        "by_tactic": by_tactic,
        "top_techniques": top_techniques,
        "sources": {
            "panther_alerts": panther_alerts_processed,
            "connector_alerts": total_alerts_with_mitre - panther_alerts_processed,
        },
    }


@router.get("/rules/{rule_id}")
async def get_rule_mappings(
    rule_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> list[MitreMappingResponse]:
    """Get MITRE mappings for a specific rule."""
    result = await db.execute(
        select(MitreMapping)
        .where(and_(MitreMapping.organization_id == org_id, MitreMapping.rule_id == rule_id))
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
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MitreMappingResponse:
    """Create a new MITRE mapping. Requires analyst role."""
    db_mapping = MitreMapping(
        rule_id=mapping.rule_id,
        rule_name=mapping.rule_name,
        technique_id=mapping.technique_id,
        technique_name=mapping.technique_name,
        subtechnique_id=mapping.subtechnique_id,
        subtechnique_name=mapping.subtechnique_name,
        tactic=mapping.tactic,
        notes=mapping.notes,
        created_by=analyst.email,
        organization_id=analyst.organization_id,
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
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MitreMappingResponse:
    """Update a MITRE mapping. Requires analyst role."""
    result = await db.execute(
        select(MitreMapping).where(
            and_(
                MitreMapping.id == mapping_id,
                MitreMapping.organization_id == analyst.organization_id,
            )
        )
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
    analyst: OrgAnalystDep,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, str]:
    """Delete a MITRE mapping. Requires analyst role."""
    result = await db.execute(
        select(MitreMapping).where(
            and_(
                MitreMapping.id == mapping_id,
                MitreMapping.organization_id == analyst.organization_id,
            )
        )
    )
    mapping = result.scalar_one_or_none()
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")

    await db.delete(mapping)
    return {"status": "deleted"}
