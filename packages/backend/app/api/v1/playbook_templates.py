"""
AI Playbook Generation API - Feature 6
Generate playbooks from incident resolution patterns.
"""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAdminDep, OrgAnalystDep, OrgIdDep, OrgUserDep
from app.db import Playbook, PlaybookStatus, PlaybookTemplate, get_db

router = APIRouter()


class PlaybookTemplateResponse(BaseModel):
    id: str
    name: str
    description: str | None
    trigger_conditions: dict
    actions: list
    confidence_score: float
    source_incident_count: int
    is_approved: bool
    approved_by: str | None
    approved_at: str | None
    converted_playbook_id: str | None
    created_at: str

    class Config:
        from_attributes = True


class TemplateListResponse(BaseModel):
    templates: list[PlaybookTemplateResponse]
    total: int


class GeneratePlaybooksRequest(BaseModel):
    min_incidents: int = 5  # Minimum incidents to identify a pattern
    severity_filter: list[str] | None = None
    time_range_days: int = 90


class ApproveTemplateRequest(BaseModel):
    convert_to_playbook: bool = False


class SuggestedPlaybookResponse(BaseModel):
    template_id: str
    name: str
    description: str | None
    match_score: float
    trigger_conditions: dict
    suggested_actions: list


def serialize_template(template: PlaybookTemplate) -> PlaybookTemplateResponse:
    return PlaybookTemplateResponse(
        id=str(template.id),
        name=template.name,
        description=template.description,
        trigger_conditions=template.trigger_conditions,
        actions=template.actions,
        confidence_score=template.confidence_score,
        source_incident_count=template.source_incident_count,
        is_approved=template.is_approved,
        approved_by=template.approved_by,
        approved_at=template.approved_at.isoformat() if template.approved_at else None,
        converted_playbook_id=str(template.converted_playbook_id)
        if template.converted_playbook_id
        else None,
        created_at=template.created_at.isoformat(),
    )


@router.get("/templates", response_model=TemplateListResponse)
async def list_playbook_templates(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    is_approved: bool | None = Query(None),
    min_confidence: float | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
):
    """List AI-generated playbook templates."""
    query = select(PlaybookTemplate).where(PlaybookTemplate.organization_id == org_id)

    if is_approved is not None:
        query = query.where(PlaybookTemplate.is_approved == is_approved)
    if min_confidence is not None:
        query = query.where(PlaybookTemplate.confidence_score >= min_confidence)

    # Count
    count_result = await db.execute(
        select(func.count(PlaybookTemplate.id)).where(PlaybookTemplate.organization_id == org_id)
    )
    total = count_result.scalar() or 0

    # Paginate
    offset = (page - 1) * page_size
    query = query.order_by(desc(PlaybookTemplate.confidence_score)).offset(offset).limit(page_size)

    result = await db.execute(query)
    templates = result.scalars().all()

    return TemplateListResponse(
        templates=[serialize_template(t) for t in templates],
        total=total,
    )


@router.get("/templates/{template_id}", response_model=PlaybookTemplateResponse)
async def get_playbook_template(
    template_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific playbook template."""
    result = await db.execute(
        select(PlaybookTemplate)
        .where(PlaybookTemplate.id == UUID(template_id))
        .where(PlaybookTemplate.organization_id == org_id)
    )
    template = result.scalar_one_or_none()

    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    return serialize_template(template)


@router.post("/generate")
async def generate_playbooks(
    request: GeneratePlaybooksRequest,
    user: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Analyze closed incidents and generate playbook templates."""
    # In production, this would:
    # 1. Query closed incidents from the time range
    # 2. Extract resolution patterns (actions taken, timing, etc.)
    # 3. Cluster similar patterns
    # 4. Use LLM to synthesize into playbook templates
    # 5. Map to existing action types

    # Demo: create sample templates based on common patterns
    demo_templates = [
        PlaybookTemplate(
            organization_id=org_id,
            name="Automated Phishing Response",
            description=(
                "Auto-generated playbook for responding to phishing alerts. "
                "Based on 23 successfully resolved phishing incidents."
            ),
            trigger_conditions={
                "severity": ["high", "critical"],
                "title_pattern": ".*phishing.*|.*suspicious email.*",
                "rule_ids": ["rule-phishing-001", "rule-phishing-002"],
            },
            actions=[
                {
                    "order": 1,
                    "type": "webhook",
                    "name": "Block sender in email gateway",
                    "config": {"url": "{{EMAIL_GATEWAY_API}}/block", "method": "POST"},
                },
                {
                    "order": 2,
                    "type": "jira_ticket",
                    "name": "Create security incident ticket",
                    "config": {"project": "SEC", "issue_type": "Incident"},
                },
                {
                    "order": 3,
                    "type": "slack",
                    "name": "Notify security team",
                    "config": {"channel": "#security-alerts"},
                },
            ],
            confidence_score=0.87,
            source_incident_count=23,
            generated_from_patterns=["phishing-response-pattern-1", "phishing-response-pattern-2"],
        ),
        PlaybookTemplate(
            organization_id=org_id,
            name="Malware Containment Workflow",
            description=(
                "Auto-generated playbook for malware detection response. "
                "Based on 15 contained malware incidents."
            ),
            trigger_conditions={
                "severity": ["critical"],
                "title_pattern": ".*malware.*|.*ransomware.*",
            },
            actions=[
                {
                    "order": 1,
                    "type": "crowdstrike_isolate",
                    "name": "Isolate affected host",
                    "config": {"isolation_type": "network"},
                },
                {
                    "order": 2,
                    "type": "pagerduty",
                    "name": "Page incident response team",
                    "config": {"urgency": "high"},
                },
                {
                    "order": 3,
                    "type": "jira_ticket",
                    "name": "Create P1 incident",
                    "config": {"project": "SEC", "priority": "P1"},
                },
            ],
            confidence_score=0.92,
            source_incident_count=15,
            generated_from_patterns=["malware-containment-pattern-1"],
        ),
    ]

    for template in demo_templates:
        db.add(template)

    await db.commit()

    return {
        "status": "success",
        "templates_generated": len(demo_templates),
        "analysis_period_days": request.time_range_days,
        "min_incidents_threshold": request.min_incidents,
    }


@router.post("/templates/{template_id}/approve")
async def approve_template(
    template_id: str,
    request: ApproveTemplateRequest,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Approve a playbook template and optionally convert to active playbook."""
    result = await db.execute(
        select(PlaybookTemplate)
        .where(PlaybookTemplate.id == UUID(template_id))
        .where(PlaybookTemplate.organization_id == org_id)
    )
    template = result.scalar_one_or_none()

    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    template.is_approved = True
    template.approved_by = user.email
    template.approved_at = datetime.utcnow()

    playbook_id = None
    if request.convert_to_playbook:
        # Create actual playbook from template
        playbook = Playbook(
            organization_id=org_id,
            name=template.name,
            description=template.description,
            trigger_conditions=template.trigger_conditions,
            actions=template.actions,
            status=PlaybookStatus.ACTIVE,
            auto_execute=False,  # Start with manual execution
            created_by=user.email,
        )
        db.add(playbook)
        await db.flush()
        template.converted_playbook_id = playbook.id
        playbook_id = str(playbook.id)

    await db.commit()

    return {
        "status": "success",
        "template_id": template_id,
        "approved": True,
        "converted_to_playbook": request.convert_to_playbook,
        "playbook_id": playbook_id,
    }


@router.get("/suggestions", response_model=list[SuggestedPlaybookResponse])
async def get_playbook_suggestions(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    alert_id: str | None = Query(None, description="Alert ID to get suggestions for"),
    rule_id: str | None = Query(None, description="Rule ID to get suggestions for"),
    severity: str | None = Query(None, description="Alert severity"),
):
    """Get suggested playbooks for a given alert or context."""
    query = (
        select(PlaybookTemplate)
        .where(PlaybookTemplate.organization_id == org_id)
        .where(PlaybookTemplate.is_approved.is_(True))
        .order_by(desc(PlaybookTemplate.confidence_score))
        .limit(5)
    )

    result = await db.execute(query)
    templates = result.scalars().all()

    # In production, this would score templates based on:
    # 1. Rule ID match in trigger conditions
    # 2. Severity match
    # 3. Title pattern match
    # 4. Historical success rate for similar alerts

    suggestions = []
    for template in templates:
        match_score = 0.5  # Base score

        # Boost score for matching criteria
        conditions = template.trigger_conditions
        if rule_id and rule_id in conditions.get("rule_ids", []):
            match_score += 0.3
        if severity and severity in conditions.get("severity", []):
            match_score += 0.2

        suggestions.append(
            SuggestedPlaybookResponse(
                template_id=str(template.id),
                name=template.name,
                description=template.description,
                match_score=min(match_score, 1.0),
                trigger_conditions=template.trigger_conditions,
                suggested_actions=template.actions,
            )
        )

    # Sort by match score
    suggestions.sort(key=lambda x: x.match_score, reverse=True)

    return suggestions


@router.delete("/templates/{template_id}", status_code=204)
async def delete_template(
    template_id: str,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Delete a playbook template."""
    result = await db.execute(
        select(PlaybookTemplate)
        .where(PlaybookTemplate.id == UUID(template_id))
        .where(PlaybookTemplate.organization_id == org_id)
    )
    template = result.scalar_one_or_none()

    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    await db.delete(template)
    await db.commit()
