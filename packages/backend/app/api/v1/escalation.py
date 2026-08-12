"""
Escalation Policies API - Feature 7
Time-based escalation chains for unacknowledged alerts.
"""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.deps import OrgAdminDep, OrgAnalystDep, OrgIdDep, OrgUserDep
from app.db import (
    AlertEscalation,
    EscalationNotificationType,
    EscalationPolicy,
    EscalationStatus,
    EscalationStep,
    get_db,
)

router = APIRouter()


# ==================== Response Models ====================


class EscalationStepResponse(BaseModel):
    id: str
    step_order: int
    delay_minutes: int
    notification_type: str
    targets: list
    use_oncall_schedule: bool
    oncall_schedule_id: str | None

    class Config:
        from_attributes = True


class EscalationPolicyResponse(BaseModel):
    id: str
    name: str
    description: str | None
    severity_filter: list
    rule_filter: list
    is_active: bool
    steps: list[EscalationStepResponse]
    call_message_template: str | None
    sms_message_template: str | None
    created_by: str
    created_at: str

    class Config:
        from_attributes = True


class AlertEscalationResponse(BaseModel):
    id: str
    alert_id: str
    policy_id: str
    status: str
    current_step: int
    started_at: str
    next_escalation_at: str | None
    acknowledged_at: str | None
    acknowledged_by: str | None
    notification_history: list

    class Config:
        from_attributes = True


# ==================== Request Models ====================


class EscalationStepCreate(BaseModel):
    step_order: int
    delay_minutes: int
    notification_type: str  # email, slack, pagerduty, teams, webhook
    targets: list[str]
    use_oncall_schedule: bool = False
    oncall_schedule_id: str | None = None


class EscalationPolicyCreate(BaseModel):
    name: str
    description: str | None = None
    severity_filter: list[str] = []
    rule_filter: list[str] = []
    is_active: bool = True
    steps: list[EscalationStepCreate] = []
    # Custom message templates - supports: {title}, {severity}, {id}, {description},
    # {rule}, {time}, {source}
    call_message_template: str | None = (
        "Alert from {source}: {title}. Severity: {severity}. {description}"
    )
    sms_message_template: str | None = "[{source}] {severity} Alert: {title}. ID: {id}"


class EscalationPolicyUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    severity_filter: list[str] | None = None
    rule_filter: list[str] | None = None
    is_active: bool | None = None
    call_message_template: str | None = None
    sms_message_template: str | None = None


def serialize_step(step: EscalationStep) -> EscalationStepResponse:
    return EscalationStepResponse(
        id=str(step.id),
        step_order=step.step_order,
        delay_minutes=step.delay_minutes,
        notification_type=step.notification_type.value,
        targets=step.targets,
        use_oncall_schedule=step.use_oncall_schedule,
        oncall_schedule_id=str(step.oncall_schedule_id) if step.oncall_schedule_id else None,
    )


def serialize_policy(policy: EscalationPolicy) -> EscalationPolicyResponse:
    return EscalationPolicyResponse(
        id=str(policy.id),
        name=policy.name,
        description=policy.description,
        severity_filter=policy.severity_filter,
        rule_filter=policy.rule_filter,
        is_active=policy.is_active,
        steps=[serialize_step(s) for s in sorted(policy.steps, key=lambda x: x.step_order)],
        call_message_template=policy.call_message_template,
        sms_message_template=policy.sms_message_template,
        created_by=policy.created_by,
        created_at=policy.created_at.isoformat(),
    )


# ==================== Escalation Policies ====================


@router.get("", response_model=list[EscalationPolicyResponse])
async def list_escalation_policies(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    is_active: bool | None = Query(None),
):
    """List all escalation policies."""
    query = (
        select(EscalationPolicy)
        .where(EscalationPolicy.organization_id == org_id)
        .options(selectinload(EscalationPolicy.steps))
    )

    if is_active is not None:
        query = query.where(EscalationPolicy.is_active == is_active)

    result = await db.execute(query)
    policies = result.scalars().unique().all()

    return [serialize_policy(p) for p in policies]


# ==================== Active Escalations (must be before /{policy_id}) ====================


@router.get("/active", response_model=list["AlertEscalationResponse"])
async def list_active_escalations(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """List active escalations."""
    result = await db.execute(
        select(AlertEscalation)
        .where(AlertEscalation.organization_id == org_id)
        .where(AlertEscalation.status.in_([EscalationStatus.PENDING, EscalationStatus.ACTIVE]))
        .order_by(AlertEscalation.next_escalation_at.asc())
    )
    escalations = result.scalars().all()

    return [
        AlertEscalationResponse(
            id=str(e.id),
            alert_id=e.alert_id,
            policy_id=str(e.policy_id),
            status=e.status.value,
            current_step=e.current_step,
            started_at=e.started_at.isoformat(),
            next_escalation_at=e.next_escalation_at.isoformat() if e.next_escalation_at else None,
            acknowledged_at=e.acknowledged_at.isoformat() if e.acknowledged_at else None,
            acknowledged_by=e.acknowledged_by,
            notification_history=e.notification_history,
        )
        for e in escalations
    ]


@router.get("/{policy_id}", response_model=EscalationPolicyResponse)
async def get_escalation_policy(
    policy_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific escalation policy."""
    result = await db.execute(
        select(EscalationPolicy)
        .where(EscalationPolicy.id == UUID(policy_id))
        .where(EscalationPolicy.organization_id == org_id)
        .options(selectinload(EscalationPolicy.steps))
    )
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    return serialize_policy(policy)


@router.post("", status_code=201, response_model=EscalationPolicyResponse)
async def create_escalation_policy(
    request: EscalationPolicyCreate,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Create a new escalation policy."""
    policy = EscalationPolicy(
        organization_id=org_id,
        name=request.name,
        description=request.description,
        severity_filter=request.severity_filter,
        rule_filter=request.rule_filter,
        is_active=request.is_active,
        call_message_template=request.call_message_template,
        sms_message_template=request.sms_message_template,
        created_by=user.email,
    )
    db.add(policy)
    await db.flush()

    # Add steps
    for step_data in request.steps:
        step = EscalationStep(
            policy_id=policy.id,
            step_order=step_data.step_order,
            delay_minutes=step_data.delay_minutes,
            notification_type=EscalationNotificationType(step_data.notification_type),
            targets=step_data.targets,
            use_oncall_schedule=step_data.use_oncall_schedule,
            oncall_schedule_id=UUID(step_data.oncall_schedule_id)
            if step_data.oncall_schedule_id
            else None,
        )
        db.add(step)

    await db.commit()

    # Refresh with steps
    result = await db.execute(
        select(EscalationPolicy)
        .where(EscalationPolicy.id == policy.id)
        .options(selectinload(EscalationPolicy.steps))
    )
    policy = result.scalar_one()

    return serialize_policy(policy)


@router.patch("/{policy_id}", response_model=EscalationPolicyResponse)
async def update_escalation_policy(
    policy_id: str,
    request: EscalationPolicyUpdate,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Update an escalation policy."""
    result = await db.execute(
        select(EscalationPolicy)
        .where(EscalationPolicy.id == UUID(policy_id))
        .where(EscalationPolicy.organization_id == org_id)
        .options(selectinload(EscalationPolicy.steps))
    )
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    update_data = request.model_dump(exclude_none=True)
    for key, value in update_data.items():
        setattr(policy, key, value)

    await db.commit()
    await db.refresh(policy)

    return serialize_policy(policy)


@router.delete("/{policy_id}", status_code=204)
async def delete_escalation_policy(
    policy_id: str,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Delete an escalation policy."""
    result = await db.execute(
        select(EscalationPolicy)
        .where(EscalationPolicy.id == UUID(policy_id))
        .where(EscalationPolicy.organization_id == org_id)
    )
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    await db.delete(policy)
    await db.commit()


# ==================== Escalation Steps ====================


@router.post("/{policy_id}/steps", status_code=201, response_model=EscalationStepResponse)
async def add_escalation_step(
    policy_id: str,
    request: EscalationStepCreate,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Add a step to an escalation policy."""
    result = await db.execute(
        select(EscalationPolicy)
        .where(EscalationPolicy.id == UUID(policy_id))
        .where(EscalationPolicy.organization_id == org_id)
    )
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    step = EscalationStep(
        policy_id=policy.id,
        step_order=request.step_order,
        delay_minutes=request.delay_minutes,
        notification_type=EscalationNotificationType(request.notification_type),
        targets=request.targets,
        use_oncall_schedule=request.use_oncall_schedule,
        oncall_schedule_id=UUID(request.oncall_schedule_id) if request.oncall_schedule_id else None,
    )
    db.add(step)
    await db.commit()
    await db.refresh(step)

    return serialize_step(step)


@router.delete("/{policy_id}/steps/{step_id}", status_code=204)
async def remove_escalation_step(
    policy_id: str,
    step_id: str,
    user: OrgAdminDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Remove a step from an escalation policy."""
    result = await db.execute(
        select(EscalationStep)
        .join(EscalationPolicy)
        .where(EscalationStep.id == UUID(step_id))
        .where(EscalationPolicy.organization_id == org_id)
    )
    step = result.scalar_one_or_none()

    if not step:
        raise HTTPException(status_code=404, detail="Step not found")

    await db.delete(step)
    await db.commit()


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert_escalation(
    alert_id: str,
    user: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Acknowledge an alert to stop its escalation."""
    result = await db.execute(
        select(AlertEscalation)
        .where(AlertEscalation.organization_id == org_id)
        .where(AlertEscalation.alert_id == alert_id)
        .where(AlertEscalation.status.in_([EscalationStatus.PENDING, EscalationStatus.ACTIVE]))
    )
    escalation = result.scalar_one_or_none()

    if not escalation:
        raise HTTPException(status_code=404, detail="No active escalation found for this alert")

    escalation.status = EscalationStatus.ACKNOWLEDGED
    escalation.acknowledged_at = datetime.utcnow()
    escalation.acknowledged_by = user.email

    await db.commit()

    return {
        "status": "success",
        "alert_id": alert_id,
        "escalation_stopped": True,
        "acknowledged_by": user.email,
    }


@router.get("/alerts/{alert_id}/escalation", response_model=AlertEscalationResponse | None)
async def get_alert_escalation(
    alert_id: str,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get escalation status for an alert."""
    result = await db.execute(
        select(AlertEscalation)
        .where(AlertEscalation.organization_id == org_id)
        .where(AlertEscalation.alert_id == alert_id)
        .order_by(desc(AlertEscalation.created_at))
        .limit(1)
    )
    escalation = result.scalar_one_or_none()

    if not escalation:
        return None

    return AlertEscalationResponse(
        id=str(escalation.id),
        alert_id=escalation.alert_id,
        policy_id=str(escalation.policy_id),
        status=escalation.status.value,
        current_step=escalation.current_step,
        started_at=escalation.started_at.isoformat(),
        next_escalation_at=escalation.next_escalation_at.isoformat()
        if escalation.next_escalation_at
        else None,
        acknowledged_at=escalation.acknowledged_at.isoformat()
        if escalation.acknowledged_at
        else None,
        acknowledged_by=escalation.acknowledged_by,
        notification_history=escalation.notification_history,
    )


class TriggerEscalationRequest(BaseModel):
    alert_id: str
    alert_title: str
    alert_severity: str = "HIGH"
    alert_description: str | None = ""
    rule_name: str | None = ""


@router.post("/trigger", response_model=AlertEscalationResponse | None)
async def trigger_escalation(
    request: TriggerEscalationRequest,
    user: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Manually trigger an escalation for an alert.

    This will find a matching escalation policy and start the escalation chain.
    """
    from app.services.escalation_service import EscalationService

    service = EscalationService(db)
    escalation = await service.check_and_trigger_escalation(
        organization_id=org_id,
        alert_id=request.alert_id,
        alert_title=request.alert_title,
        alert_severity=request.alert_severity,
        alert_description=request.alert_description or "",
        rule_name=request.rule_name or "",
    )

    if not escalation:
        raise HTTPException(
            status_code=400,
            detail="No matching escalation policy found or alert already has active escalation",
        )

    return AlertEscalationResponse(
        id=str(escalation.id),
        alert_id=escalation.alert_id,
        policy_id=str(escalation.policy_id),
        status=escalation.status.value,
        current_step=escalation.current_step,
        started_at=escalation.started_at.isoformat(),
        next_escalation_at=escalation.next_escalation_at.isoformat()
        if escalation.next_escalation_at
        else None,
        acknowledged_at=escalation.acknowledged_at.isoformat()
        if escalation.acknowledged_at
        else None,
        acknowledged_by=escalation.acknowledged_by,
        notification_history=escalation.notification_history,
    )
