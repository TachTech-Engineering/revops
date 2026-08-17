"""
Attack Simulation API endpoints.
"""

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import OrgAdminDep, OrgAnalystDep, OrgIdDep, OrgUserDep, get_panther_service
from app.db.models import SimulationFramework, SimulationStatus
from app.db.session import get_db
from app.services.attack_simulation_service import ExecutionMode, attack_simulation_service
from app.services.panther_service import PantherService
from app.services.technique_sync_service import technique_sync_service

router = APIRouter()


# Request/Response models
class RunSimulationRequest(BaseModel):
    template_id: str
    targets: list[str]
    parameters: dict | None = None
    mode: Literal["manual", "automated"] = "manual"


class GetCommandsRequest(BaseModel):
    template_id: str
    parameters: dict | None = None


class SimulationTemplateResponse(BaseModel):
    id: str
    framework: str
    technique_id: str
    mitre_technique_id: str | None = None
    name: str
    description: str | None = None
    mitre_tactic: str
    mitre_technique: str | None = None
    platforms: list[str]
    cloud_provider: str | None = None
    is_enabled: bool
    executor_type: str | None = None
    executor_command: str | None = None
    executor_cleanup: str | None = None
    input_arguments: dict | None = None
    dependencies: list | None = None
    cloud_permissions: list | None = None
    detonation_command: str | None = None
    cleanup_command: str | None = None


class TemplateListResponse(BaseModel):
    items: list[SimulationTemplateResponse]
    total: int
    page: int
    page_size: int


class ManualCommandsResponse(BaseModel):
    template_id: str
    name: str
    framework: str
    executor_type: str | None = None
    platform: str | None = None
    cloud_provider: str | None = None
    execution_command: str
    cleanup_command: str
    input_arguments: dict
    applied_parameters: dict
    dependencies: list
    cloud_permissions: list
    instructions: list[str]


class SimulationRunResponse(BaseModel):
    id: str
    template_id: str
    status: str
    targets: list[str]
    started_at: datetime | None = None
    completed_at: datetime | None = None
    detection_expected: bool
    detection_found: bool
    detection_rule_id: str | None = None
    triggered_by: str
    error_message: str | None = None
    created_at: datetime


class RunListResponse(BaseModel):
    items: list[SimulationRunResponse]
    total: int
    page: int
    page_size: int


class SimulationResultResponse(BaseModel):
    id: str
    run_id: str
    target: str
    success: bool
    output: str | None = None
    detected_at: datetime | None = None
    detection_details: dict
    created_at: datetime


class VerifyDetectionResponse(BaseModel):
    run_id: str
    technique_id: str
    technique_name: str
    mitre_technique_id: str | None = None
    status: str
    detection_found: bool
    detection_count: int
    detections: list[dict]
    time_to_detect: float | None = None


class SyncStatusResponse(BaseModel):
    last_sync: str | None = None
    atomic_red_team_count: int
    stratus_red_team_count: int
    next_sync: str


class SyncResultResponse(BaseModel):
    atomic_red_team: dict
    stratus_red_team: dict
    synced_at: str


class StatsResponse(BaseModel):
    total_runs: int
    by_status: dict[str, int]
    detections: dict
    templates: dict


def run_to_response(run) -> SimulationRunResponse:
    """Convert SimulationRun to response."""
    return SimulationRunResponse(
        id=str(run.id),
        template_id=str(run.template_id),
        status=run.status.value,
        targets=run.targets or [],
        started_at=run.started_at,
        completed_at=run.completed_at,
        detection_expected=run.detection_expected,
        detection_found=run.detection_found,
        detection_rule_id=run.detection_rule_id,
        triggered_by=run.triggered_by,
        error_message=run.error_message,
        created_at=run.created_at,
    )


def result_to_response(result) -> SimulationResultResponse:
    """Convert SimulationResult to response."""
    return SimulationResultResponse(
        id=str(result.id),
        run_id=str(result.run_id),
        target=result.target,
        success=result.success,
        output=result.output,
        detected_at=result.detected_at,
        detection_details=result.detection_details or {},
        created_at=result.created_at,
    )


# Sync endpoints
@router.get("/sync/status", response_model=SyncStatusResponse)
async def get_sync_status(
    user: OrgUserDep,
    db: AsyncSession = Depends(get_db),
):
    """Get the current sync status for attack techniques."""
    status = await technique_sync_service.get_sync_status(db)
    return SyncStatusResponse(**status)


@router.post("/sync", response_model=SyncResultResponse)
async def sync_techniques(
    admin: OrgAdminDep,
    force: bool = Query(False, description="Force sync even if recently synced"),
    db: AsyncSession = Depends(get_db),
):
    """
    Sync attack techniques from Atomic Red Team and Stratus Red Team repositories.

    Fetches technique definitions from GitHub and stores them in the database.
    """
    result = await technique_sync_service.sync_all(db, force=force)

    if result.get("skipped"):
        raise HTTPException(status_code=304, detail=result.get("reason", "Recently synced"))

    return SyncResultResponse(**result)


# Template endpoints
@router.get("/templates", response_model=TemplateListResponse)
async def list_templates(
    user: OrgUserDep,
    framework: str | None = Query(None, description="Filter by framework: atomic, stratus"),
    platform: str | None = Query(
        None, description="Filter by platform: windows, linux, macos, aws, azure, gcp"
    ),
    tactic: str | None = Query(None, description="Filter by MITRE tactic"),
    search: str | None = Query(None, description="Search by name, description, or technique ID"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List available attack simulation templates."""
    sim_framework = None
    if framework:
        if framework.lower() == "atomic":
            sim_framework = SimulationFramework.ATOMIC_RED_TEAM
        elif framework.lower() == "stratus":
            sim_framework = SimulationFramework.STRATUS_RED_TEAM
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid framework: {framework}. Use 'atomic' or 'stratus'.",
            )

    templates, total = await attack_simulation_service.list_templates(
        db,
        framework=sim_framework,
        platform=platform,
        tactic=tactic,
        search=search,
        page=page,
        page_size=page_size,
    )

    return TemplateListResponse(
        items=[SimulationTemplateResponse(**t) for t in templates],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/templates/{template_id}", response_model=SimulationTemplateResponse)
async def get_template(
    template_id: str,
    user: OrgUserDep,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific simulation template."""
    template = await attack_simulation_service.get_template(db, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")

    return SimulationTemplateResponse(**template)


@router.post("/templates/{template_id}/commands", response_model=ManualCommandsResponse)
async def get_manual_commands(
    template_id: str,
    user: OrgUserDep,
    parameters: dict | None = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Get the manual execution commands for a template.

    Returns the commands to run on your target system, with parameters substituted.
    """
    try:
        commands = await attack_simulation_service.get_manual_commands(db, template_id, parameters)
        return ManualCommandsResponse(**commands)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# Simulation run endpoints
@router.post("/run", response_model=SimulationRunResponse)
async def run_simulation(
    request: RunSimulationRequest,
    analyst: OrgAnalystDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Execute or record an attack simulation.

    - mode=manual: Records the run and returns commands to execute manually.
    - mode=automated: Executes Stratus RT techniques directly (requires cloud credentials).
    """
    if not request.targets:
        raise HTTPException(status_code=400, detail="At least one target is required")

    mode = ExecutionMode.MANUAL if request.mode == "manual" else ExecutionMode.AUTOMATED

    try:
        run = await attack_simulation_service.run_simulation(
            db,
            template_id=request.template_id,
            targets=request.targets,
            triggered_by=analyst.email,
            mode=mode,
            parameters=request.parameters,
            organization_id=analyst.organization_id,
        )
        return run_to_response(run)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/runs", response_model=RunListResponse)
async def list_runs(
    user: OrgUserDep,
    org_id: OrgIdDep,
    status: str | None = Query(None, description="Filter by status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List simulation runs."""
    sim_status = None
    if status:
        try:
            sim_status = SimulationStatus(status)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Invalid status: {status}. Use 'pending', 'running', 'completed', or 'failed'."
                ),
            )

    runs, total = await attack_simulation_service.list_runs(
        db,
        organization_id=org_id,
        status=sim_status,
        page=page,
        page_size=page_size,
    )

    return RunListResponse(
        items=[run_to_response(r) for r in runs],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/runs/{run_id}", response_model=SimulationRunResponse)
async def get_run(
    run_id: uuid.UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific simulation run."""
    run = await attack_simulation_service.get_run(db, run_id, organization_id=org_id)
    if not run:
        raise HTTPException(status_code=404, detail="Simulation run not found")

    return run_to_response(run)


@router.get("/runs/{run_id}/results", response_model=list[SimulationResultResponse])
async def get_run_results(
    run_id: uuid.UUID,
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get results for a simulation run."""
    # First verify the run belongs to this organization
    run = await attack_simulation_service.get_run(db, run_id, organization_id=org_id)
    if not run:
        raise HTTPException(status_code=404, detail="Simulation run not found")

    results = await attack_simulation_service.get_run_results(db, run_id, organization_id=org_id)
    return [result_to_response(r) for r in results]


@router.post("/runs/{run_id}/executed", response_model=SimulationRunResponse)
async def mark_run_executed(
    run_id: uuid.UUID,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Mark a manual simulation run as executed.

    Call this after you've run the commands manually on your target system.
    """
    try:
        run = await attack_simulation_service.mark_run_executed(db, run_id, organization_id=org_id)
        return run_to_response(run)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/runs/{run_id}/verify", response_model=VerifyDetectionResponse)
async def verify_detection(
    run_id: uuid.UUID,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
    panther: PantherService = Depends(get_panther_service),
):
    """
    Verify if the simulation triggered any detections in Panther.

    Queries Panther for alerts that occurred after the simulation
    started and matches them against the simulated technique.
    """
    try:
        result = await attack_simulation_service.verify_detection(
            db, run_id, panther, organization_id=org_id
        )
        return VerifyDetectionResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/runs/{run_id}/cleanup")
async def cleanup_stratus_run(
    run_id: uuid.UUID,
    analyst: OrgAnalystDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """
    Clean up resources created by a Stratus Red Team detonation.

    Only applicable for automated Stratus RT runs.
    """
    try:
        result = await attack_simulation_service.cleanup_stratus(db, run_id, organization_id=org_id)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# Stats and reference endpoints
@router.get("/stats", response_model=StatsResponse)
async def get_simulation_stats(
    user: OrgUserDep,
    org_id: OrgIdDep,
    db: AsyncSession = Depends(get_db),
):
    """Get simulation statistics including detection rate."""
    stats = await attack_simulation_service.get_stats(db, organization_id=org_id)
    return StatsResponse(**stats)


@router.get("/frameworks")
async def get_frameworks(user: OrgUserDep):
    """Get available simulation frameworks."""
    return [
        {
            "id": "atomic",
            "name": "Atomic Red Team",
            "description": "Small, portable tests mapped to MITRE ATT&CK for endpoint simulation",
            "platforms": ["windows", "linux", "macos"],
            "execution_mode": "manual",
            "url": "https://github.com/redcanaryco/atomic-red-team",
        },
        {
            "id": "stratus",
            "name": "Stratus Red Team",
            "description": "Cloud-focused attack simulation for AWS, Azure, and GCP",
            "platforms": ["aws", "azure", "gcp"],
            "execution_mode": "manual or automated",
            "url": "https://github.com/DataDog/stratus-red-team",
        },
    ]


@router.get("/tactics")
async def get_mitre_tactics(user: OrgUserDep):
    """Get MITRE ATT&CK tactics for filtering."""
    return [
        {"id": "initial-access", "name": "Initial Access"},
        {"id": "execution", "name": "Execution"},
        {"id": "persistence", "name": "Persistence"},
        {"id": "privilege-escalation", "name": "Privilege Escalation"},
        {"id": "defense-evasion", "name": "Defense Evasion"},
        {"id": "credential-access", "name": "Credential Access"},
        {"id": "discovery", "name": "Discovery"},
        {"id": "lateral-movement", "name": "Lateral Movement"},
        {"id": "collection", "name": "Collection"},
        {"id": "command-and-control", "name": "Command and Control"},
        {"id": "exfiltration", "name": "Exfiltration"},
        {"id": "impact", "name": "Impact"},
    ]
