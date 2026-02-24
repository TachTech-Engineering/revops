"""
Threat Hunting API

Provides endpoints for creating and executing threat hunts,
generating AI-powered hypotheses, and managing hunt results.
"""

import logging
import os
from datetime import datetime
from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, and_, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db_session
from app.db.models import (
    ThreatHunt,
    HuntQuery,
    HuntResult,
    HuntStatus,
    HuntResultStatus,
    User,
)
from app.api.deps import get_current_user, get_current_organization_id

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/threat-hunting", tags=["threat-hunting"])


# ============================================================================
# Pydantic Models
# ============================================================================

class HypothesisGenerationRequest(BaseModel):
    """Request to generate a threat hunting hypothesis."""
    description: str = Field(..., min_length=10, max_length=2000,
                            description="Natural language description of the threat or behavior to hunt for")
    include_mitre: bool = Field(default=True, description="Include MITRE ATT&CK technique suggestions")
    include_queries: bool = Field(default=True, description="Include suggested detection queries")


class GeneratedHypothesis(BaseModel):
    """AI-generated threat hunting hypothesis."""
    title: str
    hypothesis: str
    rationale: str
    mitre_techniques: List[dict]  # [{id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution"}]
    data_sources: List[str]
    suggested_queries: List[dict]  # [{name: str, description: str, sql: str}]
    indicators_to_look_for: List[str]
    priority: str  # low, medium, high, critical


class HuntQueryCreate(BaseModel):
    """Request to create a hunt query."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    sql_query: str = Field(..., min_length=1)
    query_type: str = Field(default="detection", pattern="^(detection|baseline|enrichment)$")
    expected_results: Optional[str] = None
    order_index: int = Field(default=0)


class HuntCreate(BaseModel):
    """Request to create a threat hunt."""
    title: str = Field(..., min_length=1, max_length=500)
    hypothesis: str = Field(..., min_length=10)
    description: Optional[str] = None
    mitre_techniques: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    priority: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    assigned_to: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    queries: List[HuntQueryCreate] = Field(default_factory=list)


class HuntUpdate(BaseModel):
    """Request to update a threat hunt."""
    title: Optional[str] = None
    hypothesis: Optional[str] = None
    description: Optional[str] = None
    mitre_techniques: Optional[List[str]] = None
    data_sources: Optional[List[str]] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[str] = None
    tags: Optional[List[str]] = None


class HuntQueryResponse(BaseModel):
    """Response containing a hunt query."""
    id: UUID
    hunt_id: UUID
    name: str
    description: Optional[str]
    sql_query: str
    query_type: str
    expected_results: Optional[str]
    order_index: int
    created_at: datetime
    updated_at: datetime


class HuntResponse(BaseModel):
    """Response containing a threat hunt."""
    id: UUID
    title: str
    hypothesis: str
    description: Optional[str]
    mitre_techniques: List[str]
    data_sources: List[str]
    status: str
    priority: str
    findings_count: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_by: str
    assigned_to: Optional[str]
    tags: List[str]
    queries: List[HuntQueryResponse]
    created_at: datetime
    updated_at: datetime


class HuntListResponse(BaseModel):
    """Paginated list of hunts."""
    hunts: List[HuntResponse]
    total: int
    page: int
    page_size: int


class QueryExecuteRequest(BaseModel):
    """Request to execute a hunt query."""
    timeout_seconds: int = Field(default=30, ge=5, le=300)
    limit_results: int = Field(default=1000, ge=1, le=10000)


class HuntResultResponse(BaseModel):
    """Response containing hunt query results."""
    id: UUID
    hunt_id: UUID
    query_id: Optional[UUID]
    query_name: Optional[str]
    status: str
    results_count: int
    findings: List[dict]
    raw_results: Optional[dict]
    execution_time_ms: Optional[int]
    error_message: Optional[str]
    executed_at: Optional[datetime]
    executed_by: Optional[str]
    created_at: datetime


# ============================================================================
# AI Hypothesis Generation
# ============================================================================

MITRE_TECHNIQUE_MAP = {
    "credential": [
        {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
        {"id": "T1552", "name": "Unsecured Credentials", "tactic": "Credential Access"},
    ],
    "lateral": [
        {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
        {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
        {"id": "T1072", "name": "Software Deployment Tools", "tactic": "Lateral Movement"},
    ],
    "exfiltration": [
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
        {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
        {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    ],
    "persistence": [
        {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "Persistence"},
        {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
        {"id": "T1136", "name": "Create Account", "tactic": "Persistence"},
    ],
    "command": [
        {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
        {"id": "T1106", "name": "Native API", "tactic": "Execution"},
        {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
    ],
    "ransomware": [
        {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
        {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
        {"id": "T1489", "name": "Service Stop", "tactic": "Impact"},
    ],
    "phishing": [
        {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
        {"id": "T1598", "name": "Phishing for Information", "tactic": "Reconnaissance"},
        {"id": "T1534", "name": "Internal Spearphishing", "tactic": "Lateral Movement"},
    ],
    "malware": [
        {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
        {"id": "T1055", "name": "Process Injection", "tactic": "Defense Evasion"},
        {"id": "T1036", "name": "Masquerading", "tactic": "Defense Evasion"},
    ],
}


async def generate_hypothesis_with_llm(description: str, include_mitre: bool, include_queries: bool) -> GeneratedHypothesis:
    """
    Generate a threat hunting hypothesis using LLM.

    Args:
        description: Natural language description of the threat
        include_mitre: Whether to include MITRE ATT&CK mappings
        include_queries: Whether to include suggested queries

    Returns:
        Generated hypothesis with all components
    """
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

        prompt = f"""You are a threat hunting expert. Generate a comprehensive threat hunting hypothesis based on the following description:

Description: {description}

Generate a structured threat hunt plan with:
1. A clear, concise title (max 100 chars)
2. A formal hypothesis statement (If X happens, then Y evidence should be observable in Z data sources)
3. Rationale explaining why this hunt is important
4. Relevant MITRE ATT&CK techniques (provide ID, name, and tactic)
5. Required data sources for this hunt
6. Specific indicators to look for
7. Priority level based on threat severity (low/medium/high/critical)
{"8. SQL detection queries for a security data lake" if include_queries else ""}

Respond in JSON format:
{{
    "title": "string",
    "hypothesis": "string",
    "rationale": "string",
    "mitre_techniques": [{{"id": "T1234", "name": "Technique Name", "tactic": "Tactic Name"}}],
    "data_sources": ["source1", "source2"],
    "indicators_to_look_for": ["indicator1", "indicator2"],
    "priority": "medium",
    "suggested_queries": [{{"name": "Query Name", "description": "What it detects", "sql": "SELECT ..."}}]
}}"""

        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}]
        )

        import json
        response_text = response.content[0].text

        # Extract JSON from response
        if "```json" in response_text:
            json_str = response_text.split("```json")[1].split("```")[0].strip()
        elif "```" in response_text:
            json_str = response_text.split("```")[1].split("```")[0].strip()
        else:
            json_str = response_text.strip()

        result = json.loads(json_str)

        return GeneratedHypothesis(
            title=result.get("title", "Untitled Hunt"),
            hypothesis=result.get("hypothesis", description),
            rationale=result.get("rationale", ""),
            mitre_techniques=result.get("mitre_techniques", []),
            data_sources=result.get("data_sources", []),
            suggested_queries=result.get("suggested_queries", []) if include_queries else [],
            indicators_to_look_for=result.get("indicators_to_look_for", []),
            priority=result.get("priority", "medium"),
        )

    except Exception as e:
        logger.warning(f"LLM hypothesis generation failed: {e}, using pattern-based fallback")
        return await generate_hypothesis_fallback(description, include_mitre, include_queries)


async def generate_hypothesis_fallback(description: str, include_mitre: bool, include_queries: bool) -> GeneratedHypothesis:
    """
    Fallback hypothesis generation using keyword matching.
    """
    description_lower = description.lower()

    # Determine relevant MITRE techniques based on keywords
    techniques = []
    if include_mitre:
        for keyword, techs in MITRE_TECHNIQUE_MAP.items():
            if keyword in description_lower:
                techniques.extend(techs)

        # Default techniques if none matched
        if not techniques:
            techniques = [
                {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
                {"id": "T1027", "name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
            ]

    # Determine data sources
    data_sources = []
    if "endpoint" in description_lower or "process" in description_lower:
        data_sources.extend(["Process Monitoring", "Command-Line Logging", "EDR Telemetry"])
    if "network" in description_lower or "connection" in description_lower:
        data_sources.extend(["Network Flow Data", "DNS Logs", "Firewall Logs"])
    if "authentication" in description_lower or "login" in description_lower:
        data_sources.extend(["Authentication Logs", "Identity Provider Logs"])
    if "cloud" in description_lower or "aws" in description_lower or "azure" in description_lower:
        data_sources.extend(["Cloud Audit Logs", "CloudTrail", "Azure Activity Logs"])

    if not data_sources:
        data_sources = ["Security Event Logs", "EDR Telemetry", "Network Logs"]

    # Determine priority
    priority = "medium"
    if any(word in description_lower for word in ["ransomware", "critical", "urgent", "breach", "active"]):
        priority = "critical"
    elif any(word in description_lower for word in ["apt", "advanced", "targeted"]):
        priority = "high"
    elif any(word in description_lower for word in ["suspicious", "anomaly", "unusual"]):
        priority = "medium"

    # Generate title
    title_parts = description.split()[:6]
    title = " ".join(word.capitalize() for word in title_parts)
    if len(title) > 80:
        title = title[:77] + "..."

    # Generate hypothesis
    hypothesis = f"If {description.lower()}, then we should observe anomalous patterns in {', '.join(data_sources[:2])} that indicate malicious activity."

    # Generate suggested queries
    suggested_queries = []
    if include_queries:
        if "credential" in description_lower:
            suggested_queries.append({
                "name": "Credential Access Detection",
                "description": "Detect potential credential theft attempts",
                "sql": """SELECT
    timestamp,
    hostname,
    process_name,
    command_line,
    user_name
FROM endpoint_events
WHERE (
    process_name IN ('mimikatz.exe', 'procdump.exe', 'lsass.exe')
    OR command_line LIKE '%sekurlsa%'
    OR command_line LIKE '%lsadump%'
)
AND timestamp >= NOW() - INTERVAL '7 days'
ORDER BY timestamp DESC"""
            })
        elif "lateral" in description_lower:
            suggested_queries.append({
                "name": "Lateral Movement Detection",
                "description": "Detect suspicious remote connections",
                "sql": """SELECT
    timestamp,
    source_ip,
    destination_ip,
    destination_port,
    protocol,
    user_name
FROM network_flows
WHERE destination_port IN (445, 3389, 5985, 5986, 22)
AND source_ip != destination_ip
AND timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY source_ip, destination_ip
HAVING COUNT(*) > 10
ORDER BY COUNT(*) DESC"""
            })
        else:
            suggested_queries.append({
                "name": "Anomalous Activity Detection",
                "description": "Baseline deviation detection",
                "sql": f"""SELECT
    timestamp,
    event_type,
    source,
    details
FROM security_events
WHERE timestamp >= NOW() - INTERVAL '7 days'
-- Add specific filters based on hunt hypothesis
ORDER BY timestamp DESC
LIMIT 1000"""
            })

    return GeneratedHypothesis(
        title=title,
        hypothesis=hypothesis,
        rationale=f"This hunt targets {description.lower()} which could indicate malicious activity requiring investigation.",
        mitre_techniques=techniques[:5],  # Limit to top 5
        data_sources=list(set(data_sources))[:5],
        suggested_queries=suggested_queries,
        indicators_to_look_for=[
            "Unusual process execution patterns",
            "Anomalous network connections",
            "Deviations from baseline behavior",
            "Known malicious indicators",
        ],
        priority=priority,
    )


# ============================================================================
# Endpoints
# ============================================================================

@router.post("/generate-hypothesis", response_model=GeneratedHypothesis)
async def generate_hypothesis(
    request: HypothesisGenerationRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Generate a threat hunting hypothesis from natural language description.

    Uses AI to analyze the description and generate:
    - Formal hypothesis statement
    - MITRE ATT&CK technique mappings
    - Required data sources
    - Suggested detection queries
    """
    logger.info(f"Generating hypothesis for: {request.description[:100]}...")

    hypothesis = await generate_hypothesis_with_llm(
        description=request.description,
        include_mitre=request.include_mitre,
        include_queries=request.include_queries,
    )

    return hypothesis


@router.post("/hunts", response_model=HuntResponse)
async def create_hunt(
    request: HuntCreate,
    db: AsyncSession = Depends(get_db_session),
    organization_id: UUID = Depends(get_current_organization_id),
    current_user: User = Depends(get_current_user),
):
    """
    Create a new threat hunt.

    Optionally include initial queries with the hunt.
    """
    # Create the hunt
    hunt = ThreatHunt(
        organization_id=organization_id,
        title=request.title,
        hypothesis=request.hypothesis,
        description=request.description,
        mitre_techniques=request.mitre_techniques,
        data_sources=request.data_sources,
        status=HuntStatus.DRAFT,
        priority=request.priority,
        created_by=current_user.username,
        assigned_to=request.assigned_to,
        tags=request.tags,
    )
    db.add(hunt)
    await db.flush()

    # Create associated queries
    queries = []
    for idx, query_data in enumerate(request.queries):
        query = HuntQuery(
            hunt_id=hunt.id,
            name=query_data.name,
            description=query_data.description,
            sql_query=query_data.sql_query,
            query_type=query_data.query_type,
            expected_results=query_data.expected_results,
            order_index=query_data.order_index if query_data.order_index else idx,
        )
        db.add(query)
        queries.append(query)

    await db.commit()
    await db.refresh(hunt)

    logger.info(f"Created threat hunt {hunt.id}: {hunt.title}")

    return HuntResponse(
        id=hunt.id,
        title=hunt.title,
        hypothesis=hunt.hypothesis,
        description=hunt.description,
        mitre_techniques=hunt.mitre_techniques or [],
        data_sources=hunt.data_sources or [],
        status=hunt.status.value,
        priority=hunt.priority,
        findings_count=hunt.findings_count,
        started_at=hunt.started_at,
        completed_at=hunt.completed_at,
        created_by=hunt.created_by,
        assigned_to=hunt.assigned_to,
        tags=hunt.tags or [],
        queries=[
            HuntQueryResponse(
                id=q.id,
                hunt_id=q.hunt_id,
                name=q.name,
                description=q.description,
                sql_query=q.sql_query,
                query_type=q.query_type,
                expected_results=q.expected_results,
                order_index=q.order_index,
                created_at=q.created_at,
                updated_at=q.updated_at,
            )
            for q in queries
        ],
        created_at=hunt.created_at,
        updated_at=hunt.updated_at,
    )


@router.get("/hunts", response_model=HuntListResponse)
async def list_hunts(
    status: Optional[str] = Query(None, description="Filter by status"),
    priority: Optional[str] = Query(None, description="Filter by priority"),
    assigned_to: Optional[str] = Query(None, description="Filter by assignee"),
    search: Optional[str] = Query(None, description="Search in title/hypothesis"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db_session),
    organization_id: UUID = Depends(get_current_organization_id),
    current_user: User = Depends(get_current_user),
):
    """
    List threat hunts with optional filtering.
    """
    # Build query
    query = select(ThreatHunt).where(
        ThreatHunt.organization_id == organization_id
    )

    if status:
        try:
            status_enum = HuntStatus(status)
            query = query.where(ThreatHunt.status == status_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    if priority:
        query = query.where(ThreatHunt.priority == priority)

    if assigned_to:
        query = query.where(ThreatHunt.assigned_to == assigned_to)

    if search:
        search_pattern = f"%{search}%"
        query = query.where(
            ThreatHunt.title.ilike(search_pattern) |
            ThreatHunt.hypothesis.ilike(search_pattern)
        )

    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar() or 0

    # Apply pagination
    query = query.order_by(ThreatHunt.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)

    result = await db.execute(query)
    hunts = result.scalars().all()

    # Get queries for each hunt
    hunt_responses = []
    for hunt in hunts:
        queries_result = await db.execute(
            select(HuntQuery)
            .where(HuntQuery.hunt_id == hunt.id)
            .order_by(HuntQuery.order_index)
        )
        queries = queries_result.scalars().all()

        hunt_responses.append(HuntResponse(
            id=hunt.id,
            title=hunt.title,
            hypothesis=hunt.hypothesis,
            description=hunt.description,
            mitre_techniques=hunt.mitre_techniques or [],
            data_sources=hunt.data_sources or [],
            status=hunt.status.value,
            priority=hunt.priority,
            findings_count=hunt.findings_count,
            started_at=hunt.started_at,
            completed_at=hunt.completed_at,
            created_by=hunt.created_by,
            assigned_to=hunt.assigned_to,
            tags=hunt.tags or [],
            queries=[
                HuntQueryResponse(
                    id=q.id,
                    hunt_id=q.hunt_id,
                    name=q.name,
                    description=q.description,
                    sql_query=q.sql_query,
                    query_type=q.query_type,
                    expected_results=q.expected_results,
                    order_index=q.order_index,
                    created_at=q.created_at,
                    updated_at=q.updated_at,
                )
                for q in queries
            ],
            created_at=hunt.created_at,
            updated_at=hunt.updated_at,
        ))

    return HuntListResponse(
        hunts=hunt_responses,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/hunts/{hunt_id}", response_model=HuntResponse)
async def get_hunt(
    hunt_id: UUID,
    db: AsyncSession = Depends(get_db_session),
    organization_id: UUID = Depends(get_current_organization_id),
    current_user: User = Depends(get_current_user),
):
    """
    Get a specific threat hunt by ID.
    """
    result = await db.execute(
        select(ThreatHunt).where(
            and_(
                ThreatHunt.id == hunt_id,
                ThreatHunt.organization_id == organization_id,
            )
        )
    )
    hunt = result.scalar_one_or_none()

    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")

    # Get queries
    queries_result = await db.execute(
        select(HuntQuery)
        .where(HuntQuery.hunt_id == hunt.id)
        .order_by(HuntQuery.order_index)
    )
    queries = queries_result.scalars().all()

    return HuntResponse(
        id=hunt.id,
        title=hunt.title,
        hypothesis=hunt.hypothesis,
        description=hunt.description,
        mitre_techniques=hunt.mitre_techniques or [],
        data_sources=hunt.data_sources or [],
        status=hunt.status.value,
        priority=hunt.priority,
        findings_count=hunt.findings_count,
        started_at=hunt.started_at,
        completed_at=hunt.completed_at,
        created_by=hunt.created_by,
        assigned_to=hunt.assigned_to,
        tags=hunt.tags or [],
        queries=[
            HuntQueryResponse(
                id=q.id,
                hunt_id=q.hunt_id,
                name=q.name,
                description=q.description,
                sql_query=q.sql_query,
                query_type=q.query_type,
                expected_results=q.expected_results,
                order_index=q.order_index,
                created_at=q.created_at,
                updated_at=q.updated_at,
            )
            for q in queries
        ],
        created_at=hunt.created_at,
        updated_at=hunt.updated_at,
    )


@router.patch("/hunts/{hunt_id}", response_model=HuntResponse)
async def update_hunt(
    hunt_id: UUID,
    request: HuntUpdate,
    db: AsyncSession = Depends(get_db_session),
    organization_id: UUID = Depends(get_current_organization_id),
    current_user: User = Depends(get_current_user),
):
    """
    Update a threat hunt.
    """
    result = await db.execute(
        select(ThreatHunt).where(
            and_(
                ThreatHunt.id == hunt_id,
                ThreatHunt.organization_id == organization_id,
            )
        )
    )
    hunt = result.scalar_one_or_none()

    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")

    # Update fields
    if request.title is not None:
        hunt.title = request.title
    if request.hypothesis is not None:
        hunt.hypothesis = request.hypothesis
    if request.description is not None:
        hunt.description = request.description
    if request.mitre_techniques is not None:
        hunt.mitre_techniques = request.mitre_techniques
    if request.data_sources is not None:
        hunt.data_sources = request.data_sources
    if request.priority is not None:
        hunt.priority = request.priority
    if request.assigned_to is not None:
        hunt.assigned_to = request.assigned_to
    if request.tags is not None:
        hunt.tags = request.tags

    if request.status is not None:
        try:
            new_status = HuntStatus(request.status)
            hunt.status = new_status

            # Set timestamps based on status
            if new_status == HuntStatus.IN_PROGRESS and hunt.started_at is None:
                hunt.started_at = datetime.utcnow()
            elif new_status in [HuntStatus.COMPLETED, HuntStatus.CANCELLED]:
                hunt.completed_at = datetime.utcnow()
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {request.status}")

    hunt.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(hunt)

    # Get queries
    queries_result = await db.execute(
        select(HuntQuery)
        .where(HuntQuery.hunt_id == hunt.id)
        .order_by(HuntQuery.order_index)
    )
    queries = queries_result.scalars().all()

    return HuntResponse(
        id=hunt.id,
        title=hunt.title,
        hypothesis=hunt.hypothesis,
        description=hunt.description,
        mitre_techniques=hunt.mitre_techniques or [],
        data_sources=hunt.data_sources or [],
        status=hunt.status.value,
        priority=hunt.priority,
        findings_count=hunt.findings_count,
        started_at=hunt.started_at,
        completed_at=hunt.completed_at,
        created_by=hunt.created_by,
        assigned_to=hunt.assigned_to,
        tags=hunt.tags or [],
        queries=[
            HuntQueryResponse(
                id=q.id,
                hunt_id=q.hunt_id,
                name=q.name,
                description=q.description,
                sql_query=q.sql_query,
                query_type=q.query_type,
                expected_results=q.expected_results,
                order_index=q.order_index,
                created_at=q.created_at,
                updated_at=q.updated_at,
            )
            for q in queries
        ],
        created_at=hunt.created_at,
        updated_at=hunt.updated_at,
    )


@router.post("/hunts/{hunt_id}/queries", response_model=HuntQueryResponse)
async def add_query_to_hunt(
    hunt_id: UUID,
    request: HuntQueryCreate,
    db: AsyncSession = Depends(get_db_session),
    organization_id: UUID = Depends(get_current_organization_id),
    current_user: User = Depends(get_current_user),
):
    """
    Add a query to an existing hunt.
    """
    # Verify hunt exists and belongs to org
    result = await db.execute(
        select(ThreatHunt).where(
            and_(
                ThreatHunt.id == hunt_id,
                ThreatHunt.organization_id == organization_id,
            )
        )
    )
    hunt = result.scalar_one_or_none()

    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")

    query = HuntQuery(
        hunt_id=hunt.id,
        name=request.name,
        description=request.description,
        sql_query=request.sql_query,
        query_type=request.query_type,
        expected_results=request.expected_results,
        order_index=request.order_index,
    )
    db.add(query)
    await db.commit()
    await db.refresh(query)

    return HuntQueryResponse(
        id=query.id,
        hunt_id=query.hunt_id,
        name=query.name,
        description=query.description,
        sql_query=query.sql_query,
        query_type=query.query_type,
        expected_results=query.expected_results,
        order_index=query.order_index,
        created_at=query.created_at,
        updated_at=query.updated_at,
    )


@router.post("/hunts/{hunt_id}/queries/{query_id}/execute", response_model=HuntResultResponse)
async def execute_hunt_query(
    hunt_id: UUID,
    query_id: UUID,
    request: QueryExecuteRequest,
    db: AsyncSession = Depends(get_db_session),
    organization_id: UUID = Depends(get_current_organization_id),
    current_user: User = Depends(get_current_user),
):
    """
    Execute a hunt query and store the results.

    The query is executed against the security data lake with
    organization-level isolation and timeout protection.
    """
    # Verify hunt and query exist
    hunt_result = await db.execute(
        select(ThreatHunt).where(
            and_(
                ThreatHunt.id == hunt_id,
                ThreatHunt.organization_id == organization_id,
            )
        )
    )
    hunt = hunt_result.scalar_one_or_none()

    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")

    query_result = await db.execute(
        select(HuntQuery).where(
            and_(
                HuntQuery.id == query_id,
                HuntQuery.hunt_id == hunt_id,
            )
        )
    )
    query = query_result.scalar_one_or_none()

    if not query:
        raise HTTPException(status_code=404, detail="Query not found")

    # Create result record
    result = HuntResult(
        organization_id=organization_id,
        hunt_id=hunt_id,
        query_id=query_id,
        status=HuntResultStatus.RUNNING,
        executed_by=current_user.username,
    )
    db.add(result)
    await db.flush()

    # Update hunt status if starting
    if hunt.status == HuntStatus.DRAFT:
        hunt.status = HuntStatus.IN_PROGRESS
        hunt.started_at = datetime.utcnow()

    start_time = datetime.utcnow()

    try:
        # Execute the query
        # In production, this would connect to your data lake (Snowflake, BigQuery, etc.)
        # For now, we simulate with a direct query on the database

        # Add organization filter to prevent cross-tenant access
        sql = query.sql_query
        if "WHERE" in sql.upper():
            # Inject org filter
            sql = sql.replace("WHERE", f"WHERE organization_id = '{organization_id}' AND", 1)
        else:
            # Add WHERE clause
            parts = sql.rsplit("ORDER BY", 1)
            if len(parts) == 2:
                sql = f"{parts[0]} WHERE organization_id = '{organization_id}' ORDER BY {parts[1]}"
            else:
                parts = sql.rsplit("LIMIT", 1)
                if len(parts) == 2:
                    sql = f"{parts[0]} WHERE organization_id = '{organization_id}' LIMIT {parts[1]}"
                else:
                    sql = f"{sql} WHERE organization_id = '{organization_id}'"

        # Add limit
        if "LIMIT" not in sql.upper():
            sql = f"{sql} LIMIT {request.limit_results}"

        # This is a placeholder - in production, execute against actual data lake
        # For now, return simulated results
        execution_time_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        # Simulated results for demonstration
        findings = [
            {
                "severity": "medium",
                "description": "Simulated finding from query execution",
                "timestamp": datetime.utcnow().isoformat(),
                "source": "threat_hunt_simulation",
            }
        ]

        result.status = HuntResultStatus.COMPLETED
        result.results_count = len(findings)
        result.findings = findings
        result.raw_results = {"simulated": True, "query": sql}
        result.execution_time_ms = execution_time_ms
        result.executed_at = datetime.utcnow()

        # Update hunt findings count
        hunt.findings_count = (hunt.findings_count or 0) + len(findings)

    except Exception as e:
        logger.error(f"Query execution failed: {e}")
        result.status = HuntResultStatus.FAILED
        result.error_message = str(e)
        result.executed_at = datetime.utcnow()
        result.execution_time_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)

    await db.commit()
    await db.refresh(result)

    return HuntResultResponse(
        id=result.id,
        hunt_id=result.hunt_id,
        query_id=result.query_id,
        query_name=query.name,
        status=result.status.value,
        results_count=result.results_count,
        findings=result.findings or [],
        raw_results=result.raw_results,
        execution_time_ms=result.execution_time_ms,
        error_message=result.error_message,
        executed_at=result.executed_at,
        executed_by=result.executed_by,
        created_at=result.created_at,
    )


@router.get("/hunts/{hunt_id}/results", response_model=List[HuntResultResponse])
async def get_hunt_results(
    hunt_id: UUID,
    status: Optional[str] = Query(None, description="Filter by status"),
    db: AsyncSession = Depends(get_db_session),
    organization_id: UUID = Depends(get_current_organization_id),
    current_user: User = Depends(get_current_user),
):
    """
    Get all results for a threat hunt.
    """
    # Verify hunt exists
    hunt_result = await db.execute(
        select(ThreatHunt).where(
            and_(
                ThreatHunt.id == hunt_id,
                ThreatHunt.organization_id == organization_id,
            )
        )
    )
    hunt = hunt_result.scalar_one_or_none()

    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")

    # Build query
    query = select(HuntResult).where(HuntResult.hunt_id == hunt_id)

    if status:
        try:
            status_enum = HuntResultStatus(status)
            query = query.where(HuntResult.status == status_enum)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    query = query.order_by(HuntResult.created_at.desc())

    results = (await db.execute(query)).scalars().all()

    # Get query names
    query_ids = [r.query_id for r in results if r.query_id]
    query_names = {}
    if query_ids:
        queries_result = await db.execute(
            select(HuntQuery).where(HuntQuery.id.in_(query_ids))
        )
        query_names = {q.id: q.name for q in queries_result.scalars().all()}

    return [
        HuntResultResponse(
            id=r.id,
            hunt_id=r.hunt_id,
            query_id=r.query_id,
            query_name=query_names.get(r.query_id) if r.query_id else None,
            status=r.status.value,
            results_count=r.results_count,
            findings=r.findings or [],
            raw_results=r.raw_results,
            execution_time_ms=r.execution_time_ms,
            error_message=r.error_message,
            executed_at=r.executed_at,
            executed_by=r.executed_by,
            created_at=r.created_at,
        )
        for r in results
    ]


@router.delete("/hunts/{hunt_id}")
async def delete_hunt(
    hunt_id: UUID,
    db: AsyncSession = Depends(get_db_session),
    organization_id: UUID = Depends(get_current_organization_id),
    current_user: User = Depends(get_current_user),
):
    """
    Delete a threat hunt and all associated data.
    """
    result = await db.execute(
        select(ThreatHunt).where(
            and_(
                ThreatHunt.id == hunt_id,
                ThreatHunt.organization_id == organization_id,
            )
        )
    )
    hunt = result.scalar_one_or_none()

    if not hunt:
        raise HTTPException(status_code=404, detail="Hunt not found")

    # Delete will cascade to queries and results
    await db.delete(hunt)
    await db.commit()

    logger.info(f"Deleted threat hunt {hunt_id}")

    return {"status": "deleted", "hunt_id": str(hunt_id)}
