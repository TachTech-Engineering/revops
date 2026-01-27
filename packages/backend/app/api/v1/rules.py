from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.api.v1.deps import PantherServiceDep

router = APIRouter()


class RuleCreateRequest(BaseModel):
    id: str
    body: str
    severity: str
    logTypes: list[str]
    displayName: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = True
    dedupPeriodMinutes: int = 60
    threshold: int = 1
    tags: list[str] = []
    runbook: Optional[str] = None
    reference: Optional[str] = None


class RuleUpdateRequest(BaseModel):
    body: Optional[str] = None
    severity: Optional[str] = None
    logTypes: Optional[list[str]] = None
    displayName: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    dedupPeriodMinutes: Optional[int] = None
    threshold: Optional[int] = None
    tags: Optional[list[str]] = None
    runbook: Optional[str] = None
    reference: Optional[str] = None


class PaginatedResponse(BaseModel):
    results: list[dict[str, Any]]
    cursor: Optional[str] = None
    hasMore: bool = False


@router.get("")
async def list_rules(
    panther: PantherServiceDep,
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    logTypes: Optional[list[str]] = Query(None, description="Filter by log types"),
    tags: Optional[list[str]] = Query(None, description="Filter by tags"),
    pageSize: int = Query(50, ge=1, le=1000, description="Page size"),
) -> PaginatedResponse:
    """List detection rules with optional filtering."""
    try:
        rules, cursor = await panther.list_rules(
            enabled=enabled,
            severity=severity,
            log_types=logTypes,
            tags=tags,
            page_size=pageSize,
        )
        return PaginatedResponse(
            results=rules,
            cursor=cursor,
            hasMore=cursor is not None,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{rule_id}")
async def get_rule(
    rule_id: str,
    panther: PantherServiceDep,
) -> dict[str, Any]:
    """Get a single rule by ID."""
    try:
        return await panther.get_rule(rule_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("", status_code=201)
async def create_rule(
    rule: RuleCreateRequest,
    panther: PantherServiceDep,
) -> dict[str, Any]:
    """Create a new detection rule."""
    try:
        return await panther.create_rule(rule.model_dump(by_alias=True))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{rule_id}")
async def update_rule(
    rule_id: str,
    update: RuleUpdateRequest,
    panther: PantherServiceDep,
) -> dict[str, Any]:
    """Update an existing rule."""
    try:
        update_data = {k: v for k, v in update.model_dump(by_alias=True).items() if v is not None}
        return await panther.update_rule(rule_id, update_data)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    panther: PantherServiceDep,
) -> None:
    """Delete a rule."""
    try:
        await panther.delete_rule(rule_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{rule_id}/test")
async def test_rule(
    rule_id: str,
    panther: PantherServiceDep,
) -> dict[str, Any]:
    """Run tests for a rule."""
    try:
        return await panther.test_rule(rule_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
