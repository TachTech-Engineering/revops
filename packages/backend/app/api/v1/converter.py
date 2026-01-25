from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.api.v1.deps import ConverterServiceDep

router = APIRouter()


class SPLConvertRequest(BaseModel):
    spl: str
    ruleId: str
    className: Optional[str] = None
    severity: Optional[str] = None


class SPLBatchConvertRequest(BaseModel):
    rules: list[dict[str, Any]]
    failFast: bool = False


class SPLValidateRequest(BaseModel):
    spl: str


@router.post("/convert")
async def convert_spl(
    request: SPLConvertRequest,
    converter: ConverterServiceDep,
) -> dict[str, Any]:
    """
    Convert a single SPL query to a Panther detection rule.

    Returns generated Python code, metadata, and any TODOs.
    """
    try:
        return await converter.convert(
            spl=request.spl,
            rule_id=request.ruleId,
            class_name=request.className,
            severity=request.severity,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/batch")
async def batch_convert_spl(
    request: SPLBatchConvertRequest,
    converter: ConverterServiceDep,
) -> dict[str, Any]:
    """
    Convert multiple SPL queries to Panther rules.

    Returns all converted rules with recommendations summary.
    """
    try:
        return await converter.convert_batch(
            rules=request.rules,
            fail_fast=request.failFast,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/validate")
async def validate_spl(
    request: SPLValidateRequest,
    converter: ConverterServiceDep,
) -> dict[str, Any]:
    """
    Validate SPL syntax without full conversion.

    Returns analysis of the query including detected patterns and recommendations.
    """
    try:
        return await converter.validate(request.spl)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
