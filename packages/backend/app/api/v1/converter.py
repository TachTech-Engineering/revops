from typing import Any, Optional, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.api.v1.deps import ConverterServiceDep
from app.services.converter_service import SourceFormat

router = APIRouter()


class ConvertRequest(BaseModel):
    """Request to convert a detection rule to Panther format."""
    spl: str  # Named 'spl' for backwards compatibility, but accepts any source
    ruleId: str
    className: Optional[str] = None
    severity: Optional[str] = None
    sourceFormat: Literal["spl", "yaral"] = "spl"


# Keep old name as alias for backwards compatibility
SPLConvertRequest = ConvertRequest


class SPLBatchConvertRequest(BaseModel):
    rules: list[dict[str, Any]]
    failFast: bool = False


class ValidateRequest(BaseModel):
    """Request to validate a detection rule."""
    spl: str  # Named 'spl' for backwards compatibility
    sourceFormat: Literal["spl", "yaral"] = "spl"


# Keep old name as alias
SPLValidateRequest = ValidateRequest


@router.get("/formats")
async def get_supported_formats(
    converter: ConverterServiceDep,
) -> list[dict[str, Any]]:
    """
    Get list of supported source formats for conversion.

    Returns format details including name, description, and examples.
    """
    return converter.get_supported_formats()


@router.post("/convert")
async def convert_rule(
    request: ConvertRequest,
    converter: ConverterServiceDep,
) -> dict[str, Any]:
    """
    Convert a detection rule to Panther format.

    Supports multiple source formats:
    - spl: Splunk SPL queries
    - yaral: Google SecOps YARA-L rules

    Returns generated Python code, metadata, and any TODOs.
    """
    try:
        source_format = SourceFormat(request.sourceFormat)
        return await converter.convert(
            spl=request.spl,
            rule_id=request.ruleId,
            class_name=request.className,
            severity=request.severity,
            source_format=source_format,
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
async def validate_rule(
    request: ValidateRequest,
    converter: ConverterServiceDep,
) -> dict[str, Any]:
    """
    Validate detection rule syntax without full conversion.

    Supports SPL and YARA-L formats.
    Returns analysis of the rule including detected patterns and recommendations.
    """
    try:
        if request.sourceFormat == "yaral":
            return await converter.validate_yaral(request.spl)
        return await converter.validate(request.spl)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
