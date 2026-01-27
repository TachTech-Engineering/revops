"""
Migration API - Detection rule conversion endpoints.
"""

from typing import Optional
from fastapi import APIRouter, HTTPException, status, UploadFile, File
from pydantic import BaseModel

from app.services.migration_service import migration_service, SIEMFormat

router = APIRouter()


class ConvertRequest(BaseModel):
    source_format: str
    target_format: str
    source_code: str


class ConvertResponse(BaseModel):
    converted_code: str
    source_format: str
    target_format: str
    intermediate_sigma: Optional[str] = None


class BulkConvertRequest(BaseModel):
    source_format: str
    target_format: str
    rules: list[str]


class BulkConvertResponse(BaseModel):
    results: list[dict]
    success_count: int
    error_count: int


class FormatInfo(BaseModel):
    id: str
    name: str
    description: str


@router.get("/formats", response_model=list[FormatInfo])
async def get_supported_formats():
    """Get list of supported SIEM formats for conversion."""
    return migration_service.get_supported_formats()


@router.post("/convert", response_model=ConvertResponse)
async def convert_rule(request: ConvertRequest):
    """
    Convert a detection rule from one SIEM format to another.

    Uses Sigma as an intermediate format for accurate conversion:
    Source → Sigma → Target

    Supported formats:
    - sigma: Universal Sigma format (YAML)
    - spl: Splunk Search Processing Language
    - yaral: Google SecOps / Chronicle YARA-L
    - kql: Microsoft Sentinel KQL
    - eql: Elastic Security EQL
    - esql: Elastic ES|QL (new query language)
    - panther: Panther Python detection rules
    """
    try:
        source_format = SIEMFormat(request.source_format.lower())
        target_format = SIEMFormat(request.target_format.lower())
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid format: {e}. Supported formats: {[f.value for f in SIEMFormat]}"
        )

    if not request.source_code.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Source code cannot be empty"
        )

    try:
        converted = migration_service.convert(
            source_code=request.source_code,
            source_format=source_format,
            target_format=target_format,
        )

        # Also get Sigma intermediate if not converting to/from Sigma
        intermediate_sigma = None
        if source_format != SIEMFormat.SIGMA and target_format != SIEMFormat.SIGMA:
            intermediate_sigma = migration_service.convert(
                source_code=request.source_code,
                source_format=source_format,
                target_format=SIEMFormat.SIGMA,
            )

        return ConvertResponse(
            converted_code=converted,
            source_format=source_format.value,
            target_format=target_format.value,
            intermediate_sigma=intermediate_sigma,
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Conversion failed: {str(e)}"
        )


@router.post("/convert/bulk", response_model=BulkConvertResponse)
async def bulk_convert_rules(request: BulkConvertRequest):
    """
    Convert multiple detection rules in batch.

    Returns results for each rule with success/failure status.
    """
    try:
        source_format = SIEMFormat(request.source_format.lower())
        target_format = SIEMFormat(request.target_format.lower())
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid format: {e}"
        )

    results = []
    success_count = 0
    error_count = 0

    for i, rule in enumerate(request.rules):
        try:
            converted = migration_service.convert(
                source_code=rule,
                source_format=source_format,
                target_format=target_format,
            )
            results.append({
                "index": i,
                "status": "success",
                "converted_code": converted,
            })
            success_count += 1
        except Exception as e:
            results.append({
                "index": i,
                "status": "error",
                "error": str(e),
            })
            error_count += 1

    return BulkConvertResponse(
        results=results,
        success_count=success_count,
        error_count=error_count,
    )


@router.post("/convert/file")
async def convert_file(
    file: UploadFile = File(...),
    source_format: str = "sigma",
    target_format: str = "spl",
):
    """
    Convert a detection rule file.

    Accepts: .yml, .yaml, .json, .txt, .spl, .kql, .eql, .py
    """
    try:
        src_format = SIEMFormat(source_format.lower())
        tgt_format = SIEMFormat(target_format.lower())
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid format: {e}"
        )

    # Read file content
    content = await file.read()
    try:
        source_code = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be UTF-8 encoded text"
        )

    try:
        converted = migration_service.convert(
            source_code=source_code,
            source_format=src_format,
            target_format=tgt_format,
        )

        return {
            "filename": file.filename,
            "source_format": src_format.value,
            "target_format": tgt_format.value,
            "converted_code": converted,
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Conversion failed: {str(e)}"
        )


@router.get("/examples/{format}")
async def get_format_example(format: str):
    """Get an example detection rule for a specific format."""
    examples = {
        "sigma": """title: Suspicious PowerShell Execution
status: experimental
description: Detects encoded PowerShell execution
author: Security Team
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
fields:
  - ComputerName
  - User
  - CommandLine
level: high
tags:
  - attack.execution
  - attack.t1059.001""",

        "spl": """index=windows sourcetype=WinEventLog:Security EventCode=4688
| where like(NewProcessName, "%powershell.exe")
| where like(CommandLine, "%-enc%")
| table _time, ComputerName, User, NewProcessName, CommandLine""",

        "yaral": """rule suspicious_powershell_execution {
  meta:
    author = "Security Team"
    description = "Detects encoded PowerShell execution"
    severity = "HIGH"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /powershell\\.exe$/
    $e.target.process.command_line = /\\-enc/

  condition:
    $e
}""",

        "kql": """SecurityEvent
| where EventID == 4688
| where NewProcessName endswith "powershell.exe"
| where CommandLine contains "-enc"
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine""",

        "eql": """process where process.name == "powershell.exe" and process.command_line : "*-enc*\"""",

        "esql": """FROM logs-windows.*
| WHERE process.name == "powershell.exe" AND process.command_line LIKE "%-enc%"
| KEEP @timestamp, host.name, user.name, process.name, process.command_line""",

        "panther": """def rule(event):
    \"\"\"
    Detects encoded PowerShell execution
    Severity: HIGH
    \"\"\"
    if event.get("process_name", "").endswith("powershell.exe"):
        command_line = event.get("command_line", "")
        if "-enc" in command_line.lower():
            return True
    return False


def title(event):
    return f"Suspicious PowerShell on {event.get('hostname', 'unknown')}"


def severity(event):
    return "HIGH\"""",
    }

    format_lower = format.lower()
    if format_lower not in examples:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No example available for format: {format}"
        )

    return {
        "format": format_lower,
        "example": examples[format_lower],
    }
