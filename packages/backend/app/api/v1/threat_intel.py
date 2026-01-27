from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
import httpx

from app.config import settings
from app.services.threat_intel_service import threat_intel_service
from app.api.v1.deps import OrgUserDep, OrgIdDep, OrgAnalystDep

router = APIRouter()


class ThreatIntelRequest(BaseModel):
    indicator: str
    indicator_type: str  # ip_address, domain, url, file_hash_md5, file_hash_sha1, file_hash_sha256


class ThreatIntelResult(BaseModel):
    indicator: str
    indicator_type: str
    virustotal: dict[str, Any] | None = None
    abuseipdb: dict[str, Any] | None = None
    error: str | None = None


@router.post("/lookup")
async def lookup_threat_intel(
    request: ThreatIntelRequest,
    analyst: OrgAnalystDep,
) -> ThreatIntelResult:
    """Look up threat intelligence for an indicator."""
    result = ThreatIntelResult(
        indicator=request.indicator,
        indicator_type=request.indicator_type,
    )

    async with httpx.AsyncClient() as client:
        # VirusTotal lookup
        if settings.virustotal_api_key:
            try:
                vt_result = await lookup_virustotal(
                    client,
                    request.indicator,
                    request.indicator_type,
                    settings.virustotal_api_key
                )
                result.virustotal = vt_result
            except Exception as e:
                result.virustotal = {"error": str(e)}
        else:
            result.virustotal = {"error": "VirusTotal API key not configured"}

        # AbuseIPDB lookup (IP only)
        if request.indicator_type == "ip" and settings.abuseipdb_api_key:
            try:
                abuse_result = await lookup_abuseipdb(
                    client,
                    request.indicator,
                    settings.abuseipdb_api_key
                )
                result.abuseipdb = abuse_result
            except Exception as e:
                result.abuseipdb = {"error": str(e)}
        elif request.indicator_type == "ip":
            result.abuseipdb = {"error": "AbuseIPDB API key not configured"}

    return result


async def lookup_virustotal(
    client: httpx.AsyncClient,
    indicator: str,
    indicator_type: str,
    api_key: str,
) -> dict[str, Any]:
    """Look up an indicator on VirusTotal."""
    base_url = "https://www.virustotal.com/api/v3"
    headers = {"x-apikey": api_key}

    if indicator_type == "ip":
        url = f"{base_url}/ip_addresses/{indicator}"
    elif indicator_type == "domain":
        url = f"{base_url}/domains/{indicator}"
    elif indicator_type.startswith("hash"):
        url = f"{base_url}/files/{indicator}"
    else:
        return {"error": f"Unsupported indicator type: {indicator_type}"}

    response = await client.get(url, headers=headers, timeout=10.0)

    if response.status_code == 404:
        return {"found": False, "message": "Not found in VirusTotal"}

    if response.status_code != 200:
        return {"error": f"VirusTotal API error: {response.status_code}"}

    data = response.json().get("data", {})
    attributes = data.get("attributes", {})

    # Extract relevant info
    result: dict[str, Any] = {"found": True}

    if indicator_type == "ip":
        result.update({
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
            "reputation": attributes.get("reputation", 0),
            "last_analysis_stats": attributes.get("last_analysis_stats", {}),
        })
    elif indicator_type == "domain":
        result.update({
            "registrar": attributes.get("registrar"),
            "creation_date": attributes.get("creation_date"),
            "reputation": attributes.get("reputation", 0),
            "last_analysis_stats": attributes.get("last_analysis_stats", {}),
            "categories": attributes.get("categories", {}),
        })
    elif indicator_type.startswith("hash"):
        result.update({
            "meaningful_name": attributes.get("meaningful_name"),
            "type_description": attributes.get("type_description"),
            "reputation": attributes.get("reputation", 0),
            "last_analysis_stats": attributes.get("last_analysis_stats", {}),
            "names": attributes.get("names", [])[:5],
        })

    return result


async def lookup_abuseipdb(
    client: httpx.AsyncClient,
    ip: str,
    api_key: str,
) -> dict[str, Any]:
    """Look up an IP on AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}

    response = await client.get(url, headers=headers, params=params, timeout=10.0)

    if response.status_code != 200:
        return {"error": f"AbuseIPDB API error: {response.status_code}"}

    data = response.json().get("data", {})

    return {
        "found": True,
        "is_public": data.get("isPublic"),
        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
        "country_code": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "total_reports": data.get("totalReports", 0),
        "last_reported_at": data.get("lastReportedAt"),
        "is_tor": data.get("isTor", False),
    }


@router.get("/status")
async def get_threat_intel_status(
    user: OrgUserDep,
) -> dict[str, Any]:
    """Check which threat intel services are configured."""
    # Get status from unified service
    unified_status = await threat_intel_service.get_sources_status()

    # Add legacy VirusTotal status
    unified_status["virustotal"] = {
        "configured": bool(settings.virustotal_api_key),
        "supported_types": ["ip_address", "domain", "file_hash_md5", "file_hash_sha1", "file_hash_sha256"],
        "description": "VirusTotal threat intelligence",
    }

    return unified_status


@router.get("/lookup")
async def unified_lookup(
    user: OrgUserDep,
    indicator: str = Query(..., description="Indicator value"),
    indicator_type: str = Query(..., description="Type: ip_address, domain, url, file_hash_md5, file_hash_sha1, file_hash_sha256"),
) -> dict[str, Any]:
    """
    Unified threat intelligence lookup across all configured providers.

    This endpoint queries all available threat intel sources in parallel and
    returns aggregated results with a composite risk score.

    Supported providers (free tier):
    - AbuseIPDB: IP reputation
    - AlienVault OTX: Multiple indicator types
    - Abuse.ch: Malware hashes, malicious URLs, botnet C2 IPs
    """
    # Normalize indicator type
    type_mapping = {
        "ip": "ip_address",
        "hash": "file_hash_sha256",
        "md5": "file_hash_md5",
        "sha1": "file_hash_sha1",
        "sha256": "file_hash_sha256",
    }
    normalized_type = type_mapping.get(indicator_type, indicator_type)

    try:
        result = await threat_intel_service.lookup(indicator, normalized_type)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/sources")
async def list_sources(
    user: OrgUserDep,
) -> dict[str, Any]:
    """List available threat intelligence sources and their capabilities."""
    return await threat_intel_service.get_sources_status()
